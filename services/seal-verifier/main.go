// Seal verifier: authenticates and opens D22 sealed fields for the WSL2 aggregator.
// See docs/adr/0007-seal-verifier.md. It uses only the Go standard library.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	LinuxKeys                                   string
	Listen, Metrics, Downstream                 string
	Keys, IdentityDir                           string
	ServerCert, ServerKey, ClientCA, ClientName string
	DownCert, DownKey, DownCA                   string
	MaxRequestBytes                             int64
	MaxConcurrent, MaxRefusalsPerMinute         int
	MaxIdentities                               int
	ReadHeaderTimeout, ReadTimeout              time.Duration
	WriteTimeout, DownstreamTimeout             time.Duration
}

func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s is not a loopback address", address)
	}
	return nil
}

type Counters struct {
	mu      sync.Mutex
	reasons map[string]uint64
}

func (c *Counters) add(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reasons[reason]++
}

func (c *Counters) write(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.reasons))
	for name := range c.reasons {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "seal_verifier_events_total{result=%q} %d\n", name, c.reasons[name])
	}
}

// errRefused means Vector gave up on the batch. Its sinks retry transient faults themselves, so a
// 400 or 500 from the source is final. Anything else may clear, and is retried.
var errRefused = errors.New("downstream refused the batch")

type Server struct {
	verifier  *Verifier
	refusals  *refusalLimit
	client    *http.Client
	cfg       Config
	counters  *Counters
	slots     chan struct{}
	forwarded atomic.Uint64
}

func NewServer(cfg Config, verifier *Verifier, client *http.Client) *Server {
	return &Server{verifier: verifier, client: client, cfg: cfg, refusals: &refusalLimit{limit: cfg.MaxRefusalsPerMinute},
		counters: &Counters{reasons: map[string]uint64{}}, slots: make(chan struct{}, cfg.MaxConcurrent)}
}

// fail answers 503 only. Vector retries 5xx, so the event stays uncommitted in Kafka. A 4xx would
// be final for Vector, so this handler never sends one for anything Vector produced.
func (s *Server) fail(w http.ResponseWriter, reason string) {
	s.counters.add(reason)
	w.Header().Set("Retry-After", "1")
	http.Error(w, reason, http.StatusServiceUnavailable)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/verify" {
		http.NotFound(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != s.cfg.ClientName {
		s.counters.add("client_rejected")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.fail(w, "busy")
		return
	}

	lines := bufio.NewReaderSize(http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes), 64<<10)
	var items []*item
	pending := map[[16]byte][16]byte{}
	results := map[string]uint64{}
	for {
		line, oversized, err := readLine(lines)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				s.counters.add("request_too_large")
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			s.fail(w, "read_failed")
			return
		}
		if oversized {
			result := s.verifier.dead(nil, eventRef{}, deadInfo{Reason: "size", RawLength: maxLineBytes}, nil)
			items = append(items, &item{output: result.line, dead: true})
			results[result.reason]++
			continue
		}
		if line == nil {
			break
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		result := s.verifier.Process(line)
		// The store only knows delivered events, so a batch must also check against itself.
		if !result.dead && !result.skip {
			if seen, repeated := pending[result.uid]; repeated {
				if seen == result.hash {
					result = outcome{reason: "replayed", skip: true}
				} else {
					result = outcome{line: s.verifier.deadRecord(line, "replay_conflict"), reason: "replay_conflict", dead: true}
				}
			} else {
				pending[result.uid] = result.hash
			}
		}
		results[result.reason]++
		if result.skip {
			continue
		}
		items = append(items, &item{input: line, output: result.line, dead: result.dead, uid: result.uid, hash: result.hash})
	}
	if len(items) > 0 {
		if err := s.deliver(r.Context(), items); err != nil {
			log.Printf("downstream failed: %v", err)
			s.fail(w, "downstream_unavailable")
			return
		}
	}
	// Recorded only now that Vector has answered, so an unacknowledged event is never marked done.
	var delivered []identity
	for _, it := range items {
		if !it.dead && !it.refused {
			delivered = append(delivered, identity{it.uid, it.hash})
		}
	}
	if err := s.verifier.store.commit(delivered, time.Now()); err != nil {
		log.Printf("identity journal failed: %v", err)
		s.fail(w, "journal_failed")
		return
	}
	for reason, count := range results {
		s.counters.mu.Lock()
		s.counters.reasons[reason] += count
		s.counters.mu.Unlock()
	}
	s.forwarded.Add(1)
	w.WriteHeader(http.StatusOK)
}

type item struct {
	input, output []byte
	dead, refused bool
	uid, hash     [16]byte
}

// deliver sends a batch, and splits it to find any event the sink has permanently refused. Without
// this, one refused document would fail its batch forever and stall the Kafka partition, so a
// single message forged into Kafka could stop ingestion.
func (s *Server) deliver(ctx context.Context, items []*item) error {
	var body bytes.Buffer
	for _, it := range items {
		body.Write(it.output)
		body.WriteByte('\n')
	}
	err := s.forward(ctx, body.Bytes())
	if err == nil || !errors.Is(err, errRefused) {
		return err
	}
	if len(items) > 1 {
		middle := len(items) / 2
		if err := s.deliver(ctx, items[:middle]); err != nil {
			return err
		}
		return s.deliver(ctx, items[middle:])
	}
	return s.deadLetter(ctx, items[0])
}

// deadLetter replaces one refused event with a dead-letter record. Dead-letter records have a
// fixed shape, so a refusal here is not about the record: storage itself is failing. Holding is
// then the only safe answer, because moving on would commit offsets for events stored nowhere.
// The rate limit does the same for a wave of refusals, which also points at storage.
func (s *Server) deadLetter(ctx context.Context, refused *item) error {
	if refused.dead {
		return errors.New("the dead-letter path refused a record")
	}
	if !s.refusals.allow(time.Now()) {
		s.counters.add("refusal_limit")
		return errors.New("too many refused events")
	}
	record := s.verifier.deadRecord(refused.input, "index_rejected")
	if err := s.forward(ctx, append(record, '\n')); err != nil {
		return err
	}
	refused.refused = true
	s.counters.add("index_rejected")
	return nil
}

// refusalLimit allows a fixed number of refusals in each minute.
type refusalLimit struct {
	mu     sync.Mutex
	limit  int
	window time.Time
	used   int
}

func (l *refusalLimit) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Minute {
		l.window, l.used = now, 0
	}
	if l.used >= l.limit {
		return false
	}
	l.used++
	return true
}

// readLine returns nil at the end of the body. A line over the limit is drained and reported, so
// one oversized record dead-letters without failing the rest of the batch.
func readLine(r *bufio.Reader) (line []byte, oversized bool, err error) {
	var buffer []byte
	for {
		part, readErr := r.ReadSlice('\n')
		if len(buffer)+len(part) <= maxLineBytes {
			buffer = append(buffer, part...)
		} else {
			oversized = true
		}
		switch {
		case readErr == nil:
			return buffer, oversized, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			if len(buffer) == 0 && !oversized {
				return nil, false, nil
			}
			return buffer, oversized, nil
		default:
			return nil, false, readErr
		}
	}
}

// forward returns only after Vector has accepted the batch, and Vector answers only after its
// own sinks have. That keeps the Kafka offset uncommitted until the event is delivered.
func (s *Server) forward(parent context.Context, body []byte) error {
	ctx, cancel := context.WithTimeout(parent, s.cfg.DownstreamTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Downstream, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusInternalServerError {
		return fmt.Errorf("%w: status %d", errRefused, response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("downstream returned %d", response.StatusCode)
	}
	return nil
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	s.counters.write(w)
	fmt.Fprintf(w, "seal_verifier_batches_forwarded_total %d\n", s.forwarded.Load())
	fmt.Fprintf(w, "seal_verifier_identities %d\n", s.verifier.store.size())
}

func (s *Server) httpServer(tlsConfig *tls.Config) *http.Server {
	return &http.Server{Addr: s.cfg.Listen, Handler: s, TLSConfig: tlsConfig,
		ReadHeaderTimeout: s.cfg.ReadHeaderTimeout, ReadTimeout: s.cfg.ReadTimeout, WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
}

func loadPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no certificates in " + path)
	}
	return pool, nil
}

func buildTLS(cfg Config) (*tls.Config, *http.Client, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return nil, nil, err
	}
	clientCA, err := loadPool(cfg.ClientCA)
	if err != nil {
		return nil, nil, err
	}
	downCert, err := tls.LoadX509KeyPair(cfg.DownCert, cfg.DownKey)
	if err != nil {
		return nil, nil, err
	}
	downCA, err := loadPool(cfg.DownCA)
	if err != nil {
		return nil, nil, err
	}
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientCAs: clientCA, ClientAuth: tls.RequireAndVerifyClientCert}
	transport := &http.Transport{
		// Vector 0.61.0's TLS listener does not negotiate 1.3, so this one hop is limited to 1.2 AEAD.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: downCA, Certificates: []tls.Certificate{downCert},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: cfg.DownstreamTimeout,
		MaxIdleConnsPerHost:   cfg.MaxConcurrent,
		IdleConnTimeout:       60 * time.Second,
	}
	return server, &http.Client{Transport: transport, Timeout: cfg.DownstreamTimeout}, nil
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:9610", "verification endpoint, loopback only")
	flag.StringVar(&cfg.Metrics, "metrics", "127.0.0.1:9612", "metrics endpoint, loopback only, counts only")
	flag.StringVar(&cfg.Downstream, "downstream", "https://127.0.0.1:9611/v1/verified", "Vector http_server source")
	flag.StringVar(&cfg.Keys, "keys", "", "D22 key file")
	flag.StringVar(&cfg.IdentityDir, "identity-dir", "", "folder for the durable identity journal")
	flag.IntVar(&cfg.MaxIdentities, "max-identities", 6000000, "identities kept in memory")
	flag.StringVar(&cfg.LinuxKeys, "linux-keys", "k2", "comma-separated key IDs that may sign Linux channels, and nothing else")
	flag.StringVar(&cfg.ServerCert, "server-cert", "", "certificate for the verification endpoint")
	flag.StringVar(&cfg.ServerKey, "server-key", "", "key for the verification endpoint")
	flag.StringVar(&cfg.ClientCA, "client-ca", "", "CA that signed Vector's client certificate")
	flag.StringVar(&cfg.ClientName, "client-name", "siem-vector", "required client certificate name")
	flag.StringVar(&cfg.DownCert, "down-cert", "", "client certificate presented to Vector")
	flag.StringVar(&cfg.DownKey, "down-key", "", "key for that client certificate")
	flag.StringVar(&cfg.DownCA, "down-ca", "", "CA that signed Vector's server certificate")
	flag.Int64Var(&cfg.MaxRequestBytes, "max-request-bytes", 16<<20, "largest request body")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 4, "requests processed at once")
	flag.IntVar(&cfg.MaxRefusalsPerMinute, "max-refusals-per-minute", 20, "refused events dead-lettered per minute before holding")
	flag.DurationVar(&cfg.ReadHeaderTimeout, "read-header-timeout", 5*time.Second, "time to receive headers")
	flag.DurationVar(&cfg.ReadTimeout, "read-timeout", 30*time.Second, "time to receive a request")
	flag.DurationVar(&cfg.WriteTimeout, "write-timeout", 120*time.Second, "time to process and answer")
	flag.DurationVar(&cfg.DownstreamTimeout, "downstream-timeout", 90*time.Second, "time for Vector to accept a batch")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	for _, address := range []string{cfg.Listen, cfg.Metrics} {
		if err := requireLoopback(address); err != nil {
			logger.Fatal(err)
		}
	}
	if !strings.HasPrefix(cfg.Downstream, "https://127.0.0.1:") {
		logger.Fatal("downstream must be https on 127.0.0.1")
	}
	keys, err := loadKeys(cfg.Keys)
	if err != nil {
		logger.Fatal(err)
	}
	tlsConfig, client, err := buildTLS(cfg)
	if err != nil {
		logger.Fatal(err)
	}
	store, err := openIdentityStore(cfg.IdentityDir, cfg.MaxIdentities, time.Now())
	if err != nil {
		logger.Fatal(err)
	}
	defer store.close()
	verifier := NewVerifier(keys, store)
	verifier.linuxKeys = map[string]bool{}
	for _, name := range strings.Split(cfg.LinuxKeys, ",") {
		verifier.linuxKeys[strings.TrimSpace(name)] = true
	}
	server := NewServer(cfg, verifier, client)
	verify := server.httpServer(tlsConfig)
	metrics := &http.Server{Addr: cfg.Metrics, Handler: http.HandlerFunc(server.metrics),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	go func() {
		if err := metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}()
	go func() {
		if err := verify.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}()
	logger.Printf("listening on %s", cfg.Listen)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	verify.Shutdown(ctx)
	metrics.Shutdown(ctx)
}
