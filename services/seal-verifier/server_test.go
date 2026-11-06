package main

import (
	"bytes"
	stdcontext "context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type bodyKey struct{}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T, name string) authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return authority{cert, key, pool}
}

func (ca authority) issue(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type harness struct {
	url      string
	address  string
	ca       authority
	clients  authority
	server   *Server
	store    *identityStore
	received atomic.Int64
}

// start runs the real handler with the production server settings over real mutual TLS.
func start(t *testing.T, downstream http.HandlerFunc, edit func(*Config)) *harness {
	t.Helper()
	h := &harness{ca: newCA(t, "server"), clients: newCA(t, "client")}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.received.Add(int64(bytes.Count(body, []byte("\n"))))
		downstream(w, r.WithContext(stdcontext.WithValue(r.Context(), bodyKey{}, body)))
	}))
	t.Cleanup(down.Close)
	cfg := Config{Downstream: down.URL, ClientName: "siem-vector", MaxRequestBytes: 16 << 20, MaxConcurrent: 2, MaxRefusalsPerMinute: 20,
		ReadHeaderTimeout: 300 * time.Millisecond, ReadTimeout: 600 * time.Millisecond, WriteTimeout: 3 * time.Second,
		DownstreamTimeout: 500 * time.Millisecond}
	if edit != nil {
		edit(&cfg)
	}
	store, err := openIdentityStore(t.TempDir(), 100000, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	h.store = store
	h.server = NewServer(cfg, NewVerifier(testKeys(t), store), &http.Client{Timeout: cfg.DownstreamTimeout})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{h.ca.issue(t, "siem-seal-verifier")},
		ClientCAs: h.clients.pool, ClientAuth: tls.RequireAndVerifyClientCert}
	web := h.server.httpServer(tlsConfig)
	go web.ServeTLS(listener, "", "")
	t.Cleanup(func() { web.Close() })
	h.address = listener.Addr().String()
	h.url = "https://" + h.address + "/v1/verify"
	return h
}

func (h *harness) client(certs ...tls.Certificate) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: h.ca.pool, Certificates: certs}}}
}

func (h *harness) vector(t *testing.T) *http.Client {
	return h.client(h.clients.issue(t, "siem-vector"))
}

func post(t *testing.T, client *http.Client, url string, body []byte) int {
	t.Helper()
	response, err := client.Post(url, "application/x-ndjson", bytes.NewReader(body))
	if err != nil {
		return -1
	}
	defer response.Body.Close()
	return response.StatusCode
}

func ok(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }

func TestForwardsBatch(t *testing.T) {
	h := start(t, ok, nil)
	in, _ := good(t)
	body := append(append(bytes.Clone(in), '\n'), []byte("{garbage\n")...)
	if got := post(t, h.vector(t), h.url, body); got != 200 {
		t.Fatal(got)
	}
	if h.received.Load() != 2 {
		t.Fatalf("forwarded %d of 2", h.received.Load())
	}
}

func TestBypassRejected(t *testing.T) {
	h := start(t, ok, nil)
	in, _ := good(t)
	other := newCA(t, "attacker")
	cases := map[string]*http.Client{
		"no client certificate":       h.client(),
		"certificate from another CA": h.client(other.issue(t, "siem-vector")),
	}
	for name, client := range cases {
		if got := post(t, client, h.url, in); got == 200 {
			t.Fatalf("%s: accepted", name)
		}
	}
	if got := post(t, h.client(h.clients.issue(t, "other")), h.url, in); got != 403 {
		t.Fatalf("wrong certificate name: %d", got)
	}
	if h.received.Load() != 0 {
		t.Fatal("a rejected client reached downstream")
	}
}

func TestDownstreamOutageIsRetriable(t *testing.T) {
	in, _ := good(t)
	cases := map[string]http.HandlerFunc{
		"unavailable": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) },
		"hang":        func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) },
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			h := start(t, handler, nil)
			began := time.Now()
			if got := post(t, h.vector(t), h.url, in); got != 503 {
				t.Fatal(got)
			}
			if took := time.Since(began); took > 1500*time.Millisecond {
				t.Fatalf("not bounded by the downstream timeout: %v", took)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		h := start(t, ok, func(c *Config) { c.Downstream = "http://127.0.0.1:1/" })
		if got := post(t, h.vector(t), h.url, in); got != 503 {
			t.Fatal(got)
		}
	})
}

func TestRecoveryAfterOutage(t *testing.T) {
	var up atomic.Bool
	h := start(t, func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(503)
		}
	}, nil)
	in, _ := good(t)
	client := h.vector(t)
	if got := post(t, client, h.url, in); got != 503 {
		t.Fatal(got)
	}
	up.Store(true)
	if got := post(t, client, h.url, in); got != 200 {
		t.Fatal("the retried event was refused:", got)
	}
}

// refusing returns a sink that refuses any request holding the marker, and records what it stored.
func refusing(marker string, status int, stored *[]string, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := r.Context().Value(bodyKey{}).([]byte)
		mu.Lock()
		defer mu.Unlock()
		if bytes.Contains(body, []byte(marker)) {
			w.WriteHeader(status)
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			*stored = append(*stored, line)
		}
	}
}

func batch(t *testing.T, poison int, size int) []byte {
	keys := testKeys(t)
	var body bytes.Buffer
	for i := 0; i < size; i++ {
		ctx := ref()
		ctx.RecordID = strconv.Itoa(i)
		ctx.EventUID = strings.Repeat("a", 58) + fmt.Sprintf("%06d", i)
		data := map[string]any{"Image": "x"}
		if i == poison {
			data["Poison"] = "POISON"
		}
		body.Write(line(t, ctx, map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret)}, data))
		body.WriteByte('\n')
	}
	return body.Bytes()
}

func TestOneRefusedEventCannotStallABatch(t *testing.T) {
	for _, status := range []int{400, 500} {
		var stored []string
		var mu sync.Mutex
		h := start(t, refusing("POISON", status, &stored, &mu), func(c *Config) { c.DownstreamTimeout = 2 * time.Second })
		if got := post(t, h.vector(t), h.url, batch(t, 7, 16)); got != 200 {
			t.Fatalf("status %d: answered %d", status, got)
		}
		if len(stored) != 16 {
			t.Fatalf("stored %d of 16", len(stored))
		}
		dead := 0
		for _, record := range stored {
			if strings.Contains(record, "index_rejected") {
				dead++
				if strings.Contains(record, secret) || strings.Contains(record, "event_data") {
					t.Fatalf("content in dead letter: %s", record)
				}
			} else if !strings.Contains(record, secret) {
				t.Fatal("a good event was not opened")
			}
		}
		if dead != 1 {
			t.Fatalf("%d dead letters", dead)
		}
		if h.store.size() != 15 {
			t.Fatalf("recorded %d identities, want the 15 that were stored", h.store.size())
		}
	}
}

func TestDeadLetterPathFailureHolds(t *testing.T) {
	h := start(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, nil)
	if got := post(t, h.vector(t), h.url, batch(t, -1, 8)); got != 503 {
		t.Fatalf("a sink refusing everything must hold, not commit: %d", got)
	}
}

func TestRefusalWaveHolds(t *testing.T) {
	var stored []string
	var mu sync.Mutex
	h := start(t, refusing(`"Image":"x"`, 400, &stored, &mu), func(c *Config) {
		c.MaxRefusalsPerMinute = 3
		c.DownstreamTimeout = 2 * time.Second
	})
	if got := post(t, h.vector(t), h.url, batch(t, -1, 10)); got != 503 {
		t.Fatalf("answered %d", got)
	}
	if len(stored) != 3 {
		t.Fatalf("converted %d events, limit is 3", len(stored))
	}
}

func TestRefusalLimitResets(t *testing.T) {
	limit := &refusalLimit{limit: 1}
	now := time.Now()
	if !limit.allow(now) || limit.allow(now.Add(time.Second)) || !limit.allow(now.Add(61*time.Second)) {
		t.Fatal("wrong window")
	}
}

func TestDeadLetterShapeIsFixed(t *testing.T) {
	in, keys := good(t)
	bad := tamper(t, in, func(e map[string]any) { e["mac"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) })
	v := newTestVerifier(t, keys)
	for _, record := range [][]byte{v.Process(bad).line, v.deadRecord(in, "index_rejected")} {
		var parsed map[string]any
		if err := json.Unmarshal(record, &parsed); err != nil {
			t.Fatal(err)
		}
		if _, isText := parsed["sealed"].(string); !isText {
			t.Fatalf("sealed is not text: %s", record)
		}
	}
}

func TestDeliveredEventIsNotForwardedTwice(t *testing.T) {
	h := start(t, ok, nil)
	in, _ := good(t)
	client := h.vector(t)
	post(t, client, h.url, append(bytes.Clone(in), '\n'))
	post(t, client, h.url, append(bytes.Clone(in), '\n'))
	if h.received.Load() != 1 {
		t.Fatalf("forwarded %d times", h.received.Load())
	}
}

func TestFailedDeliveryIsNotRecorded(t *testing.T) {
	var up atomic.Bool
	h := start(t, func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(503)
		}
	}, nil)
	in, _ := good(t)
	client := h.vector(t)
	post(t, client, h.url, append(bytes.Clone(in), '\n'))
	if h.store.size() != 0 {
		t.Fatal("an unacknowledged event was recorded")
	}
	up.Store(true)
	post(t, client, h.url, append(bytes.Clone(in), '\n'))
	if h.store.size() != 1 {
		t.Fatal("the delivered event was not recorded")
	}
}

func TestSameBatchConflict(t *testing.T) {
	keys := testKeys(t)
	var stored []string
	var mu sync.Mutex
	h := start(t, refusing("NEVER", 400, &stored, &mu), nil)
	ctx := ref()
	stamp := time.Now().UTC().Format(time.RFC3339)
	build := func(image string) []byte {
		event := eventBody(ctx, map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret)}, map[string]any{"Image": image})
		event["timestamp"] = stamp
		return wrap(t, keys, event)
	}
	body := append(append(build("a"), '\n'), append(append(build("b"), '\n'), append(build("a"), '\n')...)...)
	if got := post(t, h.vector(t), h.url, body); got != 200 {
		t.Fatal(got)
	}
	if len(stored) != 2 {
		t.Fatalf("stored %d, want the event and one conflict", len(stored))
	}
	if !strings.Contains(stored[1], "replay_conflict") || strings.Contains(stored[1], `"Image":"b"`) {
		t.Fatal(stored[1])
	}
}

func TestBusyIsRetriable(t *testing.T) {
	release := make(chan struct{})
	h := start(t, func(w http.ResponseWriter, r *http.Request) { <-release }, func(c *Config) {
		c.MaxConcurrent = 1
		c.DownstreamTimeout = 2 * time.Second
	})
	defer close(release)
	in, _ := good(t)
	client := h.vector(t)
	go post(t, client, h.url, in)
	time.Sleep(200 * time.Millisecond)
	if got := post(t, client, h.url, in); got != 503 {
		t.Fatal(got)
	}
}

func TestOversizedLineDeadLettersAlone(t *testing.T) {
	var body []byte
	h := start(t, func(w http.ResponseWriter, r *http.Request) {}, nil)
	in, _ := good(t)
	body = append(body, []byte(strings.Repeat("x", maxLineBytes+10))...)
	body = append(body, '\n')
	body = append(body, in...)
	body = append(body, '\n')
	if got := post(t, h.vector(t), h.url, body); got != 200 {
		t.Fatal(got)
	}
	if h.received.Load() != 2 {
		t.Fatalf("forwarded %d of 2", h.received.Load())
	}
}

func TestRequestLimit(t *testing.T) {
	h := start(t, ok, func(c *Config) { c.MaxRequestBytes = 1024 })
	if got := post(t, h.vector(t), h.url, bytes.Repeat([]byte("x\n"), 4096)); got != 413 {
		t.Fatal(got)
	}
	if h.received.Load() != 0 {
		t.Fatal("part of an oversized request was forwarded")
	}
}

func dialTLS(t *testing.T, h *harness) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", h.address, &tls.Config{RootCAs: h.ca.pool, Certificates: []tls.Certificate{h.clients.issue(t, "siem-vector")}})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func closedWithin(t *testing.T, conn net.Conn, limit time.Duration) {
	t.Helper()
	began := time.Now()
	conn.SetReadDeadline(time.Now().Add(limit))
	_, err := io.Copy(io.Discard, conn)
	if netErr, timedOut := err.(net.Error); timedOut && netErr.Timeout() {
		t.Fatalf("still open after %v", time.Since(began))
	}
}

func TestSilentClientIsClosed(t *testing.T) {
	h := start(t, ok, nil)
	conn, err := net.Dial("tcp", h.address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	closedWithin(t, conn, 2*time.Second)
}

func TestSlowHeadersAreClosed(t *testing.T) {
	h := start(t, ok, nil)
	conn := dialTLS(t, h)
	defer conn.Close()
	conn.Write([]byte("POST /v1/verify HTTP/1.1\r\nHost: x\r\n"))
	closedWithin(t, conn, 2*time.Second)
}

func TestSlowBodyIsNotForwarded(t *testing.T) {
	h := start(t, ok, nil)
	conn := dialTLS(t, h)
	defer conn.Close()
	conn.Write([]byte("POST /v1/verify HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{"))
	closedWithin(t, conn, 2*time.Second)
	if h.received.Load() != 0 {
		t.Fatal("a partial request was forwarded")
	}
}

func TestOnlyVerifyPathAndPost(t *testing.T) {
	h := start(t, ok, nil)
	client := h.vector(t)
	response, err := client.Get(h.url)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal(response.StatusCode)
	}
	if got := post(t, client, strings.Replace(h.url, "/v1/verify", "/other", 1), []byte("{}")); got != 404 {
		t.Fatal(got)
	}
}

func TestLoopbackRequired(t *testing.T) {
	for address, want := range map[string]bool{"127.0.0.1:9610": true, "0.0.0.0:9610": false, "192.168.1.5:9610": false, ":9610": false, "localhost:9610": false} {
		if got := requireLoopback(address) == nil; got != want {
			t.Fatalf("%s: %v", address, got)
		}
	}
}

func TestMetricsHoldNoContent(t *testing.T) {
	h := start(t, ok, nil)
	in, _ := good(t)
	post(t, h.vector(t), h.url, in)
	recorder := httptest.NewRecorder()
	h.server.metrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := recorder.Body.String()
	if !strings.Contains(text, `result="accepted"`) || strings.Contains(text, secret) {
		t.Fatal(text)
	}
}
