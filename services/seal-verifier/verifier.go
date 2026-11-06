package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	envelopeLabel = "siem-event-v1"
	macLabel      = "siem-d22-v1"
	keySize       = 32
	ivSize        = 16
	macSize       = 32
	maxCiphertext = 131072
	maxSealed     = 4
	maxLineBytes  = 2 << 20
	maxEventAge   = 14 * 24 * time.Hour
)

// deadFields is all a dead-letter record may hold: routing facts and ciphertext.
var deadFields = []string{"dlq", "kafka", "channel", "event_id", "record_id", "event_uid", "sealed"}

type keyPair struct{ enc, mac []byte }

// loadKeys reads the D22 key file. kN_enc and kN_mac must arrive in pairs, so that a rotation can
// run with two key IDs at once.
func loadKeys(path string) (map[string]keyPair, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o007 != 0 {
			return nil, errors.New("key file is accessible to other users")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("key file is not valid JSON")
	}
	keys := map[string]keyPair{}
	for name, value := range raw {
		id, kind, ok := strings.Cut(name, "_")
		if !ok || (kind != "enc" && kind != "mac") {
			return nil, errors.New("key file has an unknown entry")
		}
		key, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil || len(key) != keySize {
			return nil, errors.New("key file has a key of the wrong size")
		}
		pair := keys[id]
		if kind == "enc" {
			pair.enc = key
		} else {
			pair.mac = key
		}
		keys[id] = pair
	}
	if len(keys) == 0 {
		return nil, errors.New("key file holds no keys")
	}
	for _, pair := range keys {
		if pair.enc == nil || pair.mac == nil || bytes.Equal(pair.enc, pair.mac) {
			return nil, errors.New("key file needs separate encryption and MAC keys")
		}
	}
	return keys, nil
}

type eventRef struct {
	Channel  string `json:"channel"`
	EventID  string `json:"event_id"`
	RecordID string `json:"record_id"`
	EventUID string `json:"event_uid"`
}

type deadInfo struct {
	Reason    string `json:"reason"`
	RawSHA256 string `json:"raw_sha256"`
	RawLength int64  `json:"raw_length"`
}

type sealedField struct {
	name        string
	keyID       string
	iv, ct, mac []byte
	iv64, ct64  string
}

// outcome is one processed line. skip means the event is already stored, so nothing is forwarded.
// A delivered event's identity is recorded through uid and hash, and only after acknowledgement.
type outcome struct {
	line   []byte
	reason string
	skip   bool
	dead   bool
	uid    [16]byte
	hash   [16]byte
}

// Verifier authenticates events and opens sealed fields. compare and decrypt are fields so that
// tests can prove what reaches them, and that decrypt never runs before all MACs are verified.
type Verifier struct {
	keys    map[string]keyPair
	compare func(got, want []byte) bool
	decrypt func(enc, iv, ct []byte) ([]byte, error)
	store   *identityStore
	now     func() time.Time
	// linuxKeys names the keys that may sign Linux channels, and only those. Each agent has its own
	// key (ADR-0008), so a host that holds one cannot forge events for the other.
	linuxKeys map[string]bool
}

func NewVerifier(keys map[string]keyPair, store *identityStore) *Verifier {
	return &Verifier{keys: keys, compare: macMatches, decrypt: decryptCTR, store: store, now: time.Now, linuxKeys: map[string]bool{"k2": true}}
}

// counterWraps reports a field that crosses 2^64 in the IV's low half. The agent's VRL counter wraps
// there and Go's carries, so the two would disagree on an authentic field. Odds are near 2^-50 per
// field, and it must dead-letter rather than produce garbage that passed its MAC.
func counterWraps(iv []byte, size int) bool {
	blocks := uint64(size+aes.BlockSize-1) / aes.BlockSize
	return binary.BigEndian.Uint64(iv[8:]) > math.MaxUint64-blocks+1
}

func decryptCTR(enc, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ct)
	return plain, nil
}

// envelopeMAC covers the exact body bytes, so there is nothing to re-serialize. The label keeps
// this MAC from ever colliding with a field MAC, whose input is a JSON array.
func envelopeMAC(macKey []byte, keyID string, body []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(envelopeLabel + "|" + keyID + "|"))
	mac.Write(body)
	return mac.Sum(nil)
}

// fieldMAC matches the agent's encode_json of the same array, byte for byte.
func fieldMAC(macKey []byte, ctx eventRef, f sealedField) ([]byte, error) {
	aad, err := marshal([]string{macLabel, f.keyID, ctx.EventUID, ctx.Channel, ctx.EventID, ctx.RecordID, f.name, f.iv64, f.ct64})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write(aad)
	return mac.Sum(nil), nil
}

// macMatches is the only MAC comparison in this service. Both inputs are 32 bytes, checked first.
func macMatches(got, want []byte) bool {
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeStrict(value string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(value)
}

func parseField(name string, raw json.RawMessage) (sealedField, string) {
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil || item == nil {
		return sealedField{}, "sealed_shape"
	}
	f := sealedField{name: name}
	json.Unmarshal(item["k"], &f.keyID)
	if f.keyID == "" {
		return sealedField{}, "unknown_key_id"
	}
	var mac64 string
	for key, target := range map[string]*string{"iv": &f.iv64, "ct": &f.ct64, "mac": &mac64} {
		if err := json.Unmarshal(item[key], target); err != nil || bytes.Equal(item[key], []byte("null")) {
			return sealedField{}, "sealed_shape"
		}
	}
	var ivErr, ctErr, macErr error
	f.iv, ivErr = decodeStrict(f.iv64)
	f.ct, ctErr = decodeStrict(f.ct64)
	f.mac, macErr = decodeStrict(mac64)
	if ivErr != nil || ctErr != nil || macErr != nil {
		return sealedField{}, "bad_encoding"
	}
	if len(f.iv) != ivSize || len(f.mac) != macSize || len(f.ct) == 0 || len(f.ct) > maxCiphertext {
		return sealedField{}, "bad_length"
	}
	return f, ""
}

// Process turns one input line into one output line. It never returns plaintext to the caller on
// failure: a dead-letter record holds ciphertext and routing facts only. A panic dead-letters the
// one event, because a batch that fails forever would stall the whole Kafka partition.
func (v *Verifier) Process(line []byte) (result outcome) {
	defer func() {
		if recover() != nil {
			result = v.dead(nil, eventRef{}, deadInfo{Reason: "verifier_panic", RawSHA256: hexSum(line), RawLength: int64(len(line))}, nil)
		}
	}()
	return v.process(line)
}

type envelope struct {
	V, K, EventUID, Body, MAC string
}

// parseEnvelope accepts exactly the five string fields the agent writes.
func parseEnvelope(raw string) (envelope, string) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || fields == nil {
		return envelope{}, "malformed_json"
	}
	var e envelope
	for name, target := range map[string]*string{"v": &e.V, "k": &e.K, "event_uid": &e.EventUID, "body": &e.Body, "mac": &e.MAC} {
		value, ok := fields[name]
		if !ok || json.Unmarshal(value, target) != nil || bytes.Equal(value, []byte("null")) {
			return envelope{}, "auth_missing"
		}
	}
	if len(fields) != 5 {
		return envelope{}, "auth_missing"
	}
	if e.V != envelopeLabel {
		return envelope{}, "auth_version"
	}
	return e, ""
}

func (v *Verifier) process(line []byte) outcome {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil {
		return v.dead(nil, eventRef{}, deadInfo{Reason: "verifier_malformed", RawSHA256: hexSum(line), RawLength: int64(len(line))}, nil)
	}
	// Vector has already rejected this message. It takes the same path so there is only one route.
	// Only routing facts and ciphertext pass, whatever the record claims to hold.
	if _, ok := top["dlq"]; ok {
		kept := map[string]json.RawMessage{}
		for _, name := range deadFields {
			if value, ok := top[name]; ok {
				kept[name] = value
			}
		}
		delete(kept, "sealed")
		out, err := marshal(kept)
		if err != nil {
			return v.dead(nil, eventRef{}, deadInfo{Reason: "verifier_encode", RawSHA256: hexSum(line), RawLength: int64(len(line))}, nil)
		}
		return outcome{line: out, reason: "passed_dead_letter", dead: true}
	}

	info := deadInfo{Reason: "verifier_malformed", RawSHA256: hexSum(line), RawLength: int64(len(line))}
	var raw string
	if json.Unmarshal(top["raw"], &raw) != nil || raw == "" {
		return v.dead(top["kafka"], eventRef{}, info, nil)
	}
	json.Unmarshal(top["raw_sha256"], &info.RawSHA256)
	json.Unmarshal(top["raw_length"], &info.RawLength)
	fail := func(reason string, ctx eventRef, sealed json.RawMessage) outcome {
		info.Reason = reason
		return v.dead(top["kafka"], ctx, info, sealed)
	}

	// Nothing in the message is trusted, or even parsed as an event, until this passes.
	env, reason := parseEnvelope(raw)
	if reason != "" {
		return fail(reason, eventRef{}, nil)
	}
	key, known := v.keys[env.K]
	if !known {
		return fail("unknown_key_id", eventRef{}, sealedOf(env.Body))
	}
	mac, err := decodeStrict(env.MAC)
	if err != nil {
		return fail("bad_encoding", eventRef{}, sealedOf(env.Body))
	}
	if len(mac) != macSize {
		return fail("bad_length", eventRef{}, sealedOf(env.Body))
	}
	if !v.compare(mac, envelopeMAC(key.mac, env.K, []byte(env.Body))) {
		return fail("mac_mismatch", eventRef{}, sealedOf(env.Body))
	}

	// Authenticated from here. The checks below still run: they guard against a broken agent.
	var event map[string]json.RawMessage
	if json.Unmarshal([]byte(env.Body), &event) != nil || event == nil {
		return fail("schema_body", eventRef{}, nil)
	}
	checked, reason := checkEvent(event, env.EventUID, v.now())
	sealedRaw := event["sealed"]
	if reason != "" {
		return fail(reason, checked.ref, sealedOf(env.Body))
	}
	ctx := checked.ref
	if v.linuxKeys[env.K] != isLinux(ctx.Channel) {
		return fail("key_scope", ctx, sealedRaw)
	}

	names := make([]string, 0, len(checked.sealed))
	for name := range checked.sealed {
		names = append(names, name)
	}
	sort.Strings(names)

	// Every field is validated and authenticated before any field is decrypted.
	fields := make([]sealedField, 0, len(names))
	for _, name := range names {
		f, reason := parseField(name, checked.sealed[name])
		if reason == "" {
			if _, known := v.keys[f.keyID]; !known {
				reason = "unknown_key_id"
			} else if v.linuxKeys[f.keyID] != isLinux(ctx.Channel) {
				reason = "key_scope"
			}
		}
		if reason != "" {
			return fail(reason, ctx, sealedRaw)
		}
		want, err := fieldMAC(v.keys[f.keyID].mac, ctx, f)
		if err != nil || !v.compare(f.mac, want) {
			return fail("mac_mismatch", ctx, sealedRaw)
		}
		fields = append(fields, f)
	}

	data := checked.data
	for _, f := range fields {
		if counterWraps(f.iv, len(f.ct)) {
			return fail("counter_wrap", ctx, sealedRaw)
		}
		plain, err := v.decrypt(v.keys[f.keyID].enc, f.iv, f.ct)
		if err != nil {
			return fail("decrypt_error", ctx, sealedRaw)
		}
		value, err := marshal(string(plain))
		if err != nil {
			return fail("decrypt_error", ctx, sealedRaw)
		}
		data[f.name] = value
	}

	delete(event, "sealed")
	if len(fields) > 0 || event["event_data"] != nil {
		merged, err := marshal(data)
		if err != nil {
			return fail("verifier_encode", ctx, sealedRaw)
		}
		event["event_data"] = merged
	}
	opened, err := marshal(event)
	if err != nil {
		return fail("verifier_encode", ctx, sealedRaw)
	}

	// The hash covers the opened event, because a re-read by the agent seals with a fresh IV. It is
	// keyed, so the journal on disk cannot be used to guess the content of an event.
	uid := uidKey(ctx.EventUID)
	hash := contentHash(key.mac, opened)
	if stored, seen := v.store.lookup(uid); seen {
		if stored == hash {
			return outcome{reason: "replayed", skip: true}
		}
		return fail("replay_conflict", ctx, sealedRaw)
	}
	if kafka, ok := top["kafka"]; ok {
		event["kafka"] = kafka
	}
	out, err := marshal(event)
	if err != nil {
		return fail("verifier_encode", ctx, sealedRaw)
	}
	return outcome{line: out, reason: "accepted", uid: uid, hash: hash}
}

func contentHash(macKey, opened []byte) [16]byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte("siem-identity-v1|"))
	mac.Write(opened)
	var out [16]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func uidKey(uid string) [16]byte {
	sum := sha256.Sum256([]byte(uid))
	var out [16]byte
	copy(out[:], sum[:])
	return out
}

func (v *Verifier) dead(kafka json.RawMessage, ctx eventRef, info deadInfo, sealed json.RawMessage) outcome {
	record := map[string]any{"dlq": info, "channel": ctx.Channel, "event_id": ctx.EventID, "record_id": ctx.RecordID, "event_uid": ctx.EventUID}
	if kafka != nil {
		record["kafka"] = kafka
	}
	if text := sealedText(sealed); text != nil {
		record["sealed"] = text
	}
	out, err := marshal(record)
	if err != nil {
		out = []byte(fmt.Sprintf(`{"dlq":{"reason":%q}}`, info.Reason))
	}
	return outcome{line: out, reason: info.Reason, dead: true}
}

// sealedOf reads the ciphertext from a body that may not be authentic. sealedText then keeps only
// ciphertext from it, so a dead letter never stores anything else the message claimed to hold.
func sealedOf(body string) json.RawMessage {
	var event map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &event) != nil {
		return nil
	}
	return event["sealed"]
}

// sealedText stores ciphertext as one string, which keeps a dead-letter record's mapping fixed, so
// OpenSearch can never refuse one for its content. Only the four ciphertext fields survive.
func sealedText(sealed json.RawMessage) json.RawMessage {
	var fields map[string]map[string]json.RawMessage
	if json.Unmarshal(sealed, &fields) != nil || len(fields) == 0 || len(fields) > maxSealed {
		return nil
	}
	kept := map[string]map[string]json.RawMessage{}
	for name, item := range fields {
		entry := map[string]json.RawMessage{}
		for _, key := range []string{"k", "iv", "ct", "mac"} {
			var text string
			if json.Unmarshal(item[key], &text) == nil {
				entry[key] = item[key]
			}
		}
		kept[name] = entry
	}
	inner, err := marshal(kept)
	if err != nil {
		return nil
	}
	out, err := marshal(string(inner))
	if err != nil {
		return nil
	}
	return out
}

// deadRecord builds a dead-letter record for an authenticated event that was then refused. It
// starts from the input, so it holds ciphertext and never the opened fields.
func (v *Verifier) deadRecord(line []byte, reason string) []byte {
	info := deadInfo{Reason: reason, RawSHA256: hexSum(line), RawLength: int64(len(line))}
	var top map[string]json.RawMessage
	var raw string
	json.Unmarshal(line, &top)
	json.Unmarshal(top["raw"], &raw)
	json.Unmarshal(top["raw_sha256"], &info.RawSHA256)
	json.Unmarshal(top["raw_length"], &info.RawLength)
	env, _ := parseEnvelope(raw)
	var event map[string]json.RawMessage
	json.Unmarshal([]byte(env.Body), &event)
	checked, _ := checkEvent(event, env.EventUID, v.now())
	return v.dead(top["kafka"], checked.ref, info, event["sealed"]).line
}

func marshal(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
