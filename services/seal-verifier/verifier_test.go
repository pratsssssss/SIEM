package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testUID     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testChannel = "Microsoft-Windows-Sysmon/Operational"
	secret      = "FakeSecretPlaintext"
)

func testKeys(t testing.TB) map[string]keyPair {
	t.Helper()
	return map[string]keyPair{"k1": {enc: bytes.Repeat([]byte{1}, 32), mac: bytes.Repeat([]byte{2}, 32)}}
}

func newTestVerifier(t testing.TB, keys map[string]keyPair) *Verifier {
	t.Helper()
	store, err := openIdentityStore(t.TempDir(), 1000, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	return NewVerifier(keys, store)
}

// seal does what the agent's VRL does. run_offline.py proves the two agree on real agent output.
func seal(t testing.TB, keys map[string]keyPair, keyID string, ctx eventRef, name, plain string) map[string]any {
	t.Helper()
	iv := make([]byte, 16)
	rand.Read(iv)
	iv[8] &= 0x7f
	return sealIV(t, keys, keyID, ctx, name, plain, iv)
}

func sealIV(t testing.TB, keys map[string]keyPair, keyID string, ctx eventRef, name, plain string, iv []byte) map[string]any {
	t.Helper()
	block, _ := aes.NewCipher(keys[keyID].enc)
	ct := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(ct, []byte(plain))
	iv64, ct64 := base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(ct)
	aad, _ := json.Marshal([]string{macLabel, keyID, ctx.EventUID, ctx.Channel, ctx.EventID, ctx.RecordID, name, iv64, ct64})
	mac := hmac.New(sha256.New, keys[keyID].mac)
	mac.Write(aad)
	return map[string]any{"k": keyID, "iv": iv64, "ct": ct64, "mac": base64.StdEncoding.EncodeToString(mac.Sum(nil))}
}

func ref() eventRef {
	return eventRef{Channel: testChannel, EventID: "1", RecordID: "100", EventUID: testUID}
}

func eventBody(ctx eventRef, sealed, data map[string]any) map[string]any {
	id, _ := strconv.Atoi(ctx.EventID)
	record, _ := strconv.ParseInt(ctx.RecordID, 10, 64)
	event := map[string]any{"channel": ctx.Channel, "event_id": id, "record_id": record, "event_uid": ctx.EventUID,
		"computer": "HOST", "timestamp": time.Now().UTC().Format(time.RFC3339), "event_data": data}
	if sealed != nil {
		event["sealed"] = sealed
	}
	return event
}

// wrap signs a body with the real key, as the agent does, and adds what Vector's ingest adds.
func wrap(t testing.TB, keys map[string]keyPair, event map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := event["event_uid"].(string)
	mac := envelopeMAC(keys["k1"].mac, "k1", body)
	raw, _ := json.Marshal(map[string]string{"v": envelopeLabel, "k": "k1", "event_uid": uid, "body": string(body), "mac": base64.StdEncoding.EncodeToString(mac)})
	out, _ := json.Marshal(map[string]any{"raw": string(raw), "raw_sha256": "abc", "raw_length": len(raw),
		"kafka": map[string]any{"topic": "siem-raw-logs", "partition": 0, "offset": 7}})
	return out
}

func line(t testing.TB, ctx eventRef, sealed, data map[string]any) []byte {
	t.Helper()
	return wrap(t, testKeys(t), eventBody(ctx, sealed, data))
}

func good(t testing.TB) ([]byte, map[string]keyPair) {
	keys := testKeys(t)
	ctx := ref()
	sealed := map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret), "ParentCommandLine": seal(t, keys, "k1", ctx, "ParentCommandLine", "parent "+secret)}
	return line(t, ctx, sealed, map[string]any{"Image": "C:\\t\\tool.exe"}), keys
}

// rewrap edits the event and signs it again, so a test reaches the checks after authentication.
func rewrap(t testing.TB, in []byte, keys map[string]keyPair, edit func(event, sealed map[string]any)) []byte {
	t.Helper()
	event := bodyOf(t, in)
	sealed, _ := event["sealed"].(map[string]any)
	edit(event, sealed)
	return wrap(t, keys, event)
}

func bodyOf(t testing.TB, in []byte) map[string]any {
	t.Helper()
	var top struct{ Raw string }
	json.Unmarshal(in, &top)
	var env struct{ Body string }
	json.Unmarshal([]byte(top.Raw), &env)
	var event map[string]any
	decoder := json.NewDecoder(strings.NewReader(env.Body))
	decoder.UseNumber()
	decoder.Decode(&event)
	return event
}

// tamper changes the signed message without the key, as an attacker on Kafka would.
func tamper(t testing.TB, in []byte, edit func(env map[string]any)) []byte {
	t.Helper()
	var top map[string]any
	json.Unmarshal(in, &top)
	var env map[string]any
	json.Unmarshal([]byte(top["raw"].(string)), &env)
	edit(env)
	raw, _ := json.Marshal(env)
	top["raw"] = string(raw)
	out, _ := json.Marshal(top)
	return out
}

func tamperBody(t testing.TB, in []byte, edit func(event, sealed map[string]any)) []byte {
	return tamper(t, in, func(env map[string]any) {
		var event map[string]any
		decoder := json.NewDecoder(strings.NewReader(env["body"].(string)))
		decoder.UseNumber()
		decoder.Decode(&event)
		sealed, _ := event["sealed"].(map[string]any)
		edit(event, sealed)
		body, _ := json.Marshal(event)
		env["body"] = string(body)
	})
}

func field(sealed map[string]any, name string) map[string]any { return sealed[name].(map[string]any) }

func flipBase64(value string, position int) string {
	data, _ := base64.StdEncoding.DecodeString(value)
	data[position] ^= 0x80
	return base64.StdEncoding.EncodeToString(data)
}

func TestAcceptsAndRestores(t *testing.T) {
	in, keys := good(t)
	result := newTestVerifier(t, keys).Process(in)
	if result.reason != "accepted" {
		t.Fatal(result.reason)
	}
	var event map[string]any
	if err := json.Unmarshal(result.line, &event); err != nil {
		t.Fatal(err)
	}
	data := event["event_data"].(map[string]any)
	if data["CommandLine"] != secret || data["ParentCommandLine"] != "parent "+secret || data["Image"] != "C:\\t\\tool.exe" {
		t.Fatalf("fields not restored: %v", data)
	}
	if _, ok := event["sealed"]; ok {
		t.Fatal("sealed left on a good event")
	}
	if event["kafka"].(map[string]any)["offset"] != float64(7) {
		t.Fatal("kafka coordinates lost")
	}
}

func TestLargeNumbersSurvive(t *testing.T) {
	keys := testKeys(t)
	event := eventBody(ref(), nil, map[string]any{})
	event["event_id"] = 4624
	event["channel"] = "Security"
	event["record_id"] = json.Number("18446744073709551615")
	out := newTestVerifier(t, keys).Process(wrap(t, keys, event))
	if !bytes.Contains(out.line, []byte("18446744073709551615")) {
		t.Fatalf("number changed: %s %s", out.reason, out.line)
	}
}

func TestEveryEnvelopeMACBitRejected(t *testing.T) {
	in, keys := good(t)
	for i := 0; i < 32; i++ {
		bad := tamper(t, in, func(env map[string]any) { env["mac"] = flipBase64(env["mac"].(string), i) })
		if got := newTestVerifier(t, keys).Process(bad); got.reason != "mac_mismatch" {
			t.Fatalf("byte %d: %s", i, got.reason)
		}
	}
}

// Whole-event authentication: changing any part of the body, unsealed or not, must fail.
func TestEveryFieldOfTheEventIsAuthenticated(t *testing.T) {
	in, keys := good(t)
	cases := map[string]func(event, sealed map[string]any){
		"unsealed field": func(event, _ map[string]any) { event["event_data"].(map[string]any)["Image"] = "C:\\evil.exe" },
		"added field":    func(event, _ map[string]any) { event["event_data"].(map[string]any)["Extra"] = "x" },
		"timestamp":      func(event, _ map[string]any) { event["timestamp"] = "2020-01-01T00:00:00Z" },
		"computer":       func(event, _ map[string]any) { event["computer"] = "OTHER" },
		"channel":        func(event, _ map[string]any) { event["channel"] = "Security" },
		"event id":       func(event, _ map[string]any) { event["event_id"] = 13 },
		"record id":      func(event, _ map[string]any) { event["record_id"] = 999 },
		"event uid":      func(event, _ map[string]any) { event["event_uid"] = strings.Repeat("b", 64) },
		"labels":         func(event, _ map[string]any) { event["labels"] = map[string]any{"seal_failed": true} },
		"seal removed":   func(event, _ map[string]any) { delete(event, "sealed") },
		"ciphertext":     func(_, s map[string]any) { f := field(s, "CommandLine"); f["ct"] = flipBase64(f["ct"].(string), 0) },
		"iv":             func(_, s map[string]any) { f := field(s, "CommandLine"); f["iv"] = flipBase64(f["iv"].(string), 0) },
		"field swap": func(_, s map[string]any) {
			s["CommandLine"], s["ParentCommandLine"] = s["ParentCommandLine"], s["CommandLine"]
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			v := newTestVerifier(t, keys)
			v.decrypt = func(enc, iv, ct []byte) ([]byte, error) { t.Fatal("decrypt ran"); return nil, nil }
			result := v.Process(tamperBody(t, in, edit))
			if result.reason != "mac_mismatch" {
				t.Fatal(result.reason)
			}
			if strings.Contains(string(result.line), secret) || strings.Contains(string(result.line), "event_data") || strings.Contains(string(result.line), "evil") {
				t.Fatal("content in dead letter")
			}
		})
	}
	wrong := map[string]keyPair{"k1": {enc: keys["k1"].enc, mac: bytes.Repeat([]byte{9}, 32)}}
	if got := newTestVerifier(t, wrong).Process(in); got.reason != "mac_mismatch" {
		t.Fatal("wrong MAC key:", got.reason)
	}
}

func TestForgedEventsWithoutAKey(t *testing.T) {
	in, keys := good(t)
	plain, _ := json.Marshal(eventBody(ref(), nil, map[string]any{"CommandLine": "forged"}))
	wrapped := func(raw string) []byte {
		out, _ := json.Marshal(map[string]any{"raw": raw, "raw_sha256": "a", "raw_length": len(raw)})
		return out
	}
	cases := []struct {
		name, reason string
		line         []byte
	}{
		{"bare event, the old format", "auth_missing", wrapped(string(plain))},
		{"garbage", "malformed_json", wrapped("{not json")},
		{"array", "malformed_json", wrapped("[1,2]")},
		{"no mac", "auth_missing", tamper(t, in, func(e map[string]any) { delete(e, "mac") })},
		{"null mac", "auth_missing", tamper(t, in, func(e map[string]any) { e["mac"] = nil })},
		{"number mac", "auth_missing", tamper(t, in, func(e map[string]any) { e["mac"] = 1 })},
		{"extra field", "auth_missing", tamper(t, in, func(e map[string]any) { e["trusted"] = true })},
		{"wrong version", "auth_version", tamper(t, in, func(e map[string]any) { e["v"] = "siem-event-v0" })},
		{"unknown key", "unknown_key_id", tamper(t, in, func(e map[string]any) { e["k"] = "k9" })},
		{"bad base64", "bad_encoding", tamper(t, in, func(e map[string]any) { e["mac"] = strings.Repeat("!", 44) })},
		{"short mac", "bad_length", tamper(t, in, func(e map[string]any) { e["mac"] = base64.StdEncoding.EncodeToString(make([]byte, 31)) })},
		{"empty mac", "bad_length", tamper(t, in, func(e map[string]any) { e["mac"] = "" })},
		{"all zero mac", "mac_mismatch", tamper(t, in, func(e map[string]any) { e["mac"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) })},
		{"no raw", "verifier_malformed", []byte(`{"kafka":{}}`)},
		{"not json line", "verifier_malformed", []byte("{not json")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := newTestVerifier(t, keys).Process(c.line)
			if result.reason != c.reason {
				t.Fatalf("got %s, want %s", result.reason, c.reason)
			}
			if !json.Valid(result.line) || strings.Contains(string(result.line), "forged") {
				t.Fatalf("bad record: %s", result.line)
			}
		})
	}
}

func TestChecksAfterAuthentication(t *testing.T) {
	in, keys := good(t)
	shape := func(key string, value any) []byte {
		return rewrap(t, in, keys, func(_, s map[string]any) { field(s, "CommandLine")[key] = value })
	}
	drop := func(key string) []byte {
		return rewrap(t, in, keys, func(_, s map[string]any) { delete(field(s, "CommandLine"), key) })
	}
	set := func(key string, value any) []byte {
		return rewrap(t, in, keys, func(event, _ map[string]any) { event[key] = value })
	}
	b64 := base64.StdEncoding.EncodeToString
	cases := []struct {
		name, reason string
		line         []byte
	}{
		{"bad uid", "schema_identity", set("event_uid", "nope")},
		{"bad channel", "schema_channel", set("channel", "Other")},
		{"bad id", "schema_ids", set("event_id", "x")},
		{"unknown top field", "schema_unknown_field", set("5ealed", 1)},
		{"no computer", "schema_fields", set("computer", "")},
		{"bad timestamp", "schema_timestamp", set("timestamp", "not a time")},
		{"too old", "stale_event", set("timestamp", time.Now().Add(-maxEventAge-time.Hour).UTC().Format(time.RFC3339))},
		{"sealed text", "schema_sealed", set("sealed", "text")},
		{"event data text", "schema_event_data", set("event_data", "text")},
		{"unsealed restricted", "unsealed_restricted", rewrap(t, in, keys, func(event, _ map[string]any) {
			event["event_data"].(map[string]any)["CommandLine"] = "plain"
		})},
		{"seal missing", "seal_missing", rewrap(t, in, keys, func(event, _ map[string]any) { delete(event, "sealed") })},
		{"too many", "sealed_too_many", rewrap(t, in, keys, func(_, s map[string]any) {
			for i := 0; i < 5; i++ {
				s["x"+strconv.Itoa(i)] = map[string]any{}
			}
		})},
		{"field not allowed", "sealed_field_not_allowed", rewrap(t, in, keys, func(_, s map[string]any) { s["Image"] = s["CommandLine"] })},
		{"field text", "sealed_shape", rewrap(t, in, keys, func(_, s map[string]any) { s["CommandLine"] = "text" })},
		{"unknown key", "unknown_key_id", shape("k", "k9")},
		{"null key", "unknown_key_id", shape("k", nil)},
		{"missing key", "unknown_key_id", drop("k")},
		{"missing mac", "sealed_shape", drop("mac")},
		{"null mac", "sealed_shape", shape("mac", nil)},
		{"number mac", "sealed_shape", shape("mac", 12345)},
		{"bad base64", "bad_encoding", shape("mac", strings.Repeat("!", 44))},
		{"short mac", "bad_length", shape("mac", b64(make([]byte, 31)))},
		{"long mac", "bad_length", shape("mac", b64(make([]byte, 33)))},
		{"short iv", "bad_length", shape("iv", b64(make([]byte, 5)))},
		{"empty ct", "bad_length", shape("ct", "")},
		{"huge ct", "bad_length", shape("ct", b64(make([]byte, maxCiphertext+1)))},
		{"field mac wrong", "mac_mismatch", shape("mac", b64(make([]byte, 32)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := newTestVerifier(t, keys).Process(c.line)
			if result.reason != c.reason {
				t.Fatalf("got %s, want %s", result.reason, c.reason)
			}
			var record map[string]any
			if err := json.Unmarshal(result.line, &record); err != nil || record["dlq"] == nil {
				t.Fatalf("not a dead-letter record: %s", result.line)
			}
			if record["event_data"] != nil || strings.Contains(string(result.line), secret) || strings.Contains(string(result.line), "plain") {
				t.Fatal("content in dead letter")
			}
		})
	}
}

func TestAuthenticationBeforeDecryption(t *testing.T) {
	in, keys := good(t)
	v := newTestVerifier(t, keys)
	calls := 0
	v.decrypt = func(enc, iv, ct []byte) ([]byte, error) { calls++; return decryptCTR(enc, iv, ct) }
	bad := rewrap(t, in, keys, func(_, s map[string]any) {
		field(s, "ParentCommandLine")["mac"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	})
	if got := v.Process(bad); got.reason != "mac_mismatch" || calls != 0 {
		t.Fatalf("reason %s, decrypt ran %d times", got.reason, calls)
	}
	if got := v.Process(in); got.reason != "accepted" || calls != 2 {
		t.Fatalf("reason %s, decrypt ran %d times", got.reason, calls)
	}
}

func TestCompareOnlySeesFixedLengthMACs(t *testing.T) {
	in, keys := good(t)
	v := newTestVerifier(t, keys)
	calls := 0
	v.compare = func(got, want []byte) bool {
		calls++
		if len(got) != macSize || len(want) != macSize {
			t.Fatalf("compare saw %d and %d bytes", len(got), len(want))
		}
		return macMatches(got, want)
	}
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		outer := tamper(t, in, func(e map[string]any) { e["mac"] = base64.StdEncoding.EncodeToString(make([]byte, size)) })
		if got := v.Process(outer); got.reason != "bad_length" {
			t.Fatalf("envelope size %d: %s", size, got.reason)
		}
	}
	if calls != 0 {
		t.Fatalf("compare ran %d times on wrong lengths", calls)
	}
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		inner := rewrap(t, in, keys, func(_, s map[string]any) {
			field(s, "CommandLine")["mac"] = base64.StdEncoding.EncodeToString(make([]byte, size))
		})
		if got := v.Process(inner); got.reason != "bad_length" {
			t.Fatalf("field size %d: %s", size, got.reason)
		}
	}
	if calls != 6 {
		t.Fatalf("only the 6 envelope MACs should compare, got %d", calls)
	}
	if got := v.Process(in); got.reason != "accepted" || calls != 9 {
		t.Fatalf("%s, %d compares", got.reason, calls)
	}
}

func TestEveryFieldAuthenticatedBeforeAnyDecrypt(t *testing.T) {
	keys := testKeys(t)
	ctx := eventRef{Channel: powershellChannel, EventID: "4100", RecordID: "1", EventUID: testUID}
	names := []string{"ContextInfo", "Payload", "UserData"}
	for bad := range names {
		sealed := map[string]any{}
		for _, name := range names {
			sealed[name] = seal(t, keys, "k1", ctx, name, secret)
		}
		sealed[names[bad]].(map[string]any)["mac"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		v := newTestVerifier(t, keys)
		v.decrypt = func(enc, iv, ct []byte) ([]byte, error) { t.Fatal("decrypt ran"); return nil, nil }
		if got := v.Process(line(t, ctx, sealed, nil)); got.reason != "mac_mismatch" {
			t.Fatalf("bad field %d: %s", bad, got.reason)
		}
	}
}

func TestDeadLetterKeepsOnlyCiphertext(t *testing.T) {
	in := []byte(`{"dlq":{"reason":"x"},"kafka":{"offset":1},"event_uid":"u","sealed":{"a":{}},"event_data":{"CommandLine":"` + secret + `"},"event":{"x":"` + secret + `"},"extra":"` + secret + `"}`)
	got := newTestVerifier(t, testKeys(t)).Process(in)
	if strings.Contains(string(got.line), secret) || !got.dead {
		t.Fatalf("%s", got.line)
	}
	forged, keys := good(t)
	bad := tamperBody(t, forged, func(event, s map[string]any) {
		field(s, "CommandLine")["note"] = secret
		s["CommandLine"].(map[string]any)["ct"] = "AAAA"
	})
	record := newTestVerifier(t, keys).Process(bad)
	if strings.Contains(string(record.line), secret) || !strings.Contains(string(record.line), "sealed") {
		t.Fatalf("%s", record.line)
	}
}

func TestOnlyComparisonIsConstantTime(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "verifier.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	compares := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); ok {
			if pkg.Name == "subtle" && selector.Sel.Name == "ConstantTimeCompare" {
				compares++
			}
			if pkg.Name == "hmac" && selector.Sel.Name == "Equal" {
				t.Error("hmac.Equal must not replace the direct call")
			}
		}
		return true
	})
	if compares != 1 {
		t.Fatalf("found %d ConstantTimeCompare calls, want exactly 1", compares)
	}
}

func commit(t *testing.T, v *Verifier, result outcome) {
	t.Helper()
	if err := v.store.commit([]identity{{result.uid, result.hash}}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestReplayIsDurable(t *testing.T) {
	keys := testKeys(t)
	dir := t.TempDir()
	open := func() *Verifier {
		store, err := openIdentityStore(dir, 1000, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.close)
		return NewVerifier(keys, store)
	}
	v := open()
	ctx := ref()
	stamp := time.Now().UTC().Format(time.RFC3339)
	build := func(image string) []byte {
		event := eventBody(ctx, map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret)}, map[string]any{"Image": image})
		event["timestamp"] = stamp
		return wrap(t, keys, event)
	}
	first := build("a")
	result := v.Process(first)
	if result.reason != "accepted" {
		t.Fatal(result.reason)
	}
	// Before acknowledgement nothing is recorded, so a failed delivery can be retried.
	if got := v.Process(first); got.reason != "accepted" {
		t.Fatal("unacknowledged event was remembered:", got.reason)
	}
	commit(t, v, result)
	if got := v.Process(first); got.reason != "replayed" || !got.skip {
		t.Fatal("redelivery:", got.reason)
	}
	// The agent re-reads after a crash, sealing the same text with a new IV.
	if got := v.Process(build("a")); got.reason != "replayed" {
		t.Fatal("re-read:", got.reason)
	}
	// Signed, so only a key holder could build it, and still refused.
	if got := v.Process(build("evil")); got.reason != "replay_conflict" {
		t.Fatal("changed content:", got.reason)
	}

	// A restart must change none of that.
	v.store.close()
	v = open()
	if got := v.Process(first); got.reason != "replayed" {
		t.Fatal("after restart:", got.reason)
	}
	got := v.Process(build("evil"))
	if got.reason != "replay_conflict" || strings.Contains(string(got.line), "evil") {
		t.Fatal("after restart, changed content:", got.reason)
	}
}

func TestJournalSurvivesATornWrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	store, _ := openIdentityStore(dir, 100, now)
	if err := store.commit([]identity{{[16]byte{1}, [16]byte{2}}, {[16]byte{3}, [16]byte{4}}}, now); err != nil {
		t.Fatal(err)
	}
	store.close()
	path := filepath.Join(dir, journalName(dayNumber(now)))
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	file.Write([]byte{9, 9, 9})
	file.Close()
	again, err := openIdentityStore(dir, 100, now)
	if err != nil {
		t.Fatal(err)
	}
	defer again.close()
	if again.size() != 2 {
		t.Fatalf("%d entries", again.size())
	}
}

func TestJournalDropsCorruptRecords(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	store, _ := openIdentityStore(dir, 100, now)
	store.commit([]identity{{[16]byte{1}, [16]byte{2}}, {[16]byte{3}, [16]byte{4}}}, now)
	store.close()
	path := filepath.Join(dir, journalName(dayNumber(now)))
	data, _ := os.ReadFile(path)
	data[0] ^= 0xff
	os.WriteFile(path, data, 0o600)
	again, _ := openIdentityStore(dir, 100, now)
	defer again.close()
	if again.size() != 1 {
		t.Fatalf("%d entries", again.size())
	}
}

func TestJournalExpiresOldDays(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-(journalDays + 1) * 24 * time.Hour)
	store, _ := openIdentityStore(dir, 100, old)
	store.commit([]identity{{[16]byte{1}, [16]byte{2}}}, old)
	store.close()
	again, _ := openIdentityStore(dir, 100, now)
	defer again.close()
	if again.size() != 0 {
		t.Fatal("old day kept")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, journalName(dayNumber(old)))); len(files) != 0 {
		t.Fatal("old file kept")
	}
	if journalDays*24*time.Hour <= maxEventAge {
		t.Fatal("the journal must outlive the oldest event accepted")
	}
}

func TestJournalIsBoundedInMemory(t *testing.T) {
	now := time.Now()
	store, _ := openIdentityStore(t.TempDir(), 2, now)
	defer store.close()
	store.commit([]identity{{[16]byte{1}, [16]byte{1}}, {[16]byte{2}, [16]byte{1}}}, now.Add(-24*time.Hour))
	store.commit([]identity{{[16]byte{3}, [16]byte{1}}}, now)
	if store.size() != 1 {
		t.Fatalf("%d entries", store.size())
	}
}

func TestNoJournalNoService(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	if _, err := openIdentityStore(blocker, 10, time.Now()); err == nil {
		t.Fatal("started without a journal")
	}
}

func TestJournalHoldsNoContent(t *testing.T) {
	dir := t.TempDir()
	store, _ := openIdentityStore(dir, 10, time.Now())
	keys := testKeys(t)
	v := NewVerifier(keys, store)
	in, _ := good(t)
	result := v.Process(in)
	commit(t, v, result)
	store.close()
	data, _ := os.ReadFile(filepath.Join(dir, journalName(dayNumber(time.Now()))))
	if len(data) != recordSize || bytes.Contains(data, []byte(secret)) || bytes.Contains(data, []byte(testUID)) {
		t.Fatalf("%d bytes", len(data))
	}
}

func TestInvalidUTF8PlaintextStaysValidJSON(t *testing.T) {
	keys := testKeys(t)
	ctx := ref()
	result := newTestVerifier(t, keys).Process(line(t, ctx, map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", "ab\xff\xfe")}, nil))
	if result.reason != "accepted" || !json.Valid(result.line) {
		t.Fatalf("%s %q", result.reason, result.line)
	}
}

func TestNullEventDataIsSafe(t *testing.T) {
	keys := testKeys(t)
	ctx := ref()
	in := line(t, ctx, map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret)}, nil)
	if got := newTestVerifier(t, keys).Process(in); got.reason != "accepted" {
		t.Fatal(got.reason)
	}
}

func TestPanicDeadLettersOneEvent(t *testing.T) {
	in, keys := good(t)
	v := newTestVerifier(t, keys)
	v.decrypt = func(enc, iv, ct []byte) ([]byte, error) { panic("forced") }
	got := v.Process(in)
	if got.reason != "verifier_panic" || !json.Valid(got.line) || strings.Contains(string(got.line), secret) {
		t.Fatalf("%s %s", got.reason, got.line)
	}
}

// NIST SP 800-38A, F.5.5, CTR-AES256.Decrypt, blocks 1 and 2.
func TestNISTKnownAnswer(t *testing.T) {
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ct, _ := hex.DecodeString("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5")
	want := "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
	got, err := decryptCTR(key, iv, ct)
	if err != nil || hex.EncodeToString(got) != want {
		t.Fatalf("%x %v", got, err)
	}
}

func TestCounterWrapRejected(t *testing.T) {
	high := bytes.Repeat([]byte{0xff}, 16)
	if !counterWraps(high, 17) || counterWraps(high, 16) || counterWraps(make([]byte, 16), maxCiphertext) {
		t.Fatal("wrong boundary")
	}
	keys := testKeys(t)
	ctx := ref()
	in := line(t, ctx, map[string]any{"CommandLine": sealIV(t, keys, "k1", ctx, "CommandLine", strings.Repeat("x", 40), high)}, nil)
	v := newTestVerifier(t, keys)
	v.decrypt = func(enc, iv, ct []byte) ([]byte, error) { t.Fatal("decrypt ran"); return nil, nil }
	if got := v.Process(in); got.reason != "counter_wrap" {
		t.Fatal(got.reason)
	}
}

func linuxKeys(t testing.TB) map[string]keyPair {
	t.Helper()
	keys := testKeys(t)
	keys["k2"] = keyPair{enc: bytes.Repeat([]byte{3}, 32), mac: bytes.Repeat([]byte{4}, 32)}
	return keys
}

func linuxRef(channel string) eventRef {
	return eventRef{Channel: channel, EventID: "1", RecordID: "1793470000000000", EventUID: testUID}
}

func wrapWith(t testing.TB, keys map[string]keyPair, keyID string, event map[string]any) []byte {
	t.Helper()
	body, err := marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"v": envelopeLabel, "k": keyID, "event_uid": event["event_uid"].(string), "body": string(body),
		"mac": base64.StdEncoding.EncodeToString(envelopeMAC(keys[keyID].mac, keyID, body))})
	out, _ := json.Marshal(map[string]any{"raw": string(raw), "raw_sha256": "x", "raw_length": len(raw)})
	return out
}

func TestLinuxEventAcceptedAndOpened(t *testing.T) {
	keys := linuxKeys(t)
	for _, channel := range []string{linuxJournal, linuxPackage} {
		ctx := linuxRef(channel)
		sealed := map[string]any{"Message": seal(t, keys, "k2", ctx, "Message", secret)}
		result := newTestVerifier(t, keys).Process(wrapWith(t, keys, "k2", eventBody(ctx, sealed, map[string]any{"Identifier": "sudo"})))
		if result.dead || result.reason != "accepted" {
			t.Fatalf("%s: %s", channel, result.reason)
		}
		if !strings.Contains(string(result.line), secret) || !strings.Contains(string(result.line), "Identifier") {
			t.Fatal("the opened event is incomplete")
		}
	}
}

func TestLinuxTextMustBeSealed(t *testing.T) {
	keys := linuxKeys(t)
	ctx := linuxRef(linuxJournal)
	for _, name := range []string{"Message", "CommandLine"} {
		result := newTestVerifier(t, keys).Process(wrapWith(t, keys, "k2", eventBody(ctx, nil, map[string]any{name: secret})))
		if result.reason != "unsealed_restricted" || bytes.Contains(result.line, []byte(secret)) {
			t.Fatalf("%s: %s", name, result.reason)
		}
	}
}

// A host that holds one agent's key cannot speak for the other host.
func TestKeysAreBoundToTheirSource(t *testing.T) {
	keys := linuxKeys(t)
	linux := linuxRef(linuxJournal)
	cases := map[string][]byte{
		"Windows key on a Linux channel":   wrapWith(t, keys, "k1", eventBody(linux, map[string]any{"Message": seal(t, keys, "k1", linux, "Message", secret)}, nil)),
		"Windows key, empty Linux event":   wrapWith(t, keys, "k1", eventBody(linux, nil, nil)),
		"Linux key on a Windows channel":   wrapWith(t, keys, "k2", eventBody(ref(), map[string]any{"CommandLine": seal(t, keys, "k2", ref(), "CommandLine", secret)}, nil)),
		"Linux field key, Windows wrapper": wrapWith(t, keys, "k1", eventBody(ref(), map[string]any{"CommandLine": seal(t, keys, "k2", ref(), "CommandLine", secret)}, nil)),
		"Windows field key, Linux wrapper": wrapWith(t, keys, "k2", eventBody(linux, map[string]any{"Message": seal(t, keys, "k1", linux, "Message", secret)}, nil)),
	}
	for name, input := range cases {
		result := newTestVerifier(t, keys).Process(input)
		if !result.dead || result.reason != "key_scope" {
			t.Errorf("%s: %s", name, result.reason)
		}
		if bytes.Contains(result.line, []byte(secret)) {
			t.Errorf("%s: plaintext in a dead letter", name)
		}
	}
}

func TestWindowsEventsUnchangedWithALinuxKeyLoaded(t *testing.T) {
	keys := linuxKeys(t)
	ctx := ref()
	sealed := map[string]any{"CommandLine": seal(t, keys, "k1", ctx, "CommandLine", secret)}
	if result := newTestVerifier(t, keys).Process(wrap(t, keys, eventBody(ctx, sealed, nil))); result.reason != "accepted" {
		t.Fatal(result.reason)
	}
}

func TestLinuxReplayIsRefused(t *testing.T) {
	keys := linuxKeys(t)
	v := newTestVerifier(t, keys)
	ctx := linuxRef(linuxJournal)
	input := wrapWith(t, keys, "k2", eventBody(ctx, map[string]any{"Message": seal(t, keys, "k2", ctx, "Message", secret)}, nil))
	commit(t, v, v.Process(input))
	if result := v.Process(input); !result.skip || result.reason != "replayed" {
		t.Fatal(result.reason)
	}
	other := wrapWith(t, keys, "k2", eventBody(ctx, map[string]any{"Message": seal(t, keys, "k2", ctx, "Message", "different")}, nil))
	if result := v.Process(other); result.reason != "replay_conflict" {
		t.Fatal(result.reason)
	}
}

func TestPassesExistingDeadLetter(t *testing.T) {
	in := []byte(`{"dlq":{"reason":"size"},"kafka":{"offset":1}}`)
	got := newTestVerifier(t, testKeys(t)).Process(in)
	if !strings.Contains(string(got.line), `"reason":"size"`) || !strings.Contains(string(got.line), `"offset":1`) {
		t.Fatalf("%s", got.line)
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a, b := hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if _, err := loadKeys(write("good", `{"k1_enc":"`+a+`","k1_mac":"`+b+`"}`, 0o640)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"same":    `{"k1_enc":"` + a + `","k1_mac":"` + a + `"}`,
		"short":   `{"k1_enc":"aa","k1_mac":"` + b + `"}`,
		"half":    `{"k1_enc":"` + a + `"}`,
		"empty":   `{}`,
		"unknown": `{"other":"x"}`,
		"text":    `nope`,
	} {
		if _, err := loadKeys(write(name, body, 0o640)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := loadKeys(write("open", `{"k1_enc":"`+a+`","k1_mac":"`+b+`"}`, 0o644)); err == nil {
			t.Fatal("world-readable key file accepted")
		}
	}
	if _, err := loadKeys(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func FuzzProcess(f *testing.F) {
	in, keys := good(f)
	f.Add(in)
	f.Add([]byte(`{"raw":"{}"}`))
	f.Add([]byte(`{"dlq":{}}`))
	store, err := openIdentityStore(f.TempDir(), 1000, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(store.close)
	v := NewVerifier(keys, store)
	f.Fuzz(func(t *testing.T, data []byte) {
		result := v.Process(data)
		if result.skip {
			return
		}
		if !json.Valid(result.line) {
			t.Fatalf("invalid output for %q", data)
		}
		// Seeds differ between workers, so this recomputes the MAC rather than comparing to a seed.
		if result.reason == "accepted" {
			var top struct{ Raw string }
			json.Unmarshal(data, &top)
			env, reason := parseEnvelope(top.Raw)
			mac, _ := decodeStrict(env.MAC)
			if reason != "" || !hmac.Equal(mac, envelopeMAC(keys["k1"].mac, "k1", []byte(env.Body))) {
				t.Fatal("accepted without a valid MAC")
			}
		}
	})
}

func welch(a, b []float64) float64 {
	stats := func(x []float64) (mean, variance float64) {
		sort.Float64s(x)
		x = x[:len(x)*9/10]
		for _, v := range x {
			mean += v
		}
		mean /= float64(len(x))
		for _, v := range x {
			variance += (v - mean) * (v - mean)
		}
		return mean, variance / float64(len(x)-1)
	}
	ma, va := stats(a)
	mb, vb := stats(b)
	n := float64(len(a)) * .9
	return math.Abs(ma-mb) / math.Sqrt(va/n+vb/n)
}

// TestTiming needs SIEM_TIMING=1. The 1 MiB case is the gate, with bytes.Equal as a control that
// must be detected. 32-byte figures are logged only, because this host's noise can exceed them.
func TestTiming(t *testing.T) {
	if os.Getenv("SIEM_TIMING") == "" {
		t.Skip("set SIEM_TIMING=1")
	}
	measure := func(compare func(a, b []byte) bool, size, samples int) float64 {
		a := make([]byte, size)
		rand.Read(a)
		first, last := bytes.Clone(a), bytes.Clone(a)
		first[0] ^= 0xff
		last[size-1] ^= 0xff
		var groupA, groupB []float64
		var coin [1]byte
		for i := 0; i < samples; i++ {
			rand.Read(coin[:])
			b := first
			if coin[0]&1 == 1 {
				b = last
			}
			start := time.Now()
			compare(a, b)
			took := float64(time.Since(start))
			if coin[0]&1 == 1 {
				groupB = append(groupB, took)
			} else {
				groupA = append(groupA, took)
			}
		}
		return welch(groupA, groupB)
	}
	if got := measure(bytes.Equal, 1<<20, 4000); got < 4.5 {
		t.Fatalf("control not detected, t=%.1f, so this harness cannot see a leak", got)
	} else {
		t.Logf("bytes.Equal 1 MiB: t=%.1f (control)", got)
	}
	got := measure(macMatches, 1<<20, 4000)
	t.Logf("macMatches 1 MiB: t=%.1f", got)
	if got >= 4.5 {
		t.Fatalf("macMatches leak at 1 MiB, t=%.1f", got)
	}
	t.Logf("macMatches 32 bytes: t=%.1f (information only)", measure(macMatches, 32, 400000))
}
