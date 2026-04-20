// relay_test.go — integration tests for the HTTP + WebSocket surface.
//
// Spins up a real httptest.Server wired to a fresh Hub + Mailbox per
// test and drives it with a gorilla/websocket client.  Covers:
//
//   - HandleSend happy path (store when offline, push when online).
//   - Envelope validation (size cap, version byte, too-short).
//   - Per-recipient rate limit (the audit-relevant one — an attacker
//     rotating IPs can't bypass this).
//   - WS auth: signature, timestamp freshness, replay, and L4
//     cross-restart replay protection.
//   - M6 end-to-end: queued envelopes survive a simulated relay
//     restart AND an incomplete delivery.
//   - /healthz sanity.

package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── Fixture ────────────────────────────────────────────────────────────

type testRelay struct {
	srv    *httptest.Server
	hub    *Hub
	mbox   *Mailbox
	dbPath string
}

func (r *testRelay) Close() {
	r.hub.CloseAll()
	r.srv.Close()
	r.mbox.Close()
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()
	return newTestRelayOpt(t, false)
}

// newTestRelayOpt lets tests enable trustProxy so distinct X-Forwarded-For
// values bypass the per-IP rate limit (needed for tests that want to
// exercise the per-recipient or WS-auth limits in isolation).
func newTestRelayOpt(t *testing.T, trustProxy bool) *testRelay {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	mbox, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	hub := NewHub(mbox, trustProxy)
	pub, priv := testRelayOnionKey(t)
	hub.relayX25519Pub = pub
	hub.relayX25519Priv = priv

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/send", hub.HandleSend)
	mux.HandleFunc("/v1/receive", hub.HandleReceive)
	mux.HandleFunc("POST /v1/forward", hub.HandleForward)
	mux.HandleFunc("GET /v1/relay_info", hub.HandleRelayInfo)
	mux.HandleFunc("POST /v1/forward-onion", hub.HandleForwardOnion)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "impl": "go"})
	})

	srv := httptest.NewServer(mux)
	return &testRelay{srv: srv, hub: hub, mbox: mbox, dbPath: dbPath}
}

// The relay onion key is X25519.  Tests don't exercise onion routing,
// so a 32-byte random buffer (never referenced) is enough.
func testRelayOnionKey(t *testing.T) (*[32]byte, *[32]byte) {
	t.Helper()
	var pub, priv [32]byte
	if _, err := cryptorand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	copy(pub[:], priv[:]) // placeholder — never used on the wire here.
	return &pub, &priv
}

// ── Crypto helpers for test clients ────────────────────────────────────

type testPeer struct {
	idB64 string
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
}

func newTestPeer(t *testing.T) testPeer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testPeer{
		idB64: base64.RawURLEncoding.EncodeToString(pub),
		pub:   pub,
		priv:  priv,
	}
}

func (p testPeer) signAuth(ts int64) string {
	msg := fmt.Sprintf("RELAY1|%s|%d", p.idB64, ts)
	sig := ed25519.Sign(p.priv, []byte(msg))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// ── Envelope builder ───────────────────────────────────────────────────

func buildEnvelope(to testPeer, bodyLen int) []byte {
	if bodyLen < envelopeMinSize {
		bodyLen = envelopeMinSize
	}
	out := make([]byte, bodyLen)
	cryptorand.Read(out)
	out[0] = envelopeVersion
	copy(out[1:33], to.pub)
	return out
}

// ── WS helpers ─────────────────────────────────────────────────────────

func toWsURL(httpURL, path string) string {
	u, _ := url.Parse(httpURL)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = path
	return u.String()
}

// authResult collects everything a test might want from the post-auth
// handshake: the final auth_ok / error reply JSON, plus any binary
// envelopes the relay pushed before auth_ok (queued mailbox delivery
// happens *before* the confirmation frame — see HandleReceive).
type authResult struct {
	Reply  map[string]any
	Stored [][]byte
}

// dialAndAuth dials /v1/receive, sends the auth JSON, and reads frames
// until it receives a text frame (auth_ok or error).  Binary frames seen
// on the way in are stored envelopes being drained.  Returns the live
// conn so the caller can keep reading.
func dialAndAuth(t *testing.T, r *testRelay, p testPeer, ts int64) (*websocket.Conn, authResult) {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(toWsURL(r.srv.URL, "/v1/receive"), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	auth := map[string]any{
		"peer_id": p.idB64,
		"ts":      ts,
		"sig":     p.signAuth(ts),
	}
	if err := conn.WriteJSON(auth); err != nil {
		conn.Close()
		t.Fatalf("ws write auth: %v", err)
	}

	out := authResult{}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			// For replay/bad-sig cases the server closes before sending
			// any text; we've seen neither auth_ok nor error. Return
			// whatever we have — the test asserts on Reply.
			return conn, out
		}
		if msgType == websocket.BinaryMessage {
			out.Stored = append(out.Stored, append([]byte{}, data...))
			continue
		}
		// Text frame — either auth_ok or an error JSON.
		if err := json.Unmarshal(data, &out.Reply); err != nil {
			t.Fatalf("ws text frame not JSON: %s", string(data))
		}
		return conn, out
	}
}

// ── 1. /v1/send stores when recipient is offline ──────────────────────

func TestHandleSend_StoresWhenRecipientOffline(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, 200)

	resp, err := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if r.mbox.Count() != 1 {
		t.Fatalf("mailbox count %d, want 1", r.mbox.Count())
	}
}

// ── 2. /v1/send delivers live to an online recipient ──────────────────

func TestHandleSend_DeliversToOnlinePeer(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	conn, result := dialAndAuth(t, r, bob, time.Now().UnixMilli())
	defer conn.Close()
	if result.Reply["type"] != "auth_ok" {
		t.Fatalf("auth: %v", result.Reply)
	}

	env := buildEnvelope(bob, 300)
	resp, err := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, body, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if msgType != websocket.BinaryMessage {
		t.Fatalf("expected binary frame, got type %d", msgType)
	}
	if !bytes.Equal(body, env) {
		t.Fatalf("payload mismatch (got %d bytes)", len(body))
	}
}

// ── 3. Oversized envelope → 413 ───────────────────────────────────────

func TestHandleSend_RejectsOversizedEnvelope(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, maxEnvelopeBytes+100)
	resp, err := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
}

// ── 4. Malformed envelope → 400 ───────────────────────────────────────

func TestHandleSend_RejectsMalformedEnvelope(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	cases := []struct {
		name string
		env  []byte
	}{
		{"too-short", []byte{0x01, 0x02}},
		{"wrong-version", append([]byte{0x99}, bytes.Repeat([]byte{0}, 32)...)},
		{"empty", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(c.env))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
		})
	}
}

// ── 5. Per-recipient rate limit (audit Fix #10) ───────────────────────
// trustProxy=true so distinct X-Forwarded-For IPs bypass the per-IP cap;
// that's the threat model the per-recipient cap exists to address.

func TestHandleSend_PerRecipientRateLimit(t *testing.T) {
	r := newTestRelayOpt(t, true)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, 128)

	sendAs := func(ip string) int {
		req, _ := http.NewRequest("POST", r.srv.URL+"/v1/send", bytes.NewReader(env))
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Fire exactly the per-recipient cap worth, each from a distinct IP so
	// per-IP rate limiting stays idle.
	for i := 0; i < recipientRateLimitPerMin; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if s := sendAs(ip); s != http.StatusOK {
			t.Fatalf("POST #%d status %d, want 200", i, s)
		}
	}
	if s := sendAs("10.255.255.255"); s != http.StatusTooManyRequests {
		t.Fatalf("final status %d, want 429 (per-recipient cap)", s)
	}
}

// ── 6. WS auth: bad signature → auth failed, closed ───────────────────

func TestWsAuth_RejectsBadSignature(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	p := newTestPeer(t)
	conn, _, err := websocket.DefaultDialer.Dial(toWsURL(r.srv.URL, "/v1/receive"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	auth := map[string]any{
		"peer_id": p.idB64,
		"ts":      time.Now().UnixMilli(),
		"sig":     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64)),
	}
	if err := conn.WriteJSON(auth); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, _ := conn.ReadMessage()
	var got map[string]any
	json.Unmarshal(data, &got)
	if e, _ := got["error"].(string); !strings.Contains(e, "auth failed") {
		t.Fatalf("expected 'auth failed', got %v", got)
	}
}

// ── 7. WS auth: stale timestamp → timestamp outside window ────────────

func TestWsAuth_RejectsStaleTimestamp(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	p := newTestPeer(t)
	stale := time.Now().UnixMilli() - 5*60*1000 // 5 minutes ago
	_, result := dialAndAuth(t, r, p, stale)

	if e, _ := result.Reply["error"].(string); !strings.Contains(e, "timestamp outside window") {
		t.Fatalf("expected timestamp error, got %v", result.Reply)
	}
}

// ── 8. WS auth: replay within the window → auth replay ────────────────

func TestWsAuth_RejectsReplay(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	p := newTestPeer(t)
	ts := time.Now().UnixMilli()

	c1, r1 := dialAndAuth(t, r, p, ts)
	if r1.Reply["type"] != "auth_ok" {
		t.Fatalf("first auth: %v", r1.Reply)
	}
	c1.Close()

	_, r2 := dialAndAuth(t, r, p, ts)
	if e, _ := r2.Reply["error"].(string); !strings.Contains(e, "auth replay") {
		t.Fatalf("expected replay, got %v", r2.Reply)
	}
}

// ── 9. L4: auth replay survives relay restart ─────────────────────────
// The audit's actual concern — pre-L4 this succeeded because seenAuth
// was an in-memory map.  Now the row persists in SQLite.

func TestWsAuth_ReplayPersistsAcrossRelayRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")

	bootHub := func() *testRelay {
		mbox, err := NewMailbox(dbPath)
		if err != nil {
			t.Fatalf("mbox: %v", err)
		}
		hub := NewHub(mbox, false)
		pub, priv := testRelayOnionKey(t)
		hub.relayX25519Pub, hub.relayX25519Priv = pub, priv
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/receive", hub.HandleReceive)
		srv := httptest.NewServer(mux)
		return &testRelay{srv: srv, hub: hub, mbox: mbox, dbPath: dbPath}
	}

	p := newTestPeer(t)
	ts := time.Now().UnixMilli()

	r1 := bootHub()
	c1, rep1 := dialAndAuth(t, r1, p, ts)
	if rep1.Reply["type"] != "auth_ok" {
		r1.Close()
		t.Fatalf("first auth: %v", rep1.Reply)
	}
	c1.Close()
	r1.Close() // "relay crashes"

	r2 := bootHub() // relay restarts on same DB
	defer r2.Close()
	_, rep2 := dialAndAuth(t, r2, p, ts)
	if e, _ := rep2.Reply["error"].(string); !strings.Contains(e, "auth replay") {
		t.Fatalf("replay across restart: got %v — L4 regression", rep2.Reply)
	}
}

// ── 10. M6 end-to-end: queued envelopes survive relay restart ─────────

func TestMailboxDelivery_SurvivesRelayRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")

	bootHub := func() *testRelay {
		mbox, err := NewMailbox(dbPath)
		if err != nil {
			t.Fatalf("mbox: %v", err)
		}
		hub := NewHub(mbox, false)
		pub, priv := testRelayOnionKey(t)
		hub.relayX25519Pub, hub.relayX25519Priv = pub, priv
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/send", hub.HandleSend)
		mux.HandleFunc("/v1/receive", hub.HandleReceive)
		srv := httptest.NewServer(mux)
		return &testRelay{srv: srv, hub: hub, mbox: mbox, dbPath: dbPath}
	}

	bob := newTestPeer(t)

	r1 := bootHub()
	// Store two envelopes for Bob (offline).
	var wantEnvelopes [][]byte
	for i := 0; i < 2; i++ {
		env := buildEnvelope(bob, 128+i*8)
		wantEnvelopes = append(wantEnvelopes, env)
		resp, err := http.Post(r1.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
		if err != nil {
			t.Fatalf("POST #%d: %v", i, err)
		}
		resp.Body.Close()
	}
	if r1.mbox.Count() != 2 {
		r1.Close()
		t.Fatalf("count before crash: %d, want 2", r1.mbox.Count())
	}
	r1.Close()

	// Fresh relay on same DB — simulates a crash/restart.
	r2 := bootHub()
	defer r2.Close()

	conn, result := dialAndAuth(t, r2, bob, time.Now().UnixMilli())
	defer conn.Close()
	if result.Reply["type"] != "auth_ok" {
		t.Fatalf("auth after restart: %v", result.Reply)
	}
	if len(result.Stored) != 2 {
		t.Fatalf("stored envelopes delivered: %d, want 2 (M6 regression)", len(result.Stored))
	}
	// Content check: the set of delivered payloads matches what we POSTed
	// (order may differ thanks to secureShuffleEnv).
	wantSet := map[string]bool{}
	for _, e := range wantEnvelopes {
		wantSet[string(e)] = true
	}
	for _, got := range result.Stored {
		if !wantSet[string(got)] {
			t.Fatalf("delivered payload not in expected set")
		}
	}
}

// ── 11. M6: incomplete delivery (WS drops mid-loop) leaves rest queued ─
// We can't easily force a crash mid-loop in-process, but the mailbox-
// level test TestMailbox_M6_PartialConfirmLeavesRestForRedelivery
// covers that case.  This integration test validates the *end state*:
// after a successful full delivery, the mailbox is empty.

func TestMailboxDelivery_EmptiesAfterSuccessfulDelivery(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, 128)
	resp, _ := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
	resp.Body.Close()

	conn, res := dialAndAuth(t, r, bob, time.Now().UnixMilli())
	defer conn.Close()
	if res.Reply["type"] != "auth_ok" || len(res.Stored) != 1 {
		t.Fatalf("delivery: reply=%v stored=%d", res.Reply, len(res.Stored))
	}
	// Give the handler a tick to run ConfirmDelivered.
	time.Sleep(50 * time.Millisecond)
	if c := r.mbox.Count(); c != 0 {
		t.Fatalf("mailbox not drained: %d", c)
	}
}

// ── 12. Two peers — A's envelopes only land at A ──────────────────────

func TestHandleSend_RoutesToCorrectRecipient(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	bob := newTestPeer(t)

	// Alice online; envelope addressed to Bob must NOT land on Alice's WS.
	conn, res := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer conn.Close()
	if res.Reply["type"] != "auth_ok" {
		t.Fatalf("alice auth: %v", res.Reply)
	}

	env := buildEnvelope(bob, 128)
	resp, _ := http.Post(r.srv.URL+"/v1/send", "application/octet-stream", bytes.NewReader(env))
	resp.Body.Close()

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatalf("alice received a frame addressed to bob")
	}
	// Envelope was stored for bob, not dropped.
	if r.mbox.Count() != 1 {
		t.Fatalf("expected envelope stored for bob, got %d", r.mbox.Count())
	}
}

// ── 13. /v1/forward SSRF pre-check rejects private / loopback hosts ───

func TestHandleForward_RejectsSsrfTargets(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, 128)

	cases := []struct {
		name string
		host string
	}{
		{"localhost-name", "localhost:8443"},
		{"ip6-localhost",  "ip6-localhost:8443"},
		{"loopback-ip",    "127.0.0.1:8443"},
		{"private-10",     "10.0.0.1:8443"},
		{"private-192",    "192.168.1.1:8443"},
		{"cgnat",          "100.64.0.1:8443"},
		{"link-local",     "169.254.0.1:8443"},
		{"ipv6-loopback",  "[::1]:8443"},
		{"unspecified",    "0.0.0.0:8443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", r.srv.URL+"/v1/forward",
				bytes.NewReader(env))
			req.Header.Set("X-Forward-To", c.host)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d for %s, want 403", resp.StatusCode, c.host)
			}
		})
	}
}

// ── 14. /v1/forward bad-input handling ────────────────────────────────

func TestHandleForward_RejectsBadInputs(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	bob := newTestPeer(t)
	env := buildEnvelope(bob, 128)

	// Missing X-Forward-To.
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/forward", bytes.NewReader(env))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no header: status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Header with illegal characters (slash / space).
	req, _ = http.NewRequest("POST", r.srv.URL+"/v1/forward", bytes.NewReader(env))
	req.Header.Set("X-Forward-To", "evil.example.com/../admin")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad chars: status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Unresolvable hostname — should 403 via "cannot resolve host".  Use
	// the RFC 2606 test TLD .invalid which MUST NOT resolve.
	req, _ = http.NewRequest("POST", r.srv.URL+"/v1/forward", bytes.NewReader(env))
	req.Header.Set("X-Forward-To", "nonexistent-host-for-tests.invalid:8443")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unresolvable: status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// ── 15. M8 audit-#2: safeForwardClient blocks rebinding to loopback ───
// Even if the pre-check passed (hostname resolves to a public IP), the
// connect-time dialer re-validates every candidate IP against ipSafe.
// We force the dialer to see a loopback IP via a synthetic resolver
// shim (by passing it addr="127.0.0.1:port") and assert it errors out
// with an SSRF reason.  That's the path an actual DNS rebinding attack
// would exercise: DNS A record flips to 127.0.0.1 between pre-check
// and dial.

func TestSafeForwardClient_RefusesLoopbackAtConnect(t *testing.T) {
	// Spin up a local HTTP server — the DialContext under test must
	// refuse to connect to 127.0.0.1:* even though the listener is alive.
	bg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("safeForwardClient connected to loopback — M8 regression")
	}))
	defer bg.Close()

	client := safeForwardClient()
	// http://127.0.0.1:<port>/... should be blocked by the dialer.
	_, err := client.Get(bg.URL + "/anything")
	if err == nil {
		t.Fatalf("GET to loopback succeeded (M8 regression)")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("expected SSRF error, got: %v", err)
	}
}

// ── 16. ipSafe: rejects every private address family ──────────────────

func TestIpSafe(t *testing.T) {
	bad := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.0.1",
		"0.0.0.0",
		"100.64.0.1",
		"::1",
		"fe80::1",
		"::ffff:127.0.0.1",
	}
	good := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, ipStr := range bad {
		ip := net.ParseIP(ipStr)
		if _, ok := ipSafe(ip); ok {
			t.Fatalf("ipSafe(%q) = safe, want unsafe", ipStr)
		}
	}
	for _, ipStr := range good {
		ip := net.ParseIP(ipStr)
		if _, ok := ipSafe(ip); !ok {
			t.Fatalf("ipSafe(%q) = unsafe, want safe", ipStr)
		}
	}
}

// ── 17. /healthz returns 200 + version tag ────────────────────────────

func TestHealthz(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	resp, err := http.Get(r.srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["impl"] != "go" {
		t.Fatalf("impl field: %v", body["impl"])
	}
}
