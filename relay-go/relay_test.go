// relay_test.go — integration tests for the HTTP + WebSocket surface.
//
// Spins up a real httptest.Server wired to a fresh Hub + Mailbox per
// test and drives it with a gorilla/websocket client.  Covers:
//
//   - HandleSend happy path (store when offline, push when online).
//   - Envelope validation (size cap, version byte, too-short).
//   - Per-recipient rate limit (an attacker rotating IPs can't bypass
//     this).
//   - WS auth: signature, timestamp freshness, replay, and cross-restart
//     replay protection.
//   - End-to-end: queued envelopes survive a simulated relay restart AND
//     an incomplete delivery.
//   - /healthz sanity.

package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
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
	hub.InitPush(priv)

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

// The relay onion key is X25519.  Most tests don't exercise onion
// routing, but the onion tests below wrap envelopes to this pubkey, so
// we generate a real keypair here — the pub half must actually match.
func testRelayOnionKey(t *testing.T) (*[32]byte, *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey: %v", err)
	}
	return pub, priv
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

// ── 5. Per-recipient rate limit ──────────────────────────────────────
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

// ── 9. Auth replay survives relay restart ─────────────────────────────
// With the seenAuth row persisted in SQLite, a relay restart within the
// replay window still rejects captured auth tuples.

func TestWsAuth_ReplayPersistsAcrossRelayRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")

	// Arch-review #8 makes the auth-nonce HMAC key a function of the
	// relay's onion private key — a production-faithful "restart on
	// the same DB" test must also restore the same onion key, the
	// way loadOrCreateRelayKey would.  Generate once, reuse both boots.
	pub, priv := testRelayOnionKey(t)

	bootHub := func() *testRelay {
		mbox, err := NewMailbox(dbPath)
		if err != nil {
			t.Fatalf("mbox: %v", err)
		}
		hub := NewHub(mbox, false)
		hub.relayX25519Pub, hub.relayX25519Priv = pub, priv
		hub.InitPush(priv)
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
		t.Fatalf("replay across restart: got %v — regression", rep2.Reply)
	}
}

// ── 10. End-to-end: queued envelopes survive relay restart ────────────

func TestMailboxDelivery_SurvivesRelayRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "relay.db")

	// Arch-review #8: same constraint as TestWsAuth_ReplayPersists
	// — the HMAC key under mailbox row lookups is derived from the
	// onion key, so the test must reuse it across reboots the way
	// loadOrCreateRelayKey would.
	pub, priv := testRelayOnionKey(t)

	bootHub := func() *testRelay {
		mbox, err := NewMailbox(dbPath)
		if err != nil {
			t.Fatalf("mbox: %v", err)
		}
		hub := NewHub(mbox, false)
		hub.relayX25519Pub, hub.relayX25519Priv = pub, priv
		hub.InitPush(priv)
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
		t.Fatalf("stored envelopes delivered: %d, want 2", len(result.Stored))
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

// ── 11. Incomplete delivery (WS drops mid-loop) leaves rest queued ────
// We can't easily force a crash mid-loop in-process, but the mailbox-
// level test TestMailbox_PartialConfirmLeavesRestForRedelivery covers
// that case.  This integration test validates the *end state*: after a
// successful full delivery, the mailbox is empty.

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

// ── 15. safeForwardClient blocks rebinding to loopback ────────────────
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
		t.Fatalf("safeForwardClient connected to loopback — regression")
	}))
	defer bg.Close()

	client := safeForwardClient()
	// http://127.0.0.1:<port>/... should be blocked by the dialer.
	_, err := client.Get(bg.URL + "/anything")
	if err == nil {
		t.Fatalf("GET to loopback succeeded (regression)")
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

// ── 16b. --cert + --key path uses ListenAndServeTLS ───────────────────
// Spin up a relay listening on TLS with a self-signed cert and verify
// that an HTTPS client (configured to trust the test cert) reaches
// /healthz.  A plain HTTP client against the same port must fail.

func TestRelay_NativeTlsEndpointServes(t *testing.T) {
	cert, key := makeSelfSignedCertPEM(t)

	// Build the same handler mux main.go uses.  We can't call main()
	// directly, so stand up a parallel http.Server.
	dbPath := filepath.Join(t.TempDir(), "tls.db")
	mbox, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("mbox: %v", err)
	}
	defer mbox.Close()
	hub := NewHub(mbox, false)
	pub, priv := testRelayOnionKey(t)
	hub.relayX25519Pub, hub.relayX25519Priv = pub, priv
	hub.InitPush(priv)
	defer hub.CloseAll()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "impl": "go"})
	})

	// Build a TLS Certificate from the PEM we just produced.
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	// httptest.NewUnstartedServer lets us wire the TLS config ourselves.
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	defer srv.Close()

	// Dial with a client that trusts our self-signed cert.
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(cert); !ok {
		t.Fatalf("AppendCertsFromPEM")
	}
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := tlsClient.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("TLS GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS status %d, want 200", resp.StatusCode)
	}

	// Plaintext client against the same TLS port: Go's TLS server
	// either errors or replies with a 400 "client sent an HTTP request
	// to an HTTPS server" message.  Either way the plaintext request
	// must NOT see our real /healthz JSON payload.
	plainURL := strings.Replace(srv.URL, "https://", "http://", 1)
	plain := &http.Client{Timeout: 1 * time.Second}
	plainResp, plainErr := plain.Get(plainURL + "/healthz")
	if plainErr == nil {
		defer plainResp.Body.Close()
		// Hard check: status must NOT be 200, and body must NOT contain
		// our healthz JSON keys.
		if plainResp.StatusCode == http.StatusOK {
			t.Fatalf("plain HTTP got 200 from TLS endpoint (regression)")
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(plainResp.Body)
		if strings.Contains(body.String(), `"impl"`) {
			t.Fatalf("plain HTTP leaked /healthz JSON — server isn't actually TLS-only")
		}
	}
}

// makeSelfSignedCertPEM builds a 2048-bit RSA self-signed cert + key in
// PEM form, valid for the test duration.  Used to exercise TLS without
// depending on any external CA.
func makeSelfSignedCertPEM(t *testing.T) (cert []byte, key []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	serial, _ := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "peer2pear-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
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

// ── 18. GET /v1/relay_info publishes the onion X25519 pubkey ─────────
// Clients need the relay's pubkey to wrap onions for it.  The handler
// must return the SAME key the hub holds in relayX25519Pub, not a random
// placeholder.

func TestHandleRelayInfo_PublishesX25519PubKey(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	resp, err := http.Get(r.srv.URL + "/v1/relay_info")
	if err != nil {
		t.Fatalf("GET /v1/relay_info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pubB64, ok := body["x25519_pub"].(string)
	if !ok || pubB64 == "" {
		t.Fatalf("x25519_pub missing or not string: %v", body)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("x25519_pub not valid 32-byte b64url: err=%v len=%d", err, len(pubBytes))
	}
	if !bytes.Equal(pubBytes, r.hub.relayX25519Pub[:]) {
		t.Fatalf("advertised pubkey mismatch")
	}
	if body["impl"] != "go" {
		t.Fatalf("impl field: %v", body["impl"])
	}
}

// wrapOnion builds a version-1 onion envelope for the relay's pubkey.
// Wire format (must match onion.go): [ver=0x01][ephPub 32][nonce 24][Box ct]
// where Box plaintext = [urlLen u16 BE][nextHopURL][innerBlob].
func wrapOnion(t *testing.T, relayPub *[32]byte, nextHopURL string, innerBlob []byte) []byte {
	t.Helper()
	ephPub, ephPriv, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey: %v", err)
	}
	var nonce [24]byte
	if _, err := cryptorand.Read(nonce[:]); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}

	urlBytes := []byte(nextHopURL)
	if len(urlBytes) > 0xFFFF {
		t.Fatalf("URL too long for u16 length prefix")
	}
	plain := make([]byte, 2+len(urlBytes)+len(innerBlob))
	binary.BigEndian.PutUint16(plain[0:2], uint16(len(urlBytes)))
	copy(plain[2:], urlBytes)
	copy(plain[2+len(urlBytes):], innerBlob)

	ct := box.Seal(nil, plain, &nonce, relayPub, ephPriv)

	out := make([]byte, 1+32+24+len(ct))
	out[0] = onionVersion
	copy(out[1:33], ephPub[:])
	copy(out[33:57], nonce[:])
	copy(out[57:], ct)
	return out
}

// ── 19. /v1/forward-onion peels a layer end-to-end ────────────────────
// A correctly-wrapped onion targeting this relay's pubkey must decrypt,
// parse the next-hop URL, and advance to the SSRF guard.  Targeting
// 127.0.0.1 trips that guard and returns 403 — which is precisely how
// we prove the decrypt+parse+validate chain works.  A regression in any
// earlier step would return 400 "onion decrypt failed" or similar.

func TestHandleForwardOnion_PeelsAndValidates(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	innerBlob := bytes.Repeat([]byte{0xAB}, 200)
	onion := wrapOnion(t, r.hub.relayX25519Pub,
		"http://127.0.0.1:8443/v1/send", innerBlob)

	resp, err := http.Post(r.srv.URL+"/v1/forward-onion",
		"application/octet-stream", bytes.NewReader(onion))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d (want 403 from SSRF); body=%s", resp.StatusCode, body)
	}
}

// ── 20. /v1/forward-onion: corrupt ciphertext → 400 decrypt failed ───
// Validates the AEAD tag is actually checked.  If we flip a byte inside
// the Box ciphertext, box.Open must refuse to return plaintext.

func TestHandleForwardOnion_RejectsCorruptCiphertext(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	onion := wrapOnion(t, r.hub.relayX25519Pub,
		"https://relay.example.com/v1/send",
		bytes.Repeat([]byte{0xCD}, 100))
	// Flip a byte deep in the ciphertext region (past version+ephPub+nonce).
	onion[80] ^= 0xFF

	resp, err := http.Post(r.srv.URL+"/v1/forward-onion",
		"application/octet-stream", bytes.NewReader(onion))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (decrypt failure)", resp.StatusCode)
	}
}

// ── 21. /v1/forward-onion: assorted malformed payloads → 400 ─────────

func TestHandleForwardOnion_RejectsBadInputs(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	tooShort := make([]byte, 10)
	tooShort[0] = onionVersion

	wrongVer := make([]byte, 80)
	wrongVer[0] = 0x02

	// Valid crypto but a non-http(s) next-hop scheme.
	ftpOnion := wrapOnion(t, r.hub.relayX25519Pub,
		"ftp://relay.example.com/v1/send", bytes.Repeat([]byte{0x11}, 80))

	// Valid crypto but disallowed next-hop path.
	adminOnion := wrapOnion(t, r.hub.relayX25519Pub,
		"https://relay.example.com/admin", bytes.Repeat([]byte{0x22}, 80))

	// Valid crypto but a garbage URL that url.Parse still accepts as a
	// relative path — we want empty scheme / host to trip the guard.
	emptyURL := wrapOnion(t, r.hub.relayX25519Pub,
		"", bytes.Repeat([]byte{0x33}, 80))

	cases := []struct {
		name string
		body []byte
	}{
		{"too-short", tooShort},
		{"wrong-version", wrongVer},
		{"ftp-scheme", ftpOnion},
		{"disallowed-path", adminOnion},
		{"empty-url", emptyURL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Post(r.srv.URL+"/v1/forward-onion",
				"application/octet-stream", bytes.NewReader(c.body))
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

// ── Presence helpers ──────────────────────────────────────────────────
// Presence + cover-traffic arrive interleaved on the WS — these helpers
// skip past binary dummy envelopes to find the next matching JSON frame.

func readNextJSONOfType(t *testing.T, conn *websocket.Conn, wantType string, deadline time.Duration) map[string]any {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(deadline))
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read waiting for %q: %v", wantType, err)
		}
		if mt == websocket.BinaryMessage {
			continue
		}
		var msg map[string]any
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if msg["type"] == wantType {
			return msg
		}
	}
}

// ── 22. presence_subscribe: initial snapshot + live online/offline ────

func TestPresence_SubscribeReceivesStateAndLiveUpdates(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	bob := newTestPeer(t)

	aliceConn, rep := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer aliceConn.Close()
	if rep.Reply["type"] != "auth_ok" {
		t.Fatalf("alice auth: %v", rep.Reply)
	}

	// Subscribe to Bob (offline).
	if err := aliceConn.WriteJSON(map[string]any{
		"type":     "presence_subscribe",
		"peer_ids": []string{bob.idB64},
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	snap := readNextJSONOfType(t, aliceConn, "presence_result", 3*time.Second)
	peers, _ := snap["peers"].(map[string]any)
	if online, _ := peers[bob.idB64].(bool); online {
		t.Fatalf("bob should be offline initially: %v", snap)
	}

	// Bob connects — Alice must receive an online push.
	bobConn, rep2 := dialAndAuth(t, r, bob, time.Now().UnixMilli())
	if rep2.Reply["type"] != "auth_ok" {
		bobConn.Close()
		t.Fatalf("bob auth: %v", rep2.Reply)
	}
	push := readNextJSONOfType(t, aliceConn, "presence", 3*time.Second)
	if push["peer_id"] != bob.idB64 || !push["online"].(bool) {
		t.Fatalf("expected online push for bob, got %v", push)
	}

	// Bob disconnects — Alice must receive an offline push.
	bobConn.Close()
	push = readNextJSONOfType(t, aliceConn, "presence", 3*time.Second)
	if push["peer_id"] != bob.idB64 || push["online"].(bool) {
		t.Fatalf("expected offline push for bob, got %v", push)
	}
}

// ── 23. presence_query: snapshot without subscribing ─────────────────

func TestPresence_QueryReturnsSnapshot(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	bob := newTestPeer(t)
	carol := newTestPeer(t)

	aliceConn, _ := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer aliceConn.Close()

	bobConn, _ := dialAndAuth(t, r, bob, time.Now().UnixMilli())
	defer bobConn.Close()

	if err := aliceConn.WriteJSON(map[string]any{
		"type":     "presence_query",
		"peer_ids": []string{bob.idB64, carol.idB64},
	}); err != nil {
		t.Fatalf("query: %v", err)
	}
	snap := readNextJSONOfType(t, aliceConn, "presence_result", 3*time.Second)
	peers, _ := snap["peers"].(map[string]any)
	if online, _ := peers[bob.idB64].(bool); !online {
		t.Fatalf("bob should be online: %v", snap)
	}
	if online, _ := peers[carol.idB64].(bool); online {
		t.Fatalf("carol should be offline: %v", snap)
	}
}

// ── 24. presence_query is rate-limited per connection ─────────────────
// After maxPresenceQueriesPerWin queries, further queries are silently
// dropped.  The attacker model: authenticated peer trying to enumerate
// the social graph at arbitrary speed.

func TestPresence_QueryRateLimitDropsAfterCap(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	bob := newTestPeer(t)

	conn, _ := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer conn.Close()

	// Burn the budget — every query below the cap gets a reply.
	for i := 0; i < maxPresenceQueriesPerWin; i++ {
		if err := conn.WriteJSON(map[string]any{
			"type":     "presence_query",
			"peer_ids": []string{bob.idB64},
		}); err != nil {
			t.Fatalf("query #%d: %v", i, err)
		}
		readNextJSONOfType(t, conn, "presence_result", 3*time.Second)
	}

	// One more — must be silently dropped.
	if err := conn.WriteJSON(map[string]any{
		"type":     "presence_query",
		"peer_ids": []string{bob.idB64},
	}); err != nil {
		t.Fatalf("overflow query: %v", err)
	}

	// Expect no presence_result in a reasonable window.  Skip cover-traffic
	// binary frames; anything else signals the cap didn't hold.
	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return // expected — no presence_result arrived
		}
		if mt == websocket.BinaryMessage {
			continue
		}
		var msg map[string]any
		if json.Unmarshal(data, &msg) == nil && msg["type"] == "presence_result" {
			t.Fatalf("presence_result after cap — regression: %v", msg)
		}
	}
}

// ── 24b. presence_subscribe is rate-limited per connection ───────────
// Audit #3 H4: previously the handler accepted unlimited subscribe
// calls per connection, letting an authenticated peer churn the 200-id
// watched set repeatedly to enumerate the social graph at WebSocket
// speed.  With the cap in place, the (maxPresenceSubsPerWin+1)th call
// in a window must be silently dropped (no presence_result reply).

func TestPresence_SubscribeRateLimitDropsAfterCap(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	bob := newTestPeer(t)

	conn, _ := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer conn.Close()

	// Burn the budget — every subscribe within the cap gets a snapshot.
	for i := 0; i < maxPresenceSubsPerWin; i++ {
		if err := conn.WriteJSON(map[string]any{
			"type":     "presence_subscribe",
			"peer_ids": []string{bob.idB64},
		}); err != nil {
			t.Fatalf("subscribe #%d: %v", i, err)
		}
		readNextJSONOfType(t, conn, "presence_result", 3*time.Second)
	}

	// One more subscribe — must be silently dropped.
	if err := conn.WriteJSON(map[string]any{
		"type":     "presence_subscribe",
		"peer_ids": []string{bob.idB64},
	}); err != nil {
		t.Fatalf("overflow subscribe: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return // expected — no presence_result arrived
		}
		if mt == websocket.BinaryMessage {
			continue
		}
		var msg map[string]any
		if json.Unmarshal(data, &msg) == nil && msg["type"] == "presence_result" {
			t.Fatalf("presence_result after subscribe cap — regression: %v", msg)
		}
	}
}

// ── 25. presence_subscribe caps the watched-set size ─────────────────

func TestPresence_SubscribeCapsAtMaxSize(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)
	conn, _ := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer conn.Close()

	overBudget := make([]string, maxPresenceSubs+50)
	for i := range overBudget {
		overBudget[i] = fmt.Sprintf("peer-enum-%d", i)
	}
	if err := conn.WriteJSON(map[string]any{
		"type":     "presence_subscribe",
		"peer_ids": overBudget,
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Drain the initial snapshot so we know the handler has processed it.
	readNextJSONOfType(t, conn, "presence_result", 3*time.Second)

	r.hub.mu.RLock()
	got := len(r.hub.subs[alice.idB64])
	r.hub.mu.RUnlock()
	if got != maxPresenceSubs {
		t.Fatalf("subs count %d, want %d (cap)", got, maxPresenceSubs)
	}
}

// ── 26. Concurrent-peer race: new WS for same peer replaces old ──────
// Two sequential connections for the same peer ID.  Hub.register must
// close the old conn (with code 4005 "replaced") before installing the
// new one — otherwise envelopes could double-deliver or land on a
// stale socket.  This also exercises the implicit "second auth with a
// fresh timestamp isn't rejected as replay" path.

func TestHub_SecondConnectionReplacesFirst(t *testing.T) {
	r := newTestRelay(t)
	defer r.Close()

	alice := newTestPeer(t)

	conn1, rep1 := dialAndAuth(t, r, alice, time.Now().UnixMilli())
	defer conn1.Close()
	if rep1.Reply["type"] != "auth_ok" {
		t.Fatalf("first auth: %v", rep1.Reply)
	}

	// Distinct ts so the nonce store sees a different row.
	conn2, rep2 := dialAndAuth(t, r, alice, time.Now().UnixMilli()+1)
	defer conn2.Close()
	if rep2.Reply["type"] != "auth_ok" {
		t.Fatalf("second auth: %v", rep2.Reply)
	}

	// Hub state: exactly one peer entry, pointing at the new conn.
	time.Sleep(100 * time.Millisecond) // let register/unregister settle
	r.hub.mu.RLock()
	p, online := r.hub.peers[alice.idB64]
	r.hub.mu.RUnlock()
	if !online {
		t.Fatalf("no peer entry after replacement")
	}
	if p.Conn == conn1 {
		t.Fatalf("hub still pointing at first conn after replace")
	}

	// The old conn must observe its close.
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := conn1.ReadMessage()
		if err == nil {
			continue // drain any queued frame
		}
		if ce, ok := err.(*websocket.CloseError); ok && ce.Code == 4005 {
			break
		}
		// Any error is acceptable — the conn is dead.
		break
	}

	// An envelope sent now lands on conn2.
	env := buildEnvelope(alice, 128)
	resp, err := http.Post(r.srv.URL+"/v1/send",
		"application/octet-stream", bytes.NewReader(env))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		mt, body, err := conn2.ReadMessage()
		if err != nil {
			t.Fatalf("conn2 read: %v", err)
		}
		if mt == websocket.BinaryMessage && bytes.Equal(body, env) {
			return
		}
	}
}
