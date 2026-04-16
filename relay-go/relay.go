package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ── Envelope wire format ─────────────────────────────────────────────────────
//
//	byte  0:       version (0x01)
//	bytes 1-32:    recipient Ed25519 public key
//	bytes 33+:     sealed ciphertext
//
// The relay reads only bytes 0-32 for routing. Everything else is opaque.

const (
	envelopeVersion    = 0x01
	envelopeMinSize    = 33       // version + 32-byte pubkey
	maxEnvelopeBytes   = 256 << 10 // 256 KiB
	replayWindowMs     = 5 * 60 * 1000
	wsWriteTimeout     = 10 * time.Second
	wsReadTimeout      = 60 * time.Second
	wsPingInterval     = 30 * time.Second
	wsAuthTimeout      = 10 * time.Second
	forwardTimeout     = 10 * time.Second

	// Rate limiting for /v1/send (per IP)
	rateLimitPerMin    = 60   // max envelopes per IP per minute
	rateLimitWindow    = 60   // window in seconds

	// H4: max peer IDs a single peer can subscribe to for presence
	maxPresenceSubs    = 200

	// M5: global max envelopes stored in mailbox
	maxGlobalEnvelopes = 500_000

	// DAITA: relay-side traffic analysis defense
	coverTrafficMinSec = 5   // min seconds between cover packets
	coverTrafficMaxSec = 15  // max seconds between cover packets
	deliveryJitterMs   = 200 // max random delivery delay (ms)
	dummyVersion       = 0x00 // version byte for dummy envelopes (client discards)
)

// ── Per-IP rate limiter ─────────────────────────────────────────────────────

type ipRateEntry struct {
	count   int
	resetAt int64 // unix seconds
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipRateEntry
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{entries: make(map[string]*ipRateEntry)}
	// Purge stale entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.purge()
		}
	}()
	return rl
}

// allow returns true if the IP is within its rate limit.
func (rl *rateLimiter) allow(ip string) bool {
	now := time.Now().Unix()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[ip]
	if !ok || now >= e.resetAt {
		rl.entries[ip] = &ipRateEntry{count: 1, resetAt: now + rateLimitWindow}
		return true
	}
	e.count++
	return e.count <= rateLimitPerMin
}

func (rl *rateLimiter) purge() {
	now := time.Now().Unix()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, e := range rl.entries {
		if now >= e.resetAt {
			delete(rl.entries, ip)
		}
	}
}

// ── Peer connection ──────────────────────────────────────────────────────────

type Peer struct {
	ID   string
	Conn *websocket.Conn
	Send chan []byte // buffered outbound channel
}

// ── Hub: manages all connected peers ─────────────────────────────────────────

type Hub struct {
	mu         sync.RWMutex
	peers      map[string]*Peer // peer_id → *Peer
	subs       map[string]map[string]bool // subscriber_id → set of watched peer_ids
	mbox       *Mailbox
	rl         *rateLimiter
	trustProxy bool // H2 fix: only trust X-Forwarded-For when behind a reverse proxy

	// H3 fix: track seen auth nonces to prevent replay within the 5-min window
	authMu    sync.Mutex
	seenAuth  map[string]int64 // "peer_id|ts" → expiry unix ms

	upgrader websocket.Upgrader
}

func NewHub(mbox *Mailbox, trustProxy bool) *Hub {
	h := &Hub{
		peers:      make(map[string]*Peer),
		subs:       make(map[string]map[string]bool),
		mbox:       mbox,
		rl:         newRateLimiter(),
		trustProxy: trustProxy,
		seenAuth:   make(map[string]int64),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  maxEnvelopeBytes,
			WriteBufferSize: maxEnvelopeBytes,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
	// H3 fix: periodically purge expired auth nonces
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now().UnixMilli()
			h.authMu.Lock()
			for k, exp := range h.seenAuth {
				if now > exp {
					delete(h.seenAuth, k)
				}
			}
			h.authMu.Unlock()
		}
	}()
	return h
}

func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.peers {
		p.Conn.Close()
		close(p.Send)
	}
	h.peers = make(map[string]*Peer)
	h.subs = make(map[string]map[string]bool)
}

// register adds a peer to the hub, closing any existing connection for the same ID.
func (h *Hub) register(p *Peer) {
	h.mu.Lock()
	if old, ok := h.peers[p.ID]; ok {
		old.Conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(4005, "replaced"),
			time.Now().Add(time.Second),
		)
		old.Conn.Close()
		close(old.Send)
	}
	h.peers[p.ID] = p
	h.subs[p.ID] = make(map[string]bool)
	h.mu.Unlock()

	log.Printf("connected: %s…", truncID(p.ID))
	h.notifyPresence(p.ID, true)
}

// unregister removes a peer from the hub.
func (h *Hub) unregister(peerID string) {
	h.mu.Lock()
	if p, ok := h.peers[peerID]; ok {
		close(p.Send)
		delete(h.peers, peerID)
	}
	delete(h.subs, peerID)
	h.mu.Unlock()

	log.Printf("disconnected: %s…", truncID(peerID))
	h.notifyPresence(peerID, false)
}

// deliverOrStore tries WebSocket push first, falls back to mailbox storage.
// DAITA: adds random jitter before delivery to break timing correlation between
// "relay received POST from IP X" and "relay pushed to peer Y".
func (h *Hub) deliverOrStore(recipientID string, envelope []byte) (delivered bool, err error) {
	h.mu.RLock()
	p, online := h.peers[recipientID]
	h.mu.RUnlock()

	if online {
		// DAITA: random delivery jitter (0-200ms)
		if deliveryJitterMs > 0 {
			jitter := time.Duration(mrand.Intn(deliveryJitterMs)) * time.Millisecond
			time.Sleep(jitter)
		}
		select {
		case p.Send <- envelope:
			return true, nil
		default:
			// Send buffer full — peer is too slow, store instead
		}
	}

	// Offline or buffer full — store in mailbox
	return false, h.mbox.Store(recipientID, envelope)
}

// notifyPresence pushes online/offline events to subscribers.
func (h *Hub) notifyPresence(peerID string, online bool) {
	msg, _ := json.Marshal(map[string]any{
		"type":    "presence",
		"peer_id": peerID,
		"online":  online,
	})

	h.mu.RLock()
	var targets []*Peer
	for subID, watched := range h.subs {
		if watched[peerID] {
			if p, ok := h.peers[subID]; ok {
				targets = append(targets, p)
			}
		}
	}
	h.mu.RUnlock()

	for _, p := range targets {
		select {
		case p.Send <- msg:
		default:
			// subscriber's buffer full — skip
		}
	}
}

// ── POST /v1/send — Anonymous envelope submission ────────────────────────────

// ── DAITA helpers ────────────────────────────────────────────────────────────

// generateDummyEnvelope creates a random-looking envelope with version byte 0x00
// that the client recognizes and discards. Uses standard bucket sizes.
func generateDummyEnvelope() []byte {
	buckets := []int{2048, 16384, 262144}
	size := buckets[mrand.Intn(len(buckets))]
	buf := make([]byte, size)
	rand.Read(buf)
	buf[0] = dummyVersion // client checks this byte and discards
	return buf
}

// randomDuration returns a random duration between min and max seconds.
func randomCoverInterval() time.Duration {
	spread := coverTrafficMaxSec - coverTrafficMinSec
	if spread <= 0 {
		return time.Duration(coverTrafficMinSec) * time.Second
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(spread)))
	return time.Duration(coverTrafficMinSec+int(n.Int64())) * time.Second
}

// hashIP returns a hex-encoded SHA-256 hash of the IP (for rate limiting without storing raw IPs).
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:16]) // truncate to 128 bits — sufficient for rate limiting
}

func (h *Hub) clientIP(r *http.Request) string {
	if h.trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
		}
	}
	return r.RemoteAddr
}

func (h *Hub) HandleSend(w http.ResponseWriter, r *http.Request) {
	if !h.rl.allow(hashIP(h.clientIP(r))) {
		httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxEnvelopeBytes)+1))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read error")
		return
	}
	if len(body) > maxEnvelopeBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	recipientID, err := parseRecipient(body)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}

	delivered, err := h.deliverOrStore(recipientID, body)
	if err != nil {
		httpError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	if delivered {
		log.Printf("relayed: to=%s… size=%dB", truncID(recipientID), len(body))
		writeJSON(w, http.StatusOK, map[string]any{"delivered": true})
	} else {
		log.Printf("stored: to=%s… size=%dB", truncID(recipientID), len(body))
		writeJSON(w, http.StatusOK, map[string]any{"stored": true})
	}
}

// ── WS /v1/receive — Authenticated receive channel ──────────────────────────

func (h *Hub) HandleReceive(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}

	// Step 1: Authenticate — first message must be JSON auth
	conn.SetReadDeadline(time.Now().Add(wsAuthTimeout))
	var auth struct {
		PeerID string `json:"peer_id"`
		Ts     int64  `json:"ts"`
		Sig    string `json:"sig"`
	}
	if err := conn.ReadJSON(&auth); err != nil {
		conn.WriteJSON(map[string]string{"error": "auth timeout or invalid json"})
		conn.Close()
		return
	}

	// Verify timestamp freshness
	nowMs := time.Now().UnixMilli()
	if abs64(nowMs-auth.Ts) > replayWindowMs {
		conn.WriteJSON(map[string]string{"error": "timestamp outside window"})
		conn.Close()
		return
	}

	// Verify Ed25519 signature
	message := fmt.Sprintf("RELAY1|%s|%d", auth.PeerID, auth.Ts)
	if !verifyEd25519(auth.PeerID, auth.Sig, message) {
		conn.WriteJSON(map[string]string{"error": "auth failed"})
		conn.Close()
		return
	}

	// H3 fix: reject replayed auth messages
	authNonce := fmt.Sprintf("%s|%d", auth.PeerID, auth.Ts)
	h.authMu.Lock()
	if _, seen := h.seenAuth[authNonce]; seen {
		h.authMu.Unlock()
		conn.WriteJSON(map[string]string{"error": "auth replay"})
		conn.Close()
		return
	}
	h.seenAuth[authNonce] = nowMs + replayWindowMs
	h.authMu.Unlock()

	// Step 2: Register peer
	peer := &Peer{
		ID:   auth.PeerID,
		Conn: conn,
		Send: make(chan []byte, 256),
	}
	h.register(peer)
	defer h.unregister(peer.ID)

	// Step 3: Deliver stored envelopes
	stored := h.mbox.FetchAll(peer.ID)
	for _, env := range stored {
		conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		if err := conn.WriteMessage(websocket.BinaryMessage, env); err != nil {
			return
		}
	}
	if len(stored) > 0 {
		log.Printf("delivered %d stored envelope(s) to %s…", len(stored), truncID(peer.ID))
	}

	// Send auth confirmation
	conn.WriteJSON(map[string]any{"type": "auth_ok", "peer_id": peer.ID})

	// Step 4: Start writer goroutine (sends from the Send channel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range peer.Send {
			conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))

			// Determine message type: JSON messages start with '{', envelopes start with 0x01
			msgType := websocket.BinaryMessage
			if len(msg) > 0 && msg[0] == '{' {
				msgType = websocket.TextMessage
			}

			if err := conn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}()

	// Ping ticker to keep connection alive
	go func() {
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	// DAITA: cover traffic injection — send random dummy envelopes at
	// unpredictable intervals so an observer can't distinguish real
	// deliveries from noise on the WebSocket stream.
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(randomCoverInterval()):
				dummy := generateDummyEnvelope()
				select {
				case peer.Send <- dummy:
				default:
					// buffer full — skip this cover packet
				}
			}
		}
	}()

	// Step 5: Read loop — handle presence queries
	conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(wsReadTimeout))
		return nil
	})

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(wsReadTimeout))

		var msg map[string]any
		if json.Unmarshal(msgBytes, &msg) != nil {
			continue
		}

		switch msg["type"] {
		case "presence_query":
			peerIDs := toStringSlice(msg["peer_ids"])
			results := make(map[string]bool, len(peerIDs))
			h.mu.RLock()
			for _, pid := range peerIDs {
				_, results[pid] = h.peers[pid]
			}
			h.mu.RUnlock()
			resp, _ := json.Marshal(map[string]any{
				"type":  "presence_result",
				"peers": results,
			})
			peer.Send <- resp

		case "presence_subscribe":
			peerIDs := toStringSlice(msg["peer_ids"])
			// H4 fix: cap subscription size to prevent social graph enumeration
			if len(peerIDs) > maxPresenceSubs {
				peerIDs = peerIDs[:maxPresenceSubs]
			}
			h.mu.Lock()
			subs := make(map[string]bool, len(peerIDs))
			for _, pid := range peerIDs {
				subs[pid] = true
			}
			h.subs[peer.ID] = subs
			h.mu.Unlock()

			// Send current state immediately
			results := make(map[string]bool, len(peerIDs))
			h.mu.RLock()
			for _, pid := range peerIDs {
				_, results[pid] = h.peers[pid]
			}
			h.mu.RUnlock()
			resp, _ := json.Marshal(map[string]any{
				"type":  "presence_result",
				"peers": results,
			})
			peer.Send <- resp

		case "ping":
			resp, _ := json.Marshal(map[string]string{"type": "pong"})
			peer.Send <- resp
		}
	}
}

// ── POST /v1/forward — Multi-hop relay forwarding ────────────────────────────

func (h *Hub) HandleForward(w http.ResponseWriter, r *http.Request) {
	if !h.rl.allow(hashIP(h.clientIP(r))) {
		httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	forwardTo := r.Header.Get("X-Forward-To")
	if forwardTo == "" {
		httpError(w, http.StatusBadRequest, "missing X-Forward-To header")
		return
	}
	if strings.ContainsAny(forwardTo, "/ ") {
		httpError(w, http.StatusBadRequest, "invalid relay address")
		return
	}
	// M4 fix: block forwarding to private/loopback addresses (SSRF prevention)
	host := strings.Split(forwardTo, ":")[0]
	if host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		host == "0.0.0.0" || strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "172.") ||
		strings.HasPrefix(host, "169.254.") {
		httpError(w, http.StatusForbidden, "forwarding to private addresses not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxEnvelopeBytes)+1))
	if err != nil || len(body) > maxEnvelopeBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	// Forward to the target relay's /v1/send
	client := &http.Client{Timeout: forwardTimeout}
	url := fmt.Sprintf("https://%s/v1/send", forwardTo)
	resp, err := client.Post(url, "application/octet-stream",
		io.NopCloser(strings.NewReader(string(body))))
	if err != nil {
		httpError(w, http.StatusBadGateway, fmt.Sprintf("cannot reach relay %s", forwardTo))
		return
	}
	defer resp.Body.Close()

	writeJSON(w, http.StatusOK, map[string]any{
		"forwarded": true,
		"relay":     forwardTo,
		"status":    resp.StatusCode,
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func parseRecipient(envelope []byte) (string, error) {
	if len(envelope) < envelopeMinSize {
		return "", fmt.Errorf("envelope too small (need at least %d bytes)", envelopeMinSize)
	}
	if envelope[0] != envelopeVersion {
		return "", fmt.Errorf("unsupported envelope version: %d", envelope[0])
	}
	recipientPub := envelope[1:33]
	return b64urlEncode(recipientPub), nil
}

func verifyEd25519(peerIDB64, sigB64, message string) bool {
	pubBytes, err := b64urlDecode(peerIDB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := b64urlDecode(sigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(message), sigBytes)
}

func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func truncID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
