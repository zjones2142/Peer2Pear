package main

import (
	"context"
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
	"net"
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
	envelopeVersion  = 0x01
	envelopeMinSize  = 33        // version + 32-byte pubkey
	maxEnvelopeBytes = 256 << 10 // 256 KiB
	// Auth replay window: 30 seconds is long enough for clock skew but
	// short enough that a crash-restart race is minimal.
	replayWindowMs = 30 * 1000
	wsWriteTimeout = 10 * time.Second
	wsReadTimeout  = 60 * time.Second
	wsPingInterval = 30 * time.Second
	wsAuthTimeout  = 10 * time.Second
	forwardTimeout = 10 * time.Second

	// Rate limiting for /v1/send (per IP)
	rateLimitPerMin = 60 // max envelopes per IP per minute
	rateLimitWindow = 60 // window in seconds

	// Per-recipient ingress rate limit.  Per-IP alone can be bypassed by
	// rotating source IPs (cheap with a VPS + multiple egresses).  This
	// second limiter caps inbound envelopes per recipient pubkey regardless
	// of origin.  Sealed-sender means we can't rate-limit per-sender at the
	// /v1/send boundary, but recipient pubkey IS visible in the envelope header.
	recipientRateLimitPerMin = 300

	// Max peer IDs a single peer can subscribe to for presence.
	maxPresenceSubs = 200

	// Per-connection presence_query rate limit.  Window is generous
	// (1 minute / 60 queries) so a real client's reconnect-burst sees no
	// friction, but a malicious peer can't enumerate the social graph at
	// arbitrary speed.
	presenceQueryWindow     = 60 // seconds
	maxPresenceQueriesPerWin = 60

	// Per-connection presence_subscribe rate limit (Audit #3 H4).  The
	// subscription-size cap (maxPresenceSubs = 200) bounds the watched
	// set per call; the per-call frequency cap below prevents an
	// authenticated peer from churning the watched set ("subscribe 200
	// IDs, replace, repeat") to enumerate the social graph at WebSocket
	// speed.  6/min ≈ one every 10 s — comfortable for legitimate
	// contact-list edits, hostile to enumeration.
	presenceSubWindow         = 60 // seconds
	maxPresenceSubsPerWin     = 6

	// Global max envelopes stored in mailbox.
	maxGlobalEnvelopes = 500_000

	// DAITA: relay-side traffic analysis defense
	coverTrafficMinSec = 5    // min seconds between cover packets
	coverTrafficMaxSec = 15   // max seconds between cover packets
	deliveryJitterMs   = 200  // max random delivery delay (ms)
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
	// Audit #3 L5: signal channel so the background purge goroutine
	// terminates when the Hub shuts down.  Without this the goroutine
	// outlives the test fixture and accumulates across the suite.
	stop chan struct{}
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		entries: make(map[string]*ipRateEntry),
		stop:    make(chan struct{}),
	}
	// Purge stale entries every 5 minutes; exit on stop.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.purge()
			case <-rl.stop:
				return
			}
		}
	}()
	return rl
}

// Stop signals the purge goroutine to exit.  Safe to call once;
// subsequent calls panic on the closed channel, matching the rest of
// the relay's "lifecycle objects close exactly once" convention.
func (rl *rateLimiter) Stop() {
	close(rl.stop)
}

// allow returns true if the IP is within its rate limit.
func (rl *rateLimiter) allow(ip string) bool {
	return rl.allowWithLimit(ip, rateLimitPerMin)
}

// allowWithLimit applies a caller-specified per-key cap. Same sliding window.
// Lets us reuse the struct for per-recipient limiting with a different
// (higher) ceiling than the per-IP one.
func (rl *rateLimiter) allowWithLimit(key string, limit int) bool {
	now := time.Now().Unix()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[key]
	if !ok || now >= e.resetAt {
		rl.entries[key] = &ipRateEntry{count: 1, resetAt: now + rateLimitWindow}
		return true
	}
	e.count++
	return e.count <= limit
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

	// Per-connection presence-query rate limit.  The subscription-size cap
	// (maxPresenceSubs = 200) limits breadth; this bounds depth.  An
	// authenticated peer can't hammer arbitrary peer_ids for online status.
	// Counts reset each presenceQueryWindow seconds; over the cap → drop
	// silently.
	presenceQueryCount   int
	presenceQueryResetAt int64 // unix seconds

	// Per-connection presence_subscribe rate limit.  Same shape as the
	// query counter above — see Audit #3 H4 / `maxPresenceSubsPerWin`.
	presenceSubCount   int
	presenceSubResetAt int64 // unix seconds
}

// ── Hub: manages all connected peers ─────────────────────────────────────────

type Hub struct {
	mu         sync.RWMutex
	peers      map[string]*Peer           // peer_id → *Peer
	subs       map[string]map[string]bool // subscriber_id → set of watched peer_ids
	mbox       *Mailbox
	rl         *rateLimiter // per-IP ingress
	rlRecip    *rateLimiter // per-recipient ingress cap
	trustProxy bool         // only trust X-Forwarded-For when behind a reverse proxy

	// Seen-auth-nonce dedup lives in SQLite (see Mailbox.RegisterAuthNonce).
	// The Hub no longer owns a map — every check / register flows through
	// m.mbox so the dedup survives a relay restart within the replay window.

	// Persistent X25519 keypair for onion routing.
	// Advertised via GET /v1/relay_info; used to peel POST /v1/forward-onion.
	relayX25519Pub  *[32]byte
	relayX25519Priv *[32]byte

	// Mobile push-notification integration.  Tokens are stored per
	// (peer_id, platform) and consulted when an envelope lands for
	// an offline recipient — the sender stub logs today; swapping in
	// a real APNs client is a one-file change.
	push       *PushStore
	pushSender *PushSender

	// Audit #3 L5: signal channel that terminates the auth-nonce purge
	// goroutine when the Hub shuts down.  Closed exactly once by
	// CloseAll.  rateLimiter has its own equivalent.
	stopAuthPurge chan struct{}

	upgrader websocket.Upgrader
}

func NewHub(mbox *Mailbox, trustProxy bool) *Hub {
	h := &Hub{
		peers:      make(map[string]*Peer),
		subs:       make(map[string]map[string]bool),
		mbox:       mbox,
		rl:         newRateLimiter(),
		rlRecip:    newRateLimiter(),
		trustProxy: trustProxy,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  maxEnvelopeBytes,
			WriteBufferSize: maxEnvelopeBytes,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
		pushSender:    NewPushSender(false), // stub until APNs key configured
		stopAuthPurge: make(chan struct{}),
	}
	// PushStore is intentionally NOT initialised here — it needs the
	// AEAD key derived from the relay's persistent X25519 private key
	// for at-rest token encryption (Audit #3 C2), and that key is
	// loaded after NewHub returns.  Caller must invoke InitPush(priv)
	// once the relay key is available; until then h.push stays nil
	// and push registration is silently dropped (NotifyOffline is a
	// no-op without h.push, which is acceptable for the brief window
	// before main wires it up).
	// Periodically purge expired auth nonces from the persistent table.
	// RegisterAuthNonce() also cleans up opportunistically; this just
	// bounds table size in steady state.  Exits on stop so the goroutine
	// doesn't outlive the Hub (Audit #3 L5).  Capture the channel
	// locally — CloseAll mutates h.stopAuthPurge and the goroutine must
	// not read that field concurrently.
	stop := h.stopAuthPurge
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mbox.PurgeExpiredAuthNonces()
			case <-stop:
				return
			}
		}
	}()
	return h
}

// InitPush wires up the at-rest-encrypted push token store using the
// relay's persistent X25519 private key as HKDF input.  Idempotent —
// safe to call multiple times if the relay key is rotated.
func (h *Hub) InitPush(relayPriv *[32]byte) {
	if h.mbox == nil || h.mbox.db == nil || relayPriv == nil {
		return
	}
	key := derivePushTokenKey(relayPriv)
	store, err := NewPushStore(h.mbox.db, key)
	if err != nil {
		log.Printf("push: failed to init store: %v (push disabled)", err)
		return
	}
	h.push = store
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

	// Audit #3 L5: terminate the background purge goroutines so Hub
	// shutdown actually releases all worker resources (matters for the
	// test fixture, which spins up a fresh Hub per case).  Don't nil
	// the limiters — late HTTP handlers from a not-yet-closed listener
	// still call allow().  The stop channels only end the purger; the
	// allow() path is unaffected.
	if h.rl != nil {
		h.rl.Stop()
	}
	if h.rlRecip != nil {
		h.rlRecip.Stop()
	}
	if h.stopAuthPurge != nil {
		// The goroutine captured the channel locally at startup, so
		// closing here signals it to exit without racing on the field.
		close(h.stopAuthPurge)
		h.stopAuthPurge = nil
	}
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

// unregister removes a peer from the hub.  Takes the full *Peer so we
// can verify identity: if a second connection for the same ID replaced
// us in `register`, that call already closed our Send channel and
// installed the new peer; we must NOT wipe the new peer's state when
// our own HandleReceive finally exits.
func (h *Hub) unregister(self *Peer) {
	h.mu.Lock()
	cur, ok := h.peers[self.ID]
	replaced := !ok || cur != self
	if !replaced {
		close(cur.Send)
		delete(h.peers, self.ID)
		delete(h.subs, self.ID)
	}
	h.mu.Unlock()

	if replaced {
		// A newer connection owns this ID; don't log a spurious disconnect
		// nor flip presence to offline — the newer conn is still online.
		return
	}
	log.Printf("disconnected: %s…", truncID(self.ID))
	h.notifyPresence(self.ID, false)
}

// deliverOrStore tries WebSocket push first, falls back to mailbox storage.
// DAITA: delivery jitter (see writer goroutine in HandleReceive) breaks
// the timing correlation between "relay received POST from IP X" and
// "relay pushed to peer Y".  Jitter lives on the per-peer writer goroutine
// (which sleeps before WriteMessage) rather than inline here, so HTTP
// handlers don't pay the latency.
func (h *Hub) deliverOrStore(recipientID string, envelope []byte) (delivered bool, err error) {
	h.mu.RLock()
	p, online := h.peers[recipientID]
	h.mu.RUnlock()

	if online {
		select {
		case p.Send <- envelope:
			return true, nil
		default:
			// Send buffer full — peer is too slow, store instead
		}
	}

	// Offline or buffer full — store in mailbox + wake the peer's
	// device via push.  Push is best-effort and cooldown-gated
	// inside PushSender so a burst of queued envelopes fires only
	// one wake-up, not one per envelope.
	if err := h.mbox.Store(recipientID, envelope); err != nil {
		return false, err
	}
	if h.push != nil && h.pushSender != nil {
		if records, perr := h.push.GetForPeer(recipientID); perr == nil {
			h.pushSender.NotifyOffline(recipientID, records)
		}
	}
	return false, nil
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
// Bucket selection uses crypto/rand because it's observable from the wire.
func generateDummyEnvelope() []byte {
	buckets := []int{2048, 16384, 262144}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(buckets))))
	size := buckets[n.Int64()]
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

	// Per-recipient ingress limit — independent of source IP.
	// An attacker rotating IPs can no longer flood a specific victim's mailbox.
	if !h.rlRecip.allowWithLimit(recipientID, recipientRateLimitPerMin) {
		httpError(w, http.StatusTooManyRequests, "recipient rate limit exceeded")
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
	// Rate-limit ws auth attempts per IP.  Without this, the per-identity
	// presence-sub cap (200) can be bypassed by rotating keypairs: auth →
	// subscribe 200 → disconnect → new keypair → repeat.  Capping auth
	// attempts bounds how fast an attacker can enumerate.
	if !h.rl.allow(hashIP(h.clientIP(r))) {
		httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

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

	// Reject replayed auth messages.  Backed by SQLite so a relay restart
	// within the replay window doesn't re-open the attack.
	authNonce := fmt.Sprintf("%s|%d", auth.PeerID, auth.Ts)
	if !h.mbox.RegisterAuthNonce(authNonce, nowMs+replayWindowMs) {
		conn.WriteJSON(map[string]string{"error": "auth replay"})
		conn.Close()
		return
	}

	// Step 2: Register peer
	peer := &Peer{
		ID:   auth.PeerID,
		Conn: conn,
		Send: make(chan []byte, 256),
	}
	h.register(peer)
	defer h.unregister(peer)

	// Step 3: Deliver stored envelopes (mark-and-confirm — each row is
	// deleted only after its WS write returns nil, so a crash partway
	// through leaves the unsent envelopes in the mailbox for the next
	// reconnect.  Rows that landed on the wire but whose confirm never
	// ran age out after staleDeliveryMarkMs and get re-sent too — client
	// envelope-ID dedup takes care of the resulting duplicates.)
	stored := h.mbox.FetchAll(peer.ID)
	delivered := 0
	for _, env := range stored {
		conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		if err := conn.WriteMessage(websocket.BinaryMessage, env.Payload); err != nil {
			return
		}
		h.mbox.ConfirmDelivered(env.EnvID)
		delivered++
	}
	if delivered > 0 {
		log.Printf("delivered %d stored envelope(s) to %s…", delivered, truncID(peer.ID))
	}

	// Send auth confirmation
	conn.WriteJSON(map[string]any{"type": "auth_ok", "peer_id": peer.ID})

	// Step 4: Start writer goroutine (sends from the Send channel).
	//
	// Delivery jitter lives here rather than inline in deliverOrStore so
	// HTTP handlers don't block.  Only binary envelopes get jittered —
	// JSON control frames (presence, pong, etc.) fire immediately because
	// their timing is not information the relay operator can correlate
	// to /v1/send traffic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range peer.Send {
			// Determine message type: JSON messages start with '{', envelopes start with 0x01
			msgType := websocket.BinaryMessage
			if len(msg) > 0 && msg[0] == '{' {
				msgType = websocket.TextMessage
			}

			if msgType == websocket.BinaryMessage && deliveryJitterMs > 0 {
				jn, _ := rand.Int(rand.Reader, big.NewInt(int64(deliveryJitterMs)))
				time.Sleep(time.Duration(jn.Int64()) * time.Millisecond)
			}

			conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
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
			// Cap query frequency per connection.  The subscription-size
			// cap limits breadth; this bounds depth.
			now := time.Now().Unix()
			if now >= peer.presenceQueryResetAt {
				peer.presenceQueryCount = 0
				peer.presenceQueryResetAt = now + presenceQueryWindow
			}
			peer.presenceQueryCount++
			if peer.presenceQueryCount > maxPresenceQueriesPerWin {
				if peer.presenceQueryCount == maxPresenceQueriesPerWin+1 {
					log.Printf("presence query rate limit hit for %s…",
						truncID(peer.ID))
				}
				continue
			}
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
			// Non-blocking send (Audit #3 M8): a slow consumer must not
			// stall the read goroutine.  Buffer-full → drop the reply;
			// the client can re-query.
			select {
			case peer.Send <- resp:
			default:
			}

		case "presence_subscribe":
			// Cap subscribe frequency per connection (Audit #3 H4).
			// Without this, an authenticated peer could replace the
			// 200-id watched set repeatedly to enumerate the social
			// graph at WebSocket speed.
			now := time.Now().Unix()
			if now >= peer.presenceSubResetAt {
				peer.presenceSubCount = 0
				peer.presenceSubResetAt = now + presenceSubWindow
			}
			peer.presenceSubCount++
			if peer.presenceSubCount > maxPresenceSubsPerWin {
				if peer.presenceSubCount == maxPresenceSubsPerWin+1 {
					log.Printf("presence subscribe rate limit hit for %s…",
						truncID(peer.ID))
				}
				continue
			}
			peerIDs := toStringSlice(msg["peer_ids"])
			// Cap subscription size to prevent social graph enumeration.
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
			select {
			case peer.Send <- resp:
			default:
			}

		case "ping":
			resp, _ := json.Marshal(map[string]string{"type": "pong"})
			select {
			case peer.Send <- resp:
			default:
			}

		case "push_register":
			// Mobile client tells us "wake me via this APNs/FCM token
			// when envelopes land while I'm offline."  Authenticated
			// WS already identifies peer.ID, so we just upsert
			// (peer.ID, platform, token).  An empty token acts as
			// unregister.
			if h.push == nil {
				continue
			}
			platform, _ := msg["platform"].(string)
			token, _ := msg["token"].(string)
			if platform == "" {
				continue
			}
			if err := h.push.Upsert(peer.ID, platform, token); err != nil {
				log.Printf("push: upsert failed for %s…: %v",
					truncID(peer.ID), err)
			}
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

	// SSRF hardening — resolve DNS, reject any resolved IP that lands in
	// loopback/private/link-local/ULA/CGNAT.  A simple string-prefix check
	// on the raw host would be fooled by bracketed IPv6 like `[::1]:443`
	// and would skip DNS resolution entirely (allowing rebinding attacks).
	if reason, ok := forwardHostSafe(forwardTo); !ok {
		httpError(w, http.StatusForbidden,
			"forwarding not allowed: "+reason)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxEnvelopeBytes)+1))
	if err != nil || len(body) > maxEnvelopeBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	// Apply per-recipient cap to forwarded traffic too — parse the recipient
	// out of the inner envelope header.
	if rid, err := parseRecipient(body); err == nil {
		if !h.rlRecip.allowWithLimit(rid, recipientRateLimitPerMin) {
			httpError(w, http.StatusTooManyRequests, "recipient rate limit exceeded")
			return
		}
	}

	// Forward to the target relay's /v1/send.  The custom dialer
	// re-validates every resolved IP at connect time, so DNS rebinding
	// between our pre-check and the actual Post can't land the request
	// on a loopback/private address.
	client := safeForwardClient()
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

// ipSafe returns ("", true) when ip is a routable public address, or
// (reason, false) otherwise.  Single source of truth for the SSRF guard —
// used both by the pre-check in forwardHostSafe and by the custom
// DialContext that closes the DNS-rebinding TOCTOU.
func ipSafe(ip net.IP) (string, bool) {
	if ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return fmt.Sprintf("blocked address %s", ip.String()), false
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10 — not covered by IsPrivate.
		if v4[0] == 100 && (v4[1]&0xC0) == 64 {
			return "CGNAT range blocked", false
		}
		// IPv4-mapped IPv6 to loopback (e.g., ::ffff:127.0.0.1).  IsLoopback
		// on modern Go already catches this, belt-and-braces here.
		if v4.IsLoopback() {
			return "ipv4-mapped loopback blocked", false
		}
	}
	return "", true
}

// forwardHostSafe is the SSRF pre-check.  Parses host[:port], resolves DNS,
// and rejects any resolved IP that lands in loopback / private / link-local
// / ULA / CGNAT.  Returns (reason, true=safe).
//
// NOTE: this is a PRE-check — between this call and the HTTP Post, DNS
// could rebind.  `safeForwardClient` installs a custom DialContext that
// re-validates at connect time, closing the window.
func forwardHostSafe(forwardTo string) (string, bool) {
	// Split host[:port].  If no port, treat the whole thing as host.
	host, _, err := net.SplitHostPort(forwardTo)
	if err != nil {
		host = forwardTo
	}

	// Strip brackets that net.SplitHostPort sometimes leaves around bare IPv6.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return "empty host", false
	}

	// Block explicit names regardless of resolution (defense in depth).
	switch strings.ToLower(host) {
	case "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback":
		return "loopback name", false
	}

	// Resolve — rejects on failure so unresolvable hosts can't slip through.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "cannot resolve host", false
	}

	for _, ip := range ips {
		if reason, ok := ipSafe(ip); !ok {
			return reason, false
		}
	}
	return "", true
}

// safeForwardClient returns an http.Client whose DialContext re-resolves
// the destination host itself and verifies every candidate IP against
// ipSafe() *before* connecting.  This closes the DNS-rebinding TOCTOU:
// forwardHostSafe resolved + validated, but the default http client
// would resolve again at connect time and could land on a different
// (now-malicious) IP.
//
// Connects to the resolved IP directly (not the hostname) so the OS
// resolver is never consulted twice.  If the URL supplies a bare IP we
// skip resolution entirely.
func safeForwardClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: forwardTimeout,
	}
	return &http.Client{
		Timeout: forwardTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				// If addr already contains an IP literal, use it directly;
				// otherwise resolve now.
				var candidates []net.IP
				if ip := net.ParseIP(host); ip != nil {
					candidates = []net.IP{ip}
				} else {
					resolved, err := (&net.Resolver{}).LookupIPAddr(ctx, host)
					if err != nil {
						return nil, err
					}
					candidates = make([]net.IP, 0, len(resolved))
					for _, r := range resolved {
						candidates = append(candidates, r.IP)
					}
				}

				var lastErr error
				for _, ip := range candidates {
					if reason, ok := ipSafe(ip); !ok {
						lastErr = fmt.Errorf("SSRF: %s", reason)
						continue
					}
					conn, err := dialer.DialContext(ctx, network,
						net.JoinHostPort(ip.String(), port))
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				if lastErr == nil {
					lastErr = fmt.Errorf("no safe IP for %s", host)
				}
				return nil, lastErr
			},
		},
	}
}

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
