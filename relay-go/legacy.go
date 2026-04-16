// Legacy endpoints for backward compatibility with existing Qt clients.
// These will be removed once all clients migrate to the /v1/* protocol.
//
// Endpoints:
//   POST /mbox/enqueue    — authenticated envelope submission (→ bridges to WS push)
//   GET  /mbox/fetch      — poll for one envelope
//   GET  /mbox/fetch_all  — poll for all envelopes
//   POST /mbox/ack        — no-op (fetch already deletes)
//   POST /rvz/publish     — register host:port for peer discovery
//   POST /rvz/lookup      — look up host:port by peer ID

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ── In-memory rendezvous store (replaces old SQLite table) ───────────────────

type rvzEntry struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	ExpiryMs int64  `json:"expiry_ms"`
}

var (
	rvzMu    sync.RWMutex
	rvzStore = make(map[string]*rvzEntry)
)

const rvzMaxTTLMs = 15 * 60 * 1000 // 15 minutes

// ── Legacy auth helper ───────────────────────────────────────────────────────

func checkRecipientSig(toID string, ts int64, nonce, sig, action, envID string) error {
	now := nowMs()
	if ts+replayWindowMs < now || ts > now+replayWindowMs {
		return fmt.Errorf("timestamp outside window")
	}
	message := fmt.Sprintf("MBX1|%s|%d|%s|%s|%s", toID, ts, nonce, action, envID)
	if !verifyEd25519(toID, sig, message) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// ── POST /mbox/enqueue ───────────────────────────────────────────────────────

func (h *Hub) LegacyEnqueue(w http.ResponseWriter, r *http.Request) {
	// Fix #8: legacy /mbox/enqueue was bypassing both rate limiters entirely,
	// nullifying H3 for any attacker willing to hit the legacy endpoint.
	// Apply the same per-IP and per-recipient ceilings used by /v1/send.
	if !h.rl.allow(hashIP(h.clientIP(r))) {
		httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	xTo := r.Header.Get("X-To")
	if xTo == "" {
		httpError(w, http.StatusBadRequest, "missing X-To header")
		return
	}

	if !h.rlRecip.allowWithLimit(xTo, recipientRateLimitPerMin) {
		httpError(w, http.StatusTooManyRequests, "recipient rate limit exceeded")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxEnvelopeBytes)+1))
	if err != nil || len(body) == 0 {
		httpError(w, http.StatusBadRequest, "empty or unreadable body")
		return
	}
	if len(body) > maxEnvelopeBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	ttlMs := int64(defaultTTLMs)
	if v := r.Header.Get("X-TtlMs"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			if parsed > maxTTLMs {
				parsed = maxTTLMs
			}
			ttlMs = parsed
		}
	}

	envID := r.Header.Get("X-EnvId")

	// Try WebSocket push first (bridge old clients to new receive path)
	h.mu.RLock()
	p, online := h.peers[xTo]
	h.mu.RUnlock()

	if online {
		select {
		case p.Send <- body:
			log.Printf("legacy enqueue→ws push: to=%s… size=%dB", truncID(xTo), len(body))
			if envID == "" {
				envID = fmt.Sprintf("%d-%s", nowMs(), randomHex(8))
			}
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "env_id": envID})
			return
		default:
			// buffer full, fall through to storage
		}
	}

	// Store in mailbox
	storedID, err := h.mbox.StoreWithTTL(xTo, body, ttlMs)
	if err != nil {
		httpError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if envID == "" {
		envID = storedID
	}

	log.Printf("legacy enqueue: to=%s… size=%dB ttl=%ds", truncID(xTo), len(body), ttlMs/1000)
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "env_id": envID})
}

// ── GET /mbox/fetch ──────────────────────────────────────────────────────────

func (h *Hub) LegacyFetch(w http.ResponseWriter, r *http.Request) {
	xTo := r.Header.Get("X-To")
	ts, _ := strconv.ParseInt(r.Header.Get("X-Ts"), 10, 64)
	nonce := r.Header.Get("X-Nonce")
	sig := r.Header.Get("X-Sig")

	if err := checkRecipientSig(xTo, ts, nonce, sig, "fetch", ""); err != nil {
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}

	envID, payload, createdMs, expiryMs := h.mbox.FetchOne(xTo)
	if payload == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-EnvId", envID)
	w.Header().Set("X-CreatedAtMs", strconv.FormatInt(createdMs, 10))
	w.Header().Set("X-ExpiryAtMs", strconv.FormatInt(expiryMs, 10))
	w.Write(payload)
}

// ── GET /mbox/fetch_all ──────────────────────────────────────────────────────

func (h *Hub) LegacyFetchAll(w http.ResponseWriter, r *http.Request) {
	xTo := r.Header.Get("X-To")
	ts, _ := strconv.ParseInt(r.Header.Get("X-Ts"), 10, 64)
	nonce := r.Header.Get("X-Nonce")
	sig := r.Header.Get("X-Sig")

	if err := checkRecipientSig(xTo, ts, nonce, sig, "fetch_all", ""); err != nil {
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}

	payloads := h.mbox.FetchAll(xTo)
	if len(payloads) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Printf("legacy fetch_all: to=%s… delivered %d envelope(s)", truncID(xTo), len(payloads))

	type envResp struct {
		EnvID      string `json:"env_id"`
		PayloadB64 string `json:"payload_b64"`
	}
	result := make([]envResp, len(payloads))
	for i, p := range payloads {
		result[i] = envResp{
			EnvID:      fmt.Sprintf("legacy-%d", i),
			PayloadB64: b64urlEncode(p),
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// ── POST /mbox/ack ───────────────────────────────────────────────────────────

func (h *Hub) LegacyAck(w http.ResponseWriter, r *http.Request) {
	xTo := r.Header.Get("X-To")
	ts, _ := strconv.ParseInt(r.Header.Get("X-Ts"), 10, 64)
	nonce := r.Header.Get("X-Nonce")
	sig := r.Header.Get("X-Sig")

	var body struct {
		EnvID string `json:"env_id"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	if err := checkRecipientSig(xTo, ts, nonce, sig, "ack", body.EnvID); err != nil {
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// No-op — fetch already deletes
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── POST /rvz/publish ────────────────────────────────────────────────────────

func (h *Hub) LegacyRvzPublish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		ExpiresMs int64  `json:"expires_ms"`
		Sig       string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json")
		return
	}

	msg := fmt.Sprintf("RVZ1|%s|%s|%d|%d", req.ID, req.Host, req.Port, req.ExpiresMs)
	if !verifyEd25519(req.ID, req.Sig, msg) {
		httpError(w, http.StatusUnauthorized, "signature invalid")
		return
	}

	ttl := req.ExpiresMs
	if ttl > rvzMaxTTLMs {
		ttl = rvzMaxTTLMs
	}
	exp := time.Now().UnixMilli() + ttl

	rvzMu.Lock()
	rvzStore[req.ID] = &rvzEntry{Host: req.Host, Port: req.Port, ExpiryMs: exp}
	rvzMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expires_at_ms": exp})
}

// ── POST /rvz/lookup ─────────────────────────────────────────────────────────

func (h *Hub) LegacyRvzLookup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json")
		return
	}

	rvzMu.RLock()
	entry := rvzStore[req.ID]
	rvzMu.RUnlock()

	if entry == nil || nowMs() > entry.ExpiryMs {
		rvzMu.Lock()
		delete(rvzStore, req.ID)
		rvzMu.Unlock()
		httpError(w, http.StatusNotFound, "not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"host":          entry.Host,
		"port":          entry.Port,
		"expires_at_ms": entry.ExpiryMs,
	})
}
