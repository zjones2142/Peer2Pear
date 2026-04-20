// Fix #7: onion routing — real multi-hop forwarding where each intermediate
// relay sees ONLY the next-hop URL and an opaque inner blob.  Only the exit
// relay's /v1/send sees the recipient pubkey (unavoidable — someone has to
// route).
//
// Wire format (must match core/OnionWrap.cpp):
//   [version(1)=0x01][ephPub(32)][nonce(24)][Box ciphertext]
//   Box plaintext = [nextHopUrlLen(2 BE)][nextHopUrl][innerBlob]
//
// This relies on the standard NaCl Box construction (X25519 +
// XSalsa20-Poly1305) via golang.org/x/crypto/nacl/box, which is wire-
// compatible with libsodium's crypto_box_easy (the Python reference
// relay that also used pynacl.Box was retired on 2026-04-20).
//
// Usage: once vendored, run `go mod tidy` to fetch x/crypto.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	onionVersion        = 0x01
	relayKeyPathDefault = "/data/peer2pear_relay_x25519.key"
)

// loadOrCreateRelayKey loads this relay's persistent X25519 keypair from
// disk, or generates + persists a fresh one if the file doesn't exist.
// Returns (pub, priv, err).
func loadOrCreateRelayKey() (*[32]byte, *[32]byte, error) {
	path := os.Getenv("RELAY_KEY_PATH")
	if path == "" {
		path = relayKeyPathDefault
	}

	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		var priv [32]byte
		copy(priv[:], data)
		var pub [32]byte
		// Derive pub from priv by scalarmult with base point.  box.GenerateKey
		// doesn't expose a "given priv, give me pub" primitive, but
		// curve25519.ScalarBaseMult does.  We use the fact that NaCl uses
		// curve25519 under the hood — the "priv" is a clamped scalar.
		if err := derivePubFromPriv(&pub, &priv); err != nil {
			return nil, nil, err
		}
		return &pub, &priv, nil
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate relay key: %w", err)
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		// Best-effort — we can still run in memory if persistence fails.
		fmt.Fprintf(os.Stderr, "warning: could not mkdir %s: %v\n", dirOf(path), err)
	} else if err := os.WriteFile(path, priv[:], 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not persist relay key: %v\n", err)
	}
	return pub, priv, nil
}

// derivePubFromPriv computes the X25519 public key for a given scalar.
// Used when loading a persisted priv — box.GenerateKey returns both halves
// but we've only saved the priv half on disk.
func derivePubFromPriv(pub, priv *[32]byte) error {
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive pub: %w", err)
	}
	copy(pub[:], p)
	return nil
}

func dirOf(p string) string {
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i < 0 {
		return "."
	}
	return p[:i]
}

// HandleRelayInfo publishes the relay's X25519 pubkey for onion routing.
// Clients call this once per relay on connect and cache the result.
func (h *Hub) HandleRelayInfo(w http.ResponseWriter, r *http.Request) {
	pubB64 := b64urlEncode(h.relayX25519Pub[:])
	writeJSON(w, http.StatusOK, map[string]any{
		"x25519_pub": pubB64,
		"impl":       "go",
	})
}

// HandleForwardOnion peels one onion layer and forwards the inner blob to
// the next hop.  The intermediate relay does NOT learn the final recipient
// pubkey — only the exit relay's /v1/send does.
func (h *Hub) HandleForwardOnion(w http.ResponseWriter, r *http.Request) {
	if !h.rl.allow(hashIP(h.clientIP(r))) {
		httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxEnvelopeBytes)+2048))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read error")
		return
	}
	// Minimum: version(1) + ephPub(32) + nonce(24) + Box tag(16) + plaintext(>=3)
	if len(body) < 1+32+24+16+3 {
		httpError(w, http.StatusBadRequest, "onion envelope too small")
		return
	}
	if body[0] != onionVersion {
		httpError(w, http.StatusBadRequest, "unsupported onion version")
		return
	}

	var ephPub [32]byte
	copy(ephPub[:], body[1:33])
	var nonce [24]byte
	copy(nonce[:], body[33:57])
	ct := body[57:]

	// Peel one layer.  box.Open returns (plaintext, ok).
	plain, ok := box.Open(nil, ct, &nonce, &ephPub, h.relayX25519Priv)
	if !ok {
		httpError(w, http.StatusBadRequest, "onion decrypt failed")
		return
	}

	if len(plain) < 3 {
		httpError(w, http.StatusBadRequest, "onion plaintext too small")
		return
	}
	urlLen := int(binary.BigEndian.Uint16(plain[:2]))
	if urlLen == 0 || urlLen > len(plain)-2 {
		httpError(w, http.StatusBadRequest, "invalid next-hop url length")
		return
	}
	nextHopURL := string(plain[2 : 2+urlLen])
	innerBlob := plain[2+urlLen:]
	if len(innerBlob) == 0 {
		httpError(w, http.StatusBadRequest, "empty inner blob")
		return
	}

	// Parse + validate next-hop URL.
	parsed, err := url.Parse(nextHopURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		httpError(w, http.StatusBadRequest, "invalid next-hop url")
		return
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		httpError(w, http.StatusBadRequest, "invalid next-hop scheme")
		return
	}
	if parsed.Path != "/v1/send" && parsed.Path != "/v1/forward-onion" {
		httpError(w, http.StatusBadRequest, "invalid next-hop path")
		return
	}

	// SSRF check — exact same logic as /v1/forward.
	if reason, ok := forwardHostSafe(parsed.Host); !ok {
		httpError(w, http.StatusForbidden, "forwarding not allowed: "+reason)
		return
	}

	if len(innerBlob) > maxEnvelopeBytes+1024 {
		httpError(w, http.StatusRequestEntityTooLarge, "inner blob exceeds ceiling")
		return
	}

	// Forward the inner blob as raw bytes to the next hop.  M8 audit-#2:
	// use the TOCTOU-safe client so DNS can't rebind between the SSRF
	// check above and the actual connect.
	client := safeForwardClient()
	resp, err := client.Post(nextHopURL, "application/octet-stream",
		bytes.NewReader(innerBlob))
	if err != nil {
		httpError(w, http.StatusBadGateway, "cannot reach next hop")
		return
	}
	defer resp.Body.Close()

	writeJSON(w, http.StatusOK, map[string]any{
		"forwarded": true,
		"status":    resp.StatusCode,
	})
}
