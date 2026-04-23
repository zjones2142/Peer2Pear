// Onion routing — real multi-hop forwarding where each intermediate
// relay sees ONLY the next-hop URL and an opaque inner blob.  Only the
// exit relay's /v1/send sees the recipient pubkey (unavoidable — someone
// has to route).
//
// Wire format (must match core/OnionWrap.cpp):
//   [version(1)=0x01][ephPub(32)][nonce(24)][Box ciphertext]
//   Box plaintext = [nextHopUrlLen(2 BE)][nextHopUrl][innerBlob]
//
// This relies on the standard NaCl Box construction (X25519 +
// XSalsa20-Poly1305) via golang.org/x/crypto/nacl/box, which is wire-
// compatible with libsodium's crypto_box_easy.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	onionVersion        = 0x01
	relayKeyPathDefault = "/data/peer2pear_relay_x25519.key"

	// On-disk relay-key formats (Audit #3 C3):
	//   0x01 = legacy plaintext layout — 32 raw scalar bytes, file
	//          perms only.  Pre-C3 deploys wrote this.
	//   0x02 = KEK-wrapped:
	//             [0x02][nonce(24)][ciphertext(32+16 MAC)]
	//          Unwraps with XChaCha20-Poly1305 using the 32-byte KEK
	//          from env RELAY_KEY_KEK (base64url) or file at
	//          RELAY_KEY_KEK_FILE.  Container / shared-host deploys
	//          should set this so a file-perm bypass alone cannot
	//          recover the onion private scalar.
	relayKeyVersionPlaintext = byte(0x01)
	relayKeyVersionWrapped   = byte(0x02)
)

// loadRelayKek returns the operator-configured KEK.  Env takes
// precedence over the file path.  Returns (nil, nil) when no KEK is
// configured — callers log a warning + persist plaintext.
func loadRelayKek() ([]byte, error) {
	if b64 := os.Getenv("RELAY_KEY_KEK"); b64 != "" {
		raw, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			// Try standard base64 as a convenience — operators copy/paste
			// from different tools and the distinction shouldn't break startup.
			raw2, err2 := base64.StdEncoding.DecodeString(b64)
			if err2 != nil {
				return nil, fmt.Errorf("RELAY_KEY_KEK: not base64url or base64: %w", err)
			}
			raw = raw2
		}
		if len(raw) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("RELAY_KEY_KEK must decode to %d bytes, got %d",
				chacha20poly1305.KeySize, len(raw))
		}
		return raw, nil
	}
	if path := os.Getenv("RELAY_KEY_KEK_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read RELAY_KEY_KEK_FILE: %w", err)
		}
		if len(raw) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("RELAY_KEY_KEK_FILE must contain exactly %d bytes, got %d",
				chacha20poly1305.KeySize, len(raw))
		}
		return raw, nil
	}
	return nil, nil
}

// wrapRelayKey encrypts the 32-byte scalar under the KEK and returns
// [0x02][nonce(24)][ct||tag].
func wrapRelayKey(priv *[32]byte, kek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, priv[:], nil)
	out := make([]byte, 0, 1+len(nonce)+len(ct))
	out = append(out, relayKeyVersionWrapped)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// unwrapRelayKey reverses wrapRelayKey.  Returns (priv, nil) on success.
func unwrapRelayKey(blob []byte, kek []byte) (*[32]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(blob) < 1+ns+aead.Overhead()+32 {
		return nil, fmt.Errorf("wrapped key too short (%d bytes)", len(blob))
	}
	nonce := blob[1 : 1+ns]
	ct := blob[1+ns:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("relay key unwrap failed (wrong KEK?): %w", err)
	}
	if len(pt) != 32 {
		return nil, fmt.Errorf("unwrapped relay key has bad length %d", len(pt))
	}
	var priv [32]byte
	copy(priv[:], pt)
	return &priv, nil
}

// loadOrCreateRelayKey loads this relay's persistent X25519 keypair from
// disk, or generates + persists a fresh one if the file doesn't exist.
// Returns (pub, priv, err).
func loadOrCreateRelayKey() (*[32]byte, *[32]byte, error) {
	path := os.Getenv("RELAY_KEY_PATH")
	if path == "" {
		path = relayKeyPathDefault
	}

	kek, kekErr := loadRelayKek()
	if kekErr != nil {
		// Misconfigured KEK is a fatal startup problem — better to
		// fail loudly than silently fall back to plaintext.
		return nil, nil, kekErr
	}

	if data, err := os.ReadFile(path); err == nil {
		// Auto-detect the on-disk format.  Legacy plaintext is
		// exactly 32 bytes; wrapped is 0x02 + 24-byte nonce + 48-byte
		// ct+tag = 73 bytes.
		if len(data) == 32 {
			var priv [32]byte
			copy(priv[:], data)
			var pub [32]byte
			if err := derivePubFromPriv(&pub, &priv); err != nil {
				return nil, nil, err
			}
			// If a KEK is available now, migrate the file on next save.
			// We don't re-write opportunistically on load — that would
			// race with concurrent reads and doesn't add much value
			// given the file is already there.
			if kek != nil {
				fmt.Fprintf(os.Stderr,
					"notice: relay key at %s is still plaintext; delete it to re-generate a KEK-wrapped key\n",
					path)
			}
			return &pub, &priv, nil
		}
		if len(data) > 0 && data[0] == relayKeyVersionWrapped {
			if kek == nil {
				return nil, nil, fmt.Errorf(
					"relay key at %s is KEK-wrapped but no RELAY_KEY_KEK / RELAY_KEY_KEK_FILE is set",
					path)
			}
			priv, uerr := unwrapRelayKey(data, kek)
			if uerr != nil {
				return nil, nil, uerr
			}
			var pub [32]byte
			if err := derivePubFromPriv(&pub, priv); err != nil {
				return nil, nil, err
			}
			return &pub, priv, nil
		}
		// Unknown format — refuse to start rather than silently
		// overwrite something the operator put here on purpose.
		return nil, nil, fmt.Errorf("relay key at %s has unknown format", path)
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate relay key: %w", err)
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		// Best-effort — we can still run in memory if persistence fails.
		fmt.Fprintf(os.Stderr, "warning: could not mkdir %s: %v\n", dirOf(path), err)
	} else {
		// Prefer wrapped persistence when a KEK is configured.
		var blob []byte
		if kek != nil {
			wrapped, werr := wrapRelayKey(priv, kek)
			if werr != nil {
				return nil, nil, fmt.Errorf("wrap relay key: %w", werr)
			}
			blob = wrapped
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: RELAY_KEY_KEK not set — persisting relay key in plaintext. Set it to enable KEK wrapping (Audit #3 C3).\n")
			blob = priv[:]
		}
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not persist relay key: %v\n", err)
		}
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

	// Forward the inner blob as raw bytes to the next hop.  Use the
	// TOCTOU-safe client so DNS can't rebind between the SSRF check
	// above and the actual connect.
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
