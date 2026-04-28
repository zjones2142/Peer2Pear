// peer_hash.go — HMAC-keyed peer-ID hashing for the relay.
//
// The Go relay's SQLite file used to hold raw base64url peer IDs in
// three places:
//   * envelopes.recipient_id
//   * push_tokens.peer_id
//   * seen_auth_nonces.key   ("<peerId>|<ts>")
// Anyone with filesystem access to the relay volume could walk those
// columns and reconstruct the social graph — who talks to whom, whose
// device is online, whose tokens are registered.
//
// This helper swaps the plaintext IDs for HMAC-SHA256 hashes
// truncated to 128 bits (base64url encoded, 22 chars on the wire
// equivalent).  Rules:
//
//   * The HMAC key is per-process, derived from the relay's persistent
//     X25519 private key via HKDF-SHA256 with a stable info string.
//     The relay's disk footprint never carries the HMAC key in plain
//     form; rotating the onion key rotates the hashes too, which
//     effectively nulls the old mailbox on next restart — acceptable
//     because peers re-enqueue on reconnect and tokens re-register on
//     auth_ok.
//
//   * Hashes are collision-resistant at 2^64 birthday bound; the 128-
//     bit prefix keeps the SQLite index compact while staying far
//     outside any realistic attack budget for a relay operator who
//     wants to confirm "is this specific user using my relay?".
//
//   * Auth nonce keys hash the full "<peerId>|<ts>" string so the
//     temporal bucket is still cryptographically linked to a specific
//     peer (without revealing which peer).
//
// The live handler path always knows the raw peer ID (from the
// envelope header or WS auth frame), so hashing happens just-in-time
// at the storage boundary.  Incoming queries / pushes from memory
// are unaffected.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// peerHasher holds the HMAC key + offers a stable b64url-truncated
// hash.  The struct exists so we can pass it through Hub / Mailbox /
// PushStore without stashing a raw key in a package-level global.
type peerHasher struct {
	key []byte
}

// derivePeerHasher builds a peerHasher keyed by HKDF(relayPriv, info).
// Returns nil when relayPriv is nil — callers must fall back to the
// no-op hashPeerIDRaw path (but every production code path constructs
// the hasher after loadOrCreateRelayKey succeeds, so nil is only seen
// in pre-InitPush transient states).
func derivePeerHasher(relayPriv *[32]byte) *peerHasher {
	if relayPriv == nil {
		return nil
	}
	h := hkdf.New(sha256.New, relayPriv[:], nil,
		[]byte("peer2pear:peer-id-hash-v1"))
	key := make([]byte, 32)
	io.ReadFull(h, key)
	return &peerHasher{key: key}
}

// hash returns base64url(HMAC-SHA256(key, input))[:22 chars].  Empty
// input returns empty output so callers don't need to guard.  The
// 16-byte truncation matches the index width we use throughout.
func (p *peerHasher) hash(input string) string {
	if p == nil || input == "" {
		return input
	}
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(input))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// Package-level singleton for call sites that don't have a Hub / Mailbox
// reference handy (e.g. the SQL migration code in NewMailbox).  The Hub
// installs it via setGlobalPeerHasher after loadOrCreateRelayKey runs;
// callers guard with a nil check and fall back to raw input.
var (
	globalHasherMu sync.RWMutex
	globalHasher   *peerHasher
)

func setGlobalPeerHasher(h *peerHasher) {
	globalHasherMu.Lock()
	defer globalHasherMu.Unlock()
	globalHasher = h
}

func hashPeerID(peerID string) string {
	globalHasherMu.RLock()
	h := globalHasher
	globalHasherMu.RUnlock()
	return h.hash(peerID)
}
