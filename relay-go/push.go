package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// PushStore persists (peer_id, platform, token) tuples so the relay
// can wake an offline recipient's device via APNs / FCM when a new
// envelope arrives.  Tokens are upserted by (peer_id, platform);
// empty tokens act as "unregister" and delete the row.
//
// Tokens are encrypted at rest with XChaCha20-Poly1305 (Audit #3 C2).
// The AEAD key is derived from the relay's persistent X25519 private
// key via HKDF, so it lives only in memory and shares fate with the
// relay binary — a snapshot of the SQLite file alone does NOT expose
// any APNs/FCM tokens.  Stored format is `v1:` + base64(nonce||ct);
// the prefix lets us migrate any pre-encryption rows on read without
// a schema change.
//
// The store does NOT need to be durable across restarts for
// correctness — if it empties, clients re-register on their next
// authenticated WS connection (RelayClient replays m_pushPlatform /
// m_pushToken on every auth_ok).  Persistence is an optimisation so
// a freshly-restarted relay can wake offline recipients before they
// reconnect.
type PushStore struct {
	db   *sql.DB
	aead cipher.AEAD
}

// tokenCipherPrefix tags rows whose token column holds an encrypted
// blob (vs. a legacy plaintext token).  Pre-encryption deployments
// could have rows without this prefix; on read those are dropped
// (token returned empty) and the client re-registers on next auth_ok.
const tokenCipherPrefix = "v1:"

// derivePushTokenKey runs HKDF-SHA256 over the relay's X25519 private
// key to produce a 32-byte XChaCha20-Poly1305 key.  Tying it to the
// relay key means rotating the relay key invalidates all stored
// tokens (which is what we want — a key rotation should not leave
// reachable APNs tokens behind).
func derivePushTokenKey(relayPriv *[32]byte) []byte {
	h := hkdf.New(sha256.New, relayPriv[:], nil, []byte("peer2pear:push-token-v1"))
	out := make([]byte, chacha20poly1305.KeySize)
	io.ReadFull(h, out)
	return out
}

// PushRecord is what loadAll / GetForPeer return; tokens are stored
// as client-provided strings (hex for APNs, FCM instance ID for
// Firebase) — the relay treats them opaquely.
type PushRecord struct {
	PeerID    string
	Platform  string
	Token     string
	UpdatedAt time.Time
}

// NewPushStore opens (or creates) the push_tokens table and prepares
// the AEAD used for at-rest token encryption.  `key` must be 32 bytes
// — derive it via derivePushTokenKey from the relay's persistent
// X25519 private key.  An empty or wrong-sized key returns an error
// rather than silently disabling encryption (fail closed).
func NewPushStore(db *sql.DB, key []byte) (*PushStore, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("push token key must be %d bytes, got %d",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init push token cipher: %w", err)
	}
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS push_tokens (
            peer_id    TEXT NOT NULL,
            platform   TEXT NOT NULL,
            token      TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (peer_id, platform)
        );
    `)
	if err != nil {
		return nil, err
	}
	return &PushStore{db: db, aead: aead}, nil
}

// encryptToken seals a plaintext token with a fresh random 24-byte
// nonce and returns "v1:" + base64(nonce||ciphertext).  AAD ties the
// row to its (peer_id, platform) coordinates so a swapped row from a
// different peer fails AEAD verification.
func (s *PushStore) encryptToken(peerID, platform, plain string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aad := []byte(peerID + "|" + platform)
	ct := s.aead.Seal(nil, nonce, []byte(plain), aad)
	payload := make([]byte, 0, len(nonce)+len(ct))
	payload = append(payload, nonce...)
	payload = append(payload, ct...)
	return tokenCipherPrefix + base64.RawStdEncoding.EncodeToString(payload), nil
}

// decryptToken reverses encryptToken.  Rows missing the v1: prefix
// are pre-encryption legacy data — return empty so the caller treats
// them as missing and the client re-registers on next auth_ok rather
// than us silently exposing the plaintext.
func (s *PushStore) decryptToken(peerID, platform, stored string) (string, error) {
	if !strings.HasPrefix(stored, tokenCipherPrefix) {
		return "", nil
	}
	payload, err := base64.RawStdEncoding.DecodeString(stored[len(tokenCipherPrefix):])
	if err != nil {
		return "", err
	}
	if len(payload) < s.aead.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := payload[:s.aead.NonceSize()]
	ct := payload[s.aead.NonceSize():]
	aad := []byte(peerID + "|" + platform)
	pt, err := s.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Upsert writes or replaces the (peer_id, platform) row.  An empty
// token deletes the row instead of writing an empty string — the
// client contract is "empty token means unregister."  The token is
// sealed with XChaCha20-Poly1305 before it touches the DB; only the
// relay process (which holds the AEAD key) can read it back.
//
// Arch-review #8: the peer_id column stores hashPeerID(peerID), not
// the raw base64url peer ID.  The token AAD binds the *raw* peer ID
// + platform (so an AAD check still links the token to the specific
// user), but the row key on disk is the hash.  The hash preserves
// the uniqueness needed for ON CONFLICT targeting because HMAC-
// SHA256 collisions are out of reach at 128-bit truncation.
func (s *PushStore) Upsert(peerID, platform, token string) error {
	if peerID == "" || platform == "" {
		return nil
	}
	peerKey := hashPeerID(peerID)
	if token == "" {
		_, err := s.db.Exec(
			`DELETE FROM push_tokens WHERE peer_id=? AND platform=?;`,
			peerKey, platform)
		return err
	}
	sealed, err := s.encryptToken(peerID, platform, token)
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}
	_, err = s.db.Exec(`
        INSERT INTO push_tokens (peer_id, platform, token, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(peer_id, platform) DO UPDATE SET
            token      = excluded.token,
            updated_at = excluded.updated_at;
    `, peerKey, platform, sealed, time.Now().Unix())
	return err
}

// GetForPeer returns every token registered for a peer — typically
// one per platform, sometimes more if the user runs the app on both
// iOS and Android.  Caller fires a push to each.  Rows whose token
// fails to decrypt (legacy plaintext rows, or AEAD failures from a
// rotated relay key) are skipped silently — the client re-registers
// on next auth_ok and the next NotifyOffline picks up the fresh row.
//
// Arch-review #8: the row key on disk is hashPeerID(peerID); the
// AEAD AAD still binds the *raw* peer ID + platform, so we pass raw
// peerID into decryptToken.  PushRecord.PeerID is populated from the
// caller-supplied raw peerID (not re-read from the DB) so downstream
// callers don't see the opaque hash.
func (s *PushStore) GetForPeer(peerID string) ([]PushRecord, error) {
	if peerID == "" {
		return nil, nil
	}
	peerKey := hashPeerID(peerID)
	rows, err := s.db.Query(
		`SELECT platform, token, updated_at FROM push_tokens WHERE peer_id=?;`,
		peerKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PushRecord
	for rows.Next() {
		var r PushRecord
		var sealed string
		var ts int64
		if err := rows.Scan(&r.Platform, &sealed, &ts); err != nil {
			return nil, err
		}
		r.PeerID = peerID  // raw — what NotifyOffline / push.go expect
		plain, derr := s.decryptToken(peerID, r.Platform, sealed)
		if derr != nil || plain == "" {
			if derr != nil {
				log.Printf("push: token decrypt failed for %s… platform=%s: %v",
					truncID(peerID), r.Platform, derr)
			}
			continue
		}
		r.Token = plain
		r.UpdatedAt = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteForPeer wipes every token for a peer.  Used when a peer
// explicitly signs out (RelayClient sends a push_register with an
// empty token for one platform; Hub still calls this on peer close
// in the future if we decide to expire on disconnect).
func (s *PushStore) DeleteForPeer(peerID string) error {
	if peerID == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM push_tokens WHERE peer_id=?;`,
		hashPeerID(peerID))
	return err
}

// PushSender is the outbound side.  Today it's a stub that logs the
// call and does no network I/O — turning on real APNs / FCM is an
// operational step that requires an Apple Developer auth key
// (`.p8`) and/or a Firebase service account.  Once configured, swap
// SendStub for a real Send method that HTTP/2-POSTs to
// https://api.push.apple.com/3/device/<token>.
type PushSender struct {
	// Toggled from main.go based on env config.  When false (the
	// default) every push call just logs.  Gives us the full
	// recipient-offline-triggers-push plumbing without hitting
	// Apple's push servers unconfigured.
	live bool

	// Rate-limit: at most one push per recipient per window, to
	// avoid hammering APNs when a peer has many queued envelopes.
	mu       sync.Mutex
	lastSent map[string]time.Time
	coolDown time.Duration
}

// NewPushSender defaults to the stub.  Pass live=true once the APNs
// client is wired in.
func NewPushSender(live bool) *PushSender {
	return &PushSender{
		live:     live,
		lastSent: make(map[string]time.Time),
		coolDown: 20 * time.Second,
	}
}

// NotifyOffline fires a silent-push attempt to every device
// registered for `peerID`.  Best-effort — push failures don't block
// the envelope (it's already stored in the mailbox; the peer will
// fetch it on their next connection regardless).
func (p *PushSender) NotifyOffline(peerID string, records []PushRecord) {
	if len(records) == 0 {
		return
	}

	// Per-recipient cooldown — a burst of 50 envelopes in 2 s fires
	// one push, not 50.
	p.mu.Lock()
	if last, ok := p.lastSent[peerID]; ok && time.Since(last) < p.coolDown {
		p.mu.Unlock()
		return
	}
	p.lastSent[peerID] = time.Now()
	p.mu.Unlock()

	for _, r := range records {
		if p.live {
			// Real send path — turn on when APNs is configured.
			// Payload is `{"aps": {"content-available": 1}}` per
			// Apple's silent-push spec: wakes the app, shows no
			// banner.  Banner content is a local notification the
			// client fires after it fetches + decrypts.
			log.Printf("push: (live send not yet wired) to=%s… platform=%s",
				truncID(r.PeerID), r.Platform)
		} else {
			log.Printf("push: [stub] would wake peer=%s… platform=%s tokenPrefix=%s",
				truncID(r.PeerID), r.Platform, truncToken(r.Token))
		}
	}
}

func truncToken(t string) string {
	if len(t) > 8 {
		return t[:8] + "…"
	}
	return t
}
