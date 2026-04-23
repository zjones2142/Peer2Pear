// peer_hash_test.go — opacity tests for arch-review #8.
//
// The production invariant: a snapshot of the relay's SQLite file
// must not reveal which peer IDs have used this relay.  Before #8,
// `envelopes.recipient_id`, `push_tokens.peer_id`, and
// `seen_auth_nonces.key` all held raw base64url peer IDs.  After
// #8, each row keys off HMAC-SHA256(relayKey, peerID)[:16] — a
// snapshot alone is opaque without the onion private key.
//
// These tests drive the three writers (Mailbox.Store,
// PushStore.Upsert, Mailbox.RegisterAuthNonce), then drop down to
// raw SQL to confirm the peer ID never appears as a substring of
// any stored column value.  They also verify that the matching
// reads still find the row via the hashed lookup key.

package main

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// allPeerIdColumnValues walks every sensitive column in the relay DB
// and returns every stored value (as strings) so the test can search
// for raw-peer-ID substrings.  Uses bare sqlite3 to bypass the
// helpers — we want to see what a DBA / forensic analyst would see
// looking at the file directly.
func allPeerIdColumnValues(t *testing.T, dbPath string) []string {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()

	var out []string
	collect := func(q string) {
		rows, err := db.Query(q)
		if err != nil {
			return // table may not exist yet; that's fine
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err == nil {
				out = append(out, v)
			}
		}
	}
	collect("SELECT recipient_id FROM envelopes;")
	collect("SELECT peer_id FROM push_tokens;")
	collect("SELECT key FROM seen_auth_nonces;")
	return out
}

// Install a deterministic peer hasher so every test gets the same
// hashed form for a given peer ID (test assertions depend on
// repeatability).  Returns the key bytes so the test can verify
// the hash value directly if needed.
func installTestHasher(t *testing.T) {
	t.Helper()
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i) ^ 0xA5  // any stable non-zero pattern
	}
	setGlobalPeerHasher(derivePeerHasher(&priv))
	t.Cleanup(func() {
		setGlobalPeerHasher(nil)
	})
}

// ── 1. Mailbox.Store — recipient_id hashed at rest ─────────────────────

func TestPeerIdOpaque_MailboxStoreHashesRecipient(t *testing.T) {
	installTestHasher(t)

	dbPath := filepath.Join(t.TempDir(), "mbox.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	defer m.Close()

	const sentinelPeer = "SENTINEL_PEER_ID_zXwvUtSrQpOnMlKjIhGfEdCbAz0987654321"
	payload := bytes.Repeat([]byte{0xAB}, 128)
	if err := m.Store(sentinelPeer, payload); err != nil {
		t.Fatalf("Store: %v", err)
	}

	values := allPeerIdColumnValues(t, dbPath)
	if len(values) == 0 {
		t.Fatalf("no rows visible — did the INSERT land?")
	}
	for _, v := range values {
		if strings.Contains(v, sentinelPeer) {
			t.Fatalf("raw peer ID leaked into SQLite: %q", v)
		}
	}

	// And the live-lookup path should still find the row.
	got := m.FetchAll(sentinelPeer)
	if len(got) != 1 {
		t.Fatalf("FetchAll returned %d envelopes, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Fatalf("payload mismatch after hashed round-trip")
	}
}

// ── 2. PushStore.Upsert — peer_id hashed at rest ───────────────────────

func TestPeerIdOpaque_PushStoreHashesPeerId(t *testing.T) {
	installTestHasher(t)

	dbPath := filepath.Join(t.TempDir(), "push.db")
	mbox, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	defer mbox.Close()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	store, err := NewPushStore(mbox.db, key)
	if err != nil {
		t.Fatalf("NewPushStore: %v", err)
	}

	const sentinelPeer = "SENTINEL_PUSHPEER_xyzABC1234567890abcdefghij"
	if err := store.Upsert(sentinelPeer, "ios", "token-data"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	values := allPeerIdColumnValues(t, dbPath)
	for _, v := range values {
		if strings.Contains(v, sentinelPeer) {
			t.Fatalf("raw push peer_id leaked into SQLite: %q", v)
		}
	}

	rs, err := store.GetForPeer(sentinelPeer)
	if err != nil || len(rs) != 1 {
		t.Fatalf("GetForPeer: rs=%v err=%v", rs, err)
	}
	// Caller sees the RAW peer ID back, not the hash.
	if rs[0].PeerID != sentinelPeer {
		t.Fatalf("GetForPeer returned hashed peer ID: %q (want raw)", rs[0].PeerID)
	}
	if rs[0].Token != "token-data" {
		t.Fatalf("token mismatch: %q", rs[0].Token)
	}
}

// ── 3. RegisterAuthNonce — key hashed at rest ──────────────────────────

func TestPeerIdOpaque_AuthNonceHashesKey(t *testing.T) {
	installTestHasher(t)

	dbPath := filepath.Join(t.TempDir(), "auth.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	defer m.Close()

	const sentinelKey = "SENTINEL_AUTHKEY_987zyxwvuUUTSRQponmlkjihGFEDCBA0|1730000000000"
	if !m.RegisterAuthNonce(sentinelKey, 2000000000000) {
		t.Fatalf("RegisterAuthNonce: expected first registration to succeed")
	}
	if m.RegisterAuthNonce(sentinelKey, 2000000000000) {
		t.Fatalf("RegisterAuthNonce: second call should report replay")
	}

	values := allPeerIdColumnValues(t, dbPath)
	for _, v := range values {
		if strings.Contains(v, sentinelKey) {
			t.Fatalf("raw auth-nonce key leaked into SQLite: %q", v)
		}
	}
}

// ── 4. Rotating the HMAC key invalidates old rows (documented behavior)

func TestPeerIdOpaque_DifferentKeyFindsNoOldRows(t *testing.T) {
	installTestHasher(t)

	dbPath := filepath.Join(t.TempDir(), "rotate.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	defer m.Close()

	const peer = "some-peer-id"
	if err := m.Store(peer, []byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if got := m.FetchAll(peer); len(got) != 1 {
		t.Fatalf("pre-rotation FetchAll: got %d, want 1", len(got))
	}

	// Rotate the hasher (simulating onion-key rotation in production).
	var newPriv [32]byte
	for i := range newPriv {
		newPriv[i] = byte(i) // different bytes
	}
	setGlobalPeerHasher(derivePeerHasher(&newPriv))

	// The old row is still on disk, but the new hash can't find it.
	if got := m.FetchAll(peer); len(got) != 0 {
		t.Fatalf("post-rotation FetchAll: got %d, expected the old row "+
			"to be unreachable under the new hash key", len(got))
	}
}
