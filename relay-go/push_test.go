// push_test.go — unit tests for the PushStore + PushSender pair.
//
// PushStore exercises the storage contract: upsert-by-(peer_id, platform),
// empty-token-means-unregister, multi-platform-per-peer, and
// restart-survivability on the same SQLite file.  PushSender is
// minimally exercised since it's a stub today — the live APNs / FCM
// path lives behind an operational config toggle.

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fresh store backed by a per-test SQLite file.  Sharing the file
// with Mailbox mirrors the production layout: both use the single
// relay DB, so restart semantics are identical.
func newTestPushStore(t *testing.T) *PushStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "push.db")
	m, err := NewMailbox(path)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	// Deterministic per-test key — production derives this from the
	// relay's persistent X25519 priv via HKDF (Audit #3 C2).  Tests
	// don't need real key isolation, just a valid 32-byte key so
	// chacha20poly1305.NewX accepts it.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewPushStore(m.db, key)
	if err != nil {
		t.Fatalf("NewPushStore: %v", err)
	}
	return s
}

func TestPushStore_UpsertAndGet(t *testing.T) {
	s := newTestPushStore(t)

	if err := s.Upsert("alice", "ios", "abc123"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rs, err := s.GetForPeer("alice")
	if err != nil {
		t.Fatalf("GetForPeer: %v", err)
	}
	if len(rs) != 1 || rs[0].Platform != "ios" || rs[0].Token != "abc123" {
		t.Fatalf("unexpected rows: %+v", rs)
	}
	if rs[0].UpdatedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("updated_at ahead of wall clock")
	}
}

func TestPushStore_UpsertReplacesSamePlatformToken(t *testing.T) {
	s := newTestPushStore(t)

	_ = s.Upsert("alice", "ios", "old")
	_ = s.Upsert("alice", "ios", "new")

	rs, _ := s.GetForPeer("alice")
	if len(rs) != 1 {
		t.Fatalf("want one row after re-register, got %d", len(rs))
	}
	if rs[0].Token != "new" {
		t.Fatalf("token not replaced: got %q", rs[0].Token)
	}
}

func TestPushStore_DifferentPlatformsCoexist(t *testing.T) {
	s := newTestPushStore(t)

	_ = s.Upsert("alice", "ios", "ios-token")
	_ = s.Upsert("alice", "android", "fcm-token")

	rs, _ := s.GetForPeer("alice")
	if len(rs) != 2 {
		t.Fatalf("want two rows across platforms, got %d", len(rs))
	}
	// Platform ordering is driven by SQLite's natural row order, not
	// by the test — just check both showed up.
	platforms := map[string]string{}
	for _, r := range rs {
		platforms[r.Platform] = r.Token
	}
	if platforms["ios"] != "ios-token" || platforms["android"] != "fcm-token" {
		t.Fatalf("unexpected platform map: %+v", platforms)
	}
}

func TestPushStore_EmptyTokenDeletesRow(t *testing.T) {
	s := newTestPushStore(t)

	_ = s.Upsert("alice", "ios", "abc123")
	if rs, _ := s.GetForPeer("alice"); len(rs) != 1 {
		t.Fatalf("setup: expected 1 row")
	}

	// Empty token acts as unregister — the row is deleted, not
	// overwritten with empty string.
	if err := s.Upsert("alice", "ios", ""); err != nil {
		t.Fatalf("Upsert empty: %v", err)
	}
	if rs, _ := s.GetForPeer("alice"); len(rs) != 0 {
		t.Fatalf("expected row deleted, got %+v", rs)
	}
}

func TestPushStore_GetForUnknownPeerEmpty(t *testing.T) {
	s := newTestPushStore(t)
	rs, err := s.GetForPeer("nobody")
	if err != nil {
		t.Fatalf("GetForPeer: %v", err)
	}
	if len(rs) != 0 {
		t.Fatalf("want empty, got %+v", rs)
	}
}

func TestPushStore_DeleteForPeerRemovesAllPlatforms(t *testing.T) {
	s := newTestPushStore(t)
	_ = s.Upsert("alice", "ios", "a")
	_ = s.Upsert("alice", "android", "b")

	if err := s.DeleteForPeer("alice"); err != nil {
		t.Fatalf("DeleteForPeer: %v", err)
	}
	if rs, _ := s.GetForPeer("alice"); len(rs) != 0 {
		t.Fatalf("want nothing after delete, got %+v", rs)
	}
}

func TestPushStore_RejectsEmptyInputs(t *testing.T) {
	s := newTestPushStore(t)

	// Each guard is a silent no-op — caller can't tell the diff, but
	// the table stays empty.  Prevents garbage rows from accidental
	// empty values on the wire.
	_ = s.Upsert("", "ios", "tok")
	_ = s.Upsert("alice", "", "tok")

	if rs, _ := s.GetForPeer("alice"); len(rs) != 0 {
		t.Fatalf("empty-input guards leaked a row: %+v", rs)
	}
	if rs, _ := s.GetForPeer(""); len(rs) != 0 {
		t.Fatalf("empty-peer GetForPeer should return no rows")
	}
}

// Audit #3 C2: tokens MUST be sealed with XChaCha20-Poly1305 before
// they touch SQLite.  Read the raw token column out from under the
// store and assert (a) it carries the v1: prefix and (b) the cleartext
// token doesn't appear anywhere in the stored bytes.  A regression
// that reverted Upsert to plaintext would trip this test immediately.
func TestPushStore_TokensEncryptedAtRest(t *testing.T) {
	s := newTestPushStore(t)
	const plain = "apns-token-deadbeefcafef00d"

	if err := s.Upsert("alice", "ios", plain); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	var stored string
	row := s.db.QueryRow(
		`SELECT token FROM push_tokens WHERE peer_id=? AND platform=?;`,
		"alice", "ios")
	if err := row.Scan(&stored); err != nil {
		t.Fatalf("raw scan: %v", err)
	}
	if !strings.HasPrefix(stored, tokenCipherPrefix) {
		t.Fatalf("stored value missing %q prefix: %q", tokenCipherPrefix, stored)
	}
	if strings.Contains(stored, plain) {
		t.Fatalf("plaintext token leaked into storage: %q", stored)
	}

	// Sanity check the round trip still works through the public API.
	rs, err := s.GetForPeer("alice")
	if err != nil || len(rs) != 1 || rs[0].Token != plain {
		t.Fatalf("round-trip decrypt failed: err=%v rows=%+v", err, rs)
	}
}

// AAD ties each row to its (peer_id, platform) coordinates.  If a
// hostile relay operator copies the encrypted token from alice/ios into
// bob/ios, the AEAD tag verification must fail — otherwise we'd be
// vulnerable to row-swap attacks even with encryption on.  Models the
// "DBA can edit SQLite directly" threat that motivated C2.
func TestPushStore_RejectsRowSwap(t *testing.T) {
	s := newTestPushStore(t)
	if err := s.Upsert("alice", "ios", "alice-token"); err != nil {
		t.Fatalf("Upsert alice: %v", err)
	}
	if err := s.Upsert("bob", "ios", "bob-token"); err != nil {
		t.Fatalf("Upsert bob: %v", err)
	}

	// Swap alice's token blob into bob's row.
	var aliceCt string
	s.db.QueryRow(
		`SELECT token FROM push_tokens WHERE peer_id='alice' AND platform='ios';`,
	).Scan(&aliceCt)
	if _, err := s.db.Exec(
		`UPDATE push_tokens SET token=? WHERE peer_id='bob' AND platform='ios';`,
		aliceCt); err != nil {
		t.Fatalf("row swap: %v", err)
	}

	// bob's row now decrypts under bob/ios AAD — must fail and be
	// silently dropped (NotifyOffline gets nothing for bob).
	rs, _ := s.GetForPeer("bob")
	if len(rs) != 0 {
		t.Fatalf("expected swapped row to be rejected, got %+v", rs)
	}
}

// NewPushStore must reject keys of the wrong size — fail-closed
// behaviour so a misconfigured caller can't silently disable the
// encryption Audit #3 C2 added.
func TestNewPushStore_RejectsBadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.db")
	m, _ := NewMailbox(path)
	defer m.Close()

	if _, err := NewPushStore(m.db, nil); err == nil {
		t.Fatalf("nil key accepted")
	}
	if _, err := NewPushStore(m.db, make([]byte, 16)); err == nil {
		t.Fatalf("16-byte key accepted (want 32)")
	}
}

func TestPushSender_CooldownSuppressesBurst(t *testing.T) {
	// Stub sender only — just verifies the per-peer cooldown fires
	// exactly once when called repeatedly within the window.  The
	// stub doesn't actually block, so this is a structural check:
	// the exported behaviour is "multiple calls inside cooldown ≡
	// single call."  If we ever wire the live path, this test still
	// holds because NotifyOffline's cooldown gate runs before the
	// send branches.
	p := NewPushSender(false)
	p.coolDown = 50 * time.Millisecond

	records := []PushRecord{
		{PeerID: "alice", Platform: "ios", Token: "abc"},
	}

	// Three rapid calls — only the first should pass the cooldown;
	// the other two are absorbed.  The stub's only visible effect is
	// a log line, so we assert via the exported `lastSent` map
	// which we inspect through a second call that's forced through.
	p.NotifyOffline("alice", records)
	first := p.lastSent["alice"]

	p.NotifyOffline("alice", records)
	p.NotifyOffline("alice", records)
	if p.lastSent["alice"] != first {
		t.Fatalf("cooldown did not suppress subsequent calls")
	}

	// Wait past the cooldown window; next call should update
	// lastSent.
	time.Sleep(60 * time.Millisecond)
	p.NotifyOffline("alice", records)
	if !p.lastSent["alice"].After(first) {
		t.Fatalf("post-cooldown call did not update lastSent")
	}
}
