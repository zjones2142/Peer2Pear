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
	s, err := NewPushStore(m.db)
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
