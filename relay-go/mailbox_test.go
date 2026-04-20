// mailbox_test.go — unit tests for the Mailbox storage layer.
//
// Covers the full CRUD surface plus:
//
//   - Transactional delete so a failed commit leaves the mailbox intact.
//   - Auth-nonce replay state persists across relay restart — a
//     freshly-opened Mailbox on the same DB file must still reject a
//     previously-registered nonce.
//   - Two-phase delivery.  FetchAll marks rows as in-flight instead of
//     deleting; ConfirmDelivered finishes the drop after a successful
//     WS write.  A crash between mark and confirm is recoverable — the
//     mark ages out and the next FetchAll returns the rows again.
//
// Each test uses a freshly-created SQLite file under t.TempDir() so
// cases are isolated.  Integration tests that exercise the HTTP +
// WebSocket surface live in relay_test.go.

package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

// ── helpers ────────────────────────────────────────────────────────────

// newTestMailbox returns a fresh Mailbox backed by an on-disk SQLite
// file in the test's tempdir — so a second openMailbox on the same
// path (simulating a relay restart) sees the persisted state.
func newTestMailbox(t *testing.T) (*Mailbox, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailbox.db")
	m, err := NewMailbox(path)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m, path
}

func mustStore(t *testing.T, m *Mailbox, recipient string, payload []byte) {
	t.Helper()
	if err := m.Store(recipient, payload); err != nil {
		t.Fatalf("Store(%q): %v", recipient, err)
	}
}

func payloadSet(envs []StoredEnvelope) map[string]bool {
	out := make(map[string]bool, len(envs))
	for _, e := range envs {
		out[string(e.Payload)] = true
	}
	return out
}

// ── Store + FetchAll round-trip ────────────────────────────────────────

func TestMailbox_StoreFetchConfirm_RoundTrip(t *testing.T) {
	m, _ := newTestMailbox(t)

	mustStore(t, m, "alice", []byte("hello"))
	mustStore(t, m, "alice", []byte("world"))

	envs := m.FetchAll("alice")
	if len(envs) != 2 {
		t.Fatalf("FetchAll: got %d, want 2", len(envs))
	}
	got := payloadSet(envs)
	if !got["hello"] || !got["world"] {
		t.Fatalf("unexpected payloads: %v", got)
	}

	for _, e := range envs {
		m.ConfirmDelivered(e.EnvID)
	}

	if left := m.FetchAll("alice"); left != nil {
		t.Fatalf("FetchAll after confirm: got %d, want 0", len(left))
	}
}

// ── Crash safety: unconfirmed envelopes reappear after stale window ───

func TestMailbox_UnconfirmedRedeliversAfterStaleWindow(t *testing.T) {
	m, _ := newTestMailbox(t)

	mustStore(t, m, "bob", []byte("first"))
	mustStore(t, m, "bob", []byte("second"))

	// Simulate a crash: fetch (which marks the rows in-flight) but
	// never call ConfirmDelivered.
	first := m.FetchAll("bob")
	if len(first) != 2 {
		t.Fatalf("first FetchAll: got %d, want 2", len(first))
	}

	// A second fetch *immediately* after the first must NOT return the
	// same rows — otherwise a reconnect race would double-deliver.
	if mid := m.FetchAll("bob"); len(mid) != 0 {
		t.Fatalf("immediate re-fetch: got %d, want 0 (rows still marked in-flight)", len(mid))
	}

	// Simulate enough wall time for the in-flight mark to age out.
	// Easiest way without mocking the clock: backdate the rows directly.
	if _, err := m.db.Exec(
		"UPDATE envelopes SET delivered_at = ? WHERE recipient_id = ?",
		time.Now().UnixMilli()-staleDeliveryMarkMs-1_000, "bob",
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	second := m.FetchAll("bob")
	if len(second) != 2 {
		t.Fatalf("post-stale FetchAll: got %d, want 2 (crash-recovery)", len(second))
	}
	want := payloadSet(first)
	got := payloadSet(second)
	for k := range want {
		if !got[k] {
			t.Fatalf("missing payload %q after stale redelivery", k)
		}
	}
}

// ── Partial crash: some confirmed, rest reappear ───────────────────────

func TestMailbox_PartialConfirmLeavesRestForRedelivery(t *testing.T) {
	m, _ := newTestMailbox(t)

	payloads := [][]byte{
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
	}
	for _, p := range payloads {
		mustStore(t, m, "peer", p)
	}

	fetched := m.FetchAll("peer")
	if len(fetched) != 4 {
		t.Fatalf("FetchAll: got %d, want 4", len(fetched))
	}

	// Confirm only the first two, simulating a mid-loop crash.
	m.ConfirmDelivered(fetched[0].EnvID)
	m.ConfirmDelivered(fetched[1].EnvID)

	// Age out the remaining marks.
	if _, err := m.db.Exec(
		"UPDATE envelopes SET delivered_at = ? WHERE delivered_at IS NOT NULL",
		time.Now().UnixMilli()-staleDeliveryMarkMs-1_000,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	redelivered := m.FetchAll("peer")
	if len(redelivered) != 2 {
		t.Fatalf("redelivery: got %d, want 2 (unconfirmed remainder)", len(redelivered))
	}

	// The redelivered set must be exactly the unconfirmed payloads.
	confirmedSet := map[string]bool{
		string(fetched[0].Payload): true,
		string(fetched[1].Payload): true,
	}
	for _, e := range redelivered {
		if confirmedSet[string(e.Payload)] {
			t.Fatalf("re-delivered an already-confirmed payload: %q", e.Payload)
		}
	}
}

// ── ConfirmDelivered is idempotent ─────────────────────────────────────

func TestMailbox_ConfirmDelivered_Idempotent(t *testing.T) {
	m, _ := newTestMailbox(t)
	mustStore(t, m, "x", []byte("p"))

	envs := m.FetchAll("x")
	if len(envs) != 1 {
		t.Fatalf("FetchAll: got %d, want 1", len(envs))
	}
	m.ConfirmDelivered(envs[0].EnvID)
	m.ConfirmDelivered(envs[0].EnvID) // second call is a no-op
	m.ConfirmDelivered("not-a-real-env-id")
	// No panic, no error — contract is "removes if present".
}

// ── Expiry purge removes rows regardless of delivered_at state ─────────

func TestMailbox_PurgeExpired_DropsDeliveredAndPending(t *testing.T) {
	m, _ := newTestMailbox(t)

	// Insert the fresh row FIRST — Store() sweeps expired rows as part of
	// its capacity precheck, so we'd lose our seed data if we seeded
	// expired rows before the fresh one.
	mustStore(t, m, "r", []byte("fresh"))

	if _, err := m.db.Exec(
		"INSERT INTO envelopes (env_id, recipient_id, payload, created_ms, expiry_ms) VALUES (?, ?, ?, ?, ?)",
		"e1", "r", []byte("p1"), time.Now().UnixMilli()-10, time.Now().UnixMilli()-1,
	); err != nil {
		t.Fatalf("seed expired pending: %v", err)
	}
	if _, err := m.db.Exec(
		"INSERT INTO envelopes (env_id, recipient_id, payload, created_ms, expiry_ms, delivered_at) VALUES (?, ?, ?, ?, ?, ?)",
		"e2", "r", []byte("p2"),
		time.Now().UnixMilli()-10, time.Now().UnixMilli()-1, time.Now().UnixMilli()-100,
	); err != nil {
		t.Fatalf("seed expired in-flight: %v", err)
	}

	removed, remaining := m.PurgeExpired()
	if removed < 2 {
		t.Fatalf("PurgeExpired removed %d, want ≥2", removed)
	}
	if remaining != 1 {
		t.Fatalf("PurgeExpired remaining %d, want 1 (only the fresh one)", remaining)
	}
}

// ── Per-recipient capacity cap ─────────────────────────────────────────

func TestMailbox_Store_PerRecipientCapacity(t *testing.T) {
	m, _ := newTestMailbox(t)

	// Fill alice's queue to maxQueueItems.
	for i := 0; i < maxQueueItems; i++ {
		if err := m.Store("alice", []byte{byte(i)}); err != nil {
			t.Fatalf("Store #%d: %v", i, err)
		}
	}
	// The next one must be rejected.
	if err := m.Store("alice", []byte("overflow")); err == nil {
		t.Fatalf("Store over cap: expected error, got nil")
	}
	// Other recipients are unaffected.
	if err := m.Store("bob", []byte("fine")); err != nil {
		t.Fatalf("Store(bob): %v", err)
	}
}

// ── Recipient isolation ────────────────────────────────────────────────

func TestMailbox_FetchAll_RecipientIsolation(t *testing.T) {
	m, _ := newTestMailbox(t)

	mustStore(t, m, "alice", []byte("for-alice"))
	mustStore(t, m, "bob", []byte("for-bob-1"))
	mustStore(t, m, "bob", []byte("for-bob-2"))

	aliceEnvs := m.FetchAll("alice")
	if len(aliceEnvs) != 1 || !bytes.Equal(aliceEnvs[0].Payload, []byte("for-alice")) {
		t.Fatalf("alice: %v", aliceEnvs)
	}
	bobEnvs := m.FetchAll("bob")
	if len(bobEnvs) != 2 {
		t.Fatalf("bob got %d, want 2", len(bobEnvs))
	}
	// Alice's mailbox is empty now, bob's rows are in-flight but not consumed.
	if ghost := m.FetchAll("unknown"); ghost != nil {
		t.Fatalf("unknown recipient: got %d, want 0", len(ghost))
	}
}

// ── StoreWithTTL caps at maxTTLMs ──────────────────────────────────────

func TestMailbox_StoreWithTTL_CapsAtMax(t *testing.T) {
	m, _ := newTestMailbox(t)

	envID, err := m.StoreWithTTL("r", []byte("p"), 0) // zero → default
	if err != nil {
		t.Fatalf("StoreWithTTL(0): %v", err)
	}
	if envID == "" {
		t.Fatalf("expected envID, got empty")
	}

	// Request an absurdly long TTL — should clamp silently.
	if _, err := m.StoreWithTTL("r", []byte("p2"), 365*24*60*60*1000); err != nil {
		t.Fatalf("StoreWithTTL(huge): %v", err)
	}

	// Verify one of the rows exists and its expiry is ≤ now + maxTTLMs + slop.
	var expiry int64
	if err := m.db.QueryRow(
		"SELECT expiry_ms FROM envelopes WHERE recipient_id='r' ORDER BY created_ms DESC LIMIT 1",
	).Scan(&expiry); err != nil {
		t.Fatalf("select expiry: %v", err)
	}
	ceiling := time.Now().UnixMilli() + maxTTLMs + 1000
	if expiry > ceiling {
		t.Fatalf("expiry %d exceeds ceiling %d (cap not applied)", expiry, ceiling)
	}
}

// ── RegisterAuthNonce rejects replays within the window ────────────────

func TestMailbox_RegisterAuthNonce_RejectsReplay(t *testing.T) {
	m, _ := newTestMailbox(t)
	exp := time.Now().UnixMilli() + 30_000

	if !m.RegisterAuthNonce("alice|123", exp) {
		t.Fatalf("first RegisterAuthNonce: returned false, want true")
	}
	if m.RegisterAuthNonce("alice|123", exp) {
		t.Fatalf("second RegisterAuthNonce: returned true, want false (replay)")
	}
	// A different nonce is still fresh.
	if !m.RegisterAuthNonce("alice|124", exp) {
		t.Fatalf("different nonce rejected unexpectedly")
	}
}

// ── RegisterAuthNonce allows the same nonce after its expiry ───────────

func TestMailbox_RegisterAuthNonce_ExpiredCanReuse(t *testing.T) {
	m, _ := newTestMailbox(t)

	// Register with an already-expired timestamp.  The opportunistic
	// cleanup inside RegisterAuthNonce clears it on the next call.
	if !m.RegisterAuthNonce("stale|1", time.Now().UnixMilli()-1) {
		t.Fatalf("first RegisterAuthNonce: returned false")
	}
	// Second call inserts a fresh row (the stale one was swept) — must return true.
	if !m.RegisterAuthNonce("stale|1", time.Now().UnixMilli()+30_000) {
		t.Fatalf("second RegisterAuthNonce after expiry: returned false, want true")
	}
}

// ── Auth replay survives relay restart ─────────────────────────────────
// Reopening the DB must still reject a previously-registered nonce within
// its replay window — the row lives in SQLite.

func TestMailbox_AuthReplayPersistsAcrossReopen(t *testing.T) {
	m, path := newTestMailbox(t)
	exp := time.Now().UnixMilli() + 30_000

	if !m.RegisterAuthNonce("alice|42", exp) {
		t.Fatalf("first RegisterAuthNonce on fresh mailbox")
	}
	m.Close()

	// Simulate relay restart: new Mailbox on the same DB file.
	m2, err := NewMailbox(path)
	if err != nil {
		t.Fatalf("reopen Mailbox: %v", err)
	}
	defer m2.Close()

	if m2.RegisterAuthNonce("alice|42", exp) {
		t.Fatalf("post-restart RegisterAuthNonce: returned true, want false (regression)")
	}
}

// ── PurgeExpiredAuthNonces removes stale rows only ─────────────────────

func TestMailbox_PurgeExpiredAuthNonces(t *testing.T) {
	m, _ := newTestMailbox(t)

	// Seed the stale row directly — RegisterAuthNonce has an opportunistic
	// "DELETE expired" pass that would eat the stale entry on the *next*
	// call, stealing the result we want PurgeExpiredAuthNonces to produce.
	if _, err := m.db.Exec(
		"INSERT INTO seen_auth_nonces (key, expiry_ms) VALUES (?, ?)",
		"old|1", time.Now().UnixMilli()-10_000,
	); err != nil {
		t.Fatalf("seed stale nonce: %v", err)
	}
	if _, err := m.db.Exec(
		"INSERT INTO seen_auth_nonces (key, expiry_ms) VALUES (?, ?)",
		"fresh|1", time.Now().UnixMilli()+30_000,
	); err != nil {
		t.Fatalf("seed fresh nonce: %v", err)
	}

	n := m.PurgeExpiredAuthNonces()
	if n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	// Fresh one still rejects a replay.
	if m.RegisterAuthNonce("fresh|1", time.Now().UnixMilli()+30_000) {
		t.Fatalf("fresh nonce: returned true, want false (still active)")
	}
	// Old one is re-acceptable now (attacker re-registering with the same
	// key after expiry is by design — the timestamp bounds freshness).
	if !m.RegisterAuthNonce("old|1", time.Now().UnixMilli()+30_000) {
		t.Fatalf("purged old nonce: returned false, want true")
	}
}

// ── Empty FetchAll on unknown recipient returns nil cleanly ────────────

func TestMailbox_FetchAll_EmptyRecipient(t *testing.T) {
	m, _ := newTestMailbox(t)
	if envs := m.FetchAll("nobody"); envs != nil {
		t.Fatalf("unknown recipient: got %d, want nil", len(envs))
	}
	if envs := m.FetchAll(""); envs != nil {
		t.Fatalf("empty recipient: got %d, want nil", len(envs))
	}
}

// ── Count reflects both pending and in-flight rows ─────────────────────

func TestMailbox_Count_IncludesInFlight(t *testing.T) {
	m, _ := newTestMailbox(t)
	mustStore(t, m, "r", []byte("a"))
	mustStore(t, m, "r", []byte("b"))

	if c := m.Count(); c != 2 {
		t.Fatalf("Count before fetch: got %d, want 2", c)
	}
	fetched := m.FetchAll("r")
	if c := m.Count(); c != 2 {
		t.Fatalf("Count with 2 in-flight: got %d, want 2", c)
	}
	for _, e := range fetched {
		m.ConfirmDelivered(e.EnvID)
	}
	if c := m.Count(); c != 0 {
		t.Fatalf("Count after confirm: got %d, want 0", c)
	}
}

// ── Schema backward-compat: ALTER adds delivered_at on existing DBs ────

func TestMailbox_SchemaMigration_AddsDeliveredAtColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Create a legacy-shaped envelopes table *without* delivered_at.
	{
		m, err := NewMailbox(path)
		if err != nil {
			t.Fatalf("initial open: %v", err)
		}
		if _, err := m.db.Exec("DROP TABLE envelopes"); err != nil {
			t.Fatalf("drop: %v", err)
		}
		if _, err := m.db.Exec(`
			CREATE TABLE envelopes (
				env_id       TEXT PRIMARY KEY,
				recipient_id TEXT NOT NULL,
				payload      BLOB NOT NULL,
				created_ms   INTEGER NOT NULL,
				expiry_ms    INTEGER NOT NULL
			)
		`); err != nil {
			t.Fatalf("recreate legacy: %v", err)
		}
		m.Close()
	}

	// Reopening must ALTER in the new column.  Store → FetchAll → Confirm
	// all require delivered_at to work.
	m, err := NewMailbox(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer m.Close()

	if err := m.Store("r", []byte("post-migration")); err != nil {
		t.Fatalf("Store after migration: %v", err)
	}
	envs := m.FetchAll("r")
	if len(envs) != 1 || string(envs[0].Payload) != "post-migration" {
		t.Fatalf("FetchAll: %v", envs)
	}
}
