// sqlcipher_test.go — opt-in at-rest encryption tests (arch-review #8).
//
// When RELAY_DB_KEY / RELAY_DB_KEY_FILE is set, NewMailbox opens the
// SQLite file through the SQLCipher driver so every byte on disk is
// ciphertext.  These tests pin:
//
//   * A freshly-written encrypted DB is NOT a plain SQLite file (no
//     "SQLite format 3" magic).
//   * Writes through the normal API (Store / Upsert) don't leak the
//     payload as raw bytes in the file.
//   * A second process opening the same path WITHOUT the key fails
//     with a clear error, not a panic or a silent data loss.
//   * Re-opening with the correct key returns the prior data.
//   * If an operator sets RELAY_DB_KEY against an existing plaintext
//     file, NewMailbox refuses rather than silently mixing modes.
//
// The tests use RELAY_DB_KEY_FILE so they don't leak key bytes via
// the env snapshot; the env value is restored on cleanup.

package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDbKeyEnv is a sibling of `withEnv` from onion_wrap_test.go that
// additionally unsets whichever of the two variables the caller didn't
// supply, so tests stay isolated even when they run back-to-back.
func withDbKeyEnv(t *testing.T, envKey, envValue string) {
	t.Helper()
	for _, k := range []string{"RELAY_DB_KEY", "RELAY_DB_KEY_FILE"} {
		old, had := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
	if envKey != "" && envValue != "" {
		os.Setenv(envKey, envValue)
	}
}

// writeRandomKeyFile drops a 32-byte random file and returns the path.
// The caller is expected to point RELAY_DB_KEY_FILE at it via
// withDbKeyEnv.
func writeRandomKeyFile(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	path := filepath.Join(t.TempDir(), "db_key.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}
	return path
}

// ── 1. Encrypted DB file has no SQLite magic ───────────────────────────

func TestSqlCipher_EncryptedFileHasNoSqliteMagic(t *testing.T) {
	keyFile := writeRandomKeyFile(t)
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", keyFile)

	dbPath := filepath.Join(t.TempDir(), "mbox.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	// Force a write so the file isn't still in cache/journal only.
	if err := m.Store("peer-for-magic-check", []byte("x")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	m.Close()

	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read dbfile: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("db file empty after write")
	}
	if bytes.HasPrefix(data, []byte("SQLite format 3\x00")) {
		t.Fatalf("encrypted-mode DB still carries the plaintext SQLite magic")
	}
}

// ── 2. Sentinel bytes in payload don't appear in the raw file ──────────

func TestSqlCipher_PayloadOpaqueOnDisk(t *testing.T) {
	keyFile := writeRandomKeyFile(t)
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", keyFile)

	dbPath := filepath.Join(t.TempDir(), "mbox.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	// Construct a structured payload so a search miss is meaningful.
	const sentinel = "PEER2PEAR_PAYLOAD_SENTINEL_ABCDEFGH"
	payload := []byte(sentinel + strings.Repeat("-", 4096))
	if err := m.Store("peer-payload-test", payload); err != nil {
		t.Fatalf("Store: %v", err)
	}
	m.Close()

	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read dbfile: %v", err)
	}
	if bytes.Contains(data, []byte(sentinel)) {
		t.Fatalf("payload sentinel leaked into encrypted file")
	}
}

// ── 3. Wrong key refuses to open, right key re-opens cleanly ───────────

func TestSqlCipher_WrongKeyRefusesCorrectKeyOpens(t *testing.T) {
	keyFile := writeRandomKeyFile(t)
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", keyFile)

	dbPath := filepath.Join(t.TempDir(), "mbox.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox: %v", err)
	}
	if err := m.Store("peer-roundtrip", []byte("hello")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	m.Close()

	// Rotate to a new key by pointing the env at a different file.
	wrongKeyFile := writeRandomKeyFile(t)
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", wrongKeyFile)
	if _, err := NewMailbox(dbPath); err == nil {
		t.Fatalf("expected NewMailbox to fail with the wrong key")
	}

	// Restore the original key — open should succeed and the row
	// should be readable.
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", keyFile)
	m2, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox with correct key: %v", err)
	}
	defer m2.Close()

	got := m2.FetchAll("peer-roundtrip")
	if len(got) != 1 || string(got[0].Payload) != "hello" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// ── 4. Setting RELAY_DB_KEY against a plaintext DB fails loudly ────────

func TestSqlCipher_RefusesToOpenPlaintextFileWithKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mbox.db")

	// Step 1: create a plaintext DB by calling NewMailbox without a key.
	withDbKeyEnv(t, "", "")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox (plaintext): %v", err)
	}
	if err := m.Store("peer-for-plaintext", []byte("legacy")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	m.Close()

	// Step 2: set RELAY_DB_KEY and try to reopen the same file.
	keyFile := writeRandomKeyFile(t)
	withDbKeyEnv(t, "RELAY_DB_KEY_FILE", keyFile)
	if _, err := NewMailbox(dbPath); err == nil {
		t.Fatalf("expected NewMailbox to refuse a plaintext file when key is set")
	}
}

// ── 5. Bad RELAY_DB_KEY (wrong length / not base64) is fatal ──────────

func TestSqlCipher_BadKeyEnvIsFatal(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mbox.db")

	withDbKeyEnv(t, "RELAY_DB_KEY", "!!! not base64 !!!")
	if _, err := NewMailbox(dbPath); err == nil {
		t.Fatalf("expected failure for non-base64 RELAY_DB_KEY")
	}

	short := base64.RawURLEncoding.EncodeToString([]byte("short"))
	withDbKeyEnv(t, "RELAY_DB_KEY", short)
	if _, err := NewMailbox(dbPath); err == nil {
		t.Fatalf("expected failure for wrong-length RELAY_DB_KEY")
	}
}

// ── 6. Plaintext path still works (default, no key configured) ─────────

func TestSqlCipher_PlaintextModeStillWorks(t *testing.T) {
	withDbKeyEnv(t, "", "")
	dbPath := filepath.Join(t.TempDir(), "mbox.db")
	m, err := NewMailbox(dbPath)
	if err != nil {
		t.Fatalf("NewMailbox plaintext: %v", err)
	}
	defer m.Close()

	if err := m.Store("peer-plaintext", []byte("data")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got := m.FetchAll("peer-plaintext")
	if len(got) != 1 {
		t.Fatalf("FetchAll: got %d, want 1", len(got))
	}

	// And a raw sqlite3 client (via our own driver registration, not
	// re-registering) must confirm the magic header is present — i.e.
	// this mode is exactly the pre-#8 behaviour.
	raw, _ := os.ReadFile(dbPath)
	if !bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("plaintext-mode DB missing SQLite magic — unexpected opacity")
	}
	// And make sure `database/sql` can still reach it.
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("sql.Open plaintext: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping plaintext: %v", err)
	}
}
