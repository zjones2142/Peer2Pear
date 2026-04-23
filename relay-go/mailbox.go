package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultTTLMs  = 7 * 24 * 60 * 60 * 1000 // 7 days
	maxTTLMs      = 7 * 24 * 60 * 60 * 1000
	maxQueueItems = 5000
	// Two-phase delivery: FetchAll marks rows as in-flight (delivered_at =
	// now) instead of deleting; the caller DELETEs each row only after the
	// WS write succeeds.  If the relay crashes between mark and confirm,
	// the mark ages out and the next FetchAll for that peer re-sends the
	// envelope — client-side envelope-ID dedup (ChatController::
	// markSeenPersistent) catches any duplicate delivery after the crash.
	staleDeliveryMarkMs = 60 * 1000 // 60s
)

// StoredEnvelope bundles an env_id with its payload so the caller can
// confirm delivery per-envelope after a successful WS write.
type StoredEnvelope struct {
	EnvID   string
	Payload []byte
}

// Mailbox provides store-and-forward storage for sealed envelopes.
// Envelopes are stored as raw bytes (BLOBs) — no base64 encoding overhead.
type Mailbox struct {
	mu sync.Mutex
	db *sql.DB
}

func NewMailbox(dbPath string) (*Mailbox, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Connection pool tuning for concurrent access
	db.SetMaxOpenConns(1) // SQLite handles one writer at a time
	db.SetMaxIdleConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS envelopes (
			env_id       TEXT PRIMARY KEY,
			recipient_id TEXT NOT NULL,
			payload      BLOB NOT NULL,
			created_ms   INTEGER NOT NULL,
			expiry_ms    INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_env_recipient
		ON envelopes (recipient_id, created_ms);

		-- Persist seen auth nonces so a relay restart within the 30s
		-- replay window can't re-enable a captured auth tuple.
		CREATE TABLE IF NOT EXISTS seen_auth_nonces (
			key        TEXT PRIMARY KEY,
			expiry_ms  INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_seen_auth_expiry
		ON seen_auth_nonces (expiry_ms);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	// Ensure the envelopes table has the delivered_at column.  Idempotent:
	// newly-created DBs need the ADD, older DBs get it added on startup.
	// Ignore any "duplicate column" error — the only way ALTER fails here
	// is if the column already exists from a previous startup.
	_, _ = db.Exec("ALTER TABLE envelopes ADD COLUMN delivered_at INTEGER")

	return &Mailbox{db: db}, nil
}

// RegisterAuthNonce records `key` as seen with `expiryMs`.  Returns true if
// the nonce was new (auth proceeds), false if it was already seen (replay).
// Survives relay restart.
func (m *Mailbox) RegisterAuthNonce(key string, expiryMs int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean up stale rows opportunistically.  O(1) amortized when the index
	// on expiry_ms is used; avoids a background sweep lagging behind a flood.
	m.db.Exec("DELETE FROM seen_auth_nonces WHERE expiry_ms < ?", nowMs())

	res, err := m.db.Exec(
		"INSERT OR IGNORE INTO seen_auth_nonces (key, expiry_ms) VALUES (?, ?)",
		key, expiryMs,
	)
	if err != nil {
		log.Printf("RegisterAuthNonce insert error: %v", err)
		// Fail closed: treat DB error as "already seen" so we don't silently
		// accept replays if the insert never landed.
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		log.Printf("RegisterAuthNonce rowcount error: %v", err)
		return false
	}
	return n == 1
}

// PurgeExpiredAuthNonces drops any seen-nonce row whose expiry has passed.
// Called periodically by the Hub to keep the table bounded.
func (m *Mailbox) PurgeExpiredAuthNonces() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	res, err := m.db.Exec("DELETE FROM seen_auth_nonces WHERE expiry_ms < ?", nowMs())
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func (m *Mailbox) Close() {
	m.db.Close()
}

// Store saves an envelope for later delivery. Returns an error if the
// recipient's mailbox is full.
func (m *Mailbox) Store(recipientID string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowMs()

	// Purge expired before checking capacity
	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", now)

	// Check per-recipient capacity
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes WHERE recipient_id=?",
		recipientID).Scan(&count)
	if count >= maxQueueItems {
		return fmt.Errorf("mailbox full")
	}

	// Check global capacity to prevent disk exhaustion.
	var globalCount int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes").Scan(&globalCount)
	if globalCount >= maxGlobalEnvelopes {
		return fmt.Errorf("relay storage full")
	}

	envID := fmt.Sprintf("%d-%s", now, randomHex(8))
	expiry := now + defaultTTLMs

	_, err := m.db.Exec(
		"INSERT OR IGNORE INTO envelopes (env_id, recipient_id, payload, created_ms, expiry_ms) VALUES (?, ?, ?, ?, ?)",
		envID, recipientID, payload, now, expiry,
	)
	return err
}

// FetchAll returns all pending envelopes for a recipient, marking each
// one as in-flight.  The caller MUST call ConfirmDelivered(envID) after
// a successful WS write to remove the row; if the caller crashes before
// confirming, the mark ages out after staleDeliveryMarkMs and the next
// FetchAll on reconnect will re-deliver.  Client-side envelope-ID dedup
// catches duplicate deliveries across that window.  No data goes missing
// on the relay side; the worst case is a duplicate delivery the client
// dedups.
func (m *Mailbox) FetchAll(recipientID string) []StoredEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowMs()
	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", now)

	// Reset stale in-flight marks so a crashed previous delivery attempt
	// doesn't leave envelopes permanently stuck.
	m.db.Exec(
		"UPDATE envelopes SET delivered_at = NULL WHERE delivered_at IS NOT NULL AND delivered_at < ?",
		now-staleDeliveryMarkMs,
	)

	rows, err := m.db.Query(
		"SELECT env_id, payload FROM envelopes WHERE recipient_id=? AND delivered_at IS NULL ORDER BY created_ms ASC",
		recipientID,
	)
	if err != nil {
		log.Printf("fetchAll query error: %v", err)
		return nil
	}
	defer rows.Close()

	var out []StoredEnvelope
	var envIDs []string
	for rows.Next() {
		var envID string
		var payload []byte
		if err := rows.Scan(&envID, &payload); err != nil {
			continue
		}
		envIDs = append(envIDs, envID)
		out = append(out, StoredEnvelope{EnvID: envID, Payload: payload})
	}

	if len(envIDs) == 0 {
		return nil
	}

	// Mark each returned row as in-flight.  Use a transaction so the whole
	// batch flips atomically — if the commit fails, the rows stay NULL and
	// a follow-up FetchAll re-tries them.  We don't want to return these
	// rows without a persistent mark, because then a second FetchAll (from
	// e.g. a reconnect race) could also grab them.
	tx, err := m.db.Begin()
	if err != nil {
		log.Printf("fetchAll tx begin error: %v", err)
		return nil
	}
	for _, id := range envIDs {
		tx.Exec("UPDATE envelopes SET delivered_at = ? WHERE env_id = ?", now, id)
	}
	if err := tx.Commit(); err != nil {
		log.Printf("fetchAll tx commit error: %v", err)
		tx.Rollback()
		return nil
	}

	// Shuffle delivery order so the relay operator can't correlate
	// sender-enqueue-time with recipient-fetch-time by matching ordinals.
	// Uses crypto/rand (Fisher–Yates with rejection sampling).
	secureShuffleEnv(out)

	return out
}

// ConfirmDelivered removes one envelope after a successful WS write.
// Safe to call on already-deleted rows (no-op).
func (m *Mailbox) ConfirmDelivered(envID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db.Exec("DELETE FROM envelopes WHERE env_id = ?", envID)
}

// secureShuffleEnv does a Fisher–Yates shuffle with crypto/rand so the
// permutation isn't predictable from past samples.  Operates in place on
// a slice of StoredEnvelope.
func secureShuffleEnv(xs []StoredEnvelope) {
	for i := len(xs) - 1; i > 0; i-- {
		j := cryptoRandIntn(i + 1)
		xs[i], xs[j] = xs[j], xs[i]
	}
}

// cryptoRandIntn returns a uniform int in [0, n) using crypto/rand.
// Rejection-samples to avoid modulo bias.
func cryptoRandIntn(n int) int {
	if n <= 1 {
		return 0
	}
	// 8 bytes of entropy, reject values that would bias the modulo.
	max := ^uint64(0) - (^uint64(0) % uint64(n))
	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0 // extremely unlikely; fall back to deterministic 0
		}
		v := binary.BigEndian.Uint64(buf[:])
		if v < max {
			return int(v % uint64(n))
		}
	}
}

// FetchOne retrieves and deletes the oldest envelope for a recipient.
// Returns nil if no envelopes are pending.
func (m *Mailbox) FetchOne(recipientID string) (envID string, payload []byte, createdMs, expiryMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowMs()
	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", now)

	row := m.db.QueryRow(
		"SELECT env_id, payload, created_ms, expiry_ms FROM envelopes WHERE recipient_id=? ORDER BY created_ms ASC LIMIT 1",
		recipientID,
	)
	if err := row.Scan(&envID, &payload, &createdMs, &expiryMs); err != nil {
		return "", nil, 0, 0
	}

	m.db.Exec("DELETE FROM envelopes WHERE env_id=?", envID)
	return envID, payload, createdMs, expiryMs
}

// StoreWithTTL stores an envelope with a custom TTL (capped at maxTTLMs).
func (m *Mailbox) StoreWithTTL(recipientID string, payload []byte, ttlMs int64) (string, error) {
	if ttlMs <= 0 || ttlMs > maxTTLMs {
		ttlMs = defaultTTLMs
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowMs()
	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", now)

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes WHERE recipient_id=?",
		recipientID).Scan(&count)
	if count >= maxQueueItems {
		return "", fmt.Errorf("mailbox full")
	}

	// Enforce the same global-envelope cap that /v1/send uses.
	var globalCount int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes").Scan(&globalCount)
	if globalCount >= maxGlobalEnvelopes {
		return "", fmt.Errorf("relay storage full")
	}

	envID := fmt.Sprintf("%d-%s", now, randomHex(8))
	expiry := now + ttlMs

	_, err := m.db.Exec(
		"INSERT OR IGNORE INTO envelopes (env_id, recipient_id, payload, created_ms, expiry_ms) VALUES (?, ?, ?, ?, ?)",
		envID, recipientID, payload, now, expiry,
	)
	return envID, err
}

// PurgeExpired removes all expired envelopes. Returns (removed, remaining).
func (m *Mailbox) PurgeExpired() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var before int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes").Scan(&before)

	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", nowMs())

	var after int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes").Scan(&after)

	return before - after, after
}

// Count returns the total number of stored envelopes.  The lock
// matches every other Mailbox accessor (Audit #3 M6) so a concurrent
// Store / FetchAll can't race the COUNT(*) read against an insert
// or delete in flight.
func (m *Mailbox) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM envelopes").Scan(&count)
	return count
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
