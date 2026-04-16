package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultTTLMs   = 7 * 24 * 60 * 60 * 1000 // 7 days
	maxTTLMs       = 7 * 24 * 60 * 60 * 1000
	maxQueueItems  = 5000
)

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
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	return &Mailbox{db: db}, nil
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

	// M5 fix: check global capacity to prevent disk exhaustion
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

// FetchAll retrieves and deletes all pending envelopes for a recipient.
// Returns the raw envelope bytes, oldest first.
func (m *Mailbox) FetchAll(recipientID string) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowMs()
	m.db.Exec("DELETE FROM envelopes WHERE expiry_ms < ?", now)

	rows, err := m.db.Query(
		"SELECT env_id, payload FROM envelopes WHERE recipient_id=? ORDER BY created_ms ASC",
		recipientID,
	)
	if err != nil {
		log.Printf("fetchAll query error: %v", err)
		return nil
	}
	defer rows.Close()

	var envIDs []string
	var payloads [][]byte

	for rows.Next() {
		var envID string
		var payload []byte
		if err := rows.Scan(&envID, &payload); err != nil {
			continue
		}
		envIDs = append(envIDs, envID)
		payloads = append(payloads, payload)
	}

	if len(envIDs) == 0 {
		return nil
	}

	// H5 fix: delete in a transaction, only return payloads if commit succeeds
	tx, err := m.db.Begin()
	if err != nil {
		log.Printf("fetchAll tx begin error: %v", err)
		return nil
	}
	for _, id := range envIDs {
		tx.Exec("DELETE FROM envelopes WHERE env_id=?", id)
	}
	if err := tx.Commit(); err != nil {
		log.Printf("fetchAll tx commit error: %v", err)
		tx.Rollback()
		return nil // don't deliver if we can't confirm deletion
	}

	return payloads
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

// Count returns the total number of stored envelopes.
func (m *Mailbox) Count() int {
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
