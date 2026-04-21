package main

import (
	"database/sql"
	"log"
	"sync"
	"time"
)

// PushStore persists (peer_id, platform, token) tuples so the relay
// can wake an offline recipient's device via APNs / FCM when a new
// envelope arrives.  Tokens are upserted by (peer_id, platform);
// empty tokens act as "unregister" and delete the row.
//
// The store does NOT need to be durable across restarts for
// correctness — if it empties, clients re-register on their next
// authenticated WS connection (RelayClient replays m_pushPlatform /
// m_pushToken on every auth_ok).  Persistence is an optimisation so
// a freshly-restarted relay can wake offline recipients before they
// reconnect.
type PushStore struct {
	db *sql.DB
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

func NewPushStore(db *sql.DB) (*PushStore, error) {
	_, err := db.Exec(`
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
	return &PushStore{db: db}, nil
}

// Upsert writes or replaces the (peer_id, platform) row.  An empty
// token deletes the row instead of writing an empty string — the
// client contract is "empty token means unregister."
func (s *PushStore) Upsert(peerID, platform, token string) error {
	if peerID == "" || platform == "" {
		return nil
	}
	if token == "" {
		_, err := s.db.Exec(
			`DELETE FROM push_tokens WHERE peer_id=? AND platform=?;`,
			peerID, platform)
		return err
	}
	_, err := s.db.Exec(`
        INSERT INTO push_tokens (peer_id, platform, token, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(peer_id, platform) DO UPDATE SET
            token      = excluded.token,
            updated_at = excluded.updated_at;
    `, peerID, platform, token, time.Now().Unix())
	return err
}

// GetForPeer returns every token registered for a peer — typically
// one per platform, sometimes more if the user runs the app on both
// iOS and Android.  Caller fires a push to each.
func (s *PushStore) GetForPeer(peerID string) ([]PushRecord, error) {
	if peerID == "" {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT peer_id, platform, token, updated_at FROM push_tokens WHERE peer_id=?;`,
		peerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PushRecord
	for rows.Next() {
		var r PushRecord
		var ts int64
		if err := rows.Scan(&r.PeerID, &r.Platform, &r.Token, &ts); err != nil {
			return nil, err
		}
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
	_, err := s.db.Exec(`DELETE FROM push_tokens WHERE peer_id=?;`, peerID)
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
