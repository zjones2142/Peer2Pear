// Peer2Pear Relay Server
//
// A minimal, untrusted relay that provides:
//   - Anonymous envelope sending      (POST /v1/send)
//   - Authenticated WebSocket receive (WS   /v1/receive)
//   - Presence discovery              (GET  /v1/peers)
//   - Store-and-forward mailbox for offline peers
//   - Multi-hop forwarding            (POST /v1/forward)
//
// The relay never sees plaintext. It reads only the 'to' field
// (recipient public key, bytes 1-32) from the envelope header.
// Everything else is opaque ciphertext.
//
// Build:  go build -o peer2pear-relay .
// Run:    ./peer2pear-relay --port 8443
// Docker: docker build -t peer2pear-relay . && docker run -p 8443:8443 peer2pear-relay

package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := flag.String("port", envOr("PORT", "8443"), "listen port")
	dbPath := flag.String("db", envOr("DB_PATH", "peer2pear_relay.db"), "SQLite database path")
	flag.Parse()

	// Initialize storage
	mbox, err := NewMailbox(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer mbox.Close()

	// Initialize relay hub
	hub := NewHub(mbox)

	// Background purge of expired envelopes
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			removed, remaining := mbox.PurgeExpired()
			if removed > 0 {
				log.Printf("purge: removed %d expired envelopes, %d remaining", removed, remaining)
			}
		}
	}()

	// Routes
	mux := http.NewServeMux()

	// ── New protocol (/v1/*) ─────────────────────────────────────────
	mux.HandleFunc("POST /v1/send", hub.HandleSend)
	mux.HandleFunc("/v1/receive", hub.HandleReceive) // WebSocket — no method restriction
	mux.HandleFunc("GET /v1/peers", hub.HandlePeers)
	mux.HandleFunc("POST /v1/forward", hub.HandleForward)

	// ── Legacy endpoints (backward compatibility) ────────────────────
	mux.HandleFunc("POST /mbox/enqueue", hub.LegacyEnqueue)
	mux.HandleFunc("GET /mbox/fetch", hub.LegacyFetch)
	mux.HandleFunc("GET /mbox/fetch_all", hub.LegacyFetchAll)
	mux.HandleFunc("POST /mbox/ack", hub.LegacyAck)
	mux.HandleFunc("POST /rvz/publish", hub.LegacyRvzPublish)
	mux.HandleFunc("POST /rvz/lookup", hub.LegacyRvzLookup)

	// ── Health ───────────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		count := mbox.Count()
		peers := hub.PeerCount()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"envelopes_queued": count,
			"peers_connected":  peers,
			"version":          "2.0.0-go",
		})
	})

	// Graceful shutdown
	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		hub.CloseAll()
		srv.Close()
	}()

	log.Printf("Peer2Pear relay listening on :%s", *port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
