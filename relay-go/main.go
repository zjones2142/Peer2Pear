// Peer2Pear Relay Server
//
// A minimal, untrusted relay that provides:
//   - Anonymous envelope sending      (POST /v1/send)
//   - Authenticated WebSocket receive (WS   /v1/receive)
//   - Per-IP rate limiting on sends
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
	trustProxy := flag.Bool("trust-proxy", envOr("TRUST_PROXY", "") != "", "trust X-Forwarded-For header (set when behind a reverse proxy)")
	flag.Parse()

	// Initialize storage
	mbox, err := NewMailbox(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer mbox.Close()

	// Initialize relay hub
	hub := NewHub(mbox, *trustProxy)

	// Fix #7: load or generate the relay's X25519 keypair for onion routing.
	pub, priv, err := loadOrCreateRelayKey()
	if err != nil {
		log.Fatalf("init relay onion key: %v", err)
	}
	hub.relayX25519Pub = pub
	hub.relayX25519Priv = priv

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

	// ── Protocol (/v1/*) ─────────────────────────────────────────────
	mux.HandleFunc("POST /v1/send", hub.HandleSend)
	mux.HandleFunc("/v1/receive", hub.HandleReceive) // WebSocket — no method restriction
	mux.HandleFunc("POST /v1/forward", hub.HandleForward)
	// Fix #7: onion routing endpoints.
	mux.HandleFunc("GET /v1/relay_info", hub.HandleRelayInfo)
	mux.HandleFunc("POST /v1/forward-onion", hub.HandleForwardOnion)
	// NOTE: /v1/peers removed — exposing connected peer IDs is a privacy leak.
	// NOTE: Legacy /mbox/* and /rvz/* endpoints removed.  The Qt client uses
	// /v1/send exclusively; rendezvous is replaced by WS presence + P2P ICE.

	// ── Health ───────────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Parity fix: expose PROTOCOL version (identical across impls) as
		// `version`, and the implementation flavour as `impl`.  Clients can
		// gate on `version` for compat, operators inspect `impl`.
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"version": "2.0.0",
			"impl":    "go",
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
