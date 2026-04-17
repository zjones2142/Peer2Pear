module github.com/peer2pear/relay

go 1.22

require (
	github.com/gorilla/websocket v1.5.3
	github.com/mattn/go-sqlite3 v1.14.24
	// Fix #7: NaCl Box (X25519 + XSalsa20-Poly1305) for onion routing.
	// Wire-compatible with libsodium crypto_box_easy and pynacl Box.
	// Run `go mod tidy` to resolve the go.sum entry.
	golang.org/x/crypto v0.25.0
)

require golang.org/x/sys v0.22.0 // indirect
