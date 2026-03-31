# Peer2Pear

A hybrid peer-to-peer file sharing and messaging application built with Qt, featuring end-to-end encryption powered by [libsodium](https://libsodium.org/).

---

## Features

- **End-to-end encrypted messaging** — all messages are encrypted with XChaCha20-Poly1305 (AEAD) using per-contact shared keys derived via X25519 from Ed25519 identity keys.
- **Encrypted file transfer** — send files up to 8 MB (likely to increase in future), automatically split into chunks and encrypted before transmission.
- **Group chats** — create and participate in group conversations.
- **Hybrid P2P networking** — attempts direct peer-to-peer connections via ICE/NAT traversal (libnice), falling back to a relay mailbox server when a direct path is not available.
- **Persistent storage** — chat history and contacts are stored locally in a SQLite database.
- **Contact management** — add contacts by peer ID, block unwanted contacts.
- **Cross-platform** — builds on Linux, macOS, and Windows using Qt 5 or Qt 6.

## How It Works

Each user has an Ed25519 identity key pair generated locally (optionally protected by a passphrase). The public key serves as the user's **Peer ID** (base64url-encoded), which is shared with contacts out-of-band.

When sending a message or file:
1. A 32-byte shared secret is derived from the sender's private key and the recipient's public key (X25519 ECDH).
2. The plaintext is encrypted with XChaCha20-Poly1305 using the shared secret.
3. The encrypted envelope is delivered via the mailbox relay server and/or directly over a P2P connection negotiated by a rendezvous server.

## Dependencies

| Dependency | Purpose |
|---|---|
| [Qt 5/Qt 6](https://www.qt.io/) | GUI, networking, SQL, and application framework |
| [libsodium](https://libsodium.org/) | Cryptographic primitives (Ed25519, X25519, XChaCha20-Poly1305) |
| [libnice](https://libnice.freedesktop.org/) | ICE agent for P2P NAT traversal |
| [GLib](https://docs.gtk.org/glib/) | Required by libnice |

Dependencies (libsodium, libnice, GLib) are managed via [vcpkg](https://vcpkg.io/).

## Building

### Prerequisites

- CMake ≥ 3.16
- Qt 5 / Qt 6 (Widgets, Network, Sql modules)
- A C++17-capable compiler
- [vcpkg](https://vcpkg.io/) (bootstrapped automatically by the setup scripts)

#### Run the following before opening in Qt!  (they clone vcpkg to correct directory)
### Linux / macOS

```bash
cd Peer2Pear_QtProj
./setup.sh
```

### Windows

```bat
cd Peer2Pear_QtProj
winsetup.bat
```

## License

This project is provided as-is. See the repository for any licensing information.
