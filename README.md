# Peer2Pear

A hybrid peer-to-peer messaging and file sharing application built with Qt and C++17, featuring end-to-end encryption powered by [libsodium](https://libsodium.org/).

---

## Features

- **End-to-end encrypted messaging** — Noise IK handshake establishes sessions, then a Signal-style Double Ratchet provides forward secrecy and post-compromise security for every message.
- **Sealed Sender** — relay servers see only the recipient; the sender's identity is hidden inside an encrypted envelope, preventing metadata leakage.
- **Encrypted file transfer** — send files up to 25 MB, automatically chunked (256 KB) and encrypted before transmission.
- **Group chats** — create group conversations with encrypted broadcasts to all members.
- **Hybrid P2P networking** — direct peer-to-peer connections via ICE/NAT traversal (libnice), falling back to an HTTP mailbox relay for offline delivery.
- **Encrypted storage** — the entire local database is encrypted at the page level using SQLCipher (AES-256). Sensitive fields (message text, contact names, file paths) have an additional layer of XChaCha20-Poly1305 AEAD encryption. No plaintext SQLite databases exist on any device.
- **Contact management** — add contacts by Peer ID, block unwanted contacts, import/export contact lists.
- **Cross-platform** — builds on Linux, macOS, and Windows using Qt 5 or Qt 6, with mobile (iOS/Android) portability in mind.

## How It Works

Each user has an Ed25519 identity key pair generated locally, protected by a passphrase via Argon2id key derivation (MODERATE: 3 iterations, 256 MB on desktop; INTERACTIVE: 2 iterations, 64 MB on mobile). A single Argon2id call produces a master key, from which purpose-specific subkeys are derived via HKDF: one for SQLCipher database encryption, one for per-field AEAD, and one for identity key unlock. The public key serves as the user's **Peer ID** (base64url-encoded), shared with contacts out-of-band.

### Session Establishment

1. The initiator performs a **Noise IK handshake** (`Noise_IK_25519_XChaChaPoly_BLAKE2b`), sending the first message along with a fresh ratchet DH public key.
2. The responder completes the handshake and derives both sending and receiving chain keys from the bundled ratchet DH key.
3. Both sides initialize a **Double Ratchet** session with forward secrecy from the first message.

### Sending a Message

1. The plaintext is encrypted via the Double Ratchet (XChaCha20-Poly1305 AEAD, per-message key derived from the symmetric chain).
2. The ratchet ciphertext is wrapped in a **Sealed Sender envelope** — an ephemeral X25519 DH hides the sender's identity from the relay.
3. The envelope is delivered directly over P2P (if online) or queued on the mailbox relay (if offline).

### Cryptographic Primitives

| Primitive | Usage |
|---|---|
| Ed25519 | Identity keys, signatures |
| X25519 | ECDH key agreement (Noise, Sealed Sender) |
| XChaCha20-Poly1305 | AEAD encryption (messages, files, DB fields) |
| BLAKE2b | Hashing, KDF chains (root chain, message chain) |
| AES-256-CBC | SQLCipher page-level database encryption |
| Argon2id | Passphrase-based master key derivation |
| HKDF (BLAKE2b) | Deriving sub-keys (DB encryption, field encryption, identity unlock) |

## Dependencies

| Dependency | Purpose |
|---|---|
| [Qt 5 / Qt 6](https://www.qt.io/) | GUI, networking, and application framework |
| [SQLCipher](https://www.zetetic.net/sqlcipher/) | AES-256 encrypted SQLite (hard requirement) |
| [libsodium](https://libsodium.org/) | Cryptographic primitives |
| [libnice](https://libnice.freedesktop.org/) | ICE agent for P2P NAT traversal |
| [GLib](https://docs.gtk.org/glib/) | Required by libnice |

Dependencies (libsodium, libnice, GLib) are managed via [vcpkg](https://vcpkg.io/). SQLCipher must be installed separately via your system package manager (e.g., `brew install sqlcipher` on macOS, `apt install sqlcipher libsqlcipher-dev` on Ubuntu).

## Building

### Prerequisites

- CMake >= 3.16
- Qt 5 or Qt 6 (Widgets, Network modules)
- SQLCipher (`brew install sqlcipher` / `apt install sqlcipher libsqlcipher-dev`)
- A C++17-capable compiler
- [vcpkg](https://vcpkg.io/) (bootstrapped automatically by the setup scripts)

#### Run the setup script before opening in Qt Creator (it clones vcpkg to the correct directory):

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

The setup scripts bootstrap vcpkg, install the required libraries, and configure the CMake build.

## License

This project is provided as-is. See the repository for any licensing information.
