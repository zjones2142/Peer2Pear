# Peer2Pear

A hybrid peer-to-peer messaging and file sharing application built with Qt and C++17, featuring end-to-end encryption with post-quantum cryptography powered by [libsodium](https://libsodium.org/) and [liboqs](https://openquantumsafe.org/).

---

## Features

- **Post-quantum hybrid encryption** — every cryptographic operation uses both classical (X25519/Ed25519) and post-quantum (ML-KEM-768/ML-DSA-65) algorithms. If either holds, security holds.
- **End-to-end encrypted messaging** — Noise IK handshake establishes sessions, then a Signal-style Double Ratchet provides forward secrecy and post-compromise security for every message.
- **Sealed Sender** — relay servers see only the recipient; the sender's identity is hidden inside an encrypted envelope, preventing metadata leakage.
- **Encrypted file transfer** — send files up to 25 MB, automatically chunked (240 KB) and encrypted with per-file ratchet-derived keys for forward secrecy.
- **QUIC transport** — when both peers are online, messages and files flow over a QUIC connection (msquic) layered on ICE, providing reliable framing, multiplexing, and congestion control.
- **Group chats** — create group conversations with encrypted broadcasts to all members, with per-group sequence numbering for gap detection.
- **Hybrid P2P + relay networking** — direct peer-to-peer connections via ICE/NAT traversal (libnice) with QUIC upgrade, falling back to an HTTP mailbox relay for offline delivery.
- **Encrypted storage** — chat history, contacts, and ratchet session state are stored in a local SQLite database with per-field XChaCha20-Poly1305 encryption at rest.
- **Contact management** — add contacts by Peer ID, block unwanted contacts, import/export contact lists.
- **Cross-platform** — builds on Linux, macOS, and Windows using Qt 5 or Qt 6.

## How It Works

Each user has an Ed25519 identity key pair generated locally, protected by a passphrase (Argon2id KDF). The public key serves as the user's **Peer ID** (base64url-encoded, 43 characters), shared with contacts out-of-band. ML-KEM-768 and ML-DSA-65 key pairs are generated alongside the identity and stored encrypted in the identity file.

### Session Establishment

1. The initiator performs a **hybrid Noise IK handshake** — each X25519 DH operation is augmented with an ML-KEM-768 encapsulation. Both shared secrets are mixed into the chaining key: `mixKey(dh_shared || kem_shared)`.
2. The responder completes the handshake, derives both sending and receiving chain keys, and initializes a **hybrid Double Ratchet** session.
3. Post-quantum KEM public keys are exchanged automatically via `kem_pub_announce` messages after the first session is established.

### Sending a Message

1. The plaintext is encrypted via the Double Ratchet (XChaCha20-Poly1305 AEAD, per-message key derived from the symmetric chain). Each ratchet step includes ML-KEM-768 key material for post-quantum protection.
2. The ratchet ciphertext is wrapped in a **hybrid Sealed Sender envelope** — ephemeral X25519 + ML-KEM-768 hides the sender's identity. The inner payload is signed with both Ed25519 and ML-DSA-65.
3. The envelope is delivered directly over QUIC/P2P (if online) or queued on the mailbox relay (if offline).

### File Transfer

1. A `file_key` announcement is sent through the sealed ratchet path, producing a forward-secret per-file encryption key.
2. The file is split into 240 KB chunks, each encrypted with the ratchet-derived key.
3. Chunks are sent via QUIC file stream (if P2P is active) or sealed envelopes via the mailbox relay.
4. The receiver reassembles chunks and verifies a BLAKE2b-256 integrity hash.

### Cryptographic Primitives

| Primitive | Usage | Quantum-Safe |
|---|---|---|
| Ed25519 | Identity keys, classical signatures | No (harvest-now risk) |
| ML-DSA-65 (Dilithium) | Hybrid post-quantum signatures in sealed envelopes | Yes |
| X25519 | ECDH key agreement (Noise, Sealed Sender, Ratchet) | No (harvest-now risk) |
| ML-KEM-768 (Kyber) | Hybrid KEM in sealed envelopes, Noise handshake, and ratchet | Yes |
| XChaCha20-Poly1305 | AEAD encryption (messages, files, DB fields, session store) | Yes (128-bit PQ) |
| BLAKE2b | Hashing, KDF chains (root chain, message chain) | Yes |
| Argon2id | Passphrase-based key derivation for identity encryption | Yes |

### Transport Layers

| Transport | When Used | Properties |
|---|---|---|
| QUIC (msquic) | Both peers online, P2P established | Reliable, framed, multiplexed (message + file streams), congestion control |
| Raw ICE (libnice) | Peer doesn't support QUIC, or TURN relay path | UDP, no framing, text messages only |
| HTTP Mailbox | Peer offline, or P2P unavailable | Reliable delivery via relay server, 7-day TTL |

## Architecture

```
MainWindow
  ├── ChatView (UI rendering)
  ├── ChatController (core logic)
  │   ├── CryptoEngine (Ed25519/X25519 + ML-KEM-768/ML-DSA-65)
  │   ├── SessionManager (Noise IK + Double Ratchet lifecycle)
  │   │   ├── NoiseState (hybrid Noise IK handshake)
  │   │   ├── RatchetSession (hybrid Double Ratchet with KEM augmentation)
  │   │   └── SessionStore (encrypted SQLite persistence)
  │   ├── SealedEnvelope (hybrid sealed sender with KEM + DSA)
  │   ├── FileTransferManager (chunked encrypted file transfers)
  │   ├── MailboxClient (HTTP relay with retry queue)
  │   ├── RendezvousClient (presence discovery)
  │   ├── QuicConnection (QUIC over ICE transport)
  │   │   └── NiceConnection (ICE/STUN/TURN NAT traversal)
  │   └── DatabaseManager (encrypted SQLite storage)
  ├── SettingsPanel (configuration UI)
  ├── ChatNotifier (system tray notifications)
  └── OnboardingDialog (first-run setup)
```

## Dependencies

| Dependency | Purpose |
|---|---|
| [Qt 5 / Qt 6](https://www.qt.io/) | GUI, networking, SQL, and application framework |
| [libsodium](https://libsodium.org/) | Classical cryptographic primitives (Ed25519, X25519, XChaCha20-Poly1305, BLAKE2b, Argon2) |
| [liboqs](https://openquantumsafe.org/) | Post-quantum cryptography (ML-KEM-768, ML-DSA-65) |
| [msquic](https://github.com/microsoft/msquic) | QUIC transport protocol for reliable P2P communication |
| [libnice](https://libnice.freedesktop.org/) | ICE agent for P2P NAT traversal |
| [GLib](https://docs.gtk.org/glib/) | Required by libnice |

All native dependencies are managed via [vcpkg](https://vcpkg.io/).

## Building

### Prerequisites

- CMake >= 3.16
- Qt 5 or Qt 6 (Widgets, Network, Sql modules)
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

## Security Properties

| Property | Mechanism |
|---|---|
| **Confidentiality** | XChaCha20-Poly1305 AEAD with per-message keys |
| **Forward secrecy** | Double Ratchet with X25519 DH + ML-KEM-768 key rotation per reply |
| **Post-compromise security** | New DH + KEM keypairs generated on each ratchet step |
| **Sender anonymity** | Sealed Sender envelopes (hybrid X25519 + ML-KEM-768) |
| **Authentication** | Ed25519 + ML-DSA-65 hybrid signatures |
| **Quantum resistance** | Hybrid classical + PQ at every layer (envelopes, handshake, ratchet, signatures) |
| **Data at rest** | Per-field DB encryption, encrypted session store, passphrase-protected identity |
| **Integrity** | AEAD tags on all ciphertexts, BLAKE2b-256 file hashes |

## License

This project is provided as-is. See the repository for any licensing information.
