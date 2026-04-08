# Peer2Pear

A hybrid peer-to-peer messaging and file sharing application built with Qt and C++17, featuring end-to-end encryption powered by [libsodium](https://libsodium.org/).

---

## Features

- **End-to-end encrypted messaging** — Noise IK handshake establishes sessions, then a Signal-style Double Ratchet provides forward secrecy and post-compromise security for every message.
- **Sealed Sender** — relay servers see only the recipient; the sender's identity is hidden inside an encrypted envelope, preventing metadata leakage.
- **Encrypted file transfer** — send files up to 25 MB, automatically chunked (256 KB) and encrypted before transmission.
- **Group chats** — create group conversations with encrypted broadcasts to all members.
- **Hybrid P2P networking** — direct peer-to-peer connections via ICE/NAT traversal (libnice), falling back to an HTTP mailbox relay for offline delivery.
- **Encrypted storage** — chat history and contacts are stored in a local SQLite database with per-field XChaCha20-Poly1305 encryption at rest.
- **Contact management** — add contacts by Peer ID, block unwanted contacts, import/export contact lists.
- **Cross-platform** — builds on Linux, macOS, and Windows using Qt 5 or Qt 6.

## How It Works

Each user has an Ed25519 identity key pair generated locally, protected by a passphrase (Argon2id KDF). The public key serves as the user's **Peer ID** (base64url-encoded), shared with contacts out-of-band.

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
| Argon2id | Passphrase-based key derivation |
| HKDF (BLAKE2b) | Deriving sub-keys (pre-key payloads, DB encryption) |

## Dependencies

| Dependency | Purpose |
|---|---|
| [Qt 5 / Qt 6](https://www.qt.io/) | GUI, networking, SQL, and application framework |
| [libsodium](https://libsodium.org/) | Cryptographic primitives |
| [libnice](https://libnice.freedesktop.org/) | ICE agent for P2P NAT traversal |
| [GLib](https://docs.gtk.org/glib/) | Required by libnice |

Dependencies (libsodium, libnice, GLib) are managed via [vcpkg](https://vcpkg.io/).

## Building

### Prerequisites

- CMake >= 3.16
- Qt 5 or Qt 6 (Widgets, Network, Sql modules)
- A C++17-capable compiler
- [vcpkg](https://vcpkg.io/) (bootstrapped automatically by the setup scripts)
- **Windows only:** Visual Studio 2019+ or Build Tools with the "Desktop development with C++" workload. [Ninja](https://ninja-build.org/) is recommended for faster builds (install via `winget install Ninja-build.Ninja`); the CMake presets default to Ninja, but you can override the generator if needed.

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

Then open the folder in Qt Creator and select the **win-msvc-debug** or **win-msvc-release** CMake preset. You can also build from a **Developer Command Prompt for VS**:

```bat
cd Peer2Pear_QtProj
cmake --preset win-msvc-debug
cmake --build build
```

> **Tip:** The first build compiles all vcpkg dependencies from source and may
> take 10–20 minutes. Subsequent builds use binary caching and complete in
> seconds. To share caches across machines or CI, set `VCPKG_DEFAULT_BINARY_CACHE`
> to a shared directory before running the setup script.

The setup scripts bootstrap vcpkg, install the required libraries, and configure the CMake build.

## License

This project is provided as-is. See the repository for any licensing information.
