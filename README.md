# Peer2Pear 🍐

A peer-to-peer encrypted messaging and file-sharing **protocol**. Open source, relay-first, post-quantum cryptography, no phone numbers, no accounts.

This repository contains:

- **`core/`** — portable C++ protocol core (crypto, handshake, ratchet, sealed sender, relay client). Builds Qt-free for mobile via `-DBUILD_DESKTOP=OFF`.
- **`desktop/`** — Qt 5/6 desktop client for Linux, macOS, and Windows.
- **`ios/`** — SwiftUI iOS client built on the C FFI (`core/peer2pear.h`), targeting iOS 26+ arm64. Relay-only transport for now (P2P deferred); full feature parity with desktop for messaging, groups, files, safety numbers, and QR exchange.
- **`relay-go/`** — reference Go relay server (single static binary, SQLite mailbox, onion-capable).
- **`core/tests/`** — GoogleTest suite (295 cases across 17 binaries) covering crypto primitives, sealed envelopes, ratchet, session manager, sealer / group / file protocols, full E2E two-client round-trips, the C API surface, and relay cover traffic.

---

## Design goals

1. **Grandma simple for users.** Download, open, message. No crypto terminology, no key management, no relay awareness.
2. **Private and secure by default.** Hybrid post-quantum E2EE, sealed sender, envelope-level replay protection, minimal metadata leakage.
3. **Easy to run a node.** Single binary, single SQLite file, zero config. `docker compose --profile go up` and you're contributing relay capacity.

## Features

- **Post-quantum hybrid encryption** — every operation combines classical (X25519/Ed25519) and post-quantum (ML-KEM-768/ML-DSA-65). If either holds, security holds.
- **End-to-end encrypted messaging** — Noise IK handshake followed by a Signal-style Double Ratchet with KEM augmentation. Forward secrecy and post-compromise security per message.
- **Sealed sender v2** — relays see only the recipient pubkey. Sender identity is hidden inside AEAD-encrypted envelopes whose AAD is bound to the recipient and whose envelope-id enables receiver-side replay protection.
- **Encrypted file transfer up to 100 MB** — streamed from disk in 240 KB chunks, encrypted with forward-secret per-file keys, BLAKE2b-256 integrity verified, interrupted-transfer resumption via `file_request`.
- **Relay-first networking** — all clients connect to one or more relays via WebSocket. Anonymous HTTP `POST /v1/send` for outbound. Optional direct QUIC-over-ICE P2P upgrade when both peers are online.
- **Opt-in traffic analysis defenses** — fixed-size padding buckets, send jitter, bursty cover traffic to real contacts, multi-relay send rotation, onion-routed multi-hop forwarding.
- **Encrypted at rest** — SQLCipher (AES-256) full-DB encryption plus per-field XChaCha20-Poly1305 AEAD. No plaintext SQLite on any device.
- **Group chats** — encrypted broadcasts with per-group sequence numbering, deny-by-default roster authorization for control messages (rename / avatar / member-update / leave), and size-gated consent for file transfers.
- **Safety numbers** — sort-invariant 60-digit BLAKE2b fingerprint for out-of-band verification. Verify-once persistence; key-change detection with once-per-session warning callback; optional hard-block on mismatch.
- **QR peer exchange** — scan or display the 43-char base64url Peer ID on iOS (CoreImage + AVFoundation) or desktop (vendored Nayuki encoder). Complementary to copy/paste — same wire format on both sides.
- **Cross-platform clients** — Linux / macOS / Windows via Qt 5/6 (`desktop/`); iOS 26+ via SwiftUI (`ios/`). A C FFI (`core/peer2pear.h`) backs the iOS bridge and is the integration point for any future native frontend (Android, etc.).

## How it works

Each user has an Ed25519 identity key pair (and ML-KEM-768 + ML-DSA-65 PQ pairs) generated locally, protected by a passphrase via Argon2id. A single Argon2id call produces a master key, from which purpose-specific subkeys are derived via HKDF (SQLCipher DB key, per-field AEAD key, identity unlock key). The Ed25519 public key is the user's **Peer ID** — base64url, 43 characters, shared out of band.

### Relay connection

1. The client opens `WS /v1/receive?peer_id=<id>&ts=<unix>&sig=<ed25519_sig>`, proving ownership of the Peer ID.
2. On connect, any stored-and-forward envelopes in the relay's mailbox are delivered immediately, in shuffled order.
3. Presence is the set of currently connected peers — no separate rendezvous protocol.

### Sending a message

1. Plaintext is encrypted via the Double Ratchet (XChaCha20-Poly1305 AEAD, KEM-augmented).
2. The ratchet ciphertext is wrapped in a **sealed sender v2 envelope**:
   - Version 0x02 (classical) or 0x03 (hybrid PQ)
   - AEAD AAD = `ephPub || recipientEdPub` (binds the envelope to its intended recipient — a malicious relay cannot silently re-route it)
   - AEAD plaintext = `envelopeId(16) || senderEdPub(32) || edSig(64) || [dsaPubLen || dsaPub || dsaSig] || innerPayload`
   - Both `edSig` and the ML-DSA-65 signature cover `envelopeId || innerPayload`
3. The envelope is wrapped in a relay routing header (recipient pubkey + length) and padded to a fixed bucket (2 / 16 / 256 KiB).
4. The client `POST`s the wrapped envelope to `/v1/send` anonymously — no auth, no session, no identity. The relay routes by recipient pubkey.
5. If the recipient is online, the relay pushes the envelope via their WebSocket. Otherwise the relay stores it (7-day TTL, 5 000-per-recipient cap).

### File transfer

1. A `file_key` announcement is sent through the sealed ratchet path with **locked** `fileSize`, `chunkCount`, and BLAKE2b-256 `fileHash`. The receiver's consent policy (configurable size thresholds) gates acceptance.
2. After consent, the file is streamed from disk in 240 KB chunks, each encrypted with the ratchet-derived per-file key. Chunks whose metadata disagrees with the announced values are rejected.
3. Chunks flow via P2P (if a QUIC session is up) or as sealed envelopes through the relay.
4. Partial files and their fileKey are persisted (SQLCipher-encrypted on disk). On reconnect, the receiver sends `file_request { transferId, chunks: [...] }` for any missing indices.
5. On completion, the receiver verifies the full-file hash and sends `file_ack`; the sender then drops its sent-transfer state.

### Privacy levels

Opt-in, client-side:

| Level | Features |
|---|---|
| 0 Standard | Envelope padding, sealed sender, envelope-id replay protection |
| 1 Enhanced | + send jitter (50–300 ms), bursty cover traffic to real contacts, multi-relay send rotation |
| 2 Maximum | + high-frequency cover traffic, multi-hop onion forwarding via `/v1/forward-onion`, no relay fallback for large file transfers |

### Onion routing

At Privacy Level 2, the client fetches each relay's X25519 public key from `GET /v1/relay_info` and wraps the sealed envelope in one NaCl Box layer per hop. Each relay peels one layer, learning only the next hop URL, and forwards the inner blob. The entry relay sees sender IP but not the final recipient; the exit relay sees the final recipient but not sender IP.

### Cryptographic primitives

| Primitive | Usage | Quantum-safe |
|---|---|---|
| Ed25519 | Identity keys, classical signatures | No (harvest-now risk) |
| ML-DSA-65 (Dilithium) | Hybrid PQ signatures in sealed envelopes | Yes |
| X25519 | ECDH key agreement (Noise, sealed envelope, ratchet, onion layers) | No (harvest-now risk) |
| ML-KEM-768 (Kyber) | Hybrid KEM in sealed envelopes, Noise handshake, ratchet | Yes |
| XChaCha20-Poly1305 | AEAD (messages, files, DB fields, session store) | Yes |
| NaCl Box | Onion layer encryption per relay hop | Classical only (X25519) |
| AES-256-CBC | SQLCipher page-level database encryption | Yes |
| BLAKE2b | Hashing, KDF chains, file integrity | Yes |
| Argon2id | Passphrase-based master key derivation | Yes |
| HKDF (BLAKE2b) | Deriving purpose-specific subkeys | Yes |

### Transport layers

| Transport | When used | Properties |
|---|---|---|
| WebSocket relay | Always (baseline) | Persistent push for receive; anonymous HTTP POST for send |
| Onion-routed relay | Privacy Level 2 | Multi-hop via `/v1/forward-onion`; each hop sees only next hop |
| QUIC over ICE P2P | Optional (`-DPEER2PEAR_P2P=ON`), both peers online, NAT traversal succeeds | Direct, low latency, relay is not in the path for messages |

## Architecture

```
desktop/Peer2Pear.app         ios/Peer2Pear.app
  Qt 5/6 GUI                  SwiftUI (iOS 26+)
  Qt::WebSocket impl          URLSessionWebSocket adapter
  Qt::HttpClient impl         URLSession adapter
       │                            │
       └────── both link ───────────┘
                  │
                  ▼
core/libpeer2pear-core.a      ← portable protocol core (Qt optional)
  ├── CryptoEngine            (Ed25519, X25519, ML-KEM-768, ML-DSA-65, AEAD, HKDF, Argon2id)
  ├── SessionManager          (Noise IK + Double Ratchet lifecycle)
  │   ├── NoiseState          (hybrid Noise IK handshake)
  │   ├── RatchetSession      (hybrid Double Ratchet with KEM augmentation)
  │   └── SessionStore        (SQLCipher-encrypted persistence)
  ├── SealedEnvelope          (v2: recipient-bound AAD, envelope-id replay protection)
  ├── ChatController          (orchestration, dispatchSealedPayload, control routing)
  │   ├── SessionSealer       (single choke point for sealForPeer + safety numbers)
  │   ├── GroupProtocol       (fan-out + roster authorization + per-group seq)
  │   └── FileProtocol        (sendFile / consent flow / per-transfer key state)
  ├── FileTransferManager     (streamed chunk encryption, disk-backed partials, resumption)
  ├── RelayClient             (WebSocket, anonymous POST send, padding, jitter, cover)
  ├── OnionWrap               (NaCl Box multi-hop layering)
  ├── SqlCipherDb             (AES-256 encrypted SQLite wrapper)
  ├── IWebSocket / IHttpClient (transport interfaces — Qt impl on desktop,
  │                            URLSession impl on iOS)
  └── peer2pear.h             (C FFI for mobile / third-party clients)

relay-go/                     ← reference Go relay (single binary)
```

## Running a relay

A relay is a WebSocket forwarder plus a SQLite mailbox. It never sees plaintext and requires no configuration beyond a port.

### Docker

```bash
# At repository root
docker compose up relay-go
```

### Go relay (from source)

```bash
cd relay-go
go mod tidy

# Plaintext — run only behind a reverse proxy that terminates TLS.
go run .

# Native TLS — pass a certificate and key (PEM) and the relay listens
# with ListenAndServeTLS directly.  No reverse proxy required.
go run . --cert /path/to/fullchain.pem --key /path/to/privkey.pem

# Same via env vars (useful in Docker / systemd):
TLS_CERT=/path/to/fullchain.pem TLS_KEY=/path/to/privkey.pem go run .
```

Specify both `--cert` and `--key` together; supplying just one is a
config error and the relay refuses to start.

### Relay endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/send` | Anonymous envelope submission (rate-limited per IP and per recipient) |
| `WS /v1/receive` | Authenticated WebSocket for push delivery |
| `POST /v1/forward` | Single-hop relay-to-relay forwarding |
| `POST /v1/forward-onion` | Onion-routed multi-hop forwarding (peel one layer) |
| `GET /v1/relay_info` | This relay's X25519 pubkey for onion wrapping |
| `GET /healthz` | Returns `{ok, version, impl}` |

`relay-go` is the only supported server implementation. The Python
reference relay that previously lived at `relay/` was removed on
2026-04-20 — the behavioural divergence between the two impls (jitter
RNG, cover-traffic ordering, SSRF guard details) was itself an audit
finding (LC1/LC2), and consolidating on one impl eliminated the class
while keeping node hosting as a single static binary.

## Dependencies

### Client core + desktop

| Dependency | Purpose |
|---|---|
| [Qt 5 / Qt 6](https://www.qt.io/) | GUI, WebSockets, application framework (Qt Core in `core/`; Qt Widgets only in `desktop/`) |
| [SQLCipher](https://www.zetetic.net/sqlcipher/) | AES-256 encrypted SQLite |
| [libsodium](https://libsodium.org/) | Classical primitives (Ed25519, X25519, XChaCha20-Poly1305, BLAKE2b, Argon2id, NaCl Box) |
| [liboqs](https://openquantumsafe.org/) | Post-quantum primitives (ML-KEM-768, ML-DSA-65) |
| [msquic](https://github.com/microsoft/msquic) | Optional: QUIC transport for direct P2P (`-DPEER2PEAR_P2P=ON`) |
| [libnice](https://libnice.freedesktop.org/) | Optional: ICE/STUN/TURN for direct P2P |
| [qrcodegen](https://www.nayuki.io/page/qr-code-generator-library) | Vendored: QR rendering for Edit Profile (desktop only) |

Client dependencies are managed via [vcpkg](https://vcpkg.io/). SQLCipher (`third_party/sqlcipher/`) and qrcodegen (`third_party/qrcodegen/`) are vendored — no system install required. The repo compiles SQLCipher from source against the OpenSSL that vcpkg pulls in transitively via liboqs.

### iOS

In addition to the core library, the iOS app links **AVFoundation** (camera capture for QR scanning) and uses Apple's built-in **CoreImage** for QR rendering. Both are SDK frameworks — no third-party deps beyond what `core/` already needs.

### Go relay

`gorilla/websocket`, `golang.org/x/crypto/nacl/box`, `mattn/go-sqlite3` (all via `go.mod`).

## Building the client

### Prerequisites

- CMake ≥ 3.16
- Qt 5 or Qt 6 (Widgets, Network, WebSockets modules) — **desktop only**; iOS / Android drop Qt entirely via `-DBUILD_DESKTOP=OFF`
- A C++17-capable compiler
- (SQLCipher is vendored — see `third_party/sqlcipher/`.)
- [vcpkg](https://vcpkg.io/) (bootstrapped automatically)

### Linux / macOS

```bash
./setup.sh
cmake --build build
```

### Windows

```bat
winsetup.bat
cmake --build build
```

Direct P2P (QUIC over ICE) is optional and off by default. Enable with `-DPEER2PEAR_P2P=ON`.

### iOS

Cross-compiles `libpeer2pear-core.a` for arm64 simulator + arm64 device, then xcodegen generates `ios/Peer2Pear.xcodeproj` from the committed `ios/project.yml`. Full setup steps (including Apple Developer Team ID config for on-device builds) are in [`ios/README.md`](ios/README.md). Quick start:

```bash
./setup.sh                # bootstraps vcpkg (one-time)
./build-ios.sh --both     # builds the static core for sim + device
cd ios && ./generate.sh   # regenerates the .xcodeproj from project.yml
open Peer2Pear.xcodeproj
```

iOS is relay-only (`PEER2PEAR_P2P=OFF`); the core is built Qt-free (`WITH_QT_CORE=OFF`) so no Qt is needed in the iOS dependency chain.

## Testing

The core library ships a GoogleTest suite of 295 cases across 17 binaries — crypto primitives, Noise/ratchet/sealed-envelope round trips, persistence (SQLCipher), the per-module security gates (SessionSealer / GroupProtocol / FileProtocol), end-to-end two-client scenarios over a mock relay, the C FFI surface, and relay cover-traffic timing. Tests build by default on desktop (`BUILD_TESTS=ON`) and are skipped on iOS / Android cross-compiles.

```bash
cmake --build build              # builds the test binaries alongside the app
ctest --test-dir build           # runs all 295 cases (~125 s on M-series Mac)
ctest --test-dir build -R Group  # filter by name regex
```

The Go relay has its own `go test` suite (40+ cases under `relay-go/`) covering the L1 native-TLS path, onion forwarding, presence, and the connection-replacement race. Run with `cd relay-go && go test ./...`.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | XChaCha20-Poly1305 AEAD with per-message keys |
| Forward secrecy | Double Ratchet with X25519 DH + ML-KEM-768 key rotation per reply |
| Post-compromise security | New DH + KEM keypairs generated on each ratchet step |
| Sender anonymity | Sealed sender v2 with recipient-bound AAD |
| Envelope replay protection | 16-byte envelope-id inside AEAD; receiver-side LRU deduplication |
| Authentication | Ed25519 + ML-DSA-65 hybrid signatures over `envelopeId ‖ innerPayload` |
| Quantum resistance | Hybrid classical + PQ at every layer (envelope, handshake, ratchet, signatures) |
| Data at rest | SQLCipher full-DB encryption (AES-256) + per-field AEAD; encrypted session store; passphrase-protected identity |
| Integrity | AEAD tags on all ciphertexts; BLAKE2b-256 file hashes locked at announce time |
| Metadata protection | Fixed-bucket envelope padding; optional send jitter, cover traffic, multi-relay rotation, multi-hop onion routing |
| Relay-operator trust boundary | Relay sees recipient pubkey only; cannot read content, cannot see sender identity, cannot forge envelopes, cannot replay across hops |

## License

This project is provided as-is. See the repository for any licensing information.
