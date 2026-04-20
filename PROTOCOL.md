# Peer2Pear Protocol Specification

**Version:** 2.0.0
**Status:** Draft
**Date:** 2026-04
**Audience:** Implementers of alternate clients or relays.

---

## 1. Overview

Peer2Pear is an end-to-end encrypted messaging and file-sharing protocol.
A client has exactly one identity (an Ed25519 keypair), connects to one or
more relay servers over TLS-protected WebSockets, and exchanges sealed
envelopes with other identities.

This document defines the wire formats, cryptographic constructions, and
required behaviors. Implementations that conform to this spec can interop
with the reference Go relay and the reference Qt/C++ client.

### 1.1 Design principles

- **No accounts, no discovery service.** Your public key is your address.
  Contact exchange is out of band (QR, link, paste).
- **Relay-first.** All messaging flows through a relay. Direct P2P is an
  optional performance upgrade, not a requirement.
- **Relay never sees plaintext.** Envelopes are opaque ciphertext; the
  routing byte is only the 32-byte recipient identity.
- **Sealed sender.** Even the sender's identity is hidden from the relay.
- **Post-quantum by default.** Every layer combines classical and PQ
  primitives.
- **Small spec.** A minimal client fits in a weekend.

### 1.2 Non-goals

- Group membership with cryptographic group-level forward secrecy (MLS).
  The current group scheme is pairwise fan-out.
- Decentralized peer discovery (DHT). Clients learn relay URLs and peer
  public keys out of band.
- Multi-device identity. One identity per device. Device linking is a
  future extension.

### 1.3 Notation

- `[N]` — a byte string of length N.
- `||` — byte concatenation.
- `base64url` — RFC 4648 §5 without padding.
- `randombytes(N)` — N cryptographically random bytes.
- Integers are unsigned big-endian unless stated otherwise.
- `HMAC-BLAKE2b-256(key, data)` refers to keyed BLAKE2b with 256-bit output.
- `AEAD(k, n, ad, p)` = XChaCha20-Poly1305-IETF (24-byte nonce, 16-byte tag).

---

## 2. Identity

### 2.1 Keys

Each identity owns:

| Key | Algorithm | Size (bytes) | Purpose |
|---|---|---|---|
| `id_pub` | Ed25519 | 32 | Identity. **Peer ID = `base64url(id_pub)`.** |
| `id_priv` | Ed25519 | 64 | Sign outgoing messages, derive X25519 priv. |
| `x25519_pub` | X25519 | 32 | Derived from `id_pub` via `crypto_sign_ed25519_pk_to_curve25519`. |
| `x25519_priv` | X25519 | 32 | Derived from `id_priv` via `crypto_sign_ed25519_sk_to_curve25519`. |
| `kem_pub` | ML-KEM-768 | 1184 | PQ encapsulation; announced post-handshake. |
| `kem_priv` | ML-KEM-768 | 2400 | PQ decapsulation. |
| `dsa_pub` | ML-DSA-65 | 1952 | PQ signatures on sealed envelopes. |
| `dsa_priv` | ML-DSA-65 | 4032 | — |

The **Peer ID is the Ed25519 public key, base64url-encoded, 43 characters
with no padding.** It is the only identifier ever exchanged out of band.

### 2.2 Identity generation

1. Generate Ed25519 keypair (`id_pub`, `id_priv`).
2. Derive X25519 keypair via libsodium's `crypto_sign_ed25519_pk_to_curve25519`
   / `..._sk_to_curve25519`.
3. Generate ML-KEM-768 keypair.
4. Generate ML-DSA-65 keypair.

Identities are never rotated. A lost private key means the identity is
gone — contacts must be re-added under a new identity.

### 2.3 Local storage

Implementations SHOULD encrypt identity keys and local message history at
rest. The reference client derives an encryption key from a user passphrase
via Argon2id and stores it in a SQLCipher-encrypted SQLite database. This
is not a protocol requirement; it's a recommendation for the threat model
of device theft.

---

## 3. Wire format primitives

### 3.1 Routing envelope (relay layer)

Every byte string sent to a relay's `/v1/send` endpoint or received on
`/v1/receive` is a **routing envelope**:

```
  byte  0:         version = 0x01
  bytes 1-32:      recipient_pub (Ed25519) [32]
  bytes 33-36:     inner_len (uint32 BE)
  bytes 37-37+n:   sealed_bytes [inner_len]
  bytes …:         random padding to bucket size
```

The relay reads bytes 0-32 to know where to deliver, reads `inner_len` only
to strip padding. Everything from byte 37 onward is opaque ciphertext.

#### 3.1.1 Padding buckets

The total wire size MUST be padded to the smallest of these buckets that
fits:

| Bucket | Size | Typical payload |
|---|---|---|
| Small | 2 KiB | Text, presence, avatars (small) |
| Medium | 16 KiB | Group ops, small files |
| Large | 256 KiB | File chunks |

Envelopes larger than 256 KiB MUST be rejected by the relay with HTTP 413.
Padding is random bytes filled with `randombytes(bucket_size - raw_size)`
after the sealed blob.

### 3.2 Sealed envelope (end-to-end layer)

The `sealed_bytes` field is itself a self-delimiting structure:

```
Classical (version = 0x02):
  byte 0:         version = 0x02
  bytes 1-32:     eph_pub (X25519 ephemeral) [32]
  bytes 33-56:    nonce [24]
  bytes 57-…:     AEAD(envelope_key,
                       AAD = eph_pub || recipient_ed_pub,
                       plaintext = envelope_id(16)
                                || sender_ed_pub(32)
                                || ed_sig(64)
                                || dsa_pub_len(2)
                                || [dsa_pub || dsa_sig]
                                || inner_payload)

Hybrid (version = 0x03):
  byte 0:         version = 0x03
  bytes 1-32:     eph_pub [32]
  bytes 33-1120:  kem_ct (ML-KEM-768 encapsulation) [1088]
  bytes 1121-1144: nonce [24]
  bytes 1145-…:   AEAD(envelope_key,
                       AAD = eph_pub || recipient_ed_pub,
                       plaintext = …same as above…)
```

`envelope_key` derivation:

```
ecdh_shared = X25519(eph_priv, recipient_x25519_pub)

if classical (0x02):
    ikm = ecdh_shared
else: // hybrid (0x03)
    kem_shared = ML-KEM-768 encaps shared (32 bytes)
    ikm = ecdh_shared || kem_shared

envelope_key = BLAKE2b-256(ikm)
```

The AAD cryptographically binds the envelope to:
- `eph_pub` — prevents substitution of a different ephemeral key
- `recipient_ed_pub` — prevents a malicious relay from re-routing the
  sealed blob to a different recipient

The `envelope_id` is 16 random bytes. Receivers MUST maintain a bounded
LRU of seen envelope IDs (recommended: 2000 entries) and drop duplicates
to defeat relay-level replay.

`ed_sig` = Ed25519 signature over `envelope_id || inner_payload`. If
`dsa_pub_len > 0`, `dsa_sig` is an ML-DSA-65 signature over the same.
Both signatures MUST verify for the envelope to be accepted (fail-closed).

`dsa_pub_len` is a 16-bit BE integer. Accepted values:
- `0` → no DSA signature (classical-only signer)
- `1312` → ML-DSA-44 (44-level, sig 2420 bytes)
- `1952` → ML-DSA-65 (standard, sig 3309 bytes)
- `2592` → ML-DSA-87 (high, sig 4627 bytes)

Any other value MUST cause the unseal to fail.

### 3.3 Versions rejected

Envelope versions 0x00 and 0x01 existed in earlier drafts and are now
REJECTED. They lacked recipient AAD binding and envelope IDs.

---

## 4. Relay protocol

### 4.1 Endpoints

A conforming relay MUST expose these endpoints over HTTPS:

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/send` | Anonymous envelope submission |
| WS | `/v1/receive` | Authenticated push delivery |
| POST | `/v1/forward` | Single-hop relay-to-relay forward |
| POST | `/v1/forward-onion` | Multi-hop onion-layered forward |
| GET | `/v1/relay_info` | Advertise relay's X25519 onion pubkey |
| GET | `/healthz` | Liveness and version |

No other endpoints are defined at the protocol level.

### 4.2 POST /v1/send

Request body: raw routing envelope bytes (see §3.1).

No authentication. No identity. The relay:

1. Reads bytes 1-32 → `recipient_pub`.
2. If `recipient_pub` has an active WebSocket on `/v1/receive`, push the
   envelope to that connection.
3. Otherwise, store the envelope in the relay's mailbox with a 7-day TTL.

Response: `200 OK` with JSON `{"delivered":true}` or `{"stored":true}`.
`413` if oversized. `429` if rate-limited (see §4.7).

### 4.3 WS /v1/receive

Authenticated persistent WebSocket.

On connect, the client MUST send a first text frame containing JSON:

```json
{
  "peer_id": "<base64url(id_pub)>",
  "ts": <unix_millis>,
  "sig": "<base64url(Ed25519_sign(id_priv, 'RELAY1|' || peer_id || '|' || ts))>"
}
```

The relay verifies:
- `|ts - now| < 30_000` (30-second replay window)
- `sig` validates against `peer_id`
- `(peer_id, ts)` has not been seen before (bounded LRU)

On success, the relay:

1. Delivers all stored envelopes for `peer_id` (shuffled, not oldest-first).
2. Registers the connection as active for `peer_id`.
3. Thereafter, pushes new envelopes as binary frames as they arrive via
   `/v1/send`.

The client may send additional frames as JSON messages:

```json
{ "type": "presence_query", "peer_ids": ["<id1>", "<id2>"] }
```

→ Server responds:

```json
{ "type": "presence", "peers": { "<id1>": true, "<id2>": false } }
```

No other client-originated frames are defined. Servers MUST reject
unknown `type`s or garbage frames.

### 4.4 POST /v1/forward

Single-hop forwarding for clients that want to send through a relay
they're not connected to. Request:

```
Headers:
  X-Forward-To: <hostname:port>
Body: <routing envelope bytes>
```

The relay validates `X-Forward-To` is not a loopback / private / link-local
address (SSRF guard), then POSTs the body to `https://<forward-to>/v1/send`
and returns the downstream status.

**NOTE:** `/v1/forward` is single-layer. The entire routing envelope
(including the plaintext `recipient_pub`) is visible to the intermediate
relay. For true recipient privacy from the first hop, use `/v1/forward-onion`
(§5.4).

### 4.5 POST /v1/forward-onion

Multi-hop onion-wrapped forwarding. Request body:

```
byte  0:           version = 0x01
bytes 1-32:        eph_pub (client's ephemeral X25519) [32]
bytes 33-56:       nonce [24]
bytes 57-…:        Box(nonce, relay_x25519_pub, eph_priv,
                       plaintext = next_hop_url_len(2 BE)
                                || next_hop_url(UTF-8)
                                || inner_blob)
```

Where `Box` is libsodium's `crypto_box` construction.

The relay:

1. Decrypts the outer layer using its own X25519 private key (fetched by
   clients via `/v1/relay_info`).
2. Parses `next_hop_url`. Allowed paths: `/v1/send` or `/v1/forward-onion`.
3. SSRF-checks the host.
4. POSTs `inner_blob` to the next hop.

This allows a multi-hop path where no single relay sees both the sender's
IP and the final recipient.

### 4.6 GET /v1/relay_info

Returns the relay's X25519 public key for onion addressing:

```json
{ "x25519_pub": "<base64url(32 bytes)>", "impl": "go" | ... }
```

Clients MUST cache this value and re-fetch on reconnect.

### 4.7 GET /healthz

```json
{ "ok": true, "version": "2.0.0", "impl": "go" | ... }
```

`version` is the protocol version — identical across conforming impls.
`impl` identifies the implementation flavor for operator diagnostics.

### 4.8 Rate limits

Required per-server enforcement:

| Scope | Limit |
|---|---|
| Per source IP | ≥ 60 envelopes/minute |
| Per recipient pubkey | ≥ 300 envelopes/minute |
| Per mailbox (stored) | ≥ 5 000 envelopes |
| Global mailbox | Operator's choice (reference: 500 000) |

A relay MUST NOT relax these limits below the minimums. Relays MAY
tighten them; clients MUST be prepared for `429 Too Many Requests`.

### 4.9 Storage and purging

Stored envelopes expire after 7 days. Relays MUST purge expired rows
at least hourly. On recipient connect, stored envelopes are delivered
in random order (Fisher-Yates shuffle with CSPRNG) to defeat
send-time-to-recipient-connect-time correlation.

---

## 5. Privacy layers

### 5.1 Envelope padding (§3.1.1)

REQUIRED. All routing envelopes MUST be padded to one of the three
fixed buckets.

### 5.2 Send jitter

OPTIONAL. A client MAY delay outgoing envelopes by a random interval to
decouple user actions from wire-timing:

```
jitter_ms = uniform(min_ms, max_ms)
```

Recommended profiles:

| Privacy level | Jitter range |
|---|---|
| 0 (default) | 0 (no jitter) |
| 1 (enhanced) | 50-300 ms |
| 2 (maximum) | 100-500 ms |

Jitter is client-side only; no protocol change.

### 5.3 Cover traffic

OPTIONAL. A client MAY periodically send dummy envelopes — indistinguishable
from real traffic at the wire layer — to mask real-send timing. Dummy
envelopes:

- MUST use the same routing envelope wire format (§3.1)
- SHOULD target real contacts from the known peer list (not random pubkeys)
- MUST contain random bytes as the sealed ciphertext (which will fail to
  unseal at the receiver and be dropped)
- SHOULD follow bursty timing (not uniform intervals) to mimic real
  conversation patterns

### 5.4 Onion routing

OPTIONAL. A client MAY wrap outgoing envelopes in one or more onion layers
using `/v1/relay_info` pubkeys of intermediate relays, then submit to
`/v1/forward-onion`. Each hop peels one layer. See §4.5.

### 5.5 Relay operator trust

A relay operator, even if honest-but-curious, can observe:

- WebSocket connection patterns (who's online, when)
- Per-recipient envelope counts and timing
- Envelope sizes (padded, so: bucket class only)
- Sender IP of POST /v1/send (but not sender identity — sealed sender)

A **colluding pair of relays** can correlate send-time IP with recipient
identity. Onion routing (§5.4) defeats single-relay surveillance; it does
not defeat collusion across all hops.

Mitigations clients can apply:

- Connect through Tor/VPN for network-layer anonymity
- Use multiple relays for send (round-robin) to split knowledge
- Use onion routing when privacy matters

---

## 6. Session layer

### 6.1 Noise IK handshake

First contact with a peer uses the Noise IK pattern with the following
concrete instantiation:

- **Pattern:** IK (initiator knows responder's static pubkey)
- **DH:** X25519
- **Cipher:** ChaCha20-Poly1305
- **Hash:** SHA-256
- **Prologue:** `"P2P-Noise-IK-v1"` (ASCII)

The initiator uses the recipient's Ed25519 pubkey converted to X25519 as
the responder's static key. The initiator's own static X25519 key is also
derived from its Ed25519 identity.

Two-message exchange:

```
Alice → Bob:   msg1 (Noise IK pre-key message)
Alice ← Bob:   msg2 (Noise IK pre-key response)
[Session established on both sides; Double Ratchet initialized]
```

Because the initiator already knows the responder's static key, the first
message is sent before any interactive round-trip — compatible with
store-and-forward mailbox delivery.

### 6.2 PQ-hybrid Noise (optional)

If both peers advertise ML-KEM-768 support via `kem_pub_announce` (§7.2),
subsequent handshakes MAY upgrade to a hybrid construction combining
Noise IK's X25519 with ML-KEM-768 encapsulation in the prologue.

Current profile: classical Noise IK is REQUIRED; PQ-hybrid Noise is
OPTIONAL and signaled by capability. (The sealed envelope layer's
ML-KEM-768 in §3.2 provides PQ security for every envelope regardless.)

### 6.3 Double Ratchet

After Noise IK completes, both sides initialize a Double Ratchet using
the Noise-derived chain key as the root. Parameters:

- **DH:** X25519
- **KDF:** HKDF-BLAKE2b (keyed BLAKE2b — NOT RFC 5869; see §10.2 for the
  exact construction)
- **AEAD:** XChaCha20-Poly1305
- **Max skipped keys per chain:** 1000 (LC3).  Caps the per-session cache
  of out-of-order message keys.  Receivers MUST silently drop messages
  whose `messageNum` would require skipping more than this bound past the
  current chain head — both to prevent a peer (or a malicious relay
  replaying old ciphertexts with fabricated high counters) from forcing
  unbounded key derivations, and to keep the persisted ratchet blob
  size-bounded.  Legitimate network reordering almost never exceeds a few
  hundred in-flight messages.

A DH ratchet step occurs on the first message in a new direction.
Symmetric-key (chain) ratchets advance per message.

#### 6.3.1 KEM ratchet augmentation

On each DH ratchet step, if the peer's ML-KEM-768 pubkey is known, an
ML-KEM-768 encapsulation is performed alongside the X25519 DH. The
resulting shared secret is mixed into the new root key:

```
root_key_new = HKDF(
    salt   = root_key_old,
    ikm    = dh_shared || kem_shared,
    info   = "P2P-Ratchet-v2-KEM",
    output = 32 bytes)
```

This provides post-quantum forward secrecy: even if X25519 is broken in
the future, recovering past session keys requires also breaking ML-KEM-768.

### 6.4 Session persistence

Sessions are serialized and stored locally. Recommended (not required)
format: versioned struct containing root key, sending chain, receiving
chain, skipped message keys, and both peers' identity pubkeys. The
reference implementation stores sessions in SQLCipher-encrypted rows.

---

## 7. Inner payload format

The `inner_payload` field inside a sealed envelope (§3.2) is ratchet
ciphertext. After ratchet decryption, the plaintext is a UTF-8 JSON
object with at minimum:

```json
{
  "type":  "<type>",
  "from":  "<base64url(sender_id_pub)>",
  "ts":    <unix_seconds>,
  "msgId": "<UUID-like string>"
}
```

…plus type-specific fields documented below.

The `type` field dispatches behavior. Unknown types MUST be silently
dropped (never processed, never ack'd).

### 7.1 Message types

| type | Direction | Purpose |
|---|---|---|
| `text` | peer↔peer | Plain text message |
| `avatar` | peer↔peer | Display name + profile picture |
| `kem_pub_announce` | peer↔peer | Announce ML-KEM-768 pubkey |
| `file_key` | sender→receiver | Announce an incoming file with key |
| `file_accept` | receiver→sender | Consent to file transfer |
| `file_decline` | receiver→sender | Refuse file transfer |
| `file_cancel` | either | Cancel in-flight transfer |
| `file_ack` | receiver→sender | File fully received and integrity-verified |
| `file_request` | receiver→sender | Resume: re-send these chunks |
| `file_chunk` | sender→receiver | Encrypted chunk (uses SEALEDFC: prefix) |
| `group_text` | member→members | Text in a group chat |
| `group_invite` | member→members | New-member invite |
| `group_leave` | member→members | Member-left notification |
| `group_rename` | member→members | Rename a group |
| `group_avatar` | member→members | Update group avatar |
| `group_member_update` | member→members | Member list changed |
| `ice_offer`, `ice_answer` | peer↔peer | P2P signaling (optional) |

### 7.2 Text messages

```json
{ "type": "text", "text": "hello", "from": "...", "ts": 1712956800, "msgId": "..." }
```

For group messages:

```json
{
  "type": "group_text",
  "groupId":   "<UUID>",
  "groupName": "...",
  "members":   ["<id1>", "<id2>", ...],
  "seq":       <monotonic uint64>,
  "text":      "...",
  "from":      "...",
  "ts":        ...,
  "msgId":     "..."
}
```

`seq` is a per-(group, sender) monotonic counter detected by each member
for gap detection.

### 7.3 File transfer (1:1)

File delivery is a state machine between sender and receiver:

```
  Sender                          Receiver
  ------                          --------
  (A) file_key      ─────────────▶  [prompt user]
                                    │
                                    ├── auto/accept  ──▶ (B) file_accept
                                    │
                                    └── decline      ──▶ (C) file_decline
  
  (B) on file_accept (or auto-accept policy):
      sender begins streaming file_chunk N of M
                                    
  (D) last chunk received + hash ok ──▶ file_ack
  
  Mid-stream:
    either side MAY send  ────────▶ file_cancel
    receiver on reconnect ────────▶ file_request { chunks: [...] }
                                    [sender resends those chunks]
```

#### 7.3.1 `file_key`

```json
{
  "type":        "file_key",
  "transferId":  "<UUID>",
  "fileName":    "<stripped-of-path sep>",
  "fileSize":    <uint64 bytes, ≤ 100 MB>,
  "fileHash":    "<base64url(BLAKE2b-256 of plaintext file)>",
  "chunkCount":  <uint32>,
  "groupId":     "<optional, for group files>",
  "groupName":   "<optional>",
  "from":        "...",
  "ts":          ...,
  "msgId":       "..."
}
```

The sender derives a **per-file symmetric key** from the ratchet by
capturing `ratchet.lastMessageKey()` immediately after the `file_key`
encrypt. This key is used for AEAD-encrypting each chunk (§7.3.2).

The receiver on `file_key`:

- Checks `fileSize` against its `hard_max` and `auto_accept_max` policies.
- If `fileSize > hard_max`: reply `file_decline` (no reason field).
- If `fileSize ≤ auto_accept_max`: reply `file_accept`, begin preparing.
- Otherwise: prompt user.

On accept, the receiver MUST record `(fileSize, chunkCount, fileHash)` as
the **locked announce values**. Any subsequent chunk whose per-chunk
metadata disagrees MUST be dropped.

#### 7.3.2 `file_chunk`

File chunks do NOT go through the ratchet. They use the per-file key
established at `file_key` time, and are wrapped in a **sealed-file-chunk**
envelope (prefix `SEALEDFC:` in the reference implementation, to
distinguish from plain-text sealed envelopes).

Chunk wire format (inside the sealed envelope's `inner_payload`):

```
  bytes 0-3:        meta_len (uint32 BE)
  bytes 4-3+m:      AEAD(file_key, random_nonce, aad=eph_pub, plaintext=meta_json)
  bytes 4+m-…:      AEAD(file_key, random_nonce, aad=eph_pub, plaintext=chunk_bytes)
```

Where `meta_json` is:

```json
{
  "type":        "file_chunk",
  "transferId":  "...",
  "chunkIndex":  <0-indexed>,
  "totalChunks": <must match announced>,
  "fileName":    "<must match announced>",
  "fileSize":    <must match announced>,
  "fileHash":    "<must match announced>",
  "ts":          ...,
  "from":        "<sender id>"
}
```

Chunk size: 240 KiB (245,760 bytes). The last chunk may be shorter.

Chunk integrity: the outer sealed envelope signs the inner payload via
the sender's Ed25519 / ML-DSA-65 keys, so chunk authenticity is
guaranteed. Plus the file-level BLAKE2b-256 hash is verified after
reassembly.

#### 7.3.3 `file_ack`, `file_request`, `file_cancel`

```json
{ "type": "file_ack", "transferId": "..." }
```

Emitted by receiver when all chunks are written and the final BLAKE2b-256
matches `fileHash`.

```json
{ "type": "file_request", "transferId": "...", "chunks": [3, 7, 8, 12, ...] }
```

Emitted by receiver on reconnect if a partial transfer is persisted with
missing chunks. Sender replies with those chunks re-sent. Senders SHOULD
rate-limit resend requests and cap chunk-list size.

```json
{ "type": "file_cancel", "transferId": "..." }
```

Emitted by either side to abort. No `reason` field (anti-probing).

### 7.4 Group messaging (current: pairwise fan-out)

A group is a client-side construct: a `groupId` (UUID) and a set of member
pubkeys. To send to a group, the sender iterates members and sends a
1:1 `group_text` message through each member's ratchet session, reusing
the same `groupId`, `seq`, `msgId`.

This is O(N) messages per send for an N-member group. MLS-based group
messaging is a future extension (§11).

Membership changes:
- `group_invite` — sent by any member to a new member's 1:1 session.
- `group_leave` — sent by the leaving member to all remaining.
- `group_member_update` — sent when membership changes to push a new
  canonical list.

### 7.5 Presence

Presence is ambient, not its own message type. A peer is "online" iff
it has an active WebSocket on a relay. The relay exposes this via:

- Push-based: a peer that subscribed to presence for `peer_ids` receives
  on-connect / on-disconnect notifications.
- Pull-based: `presence_query` frame (§4.3).

Clients SHOULD NOT poll presence; the push path is the intended design.

### 7.6 ICE/P2P (optional)

For implementations that support direct peer-to-peer transport,
`ice_offer` and `ice_answer` carry standard ICE SDP blobs (a list of
candidates + ufrag + pwd). These messages are sealed like any other.

When both peers have an established direct P2P connection, sealed
envelopes MAY be delivered over the direct transport, bypassing the
relay. Falls back to the relay on any failure.

---

## 8. Replay protection

Three layers of replay protection are REQUIRED:

1. **Envelope-level:** 16-byte `envelope_id` (§3.2) bound into AEAD
   plaintext. Receivers maintain a bounded LRU of seen IDs.
2. **Ratchet-level:** the Double Ratchet counters inherently detect
   replays of ratchet ciphertext. Out-of-order messages within a chain
   are buffered via skipped-message-keys; duplicates are dropped.
3. **Application-level:** `msgId` field in JSON payloads provides a
   final dedup point for types that bypass the ratchet (e.g., `file_chunk`).

Implementations MUST apply all three.

---

## 9. Security properties

### 9.1 What the protocol guarantees

- **End-to-end encryption.** No relay operator, network observer, or
  honest-but-curious intermediary can read message content.
- **Forward secrecy.** Compromising long-term keys does NOT expose past
  messages (thanks to Double Ratchet + KEM augmentation).
- **Post-compromise security.** Within a few message exchanges after
  compromise, future messages become secure again (DH ratchet recovery).
- **Post-quantum security.** Even if classical X25519/Ed25519 are broken,
  the ML-KEM-768/ML-DSA-65 layers independently secure every sealed
  envelope.
- **Sender anonymity vs. relay.** The relay sees only `recipient_pub`,
  never sender identity.
- **Replay protection.** Every layer prevents re-delivery of previously-
  processed messages.
- **Authenticated delivery.** Every sealed envelope has a sender signature;
  unauthorized senders cannot forge messages.

### 9.2 What the protocol does NOT guarantee

- **Deniability.** The sender's Ed25519 (+ ML-DSA-65) signature is bound
  to every envelope. A receiver can prove the sender wrote the message.
- **Metadata privacy against colluding relays** (if a multi-hop onion
  path passes through multiple relays under common control).
- **Protection against endpoint compromise.** Once a device is compromised,
  the attacker has the keys.
- **Traffic analysis by a global passive adversary.** Padding + jitter +
  cover traffic raise the cost, but do not eliminate it.
- **Group-level forward secrecy on membership change.** Until the MLS
  extension lands (§11), leaving a group does not rotate keys.
- **Anti-spam / anti-abuse.** Rate limits slow flooding; there is no
  reputation system or proof-of-work.

---

## 10. Implementation conformance

### 10.1 Client and relay requirements

A conforming **client** MUST:

- Generate identity keys using the algorithms in §2.1.
- Implement routing envelope wrap/unwrap (§3.1) with padding buckets.
- Implement sealed envelope seal/unseal version 0x02 AND 0x03 (§3.2)
  with AAD binding and envelope-id replay protection.
- Implement Noise IK handshake (§6.1) and the augmented Double Ratchet
  (§6.3).
- Support the message types marked as REQUIRED in §7 (text at minimum).
- Reject envelopes with version < 0x02.

A conforming **client** MAY:

- Skip file transfer (`file_*` types).
- Skip groups.
- Skip direct P2P transport.
- Skip privacy layers beyond padding.
- Skip PQ-hybrid Noise (§6.2) — sealed-envelope PQ is enough.

A conforming **relay** MUST:

- Implement all endpoints in §4.1.
- Enforce the rate limits in §4.8.
- Purge expired envelopes hourly.
- Shuffle stored-envelope delivery on connect.
- Publish its X25519 onion pubkey via `/v1/relay_info` and honor
  `/v1/forward-onion`.
- Enforce SSRF restrictions on `/v1/forward` and `/v1/forward-onion`.
- NEVER log envelope content, unsealed payloads, or anything beyond
  (hashed IP, recipient pubkey prefix, timing, size bucket).

### 10.2 HKDF-BLAKE2b key derivation primitive

The `HKDF(...)` invocations throughout this document (§6.3 Double Ratchet,
§6.3.1 KEM ratchet, pre-key payload keys in SessionManager, identity-unlock
subkey, session-store at-rest key) all refer to the construction below.
It is **not** RFC 5869 HKDF — implementations that substitute HMAC-HKDF will
not interoperate.

```
HKDF-BLAKE2b(ikm, salt, info, L):
    requires 1 <= L <= 64
    Extract:
        PRK = BLAKE2b-256(key = salt, input = ikm)     // 32-byte PRK
    Expand:
        T   = BLAKE2b-L  (key = PRK,  input = info || 0x01)
    return T
```

Deviations from RFC 5869, all intentional:
- PRF is **keyed BLAKE2b** (libsodium `crypto_generichash`), not HMAC-SHA-256.
- PRK length is 32 bytes regardless of output size (RFC 5869 uses HashLen).
- Expand emits a single block — `L` is capped at 64 bytes (BLAKE2b max
  digest).  Larger outputs are unsupported; implementations MUST return
  an empty buffer rather than chain blocks.
- `info` is domain-separated by appending a single `0x01` counter byte
  before hashing.  Implementations MUST preserve this byte exactly.

Audit note (M4): the mismatch between "HKDF" in the name and the actual
construction is a historical artefact; it is documented rather than
renamed to avoid churning every call site.  A future protocol revision
may switch to libsodium's `crypto_kdf_*` family for cleaner audit
alignment.

---

## 11. Future extensions

The following are under consideration for a future protocol version and
are deliberately NOT part of v2.0:

- **Sender Keys / MLS** for groups > 20 members.
- **Multi-device identity** with cross-device key sync and per-device
  message fanout.
- **QR-code and invite-link contact exchange** (UX; no wire change).
- **ML-KEM-1024 / ML-DSA-87 profile** for higher security levels.
- **Relay discovery protocol** for bootstrapping community relay lists.

---

## 12. Reference implementations

- **Relay (Go):** `relay-go/` — ~1500 LOC, single static binary, SQLite
  mailbox.  Currently the only reference server.
- **Client (Qt/C++):** `desktop/` + `core/` — reference client.  The
  `core/` static library is reusable for mobile ports.

The relay exposes `/healthz → {version: "2.0.0", impl: …}` for operator
diagnostics.  A previous Python (FastAPI) reference relay at `relay/`
was retired on 2026-04-20: maintaining behavioural parity between two
impls was itself an audit finding (LC1/LC2 — jitter RNG drift,
cover-traffic ordering drift), and the spec here is the single source
of truth a future second implementation would hold itself to.

---

## Appendix A: Envelope sealing pseudocode

```
function seal(recipient_curve_pub, recipient_ed_pub,
              sender_ed_pub, sender_ed_priv,
              inner_payload,
              recipient_kem_pub = nil,
              sender_dsa_pub = nil, sender_dsa_priv = nil):

    hybrid = (recipient_kem_pub is not nil)
    (eph_pub, eph_priv) = X25519.generate_keypair()

    ecdh_shared = X25519.scalarmult(eph_priv, recipient_curve_pub)
    assert ecdh_shared is not all zeros        // reject contributory failure

    if hybrid:
        (kem_ct, kem_shared) = ML_KEM_768.encaps(recipient_kem_pub)
        ikm = ecdh_shared || kem_shared
    else:
        ikm = ecdh_shared

    envelope_key = BLAKE2b_256(ikm)

    envelope_id = randombytes(16)
    signed = envelope_id || inner_payload
    ed_sig = Ed25519.sign(sender_ed_priv, signed)
    if sender_dsa_priv:
        dsa_sig = ML_DSA_65.sign(sender_dsa_priv, signed)
    
    plaintext = envelope_id
             || sender_ed_pub
             || ed_sig
             || (sender_dsa_pub ? u16_be(|sender_dsa_pub|) || sender_dsa_pub || dsa_sig
                                 : u16_be(0))
             || inner_payload

    nonce = randombytes(24)
    aad = eph_pub || recipient_ed_pub
    ct = XChaCha20Poly1305.encrypt(envelope_key, nonce, aad, plaintext)

    version = hybrid ? 0x03 : 0x02
    if hybrid:
        return version || eph_pub || kem_ct || nonce || ct
    else:
        return version || eph_pub || nonce || ct
```

## Appendix B: Envelope unsealing pseudocode

```
function unseal(recipient_curve_priv, recipient_ed_pub,
                sealed_bytes, recipient_kem_priv = nil):

    version = sealed_bytes[0]
    if version not in {0x02, 0x03}: return invalid

    hybrid = (version == 0x03)
    eph_pub = sealed_bytes[1:33]
    assert eph_pub is not all zeros

    ecdh_shared = X25519.scalarmult(recipient_curve_priv, eph_pub)
    assert ecdh_shared is not all zeros

    if hybrid:
        kem_ct = sealed_bytes[33:33+1088]
        kem_shared = ML_KEM_768.decaps(kem_ct, recipient_kem_priv)
        ikm = ecdh_shared || kem_shared
        aead_offset = 33 + 1088
    else:
        ikm = ecdh_shared
        aead_offset = 33

    envelope_key = BLAKE2b_256(ikm)

    nonce = sealed_bytes[aead_offset : aead_offset+24]
    ct = sealed_bytes[aead_offset+24 : ]
    aad = eph_pub || recipient_ed_pub

    plaintext = XChaCha20Poly1305.decrypt(envelope_key, nonce, aad, ct)
    if plaintext is None: return invalid

    envelope_id = plaintext[0:16]
    sender_ed_pub = plaintext[16:48]
    ed_sig = plaintext[48:112]
    dsa_pub_len = u16_be(plaintext[112:114])
    offset = 114

    if dsa_pub_len == 0:
        dsa_pub = dsa_sig = nil
    elif dsa_pub_len == 1952:
        dsa_pub = plaintext[offset : offset+1952]
        dsa_sig = plaintext[offset+1952 : offset+1952+3309]
        offset += 1952 + 3309
    elif dsa_pub_len == 1312:
        dsa_pub = plaintext[offset : offset+1312]
        dsa_sig = plaintext[offset+1312 : offset+1312+2420]
        offset += 1312 + 2420
    elif dsa_pub_len == 2592:
        dsa_pub = plaintext[offset : offset+2592]
        dsa_sig = plaintext[offset+2592 : offset+2592+4627]
        offset += 2592 + 4627
    else:
        return invalid                 // unrecognized DSA profile

    inner_payload = plaintext[offset:]
    signed = envelope_id || inner_payload

    if not Ed25519.verify(sender_ed_pub, signed, ed_sig): return invalid
    if dsa_pub and not ML_DSA_65.verify(dsa_pub, signed, dsa_sig): return invalid

    if lru.contains(envelope_id): return duplicate
    lru.add(envelope_id)

    return (sender_ed_pub, inner_payload, envelope_id)
```

---

## Appendix C: Changelog

- **v2.0.0 (current)** — Recipient AAD binding, envelope-id replay
  protection, onion routing, file transfer with resumption, PQ-hybrid
  at every layer.
- **v1.x (deprecated)** — Initial design. Removed: `/mbox/enqueue`,
  `/mbox/fetch*`, `/mbox/ack`, `/rvz/publish`, `/rvz/lookup`. Sealed
  envelope versions 0x00 and 0x01.

---

*End of specification.*
