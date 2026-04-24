# Sender Keys Refactor — Plan

Status: **shipped** — all phases + metadata-encryption close-out
complete.  248 tests green, iOS simulator + desktop rebuild clean.
PROTOCOL.md v2.1 documents the wire format.  MLS remains deferred
future work (see project_mls_future.md).

Supersedes the MLS refactor direction previously tracked in
`project_mls_future.md`.  MLS remains a future consideration for larger
groups / institutional use cases; Sender Keys is the right intermediate
step for Peer2Pear's current threat model and user base.

---

## 1. Goal

Close the O(N) plaintext-encryption bottleneck in group messaging and
add group-level forward secrecy with rekey-on-leave semantics, while
preserving:

- PQ hybrid encryption on key distribution (via the existing
  ML-KEM-768-augmented Double Ratchet)
- Sealed-sender anonymity (no relay-visible sender identity on group
  envelopes)
- Compatibility with the existing relay architecture (no new endpoints,
  no per-group delivery service, no changes to the mailbox)

**Explicitly out of scope**: cryptographic membership authority (H5 is
partially mitigated, not closed — see §4.4).  MLS is the path to full
closure when the threat model warrants it.

---

## 2. Design

### 2.1 Primitive: `SenderChain`

New class `core/SenderChain.{hpp,cpp}`.  Symmetric ratchet, same KDF
family as `RatchetSession`'s message-chain but without the DH/KEM outer
loop.

```cpp
class SenderChain {
public:
    using Bytes = std::vector<uint8_t>;

    // Fresh chain — random 32-byte seed.  The seed is distributed via
    // `group_skey_announce`; both sides reconstruct identical chains
    // from it.
    static SenderChain freshOutbound();

    // Inbound: reconstruct from a seed received via skey_announce.
    static SenderChain fromSeed(const Bytes& seed, uint32_t startIdx = 0);

    // Current seed (for distribution to new members).
    const Bytes& seed() const;

    // Advance + produce a message key.  Used on send.
    // Returns (idx, messageKey).  idx is embedded in the wire header
    // so receivers can skip to it if messages arrive out of order.
    std::pair<uint32_t, Bytes> next();

    // Derive the message key for a specific index (for out-of-order
    // recv).  Caches up to kMaxSkipped keys so repeated lookups are
    // O(1) and can't be forced to recompute.
    Bytes messageKeyFor(uint32_t idx);

    Bytes serialize() const;
    static SenderChain deserialize(const Bytes& blob);

    static constexpr uint32_t kMaxSkipped = 2000;

private:
    Bytes    m_seed;        // 32 bytes — the shared group secret
    Bytes    m_chainKey;    // 32 bytes — evolves on each next()
    uint32_t m_nextIdx = 0;
    std::map<uint32_t, Bytes> m_skipped;
};
```

KDF: BLAKE2b domain-separated hashes over `chain_key || "msg"` and
`chain_key || "chain"`.  Reuses the pattern in
`RatchetSession::kdfChainKey` — ~20 LOC of actual crypto.

### 2.2 State additions to `GroupProtocol`

```cpp
class GroupProtocol {
    // ... existing m_members, m_seqOut, m_seqIn ...

    // My outbound chain per group.  Lazy-created on first send after
    // membership change; rotated on member removal.
    std::map<std::string, SenderChain> m_mySendChains;        // gid -> chain

    // Other members' inbound chains, keyed by (gid, senderId).
    // Populated from `group_skey_announce` messages received via 1:1.
    std::map<std::pair<std::string, std::string>, SenderChain> m_recvChains;

    // Per-group epoch counter.  Bumped on any roster change that
    // rotates sender keys (currently: member removal / leave only).
    std::map<std::string, uint64_t> m_epoch;
};
```

### 2.3 Wire protocol additions

#### New type: `group_skey_announce`

Sent 1:1 through existing sealed ratchet envelopes — inherits PQ
hybrid encryption from the Double Ratchet.  Sent when:

1. **Creating a group** — to each initial member.
2. **Adding a member** — to all members (new member gets existing
   chains; existing members get new member's chain).
3. **Rekeying on removal/leave** — to all remaining members, with
   incremented epoch.

```json
{
  "type":     "group_skey_announce",
  "groupId":  "<UUID>",
  "epoch":    <uint64>,
  "seed":     "<base64url 32 bytes>",
  "startIdx": 0,
  "from":     "<sender_peer_id>",
  "ts":       ...,
  "msgId":    "..."
}
```

#### Modified type: `group_msg`

Breaking change — pre-1.0, no dual-path support.  Plaintext `text`
field removed; ciphertext + chain metadata added.

```json
{
  "type":       "group_msg",
  "groupId":    "<UUID>",
  "groupName":  "...",
  "members":    [...],
  "skey_epoch": <uint64>,
  "skey_idx":   <uint32>,
  "ciphertext": "<base64url(XChaCha20-Poly1305(msgKey, plaintext, AAD))>",
  "from":       "...",
  "ts":         ...,
  "msgId":      "..."
}
```

AAD = `from_peer_id || groupId || epoch || idx` (all as raw bytes,
concatenated).  Prevents cross-epoch and cross-group replay.

#### Unchanged types (still flow through 1:1 sealed ratchet)

- `group_rename`
- `group_avatar`
- `group_member_update`
- `group_leave`

These are metadata/control, low throughput, and benefit from the 1:1
ratchet's per-peer forward secrecy + PQ augmentation.  No reason to
route them through sender keys.

### 2.4 Rekey-on-leave

**When Alice removes Bob** (via `sendMemberUpdate` with Bob dropped):

1. Alice computes new roster (excludes Bob)
2. Alice rotates: `m_mySendChains[gid] = SenderChain::freshOutbound(); m_epoch[gid]++`
3. Alice sends `group_skey_announce` to every **remaining** member (not Bob)
4. Alice sends `group_member_update` with the new roster to every remaining member
5. Remaining members receive skey_announce, install new chain under new epoch
6. Subsequent `group_msg` from Alice carries `skey_epoch = new`
7. Bob's copy of Alice's old chain is cryptographically useless

Ordering: steps 3 and 4 flow through different 1:1 ratchets but the
relay delivers per-peer FIFO, so as long as Alice emits skey_announce
before member_update on each 1:1 path, ordering holds at the receiver.

**When Alice leaves** (via `sendLeave`):
- Alice sends `group_leave` to all remaining members
- Remaining members each independently generate a fresh sender chain
  and distribute (same pattern as §2.3 #3 above) — but WITHOUT the
  leaver
- Alice's local state for the group is kept for history decryption
  (inbound chains from other members decrypt old messages still in the
  DB) but her outbound chain is never advanced again

**In-flight messages across rekey**: if Bob sent a message at epoch 5
just before being removed, and Alice's rekey to epoch 6 races Bob's
delivery, Alice keeps Bob's epoch-5 chain in memory for 5 minutes
post-rekey to decrypt in-flight messages.  After the grace window, old
chains are purged.  (This window is the fundamental async-delivery
cost; MLS would have the same issue at the protocol-delivery layer.)

### 2.5 Backward compatibility

**Hard break.**  New `group_msg` format is not wire-compatible with v1.

Rationale:
- Pre-1.0, no production users
- Dual-path handling bloats every group code path with a version flag
- Already-decrypted messages persist on-device (iOS `Peer2PearStore`,
  desktop SQLCipher) — history stays readable after upgrade

Bumped in `PROTOCOL.md` §6 with a "v2 group messaging" marker.

---

## 3. Implementation phases

### Phase 1 — `SenderChain` primitive + tests (2–3 days)

**New files**:
- `core/SenderChain.hpp` (~60 LOC)
- `core/SenderChain.cpp` (~150 LOC)
- `core/tests/test_sender_chain.cpp` (~200 LOC, ~12 test cases)

**Build wiring**:
- `core/CMakeLists.txt` (+2 lines)
- `core/tests/CMakeLists.txt` (+1 line)

**Test cases** (minimum):
1. `freshOutbound` produces a 32-byte seed
2. `fromSeed(alice.seed())` on Bob produces identical keys at same idx
3. Sequential `next()` derives unique, non-repeating keys
4. `messageKeyFor(n)` caches skipped keys up to `kMaxSkipped`
5. Skipping past `kMaxSkipped` returns empty (DoS guard)
6. `serialize()` / `deserialize()` round-trip preserves state exactly
7. Re-asking for an already-derived key returns the cached value
8. Two chains with different seeds never produce colliding keys
9. `kdfChainKey` output is 32 bytes, message-key domain separated from chain-key domain
10. Deserializing corrupted data returns invalid chain (no crash)
11. AEAD round-trip using a chain-derived key succeeds
12. AEAD round-trip with mismatched AAD fails

**Exit criterion**: `test_sender_chain` green; full suite at 188 tests, 0 failures.

### Phase 2 — Integrate into `GroupProtocol` outbound path (3 days)

**Modified**:
- `core/GroupProtocol.hpp` — add state members + `sendSkeyAnnounce`,
  `installRemoteChain`, `rotateMyChain` methods
- `core/GroupProtocol.cpp` — rewrite `sendText` to encrypt via
  `m_mySendChains[gid]`; add dispatch for inbound `group_skey_announce`
- `core/ChatController.cpp` — inbound `group_skey_announce` →
  `m_groupProto.installRemoteChain(...)`; `group_msg` handler decrypts
  via `m_recvChains[{gid, from}].messageKeyFor(idx)` before calling
  `onGroupMessage`
- `core/tests/test_group_protocol.cpp` — extended with sender-key tests

**Buffering inbound-before-skey**: if a `group_msg` arrives for a
(gid, from, epoch, idx) tuple where we don't yet have the chain,
buffer up to 50 messages per (gid, from) for 60 seconds.  On any
incoming `group_skey_announce` for that tuple, flush buffered messages
through the new chain.  Drop buffer entries after timeout; log.

**Exit criterion**: two-client unit test round-trips a group message
via sender-keys.  `test_group_protocol` extensions pass.

### Phase 3 — Invite + member-update rekey (2 days)

**Modified**:
- `core/GroupProtocol.cpp` — `sendMemberUpdate` detects roster shrink
  → rotates own chain + re-announces; `upsertMembersFromTrustedMessage`
  for new members triggers a skey_announce from us to them
- `core/ChatController.cpp` — wire through the "rotate on shrink"
  signal path
- `core/tests/test_group_protocol.cpp` — rekey test cases

**Test cases**:
- 3-member create: all three have each other's chains after setup
- Add 4th member: new member receives three chains; existing three
  receive new member's chain; epoch unchanged
- Remove member: remaining members' epoch advances; removed member's
  last-known chain rejected for new messages
- Removed member's pre-removal message still decrypts during grace
  window (5 min)
- After grace window, removed member's pre-rekey messages dropped

**Exit criterion**: rekey test suite green.  Explicit demonstration in
a test: Eve removed at epoch N, Eve's attempt to send at epoch N+1
using old chain fails to decrypt on Alice's side.

### Phase 4 — Persistence (1 day)

**Modified**:
- `core/SessionStore.{hpp,cpp}` — new methods:
  `saveSenderChain(gid, senderId, epoch, blob)`,
  `loadSenderChainsForGroup(gid) -> map<senderId, (epoch, blob)>`,
  `deleteSenderChainsForGroup(gid)`.
  New SQL table `sender_chains (group_id TEXT, sender_id TEXT, epoch
  INT, chain_blob BLOB, PRIMARY KEY (group_id, sender_id))`.
- `core/GroupProtocol.cpp` — on `setSessionManager`, restore chains
  per known group; after every `next()` or rekey, write-through to
  SessionStore.

Chain blobs are encrypted at rest using the same storeKey pattern as
RatchetSession blobs (XChaCha20-Poly1305 with AAD binding
`"sender_chain" || gid || senderId`).

**Exit criterion**: kill + restart a client mid-conversation, chains
restore, next message decrypts without re-distributing.

### Phase 5 — iOS + desktop surface (1 day)

**iOS**: no new `@Published` state needed — group messages still flow
through existing `onGroupMessage` callback.  `Peer2PearStore` snapshot
format unchanged (decrypted messages only; sender chains are
SQLCipher-persisted via core, not Swift).  Verify existing group tests
still pass after regenerating the core static lib.

**Desktop**: no UI changes.  Group chats work identically from the
user's perspective.

**Exit criterion**: both platforms exchange group messages with the
new protocol; full suite green; iOS simulator smoke build succeeds.

### Phase 6 — PROTOCOL.md + sync (0.5 day)

- §7.1 envelope-types table: correct `group_text` → `group_msg`
  (existing doc/code drift); add `group_skey_announce`
- §7.2 updated with new `group_msg` fields + AAD definition
- New §7.7 "Group sender-key announcement" with full wire format
- §11 "Known Limitations": explicit text on H5 residual risk (see §4.4
  of this plan)
- Protocol version bump marker in §6

### Phase 7 — Full test sweep (0.5 day)

- Full `ctest` pass — target: ~195 tests, 0 failures
- iOS simulator smoke build (`xcodebuild` on iPhone 17)
- Desktop smoke build
- Verify `test_e2e_two_clients` covers sender-keys end-to-end
- Commit-ready diff

---

## 4. Decisions (locked)

### 4.1 Break wire compat with old `group_msg`

**Yes.**  Pre-1.0, dual-path code debt not worth carrying.  Documented
as protocol v2 in PROTOCOL.md §6.

### 4.2 Include epoch in AAD

**Yes.**  AAD = `from_peer_id || groupId || epoch || idx`.
Defense-in-depth against cross-epoch and cross-group replay; zero
wire-size cost.

### 4.3 Rekey on rename / avatar

**No.**  Only roster removals trigger rekey.  rename / avatar /
member_update-that-only-adds are metadata; their security is provided
by the 1:1 ratchet envelope they flow through (which has PQ hybrid).

All four control messages (`group_rename`, `group_avatar`,
`group_member_update`, `group_leave`) already flow through
`SessionSealer::sealForPeer` — they are encrypted end-to-end, not just
in transit.  No change needed.

### 4.4 Document H5 residual risk

**Yes.**  PROTOCOL.md §11 will gain explicit text:

> **Group membership authority is not cryptographically enforced.**
> The current protocol (sender-key-based group messaging) derives
> member identity from the creator's invite list plus subsequent
> member_update messages, all authenticated by sender but not by a
> group-level authority.  An attacker who is a group member can claim
> a modified roster to peers who lack independent knowledge of the
> group.  The bounded attack: the attacker cannot decrypt messages
> from members whose sender keys they have not received, and cannot
> impersonate other members' messages without their sender chain
> material.  Full membership authority (MLS-style signed commits)
> remains future work.

---

## 5. Files touched summary

**New**:
- `core/SenderChain.hpp`
- `core/SenderChain.cpp`
- `core/tests/test_sender_chain.cpp`

**Modified**:
- `core/GroupProtocol.{hpp,cpp}`
- `core/ChatController.cpp`
- `core/SessionStore.{hpp,cpp}`
- `core/tests/test_group_protocol.cpp`
- `core/tests/test_e2e_two_clients.cpp`
- `core/CMakeLists.txt`
- `core/tests/CMakeLists.txt`
- `PROTOCOL.md`

**Not touched**:
- `core/SessionSealer.{hpp,cpp}`
- `core/FileProtocol.{hpp,cpp}`
- `core/CryptoEngine.{hpp,cpp}` (reuses existing aeadEncrypt/Decrypt)
- Any iOS `.swift` file
- Any desktop `chatview.cpp` path
- Relay (`relay-go/`)

---

## 6. Scope estimate

**7–10 working days**, single developer.

Phase-by-phase go/no-go gates; if Phase 1 (SenderChain primitive)
exceeds 3 days, stop to reassess.

No external dependencies added.  No vcpkg changes.  No iOS toolchain
risk.

---

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Chain-key divergence between sender and receiver | Medium | High | Deterministic KDF with idx in AAD — divergence surfaces as clean AEAD auth failure, not silent corruption; property test in Phase 1 enforces determinism |
| `group_skey_announce` lost / arrives after first message | High on lossy networks | Medium | Buffer up to 50 undecryptable messages per (gid, from) for 60 s; flush on any subsequent skey_announce for that tuple |
| Rekey race: removed member's in-flight message arrives post-rekey | Medium | Low | 5-minute grace window where old chains remain decrypt-capable; after window, old-epoch messages dropped with warn log |
| Skipped-key DoS (malicious `skey_idx=UINT32_MAX`) | Medium | Medium | `kMaxSkipped = 2000` cap in SenderChain; past that, drop + log |
| Leaving member decrypts in-flight messages sent before their `group_leave` propagates | Certain | Low | Accepted — inherent to async delivery; next rekey cycle closes the window |

---

## 8. Post-ship evaluation criteria

After Phase 7, verify:

- All 195+ tests pass
- Group message throughput improves (benchmark: send 100 group
  messages to a 10-member group; measure wall-clock vs pairwise
  baseline — expect 5–8× improvement from single-encrypt + N-envelope
  wraps)
- No regression in iOS / desktop smoke tests
- PROTOCOL.md renders cleanly with updated group sections
- `project_mls_future.md` memory updated to reference this plan as the
  intermediate step, MLS as the future path
