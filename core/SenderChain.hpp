#pragma once

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

/*
 * SenderChain — symmetric group-message ratchet.
 *
 * Unlike RatchetSession (which owns a full DH + KEM outer ratchet),
 * SenderChain is a pure symmetric key chain: one shared 32-byte seed
 * derives an evolving chain key that yields a fresh message key for
 * every group message.  Every participant with a copy of the seed
 * derives the same sequence of message keys.
 *
 * Used by GroupProtocol: each group member maintains an outbound
 * SenderChain for the groups they send in, plus one inbound SenderChain
 * per other-member-per-group for decryption.  Seeds are distributed via
 * `group_skey_announce` messages that flow through each recipient's 1:1
 * Double Ratchet session (which carries hybrid PQ encryption).
 *
 * Wire usage (see PROTOCOL.md §7.2):
 *   msg_key    = chain.messageKeyFor(idx)        // receiver
 *   (idx, msg_key) = chain.next()                 // sender
 *   ciphertext = AEAD_encrypt(msg_key, plaintext,
 *                              aad = from || gid || epoch || idx)
 *
 * Rotation (rekey-on-leave): when a member is removed, every remaining
 * member discards their old outbound chain + generates a new one via
 * freshOutbound().  Old inbound chains are held briefly (see
 * GroupProtocol) for a grace window to decrypt in-flight messages that
 * crossed the rekey event.
 *
 * Security properties:
 *   - Forward secrecy within a chain: compromising the current chain
 *     key cannot recover message keys at earlier indices (BLAKE2b is
 *     one-way).
 *   - No post-compromise security within a single chain — that comes
 *     from chain rotation on membership change.
 *   - DoS bound: messageKeyFor caps skipped derivations at kMaxSkipped
 *     per call, and caches are LRU-evicted past that cap.  A malicious
 *     sender claiming idx=UINT32_MAX cannot force unbounded work.
 *
 * Thread model: SenderChain instances live in GroupProtocol, which is
 * serialized by the same ctrl mutex as the rest of the core.  No
 * internal locking.
 */
class SenderChain {
public:
    using Bytes = std::vector<uint8_t>;

    // --- Construction -----------------------------------------------

    // Fresh outbound chain.  Generates a cryptographically random
    // 32-byte seed; caller distributes via group_skey_announce.
    static SenderChain freshOutbound();

    // Reconstruct an inbound chain from a seed received via
    // group_skey_announce.  Returns an invalid chain (isValid() false)
    // if seed isn't 32 bytes.  Starts at index 0.
    static SenderChain fromSeed(const Bytes& seed);

    // Valid = constructed from a proper 32-byte seed.  Default-
    // constructed instances are invalid placeholders.
    bool isValid() const { return m_seed.size() == 32; }

    SenderChain() = default;

    // --- Accessors --------------------------------------------------

    // The seed we were constructed from.  Used by GroupProtocol to
    // serialize our own chain into an outbound group_skey_announce.
    // Also the starting chain key (chain_key_0 = seed).
    const Bytes& seed() const { return m_seed; }

    // Index of the next message this chain would derive via next().
    // For inbound chains, the highest idx past which messageKeyFor
    // would need to advance the chain to derive a new key.
    uint32_t nextIdx() const { return m_nextIdx; }

    // --- Outbound ---------------------------------------------------

    // Advance the chain by one step.  Returns (idx, messageKey) where
    // idx is the position of the newly-derived key and messageKey is
    // 32 bytes suitable for XChaCha20-Poly1305.  Caller embeds idx in
    // the wire header so the receiver can match with messageKeyFor.
    //
    // After this returns, the chain has advanced past idx; calling
    // next() again on this instance produces a different, unrelated
    // key at idx+1.  No caching on the outbound path — the sender
    // sends each message exactly once.
    std::pair<uint32_t, Bytes> next();

    // --- Inbound ----------------------------------------------------

    // Derive the message key for a specific index.
    //
    // Semantics:
    //   - If idx < nextIdx and key was previously cached (via a
    //     forward-skip from an earlier messageKeyFor call): return
    //     the cached key.
    //   - If idx < nextIdx and key is NOT cached: return empty.
    //     Either already evicted (LRU past kMaxSkipped) or the chain
    //     advanced past it without caching (outbound usage mixed).
    //   - If idx >= nextIdx: advance the chain up to and including
    //     idx, caching intermediate keys (idx..nextIdx-1) in the
    //     skipped table.  Return the key at idx.
    //   - If the advance would require more than kMaxSkipped
    //     derivations in a single call: return empty (DoS guard).
    //
    // Repeated calls with the same idx return identical keys — cached
    // keys are not erased on retrieval.  Replay prevention happens at
    // the envelope-id layer (outer), not here.
    Bytes messageKeyFor(uint32_t idx);

    // Drop all cached skipped keys.  Called by GroupProtocol during
    // rekey to ensure old message keys don't linger in memory past
    // their grace window.
    void clearSkipped();

    // --- Persistence ------------------------------------------------

    // Binary layout (little-endian):
    //   [version:u8=0x01]
    //   [seed:32 bytes]
    //   [chainKey:32 bytes]
    //   [nextIdx:u32]
    //   [skippedCount:u32]
    //   [skipped entries: (idx:u32 || key:32) × skippedCount]
    //
    // Deserialization validates structural correctness and returns an
    // invalid chain on any error.  Skipped entries beyond
    // kMaxSkipped are silently dropped on load.
    Bytes serialize() const;
    static SenderChain deserialize(const Bytes& blob);

    // Maximum gap a single messageKeyFor call can bridge, also the
    // soft cap on cache size (oldest entries evicted LRU).
    static constexpr uint32_t kMaxSkipped = 2000;

    // Serialization version tag.  Bump if layout changes.
    static constexpr uint8_t  kVersion = 0x01;

private:
    // Derive the next message key and advance m_chainKey + m_nextIdx.
    // Shared by next() and messageKeyFor.
    Bytes advanceStep();

    // After inserting into m_skipped, evict smallest-idx entries until
    // the cache is within kMaxSkipped.  Zeros evicted key material.
    void evictOldestIfOverCap();

    Bytes    m_seed;         // 32 bytes — shared group secret
    Bytes    m_chainKey;     // 32 bytes — evolves on each advanceStep()
    uint32_t m_nextIdx = 0;  // position of the NEXT key to derive

    // LRU of forward-skipped keys indexed by their derivation idx.
    // std::map is ordered by key, so begin() is the oldest idx.
    std::map<uint32_t, Bytes> m_skipped;
};
