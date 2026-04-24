#include "SenderChain.hpp"

#include <sodium.h>

#include <cstring>

namespace {

// KDF tags for domain separation.  Same pattern as
// RatchetSession::kdfChainKey so anyone auditing one recognizes the
// other: one BLAKE2b-256 keyed by the chain key, with a single-byte
// input selecting the "next chain key" derivation (0x01) or "message
// key" derivation (0x02).
constexpr uint8_t kTagChain = 0x01;
constexpr uint8_t kTagMsg   = 0x02;

// BLAKE2b-256 keyed hash → 32-byte output.  Thin wrapper so the KDF
// sites below read as intent, not libsodium ceremony.
SenderChain::Bytes blake2bKeyed32(uint8_t tag,
                                    const SenderChain::Bytes& key)
{
    SenderChain::Bytes out(32);
    (void)crypto_generichash(out.data(), 32,
                             &tag, 1,
                             key.data(), key.size());
    return out;
}

// Little-endian u32 read/write helpers.  Serialization format pins LE
// explicitly so cross-platform restore is deterministic (BE hosts
// would otherwise produce mismatched blobs).
void writeU32LE(SenderChain::Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

bool readU32LE(const SenderChain::Bytes& in, size_t& pos, uint32_t& out) {
    if (pos + 4 > in.size()) return false;
    out = uint32_t(in[pos]) |
          (uint32_t(in[pos + 1]) << 8)  |
          (uint32_t(in[pos + 2]) << 16) |
          (uint32_t(in[pos + 3]) << 24);
    pos += 4;
    return true;
}

}  // namespace

// ── Construction ───────────────────────────────────────────────────────────

SenderChain SenderChain::freshOutbound()
{
    (void)sodium_init();
    Bytes seed(32);
    randombytes_buf(seed.data(), seed.size());
    return fromSeed(seed);
}

SenderChain SenderChain::fromSeed(const Bytes& seed)
{
    SenderChain c;
    if (seed.size() != 32) return c;  // invalid placeholder
    c.m_seed     = seed;
    c.m_chainKey = seed;   // chain_key_0 = seed; no extra KDF needed
    c.m_nextIdx  = 0;
    return c;
}

// ── Core advance step ─────────────────────────────────────────────────────

SenderChain::Bytes SenderChain::advanceStep()
{
    // msg_key       = BLAKE2b-256(key=chain_key, input=0x02)
    // next_chain_key= BLAKE2b-256(key=chain_key, input=0x01)
    Bytes msgKey   = blake2bKeyed32(kTagMsg,   m_chainKey);
    Bytes newChain = blake2bKeyed32(kTagChain, m_chainKey);

    sodium_memzero(m_chainKey.data(), m_chainKey.size());
    m_chainKey = std::move(newChain);
    ++m_nextIdx;
    return msgKey;
}

// ── Outbound ──────────────────────────────────────────────────────────────

std::pair<uint32_t, SenderChain::Bytes> SenderChain::next()
{
    const uint32_t idx = m_nextIdx;
    Bytes msgKey = advanceStep();
    return {idx, std::move(msgKey)};
}

// ── Inbound ───────────────────────────────────────────────────────────────

SenderChain::Bytes SenderChain::messageKeyFor(uint32_t idx)
{
    // 1. Already-derived key — return cached copy without erasing.
    //    Replay defense lives at the envelope-id layer; here we only
    //    care about correct decryption on duplicate / out-of-order
    //    delivery.
    auto it = m_skipped.find(idx);
    if (it != m_skipped.end()) {
        return it->second;
    }

    // 2. Behind current position and not cached — aged out (LRU) or
    //    the chain advanced past it without caching (if someone mixed
    //    next() and messageKeyFor on the same instance — not
    //    supported, but we fail cleanly instead of crashing).
    if (idx < m_nextIdx) {
        return {};
    }

    // 3. Ahead — bound the single-call gap to prevent DoS.  A
    //    malicious sender claiming idx=UINT32_MAX must not force
    //    ~4 billion BLAKE2b iterations.
    if (idx - m_nextIdx > kMaxSkipped) {
        return {};
    }

    // 4. Advance up to and including idx, caching each intermediate
    //    key so subsequent messageKeyFor calls at those indices hit
    //    the cache.  The target idx itself is also cached so repeated
    //    lookups at idx are stable.
    while (m_nextIdx <= idx) {
        const uint32_t derivedIdx = m_nextIdx;
        Bytes k = advanceStep();
        m_skipped[derivedIdx] = std::move(k);
        evictOldestIfOverCap();
    }

    // Post-loop invariant: m_nextIdx == idx + 1; m_skipped[idx]
    // exists (just inserted above).
    auto hit = m_skipped.find(idx);
    return (hit != m_skipped.end()) ? hit->second : Bytes{};
}

void SenderChain::clearSkipped()
{
    for (auto& [i, k] : m_skipped) {
        (void)i;
        sodium_memzero(k.data(), k.size());
    }
    m_skipped.clear();
}

void SenderChain::forgetSeed()
{
    if (m_seed.empty()) return;
    sodium_memzero(m_seed.data(), m_seed.size());
    m_seed.clear();
}

void SenderChain::eraseSkipped(uint32_t idx)
{
    auto it = m_skipped.find(idx);
    if (it == m_skipped.end()) return;
    sodium_memzero(it->second.data(), it->second.size());
    m_skipped.erase(it);
}

void SenderChain::evictOldestIfOverCap()
{
    // std::map iterates in ascending key order; begin() is the
    // smallest idx = oldest cached derivation.
    while (m_skipped.size() > kMaxSkipped) {
        auto victim = m_skipped.begin();
        sodium_memzero(victim->second.data(), victim->second.size());
        m_skipped.erase(victim);
    }
}

// ── Persistence ───────────────────────────────────────────────────────────

SenderChain::Bytes SenderChain::serialize() const
{
    Bytes out;
    // Preallocate typical case to avoid repeated grows.
    out.reserve(1 + 32 + 32 + 4 + 4 + m_skipped.size() * 36);

    out.push_back(kVersion);

    if (m_chainKey.size() != 32) {
        // Invalid chain — emit the version byte alone so deserialize
        // returns an invalid placeholder rather than crashing.
        return out;
    }

    // Audit #3 M3: seed may be empty (forgotten post-distribution).
    // In that case we emit 32 zero bytes so the layout is stable;
    // deserialize recognises the all-zero pattern as "forgotten" and
    // leaves m_seed empty rather than treating zeros as a real seed.
    // Cryptographic collision with a real random seed is 2^-256.
    if (m_seed.size() == 32) {
        out.insert(out.end(), m_seed.begin(), m_seed.end());
    } else {
        out.insert(out.end(), 32, uint8_t{0});
    }
    out.insert(out.end(), m_chainKey.begin(), m_chainKey.end());
    writeU32LE(out, m_nextIdx);
    writeU32LE(out, static_cast<uint32_t>(m_skipped.size()));

    for (const auto& [idx, key] : m_skipped) {
        if (key.size() != 32) continue;  // skip corrupted entries
        writeU32LE(out, idx);
        out.insert(out.end(), key.begin(), key.end());
    }

    return out;
}

SenderChain SenderChain::deserialize(const Bytes& blob)
{
    SenderChain invalid;

    // Minimum: version + seed + chainKey + nextIdx + skippedCount.
    if (blob.size() < 1 + 32 + 32 + 4 + 4) return invalid;
    if (blob[0] != kVersion) return invalid;

    size_t pos = 1;

    SenderChain c;
    // Audit #3 M3: an all-zero seed on disk means "forgotten post-
    // distribution" — leave m_seed empty so callers can't re-distribute
    // zeros as a key.  Cryptographic probability of a real random seed
    // colliding with all-zero is 2^-256.
    bool seedIsZero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (blob[pos + i] != 0) { seedIsZero = false; break; }
    }
    if (!seedIsZero) {
        c.m_seed.assign(blob.begin() + pos, blob.begin() + pos + 32);
    }
    pos += 32;
    c.m_chainKey.assign(blob.begin() + pos, blob.begin() + pos + 32);
    pos += 32;

    if (!readU32LE(blob, pos, c.m_nextIdx)) return invalid;

    uint32_t skippedCount = 0;
    if (!readU32LE(blob, pos, skippedCount)) return invalid;

    // Structural check: each entry is idx(4) + key(32) = 36 bytes.
    // Reject blobs that claim more entries than the remaining bytes
    // can encode — prevents allocation amplification from hostile
    // input.
    if (static_cast<uint64_t>(skippedCount) * 36 > blob.size() - pos) {
        return invalid;
    }

    for (uint32_t i = 0; i < skippedCount; ++i) {
        uint32_t idx;
        if (!readU32LE(blob, pos, idx)) return invalid;
        if (pos + 32 > blob.size())     return invalid;
        // Silently skip entries beyond the current cache cap; this
        // can happen if the cap was tightened since the blob was
        // written.  The chain is still usable; we just lost some
        // cached keys.
        if (c.m_skipped.size() < kMaxSkipped) {
            Bytes key(blob.begin() + pos, blob.begin() + pos + 32);
            c.m_skipped[idx] = std::move(key);
        }
        pos += 32;
    }

    return c;
}
