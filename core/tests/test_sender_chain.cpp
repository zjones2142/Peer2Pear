// test_sender_chain.cpp — tests for SenderChain.
//
// SenderChain is the symmetric group-message ratchet backing the
// sender-keys group path.  It's a pure primitive — no I/O, no session
// dependencies — so the tests stay tight and cover the invariants that
// downstream GroupProtocol code will rely on:
//
//   - Determinism: sender and receiver with the same seed derive the
//     same keys at the same indices
//   - Chain advance: next() produces strictly monotonic, unique keys
//   - Out-of-order support: messageKeyFor caches keys as it advances
//   - DoS guard: per-call gap cap at kMaxSkipped
//   - LRU eviction: cache never grows past kMaxSkipped
//   - Persistence round-trip: serialize/deserialize preserve state
//   - Structural robustness: hostile blobs produce invalid chains,
//     not crashes
//   - AEAD composition: a chain-derived key can actually encrypt +
//     authenticate with XChaCha20-Poly1305 + AAD binding
//
// No fixture needed — the primitive doesn't carry any expensive setup.

#include "SenderChain.hpp"

#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

using Bytes = SenderChain::Bytes;

// Helper: two chains share deterministic output if given the same seed.
// Returns the key at idx from a fresh inbound chain rooted at `seed`.
Bytes keyAt(const Bytes& seed, uint32_t idx) {
    SenderChain c = SenderChain::fromSeed(seed);
    return c.messageKeyFor(idx);
}

// Hex-string → byte vector for baking known-answer constants into tests
// without a libsodium dependency path in the test itself.
Bytes fromHex(const std::string& hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace

// ── 1. Construction ──────────────────────────────────────────────────────

TEST(SenderChain, FreshOutboundProduces32ByteSeed) {
    SenderChain c = SenderChain::freshOutbound();
    EXPECT_TRUE(c.isValid());
    EXPECT_EQ(c.seed().size(), 32U);
    EXPECT_EQ(c.nextIdx(), 0U);
}

TEST(SenderChain, FreshOutboundSeedsAreUnique) {
    // 32 bytes of randombytes_buf output colliding is astronomically
    // unlikely; a collision here means randombytes_buf is broken.
    SenderChain a = SenderChain::freshOutbound();
    SenderChain b = SenderChain::freshOutbound();
    EXPECT_NE(a.seed(), b.seed());
}

TEST(SenderChain, FromSeedRejectsWrongSize) {
    EXPECT_FALSE(SenderChain::fromSeed(Bytes{}).isValid());
    EXPECT_FALSE(SenderChain::fromSeed(Bytes(16, 0x11)).isValid());
    EXPECT_FALSE(SenderChain::fromSeed(Bytes(64, 0x22)).isValid());
    EXPECT_TRUE(SenderChain::fromSeed(Bytes(32, 0x33)).isValid());
}

TEST(SenderChain, DefaultConstructedIsInvalid) {
    SenderChain c;
    EXPECT_FALSE(c.isValid());
    EXPECT_EQ(c.seed().size(), 0U);
    EXPECT_EQ(c.nextIdx(), 0U);
}

// ── 2. Determinism across parties ───────────────────────────────────────

TEST(SenderChain, SameSeedSameKeysAtSameIdx) {
    // The core correctness invariant: Alice's next() at iteration N
    // and Bob's messageKeyFor(N) with the same seed must produce the
    // identical 32-byte key, otherwise AEAD round-trip fails.
    const Bytes seed(32, 0xA5);
    SenderChain alice = SenderChain::fromSeed(seed);
    SenderChain bob   = SenderChain::fromSeed(seed);

    for (uint32_t i = 0; i < 8; ++i) {
        auto [idx, aliceKey] = alice.next();
        Bytes bobKey         = bob.messageKeyFor(idx);
        EXPECT_EQ(idx, i);
        EXPECT_EQ(aliceKey.size(), 32U);
        EXPECT_EQ(aliceKey, bobKey) << "key mismatch at idx " << i;
    }
}

TEST(SenderChain, DifferentSeedsProduceDifferentKeys) {
    const Bytes seedA(32, 0x11);
    Bytes seedB(32, 0x11);
    seedB[0] = 0x12;  // flip one bit

    for (uint32_t i = 0; i < 5; ++i) {
        Bytes keyA = keyAt(seedA, i);
        Bytes keyB = keyAt(seedB, i);
        EXPECT_EQ(keyA.size(), 32U);
        EXPECT_EQ(keyB.size(), 32U);
        EXPECT_NE(keyA, keyB) << "cross-seed collision at idx " << i;
    }
}

// ── 3. Chain advance + uniqueness ───────────────────────────────────────

TEST(SenderChain, SequentialNextYieldsMonotonicUniqueKeys) {
    SenderChain c = SenderChain::freshOutbound();
    std::set<Bytes> seen;
    uint32_t expected = 0;
    for (int i = 0; i < 32; ++i) {
        auto [idx, key] = c.next();
        EXPECT_EQ(idx, expected++);
        EXPECT_EQ(key.size(), 32U);
        EXPECT_TRUE(seen.insert(key).second) << "key collision at idx " << idx;
    }
    EXPECT_EQ(c.nextIdx(), 32U);
}

TEST(SenderChain, MessageKeyDomainSeparatedFromChainKey) {
    // If the KDF tags collide (message-key tag == chain-key tag), then
    // the chain's next chain_key would equal its current msg_key.
    // Observable consequence: two consecutive keys would be identical.
    SenderChain c = SenderChain::freshOutbound();
    auto [_, k0] = c.next();
    auto [__, k1] = c.next();
    EXPECT_NE(k0, k1);
    (void)_; (void)__;
}

// ── 4. Out-of-order delivery via messageKeyFor ──────────────────────────

TEST(SenderChain, MessageKeyForCachesAheadDerivations) {
    const Bytes seed(32, 0x77);
    SenderChain chain = SenderChain::fromSeed(seed);

    // Jump ahead to idx 5.  Chain should cache keys for 0..4 along
    // the way and also make key 5 retrievable.
    Bytes key5 = chain.messageKeyFor(5);
    EXPECT_EQ(key5.size(), 32U);

    // Reference: re-derive keys 0..5 from a sequential chain.
    SenderChain ref = SenderChain::fromSeed(seed);
    for (uint32_t i = 0; i <= 5; ++i) {
        auto [idx, refKey] = ref.next();
        Bytes fetched = chain.messageKeyFor(idx);
        EXPECT_EQ(fetched, refKey) << "cached key mismatch at idx " << idx;
    }
}

TEST(SenderChain, RepeatedMessageKeyForReturnsCachedValue) {
    SenderChain chain = SenderChain::fromSeed(Bytes(32, 0x42));
    Bytes first  = chain.messageKeyFor(10);
    Bytes second = chain.messageKeyFor(10);
    Bytes third  = chain.messageKeyFor(10);
    EXPECT_EQ(first.size(), 32U);
    EXPECT_EQ(first, second);
    EXPECT_EQ(second, third);
}

TEST(SenderChain, BehindCurrentPositionWithoutCacheReturnsEmpty) {
    // next() advances without caching.  A subsequent messageKeyFor at
    // the already-advanced idx has no cached entry to return and must
    // fail cleanly rather than re-derive.
    SenderChain c = SenderChain::freshOutbound();
    (void)c.next();      // idx 0 consumed, not cached
    (void)c.next();      // idx 1 consumed, not cached
    EXPECT_TRUE(c.messageKeyFor(0).empty());
    EXPECT_TRUE(c.messageKeyFor(1).empty());
}

// ── 5. DoS guard + LRU eviction ─────────────────────────────────────────

TEST(SenderChain, MessageKeyForRejectsExcessiveForwardGap) {
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x55));
    // kMaxSkipped + 1 is past the single-call cap; must fail cleanly.
    Bytes out = c.messageKeyFor(SenderChain::kMaxSkipped + 1);
    EXPECT_TRUE(out.empty());
    // Chain must not have advanced — caller's next legitimate message
    // at any sane idx should still work.
    EXPECT_EQ(c.nextIdx(), 0U);
    Bytes ok = c.messageKeyFor(0);
    EXPECT_EQ(ok.size(), 32U);
}

TEST(SenderChain, CacheNeverExceedsMaxSkippedViaSuccessiveCalls) {
    // Build up cached entries across several calls — each within the
    // per-call gap limit but cumulatively forcing eviction.  Verify
    // the earliest-indexed keys age out.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x88));

    // Derive keys at 0..1999 (fills cache exactly to kMaxSkipped).
    Bytes k1999 = c.messageKeyFor(1999);
    EXPECT_EQ(k1999.size(), 32U);
    EXPECT_EQ(c.messageKeyFor(0).size(), 32U);  // still cached

    // Push one more — must evict the oldest (idx=0) to stay within cap.
    Bytes k2000 = c.messageKeyFor(2000);
    EXPECT_EQ(k2000.size(), 32U);
    EXPECT_TRUE(c.messageKeyFor(0).empty()) << "idx=0 should have been evicted";
    EXPECT_EQ(c.messageKeyFor(1).size(), 32U);  // next-oldest still cached
}

// Audit #3 M3: forgetSeed() drops the ability to re-derive message
// keys from idx 0 without breaking ongoing decryption.  The chain
// remains valid (isValid() still true) and messageKeyFor continues
// to work for forward messages — only the seed fan-out material is
// gone.  A serialize+deserialize round-trip preserves the forgotten
// state so a restart doesn't resurrect the seed.
TEST(SenderChain, ForgetSeedRetainsDecryptButDropsSeedAccess) {
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x55));
    const Bytes seedBefore = c.seed();
    ASSERT_EQ(seedBefore.size(), 32U);
    ASSERT_TRUE(c.isValid());

    // Advance a couple of messages, then forget the seed.
    (void)c.messageKeyFor(0);
    (void)c.messageKeyFor(1);
    c.forgetSeed();

    EXPECT_TRUE(c.isValid()) << "chain still valid — chainKey intact";
    EXPECT_EQ(c.seed().size(), 0U) << "seed should have been zeroed/cleared";

    // Forward decryption still works.
    Bytes k2 = c.messageKeyFor(2);
    EXPECT_EQ(k2.size(), 32U);

    // Serialize + deserialize preserves the "forgotten" state.
    Bytes blob = c.serialize();
    SenderChain restored = SenderChain::deserialize(blob);
    ASSERT_TRUE(restored.isValid());
    EXPECT_EQ(restored.seed().size(), 0U)
        << "deserialize should recognise all-zero seed as forgotten";

    // And the restored chain can still decrypt forward.
    Bytes k3restored = restored.messageKeyFor(3);
    EXPECT_EQ(k3restored.size(), 32U);
}

// forgetSeed is idempotent — calling twice is a no-op.
TEST(SenderChain, ForgetSeedIdempotent) {
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x77));
    c.forgetSeed();
    c.forgetSeed();
    EXPECT_EQ(c.seed().size(), 0U);
    EXPECT_TRUE(c.isValid());
}

// Audit #3 H3: explicit single-index erase (caller-driven forward
// secrecy).  GroupProtocol calls this after a successful AEAD verify
// at idx so the message key for an already-delivered envelope can't
// be recovered from a later in-memory or on-disk compromise.
TEST(SenderChain, EraseSkippedRemovesOnlyTheNamedIdx) {
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x77));
    // messageKeyFor(5) caches 0..5 then advances chain to nextIdx=6.
    Bytes k5 = c.messageKeyFor(5);
    ASSERT_EQ(k5.size(), 32U);
    ASSERT_EQ(c.messageKeyFor(3).size(), 32U) << "setup: 3 should be cached";

    c.eraseSkipped(3);

    // 3 is gone; siblings remain.
    EXPECT_TRUE(c.messageKeyFor(3).empty());
    EXPECT_EQ(c.messageKeyFor(0).size(), 32U);
    EXPECT_EQ(c.messageKeyFor(4).size(), 32U);

    // No-op on idx that's not cached (already-erased / never-cached).
    c.eraseSkipped(3);    // already gone
    c.eraseSkipped(999);  // never derived
    EXPECT_EQ(c.nextIdx(), 6U) << "eraseSkipped must not advance chain";
}

TEST(SenderChain, ClearSkippedDropsAllCachedKeys) {
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x99));
    (void)c.messageKeyFor(5);  // caches 0..5
    EXPECT_EQ(c.messageKeyFor(3).size(), 32U);

    c.clearSkipped();

    EXPECT_TRUE(c.messageKeyFor(3).empty());
    EXPECT_TRUE(c.messageKeyFor(0).empty());
    // Chain state itself (nextIdx, chainKey) is untouched.
    EXPECT_EQ(c.nextIdx(), 6U);
}

// ── 6. Persistence round-trip ──────────────────────────────────────────

TEST(SenderChain, SerializeDeserializeRoundTrip) {
    const Bytes seed(32, 0xCC);
    SenderChain orig = SenderChain::fromSeed(seed);

    // Advance + cache some keys so we exercise the skipped-table path.
    (void)orig.messageKeyFor(12);  // caches 0..12
    auto [idx, key13] = orig.next();
    EXPECT_EQ(idx, 13U);

    Bytes blob = orig.serialize();
    SenderChain restored = SenderChain::deserialize(blob);

    ASSERT_TRUE(restored.isValid());
    EXPECT_EQ(restored.seed(),    orig.seed());
    EXPECT_EQ(restored.nextIdx(), orig.nextIdx());

    // A previously-cached idx should still be retrievable.
    Bytes origK5     = orig.messageKeyFor(5);
    Bytes restoredK5 = restored.messageKeyFor(5);
    EXPECT_EQ(origK5, restoredK5);

    // Advancing past the restored state produces the same keys the
    // original would have.
    auto [idxA, keyA] = orig.next();
    auto [idxB, keyB] = restored.next();
    EXPECT_EQ(idxA, idxB);
    EXPECT_EQ(keyA, keyB);
}

TEST(SenderChain, DeserializeRejectsMalformedBlobs) {
    // Empty.
    EXPECT_FALSE(SenderChain::deserialize(Bytes{}).isValid());
    // Wrong version tag.
    Bytes badVer(1 + 32 + 32 + 4 + 4, 0x00);
    badVer[0] = 0xFF;
    EXPECT_FALSE(SenderChain::deserialize(badVer).isValid());
    // Truncated mid-skipped-entry.
    SenderChain src = SenderChain::fromSeed(Bytes(32, 0xAA));
    (void)src.messageKeyFor(3);
    Bytes truncated = src.serialize();
    truncated.resize(truncated.size() - 5);
    EXPECT_FALSE(SenderChain::deserialize(truncated).isValid());
    // Claimed-count lies — says 1000 entries in a 100-byte blob.
    Bytes liar(1 + 32 + 32 + 4 + 4, 0x00);
    liar[0] = SenderChain::kVersion;
    // Write skippedCount = 1000 at offset 1+32+32+4.
    const size_t countOff = 1 + 32 + 32 + 4;
    liar[countOff + 0] = 0xE8;  // 1000 = 0x03E8
    liar[countOff + 1] = 0x03;
    EXPECT_FALSE(SenderChain::deserialize(liar).isValid());
}

// ── 7. AEAD composition — the real-world usage pattern ─────────────────

TEST(SenderChain, ChainKeyRoundTripsXChaChaPoly1305) {
    CryptoEngine crypto;   // no ensureIdentity needed — aeadEncrypt/Decrypt
                            // are pure functions of key + plaintext + aad.

    const Bytes seed(32, 0xDE);
    SenderChain alice = SenderChain::fromSeed(seed);
    SenderChain bob   = SenderChain::fromSeed(seed);

    const std::string fromId = "alice-peer-id";
    const std::string gid    = "group-abc-123";
    const uint64_t    epoch  = 1;

    auto [idx, aliceKey] = alice.next();
    ASSERT_EQ(aliceKey.size(), 32U);

    // AAD binds (from || gid || epoch || idx) — matches the
    // wire-format binding GroupProtocol uses on the send path.
    Bytes aad;
    aad.insert(aad.end(), fromId.begin(), fromId.end());
    aad.insert(aad.end(), gid.begin(),    gid.end());
    for (int i = 0; i < 8; ++i)
        aad.push_back(static_cast<uint8_t>((epoch >> (8 * i)) & 0xFF));
    for (int i = 0; i < 4; ++i)
        aad.push_back(static_cast<uint8_t>((idx >> (8 * i)) & 0xFF));

    const std::string plaintext = "hello group chat";
    Bytes pt(plaintext.begin(), plaintext.end());

    Bytes ct = crypto.aeadEncrypt(aliceKey, pt, aad);
    ASSERT_FALSE(ct.empty());

    Bytes bobKey = bob.messageKeyFor(idx);
    Bytes recovered = crypto.aeadDecrypt(bobKey, ct, aad);
    ASSERT_EQ(recovered.size(), pt.size());
    EXPECT_EQ(recovered, pt);
}

TEST(SenderChain, AadMismatchFailsDecryption) {
    CryptoEngine crypto;
    SenderChain alice = SenderChain::freshOutbound();
    SenderChain bob   = SenderChain::fromSeed(alice.seed());

    auto [idx, key] = alice.next();

    Bytes rightAad = {'g', 'r', 'o', 'u', 'p', '1'};
    Bytes wrongAad = {'g', 'r', 'o', 'u', 'p', '2'};

    Bytes pt = {0xAA, 0xBB, 0xCC};
    Bytes ct = crypto.aeadEncrypt(key, pt, rightAad);
    ASSERT_FALSE(ct.empty());

    Bytes bobKey = bob.messageKeyFor(idx);

    // Correct AAD → decrypts.
    Bytes ok = crypto.aeadDecrypt(bobKey, ct, rightAad);
    EXPECT_EQ(ok, pt);

    // Wrong AAD (e.g., an attacker spoofing epoch or gid in the
    // plaintext fields) → empty, clean failure.
    Bytes fail = crypto.aeadDecrypt(bobKey, ct, wrongAad);
    EXPECT_TRUE(fail.empty());
}

// ── 8. Known-Answer Tests (KAT) — third-party-computed constants ───────
//
// The expected hex values below were produced by Python's hashlib
// (independent of libsodium) with:
//
//   import hashlib
//   chain0 = bytes(32)                               # seed = 32 zero bytes
//   msg0 = hashlib.blake2b(chain0, digest_size=32)
//   msg0.update(bytes([0x02])); msg0 = msg0.hexdigest()
//
//   chain1_h = hashlib.blake2b(chain0, digest_size=32)
//   chain1_h.update(bytes([0x01])); chain1 = bytes.fromhex(chain1_h.hexdigest())
//   msg1 = hashlib.blake2b(chain1, digest_size=32)
//   msg1.update(bytes([0x02])); msg1 = msg1.hexdigest()
//
//   chain2 = blake2b(chain1, 0x01); msg2 = blake2b(chain2, 0x02)
//
// If SenderChain's KDF drifts in any way (different tag bytes, wrong
// primitive, broken libsodium wrapper, wrong output length), these
// constants catch it deterministically.  This is the only test in the
// file that guards against a spec-level error — every other test
// cross-checks SenderChain against itself and would miss a scenario
// where the spec itself silently changes.

TEST(SenderChain, KnownAnswerMsgKeysForZeroSeed) {
    const Bytes zeroSeed(32, 0x00);

    // Python-produced reference values.
    const Bytes expected0 = fromHex(
        "c939156ed07cc220f799e4271ca6a9c98137423de566e7574f3264f182c9c296");
    const Bytes expected1 = fromHex(
        "1d7af196e6ec490a3f5b7e5b1dfcf0fe1e26621664e87d8cc38d53896849c5ea");
    const Bytes expected2 = fromHex(
        "0c29d7f7e0fbce8d67f90c8ca25f6d0ff568fc82d0dc8bb6f537763d71167526");

    ASSERT_EQ(expected0.size(), 32U);
    ASSERT_EQ(expected1.size(), 32U);
    ASSERT_EQ(expected2.size(), 32U);

    SenderChain chain = SenderChain::fromSeed(zeroSeed);
    auto [idx0, key0] = chain.next();
    auto [idx1, key1] = chain.next();
    auto [idx2, key2] = chain.next();

    EXPECT_EQ(idx0, 0U);
    EXPECT_EQ(idx1, 1U);
    EXPECT_EQ(idx2, 2U);
    EXPECT_EQ(key0, expected0) << "KDF drift detected at idx=0 — "
                                 "msg_key does not match reference BLAKE2b";
    EXPECT_EQ(key1, expected1) << "KDF drift detected at idx=1";
    EXPECT_EQ(key2, expected2) << "KDF drift detected at idx=2";
}

TEST(SenderChain, KnownAnswerMessageKeyForMatchesNext) {
    // messageKeyFor(N) on a fresh chain must produce the same bytes
    // as next() called N+1 times on a separate fresh chain.  Pins the
    // out-of-order derivation path against the sequential one.
    const Bytes seed(32, 0x00);
    const Bytes expected2 = fromHex(
        "0c29d7f7e0fbce8d67f90c8ca25f6d0ff568fc82d0dc8bb6f537763d71167526");

    SenderChain chain = SenderChain::fromSeed(seed);
    Bytes got = chain.messageKeyFor(2);
    EXPECT_EQ(got, expected2);
}

// ── 9. Boundary tests — exact cap, zero idx, cumulative gaps ──────────

TEST(SenderChain, MessageKeyForZeroOnFreshChainSucceeds) {
    // The trivial edge case: idx=0 on a brand-new chain.  If there's
    // an off-by-one somewhere (loop condition, cache insertion), this
    // breaks first.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x01));
    Bytes k = c.messageKeyFor(0);
    EXPECT_EQ(k.size(), 32U);
    EXPECT_EQ(c.nextIdx(), 1U);
    // Second fetch returns the cached value.
    EXPECT_EQ(c.messageKeyFor(0), k);
}

TEST(SenderChain, MessageKeyForAtExactCapSucceeds) {
    // idx == kMaxSkipped (not +1) should succeed — we cap at >, not >=.
    // Distinct from MessageKeyForRejectsExcessiveForwardGap which
    // tests kMaxSkipped + 1.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x02));
    Bytes k = c.messageKeyFor(SenderChain::kMaxSkipped);
    EXPECT_EQ(k.size(), 32U);
    EXPECT_EQ(c.nextIdx(), SenderChain::kMaxSkipped + 1);
}

TEST(SenderChain, MessageKeyForCumulativeLargeGapSucceeds) {
    // Two gaps each within per-call cap, total gap > per-call cap.
    // The per-call cap is a DoS guard against a single malicious
    // idx; it's not a total-advance cap, so successive calls that
    // each respect the cap should compose freely.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x03));
    Bytes k1 = c.messageKeyFor(1500);
    ASSERT_EQ(k1.size(), 32U);
    EXPECT_EQ(c.nextIdx(), 1501U);

    // Gap from nextIdx=1501 to 3000 is 1499 — within per-call cap.
    // Total gap from origin is 3000 — significantly over cap.
    Bytes k2 = c.messageKeyFor(3000);
    ASSERT_EQ(k2.size(), 32U);
    EXPECT_EQ(c.nextIdx(), 3001U);

    // Determinism: a parallel chain advanced through the SAME
    // staging (1500, then 3000) arrives at the same key.  Single-
    // shot messageKeyFor(3000) from origin would itself exceed the
    // per-call cap — hence the two-step reference.
    SenderChain ref = SenderChain::fromSeed(Bytes(32, 0x03));
    (void)ref.messageKeyFor(1500);
    EXPECT_EQ(ref.messageKeyFor(3000), k2);
}

TEST(SenderChain, PerCallCapEnforcedEvenOnAdvancedChain) {
    // After the chain advances to an arbitrary nextIdx, the per-call
    // cap must still apply to NEW requests — it's measured against
    // the current nextIdx, not against the origin.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x04));
    Bytes k = c.messageKeyFor(500);  // advances to nextIdx=501
    ASSERT_EQ(k.size(), 32U);
    EXPECT_EQ(c.nextIdx(), 501U);

    // Gap of kMaxSkipped + 1 from current position → strictly over
    // cap → must fail cleanly.
    Bytes fail = c.messageKeyFor(501 + SenderChain::kMaxSkipped + 1);
    EXPECT_TRUE(fail.empty());
    // Chain must not have advanced on failure — per-call cap check
    // happens before any state mutation.
    EXPECT_EQ(c.nextIdx(), 501U);

    // A gap of EXACTLY kMaxSkipped from current position is allowed
    // (the cap is strict `>`, not `>=`).  Verifies the boundary.
    Bytes boundary = c.messageKeyFor(501 + SenderChain::kMaxSkipped);
    EXPECT_EQ(boundary.size(), 32U);
}

// ── 10. Extended out-of-order delivery ─────────────────────────────────

TEST(SenderChain, OutOfOrderReverseDelivery20Messages) {
    // Alice sends 20 messages sequentially.  Bob receives them in
    // strict reverse order — simulates a pathological network where
    // the most recent arrives first.
    const Bytes seed(32, 0x66);

    SenderChain alice = SenderChain::fromSeed(seed);
    std::vector<Bytes> aliceKeys;
    for (int i = 0; i < 20; ++i) {
        auto [idx, k] = alice.next();
        EXPECT_EQ(idx, uint32_t(i));
        aliceKeys.push_back(std::move(k));
    }

    SenderChain bob = SenderChain::fromSeed(seed);
    for (int i = 19; i >= 0; --i) {
        Bytes k = bob.messageKeyFor(uint32_t(i));
        ASSERT_EQ(k.size(), 32U) << "miss at idx " << i;
        EXPECT_EQ(k, aliceKeys[i]) << "mismatch at idx " << i;
    }
}

TEST(SenderChain, InterleavedOutOfOrderDelivery) {
    // Alice sends 10 messages; Bob receives in order [5, 2, 7, 0, 9, 3, 6, 1, 8, 4].
    const Bytes seed(32, 0x77);
    const std::vector<uint32_t> arrivalOrder = {5, 2, 7, 0, 9, 3, 6, 1, 8, 4};

    SenderChain alice = SenderChain::fromSeed(seed);
    std::vector<Bytes> expected;
    for (int i = 0; i < 10; ++i) {
        auto [_, k] = alice.next();
        (void)_;
        expected.push_back(std::move(k));
    }

    SenderChain bob = SenderChain::fromSeed(seed);
    for (uint32_t idx : arrivalOrder) {
        Bytes k = bob.messageKeyFor(idx);
        ASSERT_EQ(k.size(), 32U);
        EXPECT_EQ(k, expected[idx]) << "mismatch at arrival idx " << idx;
    }
}

// ── 11. Extended persistence edge cases ────────────────────────────────

TEST(SenderChain, SerializeEmptyChainRoundTrips) {
    // Brand-new chain, nothing advanced, nothing cached.  Serialize
    // and restore.  Restored chain must behave identically to a fresh
    // one from the same seed.
    const Bytes seed(32, 0xAA);
    SenderChain fresh = SenderChain::fromSeed(seed);
    Bytes blob = fresh.serialize();

    SenderChain restored = SenderChain::deserialize(blob);
    ASSERT_TRUE(restored.isValid());
    EXPECT_EQ(restored.seed(),    seed);
    EXPECT_EQ(restored.nextIdx(), 0U);

    // Parallel-chain sanity: restored and a reference both advance
    // identically.
    SenderChain ref = SenderChain::fromSeed(seed);
    for (int i = 0; i < 5; ++i) {
        auto [idxR, keyR] = restored.next();
        auto [idxRef, keyRef] = ref.next();
        EXPECT_EQ(idxR, idxRef);
        EXPECT_EQ(keyR, keyRef);
    }
}

TEST(SenderChain, SerializeAtCapacityRoundTrips) {
    // Fill the cache to exactly kMaxSkipped entries, serialize,
    // restore.  All cached keys must still be retrievable from the
    // restored instance.
    SenderChain orig = SenderChain::fromSeed(Bytes(32, 0xBB));
    (void)orig.messageKeyFor(SenderChain::kMaxSkipped - 1);  // fills 0..kMax-1

    Bytes blob = orig.serialize();
    SenderChain restored = SenderChain::deserialize(blob);
    ASSERT_TRUE(restored.isValid());

    // Spot-check a few cached indices survived.
    for (uint32_t idx : {0U, 100U, 1000U, SenderChain::kMaxSkipped - 1}) {
        Bytes origK     = orig.messageKeyFor(idx);
        Bytes restoredK = restored.messageKeyFor(idx);
        ASSERT_EQ(origK.size(), 32U);
        EXPECT_EQ(origK, restoredK) << "at idx " << idx;
    }
}

TEST(SenderChain, RestoredChainRoundTripsAead) {
    // The real end-to-end persistence test: serialize a chain that's
    // been used, restore it, and verify the restored chain can
    // produce keys that decrypt messages encrypted with the ORIGINAL
    // chain's keys.  Bytes-equal serialize is necessary; cryptographic
    // equivalence is sufficient.
    CryptoEngine crypto;
    const Bytes seed(32, 0xCC);

    SenderChain alice = SenderChain::fromSeed(seed);
    auto [aliceIdx, aliceKey] = alice.next();

    const Bytes aad = {'g','r','o','u','p'};
    const Bytes pt  = {'s','e','c','r','e','t'};
    Bytes ct = crypto.aeadEncrypt(aliceKey, pt, aad);
    ASSERT_FALSE(ct.empty());

    // Bob's chain persisted before receiving Alice's message.
    SenderChain bob = SenderChain::fromSeed(seed);
    Bytes bobBlob = bob.serialize();

    // App restart — Bob restores from disk.
    SenderChain bobRestored = SenderChain::deserialize(bobBlob);
    ASSERT_TRUE(bobRestored.isValid());

    // Bob decrypts Alice's message using the restored chain.
    Bytes bobKey = bobRestored.messageKeyFor(aliceIdx);
    Bytes recovered = crypto.aeadDecrypt(bobKey, ct, aad);
    EXPECT_EQ(recovered, pt);
}

TEST(SenderChain, InvalidChainSerializesToRejectableBlob) {
    // A default-constructed (invalid) chain produces a blob that
    // deserialize() refuses.  Prevents the "I serialized nothing and
    // got garbage back" footgun.
    SenderChain invalid;
    EXPECT_FALSE(invalid.isValid());

    Bytes blob = invalid.serialize();
    // Blob is at most the version byte — too short for a valid chain.
    EXPECT_LT(blob.size(), 1U + 32 + 32 + 4 + 4);

    SenderChain restored = SenderChain::deserialize(blob);
    EXPECT_FALSE(restored.isValid());
}

TEST(SenderChain, ResumeAfterRestoreMatchesUninterruptedChain) {
    // Two chains start from the same seed.  Chain A runs
    // uninterrupted for 10 steps.  Chain B runs 5 steps, serializes,
    // restores, runs 5 more steps.  Both must produce the same keys
    // at every step.
    const Bytes seed(32, 0xDD);

    SenderChain uninterrupted = SenderChain::fromSeed(seed);
    std::vector<Bytes> keysA;
    for (int i = 0; i < 10; ++i) {
        auto [_, k] = uninterrupted.next();
        (void)_;
        keysA.push_back(std::move(k));
    }

    SenderChain partial = SenderChain::fromSeed(seed);
    std::vector<Bytes> keysB;
    for (int i = 0; i < 5; ++i) {
        auto [_, k] = partial.next();
        (void)_;
        keysB.push_back(std::move(k));
    }

    Bytes blob = partial.serialize();
    SenderChain restored = SenderChain::deserialize(blob);
    ASSERT_TRUE(restored.isValid());

    for (int i = 0; i < 5; ++i) {
        auto [_, k] = restored.next();
        (void)_;
        keysB.push_back(std::move(k));
    }

    ASSERT_EQ(keysA.size(), keysB.size());
    for (size_t i = 0; i < keysA.size(); ++i) {
        EXPECT_EQ(keysA[i], keysB[i]) << "mismatch at idx " << i;
    }
}

// ── 12. AEAD composition — tamper resistance + nonce uniqueness ────────

TEST(SenderChain, CiphertextBitFlipFailsDecryption) {
    // The integrity half of AEAD: flipping any bit in the ciphertext
    // (including the embedded nonce, since aeadEncrypt emits
    // nonce || ciphertext) must cause decryption to fail.
    CryptoEngine crypto;
    SenderChain alice = SenderChain::freshOutbound();
    SenderChain bob   = SenderChain::fromSeed(alice.seed());

    auto [idx, key] = alice.next();
    Bytes bobKey = bob.messageKeyFor(idx);

    const Bytes aad = {'g','i','d'};
    const Bytes pt  = {'h','e','l','l','o'};
    Bytes ct = crypto.aeadEncrypt(key, pt, aad);
    ASSERT_FALSE(ct.empty());

    // Sanity — unmodified decrypts cleanly.
    EXPECT_EQ(crypto.aeadDecrypt(bobKey, ct, aad), pt);

    // Flip one bit in the middle of the ciphertext portion (past
    // the 24-byte XChaCha nonce header).
    ASSERT_GT(ct.size(), 24U + 2);
    Bytes tampered = ct;
    tampered[24 + 1] ^= 0x01;
    EXPECT_TRUE(crypto.aeadDecrypt(bobKey, tampered, aad).empty());

    // Flip a bit in the nonce portion.  Different nonce → different
    // implicit key stream → decrypt fails.
    Bytes nonceTamp = ct;
    nonceTamp[0] ^= 0x80;
    EXPECT_TRUE(crypto.aeadDecrypt(bobKey, nonceTamp, aad).empty());

    // Flip a bit in the tag (last 16 bytes of the Poly1305 output).
    Bytes tagTamp = ct;
    tagTamp[ct.size() - 1] ^= 0x01;
    EXPECT_TRUE(crypto.aeadDecrypt(bobKey, tagTamp, aad).empty());
}

TEST(SenderChain, AeadNoncesDifferPerCallWithSameKey) {
    // aeadEncrypt uses a random nonce per call.  Two encrypts of the
    // same plaintext under the same key + AAD must produce different
    // ciphertexts — otherwise key reuse would leak keystream under
    // attacker-chosen plaintexts.  This is a property of CryptoEngine,
    // but it's specifically load-bearing for sender keys because the
    // same key will never be re-derived, and we rely on the per-call
    // randomness to prevent nonce collisions across parallel calls.
    CryptoEngine crypto;
    SenderChain chain = SenderChain::freshOutbound();
    auto [_, key] = chain.next();
    (void)_;

    const Bytes pt  = {'s','a','m','e'};
    const Bytes aad = {'s','a','m','e'};

    Bytes ct1 = crypto.aeadEncrypt(key, pt, aad);
    Bytes ct2 = crypto.aeadEncrypt(key, pt, aad);
    ASSERT_FALSE(ct1.empty());
    ASSERT_FALSE(ct2.empty());
    EXPECT_NE(ct1, ct2) << "nonce reuse detected — catastrophic for AEAD";

    // Both still decrypt to the same plaintext.
    EXPECT_EQ(crypto.aeadDecrypt(key, ct1, aad), pt);
    EXPECT_EQ(crypto.aeadDecrypt(key, ct2, aad), pt);
}

// ── 13. State invariants ───────────────────────────────────────────────

TEST(SenderChain, SeedUnchangedAcrossAdvances) {
    // The seed is what we distribute; it MUST NOT mutate as the chain
    // advances, or subsequent redistributions would send a different
    // seed than the one we originally committed to.
    const Bytes origSeed(32, 0xEE);
    SenderChain c = SenderChain::fromSeed(origSeed);

    for (int i = 0; i < 100; ++i) (void)c.next();

    EXPECT_EQ(c.seed(), origSeed)
        << "seed mutated by advance — distribution would be inconsistent";
    EXPECT_EQ(c.nextIdx(), 100U);
}

TEST(SenderChain, NextIdxIncrementsMonotonically) {
    // Interleave next() and messageKeyFor(); verify nextIdx never
    // regresses.  Ordering invariant — GroupProtocol's skey_idx in
    // group_msg relies on it.
    SenderChain c = SenderChain::freshOutbound();
    uint32_t lastIdx = c.nextIdx();

    for (int i = 0; i < 5; ++i) {
        (void)c.next();
        EXPECT_GT(c.nextIdx(), lastIdx);
        lastIdx = c.nextIdx();
    }

    (void)c.messageKeyFor(lastIdx + 10);
    EXPECT_GT(c.nextIdx(), lastIdx);
    lastIdx = c.nextIdx();

    // Looking up a cached idx does NOT advance nextIdx.
    (void)c.messageKeyFor(0);  // miss (we advanced past without caching via next())
    EXPECT_EQ(c.nextIdx(), lastIdx);
}

TEST(SenderChain, ClearSkippedLeavesChainStatePristine) {
    // clearSkipped wipes the cache but must not touch the chain key
    // or nextIdx — otherwise subsequent sends would diverge from
    // peers who didn't clear.
    SenderChain c = SenderChain::fromSeed(Bytes(32, 0x71));
    (void)c.messageKeyFor(7);    // advance + cache

    const uint32_t idxBefore = c.nextIdx();
    const Bytes seedBefore   = c.seed();

    c.clearSkipped();

    EXPECT_EQ(c.nextIdx(), idxBefore);
    EXPECT_EQ(c.seed(),    seedBefore);

    // Subsequent next() produces the same key it would have without
    // the clearSkipped call.
    SenderChain ref = SenderChain::fromSeed(Bytes(32, 0x71));
    (void)ref.messageKeyFor(7);

    auto [idxA, keyA] = c.next();
    auto [idxB, keyB] = ref.next();
    EXPECT_EQ(idxA, idxB);
    EXPECT_EQ(keyA, keyB);
}

TEST(SenderChain, DeserializedChainPreservesSkippedKeyBytes) {
    // A cached key that was legitimately derived (via forward-skip)
    // must round-trip through serialize/deserialize with the exact
    // same bytes — not re-derived from the chain key on load, because
    // after deserialize the chain_key has already advanced past those
    // indices.
    SenderChain orig = SenderChain::fromSeed(Bytes(32, 0xF1));
    Bytes key5 = orig.messageKeyFor(5);  // caches 0..5 + advances to 6
    ASSERT_EQ(key5.size(), 32U);

    Bytes blob = orig.serialize();
    SenderChain restored = SenderChain::deserialize(blob);
    ASSERT_TRUE(restored.isValid());
    EXPECT_EQ(restored.nextIdx(), 6U);

    // The cached key at idx=3 (not idx=5, which was the direct
    // lookup) must match what the original chain has cached — it was
    // derived BEFORE the chain_key advanced past it, so re-derivation
    // from post-advance chain_key is impossible.
    Bytes origKey3     = orig.messageKeyFor(3);
    Bytes restoredKey3 = restored.messageKeyFor(3);
    EXPECT_EQ(origKey3, restoredKey3);
}
