// test_sealed_envelope.cpp — Tier 3 tests for SealedEnvelope.
//
// SealedEnvelope is the sealed-sender layer that hides the sender's identity
// from the relay.  It's built on:
//   - Classical v2 (0x02): X25519 ECDH + XChaCha20-Poly1305
//   - Hybrid    v2 (0x03): X25519 ECDH  ||  ML-KEM-768 encaps → BLAKE2b-256
//
// The properties we most need to protect are:
//   1. Round-trip — the payload comes out unchanged, with the sender's
//      identity visible only to the recipient.
//   2. Tamper rejection — MAC catches any flipped bit.
//   3. Recipient binding — recipientEdPub is in the AAD, so a relay that
//      rewrites the routing header to redirect the envelope fails
//      decryption (the "cross-user re-routing" attack in H1/H2 era).
//   4. envelopeId uniqueness — each seal produces a fresh 16-byte id so
//      replay dedup on the receiver side actually distinguishes envelopes.
//   5. Relay wrap/unwrap round-trip with proper padding buckets.
//
// Test identities use libsodium directly (crypto_sign_keypair) rather than
// bootstrapping a CryptoEngine for every test — that would add ~2.6s of
// Argon2 work per case.  SealedEnvelope itself doesn't care where the keys
// come from, only that they're valid Ed25519/X25519/ML-KEM buffers.

#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct EdKey { Bytes pub, priv; };
struct CurveKey { Bytes pub, priv; };

EdKey makeEd() {
    EdKey k;
    k.pub.resize(crypto_sign_PUBLICKEYBYTES);   // 32
    k.priv.resize(crypto_sign_SECRETKEYBYTES);  // 64
    crypto_sign_keypair(k.pub.data(), k.priv.data());
    return k;
}

CurveKey makeCurve() {
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    return {pub, priv};
}

Bytes bytesOf(const char* s) {
    const size_t n = std::strlen(s);
    return Bytes(reinterpret_cast<const uint8_t*>(s),
                 reinterpret_cast<const uint8_t*>(s) + n);
}

// Global sodium_init for the binary.
class Bootstrap : public ::testing::Environment {
public:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};
::testing::Environment* const kBootstrap =
    ::testing::AddGlobalTestEnvironment(new Bootstrap);

}  // namespace

// ── 1. Classical round-trip (v2, no PQ) ───────────────────────────────────

TEST(SealedEnvelope, ClassicalRoundTrip) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();

    const Bytes inner = bytesOf("inner ratchet ciphertext (opaque to envelope)");

    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv, inner);
    ASSERT_FALSE(sealed.empty());
    EXPECT_EQ(sealed[0], 0x02) << "classical envelopes must carry the 0x02 version byte";

    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipient.pub, sealed);
    EXPECT_TRUE(r.valid);
    EXPECT_EQ(r.senderEdPub, sender.pub);
    EXPECT_EQ(r.innerPayload, inner);
    EXPECT_EQ(r.envelopeId.size(), 16u);
}

// ── 2. Hybrid (classical ECDH + ML-KEM-768) round-trip ────────────────────

TEST(SealedEnvelope, HybridPqRoundTrip) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();
    auto [kemPub, kemPriv]   = CryptoEngine::generateKemKeypair();

    const Bytes inner = bytesOf("hybrid-pq payload");
    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv, inner, kemPub);
    ASSERT_FALSE(sealed.empty());
    EXPECT_EQ(sealed[0], 0x03) << "hybrid envelopes must carry the 0x03 version byte";

    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipient.pub, sealed, kemPriv);
    EXPECT_TRUE(r.valid);
    EXPECT_EQ(r.innerPayload, inner);
    EXPECT_EQ(r.senderEdPub, sender.pub);
}

// ── 3. Hybrid envelope cannot be unsealed without the KEM private key ─────
// Passing an empty recipientKemPriv to unseal() on a v0x03 envelope must
// fail cleanly (valid=false), not crash or silently fall back to classical.

TEST(SealedEnvelope, HybridRequiresKemPrivateKey) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();
    auto [kemPub, kemPriv]   = CryptoEngine::generateKemKeypair();

    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv,
        bytesOf("inner"), kemPub);
    ASSERT_FALSE(sealed.empty());

    // No KEM priv key supplied.
    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipient.pub, sealed);
    EXPECT_FALSE(r.valid);
}

// ── 4. Tampered ciphertext is rejected by the AEAD MAC ────────────────────

TEST(SealedEnvelope, TamperedCiphertextRejected) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();

    Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv,
        bytesOf("payload"));
    ASSERT_FALSE(sealed.empty());

    // Flip a bit past the version + ephPub(32) header, inside the AEAD body.
    const size_t target = 1 + 32 + 8;
    ASSERT_LT(target, sealed.size());
    sealed[target] ^= 0x01;

    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipient.pub, sealed);
    EXPECT_FALSE(r.valid) << "AEAD should reject tampered ciphertext";
}

// ── 5. Recipient binding: a rerouted envelope fails decryption ────────────
// The sealed envelope's AEAD binds the recipient's Ed25519 pub into AAD so
// a malicious relay that swaps the routing header to target a different
// recipient trips an authentication failure.  This is the exact attack the
// H1/H2 cycle defended against.

TEST(SealedEnvelope, WrongRecipientBindingRejected) {
    const EdKey    sender    = makeEd();
    const EdKey    recipientA = makeEd();
    const EdKey    recipientB = makeEd();  // a different recipient
    const CurveKey recipCurv = makeCurve();

    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipientA.pub, sender.pub, sender.priv,
        bytesOf("to-A-only"));
    ASSERT_FALSE(sealed.empty());

    // Hand the sealed bytes to the unseal path but with recipientB's edPub
    // in the AAD — simulating a relay swapping the routing header.
    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipientB.pub, sealed);
    EXPECT_FALSE(r.valid) << "recipient binding in AAD must prevent re-routing";
}

// ── 6. Wrong curve private key cannot unseal ──────────────────────────────
// A different X25519 private key produces a different ECDH shared secret,
// which in turn fails the AEAD tag check.

TEST(SealedEnvelope, WrongCurvePrivateKeyRejected) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();
    const CurveKey attackerCurv = makeCurve();  // unrelated keypair

    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv,
        bytesOf("secret"));
    ASSERT_FALSE(sealed.empty());

    const UnsealResult r = SealedEnvelope::unseal(
        attackerCurv.priv, recipient.pub, sealed);
    EXPECT_FALSE(r.valid);
}

// ── 7. Each seal generates a fresh envelopeId (replay dedup contract) ─────
// The receiver-side replay cache keys on envelopeId.  If two seals of the
// same payload happened to produce the same id, the second would be dropped
// as a replay — silently losing legitimate messages.

TEST(SealedEnvelope, EnvelopeIdsAreUnique) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();

    const Bytes inner = bytesOf("same payload twice");
    const Bytes s1 = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv, inner);
    const Bytes s2 = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv, inner);

    const UnsealResult r1 = SealedEnvelope::unseal(recipCurv.priv, recipient.pub, s1);
    const UnsealResult r2 = SealedEnvelope::unseal(recipCurv.priv, recipient.pub, s2);
    ASSERT_TRUE(r1.valid);
    ASSERT_TRUE(r2.valid);
    ASSERT_EQ(r1.envelopeId.size(), 16u);
    ASSERT_EQ(r2.envelopeId.size(), 16u);
    EXPECT_NE(r1.envelopeId, r2.envelopeId)
        << "envelopeIds must be unique — if they collide, the replay cache drops real messages";
}

// ── 8. Short / malformed inputs are rejected, not crashed on ──────────────
// A hostile relay could hand us arbitrarily short bytes; unseal must return
// invalid without reading past the buffer.

TEST(SealedEnvelope, MalformedInputRejected) {
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();

    for (size_t n : {size_t(0), size_t(1), size_t(10), size_t(32)}) {
        const Bytes bogus(n, 0x02);  // claim classical version
        const UnsealResult r = SealedEnvelope::unseal(
            recipCurv.priv, recipient.pub, bogus);
        EXPECT_FALSE(r.valid) << "len=" << n;
    }

    // An unknown version byte must fail too.
    Bytes unknownVersion(128, 0x00);
    unknownVersion[0] = 0xFE;
    const UnsealResult r = SealedEnvelope::unseal(
        recipCurv.priv, recipient.pub, unknownVersion);
    EXPECT_FALSE(r.valid);
}

// ── 9. wrapForRelay → unwrapFromRelay round-trip ──────────────────────────
// wrapForRelay prepends a routing header and pads to a bucket size;
// unwrapFromRelay strips both and recovers the original sealed bytes.

TEST(SealedEnvelope, RelayWrapUnwrapRoundTrip) {
    const EdKey    sender    = makeEd();
    const EdKey    recipient = makeEd();
    const CurveKey recipCurv = makeCurve();

    const Bytes sealed = SealedEnvelope::seal(
        recipCurv.pub, recipient.pub, sender.pub, sender.priv,
        bytesOf("routed payload"));
    ASSERT_FALSE(sealed.empty());

    const Bytes wrapped = SealedEnvelope::wrapForRelay(recipient.pub, sealed);
    ASSERT_GT(wrapped.size(), sealed.size()) << "wrap should add header + padding";
    EXPECT_EQ(wrapped[0], 0x01) << "wrapped relay envelopes start with 0x01";

    Bytes extractedRecip;
    const Bytes roundTripped = SealedEnvelope::unwrapFromRelay(wrapped, &extractedRecip);
    EXPECT_EQ(roundTripped, sealed);
    EXPECT_EQ(extractedRecip, recipient.pub);
}

// ── 10. unwrapFromRelay rejects a malformed header ────────────────────────

TEST(SealedEnvelope, UnwrapFromRelayRejectsMalformed) {
    // Too short to contain 1 + 32 + 4 header.
    EXPECT_TRUE(SealedEnvelope::unwrapFromRelay(Bytes(10, 0x01)).empty());

    // Wrong version byte.
    Bytes badVersion(1 + 32 + 4 + 16, 0x00);
    badVersion[0] = 0x99;
    EXPECT_TRUE(SealedEnvelope::unwrapFromRelay(badVersion).empty());

    // Claimed inner length exceeds the buffer.
    Bytes tooLong(1 + 32 + 4 + 16, 0x00);
    tooLong[0] = 0x01;
    // innerLen at bytes [33..37] big-endian = 0xFFFFFFFF
    tooLong[33] = 0xFF; tooLong[34] = 0xFF; tooLong[35] = 0xFF; tooLong[36] = 0xFF;
    EXPECT_TRUE(SealedEnvelope::unwrapFromRelay(tooLong).empty());
}
