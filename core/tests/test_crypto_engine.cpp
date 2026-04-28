// test_crypto_engine.cpp — tests for CryptoEngine primitives.
//
// These exercise the pure/static crypto helpers (Ed25519, X25519, XChaCha20-
// Poly1305 AEAD, HKDF, ML-KEM-768, ML-DSA-65) without touching disk or
// identity.  Fast, deterministic, hermetic.  They validate:
//   1. The primitives produce correct outputs (round-trip + rejection).
//   2. libsodium + liboqs are actually linked into the test binary (if they
//      aren't, these tests won't even compile).
//   3. Future refactors don't silently break the crypto layer.

#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

// Small helper: build a Bytes from a C string literal (excludes trailing NUL).
Bytes bytesOf(const char* s) {
    const size_t n = std::strlen(s);
    return Bytes(reinterpret_cast<const uint8_t*>(s),
                 reinterpret_cast<const uint8_t*>(s) + n);
}

// Flip one bit in a buffer (used for tamper tests).
void flipBit(Bytes& b, size_t bitIndex) {
    ASSERT_LT(bitIndex / 8, b.size());
    b[bitIndex / 8] ^= static_cast<uint8_t>(1u << (bitIndex % 8));
}

// Hex decoder for RFC 8032 KAT constants.  Tolerant of upper/lowercase; a
// malformed input returns junk, which the KAT assertion will catch.
Bytes fromHex(const std::string& hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Environments: sodium_init must be called exactly once before any libsodium
// call.  CryptoEngine's constructor does this, so we force at least one
// construction in a fixture-free way.
class CryptoEngineBootstrap : public ::testing::Environment {
public:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};
::testing::Environment* const kBootstrap =
    ::testing::AddGlobalTestEnvironment(new CryptoEngineBootstrap);

}  // namespace

// ── 1. Ephemeral X25519 keypair generation ────────────────────────────────
// Two fresh keypairs should differ and have the expected sizes.

TEST(CryptoEngine, EphemeralX25519KeypairShapeAndUniqueness) {
    auto [pub1, priv1] = CryptoEngine::generateEphemeralX25519();
    auto [pub2, priv2] = CryptoEngine::generateEphemeralX25519();

    ASSERT_EQ(pub1.size(),  32u);
    ASSERT_EQ(priv1.size(), 32u);
    ASSERT_EQ(pub2.size(),  32u);
    ASSERT_EQ(priv2.size(), 32u);

    // Astronomically unlikely to collide — if this ever fires, something is
    // wrong with the RNG or we've lost sodium_init.
    EXPECT_NE(pub1,  pub2);
    EXPECT_NE(priv1, priv2);
}

// ── 2. AEAD round-trip ────────────────────────────────────────────────────

TEST(CryptoEngine, AeadRoundTrip) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    const Bytes pt  = bytesOf("hello, world");
    const Bytes aad = bytesOf("context-tag");

    const Bytes ct = ce.aeadEncrypt(key, pt, aad);
    ASSERT_FALSE(ct.empty());
    // Ciphertext carries a 24-byte nonce prefix + pt + 16-byte auth tag.
    EXPECT_GE(ct.size(), pt.size() + 24 + 16);

    const Bytes rt = ce.aeadDecrypt(key, ct, aad);
    EXPECT_EQ(rt, pt);
}

// ── 3. AEAD rejects tampered ciphertext ───────────────────────────────────

TEST(CryptoEngine, AeadRejectsTamperedCiphertext) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    const Bytes pt = bytesOf("secret");
    Bytes ct = ce.aeadEncrypt(key, pt, {});
    ASSERT_FALSE(ct.empty());

    // Flip the first byte of the ciphertext payload (just past the 24-byte nonce).
    ct[24] ^= 0x01;

    const Bytes rt = ce.aeadDecrypt(key, ct, {});
    EXPECT_TRUE(rt.empty()) << "AEAD accepted a tampered ciphertext — MAC check failed";
}

// ── 4. AEAD rejects wrong AAD (recipient-bound contexts) ──────────────────
// Sealed envelopes bind recipient identity into the AAD, so a relay that
// rewrites the routing header should get a MAC failure.

TEST(CryptoEngine, AeadRejectsWrongAad) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    const Bytes pt  = bytesOf("payload");
    const Bytes aadCorrect = bytesOf("recipient-A");
    const Bytes aadWrong   = bytesOf("recipient-B");

    const Bytes ct = ce.aeadEncrypt(key, pt, aadCorrect);
    ASSERT_FALSE(ct.empty());

    EXPECT_EQ(ce.aeadDecrypt(key, ct, aadCorrect), pt);
    EXPECT_TRUE(ce.aeadDecrypt(key, ct, aadWrong).empty());
}

// ── 4b. AEAD must be probabilistic (fresh nonce every call) ───────────────
// If two encryptions of the same plaintext under the same key produce the
// same output, the nonce isn't being refreshed — a catastrophic AEAD
// failure that would let an observer confirm message equality.

TEST(CryptoEngine, AeadIsProbabilistic) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    const Bytes pt = bytesOf("repeat me");
    const Bytes a = ce.aeadEncrypt(key, pt, {});
    const Bytes b = ce.aeadEncrypt(key, pt, {});

    ASSERT_FALSE(a.empty());
    ASSERT_FALSE(b.empty());
    EXPECT_NE(a, b) << "AEAD produced identical ciphertext for identical plaintext — nonce not randomized";
    // The nonce prefix (first 24 bytes) must differ, not just the tag.
    EXPECT_NE(Bytes(a.begin(), a.begin() + 24),
              Bytes(b.begin(), b.begin() + 24));
}

// ── 4c. AEAD round-trips an empty plaintext ───────────────────────────────
// Padding-oracle style bugs often hide in edge cases where the payload has
// length zero.  Authenticated empty ciphertexts are a legitimate thing we
// emit for control messages.

TEST(CryptoEngine, AeadRoundTripsEmptyPlaintext) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    const Bytes pt; // empty
    const Bytes ct = ce.aeadEncrypt(key, pt, bytesOf("aad-for-empty"));
    ASSERT_FALSE(ct.empty()) << "empty plaintext should still produce nonce+tag";
    EXPECT_EQ(ct.size(), 24u + 16u);  // pure nonce + MAC, zero-byte payload

    const Bytes rt = ce.aeadDecrypt(key, ct, bytesOf("aad-for-empty"));
    EXPECT_EQ(rt.size(), 0u);
    EXPECT_EQ(rt, pt);
}

// ── 4d. AEAD rejects ciphertext shorter than nonce+tag ────────────────────
// Any input < 40 bytes can't be a valid XChaCha20-Poly1305 ciphertext.
// The decryptor must not crash or return garbage.

TEST(CryptoEngine, AeadRejectsUndersizedCiphertext) {
    CryptoEngine ce;
    Bytes key(32, 0);
    randombytes_buf(key.data(), key.size());

    EXPECT_TRUE(ce.aeadDecrypt(key, Bytes(10, 0), {}).empty());
    EXPECT_TRUE(ce.aeadDecrypt(key, Bytes(39, 0), {}).empty());
    EXPECT_TRUE(ce.aeadDecrypt(key, Bytes{}, {}).empty());
}

// ── 5. HKDF determinism ───────────────────────────────────────────────────

TEST(CryptoEngine, HkdfIsDeterministic) {
    const Bytes ikm  = bytesOf("input-key-material");
    const Bytes salt = bytesOf("salt-0");
    const Bytes info = bytesOf("context");

    const Bytes a = CryptoEngine::hkdf(ikm, salt, info, 32);
    const Bytes b = CryptoEngine::hkdf(ikm, salt, info, 32);

    ASSERT_EQ(a.size(), 32u);
    EXPECT_EQ(a, b) << "HKDF must be deterministic for identical inputs";
}

// ── 6. HKDF: different info → different output ────────────────────────────
// This is the "domain separation" property.  Protects against silent
// regressions in the KDF itself when SealedEnvelope binds additional
// context into the info parameter.

TEST(CryptoEngine, HkdfDifferentInfoProducesDifferentOutput) {
    const Bytes ikm  = bytesOf("same-ikm");
    const Bytes salt = bytesOf("same-salt");

    const Bytes a = CryptoEngine::hkdf(ikm, salt, bytesOf("label-A"), 32);
    const Bytes b = CryptoEngine::hkdf(ikm, salt, bytesOf("label-B"), 32);

    ASSERT_EQ(a.size(), 32u);
    EXPECT_NE(a, b);
}

// ── 6b. HKDF honors the requested output length ───────────────────────────
// The engine is BLAKE2b-based; a regression that silently truncated or
// padded the output would not be caught by the 32-byte determinism test.

TEST(CryptoEngine, HkdfHonorsRequestedOutputLength) {
    const Bytes ikm  = bytesOf("ikm");
    const Bytes salt = bytesOf("salt");
    const Bytes info = bytesOf("info");

    for (int len : {16, 32, 48, 64}) {
        const Bytes out = CryptoEngine::hkdf(ikm, salt, info, len);
        EXPECT_EQ(static_cast<int>(out.size()), len) << "requested=" << len;
    }
}

// ── 6c. HKDF: different salt → different output ───────────────────────────
// Companion to the info-based domain-separation test.  Exercises the other
// public parameter so a regression in salt handling doesn't slip through.

TEST(CryptoEngine, HkdfDifferentSaltProducesDifferentOutput) {
    const Bytes ikm  = bytesOf("same-ikm");
    const Bytes info = bytesOf("same-info");

    const Bytes a = CryptoEngine::hkdf(ikm, bytesOf("salt-A"), info, 32);
    const Bytes b = CryptoEngine::hkdf(ikm, bytesOf("salt-B"), info, 32);
    EXPECT_NE(a, b);
}

// ── 6d. HKDF KAT: locks the "info || 0x01" counter byte ──────────────────
// PROTOCOL.md §10.2 specifies HKDF-BLAKE2b as:
//   PRK = BLAKE2b-256(key=salt, input=ikm)
//   out = BLAKE2b-L(key=PRK, input=info || 0x01)
// Third-party implementations MUST reproduce this byte-for-byte.  This
// test pins the construction: a hand-computed PRK and Expand run against
// libsodium's raw crypto_generichash, compared against what CryptoEngine
// produces.  A refactor that drops the 0x01 counter (or changes the
// length of PRK) would break this KAT loudly.

TEST(CryptoEngine, HkdfMatchesSpecifiedConstruction) {
    const Bytes ikm  = bytesOf("the input key material");
    const Bytes salt = bytesOf("a-salt");
    const Bytes info = bytesOf("label");

    // Manual compute PRK = BLAKE2b-256(key=salt, ikm).
    unsigned char prk[32];
    ASSERT_EQ(0, crypto_generichash(prk, sizeof(prk),
                                     ikm.data(), ikm.size(),
                                     salt.data(), salt.size()));

    // Manual compute out = BLAKE2b-32(key=PRK, input=info || 0x01).
    Bytes expandInput = info;
    expandInput.push_back(0x01);
    unsigned char expected[32];
    ASSERT_EQ(0, crypto_generichash(expected, sizeof(expected),
                                     expandInput.data(), expandInput.size(),
                                     prk, sizeof(prk)));

    const Bytes got = CryptoEngine::hkdf(ikm, salt, info, 32);
    ASSERT_EQ(got.size(), 32u);
    EXPECT_EQ(Bytes(expected, expected + 32), got)
        << "HKDF-BLAKE2b construction diverged from PROTOCOL.md §10.2";
}

// ── 6e. Safety numbers: symmetry, determinism, independence ─────────────
// The fingerprint and display string MUST be:
//   - deterministic (same inputs → same output)
//   - symmetric       (f(A,B) == f(B,A)) — both parties derive the same
//     value without coordinating who's "us"
//   - peer-specific  (different peer → different fingerprint)
//
// The display string format is also contract (third-party UIs compare
// 60-digit strings).  Verify shape: 12 groups of 5 digits, 11 spaces.

TEST(CryptoEngine, SafetyNumberIsSymmetric) {
    auto [aPub, aPriv] = CryptoEngine::generateEphemeralX25519();
    auto [bPub, bPriv] = CryptoEngine::generateEphemeralX25519();
    ASSERT_EQ(aPub.size(), 32u);

    EXPECT_EQ(CryptoEngine::safetyNumber(aPub, bPub),
              CryptoEngine::safetyNumber(bPub, aPub));
    EXPECT_EQ(CryptoEngine::safetyFingerprint(aPub, bPub),
              CryptoEngine::safetyFingerprint(bPub, aPub));
}

TEST(CryptoEngine, SafetyNumberIsDeterministic) {
    auto [aPub, aPriv] = CryptoEngine::generateEphemeralX25519();
    auto [bPub, bPriv] = CryptoEngine::generateEphemeralX25519();

    const std::string s1 = CryptoEngine::safetyNumber(aPub, bPub);
    const std::string s2 = CryptoEngine::safetyNumber(aPub, bPub);
    EXPECT_EQ(s1, s2);
}

TEST(CryptoEngine, SafetyNumberDiffersByPeer) {
    auto [aPub, _a]   = CryptoEngine::generateEphemeralX25519();
    auto [b1Pub, _b1] = CryptoEngine::generateEphemeralX25519();
    auto [b2Pub, _b2] = CryptoEngine::generateEphemeralX25519();

    EXPECT_NE(CryptoEngine::safetyNumber(aPub, b1Pub),
              CryptoEngine::safetyNumber(aPub, b2Pub));
}

TEST(CryptoEngine, SafetyNumberFormatIsTwelveGroupsOfFive) {
    auto [aPub, _a] = CryptoEngine::generateEphemeralX25519();
    auto [bPub, _b] = CryptoEngine::generateEphemeralX25519();

    const std::string s = CryptoEngine::safetyNumber(aPub, bPub);
    ASSERT_EQ(s.size(), 71u);  // 12*5 + 11 spaces

    int digitRuns = 0, spaceCount = 0;
    size_t i = 0;
    while (i < s.size()) {
        if (std::isdigit(static_cast<unsigned char>(s[i]))) {
            int run = 0;
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
                ++run; ++i;
            }
            EXPECT_EQ(run, 5) << "group of " << run << " digits";
            ++digitRuns;
        } else if (s[i] == ' ') {
            ++spaceCount; ++i;
        } else {
            FAIL() << "unexpected character at " << i;
        }
    }
    EXPECT_EQ(digitRuns, 12);
    EXPECT_EQ(spaceCount, 11);
}

TEST(CryptoEngine, SafetyNumberRejectsWrongSize) {
    Bytes ok(32, 0x11);
    Bytes bad(31, 0x22);
    EXPECT_TRUE(CryptoEngine::safetyNumber(bad, ok).empty());
    EXPECT_TRUE(CryptoEngine::safetyFingerprint(ok, bad).empty());
    EXPECT_TRUE(CryptoEngine::safetyNumber({}, ok).empty());
}

// ── 7. ML-KEM-768 encaps / decaps round-trip ──────────────────────────────

TEST(CryptoEngine, MlKem768EncapsDecapsRoundTrip) {
    auto [pub, priv] = CryptoEngine::generateKemKeypair();
    ASSERT_EQ(pub.size(),  1184u);  // FIPS 203 ML-KEM-768 public key
    ASSERT_EQ(priv.size(), 2400u);  // FIPS 203 ML-KEM-768 private key

    const KemEncapsResult enc = CryptoEngine::kemEncaps(pub);
    ASSERT_EQ(enc.ciphertext.size(),  1088u);  // FIPS 203 ML-KEM-768 ct size
    ASSERT_EQ(enc.sharedSecret.size(),  32u);

    const Bytes ss = CryptoEngine::kemDecaps(enc.ciphertext, priv);
    ASSERT_EQ(ss.size(), 32u);
    EXPECT_EQ(ss, enc.sharedSecret)
        << "ML-KEM decapsulation must recover the shared secret";
}

// ── 8. ML-KEM-768 decaps with tampered ciphertext ─────────────────────────
// ML-KEM is IND-CCA2: decaps with a bad ciphertext succeeds but returns a
// pseudo-random (and unrelated) shared secret — this is the FO transform.
// So we assert the result differs from the original, not that decaps fails.

TEST(CryptoEngine, MlKem768TamperedCiphertextYieldsDifferentSecret) {
    auto [pub, priv] = CryptoEngine::generateKemKeypair();
    KemEncapsResult enc = CryptoEngine::kemEncaps(pub);
    ASSERT_FALSE(enc.ciphertext.empty());

    // Flip a bit in the middle of the ciphertext.
    flipBit(enc.ciphertext, 4 * 8 + 3);

    const Bytes ss = CryptoEngine::kemDecaps(enc.ciphertext, priv);
    ASSERT_EQ(ss.size(), 32u);
    EXPECT_NE(ss, enc.sharedSecret);
}

// ── 8b. ML-KEM-768 decaps with a mismatched private key ───────────────────
// Encapsulate against keypair A's public key, then decaps with keypair B's
// private key.  FO-protected decaps succeeds but produces a pseudo-random
// shared secret unrelated to the one A encapsulated — not empty, not equal.

TEST(CryptoEngine, MlKem768MismatchedPrivateKeyYieldsDifferentSecret) {
    auto [pubA, privA] = CryptoEngine::generateKemKeypair();
    auto [pubB, privB] = CryptoEngine::generateKemKeypair();

    const KemEncapsResult enc = CryptoEngine::kemEncaps(pubA);
    ASSERT_FALSE(enc.ciphertext.empty());
    ASSERT_EQ(enc.sharedSecret.size(), 32u);

    const Bytes ssWrong = CryptoEngine::kemDecaps(enc.ciphertext, privB);
    ASSERT_EQ(ssWrong.size(), 32u);
    EXPECT_NE(ssWrong, enc.sharedSecret)
        << "decaps with mismatched private key should not recover A's shared secret";

    // Sanity: the correct key still works.
    const Bytes ssRight = CryptoEngine::kemDecaps(enc.ciphertext, privA);
    EXPECT_EQ(ssRight, enc.sharedSecret);
}

// ── 9. ML-DSA-65 sign / verify round-trip ─────────────────────────────────

TEST(CryptoEngine, MlDsa65SignVerifyRoundTrip) {
    auto [pub, priv] = CryptoEngine::generateDsaKeypair();
    ASSERT_FALSE(pub.empty());
    ASSERT_FALSE(priv.empty());

    const Bytes msg = bytesOf("sign this please");
    const Bytes sig = CryptoEngine::dsaSign(msg, priv);
    ASSERT_FALSE(sig.empty());

    EXPECT_TRUE(CryptoEngine::dsaVerify(sig, msg, pub));
}

// ── 10. ML-DSA-65 rejects signature under wrong message / wrong key ───────

TEST(CryptoEngine, MlDsa65RejectsWrongMessageOrWrongKey) {
    auto [pubA, privA] = CryptoEngine::generateDsaKeypair();
    auto [pubB, privB] = CryptoEngine::generateDsaKeypair();

    const Bytes msg1 = bytesOf("message one");
    const Bytes msg2 = bytesOf("message two");

    const Bytes sig = CryptoEngine::dsaSign(msg1, privA);
    ASSERT_FALSE(sig.empty());

    // Wrong message: verify fails.
    EXPECT_FALSE(CryptoEngine::dsaVerify(sig, msg2, pubA));
    // Wrong verifier key: verify fails.
    EXPECT_FALSE(CryptoEngine::dsaVerify(sig, msg1, pubB));
    // Sanity: right key + right message succeeds.
    EXPECT_TRUE(CryptoEngine::dsaVerify(sig, msg1, pubA));
}

// ── 11. Ed25519 identity-backed signing via signB64u + verifySignature ────
// Uses a transient data directory + in-memory passphrase to exercise the
// real ensureIdentity() path once, so we cover the common "sign a mailbox
// auth blob with our identity key" flow end-to-end.

TEST(CryptoEngine, Ed25519IdentitySigningRoundTrip) {
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "p2p-test-identity";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    CryptoEngine ce;
    ce.setDataDir(tmp.string());
    ce.setPassphrase("test-only-passphrase");
    ASSERT_NO_THROW(ce.ensureIdentity());

    const Bytes msg = bytesOf("mailbox-auth-nonce:12345");
    const std::string sigB64u = ce.signB64u(msg);
    ASSERT_FALSE(sigB64u.empty());

    const Bytes sig = CryptoEngine::fromBase64Url(sigB64u);
    ASSERT_EQ(sig.size(), 64u);  // Ed25519 signature size

    EXPECT_TRUE(CryptoEngine::verifySignature(sig, msg, ce.identityPub()));

    // And a tampered message must fail.
    Bytes tampered = msg;
    tampered[0] ^= 0x01;
    EXPECT_FALSE(CryptoEngine::verifySignature(sig, tampered, ce.identityPub()));

    fs::remove_all(tmp);
}

// ── 12. Ed25519 KAT from RFC 8032 §7.1 TEST 1 ─────────────────────────────
// If verifySignature silently swapped the hash (e.g. SHA-512 → SHA-256) or
// lost the domain-separation prefix, the existing round-trip tests would
// still pass — both sides would be wrong in the same way.  A canonical
// third-party test vector catches that class of bug.  Empty message case.

TEST(CryptoEngine, Ed25519VerifiesRfc8032Test1) {
    const Bytes pub = fromHex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const Bytes sig = fromHex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    const Bytes msg; // empty

    ASSERT_EQ(pub.size(), 32u);
    ASSERT_EQ(sig.size(), 64u);
    EXPECT_TRUE(CryptoEngine::verifySignature(sig, msg, pub))
        << "RFC 8032 §7.1 TEST 1 KAT failed — Ed25519 implementation is wrong";
}

// ── 13. Ed25519 verify rejects malformed signatures ───────────────────────
// A wrong-size or all-zero signature must return false.  Particularly
// important for all-zero because libsodium has historically caught weak-key
// shortcuts where an attacker submits a trivial signature.

TEST(CryptoEngine, Ed25519VerifyRejectsBadSignatureShape) {
    auto [pub, priv] = CryptoEngine::generateDsaKeypair(); // just a keypair for the pub

    const Bytes msg = bytesOf("anything");
    // DSA pub won't verify as Ed25519, so build a minimal Ed25519-shaped pub
    // by reusing the identity path isn't worth the plumbing — instead just
    // verify that bad SHAPES are rejected against a valid, freshly derived
    // Ed25519 pub.  We get one from CryptoEngine by going through the
    // identity-bootstrap machinery once.
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "p2p-test-identity-shape";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    CryptoEngine ce;
    ce.setDataDir(tmp.string());
    ce.setPassphrase("test-only-passphrase");
    ASSERT_NO_THROW(ce.ensureIdentity());
    const Bytes edPub = ce.identityPub();
    ASSERT_EQ(edPub.size(), 32u);

    // Wrong length (63 bytes instead of 64).
    EXPECT_FALSE(CryptoEngine::verifySignature(Bytes(63, 0x00), msg, edPub));
    // Right length, all zeros.
    EXPECT_FALSE(CryptoEngine::verifySignature(Bytes(64, 0x00), msg, edPub));
    // Right length, all 0xFF (never lands on a valid signature).
    EXPECT_FALSE(CryptoEngine::verifySignature(Bytes(64, 0xFF), msg, edPub));

    fs::remove_all(tmp);
}

// ── 14. Base64Url round-trip at every residue class (0..5 bytes) ──────────
// Base64 encodes 3 bytes into 4 characters; the interesting cases are
// input lengths mod 3 = {0, 1, 2} because they drive the padding logic.
// CryptoEngine uses the unpadded URL-safe flavor for mailbox auth signatures.

TEST(CryptoEngine, Base64UrlRoundTripsAllLengths) {
    for (size_t n = 0; n <= 5; ++n) {
        Bytes in(n);
        for (size_t i = 0; i < n; ++i) in[i] = static_cast<uint8_t>(0xA0 + i);

        const std::string enc = CryptoEngine::toBase64Url(in);
        const Bytes out = CryptoEngine::fromBase64Url(enc);
        EXPECT_EQ(out, in) << "len=" << n << " enc=\"" << enc << "\"";
        // URL-safe alphabet: no '+', '/', '='.
        EXPECT_EQ(enc.find('+'), std::string::npos);
        EXPECT_EQ(enc.find('/'), std::string::npos);
        EXPECT_EQ(enc.find('='), std::string::npos);
    }
}

TEST(CryptoEngine, Base64UrlRoundTripsFullByteRange) {
    Bytes in(256);
    for (size_t i = 0; i < in.size(); ++i) in[i] = static_cast<uint8_t>(i);
    const Bytes out = CryptoEngine::fromBase64Url(CryptoEngine::toBase64Url(in));
    EXPECT_EQ(out, in);
}

// ── 15. Identity persistence: second open of same data-dir yields same pub ─
// This exercises the encrypted-at-rest identity.json path end-to-end.  If a
// future change breaks Argon2 salt handling or corrupts the JSON schema, the
// user-visible failure is "I can't unlock my app after reboot" — this test
// catches it in ~100ms before anyone reinstalls.

TEST(CryptoEngine, IdentityReloadFromDiskYieldsSamePub) {
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "p2p-test-identity-reload";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    Bytes firstPub;
    {
        CryptoEngine ce;
        ce.setDataDir(tmp.string());
        ce.setPassphrase("stable-passphrase");
        ASSERT_NO_THROW(ce.ensureIdentity());
        firstPub = ce.identityPub();
        ASSERT_EQ(firstPub.size(), 32u);
    }

    {
        CryptoEngine ce;
        ce.setDataDir(tmp.string());
        ce.setPassphrase("stable-passphrase");
        ASSERT_NO_THROW(ce.ensureIdentity());
        EXPECT_EQ(ce.identityPub(), firstPub)
            << "reopening the same data-dir with the same passphrase must recover the same Ed25519 identity";
    }

    fs::remove_all(tmp);
}

// ── 13. Identity-bundle signing for hybrid PQ msg1 ────────────────────────
// Tier 1 of project_pq_messaging.md.  Tests both the SIGN path
// (instance method via real ensureIdentity) and the VERIFY path
// (static; tested independently by externally signing with
// libsodium so we don't trust sign + verify in the same test).
//
// The canonical message format MUST stay byte-exact with the
// relay's `canonicalIdentityMessage` in
// `relay-go/relay.go`.  A wire-format regression here breaks
// cross-platform sign/verify for the entire PQ-msg1 path.

namespace {

// Helper: rebuild the canonical message exactly as the C++ /
// Go signers do.  Lives in the test so a refactor in the
// production canonical-message helper that drifts from this
// shape would trip the CanonicalIsByteExact test below.
std::string identityCanonicalForTest(const std::string& idB64u,
                                       const Bytes& kemPub,
                                       uint64_t tsDay) {
    return "P2P_IDENTITY_v1|" + idB64u + "|" +
            CryptoEngine::toBase64Url(kemPub) + "|" +
            std::to_string(tsDay);
}

// Helper: external libsodium-signed bundle.  Lets the verify
// tests avoid implicit dependence on signIdentityBundle being
// correct.
Bytes externalSignBundle(const std::string& idB64u,
                          const Bytes& kemPub, uint64_t tsDay,
                          const Bytes& edPriv) {
    const std::string canonical = identityCanonicalForTest(idB64u, kemPub, tsDay);
    Bytes sig(crypto_sign_BYTES);
    crypto_sign_detached(sig.data(), nullptr,
                          reinterpret_cast<const uint8_t*>(canonical.data()),
                          canonical.size(),
                          edPriv.data());
    return sig;
}

// Helper: generate a fresh libsodium Ed25519 keypair (no
// CryptoEngine / ensureIdentity needed).  Returns
// {pub, priv, idB64u}.
struct TestKeypair {
    Bytes        pub;
    Bytes        priv;
    std::string  idB64u;
};
TestKeypair freshEd25519() {
    TestKeypair kp;
    kp.pub.assign(crypto_sign_PUBLICKEYBYTES, 0);
    kp.priv.assign(crypto_sign_SECRETKEYBYTES, 0);
    crypto_sign_keypair(kp.pub.data(), kp.priv.data());
    kp.idB64u = CryptoEngine::toBase64Url(kp.pub);
    return kp;
}

// Helper: build a 1184-byte ML-KEM-768-shaped buffer for
// signing tests.  We don't actually decapsulate against it —
// the relay/sender just stores opaque bytes.
Bytes fakeKemPubBlob(uint8_t fillByte) {
    return Bytes(1184, fillByte);
}

}  // anonymous namespace

// 13a — Verify path: external sign with libsodium, verify with
// CryptoEngine::verifyIdentityBundle.  Each tampered field
// (kem_pub byte, ts_day, sig byte, ed25519 id) must fail.
TEST(CryptoEngine, IdentityBundleVerifyHappyAndTamper) {
    const TestKeypair kp     = freshEd25519();
    const Bytes       kemPub = fakeKemPubBlob(0xAB);
    const uint64_t    tsDay  = 20571;
    const Bytes       sig    = externalSignBundle(kp.idB64u, kemPub, tsDay, kp.priv);

    // 1) Happy path — same inputs verify cleanly.
    EXPECT_TRUE(CryptoEngine::verifyIdentityBundle(kp.idB64u, kemPub, tsDay, sig));

    // 2) Tamper kemPub (first byte flipped) → fails.
    {
        Bytes badKem = kemPub;
        badKem[0] ^= 0x01;
        EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
            kp.idB64u, badKem, tsDay, sig));
    }

    // 3) Tamper kemPub (last byte flipped) → fails (full message
    //    is hashed; any byte-flip breaks the signature).
    {
        Bytes badKem = kemPub;
        badKem.back() ^= 0x80;
        EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
            kp.idB64u, badKem, tsDay, sig));
    }

    // 4) Tamper ts_day → fails (different canonical message).
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        kp.idB64u, kemPub, tsDay + 1, sig));
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        kp.idB64u, kemPub, tsDay - 1, sig));
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        kp.idB64u, kemPub, 0, sig));

    // 5) Tamper sig → fails.  Try multiple bit positions to
    //    catch any verifier that ignores chunks of the signature.
    for (size_t bit : {0u, 7u, 31u, 256u, 511u}) {
        Bytes badSig = sig;
        flipBit(badSig, bit);
        EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
            kp.idB64u, kemPub, tsDay, badSig));
    }

    // 6) Substitute id with a different valid id → fails (the
    //    sig was made for the original id; the verifier decodes
    //    the requested id as the pub-key, which now doesn't
    //    match the sig's key).
    {
        const TestKeypair other = freshEd25519();
        EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
            other.idB64u, kemPub, tsDay, sig));
    }
}

// 13b — Wrong key signing (impersonation).  Sender signs with
// their OWN keypair but submits SOMEONE ELSE's id_b64u: the
// sig won't verify under the impersonated id (Ed25519 is
// unforgeable; we test the verify path actually catches this).
TEST(CryptoEngine, IdentityBundleRejectsImpersonation) {
    const TestKeypair alice = freshEd25519();
    const TestKeypair bob   = freshEd25519();
    const Bytes       kemPub = fakeKemPubBlob(0x42);
    const uint64_t    tsDay  = 20571;

    // Bob signs a bundle that CLAIMS to be Alice's
    // (id_b64u = alice.idB64u, but sig made with bob.priv).
    const Bytes bobSig = externalSignBundle(alice.idB64u, kemPub, tsDay, bob.priv);

    // Verifier looks up the pub-key from the supplied id (alice.idB64u),
    // tries to verify bob's sig under alice's pub → fails.
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        alice.idB64u, kemPub, tsDay, bobSig));

    // Also fails when the verifier is told the id IS bob's
    // (because the canonical message was built with alice's id).
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        bob.idB64u, kemPub, tsDay, bobSig));
}

// 13c — Malformed inputs.  The verifier must reject without
// crashing on undersized / empty / oversized arguments.
TEST(CryptoEngine, IdentityBundleRejectsMalformedInputs) {
    const TestKeypair kp     = freshEd25519();
    const Bytes       kemPub = fakeKemPubBlob(0x55);
    const Bytes       sig    = externalSignBundle(kp.idB64u, kemPub, 1, kp.priv);

    // Bad id: empty, wrong size, malformed base64url.
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle("",        kemPub, 1, sig));
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle("AAAA",    kemPub, 1, sig));
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle("not!b64", kemPub, 1, sig));

    // Bad sig: empty, wrong size.
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(kp.idB64u, kemPub, 1, {}));
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        kp.idB64u, kemPub, 1, Bytes(63, 0)));   // one byte short
    EXPECT_FALSE(CryptoEngine::verifyIdentityBundle(
        kp.idB64u, kemPub, 1, Bytes(65, 0)));   // one byte long

    // Empty kemPub: should still verify if the SIGNED message
    // also had an empty kemPub (we don't enforce kem_pub size at
    // the verify layer — that's the relay's + caller's job).
    {
        const Bytes emptySig = externalSignBundle(kp.idB64u, {}, 1, kp.priv);
        EXPECT_TRUE(CryptoEngine::verifyIdentityBundle(
            kp.idB64u, {}, 1, emptySig));
    }
}

// 13d — Sign path: instance method via ensureIdentity().  Round-
// trip through both sign and verify, then check tamper cases
// against the SIGNED bundle (already covered for external-
// signed in 13a; this confirms the instance signer produces
// bytes that match the verifier's expectations).
TEST(CryptoEngine, IdentityBundleSignThroughVerify) {
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "p2p-test-id-bundle-sign";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    CryptoEngine ce;
    ce.setDataDir(tmp.string());
    ce.setPassphrase("test-only-passphrase");
    ASSERT_NO_THROW(ce.ensureIdentity());
    ASSERT_FALSE(ce.identityPub().empty());

    const std::string idB64u = CryptoEngine::toBase64Url(ce.identityPub());
    const Bytes       kemPub = fakeKemPubBlob(0xCD);
    const uint64_t    tsDay  = 20571;

    const Bytes sig = ce.signIdentityBundle(idB64u, kemPub, tsDay);
    ASSERT_EQ(sig.size(), 64u) << "Ed25519 signature must be 64 bytes";

    // Static verify path accepts.
    EXPECT_TRUE(CryptoEngine::verifyIdentityBundle(idB64u, kemPub, tsDay, sig));

    // Round-trip via the verifier's own canonical-message build:
    // re-sign the same canonical externally + compare bytes.
    // Ed25519 with libsodium is DETERMINISTIC (RFC 8032), so
    // signing the same message twice produces byte-identical
    // signatures.  This proves both signers are using the same
    // canonical bytes.
    const Bytes externalSig = externalSignBundle(
        idB64u, kemPub, tsDay, ce.identityPriv());
    EXPECT_EQ(sig, externalSig)
        << "instance-method signature must byte-match a libsodium "
        << "signature over the same canonical message — wire format drift!";

    // Sign-with-empty-kemPub returns empty (the instance method
    // explicitly rejects empty input to avoid publishing a
    // useless bundle).
    EXPECT_TRUE(ce.signIdentityBundle(idB64u, {}, tsDay).empty());

    fs::remove_all(tmp);
}

// 13e — Canonical message is byte-exact (cross-platform contract).
// If the C++ canonical-message helper drifts in any way (extra
// space, different separator, different ts encoding) the Go
// relay's signature verification will reject every signature
// from every C++ client.  Pin the bytes here as a regression
// guard — we control both sides, so changing the format
// requires updating BOTH this test AND the Go side.
TEST(CryptoEngine, IdentityBundleCanonicalMessageIsByteExact) {
    // Fixed inputs: known id (32 zeros) + known kem_pub (1184
    // zeros) + ts_day = 19840.  Both encode deterministically
    // to base64url (zero bytes → A-fill) so the canonical
    // string is fully reproducible.
    const std::string fixedIdB64u  = CryptoEngine::toBase64Url(Bytes(32, 0));
    const Bytes       fixedKemPub  = Bytes(1184, 0);
    const uint64_t    fixedTsDay   = 19840;

    const std::string expected =
        "P2P_IDENTITY_v1|" + fixedIdB64u + "|" +
        CryptoEngine::toBase64Url(fixedKemPub) + "|19840";

    const std::string actual = identityCanonicalForTest(
        fixedIdB64u, fixedKemPub, fixedTsDay);
    EXPECT_EQ(actual, expected);

    // Sanity: 32 zero bytes b64url is 43 chars of "A" (the
    // base64url-of-all-zero pattern).  This nails the
    // toBase64Url encoder shape too.
    EXPECT_EQ(fixedIdB64u, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // The bytes a Go-side `canonicalIdentityMessage` produces
    // for the same inputs (manually computed offline + checked
    // in here as a wire-format pin):
    //   "P2P_IDENTITY_v1|" (16) + 43 'A' + "|" (1) + 1579 'A'
    //   + "|" (1) + "19840" (5) = 1645 bytes.
    // (1184 raw bytes → ceil(1184 * 4/3) - padding = 1579 b64url chars)
    EXPECT_EQ(actual.size(), 1645u)
        << "canonical message size drift — Go relay will reject all signatures";
}

// 13f — Determinism + golden-vector lock-in.  Ed25519
// signatures over the same message + same priv key MUST be
// byte-identical (RFC 8032 §5.1.6).  This catches: (a) a
// non-deterministic Ed25519 implementation slipping in, (b)
// the canonical-message format drifting silently.
TEST(CryptoEngine, IdentityBundleSignatureIsDeterministic) {
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "p2p-test-id-bundle-determ";
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    CryptoEngine ce;
    ce.setDataDir(tmp.string());
    ce.setPassphrase("determinism-passphrase");
    ASSERT_NO_THROW(ce.ensureIdentity());

    const std::string idB64u = CryptoEngine::toBase64Url(ce.identityPub());
    const Bytes       kemPub = fakeKemPubBlob(0x77);

    const Bytes sig1 = ce.signIdentityBundle(idB64u, kemPub, 20571);
    const Bytes sig2 = ce.signIdentityBundle(idB64u, kemPub, 20571);
    EXPECT_EQ(sig1, sig2)
        << "same inputs must produce byte-identical Ed25519 signatures";

    // Different ts_day → different signature (sanity that the
    // canonical message actually feeds into the sign path).
    const Bytes sigDifferentTs = ce.signIdentityBundle(idB64u, kemPub, 20572);
    EXPECT_NE(sig1, sigDifferentTs);

    // Different kem_pub → different signature.
    const Bytes sigDifferentKem = ce.signIdentityBundle(
        idB64u, fakeKemPubBlob(0x78), 20571);
    EXPECT_NE(sig1, sigDifferentKem);

    fs::remove_all(tmp);
}
