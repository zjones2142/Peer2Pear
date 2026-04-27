#include "MigrationCrypto.hpp"
#include "CryptoEngine.hpp"
#include "log.hpp"

#include <sodium.h>
#include <cstring>

namespace {

// Domain-separation strings.  Pinned at this layer (NOT exposed in
// the header) because they're protocol invariants — receivers must
// reconstruct the same bytes the sender used, and the only sane
// way to keep that in sync is to copy these literals into any
// future port (desktop) verbatim.  Same trick the rest of the
// hybrid-PQ stack uses (NoiseState, RatchetSession).
constexpr const char* kHkdfInfo  = "p2p-migration-v1-aead";
constexpr const char* kAadPrefix = "p2p-migration-v1-aad|";

// Build the AEAD-authenticated-but-not-encrypted associated data.
// Both sides MUST construct this identically; any drift breaks
// decrypt with a tag-mismatch error.
//
// Includes ALL the context the receiver knows when validating:
//   - protocol version
//   - sender's X25519 pubkey (from envelope header)
//   - receiver's own X25519 + ML-KEM-768 pubkeys (receiver passes
//     them in; sender knows them from the QR)
//   - ML-KEM-768 ciphertext (in case future versions add a
//     deterministic-encap variant — pinning the CT here means an
//     attacker can't swap CTs between envelopes)
Bytes buildAad(uint8_t version,
                const Bytes& senderX25519Pub,
                const Bytes& receiverX25519Pub,
                const Bytes& receiverMlkemPub,
                const Bytes& mlkemCiphertext)
{
    const std::size_t prefixLen = std::strlen(kAadPrefix);
    Bytes aad;
    aad.reserve(prefixLen + 1
                 + senderX25519Pub.size()
                 + receiverX25519Pub.size()
                 + receiverMlkemPub.size()
                 + mlkemCiphertext.size());
    aad.insert(aad.end(),
                reinterpret_cast<const uint8_t*>(kAadPrefix),
                reinterpret_cast<const uint8_t*>(kAadPrefix) + prefixLen);
    aad.push_back(version);
    aad.insert(aad.end(), senderX25519Pub.begin(), senderX25519Pub.end());
    aad.insert(aad.end(), receiverX25519Pub.begin(), receiverX25519Pub.end());
    aad.insert(aad.end(), receiverMlkemPub.begin(), receiverMlkemPub.end());
    aad.insert(aad.end(), mlkemCiphertext.begin(), mlkemCiphertext.end());
    return aad;
}

// Concatenate two shared secrets (X25519 + ML-KEM-768) into the
// HKDF input keying material.  Order is fixed (X25519 first,
// ML-KEM second) — receivers MUST match.  This is the same
// hybrid-combine pattern Noise IK uses elsewhere in the stack.
Bytes combineSharedSecrets(const Bytes& x25519Ss, const Bytes& mlkemSs)
{
    Bytes combined;
    combined.reserve(x25519Ss.size() + mlkemSs.size());
    combined.insert(combined.end(), x25519Ss.begin(), x25519Ss.end());
    combined.insert(combined.end(), mlkemSs.begin(), mlkemSs.end());
    return combined;
}

}  // namespace

namespace MigrationCrypto {

Keypairs generateKeypairs()
{
    Keypairs k;

    auto [xPub, xPriv] = CryptoEngine::generateEphemeralX25519();
    if (xPub.size() != kX25519PubLen || xPriv.size() != kX25519PrivLen) {
        P2P_WARN("[MigrationCrypto] X25519 keypair generation failed");
        return {};
    }

    auto [mPub, mPriv] = CryptoEngine::generateKemKeypair();
    if (mPub.size() != kMlkemPubLen || mPriv.size() != kMlkemPrivLen) {
        P2P_WARN("[MigrationCrypto] ML-KEM-768 keypair generation failed");
        CryptoEngine::secureZero(xPriv);
        return {};
    }

    k.x25519Pub  = std::move(xPub);
    k.x25519Priv = std::move(xPriv);
    k.mlkemPub   = std::move(mPub);
    k.mlkemPriv  = std::move(mPriv);
    return k;
}

Bytes fingerprint(const Bytes& x25519Pub, const Bytes& mlkemPub)
{
    if (x25519Pub.size() != kX25519PubLen) return {};
    if (mlkemPub.size()  != kMlkemPubLen)  return {};

    Bytes concat;
    concat.reserve(kX25519PubLen + kMlkemPubLen);
    concat.insert(concat.end(), x25519Pub.begin(), x25519Pub.end());
    concat.insert(concat.end(), mlkemPub.begin(),  mlkemPub.end());

    // SHA-256 (libsodium) — same primitive the rest of the stack
    // uses for content fingerprints.  First 16 bytes give 64 bits
    // of collision resistance; an attacker would need ~2^64 KEM
    // keypair generations to find a colliding fingerprint, which
    // is well above any practical attack budget.
    Bytes hash(crypto_hash_sha256_BYTES, 0);
    crypto_hash_sha256(hash.data(), concat.data(), concat.size());
    hash.resize(kFingerprintLen);
    return hash;
}

Bytes seal(const Bytes& payload,
            const Bytes& receiverX25519Pub,
            const Bytes& receiverMlkemPub,
            const Bytes& handshakeNonce)
{
    // Input validation — fail fast with empty return so the caller
    // sees a single uniform "couldn't seal" signal regardless of
    // which input was malformed.
    if (receiverX25519Pub.size() != kX25519PubLen)        return {};
    if (receiverMlkemPub.size()  != kMlkemPubLen)         return {};
    if (handshakeNonce.size()    != kHandshakeNonceLen)   return {};
    if (payload.empty())                                   return {};

    // 1. Sender's ephemeral X25519 keypair (one-shot, never reused).
    auto [senderX25519Pub, senderX25519Priv] =
        CryptoEngine::generateEphemeralX25519();
    if (senderX25519Pub.size() != kX25519PubLen) return {};

    // 2. X25519 DH: scalarmult(senderPriv, receiverPub) → 32-byte SS.
    //    libsodium's crypto_scalarmult catches the all-zero result
    //    case (small-subgroup attack) via non-zero return.
    Bytes x25519Ss(crypto_scalarmult_BYTES, 0);
    if (crypto_scalarmult(x25519Ss.data(),
                           senderX25519Priv.data(),
                           receiverX25519Pub.data()) != 0) {
        CryptoEngine::secureZero(senderX25519Priv);
        return {};
    }

    // 3. ML-KEM-768 encapsulation against receiver's KEM pubkey.
    //    Sender keeps the shared secret, ships the ciphertext.
    auto kem = CryptoEngine::kemEncaps(receiverMlkemPub);
    if (kem.ciphertext.empty() || kem.sharedSecret.empty()) {
        CryptoEngine::secureZero(senderX25519Priv);
        CryptoEngine::secureZero(x25519Ss);
        return {};
    }

    // 4. Hybrid combine + HKDF-SHA256 → 32-byte AEAD key.
    //    Salt is the QR-derived nonce so a stale QR can't be
    //    reused verbatim across migration sessions.
    Bytes combined = combineSharedSecrets(x25519Ss, kem.sharedSecret);
    Bytes aeadKey = CryptoEngine::hkdf(
        combined, handshakeNonce,
        Bytes(reinterpret_cast<const uint8_t*>(kHkdfInfo),
              reinterpret_cast<const uint8_t*>(kHkdfInfo)
                  + std::strlen(kHkdfInfo)),
        32);
    CryptoEngine::secureZero(combined);
    CryptoEngine::secureZero(x25519Ss);
    CryptoEngine::secureZero(kem.sharedSecret);
    CryptoEngine::secureZero(senderX25519Priv);
    if (aeadKey.size() != 32) return {};

    // 5. ChaCha20-Poly1305 IETF AEAD.  12-byte nonce, random per
    //    envelope.  Reusing a nonce with the same key voids
    //    confidentiality; AEAD key is per-migration here so this
    //    is belt-and-suspenders, but the cost is 12 bytes.
    Bytes aeadNonce(crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 0);
    randombytes_buf(aeadNonce.data(), aeadNonce.size());

    Bytes aad = buildAad(kEnvelopeVersion,
                          senderX25519Pub,
                          receiverX25519Pub,
                          receiverMlkemPub,
                          kem.ciphertext);

    // Output buffer = ciphertext + 16-byte Poly1305 tag.
    Bytes ctAndTag(payload.size() + crypto_aead_chacha20poly1305_IETF_ABYTES,
                    0);
    unsigned long long ctLen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ctAndTag.data(), &ctLen,
            payload.data(), payload.size(),
            aad.data(), aad.size(),
            nullptr,                       // nsec — unused for this AEAD
            aeadNonce.data(),
            aeadKey.data()) != 0) {
        CryptoEngine::secureZero(aeadKey);
        return {};
    }
    ctAndTag.resize(static_cast<std::size_t>(ctLen));
    CryptoEngine::secureZero(aeadKey);

    // 6. Pack the envelope.  Layout matches the comment in
    //    MigrationCrypto.hpp; receivers must parse identically.
    Bytes envelope;
    envelope.reserve(kEnvelopeOverhead + payload.size());
    envelope.push_back(kEnvelopeVersion);
    envelope.insert(envelope.end(),
                     senderX25519Pub.begin(), senderX25519Pub.end());
    envelope.insert(envelope.end(),
                     kem.ciphertext.begin(), kem.ciphertext.end());
    envelope.insert(envelope.end(),
                     aeadNonce.begin(), aeadNonce.end());
    envelope.insert(envelope.end(), ctAndTag.begin(), ctAndTag.end());
    return envelope;
}

Bytes open(const Bytes& envelope,
            const Bytes& receiverX25519Pub,
            const Bytes& receiverX25519Priv,
            const Bytes& receiverMlkemPub,
            const Bytes& receiverMlkemPriv,
            const Bytes& handshakeNonce)
{
    // 1. Wire-format gate.  All-or-nothing parsing — any malformed
    //    field returns empty rather than partially decoding (which
    //    would give an attacker a discrimination oracle).
    constexpr int kHeaderLen = 1
                              + kX25519PubLen
                              + kMlkemCtLen
                              + 12;          // ChaChaPoly nonce
    if (static_cast<int>(envelope.size()) < kHeaderLen + 16) return {};
    if (receiverX25519Pub.size()  != kX25519PubLen)          return {};
    if (receiverX25519Priv.size() != kX25519PrivLen)         return {};
    if (receiverMlkemPub.size()   != kMlkemPubLen)           return {};
    if (receiverMlkemPriv.size()  != kMlkemPrivLen)          return {};
    if (handshakeNonce.size()     != kHandshakeNonceLen)     return {};

    // 2. Slice the envelope.
    std::size_t offset = 0;
    const uint8_t version = envelope[offset++];
    if (version != kEnvelopeVersion) return {};

    Bytes senderX25519Pub(envelope.begin() + offset,
                           envelope.begin() + offset + kX25519PubLen);
    offset += kX25519PubLen;

    Bytes kemCt(envelope.begin() + offset,
                 envelope.begin() + offset + kMlkemCtLen);
    offset += kMlkemCtLen;

    Bytes aeadNonce(envelope.begin() + offset,
                     envelope.begin() + offset + 12);
    offset += 12;

    Bytes ctAndTag(envelope.begin() + offset, envelope.end());

    // 3. X25519 DH: scalarmult(receiverPriv, senderPub) → SS.
    Bytes x25519Ss(crypto_scalarmult_BYTES, 0);
    if (crypto_scalarmult(x25519Ss.data(),
                           receiverX25519Priv.data(),
                           senderX25519Pub.data()) != 0) {
        return {};
    }

    // 4. ML-KEM-768 decapsulation.
    Bytes mlkemSs = CryptoEngine::kemDecaps(kemCt, receiverMlkemPriv);
    if (mlkemSs.empty()) {
        CryptoEngine::secureZero(x25519Ss);
        return {};
    }

    // 5. Same hybrid-combine + HKDF as seal().  ANY parameter
    //    drift produces a tag-mismatch on AEAD open below.
    Bytes combined = combineSharedSecrets(x25519Ss, mlkemSs);
    Bytes aeadKey = CryptoEngine::hkdf(
        combined, handshakeNonce,
        Bytes(reinterpret_cast<const uint8_t*>(kHkdfInfo),
              reinterpret_cast<const uint8_t*>(kHkdfInfo)
                  + std::strlen(kHkdfInfo)),
        32);
    CryptoEngine::secureZero(combined);
    CryptoEngine::secureZero(x25519Ss);
    CryptoEngine::secureZero(mlkemSs);
    if (aeadKey.size() != 32) return {};

    Bytes aad = buildAad(version,
                          senderX25519Pub,
                          receiverX25519Pub,
                          receiverMlkemPub,
                          kemCt);

    // 6. AEAD open.  Failure here = wrong key OR tampered envelope;
    //    libsodium intentionally doesn't distinguish (no oracle).
    Bytes plaintext(ctAndTag.size(), 0);
    unsigned long long ptLen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &ptLen,
            nullptr,                         // nsec — unused
            ctAndTag.data(), ctAndTag.size(),
            aad.data(), aad.size(),
            aeadNonce.data(),
            aeadKey.data()) != 0) {
        CryptoEngine::secureZero(aeadKey);
        return {};
    }
    plaintext.resize(static_cast<std::size_t>(ptLen));
    CryptoEngine::secureZero(aeadKey);
    return plaintext;
}

}  // namespace MigrationCrypto
