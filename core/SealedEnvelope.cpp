#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"

#include <sodium.h>
#include <cstdio>       // std::fprintf for warning logs (replaced qWarning)
#include <cstring>

// Version bytes for wire format (v2 — recipient-bound AAD + envelope-id)
static constexpr uint8_t kVersionClassicalV2 = 0x02;
static constexpr uint8_t kVersionHybridV2    = 0x03;

// ML-KEM-768 ciphertext size (from liboqs)
static constexpr int kKemCtLen = 1088;

// Random id used for receiver-side replay dedup.
static constexpr int kEnvelopeIdLen = 16;

// Build AAD: ephPub(32) || recipientEdPub(32).  Binds the routing recipient
// cryptographically so a malicious relay can't re-route the sealed blob.
static Bytes buildAAD(const Bytes& ephPub, const Bytes& recipientEdPub)
{
    Bytes aad;
    aad.reserve(ephPub.size() + recipientEdPub.size());
    aad.insert(aad.end(), ephPub.begin(), ephPub.end());
    aad.insert(aad.end(), recipientEdPub.begin(), recipientEdPub.end());
    return aad;
}

// Big-endian 2-byte write / read helpers.  Replaces qToBigEndian / qFromBigEndian.
static inline void write_u16_be(uint8_t* dst, uint16_t v) {
    dst[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>( v       & 0xFF);
}
static inline uint16_t read_u16_be(const uint8_t* src) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(src[0]) << 8) | static_cast<uint16_t>(src[1]));
}
static inline void write_u32_be(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
    dst[3] = static_cast<uint8_t>( v        & 0xFF);
}
static inline uint32_t read_u32_be(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24)
         | (static_cast<uint32_t>(src[1]) << 16)
         | (static_cast<uint32_t>(src[2]) <<  8)
         |  static_cast<uint32_t>(src[3]);
}

// Append a byte buffer to the end of a Bytes vector.  Syntactic sugar for
// vec.insert(vec.end(), src.begin(), src.end()).
static inline void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
static inline void append(Bytes& dst, const uint8_t* src, size_t n) {
    dst.insert(dst.end(), src, src + n);
}

// ── seal ────────────────────────────────────────────────────────────────────

Bytes SealedEnvelope::seal(const Bytes& recipientCurvePub,
                            const Bytes& recipientEdPub,
                            const Bytes& senderEdPub,
                            const Bytes& senderEdPriv,
                            const Bytes& innerPayload,
                            const Bytes& recipientKemPub,
                            const Bytes& senderDsaPub,
                            const Bytes& senderDsaPriv) {
    if (recipientCurvePub.size() != 32) return {};
    if (recipientEdPub.size() != 32) return {};
    if (senderEdPub.size() != crypto_sign_PUBLICKEYBYTES) return {};
    if (senderEdPriv.size() != crypto_sign_SECRETKEYBYTES) return {};

    const bool hybrid = !recipientKemPub.empty();

    // 1. Generate ephemeral X25519 keypair.
    auto [ephPub, ephPriv] = CryptoEngine::generateEphemeralX25519();

    // 2. ECDH: ephPriv × recipientCurvePub → classical shared secret
    unsigned char ecdhShared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(ecdhShared,
                          ephPriv.data(),
                          recipientCurvePub.data()) != 0) {
        return {};
    }
    sodium_memzero(ephPriv.data(), ephPriv.size());

    // 3. If hybrid, also do ML-KEM-768 encapsulation
    Bytes kemCt;
    Bytes combinedIkm;

    if (hybrid) {
        KemEncapsResult kemResult = CryptoEngine::kemEncaps(recipientKemPub);
        if (kemResult.ciphertext.empty()) {
            CryptoEngine::secureZero(kemResult.sharedSecret);
            sodium_memzero(ecdhShared, sizeof(ecdhShared));
            return {};
        }
        kemCt = std::move(kemResult.ciphertext);

        // Combine: ecdhShared(32) || kemShared(32)
        combinedIkm.reserve(sizeof(ecdhShared) + kemResult.sharedSecret.size());
        combinedIkm.insert(combinedIkm.end(), ecdhShared, ecdhShared + sizeof(ecdhShared));
        combinedIkm.insert(combinedIkm.end(),
                           kemResult.sharedSecret.begin(),
                           kemResult.sharedSecret.end());
        CryptoEngine::secureZero(kemResult.sharedSecret);
    } else {
        combinedIkm.insert(combinedIkm.end(), ecdhShared, ecdhShared + sizeof(ecdhShared));
    }
    sodium_memzero(ecdhShared, sizeof(ecdhShared));

    // 4. Derive envelope key: BLAKE2b-256(combinedIkm)
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32,
                             combinedIkm.data(),
                             combinedIkm.size(),
                             nullptr, 0);
    sodium_memzero(combinedIkm.data(), combinedIkm.size());

    // 5. Generate a random 16-byte envelopeId for receiver-side replay dedup.
    Bytes envelopeId(kEnvelopeIdLen);
    randombytes_buf(envelopeId.data(), static_cast<size_t>(kEnvelopeIdLen));

    // 6. Sign (envelopeId || innerPayload) with sender's Ed25519 key.
    Bytes signedBytes;
    signedBytes.reserve(envelopeId.size() + innerPayload.size());
    append(signedBytes, envelopeId);
    append(signedBytes, innerPayload);

    unsigned char edSig[crypto_sign_BYTES];
    crypto_sign_detached(edSig, nullptr,
                         signedBytes.data(),
                         signedBytes.size(),
                         senderEdPriv.data());

    // 6b. Hybrid: also sign with ML-DSA-65 if we have DSA keys
    const bool hybridSig = !senderDsaPub.empty() && !senderDsaPriv.empty();
    Bytes dsaSig;
    if (hybridSig) {
        dsaSig = CryptoEngine::dsaSign(signedBytes, senderDsaPriv);
        if (dsaSig.empty()) {
            // Fail-closed: if we have DSA keys but signing fails, don't send at all
            sodium_memzero(envelopeKey, sizeof(envelopeKey));
            return {};
        }
    }

    // 7. Build plaintext:
    //   envelopeId(16) || senderEdPub(32) || edSig(64)
    //     || dsaPubLen(2) || [dsaPub || dsaSig] || innerPayload
    Bytes envPlaintext;
    append(envPlaintext, envelopeId);
    append(envPlaintext, senderEdPub);
    append(envPlaintext, edSig, crypto_sign_BYTES);

    if (hybridSig && !dsaSig.empty()) {
        uint8_t dpLenBE[2];
        write_u16_be(dpLenBE, static_cast<uint16_t>(senderDsaPub.size()));
        append(envPlaintext, dpLenBE, 2);
        append(envPlaintext, senderDsaPub);
        append(envPlaintext, dsaSig);
    } else {
        // No DSA signature — write 0 length marker
        uint8_t zero[2] = {0, 0};
        append(envPlaintext, zero, 2);
    }

    append(envPlaintext, innerPayload);

    // 8. AEAD encrypt with envelope key.
    const Bytes aad = buildAAD(ephPub, recipientEdPub);

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    Bytes ct(sizeof(nonce) + envPlaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data() + sizeof(nonce), &clen,
        envPlaintext.data(),
        envPlaintext.size(),
        aad.data(),
        aad.size(),
        nullptr, nonce, envelopeKey);

    std::memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(sizeof(nonce) + clen);
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 9. Wire format: version(1) || ephPub(32) || [kemCt(1088)] || AEAD
    Bytes out;
    if (hybrid) {
        out.reserve(1 + 32 + kemCt.size() + ct.size());
        out.push_back(kVersionHybridV2);
        append(out, ephPub);
        append(out, kemCt);
    } else {
        out.reserve(1 + 32 + ct.size());
        out.push_back(kVersionClassicalV2);
        append(out, ephPub);
    }
    append(out, ct);
    return out;
}

// ── Relay routing header + envelope padding ──────────────────────────────────

static constexpr uint8_t kRoutingVersion = 0x01;
static constexpr int kBucketSmall  =   2 * 1024;   //   2 KiB
static constexpr int kBucketMedium =  16 * 1024;   //  16 KiB
static constexpr int kBucketLarge  = 256 * 1024;   // 256 KiB

// Routing header overhead: version(1) + recipientEdPub(32) + innerLen(4) = 37 bytes
static constexpr size_t kHeaderSize = 1 + 32 + 4;

static size_t paddedSize(size_t rawSize)
{
    if (rawSize <= kBucketSmall)  return kBucketSmall;
    if (rawSize <= kBucketMedium) return kBucketMedium;
    if (rawSize <= kBucketLarge)  return kBucketLarge;
    return rawSize;  // exceeds largest bucket — no padding
}

Bytes SealedEnvelope::wrapForRelay(const Bytes& recipientEdPub,
                                    const Bytes& sealedBytes)
{
    if (recipientEdPub.size() != 32 || sealedBytes.empty()) return {};

    const size_t totalRaw = kHeaderSize + sealedBytes.size();
    const size_t totalPadded = paddedSize(totalRaw);
    const size_t padLen = totalPadded - totalRaw;

    Bytes out;
    out.reserve(totalPadded);

    // Header: version + recipient + inner length
    out.push_back(kRoutingVersion);
    append(out, recipientEdPub);
    uint8_t innerLenBE[4];
    write_u32_be(innerLenBE, static_cast<uint32_t>(sealedBytes.size()));
    append(out, innerLenBE, 4);

    // Payload
    append(out, sealedBytes);

    // Random padding to reach bucket size
    if (padLen > 0) {
        const size_t head = out.size();
        out.resize(head + padLen);
        randombytes_buf(out.data() + head, padLen);
    }

    return out;
}

Bytes SealedEnvelope::unwrapFromRelay(const Bytes& relayEnvelope,
                                       Bytes* recipientEdPub)
{
    // Minimum: version(1) + recipientEdPub(32) + innerLen(4) + at least 1 byte
    if (relayEnvelope.size() < kHeaderSize + 1) return {};
    if (relayEnvelope[0] != kRoutingVersion) return {};

    if (recipientEdPub) {
        recipientEdPub->assign(relayEnvelope.begin() + 1,
                               relayEnvelope.begin() + 1 + 32);
    }

    // Read inner length to strip padding
    const uint32_t innerLen = read_u32_be(relayEnvelope.data() + 33);
    if (innerLen > relayEnvelope.size() - kHeaderSize) return {};

    return Bytes(relayEnvelope.begin() + kHeaderSize,
                 relayEnvelope.begin() + kHeaderSize + innerLen);
}

// ── unseal ──────────────────────────────────────────────────────────────────

UnsealResult SealedEnvelope::unseal(const Bytes& recipientCurvePriv,
                                     const Bytes& recipientEdPub,
                                     const Bytes& sealedBytes,
                                     const Bytes& recipientKemPriv) {
    UnsealResult result;

    const size_t kPubLen   = 32;
    const size_t kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const size_t kTagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16
    const size_t kSigLen   = crypto_sign_BYTES;                             // 64

    if (recipientCurvePriv.size() != 32) return result;
    if (recipientEdPub.size()     != 32) return result;
    if (sealedBytes.size() < 2) return result;

    // Only v2 format accepted.
    const uint8_t firstByte = sealedBytes[0];
    const size_t hybridMinSize    = 1 + kPubLen + kKemCtLen + kNonceLen + kEnvelopeIdLen + kPubLen + kSigLen + 2 + kTagLen;
    const size_t classicalMinSize = 1 + kPubLen + kNonceLen + kEnvelopeIdLen + kPubLen + kSigLen + 2 + kTagLen;

    bool hybrid = false;
    if (firstByte == kVersionHybridV2 && sealedBytes.size() >= hybridMinSize) {
        hybrid = true;
    } else if (firstByte == kVersionClassicalV2 && sealedBytes.size() >= classicalMinSize) {
        // versioned classical v2
    } else {
        return result;  // unknown / old / truncated
    }

    size_t offset = 1;

    // 1. Extract ephemeral X25519 public key
    Bytes ephPub(sealedBytes.begin() + offset, sealedBytes.begin() + offset + kPubLen);
    offset += kPubLen;

    // C2 fix: reject all-zeros or low-order ephemeral keys
    if (sodium_is_zero(ephPub.data(), ephPub.size())) return result;

    // 2. ECDH
    unsigned char ecdhShared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(ecdhShared,
                          recipientCurvePriv.data(),
                          ephPub.data()) != 0) {
        return result;
    }

    // C2 fix: verify contributory shared secret
    if (sodium_is_zero(ecdhShared, sizeof(ecdhShared))) {
        sodium_memzero(ecdhShared, sizeof(ecdhShared));
        return result;
    }

    // 3. If hybrid, decapsulate ML-KEM-768
    Bytes combinedIkm;

    if (hybrid) {
        Bytes kemCt(sealedBytes.begin() + offset,
                    sealedBytes.begin() + offset + kKemCtLen);
        offset += kKemCtLen;

        Bytes kemShared = CryptoEngine::kemDecaps(kemCt, recipientKemPriv);
        if (kemShared.empty()) {
            sodium_memzero(ecdhShared, sizeof(ecdhShared));
            return result;
        }

        combinedIkm.reserve(sizeof(ecdhShared) + kemShared.size());
        combinedIkm.insert(combinedIkm.end(), ecdhShared, ecdhShared + sizeof(ecdhShared));
        combinedIkm.insert(combinedIkm.end(), kemShared.begin(), kemShared.end());
        CryptoEngine::secureZero(kemShared);
    } else {
        combinedIkm.insert(combinedIkm.end(), ecdhShared, ecdhShared + sizeof(ecdhShared));
    }
    sodium_memzero(ecdhShared, sizeof(ecdhShared));

    // 4. Derive envelope key
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32,
                             combinedIkm.data(),
                             combinedIkm.size(),
                             nullptr, 0);
    sodium_memzero(combinedIkm.data(), combinedIkm.size());

    // 5. AEAD decrypt with AAD = ephPub || recipientEdPub
    if (sealedBytes.size() < offset + kNonceLen + kTagLen) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    const Bytes aad = buildAAD(ephPub, recipientEdPub);

    const uint8_t* nonce = sealedBytes.data() + offset;
    const uint8_t* c     = sealedBytes.data() + offset + kNonceLen;
    const size_t   cLen  = sealedBytes.size() - offset - kNonceLen;

    Bytes pt(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            aad.data(),
            aad.size(),
            nonce, envelopeKey) != 0) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    pt.resize(plen);
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 6. Parse envelope plaintext
    if (pt.size() < kEnvelopeIdLen + kPubLen + kSigLen + 2) return result;

    Bytes envelopeId(pt.begin(), pt.begin() + kEnvelopeIdLen);
    result.senderEdPub.assign(pt.begin() + kEnvelopeIdLen,
                               pt.begin() + kEnvelopeIdLen + kPubLen);
    Bytes edSig(pt.begin() + kEnvelopeIdLen + kPubLen,
                pt.begin() + kEnvelopeIdLen + kPubLen + kSigLen);
    size_t parseOffset = kEnvelopeIdLen + kPubLen + kSigLen;

    // dsaPubLen must be one of the recognized ML-DSA pub sizes (or 0).
    const uint16_t dsaPubLen = read_u16_be(pt.data() + parseOffset);
    parseOffset += 2;

    const bool knownDsaLen = (dsaPubLen == 0 || dsaPubLen == 1312 ||
                              dsaPubLen == 1952 || dsaPubLen == 2592);
    if (!knownDsaLen) return result;  // fail-closed on unrecognized length

    Bytes dsaPub, dsaSig;
    if (dsaPubLen > 0) {
        size_t dsaSigLen = 0;
        if (dsaPubLen == 1952)      dsaSigLen = 3309;
        else if (dsaPubLen == 1312) dsaSigLen = 2420;
        else if (dsaPubLen == 2592) dsaSigLen = 4627;

        if (dsaSigLen == 0 || pt.size() < parseOffset + dsaPubLen + dsaSigLen) {
            return result;  // fail-closed on malformed DSA extension
        }
        dsaPub.assign(pt.begin() + parseOffset, pt.begin() + parseOffset + dsaPubLen);
        parseOffset += dsaPubLen;
        dsaSig.assign(pt.begin() + parseOffset, pt.begin() + parseOffset + dsaSigLen);
        parseOffset += dsaSigLen;
    }

    result.innerPayload.assign(pt.begin() + parseOffset, pt.end());
    result.envelopeId = envelopeId;

    // 7. Verify Ed25519 signature over (envelopeId || innerPayload).
    Bytes signedBytes;
    signedBytes.reserve(envelopeId.size() + result.innerPayload.size());
    append(signedBytes, envelopeId);
    append(signedBytes, result.innerPayload);

    if (!CryptoEngine::verifySignature(edSig, signedBytes, result.senderEdPub)) {
        result.senderEdPub.clear();
        result.innerPayload.clear();
        result.envelopeId.clear();
        return result;
    }

    // 8. Verify ML-DSA-65 signature if present (hybrid — both must pass).
    if (!dsaSig.empty() && !dsaPub.empty()) {
        if (!CryptoEngine::dsaVerify(dsaSig, signedBytes, dsaPub)) {
            std::fprintf(stderr, "[SealedEnvelope] ML-DSA-65 signature verification FAILED\n");
            result.senderEdPub.clear();
            result.innerPayload.clear();
            result.envelopeId.clear();
            return result;
        }
    }

    result.valid = true;
    return result;
}
