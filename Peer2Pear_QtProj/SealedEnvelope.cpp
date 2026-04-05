#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <cstring>

// Version bytes for wire format
static constexpr quint8 kVersionClassical = 0x00;
static constexpr quint8 kVersionHybrid    = 0x01;

// ML-KEM-768 ciphertext size (from liboqs)
static constexpr int kKemCtLen = 1088;

QByteArray SealedEnvelope::seal(const QByteArray& recipientCurvePub,
                                 const QByteArray& senderEdPub,
                                 const QByteArray& senderEdPriv,
                                 const QByteArray& innerPayload,
                                 const QByteArray& recipientKemPub) {
    if (recipientCurvePub.size() != 32) return {};
    if (senderEdPub.size() != crypto_sign_PUBLICKEYBYTES) return {};
    if (senderEdPriv.size() != crypto_sign_SECRETKEYBYTES) return {};

    const bool hybrid = !recipientKemPub.isEmpty();

    // 1. Generate ephemeral X25519 keypair
    auto [ephPub, ephPriv] = CryptoEngine::generateEphemeralX25519();

    // 2. ECDH: ephPriv × recipientCurvePub → classical shared secret
    unsigned char ecdhShared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(ecdhShared,
                          reinterpret_cast<const unsigned char*>(ephPriv.constData()),
                          reinterpret_cast<const unsigned char*>(recipientCurvePub.constData())) != 0) {
        return {};
    }
    sodium_memzero(ephPriv.data(), ephPriv.size());

    // 3. If hybrid, also do ML-KEM-768 encapsulation
    QByteArray kemCt;
    QByteArray combinedIkm;

    if (hybrid) {
        KemEncapsResult kemResult = CryptoEngine::kemEncaps(recipientKemPub);
        if (kemResult.ciphertext.isEmpty()) {
            sodium_memzero(ecdhShared, sizeof(ecdhShared));
            return {};
        }
        kemCt = kemResult.ciphertext;

        // Combine: ecdhShared(32) || kemShared(32)
        combinedIkm = QByteArray(reinterpret_cast<const char*>(ecdhShared), sizeof(ecdhShared))
                     + kemResult.sharedSecret;
        CryptoEngine::secureZero(kemResult.sharedSecret);
    } else {
        combinedIkm = QByteArray(reinterpret_cast<const char*>(ecdhShared), sizeof(ecdhShared));
    }
    sodium_memzero(ecdhShared, sizeof(ecdhShared));

    // 4. Derive envelope key: BLAKE2b-256(combinedIkm)
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32,
                             reinterpret_cast<const unsigned char*>(combinedIkm.constData()),
                             static_cast<size_t>(combinedIkm.size()),
                             nullptr, 0);
    CryptoEngine::secureZero(combinedIkm);

    // 5. Sign the inner payload with sender's Ed25519 key
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr,
                         reinterpret_cast<const unsigned char*>(innerPayload.constData()),
                         static_cast<unsigned long long>(innerPayload.size()),
                         reinterpret_cast<const unsigned char*>(senderEdPriv.constData()));

    // 6. Build plaintext: senderEdPub(32) || signature(64) || innerPayload
    QByteArray envPlaintext;
    envPlaintext.reserve(32 + 64 + innerPayload.size());
    envPlaintext.append(senderEdPub);
    envPlaintext.append(reinterpret_cast<const char*>(sig), crypto_sign_BYTES);
    envPlaintext.append(innerPayload);

    // 7. AEAD encrypt with envelope key (random nonce, AAD = ephPub)
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray ct;
    ct.resize(static_cast<int>(sizeof(nonce)) + envPlaintext.size() +
              crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(ct.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(envPlaintext.constData()),
        static_cast<unsigned long long>(envPlaintext.size()),
        reinterpret_cast<const unsigned char*>(ephPub.constData()),
        static_cast<unsigned long long>(ephPub.size()),
        nullptr, nonce, envelopeKey);

    memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(static_cast<int>(sizeof(nonce) + clen));
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 8. Wire format: version(1) || ephPub(32) || [kemCt(1088)] || AEAD
    QByteArray out;
    if (hybrid) {
        out.reserve(1 + 32 + kemCt.size() + ct.size());
        out.append(static_cast<char>(kVersionHybrid));
        out.append(ephPub);
        out.append(kemCt);
    } else {
        out.reserve(1 + 32 + ct.size());
        out.append(static_cast<char>(kVersionClassical));
        out.append(ephPub);
    }
    out.append(ct);
    return out;
}

UnsealResult SealedEnvelope::unseal(const QByteArray& recipientCurvePriv,
                                     const QByteArray& sealedBytes,
                                     const QByteArray& recipientKemPriv) {
    UnsealResult result;

    const int kPubLen   = 32;
    const int kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const int kTagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16
    const int kSigLen   = crypto_sign_BYTES;                             // 64

    if (recipientCurvePriv.size() != 32) return result;
    if (sealedBytes.size() < 2) return result;  // need at least version + data

    // Parse version byte
    const quint8 version = static_cast<quint8>(sealedBytes[0]);

    // Handle legacy envelopes (no version byte — first byte is part of ephPub)
    // Legacy format: ephPub(32) || AEAD(...)  — no version prefix.
    // We detect legacy by checking if the version byte is NOT 0x00 or 0x01
    // AND the total size matches a classical envelope without a version byte.
    bool isLegacy = (version != kVersionClassical && version != kVersionHybrid);

    int offset = 0;
    if (!isLegacy) {
        offset = 1;  // skip version byte
    }

    bool hybrid = (!isLegacy && version == kVersionHybrid);

    // Minimum sizes
    const int classicalMin = offset + kPubLen + kNonceLen + kPubLen + kSigLen + kTagLen;
    const int hybridMin    = offset + kPubLen + kKemCtLen + kNonceLen + kPubLen + kSigLen + kTagLen;
    if (hybrid && sealedBytes.size() < hybridMin) return result;
    if (!hybrid && sealedBytes.size() < classicalMin) return result;

    // 1. Extract ephemeral X25519 public key
    QByteArray ephPub = sealedBytes.mid(offset, kPubLen);
    offset += kPubLen;

    // C2 fix: reject all-zeros or low-order ephemeral keys
    if (sodium_is_zero(reinterpret_cast<const unsigned char*>(ephPub.constData()),
                       static_cast<size_t>(ephPub.size()))) {
        return result;
    }

    // 2. ECDH
    unsigned char ecdhShared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(ecdhShared,
                          reinterpret_cast<const unsigned char*>(recipientCurvePriv.constData()),
                          reinterpret_cast<const unsigned char*>(ephPub.constData())) != 0) {
        return result;
    }

    // C2 fix: verify contributory shared secret
    if (sodium_is_zero(ecdhShared, sizeof(ecdhShared))) {
        sodium_memzero(ecdhShared, sizeof(ecdhShared));
        return result;
    }

    // 3. If hybrid, decapsulate ML-KEM-768
    QByteArray combinedIkm;

    if (hybrid) {
        QByteArray kemCt = sealedBytes.mid(offset, kKemCtLen);
        offset += kKemCtLen;

        QByteArray kemShared = CryptoEngine::kemDecaps(kemCt, recipientKemPriv);
        if (kemShared.isEmpty()) {
            sodium_memzero(ecdhShared, sizeof(ecdhShared));
            return result;
        }

        combinedIkm = QByteArray(reinterpret_cast<const char*>(ecdhShared), sizeof(ecdhShared))
                     + kemShared;
        CryptoEngine::secureZero(kemShared);
    } else {
        combinedIkm = QByteArray(reinterpret_cast<const char*>(ecdhShared), sizeof(ecdhShared));
    }
    sodium_memzero(ecdhShared, sizeof(ecdhShared));

    // 4. Derive envelope key
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32,
                             reinterpret_cast<const unsigned char*>(combinedIkm.constData()),
                             static_cast<size_t>(combinedIkm.size()),
                             nullptr, 0);
    CryptoEngine::secureZero(combinedIkm);

    // 5. AEAD decrypt (AAD = ephPub)
    QByteArray aeadData = sealedBytes.mid(offset);
    if (aeadData.size() < kNonceLen + kTagLen) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(aeadData.constData());
    const unsigned char* c = reinterpret_cast<const unsigned char*>(aeadData.constData() + kNonceLen);
    int cLen = aeadData.size() - kNonceLen;

    QByteArray pt;
    pt.resize(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            reinterpret_cast<const unsigned char*>(ephPub.constData()),
            static_cast<unsigned long long>(ephPub.size()),
            nonce, envelopeKey) != 0) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    pt.resize(static_cast<int>(plen));
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 6. Parse: senderEdPub(32) || signature(64) || innerPayload
    if (pt.size() < kPubLen + kSigLen) return result;

    result.senderEdPub = pt.left(kPubLen);
    QByteArray sig = pt.mid(kPubLen, kSigLen);
    result.innerPayload = pt.mid(kPubLen + kSigLen);

    // 7. Verify Ed25519 signature
    if (!CryptoEngine::verifySignature(sig, result.innerPayload, result.senderEdPub)) {
        result.senderEdPub.clear();
        result.innerPayload.clear();
        return result;
    }

    result.valid = true;
    return result;
}
