#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QDebug>
#include <QtEndian>
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
                                 const QByteArray& recipientKemPub,
                                 const QByteArray& senderDsaPub,
                                 const QByteArray& senderDsaPriv) {
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
            CryptoEngine::secureZero(kemResult.sharedSecret);
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
    unsigned char edSig[crypto_sign_BYTES];
    crypto_sign_detached(edSig, nullptr,
                         reinterpret_cast<const unsigned char*>(innerPayload.constData()),
                         static_cast<unsigned long long>(innerPayload.size()),
                         reinterpret_cast<const unsigned char*>(senderEdPriv.constData()));

    // 5b. Hybrid: also sign with ML-DSA-65 if we have DSA keys
    const bool hybridSig = !senderDsaPub.isEmpty() && !senderDsaPriv.isEmpty();
    QByteArray dsaSig;
    if (hybridSig) {
        dsaSig = CryptoEngine::dsaSign(innerPayload, senderDsaPriv);
        if (dsaSig.isEmpty()) {
            // Fail-closed: if we have DSA keys but signing fails, don't send at all
            sodium_memzero(envelopeKey, sizeof(envelopeKey));
            return {};
        }
    }

    // 6. Build plaintext:
    //   Classical: senderEdPub(32) || edSig(64) || dsaPubLen(2, =0) || innerPayload
    //   Hybrid:    senderEdPub(32) || edSig(64) || dsaPubLen(2) || dsaPub(1952) || dsaSig(~3309) || innerPayload
    QByteArray envPlaintext;
    envPlaintext.append(senderEdPub);
    envPlaintext.append(reinterpret_cast<const char*>(edSig), crypto_sign_BYTES);

    if (hybridSig && !dsaSig.isEmpty()) {
        quint16 dpLen = qToBigEndian(static_cast<quint16>(senderDsaPub.size()));
        envPlaintext.append(reinterpret_cast<const char*>(&dpLen), 2);
        envPlaintext.append(senderDsaPub);
        envPlaintext.append(dsaSig);
    } else {
        // No DSA signature — write 0 length marker
        quint16 zero = 0;
        envPlaintext.append(reinterpret_cast<const char*>(&zero), 2);
    }

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

    // Detect envelope version:
    //   0x01 + size >= 1257  → hybrid (version 0x01)
    //   0x00 + size >= 169   → classical versioned (version 0x00)
    //   anything else        → legacy (no version byte, first byte is ephPub[0])
    //
    // Legacy envelopes: ephPub(32) + nonce(24) + ... = min 168 bytes, no version prefix.
    // A hybrid envelope is always >= 1257 bytes (1+32+1088+24+32+64+16), so if the
    // first byte is 0x01 but size < 1257, it's a legacy envelope whose ephPub starts with 0x01.
    const quint8 firstByte = static_cast<quint8>(sealedBytes[0]);

    const int hybridMinSize    = 1 + kPubLen + kKemCtLen + kNonceLen + kPubLen + kSigLen + kTagLen; // 1257
    const int classicalMinSize = 1 + kPubLen + kNonceLen + kPubLen + kSigLen + kTagLen;              // 169
    const int legacyMinSize    = kPubLen + kNonceLen + kPubLen + kSigLen + kTagLen;                   // 168

    bool hybrid = false;
    bool isLegacy = false;

    if (firstByte == kVersionHybrid && sealedBytes.size() >= hybridMinSize) {
        hybrid = true;
    } else if (firstByte == kVersionClassical && sealedBytes.size() >= classicalMinSize) {
        // versioned classical
    } else {
        // Legacy (no version byte) or ambiguous — treat as legacy
        isLegacy = true;
    }

    int offset = isLegacy ? 0 : 1;
    if (!hybrid && !isLegacy && sealedBytes.size() < classicalMinSize) return result;
    if (isLegacy && sealedBytes.size() < legacyMinSize) return result;

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

    // 6. Parse envelope plaintext
    //   senderEdPub(32) || edSig(64) || dsaPubLen(2) || [dsaPub || dsaSig] || innerPayload
    //   Legacy (no dsaPubLen): senderEdPub(32) || edSig(64) || innerPayload
    if (pt.size() < kPubLen + kSigLen) return result;

    result.senderEdPub = pt.left(kPubLen);
    QByteArray edSig = pt.mid(kPubLen, kSigLen);
    int parseOffset = kPubLen + kSigLen;

    // Check for DSA signature extension (dsaPubLen field).
    // Safety: only attempt to parse dsaPubLen if the value makes sense —
    // it must be 0 (explicit no-DSA) or a known ML-DSA pub size (1312, 1952, 2592).
    // This prevents legacy envelopes (where these 2 bytes are innerPayload) from
    // being misinterpreted as a DSA header.
    QByteArray dsaPub, dsaSig;
    if (pt.size() >= parseOffset + 2) {
        quint16 dsaPubLenBE;
        memcpy(&dsaPubLenBE, pt.constData() + parseOffset, 2);
        quint16 dsaPubLen = qFromBigEndian(dsaPubLenBE);

        // Only recognized values: 0, 1312, 1952, 2592
        const bool knownDsaLen = (dsaPubLen == 0 || dsaPubLen == 1312 ||
                                  dsaPubLen == 1952 || dsaPubLen == 2592);
        if (!knownDsaLen) dsaPubLen = 0;  // treat as legacy (no DSA field)

        if (dsaPubLen > 0) {
            // Hybrid DSA signature present. Determine sig length from the pub key size.
            // ML-DSA-65: pub=1952, sig=3309.  ML-DSA-44: pub=1312, sig=2420.  ML-DSA-87: pub=2592, sig=4627.
            int dsaSigLen = 0;
            if (dsaPubLen == 1952)      dsaSigLen = 3309;  // ML-DSA-65
            else if (dsaPubLen == 1312) dsaSigLen = 2420;  // ML-DSA-44
            else if (dsaPubLen == 2592) dsaSigLen = 4627;  // ML-DSA-87

            parseOffset += 2;
            if (dsaSigLen > 0 && pt.size() >= parseOffset + dsaPubLen + dsaSigLen) {
                dsaPub = pt.mid(parseOffset, dsaPubLen);
                parseOffset += dsaPubLen;
                dsaSig = pt.mid(parseOffset, dsaSigLen);
                parseOffset += dsaSigLen;
            } else {
                // Fail-closed: if DSA extension is present but malformed, reject entirely.
                // This prevents downgrade attacks where an attacker strips the PQ signature.
                return result;
            }
        } else if (dsaPubLen == 0) {
            // Explicit "no DSA" marker
            parseOffset += 2;
        }
        // else: legacy format (no dsaPubLen field) — parseOffset stays at kPubLen + kSigLen
    }

    result.innerPayload = pt.mid(parseOffset);

    // 7. Verify Ed25519 signature (always required)
    if (!CryptoEngine::verifySignature(edSig, result.innerPayload, result.senderEdPub)) {
        result.senderEdPub.clear();
        result.innerPayload.clear();
        return result;
    }

    // 8. Verify ML-DSA-65 signature if present (hybrid — both must pass)
    if (!dsaSig.isEmpty() && !dsaPub.isEmpty()) {
        if (!CryptoEngine::dsaVerify(dsaSig, result.innerPayload, dsaPub)) {
            qWarning() << "[SealedEnvelope] ML-DSA-65 signature verification FAILED";
            result.senderEdPub.clear();
            result.innerPayload.clear();
            return result;
        }
    }

    result.valid = true;
    return result;
}
