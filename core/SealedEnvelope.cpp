#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QDebug>
#include <QtEndian>
#include <cstring>

// Version bytes for wire format (v2 — recipient-bound AAD + envelope-id)
static constexpr quint8 kVersionClassicalV2 = 0x02;
static constexpr quint8 kVersionHybridV2    = 0x03;

// ML-KEM-768 ciphertext size (from liboqs)
static constexpr int kKemCtLen = 1088;

// Random id used for receiver-side replay dedup.
static constexpr int kEnvelopeIdLen = 16;

// Build AAD: ephPub(32) || recipientEdPub(32).  Binds the routing recipient
// cryptographically so a malicious relay can't re-route the sealed blob.
static QByteArray buildAAD(const QByteArray& ephPub, const QByteArray& recipientEdPub)
{
    QByteArray aad;
    aad.reserve(ephPub.size() + recipientEdPub.size());
    aad.append(ephPub);
    aad.append(recipientEdPub);
    return aad;
}

QByteArray SealedEnvelope::seal(const QByteArray& recipientCurvePub,
                                 const QByteArray& recipientEdPub,
                                 const QByteArray& senderEdPub,
                                 const QByteArray& senderEdPriv,
                                 const QByteArray& innerPayload,
                                 const QByteArray& recipientKemPub,
                                 const QByteArray& senderDsaPub,
                                 const QByteArray& senderDsaPriv) {
    if (recipientCurvePub.size() != 32) return {};
    if (recipientEdPub.size() != 32) return {};
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

    // 5. Generate a random 16-byte envelopeId for receiver-side replay dedup.
    QByteArray envelopeId(kEnvelopeIdLen, 0);
    randombytes_buf(envelopeId.data(), static_cast<size_t>(kEnvelopeIdLen));

    // 6. Sign (envelopeId || innerPayload) with sender's Ed25519 key.
    //    Binding envelopeId into the signature means even if an attacker could
    //    guess the id, they can't splice it onto someone else's signed payload.
    QByteArray signedBytes;
    signedBytes.reserve(envelopeId.size() + innerPayload.size());
    signedBytes.append(envelopeId);
    signedBytes.append(innerPayload);

    unsigned char edSig[crypto_sign_BYTES];
    crypto_sign_detached(edSig, nullptr,
                         reinterpret_cast<const unsigned char*>(signedBytes.constData()),
                         static_cast<unsigned long long>(signedBytes.size()),
                         reinterpret_cast<const unsigned char*>(senderEdPriv.constData()));

    // 6b. Hybrid: also sign with ML-DSA-65 if we have DSA keys
    const bool hybridSig = !senderDsaPub.isEmpty() && !senderDsaPriv.isEmpty();
    QByteArray dsaSig;
    if (hybridSig) {
        dsaSig = CryptoEngine::dsaSign(signedBytes, senderDsaPriv);
        if (dsaSig.isEmpty()) {
            // Fail-closed: if we have DSA keys but signing fails, don't send at all
            sodium_memzero(envelopeKey, sizeof(envelopeKey));
            return {};
        }
    }

    // 7. Build plaintext:
    //   envelopeId(16) || senderEdPub(32) || edSig(64)
    //     || dsaPubLen(2) || [dsaPub || dsaSig] || innerPayload
    QByteArray envPlaintext;
    envPlaintext.append(envelopeId);
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

    // 8. AEAD encrypt with envelope key.
    //    AAD = ephPub || recipientEdPub (cryptographic binding to the intended recipient).
    const QByteArray aad = buildAAD(ephPub, recipientEdPub);

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
        reinterpret_cast<const unsigned char*>(aad.constData()),
        static_cast<unsigned long long>(aad.size()),
        nullptr, nonce, envelopeKey);

    memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(static_cast<int>(sizeof(nonce) + clen));
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 9. Wire format: version(1) || ephPub(32) || [kemCt(1088)] || AEAD
    QByteArray out;
    if (hybrid) {
        out.reserve(1 + 32 + kemCt.size() + ct.size());
        out.append(static_cast<char>(kVersionHybridV2));
        out.append(ephPub);
        out.append(kemCt);
    } else {
        out.reserve(1 + 32 + ct.size());
        out.append(static_cast<char>(kVersionClassicalV2));
        out.append(ephPub);
    }
    out.append(ct);
    return out;
}

// ── Relay routing header + envelope padding ──────────────────────────────────
//
// Wire format (routing layer, separate from the sealed envelope version):
//   [0x01][recipientEdPub(32)][innerLen(4 BE)][sealedBytes][randomPadding]
//
// The relay reads bytes 0-32 for routing. Everything after is opaque.
// Padding brings the total size to one of three fixed buckets so the relay
// can't distinguish message types (text vs file chunk vs handshake) by size.
//
// Buckets:
//   Small:  2 KiB   (text messages, presence, avatars, handshakes)
//   Medium: 16 KiB  (small files, group operations)
//   Large:  256 KiB  (file chunks — already near max envelope size)
//
// If the inner data exceeds 256 KiB, no padding is applied (it's already
// at the server's max envelope size).

static constexpr quint8 kRoutingVersion = 0x01;
static constexpr int kBucketSmall  =   2 * 1024;   //   2 KiB
static constexpr int kBucketMedium =  16 * 1024;   //  16 KiB
static constexpr int kBucketLarge  = 256 * 1024;   // 256 KiB

// Routing header overhead: version(1) + recipientEdPub(32) + innerLen(4) = 37 bytes
static constexpr int kHeaderSize = 1 + 32 + 4;

static int paddedSize(int rawSize)
{
    if (rawSize <= kBucketSmall)  return kBucketSmall;
    if (rawSize <= kBucketMedium) return kBucketMedium;
    if (rawSize <= kBucketLarge)  return kBucketLarge;
    return rawSize;  // exceeds largest bucket — no padding
}

QByteArray SealedEnvelope::wrapForRelay(const QByteArray& recipientEdPub,
                                         const QByteArray& sealedBytes)
{
    if (recipientEdPub.size() != 32 || sealedBytes.isEmpty()) return {};

    const int totalRaw = kHeaderSize + sealedBytes.size();
    const int totalPadded = paddedSize(totalRaw);
    const int padLen = totalPadded - totalRaw;

    QByteArray out;
    out.reserve(totalPadded);

    // Header: version + recipient + inner length
    out.append(static_cast<char>(kRoutingVersion));
    out.append(recipientEdPub);
    quint32 innerLenBE = qToBigEndian(static_cast<quint32>(sealedBytes.size()));
    out.append(reinterpret_cast<const char*>(&innerLenBE), 4);

    // Payload
    out.append(sealedBytes);

    // Random padding to reach bucket size
    if (padLen > 0) {
        QByteArray pad(padLen, 0);
        randombytes_buf(pad.data(), static_cast<size_t>(padLen));
        out.append(pad);
    }

    return out;
}

QByteArray SealedEnvelope::unwrapFromRelay(const QByteArray& relayEnvelope,
                                            QByteArray* recipientEdPub)
{
    // Minimum: version(1) + recipientEdPub(32) + innerLen(4) + at least 1 byte
    if (relayEnvelope.size() < kHeaderSize + 1) return {};
    if (static_cast<quint8>(relayEnvelope[0]) != kRoutingVersion) return {};

    if (recipientEdPub)
        *recipientEdPub = relayEnvelope.mid(1, 32);

    // Read inner length to strip padding
    quint32 innerLenBE;
    memcpy(&innerLenBE, relayEnvelope.constData() + 33, 4);
    quint32 innerLen = qFromBigEndian(innerLenBE);

    if (static_cast<int>(innerLen) > relayEnvelope.size() - kHeaderSize)
        return {};  // corrupt or truncated

    return relayEnvelope.mid(kHeaderSize, static_cast<int>(innerLen));
}

UnsealResult SealedEnvelope::unseal(const QByteArray& recipientCurvePriv,
                                     const QByteArray& recipientEdPub,
                                     const QByteArray& sealedBytes,
                                     const QByteArray& recipientKemPriv) {
    UnsealResult result;

    const int kPubLen   = 32;
    const int kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const int kTagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16
    const int kSigLen   = crypto_sign_BYTES;                             // 64

    if (recipientCurvePriv.size() != 32) return result;
    if (recipientEdPub.size()     != 32) return result;
    if (sealedBytes.size() < 2) return result;

    // Only v2 format accepted.  v0/v1 envelopes and unversioned legacy
    // envelopes are rejected — the format change is part of the security fix
    // (no way to downgrade to an envelope without recipient binding).
    const quint8 firstByte = static_cast<quint8>(sealedBytes[0]);
    const int hybridMinSize    = 1 + kPubLen + kKemCtLen + kNonceLen + kEnvelopeIdLen + kPubLen + kSigLen + 2 + kTagLen;
    const int classicalMinSize = 1 + kPubLen + kNonceLen + kEnvelopeIdLen + kPubLen + kSigLen + 2 + kTagLen;

    bool hybrid = false;
    if (firstByte == kVersionHybridV2 && sealedBytes.size() >= hybridMinSize) {
        hybrid = true;
    } else if (firstByte == kVersionClassicalV2 && sealedBytes.size() >= classicalMinSize) {
        // versioned classical v2
    } else {
        return result;  // unknown / old / truncated
    }

    int offset = 1;

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

    // 5. AEAD decrypt with AAD = ephPub || recipientEdPub
    //    A relay that rewrote the outer recipient in the routing header
    //    causes the receiving client to authenticate with a different
    //    recipientEdPub → AEAD fails. Binding enforced.
    QByteArray aeadData = sealedBytes.mid(offset);
    if (aeadData.size() < kNonceLen + kTagLen) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    const QByteArray aad = buildAAD(ephPub, recipientEdPub);

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(aeadData.constData());
    const unsigned char* c = reinterpret_cast<const unsigned char*>(aeadData.constData() + kNonceLen);
    int cLen = aeadData.size() - kNonceLen;

    QByteArray pt;
    pt.resize(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            reinterpret_cast<const unsigned char*>(aad.constData()),
            static_cast<unsigned long long>(aad.size()),
            nonce, envelopeKey) != 0) {
        sodium_memzero(envelopeKey, sizeof(envelopeKey));
        return result;
    }

    pt.resize(static_cast<int>(plen));
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 6. Parse envelope plaintext:
    //    envelopeId(16) || senderEdPub(32) || edSig(64) || dsaPubLen(2)
    //       || [dsaPub || dsaSig] || innerPayload
    if (pt.size() < kEnvelopeIdLen + kPubLen + kSigLen + 2) return result;

    QByteArray envelopeId = pt.mid(0, kEnvelopeIdLen);
    result.senderEdPub = pt.mid(kEnvelopeIdLen, kPubLen);
    QByteArray edSig   = pt.mid(kEnvelopeIdLen + kPubLen, kSigLen);
    int parseOffset    = kEnvelopeIdLen + kPubLen + kSigLen;

    // dsaPubLen must be one of the recognized ML-DSA pub sizes (or 0).
    quint16 dsaPubLenBE;
    memcpy(&dsaPubLenBE, pt.constData() + parseOffset, 2);
    quint16 dsaPubLen = qFromBigEndian(dsaPubLenBE);
    parseOffset += 2;

    const bool knownDsaLen = (dsaPubLen == 0 || dsaPubLen == 1312 ||
                              dsaPubLen == 1952 || dsaPubLen == 2592);
    if (!knownDsaLen) return result;  // fail-closed on unrecognized length

    QByteArray dsaPub, dsaSig;
    if (dsaPubLen > 0) {
        // ML-DSA-65: pub=1952, sig=3309.  ML-DSA-44: pub=1312, sig=2420.
        // ML-DSA-87: pub=2592, sig=4627.
        int dsaSigLen = 0;
        if (dsaPubLen == 1952)      dsaSigLen = 3309;
        else if (dsaPubLen == 1312) dsaSigLen = 2420;
        else if (dsaPubLen == 2592) dsaSigLen = 4627;

        if (dsaSigLen == 0 || pt.size() < parseOffset + dsaPubLen + dsaSigLen) {
            return result;  // fail-closed on malformed DSA extension
        }
        dsaPub = pt.mid(parseOffset, dsaPubLen);
        parseOffset += dsaPubLen;
        dsaSig = pt.mid(parseOffset, dsaSigLen);
        parseOffset += dsaSigLen;
    }

    result.innerPayload = pt.mid(parseOffset);
    result.envelopeId   = envelopeId;

    // 7. Verify Ed25519 signature over (envelopeId || innerPayload).
    QByteArray signedBytes;
    signedBytes.reserve(envelopeId.size() + result.innerPayload.size());
    signedBytes.append(envelopeId);
    signedBytes.append(result.innerPayload);

    if (!CryptoEngine::verifySignature(edSig, signedBytes, result.senderEdPub)) {
        result.senderEdPub.clear();
        result.innerPayload.clear();
        result.envelopeId.clear();
        return result;
    }

    // 8. Verify ML-DSA-65 signature if present (hybrid — both must pass).
    if (!dsaSig.isEmpty() && !dsaPub.isEmpty()) {
        if (!CryptoEngine::dsaVerify(dsaSig, signedBytes, dsaPub)) {
            qWarning() << "[SealedEnvelope] ML-DSA-65 signature verification FAILED";
            result.senderEdPub.clear();
            result.innerPayload.clear();
            result.envelopeId.clear();
            return result;
        }
    }

    result.valid = true;
    return result;
}
