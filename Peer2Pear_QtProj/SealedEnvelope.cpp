#include "SealedEnvelope.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <cstring>

QByteArray SealedEnvelope::seal(const QByteArray& recipientCurvePub,
                                 const QByteArray& senderEdPub,
                                 const QByteArray& senderEdPriv,
                                 const QByteArray& innerPayload) {
    if (recipientCurvePub.size() != 32) return {};
    if (senderEdPub.size() != crypto_sign_PUBLICKEYBYTES) return {};
    if (senderEdPriv.size() != crypto_sign_SECRETKEYBYTES) return {};

    // 1. Generate ephemeral X25519 keypair
    auto [ephPub, ephPriv] = CryptoEngine::generateEphemeralX25519();

    // 2. ECDH: ephPriv × recipientCurvePub → shared secret
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(ephPriv.constData()),
                          reinterpret_cast<const unsigned char*>(recipientCurvePub.constData())) != 0) {
        return {};
    }

    // 3. Derive envelope key via BLAKE2b-256
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32, shared, sizeof(shared), nullptr, 0);
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(ephPriv.data(), ephPriv.size());

    // 4. Sign the inner payload with sender's Ed25519 key
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr,
                         reinterpret_cast<const unsigned char*>(innerPayload.constData()),
                         static_cast<unsigned long long>(innerPayload.size()),
                         reinterpret_cast<const unsigned char*>(senderEdPriv.constData()));

    // 5. Build plaintext for envelope: senderEdPub(32) || signature(64) || innerPayload
    QByteArray envPlaintext;
    envPlaintext.reserve(32 + 64 + innerPayload.size());
    envPlaintext.append(senderEdPub);
    envPlaintext.append(reinterpret_cast<const char*>(sig), crypto_sign_BYTES);
    envPlaintext.append(innerPayload);

    // 6. AEAD encrypt with envelope key (random nonce)
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray ct;
    ct.resize(static_cast<int>(sizeof(nonce)) + envPlaintext.size() +
              crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    // AAD = ephemeral public key (binds the envelope key to the ephemeral)
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(ct.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(envPlaintext.constData()),
        static_cast<unsigned long long>(envPlaintext.size()),
        reinterpret_cast<const unsigned char*>(ephPub.constData()),
        static_cast<unsigned long long>(ephPub.size()),
        nullptr, nonce,
        envelopeKey);

    memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(static_cast<int>(sizeof(nonce) + clen));

    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 7. Output: ephemeralPub(32) || nonce(24) || ciphertext
    return ephPub + ct;
}

UnsealResult SealedEnvelope::unseal(const QByteArray& recipientCurvePriv,
                                     const QByteArray& sealedBytes) {
    UnsealResult result;

    const int kPubLen   = 32;
    const int kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const int kTagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16
    const int kSigLen   = crypto_sign_BYTES;                             // 64

    // Minimum: ephPub(32) + nonce(24) + senderEdPub(32) + sig(64) + tag(16) = 168
    const int kMinLen = kPubLen + kNonceLen + kPubLen + kSigLen + kTagLen;
    if (recipientCurvePriv.size() != 32) return result;
    if (sealedBytes.size() < kMinLen) return result;

    // 1. Extract ephemeral public key
    QByteArray ephPub = sealedBytes.left(kPubLen);
    QByteArray aeadData = sealedBytes.mid(kPubLen);

    // 2. ECDH: recipientCurvePriv × ephPub → shared secret
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(recipientCurvePriv.constData()),
                          reinterpret_cast<const unsigned char*>(ephPub.constData())) != 0) {
        return result;
    }

    // 3. Derive envelope key
    unsigned char envelopeKey[32];
    (void)crypto_generichash(envelopeKey, 32, shared, sizeof(shared), nullptr, 0);
    sodium_memzero(shared, sizeof(shared));

    // 4. AEAD decrypt (AAD = ephemeral public key)
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
        return result; // decryption failed
    }

    pt.resize(static_cast<int>(plen));
    sodium_memzero(envelopeKey, sizeof(envelopeKey));

    // 5. Parse: senderEdPub(32) || signature(64) || innerPayload
    if (pt.size() < kPubLen + kSigLen) return result;

    result.senderEdPub = pt.left(kPubLen);
    QByteArray sig = pt.mid(kPubLen, kSigLen);
    result.innerPayload = pt.mid(kPubLen + kSigLen);

    // 6. Verify Ed25519 signature over inner payload
    if (!CryptoEngine::verifySignature(sig, result.innerPayload, result.senderEdPub)) {
        result.senderEdPub.clear();
        result.innerPayload.clear();
        return result;
    }

    result.valid = true;
    return result;
}
