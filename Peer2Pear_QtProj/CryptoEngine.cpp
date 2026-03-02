#include "CryptoEngine.hpp"
#include <sodium.h>
#include <stdexcept>

CryptoEngine::CryptoEngine() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

void CryptoEngine::ensureIdentity() {
    if (!m_edPub.isEmpty()) return;

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    m_edPub  = QByteArray(reinterpret_cast<const char*>(pk), sizeof(pk));
    m_edPriv = QByteArray(reinterpret_cast<const char*>(sk), sizeof(sk));

    unsigned char cpk[crypto_box_PUBLICKEYBYTES];
    unsigned char csk[crypto_box_SECRETKEYBYTES];

    crypto_sign_ed25519_pk_to_curve25519(cpk, pk);
    crypto_sign_ed25519_sk_to_curve25519(csk, sk);

    m_curvePub  = QByteArray(reinterpret_cast<const char*>(cpk), sizeof(cpk));
    m_curvePriv = QByteArray(reinterpret_cast<const char*>(csk), sizeof(csk));
}

QString CryptoEngine::toBase64Url(const QByteArray& data) {
    const size_t maxlen = sodium_base64_ENCODED_LEN(data.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    QByteArray out;
    out.resize(int(maxlen));
    sodium_bin2base64(out.data(), out.size(),
                      reinterpret_cast<const unsigned char*>(data.constData()), data.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return QString::fromUtf8(out.constData());
}

QByteArray CryptoEngine::fromBase64Url(const QString& s) {
    QByteArray in = s.toUtf8();
    QByteArray out;
    out.resize(in.size());
    size_t bin_len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(),
                          in.constData(), in.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return {};
    }
    out.resize(int(bin_len));
    return out;
}

QString CryptoEngine::signB64u(const QByteArray& msgUtf8) const {
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr,
                         reinterpret_cast<const unsigned char*>(msgUtf8.constData()),
                         msgUtf8.size(),
                         reinterpret_cast<const unsigned char*>(m_edPriv.constData()));
    QByteArray s(reinterpret_cast<const char*>(sig), sizeof(sig));
    return toBase64Url(s);
}

QByteArray CryptoEngine::deriveSharedKey32(const QByteArray& peerEd25519Pub) const {
    if (peerEd25519Pub.size() != crypto_sign_PUBLICKEYBYTES) return {};

    unsigned char peerCurvePk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePk,
                                             reinterpret_cast<const unsigned char*>(peerEd25519Pub.constData())) != 0) return {};

    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(m_curvePriv.constData()),
                          peerCurvePk) != 0) return {};

    // Hash shared secret to 32 bytes key
    unsigned char key[32];
    crypto_generichash(key, sizeof(key), shared, sizeof(shared), nullptr, 0);
    sodium_memzero(shared, sizeof(shared));
    return QByteArray(reinterpret_cast<const char*>(key), sizeof(key));
}

QByteArray CryptoEngine::aeadEncrypt(const QByteArray& key32, const QByteArray& plaintext, const QByteArray& aad) const {
    if (key32.size() != 32) return {};

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray out;
    out.resize(sizeof(nonce) + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size(),
        reinterpret_cast<const unsigned char*>(aad.constData()), aad.size(),
        nullptr, nonce,
        reinterpret_cast<const unsigned char*>(key32.constData())
        );

    memcpy(out.data(), nonce, sizeof(nonce));
    out.resize(sizeof(nonce) + int(clen));
    return out;
}

QByteArray CryptoEngine::aeadDecrypt(const QByteArray& key32, const QByteArray& nonceAndCiphertext, const QByteArray& aad) const {
    if (key32.size() != 32) return {};
    if (nonceAndCiphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                        crypto_aead_xchacha20poly1305_ietf_ABYTES) return {};

    const unsigned char* nonce =
        reinterpret_cast<const unsigned char*>(nonceAndCiphertext.constData());
    const unsigned char* c =
        reinterpret_cast<const unsigned char*>(nonceAndCiphertext.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const int cLen = nonceAndCiphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    QByteArray out;
    out.resize(cLen);

    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(out.data()), &plen,
            nullptr,
            c, cLen,
            reinterpret_cast<const unsigned char*>(aad.constData()), aad.size(),
            nonce,
            reinterpret_cast<const unsigned char*>(key32.constData())
            ) != 0) {
        return {};
    }
    out.resize(int(plen));
    return out;
}
