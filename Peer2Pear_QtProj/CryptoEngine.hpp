#pragma once
#include <QByteArray>
#include <QString>

class CryptoEngine {
public:
    CryptoEngine();

    void ensureIdentity();

    const QByteArray& identityPub() const { return m_edPub; }
    const QByteArray& identityPriv() const { return m_edPriv; }

    // base64url helpers (no padding)
    static QString toBase64Url(const QByteArray& data);
    static QByteArray fromBase64Url(const QString& s);

    // mailbox auth signing
    QString signB64u(const QByteArray& msgUtf8) const;

    // derive per-peer shared 32-byte key using X25519 from Ed25519 keys
    QByteArray deriveSharedKey32(const QByteArray& peerEd25519Pub) const;

    // AEAD (XChaCha20-Poly1305). Output = nonce(24) || ciphertext
    QByteArray aeadEncrypt(const QByteArray& key32, const QByteArray& plaintext,
                           const QByteArray& aad = {}) const;

    QByteArray aeadDecrypt(const QByteArray& key32, const QByteArray& nonceAndCiphertext,
                           const QByteArray& aad = {}) const;

private:
    QByteArray m_edPub;   // 32
    QByteArray m_edPriv;  // 64

    QByteArray m_curvePub;  // 32
    QByteArray m_curvePriv; // 32
};
