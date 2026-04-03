#pragma once
#include <QByteArray>
#include <QString>
#include <utility>

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Non-copyable — prevent accidental duplication of key material
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    void ensureIdentity();

    void setPassphrase(const QString& pass);
    bool hasPassphrase() const;

    const QByteArray& identityPub() const { return m_edPub; }
    const QByteArray& identityPriv() const { return m_edPriv; }

    // base64url helpers (no padding)
    static QString toBase64Url(const QByteArray& data);
    static QByteArray fromBase64Url(const QString& s);

    // mailbox auth signing
    QString signB64u(const QByteArray& msgUtf8) const;

    // X25519 key accessors (derived from Ed25519 identity)
    const QByteArray& curvePub()  const { return m_curvePub;  }
    const QByteArray& curvePriv() const { return m_curvePriv; }

    // Generate a fresh ephemeral X25519 keypair (pub, priv)
    static std::pair<QByteArray, QByteArray> generateEphemeralX25519();

    // HKDF using BLAKE2b: derive outputLen bytes from input key material
    static QByteArray hkdf(const QByteArray& ikm, const QByteArray& salt,
                           const QByteArray& info, int outputLen = 32);

    // derive per-peer shared 32-byte key using X25519 from Ed25519 keys
    QByteArray deriveSharedKey32(const QByteArray& peerEd25519Pub) const;

    // AEAD (XChaCha20-Poly1305). Output = nonce(24) || ciphertext
    QByteArray aeadEncrypt(const QByteArray& key32, const QByteArray& plaintext,
                           const QByteArray& aad = {}) const;

    QByteArray aeadDecrypt(const QByteArray& key32, const QByteArray& nonceAndCiphertext,
                           const QByteArray& aad = {}) const;

    // Ed25519 signature verification (static — any key, not just ours)
    static bool verifySignature(const QByteArray& sig, const QByteArray& message,
                                const QByteArray& edPub);

    // Securely zero a QByteArray's backing buffer in-place.
    static void secureZero(QByteArray& buf);

    // Securely zero a QString's UTF-16 backing buffer in-place.
    static void secureZero(QString& str);

private:
    // Encrypted persistence helpers
    bool loadIdentityFromDisk();
    bool saveIdentityToDisk() const;
    void deriveCurveKeysFromEd();

    QString m_passphrase;   // zeroed after ensureIdentity() completes

    QByteArray m_edPub;     // 32  (public — not secret, but zeroed for hygiene)
    QByteArray m_edPriv;    // 64  (secret — zeroed in destructor)

    QByteArray m_curvePub;  // 32
    QByteArray m_curvePriv; // 32  (secret — zeroed in destructor)
};
