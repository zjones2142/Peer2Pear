#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QFileInfo>
#include <stdexcept>
#include <cstring>

// ---------------------------
// Helpers
// ---------------------------

static QString identityPath() {
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(base + "/keys");
    return base + "/keys/identity.json";
}

static constexpr int kIdentityVersion = 2;

static constexpr int SALT_BYTES  = crypto_pwhash_SALTBYTES;        // 16
static constexpr int KEY_BYTES   = crypto_secretbox_KEYBYTES;      // 32
static constexpr int NONCE_BYTES = crypto_secretbox_NONCEBYTES;    // 24

static QByteArray deriveKeyFromPassphrase(const QString& pass, const QByteArray& salt) {
    if (salt.size() != SALT_BYTES) return {};
    QByteArray key(KEY_BYTES, 0);

    QByteArray passUtf8 = pass.toUtf8();

    // INTERACTIVE is a good MVP setting; can bump later.
    const int rc = crypto_pwhash(
        reinterpret_cast<unsigned char*>(key.data()), KEY_BYTES,
        passUtf8.constData(), (unsigned long long)passUtf8.size(),
        reinterpret_cast<const unsigned char*>(salt.constData()),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT);

    // Zero the UTF-8 passphrase copy immediately after Argon2 is done with it
    CryptoEngine::secureZero(passUtf8);

    if (rc != 0) {
        CryptoEngine::secureZero(key);
        return {};
    }
    return key;
}

static bool secretboxEncrypt(const QByteArray& key32,
                             const QByteArray& plaintext,
                             QByteArray& outSalt,
                             QByteArray& outNonce,
                             QByteArray& outCiphertext) {
    if (key32.size() != KEY_BYTES) return false;

    outNonce.resize(NONCE_BYTES);
    randombytes_buf(outNonce.data(), NONCE_BYTES);

    outCiphertext.resize(plaintext.size() + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(reinterpret_cast<unsigned char*>(outCiphertext.data()),
                              reinterpret_cast<const unsigned char*>(plaintext.constData()),
                              (unsigned long long)plaintext.size(),
                              reinterpret_cast<const unsigned char*>(outNonce.constData()),
                              reinterpret_cast<const unsigned char*>(key32.constData())) != 0) {
        return false;
    }
    return true;
}

static QByteArray secretboxDecrypt(const QByteArray& key32,
                                   const QByteArray& nonce,
                                   const QByteArray& ciphertext) {
    if (key32.size() != KEY_BYTES) return {};
    if (nonce.size() != NONCE_BYTES) return {};
    if (ciphertext.size() < crypto_secretbox_MACBYTES) return {};

    QByteArray pt(ciphertext.size() - crypto_secretbox_MACBYTES, 0);

    if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char*>(pt.data()),
                                   reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                                   (unsigned long long)ciphertext.size(),
                                   reinterpret_cast<const unsigned char*>(nonce.constData()),
                                   reinterpret_cast<const unsigned char*>(key32.constData())) != 0) {
        return {}; // wrong passphrase or file tampered
    }
    return pt;
}

// ---------------------------
// CryptoEngine
// ---------------------------

CryptoEngine::CryptoEngine() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

CryptoEngine::~CryptoEngine() {
    secureZero(m_passphrase);
    secureZero(m_edPriv);
    secureZero(m_curvePriv);
    // Public keys are not secret, but zero for hygiene
    secureZero(m_edPub);
    secureZero(m_curvePub);
}

void CryptoEngine::secureZero(QByteArray& buf) {
    if (!buf.isEmpty())
        sodium_memzero(buf.data(), static_cast<size_t>(buf.size()));
    buf.clear();
}

void CryptoEngine::secureZero(QString& str) {
    if (!str.isEmpty())
        sodium_memzero(str.data(), static_cast<size_t>(str.size()) * sizeof(QChar));
    str.clear();
}

void CryptoEngine::setPassphrase(const QString& pass) {
    secureZero(m_passphrase);
    m_passphrase = pass;
}

bool CryptoEngine::hasPassphrase() const {
    return !m_passphrase.isEmpty();
}

// base64url helpers
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

// ---------------------------
// Persistence (encrypted private key)
// ---------------------------

bool CryptoEngine::loadIdentityFromDisk() {

    QString path = identityPath();
    QFile f(path);

    if (!f.exists())
        return false;

    if (!f.open(QIODevice::ReadOnly))
        return false;

    const auto doc = QJsonDocument::fromJson(f.readAll());
    f.close();

    if (!doc.isObject())
        return false;

    const auto o = doc.object();

    const QByteArray pub = fromBase64Url(o.value("ed_pub_b64u").toString());
    if (pub.size() != crypto_sign_PUBLICKEYBYTES)
        return false;

    if (!hasPassphrase())
        return false;

    const auto enc = o.value("ed_priv_enc").toObject();

    const QByteArray salt  = fromBase64Url(enc.value("salt_b64u").toString());
    const QByteArray nonce = fromBase64Url(enc.value("nonce_b64u").toString());
    const QByteArray ct    = fromBase64Url(enc.value("ct_b64u").toString());

    QByteArray key32 = deriveKeyFromPassphrase(m_passphrase, salt);
    if (key32.isEmpty())
        return false;

    const QByteArray priv = secretboxDecrypt(key32, nonce, ct);
    secureZero(key32);

    if (priv.size() != crypto_sign_SECRETKEYBYTES)
        return false;

    m_edPub = pub;
    m_edPriv = priv;

    qDebug() << "[CryptoEngine] Identity loaded from:" << path;

    return true;
}

bool CryptoEngine::saveIdentityToDisk() const {
    if (m_edPub.size() != crypto_sign_PUBLICKEYBYTES) return false;
    if (m_edPriv.size() != crypto_sign_SECRETKEYBYTES) return false;
    if (!hasPassphrase()) return false;

    // Generate salt
    QByteArray salt(SALT_BYTES, 0);
    randombytes_buf(salt.data(), SALT_BYTES);

    // Derive key
    QByteArray key32 = deriveKeyFromPassphrase(m_passphrase, salt);
    if (key32.isEmpty()) return false;

    // Encrypt private key
    QByteArray nonce, ct;
    QByteArray dummySalt; // not used; kept signature compatible
    const bool ok = secretboxEncrypt(key32, m_edPriv, dummySalt, nonce, ct);
    secureZero(key32);
    if (!ok) return false;

    QJsonObject enc;
    enc["salt_b64u"]  = toBase64Url(salt);
    enc["nonce_b64u"] = toBase64Url(nonce);
    enc["ct_b64u"]    = toBase64Url(ct);

    QJsonObject j;
    j["v"] = kIdentityVersion;
    j["ed_pub_b64u"] = toBase64Url(m_edPub);
    j["ed_priv_enc"] = enc;

    QString path = identityPath();

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;

    f.write(QJsonDocument(j).toJson(QJsonDocument::Compact));
    f.close();

    // Print path to Qt console
    qDebug() << "[CryptoEngine] Identity saved to:" << path;
    return true;
}

void CryptoEngine::deriveCurveKeysFromEd() {
    unsigned char cpk[crypto_box_PUBLICKEYBYTES];
    unsigned char csk[crypto_box_SECRETKEYBYTES];

    (void)crypto_sign_ed25519_pk_to_curve25519(cpk,
                                              reinterpret_cast<const unsigned char*>(m_edPub.constData()));
    (void)crypto_sign_ed25519_sk_to_curve25519(csk,
                                              reinterpret_cast<const unsigned char*>(m_edPriv.constData()));

    m_curvePub  = QByteArray(reinterpret_cast<const char*>(cpk), sizeof(cpk));
    m_curvePriv = QByteArray(reinterpret_cast<const char*>(csk), sizeof(csk));

    sodium_memzero(csk, sizeof(csk));
}

void CryptoEngine::ensureIdentity() {
    if (!m_edPub.isEmpty()) return;

    const QString path = identityPath();
    const bool identityExists = QFileInfo::exists(path);

    // If identity exists, REQUIRE passphrase and successful decrypt.
    if (identityExists) {
        if (!hasPassphrase()) {
            throw std::runtime_error("Identity exists but no passphrase provided");
        }
        if (!loadIdentityFromDisk()) {
            secureZero(m_passphrase);
            throw std::runtime_error("Failed to decrypt identity (wrong passphrase or corrupted file)");
        }
        deriveCurveKeysFromEd();
        secureZero(m_passphrase);
        return;
    }

    // If no identity exists, REQUIRE passphrase to create encrypted identity
    if (!hasPassphrase()) {
        throw std::runtime_error("No identity exists yet, but no passphrase provided to create one");
    }

    // First-run: generate new keypair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    (void)crypto_sign_keypair(pk, sk);

    m_edPub  = QByteArray(reinterpret_cast<const char*>(pk), sizeof(pk));
    m_edPriv = QByteArray(reinterpret_cast<const char*>(sk), sizeof(sk));
    sodium_memzero(sk, sizeof(sk));

    deriveCurveKeysFromEd();

    if (!saveIdentityToDisk()) {
        secureZero(m_passphrase);
        throw std::runtime_error("Failed to save encrypted identity to disk");
    }

    // Passphrase is no longer needed — identity keys are in memory
    secureZero(m_passphrase);
}

// ---------------------------
// Signing + key agreement + AEAD
// ---------------------------

QString CryptoEngine::signB64u(const QByteArray& msgUtf8) const {
    unsigned char sig[crypto_sign_BYTES];
    (void)crypto_sign_detached(sig, nullptr,
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

    unsigned char key[32];
    if (crypto_generichash(key, sizeof(key), shared, sizeof(shared), nullptr, 0) != 0) {
        sodium_memzero(shared, sizeof(shared));
        return {};
    }
    sodium_memzero(shared, sizeof(shared));
    QByteArray result(reinterpret_cast<const char*>(key), sizeof(key));
    sodium_memzero(key, sizeof(key));
    return result;
}

QByteArray CryptoEngine::aeadEncrypt(const QByteArray& key32,
                                     const QByteArray& plaintext,
                                     const QByteArray& aad) const {
    if (key32.size() != 32) return {};

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray out;
    out.resize(int(sizeof(nonce) + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES));

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size(),
        reinterpret_cast<const unsigned char*>(aad.constData()), aad.size(),
        nullptr, nonce,
        reinterpret_cast<const unsigned char*>(key32.constData())
        );

    std::memcpy(out.data(), nonce, sizeof(nonce));
    out.resize(int(sizeof(nonce) + clen));
    return out;
}

QByteArray CryptoEngine::aeadDecrypt(const QByteArray& key32,
                                     const QByteArray& nonceAndCiphertext,
                                     const QByteArray& aad) const {
    if (key32.size() != 32) return {};
    if (nonceAndCiphertext.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) return {};

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

// ---------------------------
// Ephemeral X25519 keypair
// ---------------------------

std::pair<QByteArray, QByteArray> CryptoEngine::generateEphemeralX25519() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    QByteArray pub(reinterpret_cast<const char*>(pk), sizeof(pk));
    QByteArray priv(reinterpret_cast<const char*>(sk), sizeof(sk));
    sodium_memzero(sk, sizeof(sk));
    return { pub, priv };
}

// ---------------------------
// HKDF using BLAKE2b
// ---------------------------

QByteArray CryptoEngine::hkdf(const QByteArray& ikm, const QByteArray& salt,
                               const QByteArray& info, int outputLen) {
    if (outputLen <= 0 || outputLen > 64) return {};

    // Extract: PRK = BLAKE2b(key=salt, input=ikm)
    unsigned char prk[64];
    const auto* saltPtr = salt.isEmpty() ? nullptr
                          : reinterpret_cast<const unsigned char*>(salt.constData());
    const size_t saltLen = salt.isEmpty() ? 0 : static_cast<size_t>(salt.size());

    if (crypto_generichash(prk, 32,
                           reinterpret_cast<const unsigned char*>(ikm.constData()),
                           static_cast<size_t>(ikm.size()),
                           saltPtr, saltLen) != 0)
        return {};

    // Expand: output = BLAKE2b(key=PRK, input=info || 0x01)
    QByteArray expand = info + QByteArray(1, 0x01);
    unsigned char out[64];
    if (crypto_generichash(out, static_cast<size_t>(outputLen),
                           reinterpret_cast<const unsigned char*>(expand.constData()),
                           static_cast<size_t>(expand.size()),
                           prk, 32) != 0) {
        sodium_memzero(prk, sizeof(prk));
        return {};
    }

    sodium_memzero(prk, sizeof(prk));
    return QByteArray(reinterpret_cast<const char*>(out), outputLen);
}

// ---------------------------
// Signature verification
// ---------------------------

bool CryptoEngine::verifySignature(const QByteArray& sig, const QByteArray& message,
                                    const QByteArray& edPub) {
    if (sig.size() != crypto_sign_BYTES) return false;
    if (edPub.size() != crypto_sign_PUBLICKEYBYTES) return false;

    return crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(sig.constData()),
        reinterpret_cast<const unsigned char*>(message.constData()),
        static_cast<unsigned long long>(message.size()),
        reinterpret_cast<const unsigned char*>(edPub.constData())) == 0;
}
