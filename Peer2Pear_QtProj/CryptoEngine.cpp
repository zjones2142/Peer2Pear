#include "CryptoEngine.hpp"
#include <sodium.h>
#include <oqs/oqs.h>
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

static constexpr int kIdentityVersion = 5;  // v5 unified key derivation (single Argon2 call)

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
    secureZero(m_identityKey);
    secureZero(m_edPriv);
    secureZero(m_curvePriv);
    secureZero(m_kemPriv);
    secureZero(m_dsaPriv);
    // Public keys are not secret, but zero for hygiene
    secureZero(m_edPub);
    secureZero(m_curvePub);
    secureZero(m_kemPub);
    secureZero(m_dsaPub);
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

    // Load ML-KEM-768 keys if present (v3+ identity files)
    if (o.contains("kem_pub_b64u")) {
        m_kemPub = fromBase64Url(o.value("kem_pub_b64u").toString());

        const auto kemEnc = o.value("kem_priv_enc").toObject();
        const QByteArray kemSalt  = fromBase64Url(kemEnc.value("salt_b64u").toString());
        const QByteArray kemNonce = fromBase64Url(kemEnc.value("nonce_b64u").toString());
        const QByteArray kemCt    = fromBase64Url(kemEnc.value("ct_b64u").toString());

        // Key separation: derive a distinct key using the KEM-specific salt
        QByteArray kemKey32 = kemSalt.isEmpty()
            ? deriveKeyFromPassphrase(m_passphrase, salt)   // fallback for early v3 files
            : deriveKeyFromPassphrase(m_passphrase, kemSalt);
        if (!kemKey32.isEmpty()) {
            m_kemPriv = secretboxDecrypt(kemKey32, kemNonce, kemCt);
            secureZero(kemKey32);
        }
    }

    // Load ML-DSA-65 keys if present (v4+ identity files)
    if (o.contains("dsa_pub_b64u")) {
        m_dsaPub = fromBase64Url(o.value("dsa_pub_b64u").toString());

        const auto dsaEnc = o.value("dsa_priv_enc").toObject();
        const QByteArray dsaSalt  = fromBase64Url(dsaEnc.value("salt_b64u").toString());
        const QByteArray dsaNonce = fromBase64Url(dsaEnc.value("nonce_b64u").toString());
        const QByteArray dsaCt    = fromBase64Url(dsaEnc.value("ct_b64u").toString());

        if (!dsaSalt.isEmpty()) {
            QByteArray dsaKey32 = deriveKeyFromPassphrase(m_passphrase, dsaSalt);
            if (!dsaKey32.isEmpty()) {
                m_dsaPriv = secretboxDecrypt(dsaKey32, dsaNonce, dsaCt);
                secureZero(dsaKey32);
            }
        }
    }

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[CryptoEngine] Identity loaded from:" << path
             << "| KEM:" << (hasPQKeys() ? "yes" : "no")
             << "| DSA:" << (hasDSAKeys() ? "yes" : "no");
#endif

    return true;
}

// ── v5 unified-key load: single pre-derived 32-byte key for all private keys ──
bool CryptoEngine::loadIdentityFromDisk(const QByteArray& identityKey) {
    if (identityKey.size() != KEY_BYTES) return false;

    const QString path = identityPath();
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return false;

    const auto doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject()) return false;

    const auto o = doc.object();
    const int version = o.value("v").toInt(1);

    const QByteArray pub = fromBase64Url(o.value("ed_pub_b64u").toString());
    if (pub.size() != crypto_sign_PUBLICKEYBYTES) return false;

    // ── v5 file: all keys encrypted with the same identityKey ────────────
    if (version >= 5) {
        const auto enc = o.value("ed_priv_enc").toObject();
        const QByteArray nonce = fromBase64Url(enc.value("nonce_b64u").toString());
        const QByteArray ct    = fromBase64Url(enc.value("ct_b64u").toString());
        const QByteArray priv  = secretboxDecrypt(identityKey, nonce, ct);
        if (priv.size() != crypto_sign_SECRETKEYBYTES) return false;

        m_edPub  = pub;
        m_edPriv = priv;

        // KEM
        if (o.contains("kem_pub_b64u")) {
            m_kemPub = fromBase64Url(o.value("kem_pub_b64u").toString());
            const auto kemEnc = o.value("kem_priv_enc").toObject();
            m_kemPriv = secretboxDecrypt(identityKey,
                fromBase64Url(kemEnc.value("nonce_b64u").toString()),
                fromBase64Url(kemEnc.value("ct_b64u").toString()));
            // M2 fix: warn if KEM private key decryption failed (unexpected in v5)
            if (m_kemPriv.isEmpty() && !m_kemPub.isEmpty())
                qWarning() << "[CryptoEngine] v5 ML-KEM-768 private key decryption failed"
                           << "— falling back to classical-only crypto";
        }
        // DSA
        if (o.contains("dsa_pub_b64u")) {
            m_dsaPub = fromBase64Url(o.value("dsa_pub_b64u").toString());
            const auto dsaEnc = o.value("dsa_priv_enc").toObject();
            m_dsaPriv = secretboxDecrypt(identityKey,
                fromBase64Url(dsaEnc.value("nonce_b64u").toString()),
                fromBase64Url(dsaEnc.value("ct_b64u").toString()));
            // M2 fix: warn if DSA private key decryption failed (unexpected in v5)
            if (m_dsaPriv.isEmpty() && !m_dsaPub.isEmpty())
                qWarning() << "[CryptoEngine] v5 ML-DSA-65 private key decryption failed"
                           << "— signatures will use Ed25519 only";
        }

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[CryptoEngine] Identity v5 loaded from:" << path
                 << "| KEM:" << (hasPQKeys() ? "yes" : "no")
                 << "| DSA:" << (hasDSAKeys() ? "yes" : "no");
#endif
        return true;
    }

    // ── v4 or earlier: legacy per-salt Argon2 derivation ─────────────────
    // Fall back to passphrase-based derivation for migration.
    if (!hasPassphrase()) return false;

    // Delegate to the legacy loader (which uses m_passphrase internally)
    if (!loadIdentityFromDisk()) return false;

    // M1 fix: passphrase no longer needed after legacy decrypt — zero early
    secureZero(m_passphrase);

    // Re-encrypt and save as v5 using the unified key
    if (saveIdentityToDisk(identityKey)) {
        qDebug() << "[CryptoEngine] Migrated identity.json v" << version << "→ v5";
    } else {
        qWarning() << "[CryptoEngine] identity.json migration to v5 failed"
                    << "— will retry next launch";
    }
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

    // Persist ML-KEM-768 keys if available
    if (hasPQKeys()) {
        j["kem_pub_b64u"] = toBase64Url(m_kemPub);

        // Key separation: generate a distinct salt for the KEM private key
        QByteArray kemSalt(SALT_BYTES, 0);
        randombytes_buf(kemSalt.data(), SALT_BYTES);
        QByteArray kemKey32 = deriveKeyFromPassphrase(m_passphrase, kemSalt);
        if (!kemKey32.isEmpty()) {
            QByteArray kemNonce, kemCt, kemDummySalt;
            if (secretboxEncrypt(kemKey32, m_kemPriv, kemDummySalt, kemNonce, kemCt)) {
                QJsonObject kemEnc;
                kemEnc["salt_b64u"]  = toBase64Url(kemSalt);
                kemEnc["nonce_b64u"] = toBase64Url(kemNonce);
                kemEnc["ct_b64u"]    = toBase64Url(kemCt);
                j["kem_priv_enc"] = kemEnc;
            }
            secureZero(kemKey32);
        }
    }

    // Persist ML-DSA-65 keys if available
    if (hasDSAKeys()) {
        j["dsa_pub_b64u"] = toBase64Url(m_dsaPub);

        QByteArray dsaSalt(SALT_BYTES, 0);
        randombytes_buf(dsaSalt.data(), SALT_BYTES);
        QByteArray dsaKey32 = deriveKeyFromPassphrase(m_passphrase, dsaSalt);
        if (!dsaKey32.isEmpty()) {
            QByteArray dsaNonce, dsaCt, dsaDummySalt;
            if (secretboxEncrypt(dsaKey32, m_dsaPriv, dsaDummySalt, dsaNonce, dsaCt)) {
                QJsonObject dsaEnc;
                dsaEnc["salt_b64u"]  = toBase64Url(dsaSalt);
                dsaEnc["nonce_b64u"] = toBase64Url(dsaNonce);
                dsaEnc["ct_b64u"]    = toBase64Url(dsaCt);
                j["dsa_priv_enc"] = dsaEnc;
            }
            secureZero(dsaKey32);
        }
    }

    QString path = identityPath();

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;

    f.write(QJsonDocument(j).toJson(QJsonDocument::Compact));
    f.close();

    // Print path to Qt console
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[CryptoEngine] Identity saved to:" << path;
#endif
    return true;
}

// ── v5 unified-key save: one pre-derived key, domain-tagged nonces ────────
//
// H1 defense-in-depth: all three private keys share the same identityKey.
// Security depends on nonce uniqueness (24-byte random, collision at ~2^96).
// As extra protection against OS RNG failure or VM snapshot rollback, we
// XOR a 1-byte key-index tag into the first byte of each random nonce.
// This guarantees Ed/KEM/DSA nonces differ even if randombytes_buf
// returns identical output for all three calls.
static void tagNonce(QByteArray& nonce, uint8_t keyIndex) {
    if (nonce.size() >= 1)
        nonce[0] = static_cast<char>(static_cast<uint8_t>(nonce[0]) ^ keyIndex);
}

bool CryptoEngine::saveIdentityToDisk(const QByteArray& identityKey) const {
    if (m_edPub.size()  != crypto_sign_PUBLICKEYBYTES)  return false;
    if (m_edPriv.size() != crypto_sign_SECRETKEYBYTES)  return false;
    if (identityKey.size() != KEY_BYTES) return false;

    // Ed25519 private key (tag 0x01)
    QByteArray edNonce, edCt, edDummy;
    if (!secretboxEncrypt(identityKey, m_edPriv, edDummy, edNonce, edCt))
        return false;
    tagNonce(edNonce, 0x01);
    // Re-encrypt with tagged nonce
    edCt.resize(m_edPriv.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(reinterpret_cast<unsigned char*>(edCt.data()),
                              reinterpret_cast<const unsigned char*>(m_edPriv.constData()),
                              static_cast<unsigned long long>(m_edPriv.size()),
                              reinterpret_cast<const unsigned char*>(edNonce.constData()),
                              reinterpret_cast<const unsigned char*>(identityKey.constData())) != 0)
        return false;

    QJsonObject edEnc;
    edEnc["nonce_b64u"] = toBase64Url(edNonce);
    edEnc["ct_b64u"]    = toBase64Url(edCt);

    QJsonObject j;
    j["v"]             = kIdentityVersion;
    j["ed_pub_b64u"]   = toBase64Url(m_edPub);
    j["ed_priv_enc"]   = edEnc;

    // ML-KEM-768 (tag 0x02)
    if (hasPQKeys()) {
        j["kem_pub_b64u"] = toBase64Url(m_kemPub);
        QByteArray kemNonce, kemCt, kemDummy;
        if (secretboxEncrypt(identityKey, m_kemPriv, kemDummy, kemNonce, kemCt)) {
            tagNonce(kemNonce, 0x02);
            kemCt.resize(m_kemPriv.size() + crypto_secretbox_MACBYTES);
            crypto_secretbox_easy(reinterpret_cast<unsigned char*>(kemCt.data()),
                                  reinterpret_cast<const unsigned char*>(m_kemPriv.constData()),
                                  static_cast<unsigned long long>(m_kemPriv.size()),
                                  reinterpret_cast<const unsigned char*>(kemNonce.constData()),
                                  reinterpret_cast<const unsigned char*>(identityKey.constData()));
            QJsonObject kemEnc;
            kemEnc["nonce_b64u"] = toBase64Url(kemNonce);
            kemEnc["ct_b64u"]    = toBase64Url(kemCt);
            j["kem_priv_enc"] = kemEnc;
        }
    }

    // ML-DSA-65 (tag 0x03)
    if (hasDSAKeys()) {
        j["dsa_pub_b64u"] = toBase64Url(m_dsaPub);
        QByteArray dsaNonce, dsaCt, dsaDummy;
        if (secretboxEncrypt(identityKey, m_dsaPriv, dsaDummy, dsaNonce, dsaCt)) {
            tagNonce(dsaNonce, 0x03);
            dsaCt.resize(m_dsaPriv.size() + crypto_secretbox_MACBYTES);
            crypto_secretbox_easy(reinterpret_cast<unsigned char*>(dsaCt.data()),
                                  reinterpret_cast<const unsigned char*>(m_dsaPriv.constData()),
                                  static_cast<unsigned long long>(m_dsaPriv.size()),
                                  reinterpret_cast<const unsigned char*>(dsaNonce.constData()),
                                  reinterpret_cast<const unsigned char*>(identityKey.constData()));
            QJsonObject dsaEnc;
            dsaEnc["nonce_b64u"] = toBase64Url(dsaNonce);
            dsaEnc["ct_b64u"]    = toBase64Url(dsaCt);
            j["dsa_priv_enc"] = dsaEnc;
        }
    }

    const QString path = identityPath();
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    f.write(QJsonDocument(j).toJson(QJsonDocument::Compact));
    f.close();

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[CryptoEngine] Identity v5 saved to:" << path;
#endif
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
        ensurePQKeys();  // generate + persist PQ keys if this is a v2 identity
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

    // Generate PQ keypairs on first run
    {
        auto [kPub, kPriv] = generateKemKeypair();
        m_kemPub  = kPub;
        m_kemPriv = kPriv;
        secureZero(kPriv);
    }
    {
        auto [dPub, dPriv] = generateDsaKeypair();
        m_dsaPub  = dPub;
        m_dsaPriv = dPriv;
        secureZero(dPriv);
    }

    if (!saveIdentityToDisk()) {
        secureZero(m_passphrase);
        throw std::runtime_error("Failed to save encrypted identity to disk");
    }

    // Passphrase is no longer needed — identity keys are in memory
    secureZero(m_passphrase);
}

// ── v5 unified ensureIdentity: caller passes pre-derived identityKey ─────
void CryptoEngine::ensureIdentity(const QByteArray& identityKey) {
    if (!m_edPub.isEmpty()) return;

    m_identityKey = identityKey;

    const QString path = identityPath();
    const bool identityExists = QFileInfo::exists(path);

    if (identityExists) {
        // Try v5 loader first (which handles v4 migration internally)
        if (!loadIdentityFromDisk(identityKey)) {
            secureZero(m_identityKey);
            secureZero(m_passphrase);
            throw std::runtime_error("Failed to decrypt identity (wrong passphrase or corrupted file)");
        }
        deriveCurveKeysFromEd();
        ensurePQKeys(identityKey);  // generate + persist PQ keys if missing
        secureZero(m_identityKey);
        secureZero(m_passphrase);
        return;
    }

    // First-run: generate new keypair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    (void)crypto_sign_keypair(pk, sk);

    m_edPub  = QByteArray(reinterpret_cast<const char*>(pk), sizeof(pk));
    m_edPriv = QByteArray(reinterpret_cast<const char*>(sk), sizeof(sk));
    sodium_memzero(sk, sizeof(sk));

    deriveCurveKeysFromEd();

    // Generate PQ keypairs on first run
    {
        auto [kPub, kPriv] = generateKemKeypair();
        m_kemPub  = kPub;
        m_kemPriv = kPriv;
        secureZero(kPriv);
    }
    {
        auto [dPub, dPriv] = generateDsaKeypair();
        m_dsaPub  = dPub;
        m_dsaPriv = dPriv;
        secureZero(dPriv);
    }

    if (!saveIdentityToDisk(identityKey)) {
        secureZero(m_identityKey);
        secureZero(m_passphrase);
        throw std::runtime_error("Failed to save encrypted identity to disk");
    }

    secureZero(m_identityKey);
    secureZero(m_passphrase);
}

// ---------------------------
// ML-KEM-768 (Post-Quantum)
// ---------------------------

std::pair<QByteArray, QByteArray> CryptoEngine::generateKemKeypair() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return {};

    QByteArray pub(static_cast<int>(kem->length_public_key), 0);
    QByteArray priv(static_cast<int>(kem->length_secret_key), 0);

    if (OQS_KEM_keypair(kem,
                         reinterpret_cast<uint8_t*>(pub.data()),
                         reinterpret_cast<uint8_t*>(priv.data())) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return {};
    }

    OQS_KEM_free(kem);
    return { pub, priv };
}

KemEncapsResult CryptoEngine::kemEncaps(const QByteArray& recipientKemPub) {
    KemEncapsResult result;
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return result;

    if (recipientKemPub.size() != static_cast<int>(kem->length_public_key)) {
        OQS_KEM_free(kem);
        return result;
    }

    result.ciphertext.resize(static_cast<int>(kem->length_ciphertext));
    result.sharedSecret.resize(static_cast<int>(kem->length_shared_secret));

    if (OQS_KEM_encaps(kem,
                        reinterpret_cast<uint8_t*>(result.ciphertext.data()),
                        reinterpret_cast<uint8_t*>(result.sharedSecret.data()),
                        reinterpret_cast<const uint8_t*>(recipientKemPub.constData())) != OQS_SUCCESS) {
        secureZero(result.ciphertext);
        secureZero(result.sharedSecret);
        OQS_KEM_free(kem);
        return result;
    }

    OQS_KEM_free(kem);
    return result;
}

QByteArray CryptoEngine::kemDecaps(const QByteArray& ciphertext, const QByteArray& kemPriv) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return {};

    if (ciphertext.size() != static_cast<int>(kem->length_ciphertext) ||
        kemPriv.size() != static_cast<int>(kem->length_secret_key)) {
        OQS_KEM_free(kem);
        return {};
    }

    QByteArray sharedSecret(static_cast<int>(kem->length_shared_secret), 0);

    if (OQS_KEM_decaps(kem,
                        reinterpret_cast<uint8_t*>(sharedSecret.data()),
                        reinterpret_cast<const uint8_t*>(ciphertext.constData()),
                        reinterpret_cast<const uint8_t*>(kemPriv.constData())) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return {};
    }

    OQS_KEM_free(kem);
    return sharedSecret;
}

void CryptoEngine::ensurePQKeys() {
    if (!hasPassphrase()) return;  // can't persist without passphrase

    bool changed = false;

    // Generate ML-KEM-768 keypair if missing
    if (!hasPQKeys()) {
        auto [pub, priv] = generateKemKeypair();
        if (pub.isEmpty()) {
            qWarning() << "[CryptoEngine] Failed to generate ML-KEM-768 keypair";
            return;
        }
        m_kemPub  = pub;
        m_kemPriv = priv;
        secureZero(priv);
        changed = true;
    }

    // Generate ML-DSA-65 keypair if missing
    if (!hasDSAKeys()) {
        auto [pub, priv] = generateDsaKeypair();
        if (pub.isEmpty()) {
            qWarning() << "[CryptoEngine] Failed to generate ML-DSA-65 keypair";
        } else {
            m_dsaPub  = pub;
            m_dsaPriv = priv;
            secureZero(priv);
            changed = true;
        }
    }

    if (changed) {
        if (saveIdentityToDisk()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[CryptoEngine] PQ keys generated and persisted"
                     << "| KEM:" << hasPQKeys() << "| DSA:" << hasDSAKeys();
#endif
        } else {
            qWarning() << "[CryptoEngine] Failed to persist PQ keys";
        }
    }
}

// ── v5 unified ensurePQKeys: uses pre-derived identityKey ────────────────
void CryptoEngine::ensurePQKeys(const QByteArray& identityKey) {
    if (identityKey.size() != KEY_BYTES) return;

    bool changed = false;

    if (!hasPQKeys()) {
        auto [pub, priv] = generateKemKeypair();
        if (pub.isEmpty()) {
            qWarning() << "[CryptoEngine] Failed to generate ML-KEM-768 keypair";
            return;
        }
        m_kemPub  = pub;
        m_kemPriv = priv;
        secureZero(priv);
        changed = true;
    }

    if (!hasDSAKeys()) {
        auto [pub, priv] = generateDsaKeypair();
        if (pub.isEmpty()) {
            qWarning() << "[CryptoEngine] Failed to generate ML-DSA-65 keypair";
        } else {
            m_dsaPub  = pub;
            m_dsaPriv = priv;
            secureZero(priv);
            changed = true;
        }
    }

    if (changed) {
        if (saveIdentityToDisk(identityKey)) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[CryptoEngine] PQ keys generated and persisted (v5)"
                     << "| KEM:" << hasPQKeys() << "| DSA:" << hasDSAKeys();
#endif
        } else {
            qWarning() << "[CryptoEngine] Failed to persist PQ keys (v5)";
        }
    }
}

// ---------------------------
// ML-DSA-65 (Post-Quantum Signatures)
// ---------------------------

std::pair<QByteArray, QByteArray> CryptoEngine::generateDsaKeypair() {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return {};

    QByteArray pub(static_cast<int>(dsa->length_public_key), 0);
    QByteArray priv(static_cast<int>(dsa->length_secret_key), 0);

    if (OQS_SIG_keypair(dsa,
                         reinterpret_cast<uint8_t*>(pub.data()),
                         reinterpret_cast<uint8_t*>(priv.data())) != OQS_SUCCESS) {
        OQS_SIG_free(dsa);
        return {};
    }

    OQS_SIG_free(dsa);
    return { pub, priv };
}

QByteArray CryptoEngine::dsaSign(const QByteArray& message, const QByteArray& dsaPriv) {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return {};

    if (dsaPriv.size() != static_cast<int>(dsa->length_secret_key)) {
        OQS_SIG_free(dsa);
        return {};
    }

    QByteArray sig(static_cast<int>(dsa->length_signature), 0);
    size_t sigLen = 0;

    if (OQS_SIG_sign(dsa,
                      reinterpret_cast<uint8_t*>(sig.data()), &sigLen,
                      reinterpret_cast<const uint8_t*>(message.constData()),
                      static_cast<size_t>(message.size()),
                      reinterpret_cast<const uint8_t*>(dsaPriv.constData())) != OQS_SUCCESS) {
        OQS_SIG_free(dsa);
        return {};
    }

    sig.resize(static_cast<int>(sigLen));
    OQS_SIG_free(dsa);
    return sig;
}

bool CryptoEngine::dsaVerify(const QByteArray& sig, const QByteArray& message,
                              const QByteArray& dsaPub) {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return false;

    if (dsaPub.size() != static_cast<int>(dsa->length_public_key)) {
        OQS_SIG_free(dsa);
        return false;
    }

    const bool ok = OQS_SIG_verify(dsa,
                                    reinterpret_cast<const uint8_t*>(message.constData()),
                                    static_cast<size_t>(message.size()),
                                    reinterpret_cast<const uint8_t*>(sig.constData()),
                                    static_cast<size_t>(sig.size()),
                                    reinterpret_cast<const uint8_t*>(dsaPub.constData())) == OQS_SUCCESS;
    OQS_SIG_free(dsa);
    return ok;
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

    QByteArray result(reinterpret_cast<const char*>(out), outputLen);
    sodium_memzero(out, static_cast<size_t>(outputLen));
    sodium_memzero(prk, sizeof(prk));
    return result;
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

// ---------------------------
// Master key derivation (Argon2id)
// ---------------------------

QByteArray CryptoEngine::deriveMasterKey(const QString& passphrase, const QByteArray& salt)
{
    if (salt.size() != crypto_pwhash_SALTBYTES) {
        qWarning() << "deriveMasterKey: invalid salt size" << salt.size();
        return {};
    }

    QByteArray passUtf8 = passphrase.toUtf8();
    QByteArray masterKey(32, 0);

    // Mobile devices have tight memory limits — use INTERACTIVE (64 MB).
    // Desktop can afford MODERATE (256 MB) for stronger brute-force resistance.
    // The salt is device-local so different params per platform is safe.
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID)
    constexpr auto opsLimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    constexpr auto memLimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
#else
    constexpr auto opsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    constexpr auto memLimit = crypto_pwhash_MEMLIMIT_MODERATE;
#endif

    if (crypto_pwhash(
            reinterpret_cast<unsigned char*>(masterKey.data()),
            static_cast<unsigned long long>(masterKey.size()),
            passUtf8.constData(),
            static_cast<unsigned long long>(passUtf8.size()),
            reinterpret_cast<const unsigned char*>(salt.constData()),
            opsLimit,
            memLimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        secureZero(passUtf8);
        secureZero(masterKey);  // L1 fix: zero pre-allocated buffer on failure
        qWarning() << "deriveMasterKey: Argon2id failed (out of memory?)";
        return {};
    }

    secureZero(passUtf8);
    return masterKey;
}

QByteArray CryptoEngine::deriveSubkey(const QByteArray& masterKey,
                                       const QByteArray& info, int len)
{
    return hkdf(masterKey, {}, info, len);
}

QByteArray CryptoEngine::loadOrCreateSalt(const QString& path)
{
    const int expectedSize = static_cast<int>(crypto_pwhash_SALTBYTES);
    const QString backupPath = path + ".bak";

    // Try primary salt file
    QFile f(path);
    if (f.exists() && f.open(QIODevice::ReadOnly)) {
        QByteArray salt = f.readAll();
        f.close();
        if (salt.size() == expectedSize)
            return salt;
        qWarning() << "loadOrCreateSalt: primary salt file corrupt (size"
                    << salt.size() << "expected" << expectedSize << ")";
    }

    // Try backup salt file (recovery from corruption)
    QFile backup(backupPath);
    if (backup.exists() && backup.open(QIODevice::ReadOnly)) {
        QByteArray salt = backup.readAll();
        backup.close();
        if (salt.size() == expectedSize) {
            qWarning() << "loadOrCreateSalt: recovered salt from backup";
            // Restore primary from backup
            QFile restore(path);
            if (restore.open(QIODevice::WriteOnly)) {
                restore.write(salt);
                restore.flush();
                restore.close();
            }
            return salt;
        }
    }

    // Generate new random salt (first run only — both files missing)
    if (f.exists()) {
        // Primary exists but is corrupt AND backup is missing/corrupt.
        // This means data loss is imminent — refuse to silently regenerate.
        qCritical() << "loadOrCreateSalt: salt file corrupt with no backup!"
                     << "Cannot derive the correct encryption key."
                     << "Delete" << path << "and the database to start fresh.";
        return {};
    }

    QByteArray salt(expectedSize, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(salt.data()),
                    static_cast<size_t>(salt.size()));

    // Ensure parent directory exists
    QDir().mkpath(QFileInfo(path).absolutePath());

    // Write primary + backup, flush both to disk
    if (f.open(QIODevice::WriteOnly)) {
        f.write(salt);
        f.flush();
        f.close();
    } else {
        qWarning() << "loadOrCreateSalt: failed to write salt file:" << path;
    }

    QFile bak(backupPath);
    if (bak.open(QIODevice::WriteOnly)) {
        bak.write(salt);
        bak.flush();
        bak.close();
    }

    return salt;
}
