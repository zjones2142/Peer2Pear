#include "CryptoEngine.hpp"
#include <sodium.h>
#include <oqs/oqs.h>
#include <nlohmann/json.hpp>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

// QDebug is kept temporarily for logging parity with the rest of core/.
// Will be replaced by a tiny logging abstraction in a later phase.
#include "log.hpp"

// Platform-default data directory resolution.
// On desktop builds we use QStandardPaths to match prior behavior; mobile
// builds must call setDataDir() before ensureIdentity().
#ifdef QT_CORE_LIB
#include <QStandardPaths>
#include <QDir>
namespace {
std::string defaultDataDir() {
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(base);
    return base.toStdString();
}
}
#else
namespace {
std::string defaultDataDir() {
    return {};  // caller must supply via setDataDir()
}
}
#endif

using json = nlohmann::json;
namespace fs = std::filesystem;

// ---------------------------
// Helpers
// ---------------------------

static constexpr int kIdentityVersion = 5;  // v5 unified key derivation

static constexpr size_t SALT_BYTES  = crypto_pwhash_SALTBYTES;     // 16
static constexpr size_t KEY_BYTES   = crypto_secretbox_KEYBYTES;   // 32
static constexpr size_t NONCE_BYTES = crypto_secretbox_NONCEBYTES; // 24

namespace {

// Byte-string helpers — tiny local utilities to keep the rest of the file readable.
inline const uint8_t* u8ptr(const Bytes& b) {
    return b.empty() ? nullptr : b.data();
}

inline const uint8_t* u8ptr(const std::string& s) {
    return s.empty() ? nullptr : reinterpret_cast<const uint8_t*>(s.data());
}

inline size_t safeSize(const Bytes& b) { return b.size(); }
inline size_t safeSize(const std::string& s) { return s.size(); }

Bytes deriveKeyFromPassphrase(const std::string& pass, const Bytes& salt) {
    if (salt.size() != SALT_BYTES) return {};
    Bytes key(KEY_BYTES, 0);

    // Working copy of the passphrase bytes so we can zero after use.
    std::string passCopy = pass;

    const int rc = crypto_pwhash(
        key.data(), KEY_BYTES,
        passCopy.data(), static_cast<unsigned long long>(passCopy.size()),
        salt.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT);

    CryptoEngine::secureZero(passCopy);

    if (rc != 0) {
        CryptoEngine::secureZero(key);
        return {};
    }
    return key;
}

bool secretboxEncrypt(const Bytes& key32,
                      const Bytes& plaintext,
                      Bytes& outNonce,
                      Bytes& outCiphertext) {
    if (key32.size() != KEY_BYTES) return false;

    outNonce.assign(NONCE_BYTES, 0);
    randombytes_buf(outNonce.data(), NONCE_BYTES);

    outCiphertext.assign(plaintext.size() + crypto_secretbox_MACBYTES, 0);

    if (crypto_secretbox_easy(outCiphertext.data(),
                              plaintext.data(),
                              static_cast<unsigned long long>(plaintext.size()),
                              outNonce.data(),
                              key32.data()) != 0) {
        return false;
    }
    return true;
}

Bytes secretboxDecrypt(const Bytes& key32,
                       const Bytes& nonce,
                       const Bytes& ciphertext) {
    if (key32.size() != KEY_BYTES) return {};
    if (nonce.size() != NONCE_BYTES) return {};
    if (ciphertext.size() < crypto_secretbox_MACBYTES) return {};

    Bytes pt(ciphertext.size() - crypto_secretbox_MACBYTES, 0);

    if (crypto_secretbox_open_easy(pt.data(),
                                   ciphertext.data(),
                                   static_cast<unsigned long long>(ciphertext.size()),
                                   nonce.data(),
                                   key32.data()) != 0) {
        return {};
    }
    return pt;
}

// JSON helpers — fetch a string field, return empty if missing/null.
std::string jstr(const json& obj, const char* key) {
    if (!obj.is_object()) return {};
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

const json& jobj(const json& obj, const char* key) {
    static const json kNull = json::object();
    if (!obj.is_object()) return kNull;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_object()) return kNull;
    return *it;
}

}  // anonymous namespace

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

void CryptoEngine::secureZero(Bytes& buf) {
    if (!buf.empty())
        sodium_memzero(buf.data(), buf.size());
    buf.clear();
}

void CryptoEngine::secureZero(std::string& str) {
    if (!str.empty())
        sodium_memzero(str.data(), str.size());
    str.clear();
}

void CryptoEngine::setPassphrase(const std::string& pass) {
    secureZero(m_passphrase);
    m_passphrase = pass;
}

bool CryptoEngine::hasPassphrase() const {
    return !m_passphrase.empty();
}

std::string CryptoEngine::identityPath() const {
    fs::path base = m_dataDir.empty() ? fs::path(defaultDataDir()) : fs::path(m_dataDir);
    if (base.empty()) return {};  // mobile host forgot to setDataDir
    std::error_code ec;
    fs::create_directories(base / "keys", ec);
    return (base / "keys" / "identity.json").string();
}

// base64url helpers
std::string CryptoEngine::toBase64Url(const Bytes& data) {
    const size_t maxlen = sodium_base64_ENCODED_LEN(data.size(),
                                                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(maxlen, '\0');
    sodium_bin2base64(out.data(), out.size(),
                      data.data(), data.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    // sodium writes a NUL terminator; strip it.
    if (!out.empty() && out.back() == '\0')
        out.pop_back();
    // Also trim any trailing bytes past the actual encoded length.
    const auto firstNul = out.find('\0');
    if (firstNul != std::string::npos) out.resize(firstNul);
    return out;
}

Bytes CryptoEngine::fromBase64Url(const std::string& s) {
    Bytes out(s.size(), 0);
    size_t bin_len = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          s.data(), s.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return {};
    }
    out.resize(bin_len);
    return out;
}

// ---------------------------
// Persistence (encrypted private key)
// ---------------------------

bool CryptoEngine::loadIdentityFromDisk() {
    const std::string path = identityPath();
    if (path.empty() || !fs::exists(path)) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;

    json doc;
    try {
        f >> doc;
    } catch (const std::exception&) {
        return false;
    }
    if (!doc.is_object()) return false;

    const Bytes pub = fromBase64Url(jstr(doc, "ed_pub_b64u"));
    if (pub.size() != crypto_sign_PUBLICKEYBYTES) return false;

    if (!hasPassphrase()) return false;

    const json& enc = jobj(doc, "ed_priv_enc");

    const Bytes salt  = fromBase64Url(jstr(enc, "salt_b64u"));
    const Bytes nonce = fromBase64Url(jstr(enc, "nonce_b64u"));
    const Bytes ct    = fromBase64Url(jstr(enc, "ct_b64u"));

    Bytes key32 = deriveKeyFromPassphrase(m_passphrase, salt);
    if (key32.empty()) return false;

    const Bytes priv = secretboxDecrypt(key32, nonce, ct);
    secureZero(key32);

    if (priv.size() != crypto_sign_SECRETKEYBYTES) return false;

    m_edPub  = pub;
    m_edPriv = priv;

    // Load ML-KEM-768 keys if present (v3+ identity files)
    if (doc.contains("kem_pub_b64u")) {
        m_kemPub = fromBase64Url(jstr(doc, "kem_pub_b64u"));

        const json& kemEnc = jobj(doc, "kem_priv_enc");
        const Bytes kemSalt  = fromBase64Url(jstr(kemEnc, "salt_b64u"));
        const Bytes kemNonce = fromBase64Url(jstr(kemEnc, "nonce_b64u"));
        const Bytes kemCt    = fromBase64Url(jstr(kemEnc, "ct_b64u"));

        Bytes kemKey32 = kemSalt.empty()
            ? deriveKeyFromPassphrase(m_passphrase, salt)   // fallback for early v3 files
            : deriveKeyFromPassphrase(m_passphrase, kemSalt);
        if (!kemKey32.empty()) {
            m_kemPriv = secretboxDecrypt(kemKey32, kemNonce, kemCt);
            secureZero(kemKey32);
        }
    }

    // Load ML-DSA-65 keys if present (v4+ identity files)
    if (doc.contains("dsa_pub_b64u")) {
        m_dsaPub = fromBase64Url(jstr(doc, "dsa_pub_b64u"));

        const json& dsaEnc = jobj(doc, "dsa_priv_enc");
        const Bytes dsaSalt  = fromBase64Url(jstr(dsaEnc, "salt_b64u"));
        const Bytes dsaNonce = fromBase64Url(jstr(dsaEnc, "nonce_b64u"));
        const Bytes dsaCt    = fromBase64Url(jstr(dsaEnc, "ct_b64u"));

        if (!dsaSalt.empty()) {
            Bytes dsaKey32 = deriveKeyFromPassphrase(m_passphrase, dsaSalt);
            if (!dsaKey32.empty()) {
                m_dsaPriv = secretboxDecrypt(dsaKey32, dsaNonce, dsaCt);
                secureZero(dsaKey32);
            }
        }
    }

    P2P_LOG("[CryptoEngine] Identity loaded from:" << path
             << "| KEM:" << (hasPQKeys() ? "yes" : "no")
             << "| DSA:" << (hasDSAKeys() ? "yes" : "no"));

    return true;
}

// ── v5 unified-key load: single pre-derived 32-byte key for all private keys ──
bool CryptoEngine::loadIdentityFromDisk(const Bytes& identityKey) {
    if (identityKey.size() != KEY_BYTES) return false;

    const std::string path = identityPath();
    if (path.empty() || !fs::exists(path)) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;

    json doc;
    try { f >> doc; }
    catch (const std::exception&) { return false; }
    if (!doc.is_object()) return false;

    const int version = doc.value("v", 1);

    const Bytes pub = fromBase64Url(jstr(doc, "ed_pub_b64u"));
    if (pub.size() != crypto_sign_PUBLICKEYBYTES) return false;

    // ── v5 file: all keys encrypted with the same identityKey ────────────
    if (version >= 5) {
        const json& enc = jobj(doc, "ed_priv_enc");
        const Bytes nonce = fromBase64Url(jstr(enc, "nonce_b64u"));
        const Bytes ct    = fromBase64Url(jstr(enc, "ct_b64u"));
        const Bytes priv  = secretboxDecrypt(identityKey, nonce, ct);
        if (priv.size() != crypto_sign_SECRETKEYBYTES) return false;

        m_edPub  = pub;
        m_edPriv = priv;

        // KEM
        if (doc.contains("kem_pub_b64u")) {
            m_kemPub = fromBase64Url(jstr(doc, "kem_pub_b64u"));
            const json& kemEnc = jobj(doc, "kem_priv_enc");
            m_kemPriv = secretboxDecrypt(identityKey,
                fromBase64Url(jstr(kemEnc, "nonce_b64u")),
                fromBase64Url(jstr(kemEnc, "ct_b64u")));
            if (m_kemPriv.empty() && !m_kemPub.empty())
                P2P_WARN("[CryptoEngine] v5 ML-KEM-768 private key decryption failed"
                           << "— falling back to classical-only crypto");
        }
        // DSA
        if (doc.contains("dsa_pub_b64u")) {
            m_dsaPub = fromBase64Url(jstr(doc, "dsa_pub_b64u"));
            const json& dsaEnc = jobj(doc, "dsa_priv_enc");
            m_dsaPriv = secretboxDecrypt(identityKey,
                fromBase64Url(jstr(dsaEnc, "nonce_b64u")),
                fromBase64Url(jstr(dsaEnc, "ct_b64u")));
            if (m_dsaPriv.empty() && !m_dsaPub.empty())
                P2P_WARN("[CryptoEngine] v5 ML-DSA-65 private key decryption failed"
                           << "— signatures will use Ed25519 only");
        }

        P2P_LOG("[CryptoEngine] Identity v5 loaded from:" << path
                 << "| KEM:" << (hasPQKeys() ? "yes" : "no")
                 << "| DSA:" << (hasDSAKeys() ? "yes" : "no"));
        return true;
    }

    // ── v4 or earlier: legacy per-salt Argon2 derivation ─────────────────
    if (!hasPassphrase()) return false;
    if (!loadIdentityFromDisk()) return false;
    secureZero(m_passphrase);

    if (saveIdentityToDisk(identityKey)) {
        P2P_LOG("[CryptoEngine] Migrated identity.json v" << version << "→ v5");
    } else {
        P2P_WARN("[CryptoEngine] identity.json migration to v5 failed"
                    << "— will retry next launch");
    }
    return true;
}

bool CryptoEngine::saveIdentityToDisk() const {
    if (m_edPub.size()  != crypto_sign_PUBLICKEYBYTES) return false;
    if (m_edPriv.size() != crypto_sign_SECRETKEYBYTES) return false;
    if (!hasPassphrase()) return false;

    // Generate salt
    Bytes salt(SALT_BYTES, 0);
    randombytes_buf(salt.data(), SALT_BYTES);

    // Derive key
    Bytes key32 = deriveKeyFromPassphrase(m_passphrase, salt);
    if (key32.empty()) return false;

    // Encrypt private key
    Bytes nonce, ct;
    const bool ok = secretboxEncrypt(key32, m_edPriv, nonce, ct);
    secureZero(key32);
    if (!ok) return false;

    json enc;
    enc["salt_b64u"]  = toBase64Url(salt);
    enc["nonce_b64u"] = toBase64Url(nonce);
    enc["ct_b64u"]    = toBase64Url(ct);

    json j;
    j["v"] = kIdentityVersion;
    j["ed_pub_b64u"] = toBase64Url(m_edPub);
    j["ed_priv_enc"] = enc;

    // Persist ML-KEM-768 keys if available
    if (hasPQKeys()) {
        j["kem_pub_b64u"] = toBase64Url(m_kemPub);

        Bytes kemSalt(SALT_BYTES, 0);
        randombytes_buf(kemSalt.data(), SALT_BYTES);
        Bytes kemKey32 = deriveKeyFromPassphrase(m_passphrase, kemSalt);
        if (!kemKey32.empty()) {
            Bytes kemNonce, kemCt;
            if (secretboxEncrypt(kemKey32, m_kemPriv, kemNonce, kemCt)) {
                json kemEnc;
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

        Bytes dsaSalt(SALT_BYTES, 0);
        randombytes_buf(dsaSalt.data(), SALT_BYTES);
        Bytes dsaKey32 = deriveKeyFromPassphrase(m_passphrase, dsaSalt);
        if (!dsaKey32.empty()) {
            Bytes dsaNonce, dsaCt;
            if (secretboxEncrypt(dsaKey32, m_dsaPriv, dsaNonce, dsaCt)) {
                json dsaEnc;
                dsaEnc["salt_b64u"]  = toBase64Url(dsaSalt);
                dsaEnc["nonce_b64u"] = toBase64Url(dsaNonce);
                dsaEnc["ct_b64u"]    = toBase64Url(dsaCt);
                j["dsa_priv_enc"] = dsaEnc;
            }
            secureZero(dsaKey32);
        }
    }

    const std::string path = identityPath();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    const std::string encoded = j.dump();
    f.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    f.close();

    P2P_LOG("[CryptoEngine] Identity saved to:" << path);
    return true;
}

// ── v5 unified-key save: one pre-derived key, domain-tagged nonces ────────
//
// H1 defense-in-depth: all three private keys share the same identityKey.
// Security depends on nonce uniqueness (24-byte random, collision at ~2^96).
// As extra protection against OS RNG failure or VM snapshot rollback, we
// XOR a 1-byte key-index tag into the first byte of each random nonce.
static void tagNonce(Bytes& nonce, uint8_t keyIndex) {
    if (!nonce.empty())
        nonce[0] = static_cast<uint8_t>(nonce[0] ^ keyIndex);
}

bool CryptoEngine::saveIdentityToDisk(const Bytes& identityKey) const {
    if (m_edPub.size()  != crypto_sign_PUBLICKEYBYTES) return false;
    if (m_edPriv.size() != crypto_sign_SECRETKEYBYTES) return false;
    if (identityKey.size() != KEY_BYTES) return false;

    // Ed25519 private key (tag 0x01)
    Bytes edNonce, edCt;
    if (!secretboxEncrypt(identityKey, m_edPriv, edNonce, edCt))
        return false;
    tagNonce(edNonce, 0x01);
    // Re-encrypt with tagged nonce
    edCt.assign(m_edPriv.size() + crypto_secretbox_MACBYTES, 0);
    if (crypto_secretbox_easy(edCt.data(),
                              m_edPriv.data(),
                              static_cast<unsigned long long>(m_edPriv.size()),
                              edNonce.data(),
                              identityKey.data()) != 0)
        return false;

    json edEnc;
    edEnc["nonce_b64u"] = toBase64Url(edNonce);
    edEnc["ct_b64u"]    = toBase64Url(edCt);

    json j;
    j["v"]             = kIdentityVersion;
    j["ed_pub_b64u"]   = toBase64Url(m_edPub);
    j["ed_priv_enc"]   = edEnc;

    // ML-KEM-768 (tag 0x02)
    if (hasPQKeys()) {
        j["kem_pub_b64u"] = toBase64Url(m_kemPub);
        Bytes kemNonce, kemCt;
        if (secretboxEncrypt(identityKey, m_kemPriv, kemNonce, kemCt)) {
            tagNonce(kemNonce, 0x02);
            kemCt.assign(m_kemPriv.size() + crypto_secretbox_MACBYTES, 0);
            crypto_secretbox_easy(kemCt.data(),
                                  m_kemPriv.data(),
                                  static_cast<unsigned long long>(m_kemPriv.size()),
                                  kemNonce.data(),
                                  identityKey.data());
            json kemEnc;
            kemEnc["nonce_b64u"] = toBase64Url(kemNonce);
            kemEnc["ct_b64u"]    = toBase64Url(kemCt);
            j["kem_priv_enc"] = kemEnc;
        }
    }

    // ML-DSA-65 (tag 0x03)
    if (hasDSAKeys()) {
        j["dsa_pub_b64u"] = toBase64Url(m_dsaPub);
        Bytes dsaNonce, dsaCt;
        if (secretboxEncrypt(identityKey, m_dsaPriv, dsaNonce, dsaCt)) {
            tagNonce(dsaNonce, 0x03);
            dsaCt.assign(m_dsaPriv.size() + crypto_secretbox_MACBYTES, 0);
            crypto_secretbox_easy(dsaCt.data(),
                                  m_dsaPriv.data(),
                                  static_cast<unsigned long long>(m_dsaPriv.size()),
                                  dsaNonce.data(),
                                  identityKey.data());
            json dsaEnc;
            dsaEnc["nonce_b64u"] = toBase64Url(dsaNonce);
            dsaEnc["ct_b64u"]    = toBase64Url(dsaCt);
            j["dsa_priv_enc"] = dsaEnc;
        }
    }

    const std::string path = identityPath();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    const std::string encoded = j.dump();
    f.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    f.close();

    P2P_LOG("[CryptoEngine] Identity v5 saved to:" << path);
    return true;
}

void CryptoEngine::deriveCurveKeysFromEd() {
    unsigned char cpk[crypto_box_PUBLICKEYBYTES];
    unsigned char csk[crypto_box_SECRETKEYBYTES];

    (void)crypto_sign_ed25519_pk_to_curve25519(cpk, m_edPub.data());
    (void)crypto_sign_ed25519_sk_to_curve25519(csk, m_edPriv.data());

    m_curvePub  = Bytes(cpk, cpk + sizeof(cpk));
    m_curvePriv = Bytes(csk, csk + sizeof(csk));

    sodium_memzero(csk, sizeof(csk));
}

void CryptoEngine::ensureIdentity() {
    if (!m_edPub.empty()) return;

    const std::string path = identityPath();
    const bool identityExists = !path.empty() && fs::exists(path);

    if (identityExists) {
        if (!hasPassphrase()) {
            throw std::runtime_error("Identity exists but no passphrase provided");
        }
        if (!loadIdentityFromDisk()) {
            secureZero(m_passphrase);
            throw std::runtime_error("Failed to decrypt identity (wrong passphrase or corrupted file)");
        }
        deriveCurveKeysFromEd();
        ensurePQKeys();
        secureZero(m_passphrase);
        return;
    }

    if (!hasPassphrase()) {
        throw std::runtime_error("No identity exists yet, but no passphrase provided to create one");
    }

    // First-run: generate new keypair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    (void)crypto_sign_keypair(pk, sk);

    m_edPub  = Bytes(pk, pk + sizeof(pk));
    m_edPriv = Bytes(sk, sk + sizeof(sk));
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

    secureZero(m_passphrase);
}

// ── v5 unified ensureIdentity: caller passes pre-derived identityKey ─────
void CryptoEngine::ensureIdentity(const Bytes& identityKey) {
    if (!m_edPub.empty()) return;

    m_identityKey = identityKey;

    const std::string path = identityPath();
    const bool identityExists = !path.empty() && fs::exists(path);

    if (identityExists) {
        if (!loadIdentityFromDisk(identityKey)) {
            secureZero(m_identityKey);
            secureZero(m_passphrase);
            throw std::runtime_error("Failed to decrypt identity (wrong passphrase or corrupted file)");
        }
        deriveCurveKeysFromEd();
        ensurePQKeys(identityKey);
        secureZero(m_identityKey);
        secureZero(m_passphrase);
        return;
    }

    // First-run: generate new keypair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    (void)crypto_sign_keypair(pk, sk);

    m_edPub  = Bytes(pk, pk + sizeof(pk));
    m_edPriv = Bytes(sk, sk + sizeof(sk));
    sodium_memzero(sk, sizeof(sk));

    deriveCurveKeysFromEd();

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

std::pair<Bytes, Bytes> CryptoEngine::generateKemKeypair() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return {};

    Bytes pub(kem->length_public_key, 0);
    Bytes priv(kem->length_secret_key, 0);

    if (OQS_KEM_keypair(kem, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return {};
    }

    OQS_KEM_free(kem);
    return { pub, priv };
}

KemEncapsResult CryptoEngine::kemEncaps(const Bytes& recipientKemPub) {
    KemEncapsResult result;
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return result;

    if (recipientKemPub.size() != kem->length_public_key) {
        OQS_KEM_free(kem);
        return result;
    }

    result.ciphertext.assign(kem->length_ciphertext, 0);
    result.sharedSecret.assign(kem->length_shared_secret, 0);

    if (OQS_KEM_encaps(kem,
                        result.ciphertext.data(),
                        result.sharedSecret.data(),
                        recipientKemPub.data()) != OQS_SUCCESS) {
        secureZero(result.ciphertext);
        secureZero(result.sharedSecret);
        OQS_KEM_free(kem);
        return result;
    }

    OQS_KEM_free(kem);
    return result;
}

Bytes CryptoEngine::kemDecaps(const Bytes& ciphertext, const Bytes& kemPriv) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return {};

    if (ciphertext.size() != kem->length_ciphertext ||
        kemPriv.size()    != kem->length_secret_key) {
        OQS_KEM_free(kem);
        return {};
    }

    Bytes sharedSecret(kem->length_shared_secret, 0);

    if (OQS_KEM_decaps(kem,
                        sharedSecret.data(),
                        ciphertext.data(),
                        kemPriv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return {};
    }

    OQS_KEM_free(kem);
    return sharedSecret;
}

void CryptoEngine::ensurePQKeys() {
    if (!hasPassphrase()) return;  // can't persist without passphrase

    bool changed = false;

    if (!hasPQKeys()) {
        auto [pub, priv] = generateKemKeypair();
        if (pub.empty()) {
            P2P_WARN("[CryptoEngine] Failed to generate ML-KEM-768 keypair");
            return;
        }
        m_kemPub  = pub;
        m_kemPriv = priv;
        secureZero(priv);
        changed = true;
    }

    if (!hasDSAKeys()) {
        auto [pub, priv] = generateDsaKeypair();
        if (pub.empty()) {
            P2P_WARN("[CryptoEngine] Failed to generate ML-DSA-65 keypair");
        } else {
            m_dsaPub  = pub;
            m_dsaPriv = priv;
            secureZero(priv);
            changed = true;
        }
    }

    if (changed) {
        if (saveIdentityToDisk()) {
            P2P_LOG("[CryptoEngine] PQ keys generated and persisted"
                     << "| KEM:" << hasPQKeys() << "| DSA:" << hasDSAKeys());
        } else {
            P2P_WARN("[CryptoEngine] Failed to persist PQ keys");
        }
    }
}

void CryptoEngine::ensurePQKeys(const Bytes& identityKey) {
    if (identityKey.size() != KEY_BYTES) return;

    bool changed = false;

    if (!hasPQKeys()) {
        auto [pub, priv] = generateKemKeypair();
        if (pub.empty()) {
            P2P_WARN("[CryptoEngine] Failed to generate ML-KEM-768 keypair");
            return;
        }
        m_kemPub  = pub;
        m_kemPriv = priv;
        secureZero(priv);
        changed = true;
    }

    if (!hasDSAKeys()) {
        auto [pub, priv] = generateDsaKeypair();
        if (pub.empty()) {
            P2P_WARN("[CryptoEngine] Failed to generate ML-DSA-65 keypair");
        } else {
            m_dsaPub  = pub;
            m_dsaPriv = priv;
            secureZero(priv);
            changed = true;
        }
    }

    if (changed) {
        if (saveIdentityToDisk(identityKey)) {
            P2P_LOG("[CryptoEngine] PQ keys generated and persisted (v5)"
                     << "| KEM:" << hasPQKeys() << "| DSA:" << hasDSAKeys());
        } else {
            P2P_WARN("[CryptoEngine] Failed to persist PQ keys (v5)");
        }
    }
}

// ---------------------------
// ML-DSA-65 (Post-Quantum Signatures)
// ---------------------------

std::pair<Bytes, Bytes> CryptoEngine::generateDsaKeypair() {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return {};

    Bytes pub(dsa->length_public_key, 0);
    Bytes priv(dsa->length_secret_key, 0);

    if (OQS_SIG_keypair(dsa, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(dsa);
        return {};
    }

    OQS_SIG_free(dsa);
    return { pub, priv };
}

Bytes CryptoEngine::dsaSign(const Bytes& message, const Bytes& dsaPriv) {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return {};

    if (dsaPriv.size() != dsa->length_secret_key) {
        OQS_SIG_free(dsa);
        return {};
    }

    Bytes sig(dsa->length_signature, 0);
    size_t sigLen = 0;

    if (OQS_SIG_sign(dsa,
                      sig.data(), &sigLen,
                      message.data(),
                      message.size(),
                      dsaPriv.data()) != OQS_SUCCESS) {
        OQS_SIG_free(dsa);
        return {};
    }

    sig.resize(sigLen);
    OQS_SIG_free(dsa);
    return sig;
}

bool CryptoEngine::dsaVerify(const Bytes& sig, const Bytes& message,
                              const Bytes& dsaPub) {
    OQS_SIG* dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!dsa) return false;

    if (dsaPub.size() != dsa->length_public_key) {
        OQS_SIG_free(dsa);
        return false;
    }

    const bool ok = OQS_SIG_verify(dsa,
                                    message.data(),
                                    message.size(),
                                    sig.data(),
                                    sig.size(),
                                    dsaPub.data()) == OQS_SUCCESS;
    OQS_SIG_free(dsa);
    return ok;
}

// ---------------------------
// Signing + key agreement + AEAD
// ---------------------------

std::string CryptoEngine::signB64u(const Bytes& msgUtf8) const {
    unsigned char sig[crypto_sign_BYTES];
    (void)crypto_sign_detached(sig, nullptr,
                              msgUtf8.data(),
                              msgUtf8.size(),
                              m_edPriv.data());
    Bytes s(sig, sig + sizeof(sig));
    return toBase64Url(s);
}

// CryptoEngine::deriveSharedKey32 was removed in the H1 fix (2026-04-19).
// It computed a static X25519 shared secret from the peer's long-term
// Ed25519 identity key, which the legacy FROM: and P2P-fallback paths
// used to AEAD-encrypt messages with no forward secrecy.  Every sender
// now routes through the Noise IK + Double Ratchet session, so the
// static-ECDH helper is no longer reachable from anywhere in the tree.

Bytes CryptoEngine::aeadEncrypt(const Bytes& key32,
                                const Bytes& plaintext,
                                const Bytes& aad) const {
    if (key32.size() != 32) return {};

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    Bytes out(sizeof(nonce) + plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + sizeof(nonce), &clen,
        plaintext.data(), plaintext.size(),
        u8ptr(aad), aad.size(),
        nullptr, nonce,
        key32.data());

    std::memcpy(out.data(), nonce, sizeof(nonce));
    out.resize(sizeof(nonce) + clen);
    return out;
}

Bytes CryptoEngine::aeadDecrypt(const Bytes& key32,
                                const Bytes& nonceAndCiphertext,
                                const Bytes& aad) const {
    if (key32.size() != 32) return {};
    if (nonceAndCiphertext.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) return {};

    const unsigned char* nonce = nonceAndCiphertext.data();
    const unsigned char* c     = nonceAndCiphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t cLen = nonceAndCiphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    Bytes out(cLen, 0);

    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &plen,
            nullptr,
            c, cLen,
            u8ptr(aad), aad.size(),
            nonce,
            key32.data()) != 0) {
        return {};
    }

    out.resize(plen);
    return out;
}

// ---------------------------
// Ephemeral X25519 keypair
// ---------------------------

std::pair<Bytes, Bytes> CryptoEngine::generateEphemeralX25519() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    Bytes pub(pk, pk + sizeof(pk));
    Bytes priv(sk, sk + sizeof(sk));
    sodium_memzero(sk, sizeof(sk));
    return { pub, priv };
}

// ---------------------------
// Safety numbers — see header comment for construction details.
// Sort-and-hash is the whole trick; keep it boring so a third-party
// implementation matches byte-for-byte from the spec alone.
// ---------------------------

namespace {
// Lexicographic compare on two 32-byte pubkeys; memcmp-style.  Kept
// local so the sort order is explicit at every call site.
inline bool edLess(const Bytes& a, const Bytes& b) {
    return std::lexicographical_compare(
        a.begin(), a.end(), b.begin(), b.end());
}
}  // namespace

Bytes CryptoEngine::safetyFingerprint(const Bytes& edA, const Bytes& edB) {
    if (edA.size() != 32 || edB.size() != 32) return {};
    const Bytes& first  = edLess(edA, edB) ? edA : edB;
    const Bytes& second = edLess(edA, edB) ? edB : edA;

    Bytes input;
    input.reserve(64);
    input.insert(input.end(), first.begin(),  first.end());
    input.insert(input.end(), second.begin(), second.end());

    unsigned char out[32];
    if (crypto_generichash(out, sizeof(out),
                           input.data(), input.size(),
                           nullptr, 0) != 0) {
        return {};
    }
    return Bytes(out, out + sizeof(out));
}

std::string CryptoEngine::safetyNumber(const Bytes& edA, const Bytes& edB) {
    if (edA.size() != 32 || edB.size() != 32) return {};
    const Bytes& first  = edLess(edA, edB) ? edA : edB;
    const Bytes& second = edLess(edA, edB) ? edB : edA;

    Bytes input;
    input.reserve(64);
    input.insert(input.end(), first.begin(),  first.end());
    input.insert(input.end(), second.begin(), second.end());

    // BLAKE2b-512 gives 64 bytes — plenty for 12 groups × 5 bytes = 60.
    unsigned char h[64];
    if (crypto_generichash(h, sizeof(h),
                           input.data(), input.size(),
                           nullptr, 0) != 0) {
        return {};
    }

    std::string out;
    out.reserve(71);  // 12*5 digits + 11 spaces
    for (int i = 0; i < 12; ++i) {
        const unsigned char* p = h + i * 5;
        const uint64_t v =
            (uint64_t(p[0]) << 32) |
            (uint64_t(p[1]) << 24) |
            (uint64_t(p[2]) << 16) |
            (uint64_t(p[3]) <<  8) |
             uint64_t(p[4]);
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%05u",
                      static_cast<unsigned>(v % 100000ULL));
        if (i > 0) out += ' ';
        out += buf;
    }
    return out;
}

// ---------------------------
// HKDF-style KDF — keyed BLAKE2b, NOT RFC 5869 HMAC-HKDF.  See the header
// comment for the exact construction and the audit-M4 deviations.  The
// name "hkdf" is retained because the callers all use it, and a rename
// would churn the ratchet / envelope / identity derivation call sites.
// ---------------------------

Bytes CryptoEngine::hkdf(const Bytes& ikm, const Bytes& salt,
                         const Bytes& info, int outputLen) {
    if (outputLen <= 0 || outputLen > 64) return {};

    // Extract: PRK = BLAKE2b(key=salt, input=ikm)
    unsigned char prk[64];
    const unsigned char* saltPtr = salt.empty() ? nullptr : salt.data();
    const size_t saltLen = salt.size();

    if (crypto_generichash(prk, 32,
                           ikm.data(), ikm.size(),
                           saltPtr, saltLen) != 0)
        return {};

    // Expand: output = BLAKE2b(key=PRK, input=info || 0x01)
    Bytes expand = info;
    expand.push_back(0x01);
    unsigned char out[64];
    if (crypto_generichash(out, static_cast<size_t>(outputLen),
                           expand.data(), expand.size(),
                           prk, 32) != 0) {
        sodium_memzero(prk, sizeof(prk));
        return {};
    }

    Bytes result(out, out + outputLen);
    sodium_memzero(out, sizeof(out));
    sodium_memzero(prk, sizeof(prk));
    return result;
}

// ---------------------------
// Signature verification
// ---------------------------

bool CryptoEngine::verifySignature(const Bytes& sig, const Bytes& message,
                                    const Bytes& edPub) {
    if (sig.size()   != crypto_sign_BYTES)         return false;
    if (edPub.size() != crypto_sign_PUBLICKEYBYTES) return false;

    return crypto_sign_verify_detached(
        sig.data(),
        message.data(),
        static_cast<unsigned long long>(message.size()),
        edPub.data()) == 0;
}

// ---------------------------
// Master key derivation (Argon2id)
// ---------------------------

Bytes CryptoEngine::deriveMasterKey(const std::string& passphrase, const Bytes& salt) {
    if (salt.size() != crypto_pwhash_SALTBYTES) {
        P2P_WARN("deriveMasterKey: invalid salt size" << int(salt.size()));
        return {};
    }

    std::string passCopy = passphrase;
    Bytes masterKey(32, 0);

    // L1 audit fix (2026-04-19): raise the mobile Argon2 floor above
    // libsodium's INTERACTIVE tier (2 ops, 64 MiB — flagged as potentially
    // brute-forceable for short passphrases).  The new mobile tier uses
    //   - 3 iterations (MODERATE-level opslimit)
    //   - 128 MiB memory  (halfway between INTERACTIVE and MODERATE)
    // which roughly triples attacker cost per guess while staying inside
    // the memory budget of every supported iPhone (iPhone 8 and up).  Full
    // MODERATE (256 MiB) risks iOS jetsam termination on ≤3 GiB devices
    // during onboarding; that's the reason we don't just reuse the desktop
    // tier.  Android uses the same mobile tier.
    //
    // Wire-compat: this changes the master key that a given (passphrase,
    // salt) pair derives to, so mobile identity.json files created before
    // this bump can't be unlocked by post-bump builds.  The project has no
    // shipped mobile users yet; desktop is unchanged.
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID) \
    || (defined(__APPLE__) && TARGET_OS_IPHONE)
    constexpr auto opsLimit = 3ULL;                     // matches MODERATE ops
    constexpr auto memLimit = 128ULL * 1024 * 1024;     // 128 MiB
#else
    constexpr auto opsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    constexpr auto memLimit = crypto_pwhash_MEMLIMIT_MODERATE;
#endif

    if (crypto_pwhash(
            masterKey.data(),
            static_cast<unsigned long long>(masterKey.size()),
            passCopy.data(),
            static_cast<unsigned long long>(passCopy.size()),
            salt.data(),
            opsLimit,
            memLimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        secureZero(passCopy);
        secureZero(masterKey);
        P2P_WARN("deriveMasterKey: Argon2id failed (out of memory?)");
        return {};
    }

    secureZero(passCopy);
    return masterKey;
}

Bytes CryptoEngine::deriveSubkey(const Bytes& masterKey,
                                  const Bytes& info, int len) {
    return hkdf(masterKey, {}, info, len);
}

Bytes CryptoEngine::loadOrCreateSalt(const std::string& path) {
    const size_t expectedSize = crypto_pwhash_SALTBYTES;
    const std::string backupPath = path + ".bak";

    auto readAll = [](const std::string& p) -> Bytes {
        std::ifstream f(p, std::ios::binary);
        if (!f.is_open()) return {};
        std::vector<char> buf((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
        return Bytes(buf.begin(), buf.end());
    };
    auto writeAll = [](const std::string& p, const Bytes& b) -> bool {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
        f.flush();
        return static_cast<bool>(f);
    };

    // Try primary salt file
    if (fs::exists(path)) {
        Bytes salt = readAll(path);
        if (salt.size() == expectedSize) return salt;
        P2P_WARN("loadOrCreateSalt: primary salt file corrupt (size"
                    << int(salt.size()) << "expected" << int(expectedSize) << ")");
    }

    // Try backup salt file (recovery from corruption)
    if (fs::exists(backupPath)) {
        Bytes salt = readAll(backupPath);
        if (salt.size() == expectedSize) {
            P2P_WARN("loadOrCreateSalt: recovered salt from backup");
            writeAll(path, salt);
            return salt;
        }
    }

    // Both files missing-or-corrupt?
    if (fs::exists(path)) {
        P2P_CRITICAL("loadOrCreateSalt: salt file corrupt with no backup!"
                     << "Cannot derive the correct encryption key."
                     << "Delete" << path
                     << "and the database to start fresh.");
        return {};
    }

    // Generate new random salt
    Bytes salt(expectedSize, 0);
    randombytes_buf(salt.data(), salt.size());

    // Ensure parent directory exists
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    if (!writeAll(path, salt))
        P2P_WARN("loadOrCreateSalt: failed to write salt file:" << path);
    writeAll(backupPath, salt);

    return salt;
}
