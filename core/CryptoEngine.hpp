#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/*
 * CryptoEngine — identity keys + crypto primitives.
 *
 * Owns the local Ed25519 identity, derived X25519 keys, ML-KEM-768 (PQ KEM),
 * and ML-DSA-65 (PQ signatures).  Handles encrypted persistence of the
 * private-key material via identity.json in the app data directory.
 *
 * Types: std::vector<uint8_t> for bytes, std::string (UTF-8) for text.
 * Migrated off Qt on 2026-04-18.
 */

using Bytes = std::vector<uint8_t>;

// ML-KEM-768 encapsulation result
struct KemEncapsResult {
    Bytes ciphertext;    // KEM ciphertext (1088 bytes for ML-KEM-768)
    Bytes sharedSecret;  // 32-byte shared secret
};

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Non-copyable — prevent accidental duplication of key material
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    // Set the app data directory (where identity.json lives).
    // If unset, falls back to the platform's default via the host-provided helper.
    // Must be called before ensureIdentity() on hosts that don't provide a default
    // (iOS, Android).  On desktop with Qt, a sensible default is computed.
    void setDataDir(std::string dir) { m_dataDir = std::move(dir); }

    void ensureIdentity();

    // Unified path: caller supplies a pre-derived 32-byte key for identity
    // file encryption (from HKDF(masterKey, "identity-unlock")).
    // Falls back to legacy per-salt Argon2 for v4 files, then re-encrypts as v5.
    void ensureIdentity(const Bytes& identityKey);

    void setPassphrase(const std::string& pass);
    bool hasPassphrase() const;

    const Bytes& identityPub()  const { return m_edPub;  }
    const Bytes& identityPriv() const { return m_edPriv; }

    // base64url helpers (no padding)
    static std::string toBase64Url(const Bytes& data);
    static Bytes       fromBase64Url(const std::string& s);

    // mailbox auth signing — returns base64url-encoded Ed25519 signature
    std::string signB64u(const Bytes& msgUtf8) const;

    // X25519 key accessors (derived from Ed25519 identity)
    const Bytes& curvePub()  const { return m_curvePub;  }
    const Bytes& curvePriv() const { return m_curvePriv; }

    // ML-KEM-768 key accessors (generated alongside Ed25519 identity)
    // Empty if PQ keys haven't been generated yet (legacy identity file)
    const Bytes& kemPub()  const { return m_kemPub;  }
    const Bytes& kemPriv() const { return m_kemPriv; }
    bool hasPQKeys() const { return !m_kemPub.empty(); }

    // ML-DSA-65 signature key accessors (generated alongside identity)
    const Bytes& dsaPub()  const { return m_dsaPub;  }
    const Bytes& dsaPriv() const { return m_dsaPriv; }
    bool hasDSAKeys() const { return !m_dsaPub.empty(); }

    // ML-KEM-768 operations (static — work with any keys, not just ours)
    // Returns (pub, priv) keypair. pub=1184 bytes, priv=2400 bytes.
    static std::pair<Bytes, Bytes> generateKemKeypair();

    // Encapsulate: generate shared secret and ciphertext for a recipient's KEM pub.
    // Returns empty fields on failure.
    static KemEncapsResult kemEncaps(const Bytes& recipientKemPub);

    // Decapsulate: recover shared secret from ciphertext using our KEM private key.
    // Returns empty on failure.
    static Bytes kemDecaps(const Bytes& ciphertext, const Bytes& kemPriv);

    // Generate a fresh ephemeral X25519 keypair (pub, priv)
    static std::pair<Bytes, Bytes> generateEphemeralX25519();

    // HKDF-style key derivation using keyed BLAKE2b — NOT RFC 5869.
    //
    // Extract: PRK = BLAKE2b-256(key=salt, input=ikm)   // 32-byte PRK
    // Expand : out = BLAKE2b(key=PRK, input=info||0x01) // single block
    //
    // Known deviations from RFC 5869 (audit M4):
    //   - RFC 5869 specifies HMAC-SHA-256; we use keyed BLAKE2b-256 as the PRF.
    //   - PRK is 32 bytes, not HashLen (64 for BLAKE2b-512).
    //   - Expand emits one block, so `outputLen` is capped at 64 bytes —
    //     larger requests return {}.
    //
    // The construction is sound (BLAKE2b is a secure PRF, salt is used as
    // the key in Extract, info is domain-separated via the 0x01 counter)
    // but any interoperable third-party implementation MUST match this
    // byte-for-byte and cannot drop in a stock RFC 5869 HKDF.  See
    // PROTOCOL.md §10.2 for the full construction spec.
    static Bytes hkdf(const Bytes& ikm, const Bytes& salt,
                      const Bytes& info, int outputLen = 32);

    // (deriveSharedKey32 removed in H1 fix — it produced a static-ECDH key
    // with no forward secrecy.  Use the Noise IK + Double Ratchet path in
    // SessionManager instead.)

    // AEAD (XChaCha20-Poly1305). Output = nonce(24) || ciphertext
    Bytes aeadEncrypt(const Bytes& key32, const Bytes& plaintext,
                      const Bytes& aad = {}) const;

    Bytes aeadDecrypt(const Bytes& key32, const Bytes& nonceAndCiphertext,
                      const Bytes& aad = {}) const;

    // Ed25519 signature verification (static — any key, not just ours)
    static bool verifySignature(const Bytes& sig, const Bytes& message,
                                const Bytes& edPub);

    // ML-DSA-65 operations (static)
    static std::pair<Bytes, Bytes> generateDsaKeypair();  // (pub, priv)
    static Bytes dsaSign(const Bytes& message, const Bytes& dsaPriv);
    static bool  dsaVerify(const Bytes& sig, const Bytes& message,
                           const Bytes& dsaPub);

    // Derive a master key from a passphrase using Argon2id.
    // Salt must be 16 bytes (use loadOrCreateSalt() to manage it).
    static Bytes deriveMasterKey(const std::string& passphrase, const Bytes& salt);

    // Derive a purpose-specific subkey from a master key via HKDF.
    static Bytes deriveSubkey(const Bytes& masterKey, const Bytes& info, int len = 32);

    // Load a salt file from disk, or create a new random 16-byte one.
    static Bytes loadOrCreateSalt(const std::string& path);

    // Securely zero a Bytes buffer in-place.
    static void secureZero(Bytes& buf);

    // Securely zero a std::string's buffer in-place.
    static void secureZero(std::string& str);

private:
    // Encrypted persistence helpers
    bool loadIdentityFromDisk();
    bool loadIdentityFromDisk(const Bytes& identityKey);  // v5 unified key path
    bool saveIdentityToDisk() const;
    bool saveIdentityToDisk(const Bytes& identityKey) const;  // v5 unified key path
    void deriveCurveKeysFromEd();
    void ensurePQKeys();
    void ensurePQKeys(const Bytes& identityKey);

    // Resolve identity.json path — uses m_dataDir, or a platform default.
    std::string identityPath() const;

    std::string m_dataDir;       // app data dir; "" = use platform default
    std::string m_passphrase;    // zeroed after ensureIdentity() completes
    Bytes       m_identityKey;   // v5: 32-byte key from HKDF(masterKey, "identity-unlock")

    Bytes m_edPub;     // 32
    Bytes m_edPriv;    // 64

    Bytes m_curvePub;  // 32
    Bytes m_curvePriv; // 32

    Bytes m_kemPub;    // 1184
    Bytes m_kemPriv;   // 2400

    Bytes m_dsaPub;    // 1952
    Bytes m_dsaPriv;   // 4032
};
