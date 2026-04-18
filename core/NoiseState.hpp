#pragma once

#include <cstdint>
#include <vector>

/*
 * Noise Protocol Framework — IK handshake pattern (classical + hybrid PQ)
 *
 * Classical IK:
 *   <- s                         (responder's static key is pre-known)
 *   ...
 *   -> e, es, s, ss              (initiator message 1)
 *   <- e, ee, se                 (responder message 2)
 *
 * Hybrid IK (X25519 + ML-KEM-768):
 *   <- s, s_kem                  (responder's static + KEM pub pre-known)
 *   ...
 *   -> e, es, KEM_es, s, ss      (msg1: adds KEM encaps to responder's KEM pub)
 *   <- e, ee, KEM_ee, se         (msg2: adds KEM encaps to initiator's KEM pub)
 *
 * Each DH result is augmented: mixKey(dh_shared || kem_shared)
 * If either classical or PQ holds, the derived keys remain safe.
 *
 * Crypto primitives:
 *   DH:   X25519 (crypto_scalarmult)
 *   KEM:  ML-KEM-768 (liboqs)
 *   Hash: BLAKE2b-256 (crypto_generichash)
 *   AEAD: XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf)
 *
 * Types: std::vector<uint8_t> for all buffers (migrated off Qt 2026-04).
 */

using Bytes = std::vector<uint8_t>;

struct CipherState {
    Bytes    key;    // 32 bytes — symmetric transport key
    uint64_t nonce = 0;

    bool isValid() const { return key.size() == 32; }
};

struct HandshakeResult {
    CipherState sendCipher;   // initiator->responder (or responder->initiator)
    CipherState recvCipher;
    Bytes       handshakeHash; // 32 bytes — channel binding
};

class NoiseState {
public:
    enum Role { Initiator, Responder };

    // Create a classical initiator: we know the responder's static X25519 public key
    static NoiseState createInitiator(
        const Bytes& localStaticPub,   // our X25519 pub (32)
        const Bytes& localStaticPriv,  // our X25519 priv (32)
        const Bytes& remoteStaticPub   // peer's X25519 pub (32)
    );

    // Create a hybrid PQ initiator: also knows responder's KEM pub
    static NoiseState createHybridInitiator(
        const Bytes& localStaticPub,       // our X25519 pub (32)
        const Bytes& localStaticPriv,      // our X25519 priv (32)
        const Bytes& remoteStaticPub,      // peer's X25519 pub (32)
        const Bytes& localKemPub,          // our ML-KEM-768 pub (1184)
        const Bytes& localKemPriv,         // our ML-KEM-768 priv (2400)
        const Bytes& remoteKemPub          // peer's ML-KEM-768 pub (1184)
    );

    // Create a classical responder: we don't know the initiator's static key yet
    static NoiseState createResponder(
        const Bytes& localStaticPub,   // our X25519 pub (32)
        const Bytes& localStaticPriv   // our X25519 priv (32)
    );

    // Create a hybrid PQ responder: has own KEM keypair
    static NoiseState createHybridResponder(
        const Bytes& localStaticPub,       // our X25519 pub (32)
        const Bytes& localStaticPriv,      // our X25519 priv (32)
        const Bytes& localKemPub,          // our ML-KEM-768 pub (1184)
        const Bytes& localKemPriv          // our ML-KEM-768 priv (2400)
    );

    bool isHybrid() const { return m_hybrid; }

    // Initiator: produce handshake message 1
    // Returns the message bytes to send, or empty on error
    Bytes writeMessage1(const Bytes& payload = {});

    // Responder: process message 1, produce message 2
    // Decrypted payload (if any) is stored in payloadOut
    Bytes readMessage1AndWriteMessage2(const Bytes& msg1,
                                        Bytes& payloadOut,
                                        const Bytes& msg2Payload = {});

    // Initiator: process message 2 to complete the handshake
    // Decrypted payload (if any) is stored in payloadOut
    bool readMessage2(const Bytes& msg2, Bytes& payloadOut);

    // After handshake completes, extract the transport keys
    HandshakeResult finish();

    // Get the remote static public key (available after handshake)
    const Bytes& remoteStaticPub() const { return m_rs; }

    // Serialization for persisting mid-handshake state.
    // C3 fix: static private key (m_sk) is NOT serialized — it must be
    // re-injected via setStaticPrivateKey() after deserialization.
    Bytes serialize() const;
    static NoiseState deserialize(const Bytes& data);

    // Re-inject the static private key after deserialization (C3 fix).
    // Must be called before readMessage2() if this is an initiator.
    void setStaticPrivateKey(const Bytes& curvePriv) { m_sk = curvePriv; }

    Role role() const { return m_role; }
    bool isComplete() const { return m_complete; }

    // Chaining key after msg1 processing (incorporates e, es, s, ss DH secrets).
    // On initiator: valid after writeMessage1().
    // On responder: valid after readMessage1AndWriteMessage2().
    const Bytes& postMsg1ChainingKey() const { return m_ckAfterMsg1; }

    // Local ephemeral keypair (valid after writeMessage1 / readMessage1AndWriteMessage2).
    // Used to bootstrap the Double Ratchet with the same DH keys from the handshake.
    const Bytes& ephemeralPub()  const { return m_e; }
    const Bytes& ephemeralPriv() const { return m_ek; }

private:
    NoiseState() = default;

    // Noise symmetric state operations
    void  mixHash(const Bytes& data);
    void  mixKey(const Bytes& ikm);
    Bytes encryptAndHash(const Bytes& plaintext);
    Bytes decryptAndHash(const Bytes& ciphertext);
    static Bytes dh(const Bytes& priv, const Bytes& pub);

    // Split: derive two CipherState from chaining key
    void split(CipherState& c1, CipherState& c2);

    Role m_role = Initiator;
    bool m_complete = false;
    bool m_hybrid = false;  // true = hybrid X25519 + ML-KEM-768

    // Noise symmetric state
    Bytes    m_ck;          // chaining key (32)
    Bytes    m_ckAfterMsg1; // snapshot of m_ck after msg1 (for pre-key derivation)
    Bytes    m_h;   // handshake hash (32)
    Bytes    m_k;   // cipher key for handshake encryption (32, may be empty)
    uint64_t m_n = 0; // nonce for handshake cipher

    // Static keys (X25519)
    Bytes m_s;   // local static X25519 pub (32)
    Bytes m_sk;  // local static X25519 priv (32)
    Bytes m_rs;  // remote static X25519 pub (32)

    // Ephemeral keys (X25519)
    Bytes m_e;   // local ephemeral X25519 pub (32)
    Bytes m_ek;  // local ephemeral X25519 priv (32)
    Bytes m_re;  // remote ephemeral X25519 pub (32)

    // ML-KEM-768 keys (hybrid mode only)
    Bytes m_kemPub;      // local KEM pub (1184)
    Bytes m_kemPriv;     // local KEM priv (2400)
    Bytes m_rsKem;       // remote static KEM pub (1184)

    // Transport cipher states (populated on finish)
    CipherState m_c1, m_c2;
};
