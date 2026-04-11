#pragma once
#include <QByteArray>

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
 */

struct CipherState {
    QByteArray key;    // 32 bytes — symmetric transport key
    quint64    nonce = 0;

    bool isValid() const { return key.size() == 32; }
};

struct HandshakeResult {
    CipherState sendCipher;   // initiator->responder (or responder->initiator)
    CipherState recvCipher;
    QByteArray  handshakeHash; // 32 bytes — channel binding
};

class NoiseState {
public:
    enum Role { Initiator, Responder };

    // Create a classical initiator: we know the responder's static X25519 public key
    static NoiseState createInitiator(
        const QByteArray& localStaticPub,   // our X25519 pub (32)
        const QByteArray& localStaticPriv,  // our X25519 priv (32)
        const QByteArray& remoteStaticPub   // peer's X25519 pub (32)
    );

    // Create a hybrid PQ initiator: also knows responder's KEM pub
    static NoiseState createHybridInitiator(
        const QByteArray& localStaticPub,       // our X25519 pub (32)
        const QByteArray& localStaticPriv,      // our X25519 priv (32)
        const QByteArray& remoteStaticPub,      // peer's X25519 pub (32)
        const QByteArray& localKemPub,          // our ML-KEM-768 pub (1184)
        const QByteArray& localKemPriv,         // our ML-KEM-768 priv (2400)
        const QByteArray& remoteKemPub          // peer's ML-KEM-768 pub (1184)
    );

    // Create a classical responder: we don't know the initiator's static key yet
    static NoiseState createResponder(
        const QByteArray& localStaticPub,   // our X25519 pub (32)
        const QByteArray& localStaticPriv   // our X25519 priv (32)
    );

    // Create a hybrid PQ responder: has own KEM keypair
    static NoiseState createHybridResponder(
        const QByteArray& localStaticPub,       // our X25519 pub (32)
        const QByteArray& localStaticPriv,      // our X25519 priv (32)
        const QByteArray& localKemPub,          // our ML-KEM-768 pub (1184)
        const QByteArray& localKemPriv          // our ML-KEM-768 priv (2400)
    );

    bool isHybrid() const { return m_hybrid; }

    // Initiator: produce handshake message 1
    // Returns the message bytes to send, or empty on error
    QByteArray writeMessage1(const QByteArray& payload = {});

    // Responder: process message 1, produce message 2
    // Decrypted payload (if any) is stored in payloadOut
    QByteArray readMessage1AndWriteMessage2(const QByteArray& msg1,
                                            QByteArray& payloadOut,
                                            const QByteArray& msg2Payload = {});

    // Initiator: process message 2 to complete the handshake
    // Decrypted payload (if any) is stored in payloadOut
    bool readMessage2(const QByteArray& msg2, QByteArray& payloadOut);

    // After handshake completes, extract the transport keys
    HandshakeResult finish();

    // Get the remote static public key (available after handshake)
    const QByteArray& remoteStaticPub() const { return m_rs; }

    // Serialization for persisting mid-handshake state.
    // C3 fix: static private key (m_sk) is NOT serialized — it must be
    // re-injected via setStaticPrivateKey() after deserialization.
    QByteArray serialize() const;
    static NoiseState deserialize(const QByteArray& data);

    // Re-inject the static private key after deserialization (C3 fix).
    // Must be called before readMessage2() if this is an initiator.
    void setStaticPrivateKey(const QByteArray& curvePriv) { m_sk = curvePriv; }

    Role role() const { return m_role; }
    bool isComplete() const { return m_complete; }

    // Chaining key after msg1 processing (incorporates e, es, s, ss DH secrets).
    // On initiator: valid after writeMessage1().
    // On responder: valid after readMessage1AndWriteMessage2().
    const QByteArray& postMsg1ChainingKey() const { return m_ckAfterMsg1; }

    // Local ephemeral keypair (valid after writeMessage1 / readMessage1AndWriteMessage2).
    // Used to bootstrap the Double Ratchet with the same DH keys from the handshake.
    const QByteArray& ephemeralPub()  const { return m_e; }
    const QByteArray& ephemeralPriv() const { return m_ek; }

private:
    NoiseState() = default;

    // Noise symmetric state operations
    void mixHash(const QByteArray& data);
    void mixKey(const QByteArray& ikm);
    QByteArray encryptAndHash(const QByteArray& plaintext);
    QByteArray decryptAndHash(const QByteArray& ciphertext);
    static QByteArray dh(const QByteArray& priv, const QByteArray& pub);

    // Split: derive two CipherState from chaining key
    void split(CipherState& c1, CipherState& c2);

    Role m_role = Initiator;
    bool m_complete = false;
    bool m_hybrid = false;  // true = hybrid X25519 + ML-KEM-768

    // Noise symmetric state
    QByteArray m_ck;          // chaining key (32)
    QByteArray m_ckAfterMsg1; // snapshot of m_ck after msg1 (for pre-key derivation)
    QByteArray m_h;   // handshake hash (32)
    QByteArray m_k;   // cipher key for handshake encryption (32, may be empty)
    quint64    m_n = 0; // nonce for handshake cipher

    // Static keys (X25519)
    QByteArray m_s;   // local static X25519 pub (32)
    QByteArray m_sk;  // local static X25519 priv (32)
    QByteArray m_rs;  // remote static X25519 pub (32)

    // Ephemeral keys (X25519)
    QByteArray m_e;   // local ephemeral X25519 pub (32)
    QByteArray m_ek;  // local ephemeral X25519 priv (32)
    QByteArray m_re;  // remote ephemeral X25519 pub (32)

    // ML-KEM-768 keys (hybrid mode only)
    QByteArray m_kemPub;      // local KEM pub (1184)
    QByteArray m_kemPriv;     // local KEM priv (2400)
    QByteArray m_rsKem;       // remote static KEM pub (1184)

    // Transport cipher states (populated on finish)
    CipherState m_c1, m_c2;
};
