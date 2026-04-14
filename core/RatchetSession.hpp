#pragma once
#include <QByteArray>
#include <QMap>
#include <QPair>

/*
 * Double Ratchet Algorithm — hybrid X25519 + ML-KEM-768
 *
 * Initialized from the output of a Noise handshake (root key + DH keys).
 * Provides forward secrecy and post-compromise security via:
 *   - DH ratchet: new ephemeral X25519 keypair on each reply
 *   - KEM ratchet (hybrid): ML-KEM-768 encaps/decaps mixed into root key,
 *     runs one step behind the DH ratchet for PQ protection
 *   - Symmetric ratchet: KDF chain for per-message keys
 *
 * Skipped message keys are cached (bounded) for out-of-order delivery.
 */

struct RatchetHeader {
    QByteArray dhPub;          // 32 bytes — sender's current DH ratchet public key
    quint32    prevChainLen;   // number of messages in previous sending chain
    quint32    messageNum;     // index in current sending chain

    // PQ hybrid fields (may be empty for classical sessions)
    QByteArray kemPub;         // 1184 bytes — sender's current KEM ratchet public key
    QByteArray kemCt;          // 1088 bytes — KEM ciphertext encapsulated to peer's last KEM pub
                               //              (empty if we haven't received peer's KEM pub yet)

    QByteArray serialize() const;
    static RatchetHeader deserialize(const QByteArray& data, int& bytesRead);

    static constexpr int kClassicalSize = 32 + 4 + 4; // 40 bytes
};

class RatchetSession {
public:
    // Maximum number of skipped message keys to cache per session
    static constexpr int kMaxSkipped = 1000;

    // Initialize as the initiator after Noise handshake
    // rootKey = derived from Noise chaining key
    // remoteDhPub = responder's initial DH public key (from Noise ephemeral)
    // localDhPub/Priv = our initial DH keypair (Noise ephemeral, so responder knows it)
    // hybrid = true if this session should use ML-KEM-768 ratchet augmentation
    static RatchetSession initAsInitiator(const QByteArray& rootKey,
                                          const QByteArray& remoteDhPub,
                                          const QByteArray& localDhPub,
                                          const QByteArray& localDhPriv,
                                          bool hybrid = false);

    // Initialize as the responder after Noise handshake
    // rootKey = derived from Noise chaining key
    // localDhPub/Priv = our initial DH keypair (Noise ephemeral)
    // remoteDhPub = initiator's initial DH pub (Noise ephemeral from msg1)
    // hybrid = true if this session should use ML-KEM-768 ratchet augmentation
    static RatchetSession initAsResponder(const QByteArray& rootKey,
                                          const QByteArray& localDhPub,
                                          const QByteArray& localDhPriv,
                                          const QByteArray& remoteDhPub,
                                          bool hybrid = false);

    // Encrypt a plaintext message
    // Returns serialized header + ciphertext
    QByteArray encrypt(const QByteArray& plaintext);

    // Decrypt a received message
    // Input: serialized header + ciphertext (as produced by encrypt)
    QByteArray decrypt(const QByteArray& headerAndCiphertext);

    // Get the message key from the last encrypt() call
    // Useful for deriving sub-keys (e.g., file transfer keys)
    const QByteArray& lastMessageKey() const { return m_lastMessageKey; }

    // Serialization for DB persistence
    QByteArray serialize() const;
    static RatchetSession deserialize(const QByteArray& data);

    bool isValid() const { return m_rootKey.size() == 32; }

    RatchetSession() = default;

private:

    // KDF for root chain: (rootKey, dhOutput) -> (newRootKey, chainKey)
    static QPair<QByteArray, QByteArray> kdfRootKey(const QByteArray& rootKey,
                                                     const QByteArray& dhOutput);

    // KDF for message chain: chainKey -> (newChainKey, messageKey)
    static QPair<QByteArray, QByteArray> kdfChainKey(const QByteArray& chainKey);

    // Perform a DH ratchet step when we receive a new remote DH key
    // kemCt: KEM ciphertext from the peer (empty if peer hasn't sent one)
    void dhRatchetStep(const QByteArray& remoteDhPub,
                       const QByteArray& kemCt = {});

    // Try to decrypt using a skipped message key
    QByteArray trySkippedKeys(const RatchetHeader& header,
                              const QByteArray& ciphertext);

    // Skip ahead in receiving chain, caching message keys
    bool skipMessageKeys(const QByteArray& dhPub, quint32 until);

    // State
    QByteArray m_rootKey;          // 32 bytes — root chain key
    QByteArray m_sendChainKey;     // 32 bytes — sending symmetric chain
    QByteArray m_recvChainKey;     // 32 bytes — receiving symmetric chain

    QByteArray m_dhPub;            // 32 bytes — our current DH ratchet pub
    QByteArray m_dhPriv;           // 32 bytes — our current DH ratchet priv
    QByteArray m_remoteDhPub;      // 32 bytes — peer's current DH ratchet pub

    // ML-KEM-768 ratchet state (hybrid mode)
    bool       m_hybrid = false;
    QByteArray m_kemPub;           // 1184 — our current KEM ratchet pub
    QByteArray m_kemPriv;          // 2400 — our current KEM ratchet priv
    QByteArray m_remoteKemPub;     // 1184 — peer's current KEM ratchet pub (for encaps on next send)
    QByteArray m_pendingKemCt;     // 1088 — KEM ciphertext to include in next message header
                                   //         (produced during dhRatchetStep, consumed during encrypt)

    quint32 m_sendMsgNum = 0;      // messages sent in current chain
    quint32 m_recvMsgNum = 0;      // messages received in current chain
    quint32 m_prevChainLen = 0;    // length of previous sending chain

    QByteArray m_lastMessageKey;   // last message key from encrypt()

    // Skipped message keys: (dhPub, messageNum) -> messageKey
    QMap<QPair<QByteArray, quint32>, QByteArray> m_skippedKeys;
};
