#pragma once

#include "types.hpp"

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

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
 *
 * Types: std::vector<uint8_t> for all buffers.
 */


struct RatchetHeader {
    Bytes    dhPub;          // 32 bytes — sender's current DH ratchet public key
    uint32_t prevChainLen = 0;   // number of messages in previous sending chain
    uint32_t messageNum = 0;     // index in current sending chain

    // PQ hybrid fields (may be empty for classical sessions)
    Bytes kemPub;            // 1184 bytes — sender's current KEM ratchet public key
    Bytes kemCt;             // 1088 bytes — KEM ciphertext encapsulated to peer's last KEM pub
                             //              (empty if we haven't received peer's KEM pub yet)

    Bytes serialize() const;
    static RatchetHeader deserialize(const Bytes& data, size_t& bytesRead);

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
    static RatchetSession initAsInitiator(const Bytes& rootKey,
                                          const Bytes& remoteDhPub,
                                          const Bytes& localDhPub,
                                          const Bytes& localDhPriv,
                                          bool hybrid = false);

    // Initialize as the responder after Noise handshake
    // rootKey = derived from Noise chaining key
    // localDhPub/Priv = our initial DH keypair (Noise ephemeral)
    // remoteDhPub = initiator's initial DH pub (Noise ephemeral from msg1)
    // hybrid = true if this session should use ML-KEM-768 ratchet augmentation
    static RatchetSession initAsResponder(const Bytes& rootKey,
                                          const Bytes& localDhPub,
                                          const Bytes& localDhPriv,
                                          const Bytes& remoteDhPub,
                                          bool hybrid = false);

    // Encrypt a plaintext message
    // Returns serialized header + ciphertext
    Bytes encrypt(const Bytes& plaintext);

    // Decrypt a received message
    // Input: serialized header + ciphertext (as produced by encrypt)
    Bytes decrypt(const Bytes& headerAndCiphertext);

    // Get the message key from the last encrypt() call
    // Useful for deriving sub-keys (e.g., file transfer keys)
    const Bytes& lastMessageKey() const { return m_lastMessageKey; }

    // Serialization for DB persistence
    Bytes serialize() const;
    static RatchetSession deserialize(const Bytes& data);

    bool isValid() const { return m_rootKey.size() == 32; }

    RatchetSession() = default;

private:

    // KDF for root chain: (rootKey, dhOutput) -> (newRootKey, chainKey)
    static std::pair<Bytes, Bytes> kdfRootKey(const Bytes& rootKey,
                                              const Bytes& dhOutput);

    // KDF for message chain: chainKey -> (newChainKey, messageKey)
    static std::pair<Bytes, Bytes> kdfChainKey(const Bytes& chainKey);

    // Perform a DH ratchet step when we receive a new remote DH key
    // kemCt: KEM ciphertext from the peer (empty if peer hasn't sent one)
    void dhRatchetStep(const Bytes& remoteDhPub,
                       const Bytes& kemCt = {});

    // Try to decrypt using a skipped message key
    Bytes trySkippedKeys(const RatchetHeader& header,
                         const Bytes& ciphertext);

    // Skip ahead in receiving chain, caching message keys
    bool skipMessageKeys(const Bytes& dhPub, uint32_t until);

    // State
    Bytes m_rootKey;          // 32 bytes — root chain key
    Bytes m_sendChainKey;     // 32 bytes — sending symmetric chain
    Bytes m_recvChainKey;     // 32 bytes — receiving symmetric chain

    Bytes m_dhPub;            // 32 bytes — our current DH ratchet pub
    Bytes m_dhPriv;           // 32 bytes — our current DH ratchet priv
    Bytes m_remoteDhPub;      // 32 bytes — peer's current DH ratchet pub

    // ML-KEM-768 ratchet state (hybrid mode)
    bool  m_hybrid = false;
    Bytes m_kemPub;           // 1184 — our current KEM ratchet pub
    Bytes m_kemPriv;          // 2400 — our current KEM ratchet priv
    Bytes m_remoteKemPub;     // 1184 — peer's current KEM ratchet pub (for encaps on next send)
    Bytes m_pendingKemCt;     // 1088 — KEM ciphertext to include in next message header
                              //         (produced during dhRatchetStep, consumed during encrypt)

    uint32_t m_sendMsgNum = 0;   // messages sent in current chain
    uint32_t m_recvMsgNum = 0;   // messages received in current chain
    uint32_t m_prevChainLen = 0; // length of previous sending chain

    Bytes m_lastMessageKey;      // last message key from encrypt()

    // Skipped message keys: (dhPub, messageNum) -> messageKey
    std::map<std::pair<Bytes, uint32_t>, Bytes> m_skippedKeys;
};
