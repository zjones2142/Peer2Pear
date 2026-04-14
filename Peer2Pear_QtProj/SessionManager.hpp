#pragma once
#include "NoiseState.hpp"
#include "RatchetSession.hpp"
#include "SessionStore.hpp"
#include "CryptoEngine.hpp"
#include <QMap>
#include <QString>
#include <QByteArray>
#include <functional>

/*
 * SessionManager — orchestrates Noise handshake + Double Ratchet lifecycle.
 *
 * Message type bytes (first byte of session-layer blobs):
 *   0x01 = PREKEY_MSG      — Noise msg1 + initial payload encrypted with a
 *                            one-shot pre-key derived from the Noise chaining key
 *   0x02 = PREKEY_RESPONSE — Noise msg2 + initial payload encrypted with a
 *                            one-shot pre-key derived from the Noise chaining key
 *   0x03 = RATCHET_MSG     — normal ratchet-encrypted message
 *
 * Pre-key flow (offline delivery):
 *   Alice -> Bob:  [0x01][noise_msg1][prekey(payload)]
 *   Bob -> Alice:  [0x02][noise_msg2][prekey(payload)]
 *   After:         [0x03][ratchet(payload)]
 */

class SessionManager {
public:
    // Message type constants
    static constexpr quint8 kPreKeyMsg          = 0x01;
    static constexpr quint8 kPreKeyResponse     = 0x02;
    static constexpr quint8 kRatchetMsg         = 0x03;
    static constexpr quint8 kHybridPreKeyMsg    = 0x04;  // Phase 2: hybrid PQ handshake
    static constexpr quint8 kHybridPreKeyResp   = 0x05;  // Phase 2: hybrid PQ response
    static constexpr quint8 kAdditionalPreKey   = 0x06;  // Additional msg during pending handshake

    // Callback for sending handshake responses back to peers
    // Called with (peerId, sessionBlob) when a handshake response needs to be sent
    using SendResponseFn = std::function<void(const QString& peerId, const QByteArray& blob)>;

    SessionManager(CryptoEngine& crypto, SessionStore& store);

    // Set the callback for sending handshake responses
    void setSendResponseFn(SendResponseFn fn) { m_sendResponse = std::move(fn); }

    // Encrypt a plaintext for a peer.
    // peerEdPub: peer's Ed25519 public key (base64url)
    // peerKemPub: peer's ML-KEM-768 public key (1184 bytes, optional)
    //             If provided and we have PQ keys, uses hybrid Noise IK handshake.
    // Returns a session-layer blob (type byte + content)
    QByteArray encryptForPeer(const QString& peerIdB64u, const QByteArray& plaintext,
                              const QByteArray& peerKemPub = {});

    // Decrypt a session-layer blob received from a peer.
    // Returns decrypted plaintext, or empty on failure.
    // If msgKeyOut is non-null, receives the message key used for decryption
    // (used by file_key announcements to derive per-file encryption keys).
    QByteArray decryptFromPeer(const QString& senderIdB64u, const QByteArray& blob,
                               QByteArray* msgKeyOut = nullptr);

    // Check if a ratchet session exists for a peer
    bool hasSession(const QString& peerIdB64u) const;

    // Get the last message key from the most recent encrypt() call
    // Useful for deriving file transfer sub-keys
    const QByteArray& lastMessageKey() const { return m_lastMessageKey; }

    // Delete a session (e.g., when removing a contact)
    void deleteSession(const QString& peerIdB64u);

private:
    // Get or load a ratchet session from cache/DB
    RatchetSession* getSession(const QString& peerIdB64u);

    // Save session state to DB
    void persistSession(const QString& peerIdB64u);

    CryptoEngine& m_crypto;
    SessionStore& m_store;

    QMap<QString, RatchetSession> m_sessions;
    QByteArray m_lastMessageKey;

    // Chaining keys from completed handshakes — used to decrypt additional
    // pre-key messages (type 0x06) that arrived while the handshake was pending.
    // Cleared when the ratchet session receives a normal ratchet message.
    QMap<QString, QByteArray> m_pendingCk;

    SendResponseFn m_sendResponse;
};
