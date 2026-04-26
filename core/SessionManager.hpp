#pragma once

#include "types.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "NoiseState.hpp"
#include "RatchetSession.hpp"
#include "SessionStore.hpp"
#include "CryptoEngine.hpp"

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
 *
 * Types: std::string for peer IDs (base64url-encoded), std::vector<uint8_t>
 * for byte blobs.
 */


class SessionManager {
public:
    // Message type constants
    static constexpr uint8_t kPreKeyMsg          = 0x01;
    static constexpr uint8_t kPreKeyResponse     = 0x02;
    static constexpr uint8_t kRatchetMsg         = 0x03;
    static constexpr uint8_t kHybridPreKeyMsg    = 0x04;  // hybrid PQ handshake
    static constexpr uint8_t kHybridPreKeyResp   = 0x05;  // hybrid PQ response
    static constexpr uint8_t kAdditionalPreKey   = 0x06;  // Additional msg during pending handshake

    // Callback for sending handshake responses back to peers.
    // Called with (peerId, sessionBlob) when a handshake response needs to be sent.
    using SendResponseFn =
        std::function<void(const std::string& peerId, const Bytes& blob)>;

    SessionManager(CryptoEngine& crypto, SessionStore& store);

    // Set the callback for sending handshake responses.
    void setSendResponseFn(SendResponseFn fn) { m_sendResponse = std::move(fn); }

    // Encrypt a plaintext for a peer.
    // peerEdPub: peer's Ed25519 public key (base64url)
    // peerKemPub: peer's ML-KEM-768 public key (1184 bytes, optional)
    //             If provided and we have PQ keys, uses hybrid Noise IK handshake.
    // Returns a session-layer blob (type byte + content).
    Bytes encryptForPeer(const std::string& peerIdB64u, const Bytes& plaintext,
                         const Bytes& peerKemPub = {});

    // Decrypt a session-layer blob received from a peer.
    // Returns decrypted plaintext, or empty on failure.
    // If msgKeyOut is non-null, receives the message key used for decryption
    // (used by file_key announcements to derive per-file encryption keys).
    Bytes decryptFromPeer(const std::string& senderIdB64u, const Bytes& blob,
                          Bytes* msgKeyOut = nullptr);

    // Check if a ratchet session exists for a peer.
    bool hasSession(const std::string& peerIdB64u) const;

    /// 8-byte stable identifier for the live DR session with `peerIdB64u`,
    /// derived from the handshake-time root key (see RatchetSession::sessionId).
    /// Returns an empty Bytes when no session exists yet — callers should
    /// either establish one (via the regular send path that lazy-handshakes)
    /// or skip the per-peer envelope.
    ///
    /// Used by Causally-Linked Pairwise group messaging to namespace
    /// per-(sender, group, recipient) counters on the wire.
    Bytes sessionIdFor(const std::string& peerIdB64u);

    // Get the last message key from the most recent encrypt() call.
    // Useful for deriving file transfer sub-keys.
    const Bytes& lastMessageKey() const { return m_lastMessageKey; }

    // Delete a session (e.g., when removing a contact).
    void deleteSession(const std::string& peerIdB64u);

private:
    // Get or load a ratchet session from cache/DB.
    RatchetSession* getSession(const std::string& peerIdB64u);

    // Save session state to DB.
    void persistSession(const std::string& peerIdB64u);

    CryptoEngine& m_crypto;
    SessionStore& m_store;

    std::map<std::string, RatchetSession> m_sessions;
    Bytes m_lastMessageKey;

    // Chaining keys from completed handshakes — used to decrypt additional
    // pre-key messages (type 0x06) that arrived while the handshake was pending.
    // Cleared when the ratchet session receives a normal ratchet message.
    std::map<std::string, Bytes> m_pendingCk;

    // Ephemeral DH private keys are held ONLY in memory between
    // writeMessage1() and readMessage2().  If the process crashes
    // mid-handshake the key dies with it and forward secrecy is
    // preserved.  Keyed by peerIdB64u; zeroed + erased on handshake
    // completion or abandonment.
    std::map<std::string, Bytes> m_pendingEk;

    // Track consumed counters on the responder side for the additional-
    // pre-key path (type 0x06).  Each counter yields a deterministic key
    // from the chaining key, so a relay that captures a 0x06 envelope
    // could otherwise replay it.  Set is cleared when the first ratchet
    // message arrives from this sender — at that point m_pendingCk is no
    // longer used for derivation.
    std::map<std::string, std::set<uint32_t>> m_consumedPreKeyCounters;
    // Bound per-peer counter set so a malicious flood can't grow memory.
    static constexpr size_t kMaxPreKeyCounters = 10000;

    SendResponseFn m_sendResponse;
};
