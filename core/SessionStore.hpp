#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "SqlCipherDb.hpp"

/*
 * SessionStore — persistent storage for ratchet session state.
 *
 * Uses the same SQLCipher database as DatabaseManager.
 * Tables:
 *   ratchet_sessions       — serialized RatchetSession per peer
 *   pending_handshakes     — in-progress Noise handshakes
 *
 * When a 32-byte storeKey is provided all BLOBs (session state and
 * handshake state) are authenticated-encrypted at rest using
 * XChaCha20-Poly1305 before being written to the database.
 *
 * Types: std::string peer IDs, std::vector<uint8_t> (Bytes) blobs.
 */
class SessionStore {
public:
    using Bytes = std::vector<uint8_t>;

    // db must outlive this SessionStore.
    // storeKey must be exactly 32 bytes to enable at-rest encryption.
    explicit SessionStore(SqlCipherDb& db, Bytes storeKey = {});
    ~SessionStore();

    void createTables();

    // Ratchet session state
    void saveSession(const std::string& peerId, const Bytes& stateBlob);
    Bytes loadSession(const std::string& peerId) const;
    void  deleteSession(const std::string& peerId);

    // Clear all sessions and pending handshakes
    void clearAll();

    // Pending handshakes (survive app restart)
    void savePendingHandshake(const std::string& peerId, int role,
                              const Bytes& handshakeBlob);
    Bytes loadPendingHandshake(const std::string& peerId, int& roleOut) const;
    void  deletePendingHandshake(const std::string& peerId);

    // 5-minute default: stuck handshakes otherwise block messaging for
    // the peer.  Returns peer IDs whose handshakes were pruned (used by
    // callers for upgrade detection).
    std::vector<std::string> pruneStaleHandshakes(int maxAgeSecs = 300);

private:
    // Encrypt/decrypt a BLOB using XChaCha20-Poly1305 and m_storeKey.
    // AAD binds the row identity into the tag — callers supply a stable
    // string per logical slot (see the static sessionAad() /
    // handshakeAad() helpers in SessionStore.cpp).
    Bytes encryptBlob(const Bytes& plaintext, const std::string& aad) const;
    Bytes decryptBlob(const Bytes& ciphertext, const std::string& aad) const;

    SqlCipherDb& m_db;
    Bytes        m_storeKey; // 32-byte at-rest encryption key; zeroed in destructor
};
