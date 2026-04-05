#pragma once
#include <QByteArray>
#include <QString>
#include <QtSql/QSqlDatabase>

/*
 * SessionStore — persistent storage for ratchet session state.
 *
 * Uses the same SQLite database as DatabaseManager.
 * Tables:
 *   ratchet_sessions       — serialized RatchetSession per peer
 *   skipped_message_keys   — cached keys for out-of-order messages
 *   pending_handshakes     — in-progress Noise handshakes
 *
 * When a 32-byte storeKey is provided all BLOBs (session state and
 * handshake state) are authenticated-encrypted at rest using
 * XChaCha20-Poly1305 before being written to SQLite.
 */

class SessionStore {
public:
    // storeKey must be exactly 32 bytes to enable at-rest encryption.
    // If storeKey is not 32 bytes, encryptBlob/decryptBlob return {} (fail-safe):
    // save operations will be no-ops and load operations will return nothing,
    // so sessions will simply be re-established. In practice ChatController
    // always derives and passes a valid 32-byte key.
    explicit SessionStore(QSqlDatabase db, QByteArray storeKey = {});
    ~SessionStore();

    void createTables();

    // Ratchet session state
    void saveSession(const QString& peerId, const QByteArray& stateBlob);
    QByteArray loadSession(const QString& peerId) const;
    void deleteSession(const QString& peerId);

    // Skipped message keys
    void saveSkippedKey(const QString& peerId, const QByteArray& dhPub,
                        quint32 msgNum, const QByteArray& messageKey);
    QByteArray loadAndDeleteSkippedKey(const QString& peerId,
                                       const QByteArray& dhPub, quint32 msgNum);
    void pruneSkippedKeys(const QString& peerId, int maxCount);
    void deleteSkippedKeysForPeer(const QString& peerId);

    // Clear all sessions, skipped keys, and pending handshakes
    void clearAll();

    // Pending handshakes (survive app restart)
    void savePendingHandshake(const QString& peerId, int role,
                               const QByteArray& handshakeBlob);
    QByteArray loadPendingHandshake(const QString& peerId, int& roleOut) const;
    void deletePendingHandshake(const QString& peerId);
    // H2 fix: reduced from 24h to 5 min — stuck handshakes block messaging
    void pruneStaleHandshakes(int maxAgeSecs = 300);

private:
    // Encrypt/decrypt a BLOB using XChaCha20-Poly1305 and m_storeKey.
    // Returns the input unchanged when m_storeKey is not 32 bytes.
    // decryptBlob() returns {} on authentication failure.
    QByteArray encryptBlob(const QByteArray& plaintext) const;
    QByteArray decryptBlob(const QByteArray& ciphertext) const;

    QSqlDatabase m_db;
    QByteArray   m_storeKey; // 32-byte at-rest encryption key; zeroed in destructor
};
