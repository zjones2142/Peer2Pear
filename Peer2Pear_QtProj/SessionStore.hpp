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
 */

class SessionStore {
public:
    explicit SessionStore(QSqlDatabase db);

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

private:
    QSqlDatabase m_db;
};
