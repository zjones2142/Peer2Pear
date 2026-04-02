#include "SessionStore.hpp"
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDateTime>
#include <QDebug>

SessionStore::SessionStore(QSqlDatabase db)
    : m_db(db)
{
    createTables();
}

void SessionStore::createTables() {
    QSqlQuery q(m_db);

    q.exec(
        "CREATE TABLE IF NOT EXISTS ratchet_sessions ("
        "  peer_id    TEXT PRIMARY KEY,"
        "  state_blob BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL"
        ");"
    );

    q.exec(
        "CREATE TABLE IF NOT EXISTS skipped_message_keys ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  peer_id     TEXT NOT NULL,"
        "  dh_pub      BLOB NOT NULL,"
        "  msg_num     INTEGER NOT NULL,"
        "  message_key BLOB NOT NULL,"
        "  created_at  INTEGER NOT NULL,"
        "  UNIQUE(peer_id, dh_pub, msg_num)"
        ");"
    );

    q.exec(
        "CREATE TABLE IF NOT EXISTS pending_handshakes ("
        "  peer_id        TEXT PRIMARY KEY,"
        "  role           INTEGER NOT NULL,"
        "  handshake_blob BLOB NOT NULL,"
        "  created_at     INTEGER NOT NULL"
        ");"
    );
}

// ---------------------------
// Ratchet sessions
// ---------------------------

void SessionStore::saveSession(const QString& peerId, const QByteArray& stateBlob) {
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO ratchet_sessions (peer_id, state_blob, created_at, updated_at)"
        " VALUES (:pid, :blob, :now, :now)"
        " ON CONFLICT(peer_id) DO UPDATE SET state_blob=excluded.state_blob, updated_at=excluded.updated_at;"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":blob", stateBlob);
    q.bindValue(":now", now);
    if (!q.exec()) qWarning() << "SessionStore::saveSession:" << q.lastError().text();
}

QByteArray SessionStore::loadSession(const QString& peerId) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT state_blob FROM ratchet_sessions WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) return q.value(0).toByteArray();
    return {};
}

void SessionStore::deleteSession(const QString& peerId) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM ratchet_sessions WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
    deleteSkippedKeysForPeer(peerId);
    deletePendingHandshake(peerId);
}

// ---------------------------
// Skipped message keys
// ---------------------------

void SessionStore::saveSkippedKey(const QString& peerId, const QByteArray& dhPub,
                                   quint32 msgNum, const QByteArray& messageKey) {
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO skipped_message_keys"
        " (peer_id, dh_pub, msg_num, message_key, created_at)"
        " VALUES (:pid, :dh, :mn, :mk, :now);"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":dh", dhPub);
    q.bindValue(":mn", msgNum);
    q.bindValue(":mk", messageKey);
    q.bindValue(":now", now);
    if (!q.exec()) qWarning() << "SessionStore::saveSkippedKey:" << q.lastError().text();
}

QByteArray SessionStore::loadAndDeleteSkippedKey(const QString& peerId,
                                                  const QByteArray& dhPub, quint32 msgNum) {
    QSqlQuery q(m_db);
    q.prepare(
        "SELECT id, message_key FROM skipped_message_keys"
        " WHERE peer_id=:pid AND dh_pub=:dh AND msg_num=:mn;"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":dh", dhPub);
    q.bindValue(":mn", msgNum);
    if (!q.exec() || !q.next()) return {};

    qint64 id = q.value(0).toLongLong();
    QByteArray key = q.value(1).toByteArray();

    QSqlQuery del(m_db);
    del.prepare("DELETE FROM skipped_message_keys WHERE id=:id;");
    del.bindValue(":id", id);
    del.exec();

    return key;
}

void SessionStore::pruneSkippedKeys(const QString& peerId, int maxCount) {
    QSqlQuery q(m_db);
    q.prepare(
        "DELETE FROM skipped_message_keys WHERE peer_id=:pid AND id NOT IN"
        " (SELECT id FROM skipped_message_keys WHERE peer_id=:pid2"
        "  ORDER BY created_at DESC LIMIT :lim);"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":pid2", peerId);
    q.bindValue(":lim", maxCount);
    q.exec();
}

void SessionStore::deleteSkippedKeysForPeer(const QString& peerId) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM skipped_message_keys WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
}

// ---------------------------
// Pending handshakes
// ---------------------------

void SessionStore::savePendingHandshake(const QString& peerId, int role,
                                         const QByteArray& handshakeBlob) {
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO pending_handshakes (peer_id, role, handshake_blob, created_at)"
        " VALUES (:pid, :role, :blob, :now)"
        " ON CONFLICT(peer_id) DO UPDATE SET role=excluded.role,"
        "   handshake_blob=excluded.handshake_blob, created_at=excluded.created_at;"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":role", role);
    q.bindValue(":blob", handshakeBlob);
    q.bindValue(":now", now);
    if (!q.exec()) qWarning() << "SessionStore::savePendingHandshake:" << q.lastError().text();
}

QByteArray SessionStore::loadPendingHandshake(const QString& peerId, int& roleOut) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT role, handshake_blob FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) {
        roleOut = q.value(0).toInt();
        return q.value(1).toByteArray();
    }
    return {};
}

void SessionStore::deletePendingHandshake(const QString& peerId) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
}
