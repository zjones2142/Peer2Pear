#include "SessionStore.hpp"
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDateTime>
#include <QDebug>
#include <sodium.h>
#include <cstring>

SessionStore::SessionStore(QSqlDatabase db, QByteArray storeKey)
    : m_db(db)
    , m_storeKey(std::move(storeKey))
{
    createTables();
    pruneStaleHandshakes();   // G2 fix: clean up on startup
}

SessionStore::~SessionStore() {
    if (!m_storeKey.isEmpty())
        sodium_memzero(m_storeKey.data(), static_cast<size_t>(m_storeKey.size()));
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
// Blob encryption helpers
// ---------------------------

QByteArray SessionStore::encryptBlob(const QByteArray& plaintext) const {
    if (m_storeKey.size() != 32) return plaintext;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray out;
    out.resize(static_cast<int>(sizeof(nonce)) + plaintext.size() +
               static_cast<int>(crypto_aead_xchacha20poly1305_ietf_ABYTES));
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()),
        static_cast<unsigned long long>(plaintext.size()),
        nullptr, 0, nullptr, nonce,
        reinterpret_cast<const unsigned char*>(m_storeKey.constData()));
    memcpy(out.data(), nonce, sizeof(nonce));
    out.resize(static_cast<int>(sizeof(nonce) + clen));
    return out;
}

QByteArray SessionStore::decryptBlob(const QByteArray& ciphertext) const {
    const int kMinSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                         crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (m_storeKey.size() != 32) return {};  // no valid key — fail safe
    if (ciphertext.size() < kMinSize) return {};   // too short — treat as invalid

    const unsigned char* nonce =
        reinterpret_cast<const unsigned char*>(ciphertext.constData());
    const int ctLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    QByteArray pt;
    pt.resize(ctLen - static_cast<int>(crypto_aead_xchacha20poly1305_ietf_ABYTES));
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()) +
                crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            static_cast<unsigned long long>(ctLen),
            nullptr, 0, nonce,
            reinterpret_cast<const unsigned char*>(m_storeKey.constData())) != 0) {
        return {}; // authentication failed — invalid or old plaintext blob
    }
    pt.resize(static_cast<int>(plen));
    return pt;
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
    q.bindValue(":blob", encryptBlob(stateBlob));
    q.bindValue(":now", now);
    if (!q.exec()) qWarning() << "SessionStore::saveSession:" << q.lastError().text();
}

QByteArray SessionStore::loadSession(const QString& peerId) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT state_blob FROM ratchet_sessions WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) return decryptBlob(q.value(0).toByteArray());
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
    q.bindValue(":mk", encryptBlob(messageKey));   // S2 fix: encrypt at rest
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
    QByteArray key = decryptBlob(q.value(1).toByteArray());  // S2 fix: decrypt

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
// Clear all
// ---------------------------

void SessionStore::clearAll() {
    QSqlQuery q(m_db);
    q.exec("DELETE FROM ratchet_sessions;");
    q.exec("DELETE FROM skipped_message_keys;");
    q.exec("DELETE FROM pending_handshakes;");
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionStore] Cleared all sessions, skipped keys, and pending handshakes";
#endif
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
    q.bindValue(":blob", encryptBlob(handshakeBlob));
    q.bindValue(":now", now);
    if (!q.exec()) qWarning() << "SessionStore::savePendingHandshake:" << q.lastError().text();
}

QByteArray SessionStore::loadPendingHandshake(const QString& peerId, int& roleOut) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT role, handshake_blob FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) {
        roleOut = q.value(0).toInt();
        return decryptBlob(q.value(1).toByteArray());
    }
    return {};
}

void SessionStore::deletePendingHandshake(const QString& peerId) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
}

void SessionStore::pruneStaleHandshakes(int maxAgeSecs) {
    // G2 fix: remove pending handshakes older than maxAgeSecs (default 24h)
    const qint64 cutoff = QDateTime::currentSecsSinceEpoch() - maxAgeSecs;
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM pending_handshakes WHERE created_at < :cutoff;");
    q.bindValue(":cutoff", cutoff);
    if (q.exec() && q.numRowsAffected() > 0) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionStore] Pruned" << q.numRowsAffected() << "stale pending handshakes";
#endif
    }
}
