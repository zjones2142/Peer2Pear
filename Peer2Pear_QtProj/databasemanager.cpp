#include "databasemanager.h"

#include <QStandardPaths>
#include <QDir>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>

// ── Internal helper: stable DB key for a contact ──────────────────────────────
static QString contactKey(const QString &peerIdB64u, const QString &name)
{
    if (!peerIdB64u.isEmpty()) return peerIdB64u;
    return "name:" + name;
}

// ── DatabaseManager ───────────────────────────────────────────────────────────

DatabaseManager::DatabaseManager()
{
    m_db = QSqlDatabase::addDatabase("QSQLITE", "peer2pear_conn");
}

DatabaseManager::~DatabaseManager()
{
    close();
}

bool DatabaseManager::open()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(base);
    m_db.setDatabaseName(base + "/peer2PearUser.db");

    if (!m_db.open()) {
        qWarning() << "DatabaseManager: failed to open DB:" << m_db.lastError().text();
        return false;
    }

    QSqlQuery pragma(m_db);
    pragma.exec("PRAGMA journal_mode=WAL;");
    pragma.exec("PRAGMA foreign_keys=ON;");

    createTables();
    qDebug() << "DatabaseManager: opened" << m_db.databaseName();
    return true;
}

void DatabaseManager::close()
{
    if (m_db.isOpen())
        m_db.close();
}

void DatabaseManager::createTables()
{
    QSqlQuery q(m_db);

    // contacts — includes last_active for ordering
    q.exec(
        "CREATE TABLE IF NOT EXISTS contacts ("
        "  peer_id     TEXT PRIMARY KEY,"
        "  name        TEXT NOT NULL,"
        "  subtitle    TEXT,"
        "  keys        TEXT,"
        "  last_active INTEGER DEFAULT 0"   // ── ORDER: Unix epoch, updated on each message
        ");"
        );

    // ── ORDER: if this is an existing DB that predates last_active, add the
    //    column safely — ALTER TABLE ignores errors if it already exists
    q.exec("ALTER TABLE contacts ADD COLUMN last_active INTEGER DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN is_blocked INTEGER DEFAULT 0;");
    // (the error from "duplicate column" is harmless — we just swallow it)

    q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  peer_id     TEXT NOT NULL,"
        "  sent        INTEGER NOT NULL,"
        "  text        TEXT NOT NULL,"
        "  timestamp   INTEGER NOT NULL,"
        "  FOREIGN KEY(peer_id) REFERENCES contacts(peer_id) ON DELETE CASCADE"
        ");"
        );

    q.exec(
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        );
}

// ── Contacts ──────────────────────────────────────────────────────────────────

QVector<ChatData> DatabaseManager::loadAllContacts() const
{
    QVector<ChatData> result;

    QSqlQuery q(m_db);
    // ── ORDER: sort by last_active descending so the most recently
    //    active chat is at the top — exactly as the user left it
    q.prepare(
        "SELECT peer_id, name, subtitle, keys, is_blocked"
        " FROM contacts"
        " ORDER BY last_active DESC, rowid ASC;"
        );
    if (!q.exec()) {
        qWarning() << "loadAllContacts error:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        ChatData chat;
        const QString storedKey = q.value(0).toString();

        chat.peerIdB64u = storedKey.startsWith("name:") ? QString() : storedKey;
        chat.name       = q.value(1).toString();
        chat.subtitle   = q.value(2).toString();
        chat.isBlocked = q.value(4).toInt() == 1;

        const QString keysStr = q.value(3).toString();
        if (!keysStr.isEmpty())
            chat.keys = keysStr.split('|', Qt::SkipEmptyParts);

        chat.messages = loadMessages(storedKey);
        result.append(chat);
    }

    return result;
}

void DatabaseManager::saveContact(const ChatData &chat)
{
    const QString key = contactKey(chat.peerIdB64u, chat.name);
    if (key.isEmpty()) return;

    QSqlQuery q(m_db);
    // ── Use INSERT ... ON CONFLICT DO UPDATE instead of INSERT OR REPLACE.
    // INSERT OR REPLACE does a DELETE + INSERT which fires ON DELETE CASCADE
    // and wipes all messages for that contact. The upsert form updates the
    // existing row in-place so messages are always preserved.
q.prepare(
        "INSERT INTO contacts (peer_id, name, subtitle, keys, is_blocked, last_active)"
        " VALUES (:peer_id, :name, :subtitle, :keys, :is_blocked, 0)"
        " ON CONFLICT(peer_id) DO UPDATE SET"
        "   name       = excluded.name,"
        "   subtitle   = excluded.subtitle,"
        "   keys       = excluded.keys,"
        "   is_blocked = excluded.is_blocked;"

        // last_active is intentionally NOT updated here — only saveMessage touches it
        );
    q.bindValue(":peer_id",  key);
    q.bindValue(":name",     chat.name);
    q.bindValue(":subtitle", chat.subtitle);
    q.bindValue(":keys",     chat.keys.join('|'));
    q.bindValue(":is_blocked", chat.isBlocked ? 1 : 0);

    if (!q.exec())
        qWarning() << "saveContact error:" << q.lastError().text();
}

void DatabaseManager::deleteContact(const QString &peerIdB64u)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM contacts WHERE peer_id = :peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec())
        qWarning() << "deleteContact error:" << q.lastError().text();
}

// ── ORDER: stamp the contact's last_active with the current UTC time ──────────
void DatabaseManager::updateLastActive(const QString &key)
{
    if (key.isEmpty()) return;
    QSqlQuery q(m_db);
    q.prepare(
        "UPDATE contacts SET last_active = :ts WHERE peer_id = :peer_id;"
        );
    q.bindValue(":ts",      QDateTime::currentDateTimeUtc().toSecsSinceEpoch());
    q.bindValue(":peer_id", key);
    if (!q.exec())
        qWarning() << "updateLastActive error:" << q.lastError().text();
}

// ── Messages ──────────────────────────────────────────────────────────────────

void DatabaseManager::saveMessage(const QString &peerIdB64u, const Message &msg)
{
    if (peerIdB64u.isEmpty()) return;

    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO messages (peer_id, sent, text, timestamp)"
        " VALUES (:peer_id, :sent, :text, :timestamp);"
        );
    q.bindValue(":peer_id",   peerIdB64u);
    q.bindValue(":sent",      msg.sent ? 1 : 0);
    q.bindValue(":text",      msg.text);
    q.bindValue(":timestamp", msg.timestamp.toUTC().toSecsSinceEpoch());

    if (!q.exec()) {
        qWarning() << "saveMessage error:" << q.lastError().text();
        return;
    }

    // ── ORDER: every message updates the contact's position in the list ───────
    updateLastActive(peerIdB64u);
}

QVector<Message> DatabaseManager::loadMessages(const QString &peerIdB64u) const
{
    QVector<Message> result;
    if (peerIdB64u.isEmpty()) return result;

    QSqlQuery q(m_db);
    q.prepare(
        "SELECT sent, text, timestamp FROM messages"
        " WHERE peer_id = :peer_id"
        " ORDER BY timestamp ASC, id ASC;"
        );
    q.bindValue(":peer_id", peerIdB64u);

    if (!q.exec()) {
        qWarning() << "loadMessages error:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        Message msg;
        msg.sent      = q.value(0).toInt() == 1;
        msg.text      = q.value(1).toString();
        msg.timestamp = QDateTime::fromSecsSinceEpoch(
                            q.value(2).toLongLong(), Qt::UTC).toLocalTime();
        result.append(msg);
    }

    return result;
}

// ── Settings ──────────────────────────────────────────────────────────────────

void DatabaseManager::saveSetting(const QString &key, const QString &value)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (:key, :value);");
    q.bindValue(":key",   key);
    q.bindValue(":value", value);
    if (!q.exec())
        qWarning() << "saveSetting error:" << q.lastError().text();
}

QString DatabaseManager::loadSetting(const QString &key, const QString &defaultValue) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT value FROM settings WHERE key = :key;");
    q.bindValue(":key", key);
    if (q.exec() && q.next())
        return q.value(0).toString();
    return defaultValue;
}
