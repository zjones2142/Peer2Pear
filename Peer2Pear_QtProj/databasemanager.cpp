#include "databasemanager.h"

#include <QStandardPaths>
#include <QDir>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>

static QString contactKey(const QString &peerIdB64u, const QString &name)
{
    if (!peerIdB64u.isEmpty()) return peerIdB64u;
    return "name:" + name;
}

DatabaseManager::DatabaseManager()
{
    m_db = QSqlDatabase::addDatabase("QSQLITE", "peer2pear_conn");
}

DatabaseManager::~DatabaseManager() { close(); }

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
    if (m_db.isOpen()) m_db.close();
}

void DatabaseManager::createTables()
{
    QSqlQuery q(m_db);

    q.exec(
        "CREATE TABLE IF NOT EXISTS contacts ("
        "  peer_id     TEXT PRIMARY KEY,"
        "  name        TEXT NOT NULL,"
        "  subtitle    TEXT,"
        "  keys        TEXT,"
        "  last_active INTEGER DEFAULT 0"
        ");"
        );

    // Safe migrations — duplicate column errors are harmless
    q.exec("ALTER TABLE contacts ADD COLUMN last_active INTEGER DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN is_blocked  INTEGER DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN is_group    INTEGER DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN group_id    TEXT    DEFAULT '';");
    q.exec("ALTER TABLE contacts ADD COLUMN avatar      TEXT    DEFAULT '';");

    q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  peer_id     TEXT NOT NULL,"
        "  sent        INTEGER NOT NULL,"
        "  text        TEXT NOT NULL,"
        "  timestamp   INTEGER NOT NULL,"
        "  msg_id      TEXT DEFAULT '',"
        "  FOREIGN KEY(peer_id) REFERENCES contacts(peer_id) ON DELETE CASCADE"
        ");"
        );

    // Safe migration for existing DBs
    q.exec("ALTER TABLE messages ADD COLUMN msg_id TEXT DEFAULT '';");
    q.exec("ALTER TABLE messages ADD COLUMN sender_name TEXT DEFAULT '';");

    q.exec(
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        );

    q.exec(
        "CREATE TABLE IF NOT EXISTS file_transfers ("
        "  transfer_id      TEXT PRIMARY KEY,"
        "  chat_key         TEXT NOT NULL,"
        "  file_name        TEXT NOT NULL,"
        "  file_size        INTEGER NOT NULL,"
        "  peer_id          TEXT,"
        "  peer_name        TEXT,"
        "  timestamp        INTEGER NOT NULL,"
        "  sent             INTEGER NOT NULL,"
        "  status           INTEGER NOT NULL,"
        "  chunks_total     INTEGER NOT NULL,"
        "  chunks_complete  INTEGER NOT NULL,"
        "  saved_path       TEXT"
        ");"
        );
}

QVector<ChatData> DatabaseManager::loadAllContacts() const
{
    QVector<ChatData> result;
    QSqlQuery q(m_db);
    q.prepare(
        "SELECT peer_id, name, subtitle, keys, is_blocked, is_group, group_id, avatar"
        " FROM contacts ORDER BY last_active DESC, rowid ASC;"
        );
    if (!q.exec()) { qWarning() << "loadAllContacts:" << q.lastError().text(); return result; }

    while (q.next()) {
        ChatData chat;
        const QString stored = q.value(0).toString();
        chat.peerIdB64u = stored.startsWith("name:") ? QString() : stored;
        chat.name       = q.value(1).toString();
        chat.subtitle   = q.value(2).toString();
        chat.isBlocked  = q.value(4).toInt() == 1;
        chat.isGroup    = q.value(5).toInt() == 1;
        chat.groupId    = q.value(6).toString();
        chat.avatarData = q.value(7).toString();

        const QString ks = q.value(3).toString();
        if (!ks.isEmpty()) chat.keys = ks.split('|', Qt::SkipEmptyParts);

        chat.messages = loadMessages(stored);
        result.append(chat);
    }
    return result;
}

void DatabaseManager::saveContact(const ChatData &chat)
{
    const QString key = contactKey(chat.peerIdB64u, chat.name);
    if (key.isEmpty()) return;

    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO contacts (peer_id,name,subtitle,keys,is_blocked,is_group,group_id,last_active,avatar)"
        " VALUES (:peer_id,:name,:subtitle,:keys,:is_blocked,:is_group,:group_id,0,:avatar)"
        " ON CONFLICT(peer_id) DO UPDATE SET"
        "   name=excluded.name, subtitle=excluded.subtitle, keys=excluded.keys,"
        "   is_blocked=excluded.is_blocked, is_group=excluded.is_group, group_id=excluded.group_id;"
        );
    q.bindValue(":peer_id",   key);
    q.bindValue(":name",      chat.name);
    q.bindValue(":subtitle",  chat.subtitle);
    q.bindValue(":keys",      chat.keys.join('|'));
    q.bindValue(":is_blocked",chat.isBlocked ? 1 : 0);
    q.bindValue(":is_group",  chat.isGroup   ? 1 : 0);
    q.bindValue(":group_id",  chat.groupId);
    q.bindValue(":avatar",    chat.avatarData);
    if (!q.exec()) qWarning() << "saveContact:" << q.lastError().text();
}

void DatabaseManager::deleteContact(const QString &peerIdB64u)
{
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM contacts WHERE peer_id=:peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) qWarning() << "deleteContact:" << q.lastError().text();
}

void DatabaseManager::saveContactAvatar(const QString &peerIdB64u, const QString &avatarB64)
{
    if (peerIdB64u.isEmpty()) return;
    QSqlQuery q(m_db);
    q.prepare("UPDATE contacts SET avatar=:avatar WHERE peer_id=:peer_id;");
    q.bindValue(":avatar",  avatarB64);
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) qWarning() << "saveContactAvatar:" << q.lastError().text();
}

void DatabaseManager::updateLastActive(const QString &key)
{
    if (key.isEmpty()) return;
    QSqlQuery q(m_db);
    q.prepare("UPDATE contacts SET last_active=:ts WHERE peer_id=:peer_id;");
    q.bindValue(":ts",      QDateTime::currentDateTimeUtc().toSecsSinceEpoch());
    q.bindValue(":peer_id", key);
    if (!q.exec()) qWarning() << "updateLastActive:" << q.lastError().text();
}

void DatabaseManager::saveMessage(const QString &peerIdB64u, const Message &msg)
{
    if (peerIdB64u.isEmpty()) return;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO messages (peer_id,sent,text,timestamp,msg_id,sender_name)"
        " VALUES (:peer_id,:sent,:text,:timestamp,:msg_id,:sender_name);"
        );
    q.bindValue(":peer_id",   peerIdB64u);
    q.bindValue(":sent",      msg.sent ? 1 : 0);
    q.bindValue(":text",      msg.text);
    q.bindValue(":timestamp", msg.timestamp.toUTC().toSecsSinceEpoch());
    q.bindValue(":msg_id",    msg.msgId);
    q.bindValue(":sender_name", msg.senderName);
    if (!q.exec()) { qWarning() << "saveMessage:" << q.lastError().text(); return; }
    updateLastActive(peerIdB64u);
}

QVector<Message> DatabaseManager::loadMessages(const QString &peerIdB64u) const
{
    QVector<Message> result;
    if (peerIdB64u.isEmpty()) return result;
    QSqlQuery q(m_db);
    q.prepare(
        "SELECT sent,text,timestamp,msg_id,sender_name FROM messages"
        " WHERE peer_id=:peer_id ORDER BY timestamp ASC, id ASC;"
        );
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) { qWarning() << "loadMessages:" << q.lastError().text(); return result; }
    while (q.next()) {
        Message msg;
        msg.sent      = q.value(0).toInt() == 1;
        msg.text      = q.value(1).toString();
        msg.timestamp = QDateTime::fromSecsSinceEpoch(q.value(2).toLongLong(), Qt::UTC).toLocalTime();
        msg.msgId     = q.value(3).toString();
        msg.senderName = q.value(4).toString();
        result.append(msg);
    }
    return result;
}

void DatabaseManager::saveFileRecord(const QString &chatKey, const FileTransferRecord &rec)
{
    if (chatKey.isEmpty() || rec.transferId.isEmpty()) return;
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO file_transfers"
        " (transfer_id,chat_key,file_name,file_size,peer_id,peer_name,"
        "  timestamp,sent,status,chunks_total,chunks_complete,saved_path)"
        " VALUES (:tid,:ck,:fn,:fs,:pid,:pn,:ts,:sent,:status,:ct,:cc,:sp);"
        );
    q.bindValue(":tid",    rec.transferId);
    q.bindValue(":ck",     chatKey);
    q.bindValue(":fn",     rec.fileName);
    q.bindValue(":fs",     rec.fileSize);
    q.bindValue(":pid",    rec.peerIdB64u);
    q.bindValue(":pn",     rec.peerName);
    q.bindValue(":ts",     rec.timestamp.toUTC().toSecsSinceEpoch());
    q.bindValue(":sent",   rec.sent ? 1 : 0);
    q.bindValue(":status", static_cast<int>(rec.status));
    q.bindValue(":ct",     rec.chunksTotal);
    q.bindValue(":cc",     rec.chunksComplete);
    q.bindValue(":sp",     rec.savedPath);
    if (!q.exec()) qWarning() << "saveFileRecord:" << q.lastError().text();
}

QVector<FileTransferRecord> DatabaseManager::loadFileRecords(const QString &chatKey) const
{
    QVector<FileTransferRecord> result;
    if (chatKey.isEmpty()) return result;
    QSqlQuery q(m_db);
    q.prepare(
        "SELECT transfer_id,file_name,file_size,peer_id,peer_name,"
        "       timestamp,sent,status,chunks_total,chunks_complete,saved_path"
        " FROM file_transfers WHERE chat_key=:ck ORDER BY timestamp ASC;"
        );
    q.bindValue(":ck", chatKey);
    if (!q.exec()) { qWarning() << "loadFileRecords:" << q.lastError().text(); return result; }
    while (q.next()) {
        FileTransferRecord rec;
        rec.transferId      = q.value(0).toString();
        rec.fileName        = q.value(1).toString();
        rec.fileSize        = q.value(2).toLongLong();
        rec.peerIdB64u      = q.value(3).toString();
        rec.peerName        = q.value(4).toString();
        rec.timestamp       = QDateTime::fromSecsSinceEpoch(q.value(5).toLongLong(), Qt::UTC).toLocalTime();
        rec.sent            = q.value(6).toInt() == 1;
        rec.status          = static_cast<FileTransferStatus>(q.value(7).toInt());
        rec.chunksTotal     = q.value(8).toInt();
        rec.chunksComplete  = q.value(9).toInt();
        rec.savedPath       = q.value(10).toString();
        result.append(rec);
    }
    return result;
}

void DatabaseManager::saveSetting(const QString &key, const QString &value)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(:key,:value);");
    q.bindValue(":key", key); q.bindValue(":value", value);
    if (!q.exec()) qWarning() << "saveSetting:" << q.lastError().text();
}

QString DatabaseManager::loadSetting(const QString &key, const QString &def) const
{
    QSqlQuery q(m_db);
    q.prepare("SELECT value FROM settings WHERE key=:key;");
    q.bindValue(":key", key);
    if (q.exec() && q.next()) return q.value(0).toString();
    return def;
}
