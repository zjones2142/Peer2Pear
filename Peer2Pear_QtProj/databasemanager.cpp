#include "databasemanager.h"

#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QTimeZone>
#include <sodium.h>
#include <sqlite3.h>

static QString contactKey(const QString &peerIdB64u, const QString &name)
{
    if (!peerIdB64u.isEmpty()) return peerIdB64u;
    return "name:" + name;
}

DatabaseManager::~DatabaseManager()
{
    close();
    // Securely zero key material
    if (!m_encKey.isEmpty())
        sodium_memzero(m_encKey.data(), static_cast<size_t>(m_encKey.size()));
    for (auto &k : m_legacyKeys) {
        if (!k.isEmpty())
            sodium_memzero(k.data(), static_cast<size_t>(k.size()));
    }
}

bool DatabaseManager::open(const QByteArray &dbKey)
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(base);
    const QString dbPath = base + "/peer2PearUser.db";

    // Only attempt migration if:
    //  1. A key is provided (new unified flow)
    //  2. The DB file already exists on disk
    //  3. We haven't already migrated (checked via a marker file)
    // The marker file avoids re-probing the DB on every startup.
    const QString migratedMarker = base + "/.sqlcipher_migrated";
    if (!dbKey.isEmpty() && QFile::exists(dbPath) && !QFile::exists(migratedMarker)) {
        if (migrateToEncrypted(dbPath, dbKey)) {
            // Migration succeeded — write marker so we never probe again
            QFile marker(migratedMarker);
            if (marker.open(QIODevice::WriteOnly))
                marker.close();
        } else {
            // Not necessarily an error — the DB may already be encrypted.
            // Write marker anyway to avoid re-probing every launch.
            QFile marker(migratedMarker);
            if (marker.open(QIODevice::WriteOnly))
                marker.close();
            qDebug() << "DatabaseManager: migration skipped (already encrypted or not needed)";
        }
    }

    if (!m_db.open(dbPath, dbKey)) {
        qWarning() << "DatabaseManager: failed to open DB:" << m_db.lastError();
        return false;
    }

    createTables();
    qDebug() << "DatabaseManager: opened" << m_db.databaseName()
             << (m_db.isSqlCipher() ? "(encrypted)" : "(plain)");
    return true;
}

void DatabaseManager::close()
{
    m_db.close();
}

void DatabaseManager::setEncryptionKey(const QByteArray &key32,
                                       const QVector<QByteArray> &legacyKeys)
{
    if (key32.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        m_encKey = key32;
    m_legacyKeys.clear();
    for (const auto &k : legacyKeys) {
        if (k.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
            m_legacyKeys.append(k);
    }
}

// ── Per-field encryption helpers ─────────────────────────────────────────────
// Encrypted values are stored as "ENC:" + base64(nonce + ciphertext).
// Unencrypted legacy values lack the prefix and are returned as-is.

static const QByteArray kEncPrefix = "ENC:";

QString DatabaseManager::encryptField(const QString &plaintext) const
{
    if (m_encKey.isEmpty()) return plaintext;

    const QByteArray pt = plaintext.toUtf8();
    const int nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;   // 24
    const int tagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;      // 16

    QByteArray out(nonceLen + pt.size() + tagLen, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(out.data()), nonceLen);

    unsigned long long ctLen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()) + nonceLen, &ctLen,
        reinterpret_cast<const unsigned char*>(pt.constData()), pt.size(),
        nullptr, 0,   // no additional data
        nullptr,       // nsec unused
        reinterpret_cast<const unsigned char*>(out.constData()),  // nonce
        reinterpret_cast<const unsigned char*>(m_encKey.constData()));

    out.resize(nonceLen + int(ctLen));
    return QString::fromLatin1(kEncPrefix + out.toBase64());
}

QString DatabaseManager::decryptField(const QString &stored) const
{
    // Unencrypted legacy value — return as-is
    if (!stored.startsWith(QString::fromLatin1(kEncPrefix)))
        return stored;

    if (m_encKey.isEmpty() && m_legacyKeys.isEmpty())
        return {};  // can't decrypt without any key — never expose ciphertext

    const QByteArray blob = QByteArray::fromBase64(
        stored.mid(kEncPrefix.size()).toLatin1());

    const int nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (blob.size() < nonceLen + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return {};  // malformed ciphertext — never expose to caller

    QByteArray pt(blob.size() - nonceLen - crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    unsigned long long ptLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &ptLen,
            nullptr,   // nsec unused
            reinterpret_cast<const unsigned char*>(blob.constData()) + nonceLen,
            blob.size() - nonceLen,
            nullptr, 0,   // no additional data
            reinterpret_cast<const unsigned char*>(blob.constData()),  // nonce
            reinterpret_cast<const unsigned char*>(m_encKey.constData())) != 0) {

        // Try each legacy key in order (handles multi-generation migration)
        for (const auto &legKey : m_legacyKeys) {
            ptLen = 0;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    reinterpret_cast<unsigned char*>(pt.data()), &ptLen,
                    nullptr,
                    reinterpret_cast<const unsigned char*>(blob.constData()) + nonceLen,
                    blob.size() - nonceLen,
                    nullptr, 0,
                    reinterpret_cast<const unsigned char*>(blob.constData()),
                    reinterpret_cast<const unsigned char*>(legKey.constData())) == 0) {
                pt.resize(int(ptLen));
                return QString::fromUtf8(pt);
            }
        }
        qWarning() << "decryptField: all keys failed — returning empty string";
        return {};  // decryption failed — return empty, never expose ciphertext
    }

    pt.resize(int(ptLen));
    return QString::fromUtf8(pt);
}

// ── Migration: plaintext DB → SQLCipher-encrypted DB ────────────────────────

// Overwrite a file's contents with random bytes before unlinking.
// Best-effort — not guaranteed on copy-on-write filesystems (APFS, btrfs).
static void secureRemoveFile(const QString &filePath)
{
    QFile f(filePath);
    if (!f.exists()) return;
    const qint64 sz = f.size();
    if (sz > 0 && f.open(QIODevice::WriteOnly)) {
        QByteArray noise(static_cast<int>(qMin(sz, qint64(1 << 20))), 0); // cap at 1 MB chunks
        qint64 remaining = sz;
        while (remaining > 0) {
            int chunk = static_cast<int>(qMin(remaining, qint64(noise.size())));
            randombytes_buf(reinterpret_cast<unsigned char*>(noise.data()),
                            static_cast<size_t>(chunk));
            f.write(noise.constData(), chunk);
            remaining -= chunk;
        }
        f.flush();
        f.close();
    }
    QFile::remove(filePath);
}

bool DatabaseManager::migrateToEncrypted(const QString &dbPath, const QByteArray &dbKey)
{
    const QString encPath    = dbPath + ".encrypted";
    const QString backupPath = dbPath + ".backup";

    // ── Step 0: Clean up debris from prior failed migration attempts ────
    // Previous attempts (ATTACH KEY, PRAGMA rekey) may have left stale files.
    QFile::remove(encPath);
    QFile::remove(encPath + "-wal");
    QFile::remove(encPath + "-shm");
    // If a .backup exists from a crashed swap, the original was already renamed.
    // Restore it before trying again.
    if (QFile::exists(backupPath) && !QFile::exists(dbPath)) {
        qWarning() << "Migration: found orphaned .backup — restoring original DB";
        QFile::rename(backupPath, dbPath);
    }
    QFile::remove(backupPath);

    // ── Step 1: Check if the DB is actually plaintext ───────────────────
    // Open with raw sqlite3 (no key) and try to read sqlite_master.
    // If it succeeds → DB is plaintext and needs migration.
    // If it fails   → DB is already encrypted (or corrupt) — skip migration.
    sqlite3* plainDb = nullptr;
    int rc = sqlite3_open_v2(dbPath.toUtf8().constData(), &plainDb,
                             SQLITE_OPEN_READWRITE, nullptr);
    if (rc != SQLITE_OK) {
        if (plainDb) sqlite3_close_v2(plainDb);
        return false;
    }

    sqlite3_exec(plainDb, "PRAGMA locking_mode=EXCLUSIVE;", nullptr, nullptr, nullptr);

    // Quick check: can we read sqlite_master without a key?
    rc = sqlite3_exec(plainDb, "SELECT count(*) FROM sqlite_master;",
                      nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        // Can't read without key → already encrypted or corrupt
        sqlite3_close_v2(plainDb);
        qDebug() << "Migration: DB is not plaintext (already encrypted or corrupt) — skipping";
        return false;
    }

    // Also verify there's actually data worth migrating
    int tableCount = 0;
    sqlite3_stmt* countStmt = nullptr;
    if (sqlite3_prepare_v2(plainDb, "SELECT count(*) FROM sqlite_master WHERE type='table';",
                           -1, &countStmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(countStmt) == SQLITE_ROW)
            tableCount = sqlite3_column_int(countStmt, 0);
        sqlite3_finalize(countStmt);
    }

    // Flush WAL into the main DB file before we copy
    sqlite3_exec(plainDb, "PRAGMA wal_checkpoint(TRUNCATE);", nullptr, nullptr, nullptr);
    sqlite3_close_v2(plainDb);

    if (tableCount == 0) {
        // Empty database — no need to migrate, just delete it and let
        // SqlCipherDb::open() create a fresh encrypted one.
        QFile::remove(dbPath);
        QFile::remove(dbPath + "-wal");
        QFile::remove(dbPath + "-shm");
        qDebug() << "Migration: empty plaintext DB — removed, will create encrypted fresh";
        return true;
    }

    qDebug() << "DatabaseManager: plaintext DB detected (" << tableCount
             << "tables) — migrating to SQLCipher...";

    // ── Step 2: Create a NEW encrypted DB, attach the OLD plaintext ─────
    SqlCipherDb encDb;
    if (!encDb.open(encPath, dbKey)) {
        qWarning() << "Migration: failed to create encrypted DB:" << encDb.lastError();
        QFile::remove(encPath);
        return false;
    }

    // Attach the old plaintext DB — KEY '' tells SQLCipher it's unencrypted.
    // Without this, SQLCipher tries to decrypt the attached DB with the
    // parent connection's key, which fails with "file is not a database".
    QString escapedPlain = dbPath;
    escapedPlain.replace(QLatin1Char('\''), QLatin1String("''"));
    const QString attachSql = QStringLiteral(
        "ATTACH DATABASE '%1' AS plaintext KEY '';").arg(escapedPlain);

    char* err = nullptr;
    rc = sqlite3_exec(encDb.handle(), attachSql.toUtf8().constData(),
                      nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        qWarning() << "Migration ATTACH plaintext failed:"
                   << (err ? err : "unknown") << "(rc=" << rc << ")";
        sqlite3_free(err);
        encDb.close();
        QFile::remove(encPath);
        return false;
    }

    // ── Step 3: Export data from plaintext → encrypted (main) ───────────
    // sqlcipher_export('main', 'plaintext') copies all tables/data from
    // the attached 'plaintext' schema into the encrypted 'main' schema.
    err = nullptr;
    rc = sqlite3_exec(encDb.handle(),
                      "SELECT sqlcipher_export('main', 'plaintext');",
                      nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        qWarning() << "Migration sqlcipher_export failed:"
                   << (err ? err : "unknown") << "(rc=" << rc << ")";
        sqlite3_free(err);
        sqlite3_exec(encDb.handle(), "DETACH DATABASE plaintext;",
                     nullptr, nullptr, nullptr);
        encDb.close();
        QFile::remove(encPath);
        return false;
    }

    sqlite3_exec(encDb.handle(), "DETACH DATABASE plaintext;",
                 nullptr, nullptr, nullptr);
    encDb.close();

    // ── Step 4: Verify the encrypted DB before swapping ─────────────────
    // Re-open the new encrypted DB to make sure it's valid and readable.
    {
        SqlCipherDb verifyDb;
        if (!verifyDb.open(encPath, dbKey)) {
            qWarning() << "Migration: encrypted DB verification failed — aborting swap";
            QFile::remove(encPath);
            return false;
        }
        // Check that at least some tables exist
        int verifyCount = 0;
        sqlite3_stmt* vs = nullptr;
        if (sqlite3_prepare_v2(verifyDb.handle(),
                               "SELECT count(*) FROM sqlite_master WHERE type='table';",
                               -1, &vs, nullptr) == SQLITE_OK) {
            if (sqlite3_step(vs) == SQLITE_ROW)
                verifyCount = sqlite3_column_int(vs, 0);
            sqlite3_finalize(vs);
        }
        verifyDb.close();

        if (verifyCount == 0) {
            qWarning() << "Migration: encrypted DB has 0 tables — export may have failed silently";
            QFile::remove(encPath);
            return false;
        }
        qDebug() << "Migration: verified encrypted DB has" << verifyCount << "tables";
    }

    // ── Step 5: Swap files ──────────────────────────────────────────────
    if (!QFile::rename(dbPath, backupPath)) {
        qWarning() << "Migration: failed to rename original to backup";
        QFile::remove(encPath);
        return false;
    }
    if (!QFile::rename(encPath, dbPath)) {
        qWarning() << "Migration: failed to rename encrypted to original — restoring backup";
        QFile::rename(backupPath, dbPath);
        return false;
    }

    // Securely delete plaintext remnants
    secureRemoveFile(dbPath + "-wal");
    secureRemoveFile(dbPath + "-shm");
    secureRemoveFile(backupPath);

    qDebug() << "DatabaseManager: successfully migrated plaintext DB to SQLCipher";
    return true;
}

// ── Table creation ──────────────────────────────────────────────────────────

void DatabaseManager::createTables()
{
    SqlCipherQuery q(m_db);

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
    q.exec("ALTER TABLE contacts ADD COLUMN kem_pub     BLOB    DEFAULT NULL;");

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

// ── Contact operations ──────────────────────────────────────────────────────

QVector<ChatData> DatabaseManager::loadAllContacts() const
{
    QVector<ChatData> result;
    SqlCipherQuery q(m_db.handle());
    q.prepare(
        "SELECT peer_id, name, subtitle, keys, is_blocked, is_group, group_id, avatar, last_active"
        " FROM contacts ORDER BY last_active DESC, rowid ASC;"
        );
    if (!q.exec()) { qWarning() << "loadAllContacts:" << q.lastError(); return result; }

    while (q.next()) {
        ChatData chat;
        const QString stored = q.value(0).toString();
        chat.peerIdB64u = stored.startsWith("name:") ? QString() : stored;
        chat.name       = decryptField(q.value(1).toString());
        chat.subtitle   = decryptField(q.value(2).toString());
        chat.isBlocked  = q.value(4).toInt() == 1;
        chat.isGroup    = q.value(5).toInt() == 1;
        chat.groupId    = q.value(6).toString();
        chat.avatarData = decryptField(q.value(7).toString());
        const qint64 laSecs = q.value(8).toLongLong();
        if (laSecs > 0)
            chat.lastActive = QDateTime::fromSecsSinceEpoch(laSecs, QTimeZone::utc());

        const QString ks = decryptField(q.value(3).toString());
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

    SqlCipherQuery q(m_db);
    q.prepare(
        "INSERT INTO contacts (peer_id,name,subtitle,keys,is_blocked,is_group,group_id,last_active,avatar)"
        " VALUES (:peer_id,:name,:subtitle,:keys,:is_blocked,:is_group,:group_id,0,:avatar)"
        " ON CONFLICT(peer_id) DO UPDATE SET"
        "   name=excluded.name, subtitle=excluded.subtitle, keys=excluded.keys,"
        "   is_blocked=excluded.is_blocked, is_group=excluded.is_group, group_id=excluded.group_id,"
        "   avatar=excluded.avatar;"
        );
    q.bindValue(":peer_id",   key);
    q.bindValue(":name",      encryptField(chat.name));
    q.bindValue(":subtitle",  encryptField(chat.subtitle));
    q.bindValue(":keys",      encryptField(chat.keys.join('|')));
    q.bindValue(":is_blocked",chat.isBlocked ? 1 : 0);
    q.bindValue(":is_group",  chat.isGroup   ? 1 : 0);
    q.bindValue(":group_id",  chat.groupId);
    q.bindValue(":avatar",    encryptField(chat.avatarData));
    if (!q.exec()) qWarning() << "saveContact:" << q.lastError();
}

void DatabaseManager::deleteContact(const QString &peerIdB64u)
{
    SqlCipherQuery q(m_db);
    q.prepare("DELETE FROM contacts WHERE peer_id=:peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) qWarning() << "deleteContact:" << q.lastError();
}

void DatabaseManager::saveContactAvatar(const QString &peerIdB64u, const QString &avatarB64)
{
    if (peerIdB64u.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare("UPDATE contacts SET avatar=:avatar WHERE peer_id=:peer_id;");
    q.bindValue(":avatar",  encryptField(avatarB64));
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) qWarning() << "saveContactAvatar:" << q.lastError();
}

void DatabaseManager::saveContactKemPub(const QString &peerIdB64u, const QByteArray &kemPub)
{
    if (peerIdB64u.isEmpty() || kemPub.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:peer_id;");
    q.bindValue(":kp",      kemPub);
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) qWarning() << "saveContactKemPub:" << q.lastError();
}

QByteArray DatabaseManager::loadContactKemPub(const QString &peerIdB64u) const
{
    if (peerIdB64u.isEmpty()) return {};
    SqlCipherQuery q(m_db.handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    if (q.exec() && q.next()) return q.value(0).toByteArray();
    return {};
}

void DatabaseManager::updateLastActive(const QString &key)
{
    if (key.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare("UPDATE contacts SET last_active=:ts WHERE peer_id=:peer_id;");
    q.bindValue(":ts",      QDateTime::currentSecsSinceEpoch());
    q.bindValue(":peer_id", key);
    if (!q.exec()) qWarning() << "updateLastActive:" << q.lastError();
}

// ── Message operations ──────────────────────────────────────────────────────

void DatabaseManager::saveMessage(const QString &peerIdB64u, const Message &msg)
{
    if (peerIdB64u.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare(
        "INSERT INTO messages (peer_id,sent,text,timestamp,msg_id,sender_name)"
        " VALUES (:peer_id,:sent,:text,:timestamp,:msg_id,:sender_name);"
        );
    q.bindValue(":peer_id",   peerIdB64u);
    q.bindValue(":sent",      msg.sent ? 1 : 0);
    q.bindValue(":text",      encryptField(msg.text));
    q.bindValue(":timestamp", msg.timestamp.toUTC().toSecsSinceEpoch());
    q.bindValue(":msg_id",    msg.msgId);
    q.bindValue(":sender_name", encryptField(msg.senderName));
    if (!q.exec()) { qWarning() << "saveMessage:" << q.lastError(); return; }
    updateLastActive(peerIdB64u);
}

QVector<Message> DatabaseManager::loadMessages(const QString &peerIdB64u) const
{
    QVector<Message> result;
    if (peerIdB64u.isEmpty()) return result;
    SqlCipherQuery q(m_db.handle());
    q.prepare(
        "SELECT sent,text,timestamp,msg_id,sender_name FROM messages"
        " WHERE peer_id=:peer_id ORDER BY timestamp ASC, id ASC;"
        );
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) { qWarning() << "loadMessages:" << q.lastError(); return result; }
    while (q.next()) {
        Message msg;
        msg.sent      = q.value(0).toInt() == 1;
        msg.text      = decryptField(q.value(1).toString());
        msg.timestamp = QDateTime::fromSecsSinceEpoch(q.value(2).toLongLong(), QTimeZone::utc()).toLocalTime();
        msg.msgId     = q.value(3).toString();
        msg.senderName = decryptField(q.value(4).toString());
        result.append(msg);
    }
    return result;
}

// ── File transfer records ───────────────────────────────────────────────────

void DatabaseManager::saveFileRecord(const QString &chatKey, const FileTransferRecord &rec)
{
    if (chatKey.isEmpty() || rec.transferId.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO file_transfers"
        " (transfer_id,chat_key,file_name,file_size,peer_id,peer_name,"
        "  timestamp,sent,status,chunks_total,chunks_complete,saved_path)"
        " VALUES (:tid,:ck,:fn,:fs,:pid,:pn,:ts,:sent,:status,:ct,:cc,:sp);"
        );
    q.bindValue(":tid",    rec.transferId);
    q.bindValue(":ck",     chatKey);
    q.bindValue(":fn",     encryptField(rec.fileName));
    q.bindValue(":fs",     rec.fileSize);
    q.bindValue(":pid",    rec.peerIdB64u);
    q.bindValue(":pn",     encryptField(rec.peerName));
    q.bindValue(":ts",     rec.timestamp.toUTC().toSecsSinceEpoch());
    q.bindValue(":sent",   rec.sent ? 1 : 0);
    q.bindValue(":status", static_cast<int>(rec.status));
    q.bindValue(":ct",     rec.chunksTotal);
    q.bindValue(":cc",     rec.chunksComplete);
    q.bindValue(":sp",     encryptField(rec.savedPath));
    if (!q.exec()) qWarning() << "saveFileRecord:" << q.lastError();
}

void DatabaseManager::deleteFileRecord(const QString &transferId)
{
    if (transferId.isEmpty()) return;
    SqlCipherQuery q(m_db);
    q.prepare("DELETE FROM file_transfers WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    if (!q.exec()) qWarning() << "deleteFileRecord:" << q.lastError();
}

QVector<FileTransferRecord> DatabaseManager::loadFileRecords(const QString &chatKey) const
{
    QVector<FileTransferRecord> result;
    if (chatKey.isEmpty()) return result;
    SqlCipherQuery q(m_db.handle());
    q.prepare(
        "SELECT transfer_id,file_name,file_size,peer_id,peer_name,"
        "       timestamp,sent,status,chunks_total,chunks_complete,saved_path"
        " FROM file_transfers WHERE chat_key=:ck ORDER BY timestamp ASC;"
        );
    q.bindValue(":ck", chatKey);
    if (!q.exec()) { qWarning() << "loadFileRecords:" << q.lastError(); return result; }
    while (q.next()) {
        FileTransferRecord rec;
        rec.transferId      = q.value(0).toString();
        rec.fileName        = decryptField(q.value(1).toString());
        rec.fileSize        = q.value(2).toLongLong();
        rec.peerIdB64u      = q.value(3).toString();
        rec.peerName        = decryptField(q.value(4).toString());
        rec.timestamp       = QDateTime::fromSecsSinceEpoch(q.value(5).toLongLong(), QTimeZone::utc()).toLocalTime();
        rec.sent            = q.value(6).toInt() == 1;
        rec.status          = static_cast<FileTransferStatus>(q.value(7).toInt());
        rec.chunksTotal     = q.value(8).toInt();
        rec.chunksComplete  = q.value(9).toInt();
        rec.savedPath       = decryptField(q.value(10).toString());
        result.append(rec);
    }
    return result;
}

// ── Settings ────────────────────────────────────────────────────────────────

void DatabaseManager::saveSetting(const QString &key, const QString &value)
{
    SqlCipherQuery q(m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(:key,:value);");
    q.bindValue(":key", key); q.bindValue(":value", value);
    if (!q.exec()) qWarning() << "saveSetting:" << q.lastError();
}

QString DatabaseManager::loadSetting(const QString &key, const QString &def) const
{
    SqlCipherQuery q(m_db.handle());
    q.prepare("SELECT value FROM settings WHERE key=:key;");
    q.bindValue(":key", key);
    if (q.exec() && q.next()) return q.value(0).toString();
    return def;
}
