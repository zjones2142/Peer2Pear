#pragma once

#include <QString>
#include <QByteArray>
#include <QVector>
#include <QDateTime>
#include <QtSql/QSqlDatabase>

#include "chattypes.h"
#include "filetransfer.h"

class DatabaseManager
{
public:
    DatabaseManager();
    ~DatabaseManager();

    // Open the database at the default application-data location.
    bool open();

    // Open the database at a caller-supplied path (useful for testing).
    // Pass ":memory:" for a transient in-memory database.
    bool open(const QString &dbPath);

    void close();

    bool isOpen() const;

    // Set a 32-byte symmetric key for encrypting sensitive fields at rest.
    // Must be called after open() and before any save/load.
    void setEncryptionKey(const QByteArray &key32);

    // ── Contact operations ───────────────────────────────────────────────
    QVector<ChatData> loadAllContacts() const;
    void saveContact(const ChatData &chat);
    void saveContactAvatar(const QString &peerIdB64u, const QString &avatarB64);
    void deleteContact(const QString &peerIdB64u);
    bool contactExists(const QString &peerIdB64u) const;
    ChatData getContact(const QString &peerIdB64u) const;
    void blockContact(const QString &peerIdB64u, bool blocked);

    // ── Message operations ───────────────────────────────────────────────
    // saveMessage also updates last_active on the contact row
    void saveMessage(const QString &peerIdB64u, const Message &msg);
    QVector<Message> loadMessages(const QString &peerIdB64u) const;
    void clearMessages(const QString &peerIdB64u);
    int  messageCount(const QString &peerIdB64u) const;

    // ── File-transfer operations ─────────────────────────────────────────
    void saveFileRecord(const QString &chatKey, const FileTransferRecord &rec);
    QVector<FileTransferRecord> loadFileRecords(const QString &chatKey) const;
    void deleteFileRecord(const QString &transferId);

    // ── Settings operations ──────────────────────────────────────────────
    void    saveSetting(const QString &key, const QString &value);
    QString loadSetting(const QString &key, const QString &defaultValue = {}) const;

private:
    bool openDatabase(const QString &dbPath);
    void createTables();
    void updateLastActive(const QString &key);

    // Per-field encryption helpers (XChaCha20-Poly1305)
    QString encryptField(const QString &plaintext) const;
    QString decryptField(const QString &stored) const;

    QSqlDatabase m_db;
    QByteArray   m_encKey;   // 32-byte key; empty = no encryption
};
