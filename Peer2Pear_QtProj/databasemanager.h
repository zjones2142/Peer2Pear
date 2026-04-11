#pragma once

#include <QString>
#include <QByteArray>
#include <QVector>
#include <QDateTime>

#include "SqlCipherDb.hpp"
#include "chattypes.h"
#include "filetransfer.h"

class DatabaseManager
{
public:
    DatabaseManager() = default;
    ~DatabaseManager();

    // Open the database.  When dbKey is non-empty the database is opened
    // with SQLCipher page-level encryption (PRAGMA key).
    bool open(const QByteArray &dbKey = {});
    void close();

    // Set the primary 32-byte key for encrypting sensitive fields at rest.
    // Legacy keys are tried in order when the primary key fails to decrypt
    // an existing ENC: field — this handles multi-generation key migration.
    void setEncryptionKey(const QByteArray &key32,
                          const QVector<QByteArray> &legacyKeys = {});

    QVector<ChatData> loadAllContacts() const;
    void saveContact(const ChatData &chat);
    void saveContactAvatar(const QString &peerIdB64u, const QString &avatarB64);
    void deleteContact(const QString &peerIdB64u);

    // saveMessage also updates last_active on the contact row
    void saveMessage(const QString &peerIdB64u, const Message &msg);
    QVector<Message> loadMessages(const QString &peerIdB64u) const;

    void saveFileRecord(const QString &chatKey, const FileTransferRecord &rec);
    void deleteFileRecord(const QString &transferId);
    QVector<FileTransferRecord> loadFileRecords(const QString &chatKey) const;

    void    saveSetting(const QString &key, const QString &value);
    QString loadSetting(const QString &key, const QString &defaultValue = {}) const;

    // Expose the underlying SqlCipherDb for shared use (e.g., SessionStore)
    SqlCipherDb& database() { return m_db; }

private:
    void createTables();
    void updateLastActive(const QString &key);
    bool migrateToEncrypted(const QString &dbPath, const QByteArray &dbKey);

    // Per-field encryption helpers (XChaCha20-Poly1305)
    QString encryptField(const QString &plaintext) const;
    QString decryptField(const QString &stored) const;

    SqlCipherDb          m_db;
    QByteArray           m_encKey;       // 32-byte primary key; empty = no encryption
    QVector<QByteArray>  m_legacyKeys;   // older keys, tried in order on decrypt failure
};
