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

    bool open();
    void close();

    // Set a 32-byte symmetric key for encrypting sensitive fields at rest.
    // Must be called after open() and before any save/load.
    void setEncryptionKey(const QByteArray &key32);

    QVector<ChatData> loadAllContacts() const;
    void saveContact(const ChatData &chat);
    void saveContactAvatar(const QString &peerIdB64u, const QString &avatarB64);
    void deleteContact(const QString &peerIdB64u);

    // saveMessage also updates last_active on the contact row
    void saveMessage(const QString &peerIdB64u, const Message &msg);
    QVector<Message> loadMessages(const QString &peerIdB64u) const;

    void saveFileRecord(const QString &chatKey, const FileTransferRecord &rec);
    QVector<FileTransferRecord> loadFileRecords(const QString &chatKey) const;

    void    saveSetting(const QString &key, const QString &value);
    QString loadSetting(const QString &key, const QString &defaultValue = {}) const;

    // Expose the underlying QSqlDatabase for shared use (e.g., SessionStore)
    QSqlDatabase database() const { return m_db; }

private:
    void createTables();
    void updateLastActive(const QString &key);

    // Per-field encryption helpers (XChaCha20-Poly1305)
    QString encryptField(const QString &plaintext) const;
    QString decryptField(const QString &stored) const;

    QSqlDatabase m_db;
    QByteArray   m_encKey;   // 32-byte key; empty = no encryption
};
