#pragma once

#include <QString>
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

private:
    void createTables();
    void updateLastActive(const QString &key);

    QSqlDatabase m_db;
};
