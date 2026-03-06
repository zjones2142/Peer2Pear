#pragma once

#include <QString>
#include <QVector>
#include <QDateTime>
#include <QtSql/QSqlDatabase>

#include "chattypes.h"

class DatabaseManager
{
public:
    DatabaseManager();
    ~DatabaseManager();

    bool open();
    void close();

    // ── Contacts ──────────────────────────────────────────────────────────────
    QVector<ChatData> loadAllContacts() const;
    void saveContact(const ChatData &chat);
    void deleteContact(const QString &peerIdB64u);

    // ── Messages ──────────────────────────────────────────────────────────────
    // saveMessage now also updates last_active on the contact automatically
    void saveMessage(const QString &peerIdB64u, const Message &msg);
    QVector<Message> loadMessages(const QString &peerIdB64u) const;

    // ── Settings ──────────────────────────────────────────────────────────────
    void    saveSetting(const QString &key, const QString &value);
    QString loadSetting(const QString &key, const QString &defaultValue = {}) const;

private:
    void createTables();
    void updateLastActive(const QString &key); // ── ORDER: internal helper

    QSqlDatabase m_db;
};
