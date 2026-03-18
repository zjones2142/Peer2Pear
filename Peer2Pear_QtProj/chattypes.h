#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QDateTime>

struct Message {
    bool      sent;
    QString   text;
    QDateTime timestamp;
    QString   msgId;      // dedup ID; empty for legacy messages
};

struct ChatData {
    QString     name;
    QString     subtitle;
    QString     peerIdB64u;
    QStringList keys;
    QVector<Message> messages;
    bool isBlocked  = false;
    bool isGroup    = false;
    QString groupId;
};
