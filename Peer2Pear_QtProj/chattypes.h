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
    QString   senderName; // populated for received group messages
};

struct ChatData {
    QString     name;
    QString     subtitle;
    QString     peerIdB64u;
    QStringList keys;
    QVector<Message> messages;
    bool isBlocked  = false;
    bool isGroup    = false;
    bool isOnline   = false;
    QString groupId;
    QString avatarData; // base64 PNG received from peer, may be empty
};
