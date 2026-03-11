#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QDateTime>

// ── Message ───────────────────────────────────────────────────────────────────
struct Message {
    bool      sent;
    QString   text;
    QDateTime timestamp;
};

// ── ChatData ──────────────────────────────────────────────────────────────────
struct ChatData {
    QString     name;
    QString     subtitle;
    QString     peerIdB64u;
    QStringList keys;
    QVector<Message> messages;
    bool isBlocked = false;
};
