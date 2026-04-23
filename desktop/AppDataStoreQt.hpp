#pragma once

// Qt-flavoured façade-free bridge over core/AppDataStore.  Each function
// takes an AppDataStore* (nullable, to mirror the old `if (m_db) m_db->X()`
// pattern) plus Qt-typed arguments, marshals to std::-typed values, and
// forwards to the core API.  No class — just free functions in
// `appData::`, so call sites read like `appData::saveContact(m_store, c)`
// instead of carrying around a Qt facade object.
//
// Replaces the legacy `desktop/databasemanager.{h,cpp}` Qt facade.  The
// per-field XChaCha20-Poly1305 encryption setup, plaintext→SQLCipher
// migration, and DB key handling all live with the caller (MainWindow)
// — those are platform-specific glue, not bridges.

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QVector>
#include <QMap>
#include <QDateTime>
#include <QTimeZone>

#include "AppDataStore.hpp"
#include "chattypes.h"
#include "filetransfer.h"

namespace appData {

// ── Type-conversion primitives ──────────────────────────────────────────────

inline int64_t toEpochSecs(const QDateTime& dt) {
    return dt.isValid() ? dt.toUTC().toSecsSinceEpoch() : 0;
}

inline QDateTime fromEpochSecs(int64_t secs) {
    if (secs <= 0) return QDateTime();
    return QDateTime::fromSecsSinceEpoch(secs, QTimeZone::utc()).toLocalTime();
}

inline std::vector<std::string> qStringListToStd(const QStringList& l) {
    std::vector<std::string> out;
    out.reserve(l.size());
    for (const QString& s : l) out.push_back(s.toStdString());
    return out;
}

inline QStringList stdToQStringList(const std::vector<std::string>& v) {
    QStringList out;
    out.reserve(static_cast<int>(v.size()));
    for (const auto& s : v) out << QString::fromStdString(s);
    return out;
}

inline AppDataStore::Bytes qByteArrayToBytes(const QByteArray& b) {
    return AppDataStore::Bytes(reinterpret_cast<const uint8_t*>(b.constData()),
                                reinterpret_cast<const uint8_t*>(b.constData()) + b.size());
}

inline QByteArray bytesToQByteArray(const AppDataStore::Bytes& b) {
    return QByteArray(reinterpret_cast<const char*>(b.data()),
                      static_cast<int>(b.size()));
}

// ── Encryption-key plumbing ────────────────────────────────────────────────

inline void setEncryptionKey(AppDataStore* s,
                              const QByteArray& key32,
                              const QVector<QByteArray>& legacyKeys = {}) {
    if (!s) return;
    std::vector<AppDataStore::Bytes> legacy;
    legacy.reserve(legacyKeys.size());
    for (const auto& k : legacyKeys) legacy.push_back(qByteArrayToBytes(k));
    s->setEncryptionKey(qByteArrayToBytes(key32), legacy);
}

// ── Contacts ───────────────────────────────────────────────────────────────

inline QVector<ChatData> loadAllContacts(const AppDataStore* s);  // forward; defined below

inline void saveContact(AppDataStore* s, const ChatData& chat) {
    if (!s || chat.peerIdB64u.isEmpty()) return;
    AppDataStore::Contact c;
    c.peerIdB64u     = chat.peerIdB64u.toStdString();
    c.name           = chat.name.toStdString();
    c.subtitle       = chat.subtitle.toStdString();
    c.keys           = qStringListToStd(chat.keys);
    c.isBlocked      = chat.isBlocked;
    c.isGroup        = chat.isGroup;
    c.groupId        = chat.groupId.toStdString();
    c.avatarB64      = chat.avatarData.toStdString();
    c.lastActiveSecs = toEpochSecs(chat.lastActive);
    // Desktop semantic: every saved contact is in the address book.
    // The iOS-only stranger-stub state (in_address_book=0) is managed
    // by the iOS path, not here.
    c.inAddressBook  = true;
    s->saveContact(c);
}

inline void deleteContact(AppDataStore* s, const QString& peerIdB64u) {
    if (!s) return;
    s->deleteContact(peerIdB64u.toStdString());
}

inline void saveContactAvatar(AppDataStore* s,
                               const QString& peerIdB64u,
                               const QString& avatarB64) {
    if (!s) return;
    s->saveContactAvatar(peerIdB64u.toStdString(), avatarB64.toStdString());
}

inline void saveContactKemPub(AppDataStore* s,
                               const QString& peerIdB64u,
                               const QByteArray& kemPub) {
    if (!s) return;
    s->saveContactKemPub(peerIdB64u.toStdString(), qByteArrayToBytes(kemPub));
}

inline QByteArray loadContactKemPub(const AppDataStore* s, const QString& peerIdB64u) {
    if (!s) return {};
    return bytesToQByteArray(s->loadContactKemPub(peerIdB64u.toStdString()));
}

// ── Messages ───────────────────────────────────────────────────────────────

inline QVector<Message> loadMessages(const AppDataStore* s, const QString& peerIdB64u) {
    QVector<Message> out;
    if (!s) return out;
    s->loadMessages(peerIdB64u.toStdString(), [&](const AppDataStore::Message& m) {
        Message qm;
        qm.sent       = m.sent;
        qm.text       = QString::fromStdString(m.text);
        qm.timestamp  = fromEpochSecs(m.timestampSecs);
        qm.msgId      = QString::fromStdString(m.msgId);
        qm.senderName = QString::fromStdString(m.senderName);
        out.append(qm);
    });
    return out;
}

inline void saveMessage(AppDataStore* s,
                         const QString& peerIdB64u,
                         const Message& msg) {
    if (!s) return;
    AppDataStore::Message m;
    m.sent          = msg.sent;
    m.text          = msg.text.toStdString();
    m.timestampSecs = toEpochSecs(msg.timestamp);
    m.msgId         = msg.msgId.toStdString();
    m.senderName    = msg.senderName.toStdString();
    s->saveMessage(peerIdB64u.toStdString(), m);
}

inline QVector<ChatData> loadAllContacts(const AppDataStore* s) {
    QVector<ChatData> result;
    if (!s) return result;
    s->loadAllContacts([&](const AppDataStore::Contact& c) {
        ChatData chat;
        chat.peerIdB64u = QString::fromStdString(c.peerIdB64u);
        chat.name       = QString::fromStdString(c.name);
        chat.subtitle   = QString::fromStdString(c.subtitle);
        chat.keys       = stdToQStringList(c.keys);
        chat.isBlocked  = c.isBlocked;
        chat.isGroup    = c.isGroup;
        chat.groupId    = QString::fromStdString(c.groupId);
        chat.avatarData = QString::fromStdString(c.avatarB64);
        chat.lastActive = fromEpochSecs(c.lastActiveSecs);
        chat.messages   = loadMessages(s, chat.peerIdB64u);
        result.append(chat);
    });
    return result;
}

// ── Settings ───────────────────────────────────────────────────────────────

inline void saveSetting(AppDataStore* s,
                         const QString& key,
                         const QString& value) {
    if (!s) return;
    s->saveSetting(key.toStdString(), value.toStdString());
}

inline QString loadSetting(const AppDataStore* s,
                            const QString& key,
                            const QString& defaultValue = QString()) {
    if (!s) return defaultValue;
    return QString::fromStdString(
        s->loadSetting(key.toStdString(), defaultValue.toStdString()));
}

// ── File transfer records ──────────────────────────────────────────────────

inline void saveFileRecord(AppDataStore* s,
                            const QString& chatKey,
                            const FileTransferRecord& rec) {
    if (!s) return;
    AppDataStore::FileRecord r;
    r.transferId      = rec.transferId.toStdString();
    r.chatKey         = chatKey.toStdString();
    r.fileName        = rec.fileName.toStdString();
    r.fileSize        = rec.fileSize;
    r.peerIdB64u      = rec.peerIdB64u.toStdString();
    r.peerName        = rec.peerName.toStdString();
    r.timestampSecs   = toEpochSecs(rec.timestamp);
    r.sent            = rec.sent;
    r.status          = static_cast<int>(rec.status);
    r.chunksTotal     = rec.chunksTotal;
    r.chunksComplete  = rec.chunksComplete;
    r.savedPath       = rec.savedPath.toStdString();
    s->saveFileRecord(r.chatKey, r);
}

inline void deleteFileRecord(AppDataStore* s, const QString& transferId) {
    if (!s) return;
    s->deleteFileRecord(transferId.toStdString());
}

inline QVector<FileTransferRecord> loadFileRecords(const AppDataStore* s,
                                                    const QString& chatKey) {
    QVector<FileTransferRecord> out;
    if (!s) return out;
    s->loadFileRecords(chatKey.toStdString(), [&](const AppDataStore::FileRecord& r) {
        FileTransferRecord rec;
        rec.transferId     = QString::fromStdString(r.transferId);
        rec.fileName       = QString::fromStdString(r.fileName);
        rec.fileSize       = r.fileSize;
        rec.peerIdB64u     = QString::fromStdString(r.peerIdB64u);
        rec.peerName       = QString::fromStdString(r.peerName);
        rec.timestamp      = fromEpochSecs(r.timestampSecs);
        rec.sent           = r.sent;
        rec.status         = static_cast<FileTransferStatus>(r.status);
        rec.chunksTotal    = r.chunksTotal;
        rec.chunksComplete = r.chunksComplete;
        rec.savedPath      = QString::fromStdString(r.savedPath);
        out.append(rec);
    });
    return out;
}

// ── Group sequence counters ────────────────────────────────────────────────

inline void saveGroupSeqOut(AppDataStore* s, const QMap<QString, qint64>& counters) {
    if (!s) return;
    std::map<std::string, int64_t> m;
    for (auto it = counters.cbegin(); it != counters.cend(); ++it)
        m[it.key().toStdString()] = it.value();
    s->saveGroupSeqOut(m);
}

inline void saveGroupSeqIn(AppDataStore* s, const QMap<QString, qint64>& counters) {
    if (!s) return;
    std::map<std::string, int64_t> m;
    for (auto it = counters.cbegin(); it != counters.cend(); ++it)
        m[it.key().toStdString()] = it.value();
    s->saveGroupSeqIn(m);
}

inline QMap<QString, qint64> loadGroupSeqOut(const AppDataStore* s) {
    QMap<QString, qint64> out;
    if (!s) return out;
    for (const auto& [k, v] : s->loadGroupSeqOut())
        out.insert(QString::fromStdString(k), v);
    return out;
}

inline QMap<QString, qint64> loadGroupSeqIn(const AppDataStore* s) {
    QMap<QString, qint64> out;
    if (!s) return out;
    for (const auto& [k, v] : s->loadGroupSeqIn())
        out.insert(QString::fromStdString(k), v);
    return out;
}

} // namespace appData
