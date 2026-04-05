#pragma once

#include "NiceConnection.hpp"
#include <QObject>
#include <QTimer>
#include <QSet>
#include <QMap>

#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include "RendezvousClient.hpp"
#include "SessionManager.hpp"
#include "SealedEnvelope.hpp"
#include "FileTransferManager.hpp"

#include <QtSql/QSqlDatabase>
#include <memory>


class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(QObject* parent = nullptr);

    void setPassphrase(const QString& pass);
    void setServerBaseUrl(const QUrl& base);
    void setDatabase(QSqlDatabase db);
    QString myIdB64u() const;

    // Send encrypted text to a peer
    void sendText(const QString& peerIdB64u, const QString& text);

    // Send an encrypted file via FileTransferManager.
    // Returns the transferId on success or an empty string on failure.
    QString sendFile(const QString& peerIdB64u,
                     const QString& fileName,
                     const QByteArray& fileData);

    // Send an encrypted file to every member of a group chat.
    QString sendGroupFile(const QString& groupId,
                          const QString& groupName,
                          const QStringList& memberPeerIds,
                          const QString& fileName,
                          const QByteArray& fileData);

    // Maximum allowed file size in bytes (25 MB).
    static constexpr qint64 maxFileBytes() { return FileTransferManager::kMaxFileBytes; }

    // Compute BLAKE2b-256 hash of data (used for integrity checks).
    static QByteArray blake2b256(const QByteArray& data) { return FileTransferManager::blake2b256(data); }

    FileTransferManager& fileTransferMgr() { return m_fileMgr; }

    void startPolling(int intervalMs = 2000);
    void stopPolling();

    void setSelfKeys(const QStringList& keys);

    void sendGroupMessageViaMailbox(const QString& groupId,
                                    const QString& groupName,
                                    const QStringList& memberPeerIds,
                                    const QString& text);
    void sendGroupLeaveNotification(const QString& groupId,
                                    const QString& groupName,
                                    const QStringList& memberPeerIds);

    void checkPresence(const QStringList& peerIds);

    void setTurnServer(const QString& host, int port,
                       const QString& username, const QString& password);

    void sendAvatar(const QString& peerIdB64u, const QString& displayName, const QString& avatarB64);

    void sendGroupRename(const QString& groupId, const QString& newName, const QStringList& memberKeys);
    void sendGroupAvatar(const QString& groupId, const QString& avatarB64, const QStringList& memberKeys);

    // G3: Wipe ratchet session for a peer, forcing a fresh Noise IK handshake
    void resetSession(const QString& peerIdB64u);

signals:
    void status(const QString& s);
    void presenceChanged(const QString& peerIdB64u, bool online);

    void messageReceived(const QString& fromPeerIdB64u,
                         const QString& text,
                         const QDateTime& timestamp,
                         const QString& msgId);

    void groupMessageReceived(const QString& fromPeerIdB64u,
                              const QString& groupId,
                              const QString& groupName,
                              const QStringList& memberKeys,
                              const QString& text,
                              const QDateTime& ts,
                              const QString& msgId);
    void groupMemberLeft(const QString& fromPeerIdB64u,
                         const QString& groupId,
                         const QString& groupName,
                         const QStringList& memberKeys,
                         const QDateTime& ts,
                         const QString& msgId);

    void avatarReceived(const QString& peerIdB64u, const QString& displayName, const QString& avatarB64);
    void groupRenamed(const QString& groupId, const QString& newName);
    void groupAvatarReceived(const QString& groupId, const QString& avatarB64);

    // Emitted each time a chunk of an incoming transfer arrives.
    // chunksReceived == chunksTotal signals completion; fileData contains
    // the fully reassembled plaintext only at that final emission.
    // groupId is non-empty when this file was sent to a group chat.
    void fileChunkReceived(const QString& fromPeerIdB64u,
                           const QString& transferId,
                           const QString& fileName,
                           qint64         fileSize,
                           int            chunksReceived,
                           int            chunksTotal,
                           const QByteArray& fileData,   // non-empty only when complete
                           const QDateTime& timestamp,
                           const QString& groupId = {},
                           const QString& groupName = {});

private slots:
    void pollOnce();
    void onEnvelope(const QByteArray& body, const QString& envId);
    void onP2PDataReceived(const QString& peerIdB64u, const QByteArray& data);

private:
    QByteArray sealForPeer(const QString& peerIdB64u, const QByteArray& plaintext);
    void sendSealedPayload(const QString& peerIdB64u, const QJsonObject& payload);
    NiceConnection* setupP2PConnection(const QString& peerIdB64u, bool controlling);
    void initiateP2PConnection(const QString& peerIdB64u);

    // ── Deduplication ─────────────────────────────────────────────────────────
    // Bounded set (capped at 2 000 entries); used for msgId and transferId.
    // Per-chunk dedup uses a separate key: "<transferId>:<chunkIndex>".
    static constexpr int kSeenIdsCap = 2000;
    QSet<QString>    m_seenIds;
    QVector<QString> m_seenOrder;
    bool markSeen(const QString& id); // true = first time; false = duplicate

    CryptoEngine         m_crypto;
    RendezvousClient     m_rvz;
    MailboxClient        m_mbox;
    FileTransferManager  m_fileMgr;

    // Session-based crypto (Noise IK + Double Ratchet + Sealed Sender)
    std::unique_ptr<SessionStore>   m_sessionStore;
    std::unique_ptr<SessionManager> m_sessionMgr;

    QTimer      m_pollTimer;
    QStringList m_selfKeys;

    QMap<QString, NiceConnection*> m_p2pConnections;

    // G5 fix: per-group outbound sequence counter (monotonic, not persisted)
    QMap<QString, qint64> m_groupSeqOut;
    // G5 fix: per-(group,sender) last-seen sequence — detects gaps
    QMap<QString, qint64> m_groupSeqIn;  // key: "groupId:senderId"

    // File transfer ratchet keys: senderId:transferId -> 32-byte symmetric key
    // Populated by file_key announcements, consumed by handleFileEnvelope()
    QMap<QString, QByteArray> m_fileKeys;
    // M8 fix: creation timestamps for m_fileKeys entries (epoch seconds)
    QMap<QString, qint64> m_fileKeyTimes;

    // H3 fix: per-sender envelope rate limiting
    // Tracks (senderId -> count) within current poll cycle; reset each poll.
    QMap<QString, int> m_envelopeCount;
    static constexpr int kMaxEnvelopesPerSenderPerPoll = 200;

    // TURN relay config for symmetric NAT fallback
    QString m_turnHost;
    int     m_turnPort = 0;
    QString m_turnUser;
    QString m_turnPass;

    // Refreshes rendezvous presence every 50 seconds (just under the 60-s TTL)
    QTimer m_rvzRefreshTimer;
};
