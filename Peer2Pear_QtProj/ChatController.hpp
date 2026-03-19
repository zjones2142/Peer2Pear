#pragma once

#include "NiceConnection.hpp"
#include <QObject>
#include <QTimer>
#include <QSet>
#include <QMap>

#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include "RendezvousClient.hpp"


class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(QObject* parent = nullptr);

    void setPassphrase(const QString& pass);
    void setServerBaseUrl(const QUrl& base);
    QString myIdB64u() const;

    // Send encrypted text to a peer
    void sendText(const QString& peerIdB64u, const QString& text);

    // Send an encrypted file, split into ≤ 256 KB chunks.
    // Returns the transferId on success or an empty string on failure.
    // The transferId is guaranteed to match the one embedded in every chunk
    // envelope, so the caller can build a local FileTransferRecord immediately.
    QString sendFile(const QString& peerIdB64u,
                     const QString& fileName,
                     const QByteArray& fileData);

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

signals:
    void status(const QString& s);

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

    // Emitted each time a chunk of an incoming transfer arrives.
    // chunksReceived == chunksTotal signals completion; fileData contains
    // the fully reassembled plaintext only at that final emission.
    void fileChunkReceived(const QString& fromPeerIdB64u,
                           const QString& transferId,
                           const QString& fileName,
                           qint64         fileSize,
                           int            chunksReceived,
                           int            chunksTotal,
                           const QByteArray& fileData,   // non-empty only when complete
                           const QDateTime& timestamp);

private slots:
    void pollOnce();
    void onEnvelope(const QByteArray& body, const QString& envId);
    void onP2PDataReceived(const QString& peerIdB64u, const QByteArray& data);

private:
    void sendSignalingMessage(const QString& peerIdB64u, const QJsonObject& payload);
    void initiateP2PConnection(const QString& peerIdB64u);

    // ── Incoming chunk reassembly ─────────────────────────────────────────────
    struct IncomingTransfer {
        QString   fromId;
        QString   fileName;
        qint64    fileSize    = 0;
        int       totalChunks = 0;
        QDateTime ts;
        QMap<int, QByteArray> chunks; // chunkIndex → decrypted chunk data
    };
    QMap<QString, IncomingTransfer> m_incomingTransfers; // transferId → state

    // ── Deduplication ─────────────────────────────────────────────────────────
    // Bounded set (capped at 2 000 entries); used for msgId and transferId.
    // Per-chunk dedup uses a separate key: "<transferId>:<chunkIndex>".
    static constexpr int kSeenIdsCap = 2000;
    QSet<QString>    m_seenIds;
    QVector<QString> m_seenOrder;
    bool markSeen(const QString& id); // true = first time; false = duplicate

    CryptoEngine     m_crypto;
    RendezvousClient m_rvz;
    MailboxClient    m_mbox;

    QTimer      m_pollTimer;
    QStringList m_selfKeys;

    QMap<QString, NiceConnection*> m_p2pConnections;

    // Refreshes rendezvous registration every 9 minutes (just under the 10-min TTL)
    QTimer m_rvzRefreshTimer;
};
