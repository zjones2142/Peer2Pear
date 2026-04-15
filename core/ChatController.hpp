#pragma once

#ifdef PEER2PEAR_P2P
class QuicConnection;  // forward declaration — full include in .cpp
#endif
#include <QObject>
#include <QTimer>
#include <QSet>
#include <QMap>

#include "CryptoEngine.hpp"
#include "RelayClient.hpp"
#include "SessionManager.hpp"
#include "SealedEnvelope.hpp"
#include "FileTransferManager.hpp"

#include "SqlCipherDb.hpp"
#include <memory>


class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(IWebSocket& ws, IHttpClient& http, QObject* parent = nullptr);

    void setPassphrase(const QString& pass);
    // Unified path: pass the pre-derived identity key from HKDF(masterKey, "identity-unlock")
    void setPassphrase(const QString& pass, const QByteArray& identityKey);
    void setRelayUrl(const QUrl& url);
    void setDatabase(SqlCipherDb& db);
    QString myIdB64u() const;
    const QByteArray& identityPub() const { return m_crypto.identityPub(); }

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

    void connectToRelay();
    void disconnectFromRelay();

    void setSelfKeys(const QStringList& keys);

    void sendGroupMessageViaMailbox(const QString& groupId,
                                    const QString& groupName,
                                    const QStringList& memberPeerIds,
                                    const QString& text);
    void sendGroupLeaveNotification(const QString& groupId,
                                    const QString& groupName,
                                    const QStringList& memberPeerIds);

    void checkPresence(const QStringList& peerIds);
    void subscribePresence(const QStringList& peerIds);

#ifdef PEER2PEAR_P2P
    void setTurnServer(const QString& host, int port,
                       const QString& username, const QString& password);
#endif

    void sendAvatar(const QString& peerIdB64u, const QString& displayName, const QString& avatarB64);

    void sendGroupRename(const QString& groupId, const QString& newName, const QStringList& memberKeys);
    void sendGroupAvatar(const QString& groupId, const QString& avatarB64, const QStringList& memberKeys);
    void sendGroupMemberUpdate(const QString& groupId, const QString& groupName, const QStringList& memberKeys);

    // G3: Wipe ratchet session for a peer, forcing a fresh Noise IK handshake
    void resetSession(const QString& peerIdB64u);

    // GAP5: restore/persist group sequence counters across restarts
    void setGroupSeqCounters(const QMap<QString, qint64>& seqOut,
                             const QMap<QString, qint64>& seqIn);
    const QMap<QString, qint64>& groupSeqOut() const { return m_groupSeqOut; }
    const QMap<QString, qint64>& groupSeqIn()  const { return m_groupSeqIn;  }

signals:
    void status(const QString& s);
    void relayConnected();
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

    // SEC9: emitted when a handshake with a peer is pruned (timed out) more
    // than once — likely means the peer is running an older client that
    // doesn't understand hybrid PQ Noise messages.
    void peerMayNeedUpgrade(const QString& peerIdB64u);

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
    void onEnvelope(const QByteArray& body);
#ifdef PEER2PEAR_P2P
    void onP2PDataReceived(const QString& peerIdB64u, const QByteArray& data);
#endif
    void onRelayConnected();

private:
    QByteArray sealForPeer(const QString& peerIdB64u, const QByteArray& plaintext);
    void sendSealedPayload(const QString& peerIdB64u, const QJsonObject& payload);
#ifdef PEER2PEAR_P2P
    QuicConnection* setupP2PConnection(const QString& peerIdB64u, bool controlling);
    void initiateP2PConnection(const QString& peerIdB64u);
#endif

    // ── Deduplication ─────────────────────────────────────────────────────────
    // Bounded set (capped at 2 000 entries); used for msgId and transferId.
    // Per-chunk dedup uses a separate key: "<transferId>:<chunkIndex>".
    static constexpr int kSeenIdsCap = 2000;
    QSet<QString>    m_seenIds;
    QVector<QString> m_seenOrder;
    bool markSeen(const QString& id); // true = first time; false = duplicate

    CryptoEngine         m_crypto;
    RelayClient          m_relay;
    FileTransferManager  m_fileMgr;

    // Session-based crypto (Noise IK + Double Ratchet + Sealed Sender)
    std::unique_ptr<SessionStore>   m_sessionStore;
    std::unique_ptr<SessionManager> m_sessionMgr;
    SqlCipherDb* m_dbPtr = nullptr;  // stored for KEM pub lookups

    QStringList m_selfKeys;

#ifdef PEER2PEAR_P2P
    QMap<QString, QuicConnection*> m_p2pConnections;
#endif

    // G5 fix: per-group outbound sequence counter (monotonic, not persisted)
    QMap<QString, qint64> m_groupSeqOut;
    // G5 fix: per-(group,sender) last-seen sequence — detects gaps
    QMap<QString, qint64> m_groupSeqIn;  // key: "groupId:senderId"

    // SEC9: count consecutive handshake timeouts per peer — 2+ suggests legacy client
    QMap<QString, int> m_handshakeFailCount;

    // Peer ML-KEM-768 public keys: peerIdB64u -> 1184-byte KEM pub
    // Populated by kem_pub_announce messages, used by sealForPeer() for hybrid envelopes
    QMap<QString, QByteArray> m_peerKemPubs;
    QSet<QString> m_kemPubAnnounced;  // peers we've already announced to this session
    QByteArray lookupPeerKemPub(const QString& peerIdB64u);
    void announceKemPub(const QString& peerIdB64u);

    // File transfer ratchet keys: senderId:transferId -> 32-byte symmetric key
    // Populated by file_key announcements, consumed by handleFileEnvelope()
    QMap<QString, QByteArray> m_fileKeys;
    // M8 fix: creation timestamps for m_fileKeys entries (epoch seconds)
    QMap<QString, qint64> m_fileKeyTimes;

    // H3 fix: per-sender envelope rate limiting
    // Tracks (senderId -> count) within current poll cycle; reset each poll.
    QMap<QString, int> m_envelopeCount;
    static constexpr int kMaxEnvelopesPerSenderPerPoll = 200;

#ifdef PEER2PEAR_P2P
    // TURN relay config for symmetric NAT fallback
    QString m_turnHost;
    int     m_turnPort = 0;
    QString m_turnUser;
    QString m_turnPass;
#endif

    // Periodic maintenance (handshake pruning, file key cleanup)
    QTimer m_maintenanceTimer;
};
