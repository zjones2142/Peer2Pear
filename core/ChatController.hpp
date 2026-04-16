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

    // Send an encrypted file via FileTransferManager — path-based, streams from disk.
    // Returns the transferId on success or an empty string on failure.
    QString sendFile(const QString& peerIdB64u,
                     const QString& fileName,
                     const QString& filePath);

    // Send an encrypted file to every member of a group chat — path-based.
    QString sendGroupFile(const QString& groupId,
                          const QString& groupName,
                          const QStringList& memberPeerIds,
                          const QString& fileName,
                          const QString& filePath);

    // Maximum allowed file size in bytes (25 MB).
    static constexpr qint64 maxFileBytes() { return FileTransferManager::kMaxFileBytes; }

    // Compute BLAKE2b-256 hash of data (used for integrity checks).
    static QByteArray blake2b256(const QByteArray& data) { return FileTransferManager::blake2b256(data); }

    FileTransferManager& fileTransferMgr() { return m_fileMgr; }
    RelayClient& relay() { return m_relay; }

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

    /// Fix #20: populate known-group-members state on startup from the UI's
    /// persisted group rosters.  ChatController rejects group_rename,
    /// group_avatar, group_member_update, and group_leave from peers who
    /// aren't currently members of the named group, defeating the spoof
    /// where a prior / evicted member (or anyone who learned the groupId)
    /// pushes updates with an attacker-chosen member list.
    ///
    /// Should be called once per known group after loading state at startup.
    void setKnownGroupMembers(const QString& groupId, const QStringList& members);

    // ── Phase 2: file-transfer consent ──────────────────────────────────────

    /// Accept a pending incoming file transfer. Installs the ratchet-derived
    /// file key so subsequent chunks decrypt, and sends file_accept to the sender.
    /// requireP2P tells the sender "I refuse relay fallback for this transfer"
    /// (Phase 3 enforces it; for now just forwarded in the file_accept message).
    void acceptFileTransfer(const QString& transferId, bool requireP2P = false);

    /// Decline a pending incoming file transfer. Discards the stashed key and
    /// sends file_decline (no reason field — anti-probing).
    void declineFileTransfer(const QString& transferId);

    /// Cancel an in-flight transfer — works for both outbound and inbound.
    /// Sender: aborts streaming, drops state. Receiver: closes + deletes partial.
    /// Sends file_cancel to the peer.
    void cancelFileTransfer(const QString& transferId);

    /// Global consent settings (persisted by the caller via DatabaseManager).
    void setFileAutoAcceptMaxMB(int mb) { m_fileAutoAcceptMaxMB = mb; }
    void setFileHardMaxMB(int mb)       { m_fileHardMaxMB       = mb; }
    void setFileRequireP2P(bool on)     {
        m_fileRequireP2P = on;
        // Fix #16: propagate live so in-flight streams upgrade to P2P-only
        // on the next chunk rather than finishing under the old policy.
        m_fileMgr.setSenderRequiresP2P(on);
    }
    int  fileAutoAcceptMaxMB() const    { return m_fileAutoAcceptMaxMB; }
    int  fileHardMaxMB() const          { return m_fileHardMaxMB; }
    bool fileRequireP2P() const         { return m_fileRequireP2P; }

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

    // ── Phase 2: file consent / cancellation signals ────────────────────────

    /// Receiver-side: an incoming file transfer needs user consent.
    /// UI should prompt Accept / Decline (with optional "require direct connection").
    void fileAcceptRequested(const QString& fromPeerIdB64u,
                             const QString& transferId,
                             const QString& fileName,
                             qint64 fileSize);

    /// Either direction: transfer was canceled, declined, or abandoned.
    /// byReceiver = true  → sender lost the race (receiver declined/canceled)
    /// byReceiver = false → receiver lost the race (sender canceled/gave up)
    void fileTransferCanceled(const QString& transferId, bool byReceiver);

    /// Phase 3: receiver confirmed the full file arrived with a valid hash.
    /// Sender-side UI should flip the record to Delivered.
    void fileTransferDelivered(const QString& transferId);

    /// Phase 3: the transport policy (Privacy Level 2 or fileRequireP2P)
    /// blocked the transfer after P2P failed to come up in time.
    /// byReceiver = true → receiver's requireP2P refused relay fallback
    /// byReceiver = false → our own privacy setting refused relay fallback
    void fileTransferBlocked(const QString& transferId, bool byReceiver);

    // Emitted each time a chunk of an incoming transfer arrives.
    // chunksReceived == chunksTotal signals completion; savedPath is the
    // on-disk location of the received file (non-empty only when complete).
    // Files are streamed to disk — no full-file buffer is ever held in RAM.
    // groupId is non-empty when this file was sent to a group chat.
    void fileChunkReceived(const QString& fromPeerIdB64u,
                           const QString& transferId,
                           const QString& fileName,
                           qint64         fileSize,
                           int            chunksReceived,
                           int            chunksTotal,
                           const QString& savedPath,     // non-empty only when complete
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

    // Fix #20: is `peerId` currently a known member of group `gid`?
    // Returns true (permissively) only for groups we've never seen before;
    // otherwise false unless peerId is in our roster.
    bool isAuthorizedGroupSender(const QString& gid, const QString& peerId) const;
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

    // Fix #20: known members per group, bootstrapped by setKnownGroupMembers
    // from persisted UI state and updated as trusted group messages arrive.
    // Used to authorize group_member_update / group_leave / group_rename /
    // group_avatar — messages from peers not in this set are dropped.
    QMap<QString, QSet<QString>> m_groupMembers;
    // True for groups we have no prior knowledge of — the first sender of a
    // group_msg bootstraps the roster.  Once populated, entry is removed.
    QSet<QString> m_groupBootstrapNeeded;

    // SEC9: count consecutive handshake timeouts per peer — 2+ suggests legacy client
    QMap<QString, int> m_handshakeFailCount;

    // Peer ML-KEM-768 public keys: peerIdB64u -> 1184-byte KEM pub
    // Populated by kem_pub_announce messages, used by sealForPeer() for hybrid envelopes
    QMap<QString, QByteArray> m_peerKemPubs;
    QSet<QString> m_kemPubAnnounced;  // peers we've already announced to this session
    QByteArray lookupPeerKemPub(const QString& peerIdB64u);
    void announceKemPub(const QString& peerIdB64u);

    // File transfer ratchet keys: senderId:transferId -> 32-byte symmetric key
    // Populated by file_key announcements (after consent), consumed by handleFileEnvelope().
    // Lifetime bounded by FileTransferManager's 7-day partial-file purge — no
    // separate in-memory TTL (Fix #4: the older 30-min TTL would expire keys
    // while the DB still held the transfer, causing livelock resumptions).
    QMap<QString, QByteArray> m_fileKeys;

    // ── Phase 2: incoming file transfers awaiting user consent ──────────────
    // When a file_key arrives but policy says "prompt", we stash the key here
    // (instead of m_fileKeys) so chunks arriving before the user responds will
    // drop silently. On accept → move into m_fileKeys. On decline → zero + drop.
    struct PendingIncoming {
        QString    peerId;
        QString    fileName;
        qint64     fileSize    = 0;
        QByteArray fileKey;            // 32 bytes, zeroed on drop
        QByteArray fileHash;           // 32 bytes — locked at file_key time
        int        totalChunks  = 0;   // locked at file_key time
        qint64     announcedTs  = 0;   // sender's ts from file_key
        QString    groupId;
        QString    groupName;
        qint64     announcedSecs = 0;
    };
    QMap<QString, PendingIncoming> m_pendingIncomingFiles;

    // Consent settings (persisted by the application via DatabaseManager).
    // Defaults match v1 behavior: everything below hard-max auto-accepts.
    int  m_fileAutoAcceptMaxMB = 100;  // everything ≤ this auto-accepts
    int  m_fileHardMaxMB       = 100;  // anything > this auto-declines
    bool m_fileRequireP2P      = false;

    // Internal: construct and route control messages via ratchet.
    void sendFileControlMessage(const QString& peerIdB64u, const QJsonObject& msg);

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
