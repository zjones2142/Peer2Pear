#pragma once

#ifdef PEER2PEAR_P2P
class QuicConnection;  // forward declaration — full include in .cpp
#endif

// Qt is no longer part of ChatController's public surface.  All types are
// std::* (string / vector / map / set) or Bytes (std::vector<uint8_t>).
// QObject was stripped in Phase 7b; Qt::Core was dropped from core/ in
// Phase 7c — desktop/ still uses Qt for UI but calls the std-typed surface
// with toStdString()/fromStdString() at the boundary.

#include <nlohmann/json.hpp>

#include "CryptoEngine.hpp"
#include "RelayClient.hpp"
#include "SessionManager.hpp"
#include "SealedEnvelope.hpp"
#include "FileTransferManager.hpp"
#include "ITimer.hpp"

#include "SqlCipherDb.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>


class ChatController {
public:
    explicit ChatController(IWebSocket& ws, IHttpClient& http,
                            ITimerFactory& timers);

    // Set the app data directory (where identity.json + per-user DB live).
    // Must be called before setPassphrase() on hosts that don't have a
    // platform default (iOS, Android).  Desktop builds pick up the platform
    // AppDataLocation via CryptoEngine if this is unset.
    void setDataDir(const std::string& dir) { m_crypto.setDataDir(dir); }

    void setPassphrase(const std::string& pass);
    // Unified path: pass the pre-derived identity key from HKDF(masterKey, "identity-unlock")
    void setPassphrase(const std::string& pass, const Bytes& identityKey);
    void setRelayUrl(const std::string& url);
    void setDatabase(SqlCipherDb& db);
    std::string myIdB64u() const;
    const Bytes& identityPub() const { return m_crypto.identityPub(); }

    // Send encrypted text to a peer
    void sendText(const std::string& peerIdB64u, const std::string& text);

    // Send an encrypted file via FileTransferManager — path-based, streams from disk.
    // Returns the transferId on success or an empty string on failure.
    std::string sendFile(const std::string& peerIdB64u,
                         const std::string& fileName,
                         const std::string& filePath);

    // Send an encrypted file to every member of a group chat — path-based.
    std::string sendGroupFile(const std::string& groupId,
                              const std::string& groupName,
                              const std::vector<std::string>& memberPeerIds,
                              const std::string& fileName,
                              const std::string& filePath);

    // Maximum allowed file size in bytes (25 MB).
    static constexpr int64_t maxFileBytes() { return FileTransferManager::kMaxFileBytes; }

    // Compute BLAKE2b-256 hash of data (used for integrity checks).
    static Bytes blake2b256(const Bytes& data) {
        return FileTransferManager::blake2b256(data);
    }

    FileTransferManager& fileTransferMgr() { return m_fileMgr; }
    RelayClient& relay() { return m_relay; }

    void connectToRelay();
    void disconnectFromRelay();

    void setSelfKeys(const std::vector<std::string>& keys);

    void sendGroupMessageViaMailbox(const std::string& groupId,
                                    const std::string& groupName,
                                    const std::vector<std::string>& memberPeerIds,
                                    const std::string& text);
    void sendGroupLeaveNotification(const std::string& groupId,
                                    const std::string& groupName,
                                    const std::vector<std::string>& memberPeerIds);

    void checkPresence(const std::vector<std::string>& peerIds);
    void subscribePresence(const std::vector<std::string>& peerIds);

#ifdef PEER2PEAR_P2P
    void setTurnServer(const std::string& host, int port,
                       const std::string& username, const std::string& password);
#endif

    void sendAvatar(const std::string& peerIdB64u, const std::string& displayName, const std::string& avatarB64);

    void sendGroupRename(const std::string& groupId, const std::string& newName, const std::vector<std::string>& memberKeys);
    void sendGroupAvatar(const std::string& groupId, const std::string& avatarB64, const std::vector<std::string>& memberKeys);
    void sendGroupMemberUpdate(const std::string& groupId, const std::string& groupName, const std::vector<std::string>& memberKeys);

    // G3: Wipe ratchet session for a peer, forcing a fresh Noise IK handshake
    void resetSession(const std::string& peerIdB64u);

    // GAP5: restore/persist group sequence counters across restarts
    void setGroupSeqCounters(const std::map<std::string, int64_t>& seqOut,
                             const std::map<std::string, int64_t>& seqIn);
    const std::map<std::string, int64_t>& groupSeqOut() const { return m_groupSeqOut; }
    const std::map<std::string, int64_t>& groupSeqIn()  const { return m_groupSeqIn;  }

    /// Fix #20: populate known-group-members state on startup from the UI's
    /// persisted group rosters.  ChatController rejects group_rename,
    /// group_avatar, group_member_update, and group_leave from peers who
    /// aren't currently members of the named group, defeating the spoof
    /// where a prior / evicted member (or anyone who learned the groupId)
    /// pushes updates with an attacker-chosen member list.
    ///
    /// Should be called once per known group after loading state at startup.
    void setKnownGroupMembers(const std::string& groupId, const std::vector<std::string>& members);

    // ── Phase 2: file-transfer consent ──────────────────────────────────────

    /// Accept a pending incoming file transfer. Installs the ratchet-derived
    /// file key so subsequent chunks decrypt, and sends file_accept to the sender.
    /// requireP2P tells the sender "I refuse relay fallback for this transfer"
    /// (Phase 3 enforces it; for now just forwarded in the file_accept message).
    void acceptFileTransfer(const std::string& transferId, bool requireP2P = false);

    /// Decline a pending incoming file transfer. Discards the stashed key and
    /// sends file_decline (no reason field — anti-probing).
    void declineFileTransfer(const std::string& transferId);

    /// Cancel an in-flight transfer — works for both outbound and inbound.
    /// Sender: aborts streaming, drops state. Receiver: closes + deletes partial.
    /// Sends file_cancel to the peer.
    void cancelFileTransfer(const std::string& transferId);

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

    // ── Event callbacks — plain class, no signals ──────────────────────────
    //
    // Each replaces a former Qt signal.  Assign directly:
    //   controller.onMessageReceived = [this](auto&&... args){ ... };
    //
    // Timestamps are unix-epoch seconds (int64_t).  The UI converts to its
    // preferred calendar type at the boundary.

    std::function<void(const std::string&)> onStatus;
    std::function<void()>               onRelayConnected;
    std::function<void(const std::string&, bool)> onPresenceChanged;

    std::function<void(const std::string& from, const std::string& text,
                       int64_t tsSecs, const std::string& msgId)>
        onMessageReceived;

    std::function<void(const std::string& from, const std::string& groupId,
                       const std::string& groupName, const std::vector<std::string>& members,
                       const std::string& text, int64_t tsSecs,
                       const std::string& msgId)>
        onGroupMessageReceived;

    std::function<void(const std::string& from, const std::string& groupId,
                       const std::string& groupName, const std::vector<std::string>& members,
                       int64_t tsSecs, const std::string& msgId)>
        onGroupMemberLeft;

    std::function<void(const std::string& peerId, const std::string& displayName,
                       const std::string& avatarB64)>
        onAvatarReceived;

    std::function<void(const std::string& groupId, const std::string& newName)>
        onGroupRenamed;
    std::function<void(const std::string& groupId, const std::string& avatarB64)>
        onGroupAvatarReceived;

    /// SEC9: peer may be running an older client that doesn't support our
    /// current hybrid-PQ Noise messages.
    std::function<void(const std::string& peerId)> onPeerMayNeedUpgrade;

    // ── Phase 2: file consent / cancellation callbacks ──────────────────────
    std::function<void(const std::string& from, const std::string& transferId,
                       const std::string& fileName, int64_t fileSize)>
        onFileAcceptRequested;
    std::function<void(const std::string& transferId, bool byReceiver)>
        onFileTransferCanceled;
    std::function<void(const std::string& transferId)>
        onFileTransferDelivered;
    std::function<void(const std::string& transferId, bool byReceiver)>
        onFileTransferBlocked;

    std::function<void(const std::string& from, const std::string& transferId,
                       const std::string& fileName, int64_t fileSize,
                       int chunksReceived, int chunksTotal,
                       const std::string& savedPath, int64_t tsSecs,
                       const std::string& groupId, const std::string& groupName)>
        onFileChunkReceived;

private:
    void onEnvelope(const Bytes& body);
#ifdef PEER2PEAR_P2P
    void onP2PDataReceived(const std::string& peerIdB64u, const Bytes& data);
#endif
    void handleRelayConnected();

private:
    Bytes sealForPeer(const std::string& peerIdB64u, const Bytes& plaintext);
    void sendSealedPayload(const std::string& peerIdB64u, const nlohmann::json& payload);

    // Fix #20: is `peerId` currently a known member of group `gid`?
    // Returns true (permissively) only for groups we've never seen before;
    // otherwise false unless peerId is in our roster.
    bool isAuthorizedGroupSender(const std::string& gid, const std::string& peerId) const;
#ifdef PEER2PEAR_P2P
    QuicConnection* setupP2PConnection(const std::string& peerIdB64u, bool controlling);
    void initiateP2PConnection(const std::string& peerIdB64u);
#endif

    // ── Deduplication ─────────────────────────────────────────────────────────
    // Bounded set (capped at 2 000 entries); used for msgId and transferId.
    // Per-chunk dedup uses a separate key: "<transferId>:<chunkIndex>".
    static constexpr int kSeenIdsCap = 2000;
    std::set<std::string>    m_seenIds;
    std::vector<std::string> m_seenOrder;
    bool markSeen(const std::string& id); // true = first time; false = duplicate

    CryptoEngine         m_crypto;
    RelayClient          m_relay;
    FileTransferManager  m_fileMgr;

    // Session-based crypto (Noise IK + Double Ratchet + Sealed Sender)
    std::unique_ptr<SessionStore>   m_sessionStore;
    std::unique_ptr<SessionManager> m_sessionMgr;
    SqlCipherDb* m_dbPtr = nullptr;  // stored for KEM pub lookups

    std::vector<std::string> m_selfKeys;

#ifdef PEER2PEAR_P2P
    std::map<std::string, QuicConnection*> m_p2pConnections;
    // Per-peer P2P connection creation timestamp, used by the maintenance
    // timer's cleanup pass to give in-progress ICE negotiations a grace
    // period before pruning.  Without this, a connection that takes >30s
    // to complete ICE (common on real networks behind NAT) would get
    // killed mid-handshake by the default cleanup.
    std::map<std::string, int64_t> m_p2pCreatedSecs;
    // Do not prune a P2P connection until it's been alive at least this
    // long without reaching isReady().  ICE + QUIC handshake on cellular
    // or corporate networks routinely takes 30-60s.
    static constexpr int64_t kP2PCleanupGraceSecs = 120;
#endif

    // G5 fix: per-group outbound sequence counter (monotonic, not persisted)
    std::map<std::string, int64_t> m_groupSeqOut;
    // G5 fix: per-(group,sender) last-seen sequence — detects gaps
    std::map<std::string, int64_t> m_groupSeqIn;  // key: "groupId:senderId"

    // Fix #20: known members per group, bootstrapped by setKnownGroupMembers
    // from persisted UI state and updated as trusted group messages arrive.
    // Used to authorize group_member_update / group_leave / group_rename /
    // group_avatar — messages from peers not in this set are dropped.
    std::map<std::string, std::set<std::string>> m_groupMembers;
    // (m_groupBootstrapNeeded removed in LC5 cleanup — was never populated.)

    // SEC9: count consecutive handshake timeouts per peer — 2+ suggests legacy client
    std::map<std::string, int> m_handshakeFailCount;

    // Peer ML-KEM-768 public keys: peerIdB64u -> 1184-byte KEM pub
    // Populated by kem_pub_announce messages, used by sealForPeer() for hybrid envelopes
    std::map<std::string, Bytes> m_peerKemPubs;
    std::set<std::string> m_kemPubAnnounced;  // peers we've already announced to this session
    Bytes lookupPeerKemPub(const std::string& peerIdB64u);
    void announceKemPub(const std::string& peerIdB64u);

    // File transfer ratchet keys: senderId:transferId -> 32-byte symmetric key
    // Populated by file_key announcements (after consent), consumed by handleFileEnvelope().
    // Lifetime bounded by FileTransferManager's 7-day partial-file purge — no
    // separate in-memory TTL (Fix #4: the older 30-min TTL would expire keys
    // while the DB still held the transfer, causing livelock resumptions).
    std::map<std::string, Bytes> m_fileKeys;

    // ── Phase 2: incoming file transfers awaiting user consent ──────────────
    // When a file_key arrives but policy says "prompt", we stash the key here
    // (instead of m_fileKeys) so chunks arriving before the user responds will
    // drop silently. On accept → move into m_fileKeys. On decline → zero + drop.
    struct PendingIncoming {
        std::string peerId;
        std::string fileName;
        int64_t     fileSize    = 0;
        Bytes       fileKey;            // 32 bytes, zeroed on drop
        Bytes       fileHash;           // 32 bytes — locked at file_key time
        int         totalChunks  = 0;   // locked at file_key time
        int64_t     announcedTs  = 0;   // sender's ts from file_key
        std::string groupId;
        std::string groupName;
        int64_t     announcedSecs = 0;
    };
    std::map<std::string, PendingIncoming> m_pendingIncomingFiles;

    // Consent settings (persisted by the application via DatabaseManager).
    // Defaults match v1 behavior: everything below hard-max auto-accepts.
    int  m_fileAutoAcceptMaxMB = 100;  // everything ≤ this auto-accepts
    int  m_fileHardMaxMB       = 100;  // anything > this auto-declines
    bool m_fileRequireP2P      = false;

    // Internal: construct and route control messages via ratchet.
    void sendFileControlMessage(const std::string& peerIdB64u, const nlohmann::json& msg);

    // H3 fix: per-sender envelope rate limiting
    // Tracks (senderId -> count) within current poll cycle; reset each poll.
    std::map<std::string, int> m_envelopeCount;
    static constexpr int kMaxEnvelopesPerSenderPerPoll = 200;

#ifdef PEER2PEAR_P2P
    // TURN relay config for symmetric NAT fallback
    std::string m_turnHost;
    int         m_turnPort = 0;
    std::string m_turnUser;
    std::string m_turnPass;
#endif

    // Periodic maintenance (handshake pruning, file key cleanup)
    ITimerFactory*          m_timerFactory = nullptr;
    std::unique_ptr<ITimer> m_maintenanceTimer;
    void scheduleMaintenance();
    void runMaintenance();
};
