#pragma once

#ifdef PEER2PEAR_P2P
class QuicConnection;  // forward declaration — full include in .cpp
#endif

// Qt is not part of ChatController's public surface.  All types are std::*
// (string / vector / map / set) or Bytes (std::vector<uint8_t>).  desktop/
// still uses Qt for UI but calls the std-typed surface with
// toStdString()/fromStdString() at the boundary.

#include <nlohmann/json.hpp>

#include "CryptoEngine.hpp"
#include "RelayClient.hpp"
#include "SessionManager.hpp"
#include "SealedEnvelope.hpp"
#include "SessionSealer.hpp"
#include "GroupProtocol.hpp"
#include "FileProtocol.hpp"
#include "FileTransferManager.hpp"
#include "ITimer.hpp"

#include "SqlCipherDb.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>


class ChatController {
public:
    explicit ChatController(IWebSocket& ws, IHttpClient& http,
                            ITimerFactory& timers);

    // Zero TURN creds + key material on destruction.
    ~ChatController();

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

    // Wipe ratchet session for a peer, forcing a fresh Noise IK handshake.
    void resetSession(const std::string& peerIdB64u);

    // ── Safety numbers / out-of-band key verification ──────────────────────
    //
    // Without safety numbers, Alice has no way to confirm the peerId she
    // received via any out-of-band channel (invite link, QR scan) wasn't
    // MITM'd.
    //
    // Trust states:
    //   Unverified — no record; first contact; messaging works with a
    //                soft "unverified" indicator in the UI.
    //   Verified   — user compared safety numbers out-of-band and
    //                confirmed.  Current fingerprint matches stored.
    //   Mismatch   — stored fingerprint no longer matches current —
    //                usually means the local identity was regenerated
    //                (fresh install) and every verification is stale.
    //                Fires onPeerKeyChanged.  If hard-block toggle is on,
    //                sends + receives for that peer are refused.
    // Re-exported from SessionSealer so existing callers (C API, tests,
    // desktop/chatview.cpp) can keep using ChatController::PeerTrust.
    using PeerTrust = SessionSealer::PeerTrust;

    /// Returns the 60-digit safety-number display string for the
    /// (self, peer) pair.  Empty on invalid peerId.
    std::string safetyNumber(const std::string& peerIdB64u) const {
        return m_sealer.safetyNumber(peerIdB64u);
    }

    /// Current verification state for peer.  Computed fresh each call.
    PeerTrust peerTrust(const std::string& peerIdB64u) const {
        return m_sealer.peerTrust(peerIdB64u);
    }

    // Wipe the in-memory fingerprint cache.  See SessionSealer for
    // when / why to call this (test fixtures + migration tooling).
    void clearPeerKeyCache() { m_sealer.clearPeerKeyCache(); }

    /// Persist "user has compared safety numbers and confirmed".  The
    /// current (self, peer) fingerprint is stored; mismatches surface if
    /// either side changes.  Returns false on invalid peerId.
    bool markPeerVerified(const std::string& peerIdB64u) {
        return m_sealer.markPeerVerified(peerIdB64u);
    }

    /// Forget the verification for a peer — they become Unverified.
    void unverifyPeer(const std::string& peerIdB64u) {
        m_sealer.unverifyPeer(peerIdB64u);
    }

    /// Policy toggle: when true, messages to/from a Mismatch peer are
    /// blocked at the ChatController level.  Default false (soft warn
    /// via onPeerKeyChanged; UI decides how to surface).
    void setHardBlockOnKeyChange(bool on) { m_sealer.setHardBlockOnKeyChange(on); }
    bool hardBlockOnKeyChange() const     { return m_sealer.hardBlockOnKeyChange(); }

    // Restore/persist group sequence counters across restarts.  Delegates
    // to GroupProtocol — the counters themselves live there.
    void setGroupSeqCounters(const std::map<std::string, int64_t>& seqOut,
                             const std::map<std::string, int64_t>& seqIn) {
        m_groupProto.setSeqCounters(seqOut, seqIn);
    }
    const std::map<std::string, int64_t>& groupSeqOut() const {
        return m_groupProto.seqOut();
    }
    const std::map<std::string, int64_t>& groupSeqIn() const {
        return m_groupProto.seqIn();
    }

    /// Populate known-group-members state on startup from the UI's
    /// persisted group rosters.  ChatController rejects group_rename,
    /// group_avatar, group_member_update, and group_leave from peers who
    /// aren't currently members of the named group, defeating the spoof
    /// where a prior / evicted member (or anyone who learned the groupId)
    /// pushes updates with an attacker-chosen member list.
    ///
    /// Should be called once per known group after loading state at startup.
    void setKnownGroupMembers(const std::string& groupId, const std::vector<std::string>& members);

    // ── File-transfer consent ───────────────────────────────────────────────

    /// Accept a pending incoming file transfer.  Installs the ratchet-
    /// derived file key so subsequent chunks decrypt, and sends file_accept
    /// to the sender.  requireP2P tells the sender "I refuse relay fallback
    /// for this transfer" (for now just forwarded in the file_accept
    /// message).
    void acceptFileTransfer(const std::string& transferId, bool requireP2P = false) {
        m_fileProto.acceptIncoming(transferId, requireP2P);
    }

    /// Decline a pending incoming file transfer. Discards the stashed key and
    /// sends file_decline (no reason field — anti-probing).
    void declineFileTransfer(const std::string& transferId) {
        m_fileProto.declineIncoming(transferId);
    }

    /// Cancel an in-flight transfer — works for both outbound and inbound.
    /// Sender: aborts streaming, drops state. Receiver: closes + deletes partial.
    /// Sends file_cancel to the peer.
    void cancelFileTransfer(const std::string& transferId) {
        m_fileProto.cancel(transferId);
    }

    /// Global consent settings (persisted by the caller via DatabaseManager).
    void setFileAutoAcceptMaxMB(int mb) { m_fileProto.setAutoAcceptMaxMB(mb); }
    void setFileHardMaxMB(int mb)       { m_fileProto.setHardMaxMB(mb); }
    void setFileRequireP2P(bool on)     {
        m_fileProto.setRequireP2P(on);
        // Propagate live so in-flight streams upgrade to P2P-only on the
        // next chunk rather than finishing under the prior policy.
        m_fileMgr.setSenderRequiresP2P(on);
    }
    int  fileAutoAcceptMaxMB() const    { return m_fileProto.autoAcceptMaxMB(); }
    int  fileHardMaxMB() const          { return m_fileProto.hardMaxMB(); }
    bool fileRequireP2P() const         { return m_fileProto.requireP2P(); }

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

    /// Peer may be running an older client that doesn't support our
    /// current hybrid-PQ Noise messages.
    std::function<void(const std::string& peerId)> onPeerMayNeedUpgrade;

    /// Safety numbers: fires ONCE per session when a verified peer's
    /// fingerprint no longer matches (usually: local identity regenerated,
    /// or DB tampering).  The UI should surface a banner.  `oldFingerprint`
    /// is the stored 32-byte BLAKE2b, `newFingerprint` is the freshly-
    /// computed one.
    std::function<void(const std::string& peerId,
                       const Bytes&       oldFingerprint,
                       const Bytes&       newFingerprint)> onPeerKeyChanged;

    // ── File consent / cancellation callbacks ───────────────────────────────
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

    /// Sender-side per-chunk progress.  Fires after every outbound chunk
    /// dispatches (relay or P2P).  UIs use this to draw a progress bar
    /// for files THEY send; onFileChunkReceived covers inbound.
    /// `to` is the recipient peer ID (b64url).
    std::function<void(const std::string& to, const std::string& transferId,
                       const std::string& fileName, int64_t fileSize,
                       int chunksSent, int chunksTotal,
                       int64_t tsSecs,
                       const std::string& groupId, const std::string& groupName)>
        onFileChunkSent;

private:
    void onEnvelope(const Bytes& body);
    // Splits onEnvelope: the outer method owns unseal / session-decrypt /
    // rate-limit / safety-number check, then hands the decrypted JSON
    // payload here for type-dispatch.  Separating the two keeps each
    // function under control (both were ~640 lines in one pre-split).
    // `via` is "RELAY" or "P2P" and is only used for log tagging + the
    // "P2P presence heartbeat" behaviour.
    // `msgKey` is the 32-byte ratchet message key from the just-completed
    // session decrypt.  The file_key handler installs it as the file's
    // AEAD key; other handlers ignore it.  Passed by value so the handler
    // can zero it on exit.
    void dispatchSealedPayload(const nlohmann::json& o,
                                const std::string& senderId,
                                int64_t tsSecs,
                                const std::string& msgId,
                                const std::string& via,
                                Bytes msgKey);

    // Decrypt a `group_rename` / `group_avatar` / `group_leave` /
    // `group_member_update` envelope and return the parsed inner JSON,
    // or an empty optional on any failure (malformed envelope,
    // unauthorized sender, decrypt failed, inner JSON malformed).
    // Every branch used to open-code the same five-step pattern;
    // collapsing here makes the control-message handlers one-liners
    // and guarantees they stay in sync when the pattern evolves.
    //
    // `requireAuthorizedSender = false` is for bootstrap-capable
    // messages (`group_member_update`) that have their own auth
    // check after decryption.
    std::optional<nlohmann::json> decryptGroupControlInner(
        const std::string& msgType,
        const std::string& senderId,
        const nlohmann::json& outer,
        bool requireAuthorizedSender);
#ifdef PEER2PEAR_P2P
    void onP2PDataReceived(const std::string& peerIdB64u, const Bytes& data);
#endif
    void handleRelayConnected();

private:
    // Transport preference for sendSealedPayload.  RelayOnly is the
    // default — used for every message type that should never go
    // direct (ICE / KEM announce / group fan-outs).  PreferP2P tries
    // the direct QUIC stream first and falls back to the relay,
    // initiating a new P2P connection on the way.  Only 1:1 text
    // uses PreferP2P today.
    enum class SendMode { RelayOnly, PreferP2P };

    // Seal + send.  Thin wrapper — the sealing itself lives on
    // SessionSealer (the choke point for safety-number enforcement);
    // this just adds the "hand the sealed envelope to the relay /
    // direct QUIC stream" step.  Arch-review #3: sendText used to
    // open-code its own seal-then-dispatch inline; sendSealedPayload
    // is now the single outbound code path for everything that goes
    // through the ratchet.
    void sendSealedPayload(const std::string& peerIdB64u,
                            const nlohmann::json& payload,
                            SendMode mode = SendMode::RelayOnly);

    // Roster authorization for inbound group control messages lives on
    // GroupProtocol.  onEnvelope calls m_groupProto.isAuthorizedSender
    // directly — no local indirection needed.
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

    // Persistent envelope-ID dedup survives app restart.  Backs the
    // in-memory LRU with a row in seen_envelopes so a malicious relay
    // can't replay a sealed envelope after we restart and our RAM cache
    // is cold.  Use this (not markSeen) for the outer env: check; msgIds
    // inside the ratchet don't need persistence because the chain counter
    // already rejects replays once a message key is consumed.
    bool markSeenPersistent(const std::string& id);
    void ensureSeenEnvelopesTable();
    void pruneSeenEnvelopes();
    static constexpr int64_t kSeenEnvelopesMaxAgeSecs =
        30LL * 24 * 60 * 60;  // 30 days

    CryptoEngine         m_crypto;
    RelayClient          m_relay;
    FileTransferManager  m_fileMgr;

    // Choke point for outbound sealing + safety-number enforcement + KEM
    // pub bookkeeping.  See SessionSealer.hpp for details.  Must be
    // declared AFTER m_crypto (holds a reference) and BEFORE any member
    // that wires a callback to it (so the callback is established before
    // anything that could fire it).
    SessionSealer m_sealer{m_crypto};

    // Group outbound actions + roster + seq counters.  See
    // GroupProtocol.hpp.  Inbound group_* handlers still live in
    // onEnvelope and query this for authorization + counter state;
    // they move in the future EnvelopeDispatcher refactor.
    GroupProtocol m_groupProto{m_crypto};

    // File-transfer outbound + per-transfer state + consent flow.  See
    // FileProtocol.hpp.  Inbound file_* handlers in onEnvelope mutate
    // the state via public accessors (fileKeys() / pendingIncoming())
    // — they move into EnvelopeDispatcher in the next refactor step.
    FileProtocol m_fileProto{m_crypto, m_sealer, m_fileMgr};

    // Session-based crypto (Noise IK + Double Ratchet + Sealed Sender)
    std::unique_ptr<SessionStore>   m_sessionStore;
    std::unique_ptr<SessionManager> m_sessionMgr;
    SqlCipherDb* m_dbPtr = nullptr;  // kept for group / file / seen-envelopes tables

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

    // Group sequence counters + roster now live on m_groupProto.

    // Count consecutive handshake timeouts per peer — 2+ suggests an older client.
    std::map<std::string, int> m_handshakeFailCount;

    // Peer ML-KEM-768 pub storage + announce-once tracking live on
    // SessionSealer.  announceKemPub stays here because it builds a
    // sealed payload and hands it to m_relay.
    void announceKemPub(const std::string& peerIdB64u);

    // Safety-numbers state + fingerprint cache + verified_peers DB helpers
    // all live on SessionSealer.  ChatController's public trust API
    // (peerTrust / markPeerVerified / unverifyPeer / etc.) delegates
    // through m_sealer.  Inbound dispatch calls m_sealer.detectKeyChange
    // directly at the top of onEnvelope.

    // File-transfer state (m_fileKeys / m_pendingIncomingFiles /
    // m_groupFileMembers) + consent settings now live on m_fileProto.
    // Inbound file_* handlers in onEnvelope mutate them via the public
    // accessors on FileProtocol.

    // Per-sender envelope rate limiting.
    // Tracks (senderId -> count) within current poll cycle; reset each poll.
    std::map<std::string, int> m_envelopeCount;
    static constexpr int kMaxEnvelopesPerSenderPerPoll = 200;

    // Per-sender file_request rate limiting.  Same poll-reset model as
    // m_envelopeCount — capped in the file_request handler, cleared in
    // runMaintenance().
    std::map<std::string, int> m_fileRequestCount;

#ifdef PEER2PEAR_P2P
    // TURN relay config for symmetric NAT fallback.
    //
    // Keep creds encrypted between calls so a crash dump or
    // memory-scraping attack can't surface them.  We hold an
    // ephemeral per-session AEAD key and only store the ciphertext;
    // setupP2PConnection decrypts into scratch buffers, hands them to
    // QuicConnection, and zeroes the scratch immediately.  The key
    // itself is 32 bytes of sodium randomness generated once in
    // ChatController's ctor.
    std::string m_turnHost;   // host is not a secret — keep as-is
    int         m_turnPort = 0;
    Bytes       m_turnCredsKey;   // 32 bytes; never rotates within a session
    Bytes       m_turnUserCt;     // nonce||ct of username
    Bytes       m_turnPassCt;     // nonce||ct of password
#endif

    // Periodic maintenance (handshake pruning, file key cleanup)
    ITimerFactory*          m_timerFactory = nullptr;
    std::unique_ptr<ITimer> m_maintenanceTimer;
    void scheduleMaintenance();
    void runMaintenance();
};
