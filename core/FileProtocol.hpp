#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

class CryptoEngine;
class SessionManager;
class SessionSealer;
class FileTransferManager;

/*
 * FileProtocol — outbound file-send + per-transfer state + consent flow.
 *
 * Owns the three file-related state maps:
 *   - `fileKeys`           : ratchet-derived AEAD keys for active transfers
 *                            (senderId + ":" + transferId → 32-byte key)
 *   - `pendingIncomingFiles`: incoming transfers waiting on user consent
 *                            (transferId → PendingIncoming)
 *   - `groupFileMembers`   : group-level transferId → list of per-member
 *                            transferIds used for fan-out cancellation
 *
 * The inbound file_* envelope handlers still live in ChatController's
 * onEnvelope switch (until the EnvelopeDispatcher refactor); they mutate
 * these maps directly through public accessors.  The outbound paths
 * (sendFile / sendGroupFile / accept / decline / cancel) all own their
 * state changes internally.
 *
 * Choke-point invariant: every outbound file byte still goes through
 * SessionSealer.sealForPeer, either via the sendSealed callback for
 * control messages or directly for the file_key announcement (where
 * we need the sealed envelope AND the derived lastMessageKey from
 * the same seal operation — see sendFile for the ordering).
 */
class FileProtocol {
public:
    using Bytes = std::vector<uint8_t>;
    using SendEnvelopeFn = std::function<void(const Bytes& relayEnvelope)>;

    FileProtocol(CryptoEngine& crypto,
                  SessionSealer& sealer,
                  FileTransferManager& ftm);

    // Late binding — ChatController wires these once SessionManager is
    // constructed and the relay is ready.
    void setSessionManager(SessionManager* mgr) { m_sessionMgr = mgr; }
    void setSendEnvelopeFn(SendEnvelopeFn fn)   { m_sendEnvelope = std::move(fn); }

    // Consent policy knobs.  Read by the inbound file_key handler to
    // decide auto-accept / prompt / auto-decline.
    void setAutoAcceptMaxMB(int mb) { m_autoAcceptMaxMB = mb; }
    void setHardMaxMB(int mb)        { m_hardMaxMB       = mb; }
    void setRequireP2P(bool on)      { m_requireP2P      = on; }
    int  autoAcceptMaxMB() const { return m_autoAcceptMaxMB; }
    int  hardMaxMB()       const { return m_hardMaxMB; }
    bool requireP2P()      const { return m_requireP2P; }

    // ── Outbound actions ──────────────────────────────────────────────
    // Returns the transferId (UUID) on success, empty on failure.
    std::string sendFile(const std::string& peerIdB64u,
                          const std::string& fileName,
                          const std::string& filePath);

    // Returns a group-level transferId bundling the per-member ids.
    std::string sendGroupFile(const std::string& groupId,
                               const std::string& groupName,
                               const std::vector<std::string>& memberPeerIds,
                               const std::string& fileName,
                               const std::string& filePath);

    // Accept / decline a pending-consent incoming.  Moves the file key
    // from pendingIncomingFiles into fileKeys on accept, or zeros +
    // drops on decline.  Fires onCanceled(tid, byReceiver=true) on
    // decline.  No-op on unknown transferId.
    void acceptIncoming(const std::string& transferId, bool requireP2P);
    void declineIncoming(const std::string& transferId);

    // Cancel any transfer (outbound pending, inbound pre-accept,
    // inbound in-progress, or group-level fanout).  Dispatches the
    // right cleanup + fires onCanceled with byReceiver set appropriately.
    void cancel(const std::string& transferId);

    // Send a file-control message (file_accept / file_decline / file_cancel /
    // file_request / file_ack).  Stamps from/ts/msgId.  The type /
    // transferId / other fields are the caller's to set.
    void sendControlMessage(const std::string& peerIdB64u,
                             const nlohmann::json& msg);

    // Arch-review #5: file_ack composition used to live in a lambda
    // in ChatController's ctor.  Lifting it here keeps every outbound
    // file control message in one place (sendControlMessage family).
    void sendFileAck(const std::string& peerIdB64u,
                      const std::string& transferId);

    // Wire FileTransferManager's per-chunk seal callback to
    // SessionSealer::sealPreEncryptedForPeer.  Called by
    // ChatController once the FTM + sealer are both ready.
    // Arch-review #5: the wiring was previously open-coded in
    // ChatController, which meant the choke-point invariant had
    // to be re-verified there; now FileProtocol owns it.
    void installChunkSealCallback();

    // Install the per-file AEAD key for (peer, transfer) so
    // FileTransferManager's chunk handler can find it.  Used both
    // on live accept and on DB-restore rehydration.  Arch-review
    // #5: callers previously reached through `fileKeys()` directly.
    void installIncomingKey(const std::string& peerIdB64u,
                             const std::string& transferId,
                             const Bytes& fileKey);

    // Drop every key belonging to a transfer (keyed "<peer>:<tid>"
    // or bare "<tid>" for test shim callers).  Zeroes the cached
    // key material before erasing.  Called on transfer completion
    // and on explicit cancellation.  Arch-review #5.
    void eraseFileKeysFor(const std::string& transferId);

    // ── State accessors for inbound handlers ──────────────────────────
    // These are the minimum public API the onEnvelope file_* branches
    // need to mutate per-transfer state without reaching across an
    // abstraction boundary.

    struct PendingIncoming {
        std::string peerId;
        std::string fileName;
        int64_t     fileSize    = 0;
        Bytes       fileKey;            // 32 bytes, zeroed on drop
        Bytes       fileHash;           // 32 bytes — locked at file_key time
        int         totalChunks  = 0;
        int64_t     announcedTs  = 0;
        std::string groupId;
        std::string groupName;
        int64_t     announcedSecs = 0;
    };

    // Cap on pending-consent queue size.  A hostile peer flooding
    // file_key announcements in the prompt-size band can't exhaust
    // memory because the inbound handler evicts the oldest entry once
    // this cap is reached (see onEnvelope file_key branch).
    static constexpr size_t kMaxPendingIncomingFiles = 50;

    // Accessors used by onEnvelope file_* handlers.  Public because the
    // inbound logic is complex enough that wrapping each access in a
    // method would just add ceremony.  Once EnvelopeDispatcher lands,
    // these get private + friended.
    std::map<std::string, Bytes>&                  fileKeys()           { return m_fileKeys; }
    const std::map<std::string, Bytes>&            fileKeys() const     { return m_fileKeys; }
    std::map<std::string, PendingIncoming>&        pendingIncoming()    { return m_pendingIncomingFiles; }
    const std::map<std::string, PendingIncoming>&  pendingIncoming() const { return m_pendingIncomingFiles; }

    // Per-transfer GC from the maintenance loop / FTM signals.
    void eraseFileKey(const std::string& compoundKey);

    // ── Callbacks ─────────────────────────────────────────────────────
    std::function<void(const std::string& from, const std::string& transferId,
                       const std::string& fileName, int64_t fileSize)>
        onAcceptRequested;
    std::function<void(const std::string& transferId, bool byReceiver)>
        onCanceled;
    std::function<void(const std::string& transferId)>
        onDelivered;
    std::function<void(const std::string& transferId, bool byReceiver)>
        onBlocked;

private:
    std::string myId() const;  // base64url(identityPub)

    CryptoEngine&        m_crypto;
    SessionSealer&       m_sealer;
    FileTransferManager& m_ftm;
    SessionManager*      m_sessionMgr   = nullptr;
    SendEnvelopeFn       m_sendEnvelope;

    // State owned by FileProtocol.
    std::map<std::string, Bytes>           m_fileKeys;
    std::map<std::string, PendingIncoming> m_pendingIncomingFiles;
    // Group file transfers create a distinct per-member transferId
    // internally so the sender honors each recipient's consent gate
    // independently.  This map bundles those per-member transferIds
    // under a single group-level id returned to the caller, so cancel
    // can fan out across all members.
    std::map<std::string, std::vector<std::string>> m_groupFileMembers;

    // Consent policy.  Readable + writable via the accessors above.
    // Defaults split (Audit #3 H5): with the previous 100/100 the
    // `autoAccept < size <= hardMax` prompt range was empty, so every
    // file under 100 MB silently auto-accepted — the consent prompt
    // was dead code.  25/100 means files up to 25 MB auto-accept,
    // 25-100 MB prompt the user, > 100 MB auto-decline.  iOS already
    // overrides via UI; this default protects desktop callers that
    // never set explicit thresholds.
    int  m_autoAcceptMaxMB = 25;
    int  m_hardMaxMB       = 100;
    bool m_requireP2P      = false;
};
