#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "SenderChain.hpp"

class CryptoEngine;
class SessionStore;
class SessionManager;
class AppDataStore;

/*
 * GroupProtocol — outbound group send methods + roster + seq counters.
 *
 * Fan-out is client-side: groups exist only in the clients (the relay
 * is memberless).  Each `send*` method wraps a payload and hands it to
 * a `SendSealedFn` callback for every group member; the callback
 * routes it through SessionSealer + RelayClient.
 *
 * Roster authorization: inbound group control messages (rename /
 * avatar / leave / member_update) must check `isAuthorizedSender`
 * before taking effect.  The roster is seeded from either
 * (a) `setKnownMembers` at app start (UI's persisted state), or
 * (b) `upsertMembersFromTrustedMessage` when a valid group_msg
 * arrives with the sender in its declared member list.
 *
 * Sequence counters:
 *   - `nextOutboundSeq(gid)` returns a monotonic per-group counter
 *     attached to every outbound group_msg, used by receivers to
 *     detect gaps + replays.
 *   - `recordInboundSeq(gid, sender, seq)` returns the previously
 *     seen counter for that (group, sender) pair (or -1 if never
 *     seen) so the dispatcher can reject non-monotonic seq.
 *
 * Inbound message handling lives in ChatController's onEnvelope for
 * now; GroupProtocol exposes the state queries it needs.  A future
 * EnvelopeDispatcher refactor will own the inbound switch itself.
 */
class GroupProtocol {
public:
    using Bytes       = std::vector<uint8_t>;

    /// Returns the sealed envelope bytes (or empty on seal failure).
    /// The pv=2 sender path uses the return value to compute the
    /// prev_hash chain and to populate the group_replay_cache; the
    /// legacy pv=1 path discards it.  Either way the callback owns
    /// the actual seal+dispatch; this typedef just lets the protocol
    /// observe what went out.
    using SendSealedFn = std::function<Bytes(const std::string& peerId,
                                              const nlohmann::json& payload)>;

    /// Re-dispatch a pre-sealed envelope (no re-encryption).  Used by
    /// the gap_request handler to replay byte-identical sealed bytes
    /// from group_replay_cache when a peer asks for messages they
    /// missed.  ChatController binds this to RelayClient::sendEnvelope
    /// directly — bypassing SessionSealer because the bytes are
    /// already sealed for the recipient that asked.
    using ReplayRelayFn = std::function<void(const Bytes& sealedEnvelope)>;

    explicit GroupProtocol(CryptoEngine& crypto);

    // Route wiring — ChatController sets this to a lambda that forwards
    // to sendSealedPayload (seal + relay send).
    void setSendSealedFn(SendSealedFn fn) { m_sendSealed = std::move(fn); }

    /// Wire the per-user app data store so the v2 sender can persist
    /// its monotonic counter (group_send_state) and cache sealed
    /// envelopes for gap_request replay (group_replay_cache).  Required
    /// before sendTextV2 — setting null disables the v2 path.
    void setAppDataStore(AppDataStore* appData) { m_appData = appData; }

    /// Wire the SessionManager so the v2 sender can resolve each
    /// recipient's per-(peer) DR session id at send time.  Required
    /// before sendTextV2.
    void setSessionManager(SessionManager* mgr) { m_sessionMgr = mgr; }

    /// Wire the raw-relay-send callback used by handleGapRequest to
    /// replay cached sealed envelopes.  Required before
    /// handleGapRequest can do anything (logs + no-ops otherwise).
    void setReplayRelayFn(ReplayRelayFn fn) { m_replayRelay = std::move(fn); }

    // ── Outbound actions ──────────────────────────────────────────────
    void sendText(const std::string& groupId, const std::string& groupName,
                  const std::vector<std::string>& memberPeerIds,
                  const std::string& text);

    /// pv=2 (Causally-Linked Pairwise) replacement for sendText.
    /// Builds a per-recipient inner payload tagged with the DR
    /// session_id, a monotonic counter, and the prev_hash chain link;
    /// after the seal callback returns, caches the sealed bytes in
    /// group_replay_cache and bumps group_send_state.
    ///
    /// Wire format documented in core/CausallyLinkedPairwise.hpp.
    /// Requires both setAppDataStore() and setSessionManager() to
    /// have been called; otherwise it logs and no-ops.
    void sendTextV2(const std::string& groupId,
                     const std::string& groupName,
                     const std::vector<std::string>& memberPeerIds,
                     const std::string& text);

    // ── Receive side (pv=2) ───────────────────────────────────────────

    /// One message ready to surface to the application — either the
    /// just-arrived envelope or a previously-buffered one being drained
    /// after a gap finally closed.  Counter is preserved so the UI
    /// can render in send-order; ts is the wall-clock the receiver
    /// stamped at receive time (best we have for buffered drains).
    struct DeliveredGroupMessage {
        std::string body;
        std::string senderName;
        int64_t     counter;
        int64_t     ts;
        std::string msgId;
    };

    enum class ReceiveStatus {
        Delivered,     // counter == expected; this msg + any drain handed up
        Buffered,      // counter > expected; row stashed, stream is blocked
        Dropped,       // counter < expected (replay) OR prev_hash mismatch
        SessionReset,  // session_id changed; old buffer surfaced as lost,
                        // result.deliver / .blocked reflect the new session
    };

    struct ReceiveResult {
        ReceiveStatus status = ReceiveStatus::Dropped;
        std::vector<DeliveredGroupMessage> deliver;
        // Only meaningful when status == SessionReset.  Number of
        // pre-reset buffer rows we threw away — surfaces as the
        // "K messages lost during reconnection" UI event.
        int64_t lostMessages = 0;
        // Only meaningful when stream is blocked at the gap range
        // [gapFrom, gapTo].  Caller fires gap_request to the sender
        // for that range.
        bool    blocked = false;
        int64_t gapFrom = 0;
        int64_t gapTo   = 0;
    };

    /// Send a gap_request to `targetPeerId` asking them to replay
    /// counters [fromCtr, toCtr] from their group_replay_cache for
    /// (groupId, sessionId).  Used by the receiver after
    /// dispatchGroupMessageV2 returns blocked=true.  Builds a sealed
    /// pairwise control envelope of type "group_gap_request" via the
    /// existing sendSealed callback.
    ///
    /// Wire format:
    ///   { type, from, groupId, session, from_ctr, to_ctr, ts, msgId }
    void sendGapRequest(const std::string& targetPeerId,
                         const std::string& groupId,
                         const Bytes& sessionId,
                         int64_t fromCtr,
                         int64_t toCtr);

    /// Handle an incoming gap_request from `requestorPeerId`.  Loads
    /// each cached sealed envelope in [fromCtr, toCtr] from
    /// group_replay_cache and re-dispatches via the raw replay-relay
    /// callback (no re-seal).  Missing rows (cache TTL expired, or
    /// no such counter) are silently skipped — the requestor's UI
    /// surfaces the unfilled gap as a "lost messages" event after
    /// its own retry timeout.
    ///
    /// Requires setAppDataStore() AND setReplayRelayFn() to have been
    /// called; otherwise logs a warn and does nothing.
    void handleGapRequest(const std::string& requestorPeerId,
                            const std::string& groupId,
                            const Bytes& sessionId,
                            int64_t fromCtr,
                            int64_t toCtr);

    /// Run the pv=2 receiver state machine for one decrypted group_msg.
    /// `sealedEnvelope` is the OUTER sealed bytes — needed for the
    /// prev_hash chain (we hash these bytes as the lastHash for the
    /// next received message).  All other params are the parsed
    /// fields from the inner payload.
    ///
    /// Returns a struct describing what the application should do:
    ///   - deliver any messages in `result.deliver` (in counter order)
    ///   - if blocked, fire a gap_request for [gapFrom, gapTo]
    ///   - if lostMessages > 0, surface the "K lost" UI event
    ///
    /// Persists chain_state + buffer transitions to AppDataStore.
    /// Requires setAppDataStore() to have been called; otherwise
    /// returns Dropped with empty deliver.
    ReceiveResult dispatchGroupMessageV2(
        const std::string& groupId,
        const std::string& senderPeerId,
        const Bytes& sessionId,
        int64_t counter,
        const Bytes& prevHash,
        const std::string& body,
        const std::string& senderName,
        int64_t ts,
        const std::string& msgId,
        const Bytes& sealedEnvelope);

    void sendLeave(const std::string& groupId, const std::string& groupName,
                   const std::vector<std::string>& memberPeerIds);

    void sendRename(const std::string& groupId, const std::string& newName,
                    const std::vector<std::string>& memberKeys);

    void sendAvatar(const std::string& groupId, const std::string& avatarB64,
                    const std::vector<std::string>& memberKeys);

    void sendMemberUpdate(const std::string& groupId, const std::string& groupName,
                          const std::vector<std::string>& memberKeys);

    // ── Roster authorization ──────────────────────────────────────────
    void setKnownMembers(const std::string& groupId,
                         const std::vector<std::string>& members);

    // Returns false for unknown groups (deny-by-default) or peers not
    // in the group's roster.  Group control messages must pass this
    // check before taking effect.
    bool isAuthorizedSender(const std::string& gid,
                            const std::string& peerId) const;

    // Called from the group_msg inbound path with the payload's
    // declared `memberKeys`.  If we've never heard of this group
    // before AND the sender included themselves in `memberKeys`, we
    // accept the list as the roster.  Otherwise we just ensure the
    // sender is in the existing roster.
    void upsertMembersFromTrustedMessage(const std::string& gid,
                                          const std::string& senderId,
                                          const std::vector<std::string>& memberKeys);

    // Drop a peer from the roster (group_leave / group_member_update).
    void removeMember(const std::string& gid, const std::string& peerId);

    // Full roster replace — used by group_member_update handler after
    // authorization passes.
    void replaceMembers(const std::string& gid,
                         const std::vector<std::string>& members);

    // ── Sequence counters ─────────────────────────────────────────────
    void setSeqCounters(const std::map<std::string, int64_t>& seqOut,
                        const std::map<std::string, int64_t>& seqIn);
    const std::map<std::string, int64_t>& seqOut() const { return m_seqOut; }
    const std::map<std::string, int64_t>& seqIn()  const { return m_seqIn;  }

    // Inbound guard: record a seen seq for (gid, sender).  Returns the
    // PREVIOUSLY-seen seq (-1 if never seen).  Caller decides whether
    // to drop on non-monotonic.
    //
    // Not used by `group_msg` — skey_idx provides monotonicity inside
    // each SenderChain.  Kept for potential future use on other group
    // control messages and for test compatibility.
    int64_t recordInboundSeq(const std::string& gid,
                              const std::string& senderId,
                              int64_t seq);

    // ── Sender-key chains ─────────────────────────────────────────────
    //
    // Each member of a group maintains an outbound SenderChain (keyed
    // by gid) plus one inbound chain per other-member per group.
    // Chain seeds are distributed via `group_skey_announce` control
    // messages that flow through each recipient's 1:1 sealed ratchet
    // (which carries hybrid PQ encryption).  Only the user content
    // inside `group_msg` is encrypted via sender-chain-derived keys;
    // control messages (rename / avatar / leave / member_update) stay
    // on the 1:1 path.

    // My current epoch for a group.  Defaults to 0; bumped by
    // rotateMyChain on member removal.
    uint64_t myEpoch(const std::string& gid) const;

    // True iff I've created an outbound chain for this group.  Used
    // by ChatController to decide whether to seed + distribute a
    // chain on first send.
    bool hasMyChain(const std::string& gid) const;

    // Install a peer's sender chain from a received
    // `group_skey_announce` payload.  If an existing chain for
    // (gid, senderId) is at a lower epoch, it moves into the
    // grace-window prev slot so in-flight messages at the old epoch
    // still decrypt for `graceWindowSecs` seconds.
    void installRemoteChain(const std::string& gid,
                             const std::string& senderId,
                             uint64_t epoch,
                             const Bytes& seed);

    // Drop a peer's sender chain (e.g., they left the group).  Zeros
    // the chain's cached material before erasing the map entry.
    void forgetRemoteChain(const std::string& gid,
                             const std::string& senderId);

    // Rotate my outbound chain for a group — bumps epoch, generates a
    // fresh seed, redistributes to every peer in `remainingMembers`
    // (not including self).  Called from sendMemberUpdate when a peer
    // is removed so the removed peer's copy of our old chain becomes
    // cryptographically useless for future messages.
    //
    // If we don't currently have an outbound chain for this group,
    // this is a no-op — the next sendText will lazy-create a fresh
    // chain at the incoming epoch.
    void rotateMyChain(const std::string& gid,
                         const std::vector<std::string>& remainingMembers);

    // Grace window for inbound chains after a rekey.  When a peer
    // rotates, they send us a new skey_announce at a higher epoch.
    // We move their current chain to a "previous" slot so in-flight
    // messages at the old epoch (sent just before the rekey) still
    // decrypt during the window.
    //
    // Tests may override this to 0 to force immediate expiration of
    // the prev slot for grace-window-expiry test cases.
    static constexpr int64_t kDefaultGraceWindowSecs = 300;
    void setGraceWindowSecs(int64_t secs) { m_graceWindowSecs = secs; }
    int64_t graceWindowSecs() const { return m_graceWindowSecs; }

    // Decrypt a sender-chain-encrypted group payload using the
    // appropriate inbound chain.  `msgType` is the wire envelope
    // type (e.g., "group_msg", "group_rename") — bound into the AAD
    // so a ciphertext produced for one type cannot be relabelled as
    // another.  Returns empty on any failure:
    //   - no chain installed for (gid, senderId)
    //   - chain is at a different epoch than the message claims
    //   - messageKeyFor(idx) returns empty (out of window)
    //   - AEAD auth fails (tampered ciphertext, wrong AAD / type, etc.)
    Bytes decryptGroupMessage(const std::string& msgType,
                                const std::string& gid,
                                const std::string& senderId,
                                uint64_t epoch,
                                uint32_t idx,
                                const Bytes& ciphertext);

    // Raw serialize / restore of a single outbound chain.  Useful for
    // tests; production callers route through setSessionStore +
    // restorePersistedChains for automatic disk-backed state.
    Bytes serializeMyChain(const std::string& gid) const;
    void  restoreMyChain(const std::string& gid,
                           uint64_t epoch,
                           const Bytes& chainBlob);

    // Wire a SessionStore for automatic disk persistence of sender
    // chains (ours + each peer's).  Every mutation that advances a
    // chain or installs a new one writes through to the store;
    // forgetRemoteChain / rotateMyChain-with-removed-members deletes
    // the stale row.  The pointer is not owned; caller ensures the
    // store outlives the GroupProtocol.
    void setSessionStore(SessionStore* store);

    // Load every persisted chain from the wired SessionStore and
    // install it in memory.  Chains whose sender_id equals our own
    // peer_id become outbound chains; the rest become inbound chains
    // keyed by (gid, senderId).  Safe to call if no store is wired —
    // becomes a no-op.
    void restorePersistedChains();

    // Testing access: how many outbound / inbound chains are tracked.
    size_t outboundChainCount() const { return m_mySendChains.size(); }
    size_t inboundChainCount()  const { return m_recvChains.size();   }

private:
    std::string myId() const;  // base64url(identityPub)

    // Compose the AAD for sender-chain-encrypted group payloads.
    // Layout: msgType || '\n' || fromId || '\n' || gid ||
    //         epoch(u64 LE) || idx(u32 LE).
    // The '\n' separators are safe because peer IDs (base64url) and
    // group IDs (UUIDs) never contain them.  Binding msgType
    // prevents cross-type replay: a ciphertext produced for
    // "group_msg" cannot be re-framed as "group_rename" without
    // tripping the AEAD tag.  Must match the sender's construction
    // exactly or decryption fails.
    static Bytes buildGroupAad(const std::string& msgType,
                                 const std::string& fromId,
                                 const std::string& gid,
                                 uint64_t epoch,
                                 uint32_t idx);

    // Ensure our outbound chain for `gid` exists (lazy-create and
    // fan `group_skey_announce` to `members` if not), advance it,
    // and encrypt `plaintextJson` with AAD bound to `msgType`.
    // Returns (epoch, idx, base64url-ciphertext); ciphertext is
    // empty on failure (AEAD failed or caller asked for encryption
    // without m_sendSealed wired).
    struct GroupCiphertext {
        uint64_t    epoch = 0;
        uint32_t    idx   = 0;
        std::string ciphertextB64;
    };
    GroupCiphertext encryptForGroup(const std::string& msgType,
                                      const std::string& gid,
                                      const std::vector<std::string>& members,
                                      const nlohmann::json& plaintextJson);

    // Fan a group_skey_announce out to `recipients` through each of
    // their 1:1 sealed ratchet channels.  Called on lazy-create in
    // sendText and on rotateMyChain during rekey.
    void sendSkeyAnnounce(const std::string& gid,
                            uint64_t epoch,
                            const Bytes& seed,
                            const std::vector<std::string>& recipients);

    CryptoEngine& m_crypto;
    SendSealedFn  m_sendSealed;

    // Per-group outbound monotonic counter + per-(group,sender) last-
    // seen inbound seq.  Not consumed by the current `group_msg` path
    // (skey_idx supplies the same guarantee inside each SenderChain);
    // retained for potential future use on other group control
    // messages and for test compatibility.  See recordInboundSeq.
    std::map<std::string, int64_t> m_seqOut;
    std::map<std::string, int64_t> m_seqIn;  // key: "groupId:senderId"

    // Known members per group.  Bootstrapped from UI-persisted state
    // (setKnownMembers) or first trusted group_msg.  Used by
    // isAuthorizedSender for control-message authorization.
    std::map<std::string, std::set<std::string>> m_members;

    // ── Sender-chain state ───────────────────────────────────────────

    struct OutboundGroupState {
        SenderChain chain;
        uint64_t    epoch = 0;
    };

    // Inbound chain state per (gid, senderId).  Holds the current-
    // epoch chain the peer is actively using, plus a small ring of
    // previous-epoch chains retained for a grace window so in-flight
    // messages at prior epochs still decrypt.  A single prev slot
    // would drop epoch N-1 the moment epoch N+1 arrived, so a rapid
    // back-to-back rekey (member leaves + another joins + another
    // leaves) would make stragglers from the oldest epoch
    // undecryptable even within the grace window.  Two slots cover
    // the typical "two consecutive membership changes" case; further
    // slots are diminishing returns for unbounded memory growth.
    struct PrevChainSlot {
        SenderChain chain;
        uint64_t    epoch     = 0;
        int64_t     expiresAt = 0;

        bool valid() const {
            return chain.isValid() && expiresAt > 0;
        }
        void clear() {
            if (chain.isValid()) chain.clearSkipped();
            chain     = SenderChain{};
            epoch     = 0;
            expiresAt = 0;
        }
    };
    static constexpr size_t kPrevChainSlots = 2;
    struct InboundChainState {
        SenderChain chain;
        uint64_t    epoch = 0;
        // prevSlots[0] is the most-recently-rotated chain; older
        // slots have higher index.  rotateInboundPrevSlots shifts the
        // contents one position toward the back so new rotations land
        // in slot 0.
        std::array<PrevChainSlot, kPrevChainSlots> prevSlots;
    };

    // gid -> my outbound chain state for that group.
    std::map<std::string, OutboundGroupState> m_mySendChains;

    // (gid, senderId) -> their chain(s) as I've installed them.
    // Carries at most one current + one previous epoch.
    std::map<std::pair<std::string, std::string>, InboundChainState>
        m_recvChains;

    // Grace window for prev-epoch chains.  Mutable so tests can shrink
    // to zero without touching the compile-time default.
    int64_t m_graceWindowSecs = kDefaultGraceWindowSecs;

    // Optional persistence sink — every chain mutation writes through
    // to the store, and restorePersistedChains re-hydrates on startup.
    // Nullable; mutations are in-memory-only when unset.
    SessionStore* m_store = nullptr;

    // Phase 1 (Causally-Linked Pairwise) v2 sender deps.  Both
    // optional: when null, sendTextV2 logs a warning and no-ops.
    AppDataStore*   m_appData    = nullptr;
    SessionManager* m_sessionMgr = nullptr;
    // Raw-bytes relay callback used by handleGapRequest to replay
    // cached sealed envelopes without re-encryption.
    ReplayRelayFn   m_replayRelay;

    // Write the current outbound chain for `gid` to m_store (if wired).
    // Called internally after any op that advances or rotates it.
    void persistMyChain(const std::string& gid);

    // Write the current inbound chain for (gid, senderId) to m_store.
    // Called internally after installRemoteChain.
    void persistRemoteChain(const std::string& gid, const std::string& senderId);
};
