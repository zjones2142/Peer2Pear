#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

class CryptoEngine;

/*
 * GroupProtocol — outbound group send methods + roster + seq counters.
 *
 * Fan-out is client-side: groups exist only in the clients (the relay
 * is memberless).  Each `send*` method wraps a payload and hands it to
 * a `SendSealedFn` callback for every group member; the callback
 * routes it through SessionSealer + RelayClient.
 *
 * Roster authorization (the H2 gate): inbound group control messages
 * (rename / avatar / leave / member_update) must check
 * `isAuthorizedSender` before taking effect.  The roster is seeded
 * from either (a) `setKnownMembers` at app start (UI's persisted
 * state), or (b) `upsertMembersFromTrustedMessage` when a valid
 * group_msg arrives with the sender in its declared member list.
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
    using SendSealedFn = std::function<void(const std::string& peerId,
                                             const nlohmann::json& payload)>;

    explicit GroupProtocol(CryptoEngine& crypto);

    // Route wiring — ChatController sets this to a lambda that forwards
    // to sendSealedPayload (seal + relay send).
    void setSendSealedFn(SendSealedFn fn) { m_sendSealed = std::move(fn); }

    // ── Outbound actions ──────────────────────────────────────────────
    void sendText(const std::string& groupId, const std::string& groupName,
                  const std::vector<std::string>& memberPeerIds,
                  const std::string& text);

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
    int64_t recordInboundSeq(const std::string& gid,
                              const std::string& senderId,
                              int64_t seq);

private:
    std::string myId() const;  // base64url(identityPub)

    CryptoEngine& m_crypto;
    SendSealedFn  m_sendSealed;

    // Per-group outbound monotonic counter (not persisted across
    // restarts — relays + receivers accept gaps, only reject replays).
    std::map<std::string, int64_t> m_seqOut;
    // Per-(group,sender) last-seen sequence — detects replays.
    std::map<std::string, int64_t> m_seqIn;  // key: "groupId:senderId"

    // Known members per group.  Bootstrapped from UI-persisted state
    // (setKnownMembers) or first trusted group_msg.  Used by
    // isAuthorizedSender for control-message authorization.
    std::map<std::string, std::set<std::string>> m_members;
};
