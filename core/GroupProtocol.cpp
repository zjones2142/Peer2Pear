#include "GroupProtocol.hpp"

#include "CryptoEngine.hpp"
#include "log.hpp"
#include "uuid.hpp"

#include <algorithm>
#include <chrono>

using json = nlohmann::json;

namespace {

int64_t nowSecs() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// Strip surrounding whitespace.  Group sender-key strings sometimes
// carry leading/trailing newlines from the UI's textarea copy-paste,
// so every comparison trims first.
std::string trimmed(const std::string& s) {
    auto lb = s.find_first_not_of(" \t\r\n");
    if (lb == std::string::npos) return {};
    auto rb = s.find_last_not_of(" \t\r\n");
    return s.substr(lb, rb - lb + 1);
}

}  // namespace

GroupProtocol::GroupProtocol(CryptoEngine& crypto) : m_crypto(crypto) {}

std::string GroupProtocol::myId() const
{
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
}

// ── Outbound actions ──────────────────────────────────────────────────────

void GroupProtocol::sendText(const std::string& groupId,
                              const std::string& groupName,
                              const std::vector<std::string>& memberPeerIds,
                              const std::string& text)
{
    if (!m_sendSealed) return;

    const std::string me   = myId();
    const int64_t     ts   = nowSecs();
    const std::string msg  = p2p::makeUuid();

    json membersArray = json::array();
    for (const std::string& key : memberPeerIds) {
        if (trimmed(key) == me) continue;
        membersArray.push_back(key);
    }

    const int64_t seq = ++m_seqOut[groupId];

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        json payload = json::object();
        payload["from"]      = me;
        payload["type"]      = "group_msg";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["text"]      = text;
        payload["ts"]        = ts;
        payload["msgId"]     = msg;
        payload["seq"]       = seq;

        m_sendSealed(peerId, payload);
    }
}

void GroupProtocol::sendLeave(const std::string& groupId,
                               const std::string& groupName,
                               const std::vector<std::string>& memberPeerIds)
{
    if (!m_sendSealed) return;

    const std::string me   = myId();
    const int64_t     ts   = nowSecs();
    const std::string msg  = p2p::makeUuid();

    // Include full roster (including self) so receivers can update
    // their local group member list.
    json membersArray = json::array();
    for (const std::string& key : memberPeerIds)
        membersArray.push_back(key);

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        json payload = json::object();
        payload["from"]      = me;
        payload["type"]      = "group_leave";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["ts"]        = ts;
        payload["msgId"]     = msg;

        m_sendSealed(peerId, payload);
    }
}

void GroupProtocol::sendRename(const std::string& groupId,
                                const std::string& newName,
                                const std::vector<std::string>& memberKeys)
{
    if (!m_sendSealed) return;

    const std::string msgId = p2p::makeUuid();
    json payload = json::object();
    payload["from"]    = myId();
    payload["type"]    = "group_rename";
    payload["groupId"] = groupId;
    payload["newName"] = newName;
    payload["msgId"]   = msgId;
    payload["ts"]      = nowSecs();
    for (const std::string& key : memberKeys)
        m_sendSealed(key, payload);
}

void GroupProtocol::sendAvatar(const std::string& groupId,
                                const std::string& avatarB64,
                                const std::vector<std::string>& memberKeys)
{
    if (!m_sendSealed) return;

    const std::string msgId = p2p::makeUuid();
    json payload = json::object();
    payload["from"]    = myId();
    payload["type"]    = "group_avatar";
    payload["groupId"] = groupId;
    payload["avatar"]  = avatarB64;
    payload["msgId"]   = msgId;
    payload["ts"]      = nowSecs();
    for (const std::string& key : memberKeys)
        m_sendSealed(key, payload);
}

void GroupProtocol::sendMemberUpdate(const std::string& groupId,
                                      const std::string& groupName,
                                      const std::vector<std::string>& memberKeys)
{
    if (!m_sendSealed) return;

    const std::string me    = myId();
    const std::string msgId = p2p::makeUuid();

    // Member array excludes self, matching group_msg shape.
    json membersArray = json::array();
    for (const std::string& key : memberKeys) {
        if (trimmed(key) == me) continue;
        membersArray.push_back(key);
    }

    // Send to ALL members (including newly added ones) so everyone gets
    // the updated member list and new members discover the group.
    for (const std::string& peerIdRaw : memberKeys) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        json payload = json::object();
        payload["from"]      = me;
        payload["type"]      = "group_member_update";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["msgId"]     = msgId;
        payload["ts"]        = nowSecs();

        m_sendSealed(peerId, payload);
    }
}

// ── Roster ────────────────────────────────────────────────────────────────

void GroupProtocol::setKnownMembers(const std::string& groupId,
                                     const std::vector<std::string>& members)
{
    if (groupId.empty()) return;
    m_members[groupId] = std::set<std::string>(members.begin(), members.end());
}

bool GroupProtocol::isAuthorizedSender(const std::string& gid,
                                        const std::string& peerId) const
{
    if (gid.empty() || peerId.empty()) return false;
    auto it = m_members.find(gid);
    if (it == m_members.end()) {
        // Deny-by-default for unknown groups.  Bootstrap happens via
        // upsertMembersFromTrustedMessage on the first group_msg; this
        // check only gates control messages (rename / avatar / leave /
        // member_update) so an attacker who guessed or observed a gid
        // can't inject them before the legitimate roster arrives.
        return false;
    }
    return it->second.count(peerId) != 0;
}

void GroupProtocol::upsertMembersFromTrustedMessage(
    const std::string& gid,
    const std::string& senderId,
    const std::vector<std::string>& memberKeys)
{
    if (gid.empty() || senderId.empty()) return;
    auto it = m_members.find(gid);
    if (it == m_members.end()) {
        // Bootstrap: accept only if sender includes themselves.  This
        // is the H5 known-limitation first-mover race (an attacker who
        // races a legit sender can seed a bogus roster); pairing with
        // UI-persisted setKnownMembers at startup beats the bootstrap
        // in practice.
        const bool senderInList =
            std::find(memberKeys.begin(), memberKeys.end(), senderId)
            != memberKeys.end();
        if (senderInList) {
            m_members[gid] = std::set<std::string>(memberKeys.begin(), memberKeys.end());
        }
    } else {
        it->second.insert(senderId);
    }
}

void GroupProtocol::removeMember(const std::string& gid,
                                  const std::string& peerId)
{
    auto it = m_members.find(gid);
    if (it != m_members.end()) it->second.erase(peerId);
}

void GroupProtocol::replaceMembers(const std::string& gid,
                                    const std::vector<std::string>& members)
{
    if (gid.empty()) return;
    m_members[gid] = std::set<std::string>(members.begin(), members.end());
}

// ── Sequence counters ─────────────────────────────────────────────────────

void GroupProtocol::setSeqCounters(const std::map<std::string, int64_t>& seqOut,
                                    const std::map<std::string, int64_t>& seqIn)
{
    m_seqOut = seqOut;
    m_seqIn  = seqIn;
}

int64_t GroupProtocol::recordInboundSeq(const std::string& gid,
                                         const std::string& senderId,
                                         int64_t seq)
{
    const std::string key = gid + ":" + senderId;
    auto it = m_seqIn.find(key);
    const int64_t prev = (it == m_seqIn.end()) ? -1 : it->second;
    // Only advance on strictly-greater seq.  If the caller receives
    // a replay (seq <= prev) and we've already advanced the counter,
    // a subsequent replay of seq=prev+1 would pass the gate — so
    // leave the high-water mark untouched on replays.  The caller
    // decides whether to drop based on the returned `prev`.
    if (prev < seq) m_seqIn[key] = seq;
    return prev;
}
