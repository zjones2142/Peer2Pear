#include "GroupProtocol.hpp"

#include "CryptoEngine.hpp"
#include "SessionStore.hpp"
#include "log.hpp"
#include "uuid.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstring>

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
    if (groupId.empty()) return;

    const std::string me = myId();

    // Pack the user content into an inner JSON that the sender chain
    // will encrypt.  Metadata that needs to stay plaintext for
    // routing (groupId, members, ts, msgId) rides on the outer
    // payload; user content lives inside the ciphertext.
    const json plaintext = { {"text", text} };
    GroupCiphertext enc = encryptForGroup(
        "group_msg", groupId, memberPeerIds, plaintext);
    if (enc.ciphertextB64.empty()) return;

    const int64_t     ts    = nowSecs();
    const std::string msgId = p2p::makeUuid();

    json membersArray = json::array();
    for (const std::string& key : memberPeerIds) {
        if (trimmed(key) == me) continue;
        membersArray.push_back(key);
    }

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        json payload = json::object();
        payload["from"]       = me;
        payload["type"]       = "group_msg";
        payload["groupId"]    = groupId;
        payload["groupName"]  = groupName;
        payload["members"]    = membersArray;
        payload["skey_epoch"] = enc.epoch;
        payload["skey_idx"]   = enc.idx;
        payload["ciphertext"] = enc.ciphertextB64;
        payload["ts"]         = ts;
        payload["msgId"]      = msgId;

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
    if (groupId.empty()) return;

    const std::string me       = myId();
    const json        plaintext = { {"newName", newName} };

    GroupCiphertext enc = encryptForGroup(
        "group_rename", groupId, memberKeys, plaintext);
    if (enc.ciphertextB64.empty()) return;

    const std::string msgId = p2p::makeUuid();
    const int64_t     ts    = nowSecs();

    json payload = json::object();
    payload["from"]       = me;
    payload["type"]       = "group_rename";
    payload["groupId"]    = groupId;
    payload["skey_epoch"] = enc.epoch;
    payload["skey_idx"]   = enc.idx;
    payload["ciphertext"] = enc.ciphertextB64;
    payload["msgId"]      = msgId;
    payload["ts"]         = ts;

    for (const std::string& peerIdRaw : memberKeys) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;
        m_sendSealed(peerId, payload);
    }
}

void GroupProtocol::sendAvatar(const std::string& groupId,
                                const std::string& avatarB64,
                                const std::vector<std::string>& memberKeys)
{
    if (!m_sendSealed) return;
    if (groupId.empty()) return;

    const std::string me       = myId();
    const json        plaintext = { {"avatar", avatarB64} };

    GroupCiphertext enc = encryptForGroup(
        "group_avatar", groupId, memberKeys, plaintext);
    if (enc.ciphertextB64.empty()) return;

    const std::string msgId = p2p::makeUuid();
    const int64_t     ts    = nowSecs();

    json payload = json::object();
    payload["from"]       = me;
    payload["type"]       = "group_avatar";
    payload["groupId"]    = groupId;
    payload["skey_epoch"] = enc.epoch;
    payload["skey_idx"]   = enc.idx;
    payload["ciphertext"] = enc.ciphertextB64;
    payload["msgId"]      = msgId;
    payload["ts"]         = ts;

    for (const std::string& peerIdRaw : memberKeys) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;
        m_sendSealed(peerId, payload);
    }
}

void GroupProtocol::sendMemberUpdate(const std::string& groupId,
                                      const std::string& groupName,
                                      const std::vector<std::string>& memberKeys)
{
    if (!m_sendSealed) return;

    const std::string me    = myId();
    const std::string msgId = p2p::makeUuid();

    // Diff the proposed new roster against our current local view so
    // we can detect whether anyone was removed (triggers rekey) or
    // only added (distribute current chain to new members).
    //
    // m_members is the authoritative local roster; callers that want
    // the old state before dispatch is applied should consult this
    // map directly (or via isAuthorizedSender).
    std::set<std::string> oldRoster;
    {
        auto it = m_members.find(groupId);
        if (it != m_members.end()) oldRoster = it->second;
    }

    std::set<std::string> newRoster;
    for (const auto& k : memberKeys) {
        const std::string t = trimmed(k);
        if (!t.empty()) newRoster.insert(t);
    }

    std::vector<std::string> removedPeers;
    for (const auto& p : oldRoster) {
        if (newRoster.count(p) == 0) removedPeers.push_back(p);
    }

    std::vector<std::string> addedPeers;
    for (const auto& p : newRoster) {
        if (oldRoster.count(p) == 0) addedPeers.push_back(p);
    }

    // Rekey-on-leave: any removal from the roster rotates our chain
    // so the removed peers' copy of our old seed becomes cryptograph-
    // ically useless for any future outbound messages.  We excluded
    // them from the new-chain recipient list deliberately.
    //
    // If we never had a chain for this group (never sent anything),
    // skip rotation — next sendText will lazy-create at epoch 0.
    // This also handles the "ChatController updates roster before we
    // ever send" path cleanly.
    if (!removedPeers.empty()) {
        for (const auto& peer : removedPeers) {
            // Drop the removed peer's inbound chain too — we won't be
            // receiving group messages from them anymore.  The outer
            // 1:1 sealed envelope from them would still decrypt, but
            // without an installed sender chain for them in this
            // group, the inner group_msg ciphertext is unreadable.
            forgetRemoteChain(groupId, peer);
        }
        if (hasMyChain(groupId)) {
            rotateMyChain(groupId,
                           std::vector<std::string>(newRoster.begin(),
                                                     newRoster.end()));
        }
    } else if (!addedPeers.empty() && hasMyChain(groupId)) {
        // Add-only: no epoch bump; just send our CURRENT seed to the
        // newly-added peers so they can decrypt our future messages.
        // Existing members already have it.
        const auto& state = m_mySendChains.at(groupId);
        sendSkeyAnnounce(groupId, state.epoch, state.chain.seed(),
                          addedPeers);
    }

    // Commit the new roster locally.  Doing this AFTER the diff-based
    // chain decisions keeps the comparison honest (no self-trip where
    // we diff the new roster against itself).
    m_members[groupId] = newRoster;

    // Member array excludes self, matching group_msg shape.
    json membersArray = json::array();
    for (const std::string& key : memberKeys) {
        if (trimmed(key) == me) continue;
        membersArray.push_back(key);
    }

    // Encrypt the sensitive fields (groupName, members) inside a
    // sender-chain ciphertext.  Receivers decrypt with the chain we
    // just lazy-created (or, for add-only, the one announced to new
    // members moments before).  Plaintext envelope carries only
    // routing-critical fields.
    json plaintext = json::object();
    plaintext["groupName"] = groupName;
    plaintext["members"]   = membersArray;

    GroupCiphertext enc = encryptForGroup(
        "group_member_update", groupId, memberKeys, plaintext);
    if (enc.ciphertextB64.empty()) return;

    for (const std::string& peerIdRaw : memberKeys) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        json payload = json::object();
        payload["from"]       = me;
        payload["type"]       = "group_member_update";
        payload["groupId"]    = groupId;
        payload["skey_epoch"] = enc.epoch;
        payload["skey_idx"]   = enc.idx;
        payload["ciphertext"] = enc.ciphertextB64;
        payload["msgId"]      = msgId;
        payload["ts"]         = nowSecs();

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

// ── Sender-chain management ───────────────────────────────────────────────

uint64_t GroupProtocol::myEpoch(const std::string& gid) const
{
    auto it = m_mySendChains.find(gid);
    return it == m_mySendChains.end() ? 0 : it->second.epoch;
}

bool GroupProtocol::hasMyChain(const std::string& gid) const
{
    return m_mySendChains.count(gid) != 0;
}

void GroupProtocol::installRemoteChain(const std::string& gid,
                                         const std::string& senderId,
                                         uint64_t epoch,
                                         const Bytes& seed)
{
    if (gid.empty() || senderId.empty()) return;
    if (seed.size() != 32) {
        P2P_WARN("[GROUP] installRemoteChain: invalid seed size "
                 << seed.size() << " from " << senderId.substr(0, 8) << "...");
        return;
    }

    const auto key = std::make_pair(gid, senderId);
    auto it = m_recvChains.find(key);

    // Fast path: no prior entry for this (gid, sender) — just install.
    if (it == m_recvChains.end()) {
        InboundChainState s;
        s.chain = SenderChain::fromSeed(seed);
        s.epoch = epoch;
        m_recvChains[key] = std::move(s);
        persistRemoteChain(gid, senderId);
        return;
    }

    // Same-epoch re-announce (rare but possible — e.g., a peer
    // retransmits after they think we missed the first copy, or a
    // relay delivers two copies).  Replace outright without touching
    // the prev slot; the chain bytes are identical so replay is a
    // no-op cryptographically.
    if (it->second.epoch == epoch) {
        it->second.chain = SenderChain::fromSeed(seed);
        persistRemoteChain(gid, senderId);
        return;
    }

    // True rekey — epoch has advanced.  Move the current chain into
    // the prev slot with a grace-window expiration so in-flight
    // messages at the old epoch still decrypt while new-epoch traffic
    // ramps up.  Zero any prior prev slot's keys first to avoid
    // leaking material indefinitely across multiple back-to-back
    // rekeys.
    if (it->second.prevChain.isValid()) {
        it->second.prevChain.clearSkipped();
    }
    it->second.prevChain     = std::move(it->second.chain);
    it->second.prevEpoch     = it->second.epoch;
    it->second.prevExpiresAt = nowSecs() + m_graceWindowSecs;

    it->second.chain = SenderChain::fromSeed(seed);
    it->second.epoch = epoch;

    P2P_LOG("[GROUP] rekey from " << senderId.substr(0, 8)
            << "... in " << gid.substr(0, 8) << "... epoch "
            << it->second.prevEpoch << " -> " << epoch
            << " (grace window " << m_graceWindowSecs << "s)");

    persistRemoteChain(gid, senderId);
}

void GroupProtocol::forgetRemoteChain(const std::string& gid,
                                        const std::string& senderId)
{
    const auto key = std::make_pair(gid, senderId);
    auto it = m_recvChains.find(key);
    if (it == m_recvChains.end()) {
        // Nothing in memory, but the disk row might still exist if a
        // prior process saved it.  Clean up so a restart doesn't
        // resurrect the chain we just dropped.
        if (m_store) m_store->deleteSenderChain(gid, senderId);
        return;
    }
    // Wipe BOTH the current and any grace-window prev chain before
    // erasing — defence-in-depth against later reads of freed memory.
    it->second.chain.clearSkipped();
    if (it->second.prevChain.isValid())
        it->second.prevChain.clearSkipped();
    m_recvChains.erase(it);
    if (m_store) m_store->deleteSenderChain(gid, senderId);
}

void GroupProtocol::rotateMyChain(const std::string& gid,
                                    const std::vector<std::string>& remainingMembers)
{
    if (gid.empty()) return;
    auto it = m_mySendChains.find(gid);
    if (it == m_mySendChains.end()) {
        // No existing chain to rotate.  The next sendText will lazy-
        // create a fresh chain at epoch 0 anyway, so this is a no-op.
        return;
    }

    // Zero the existing chain's cached material before overwriting.
    it->second.chain.clearSkipped();

    // Bump epoch, generate fresh seed, replace in place.
    const uint64_t newEpoch = it->second.epoch + 1;
    it->second.chain = SenderChain::freshOutbound();
    it->second.epoch = newEpoch;

    P2P_LOG("[GROUP] rotated my chain for " << gid.substr(0, 8)
            << "... to epoch " << newEpoch);

    persistMyChain(gid);

    // Fan the new seed out to every remaining member.  Removed peers
    // are deliberately excluded from this recipient list so they
    // can't install the new chain.
    sendSkeyAnnounce(gid, newEpoch, it->second.chain.seed(),
                      remainingMembers);
}

GroupProtocol::Bytes
GroupProtocol::decryptGroupMessage(const std::string& msgType,
                                     const std::string& gid,
                                     const std::string& senderId,
                                     uint64_t epoch,
                                     uint32_t idx,
                                     const Bytes& ciphertext)
{
    if (gid.empty() || senderId.empty() || ciphertext.empty() ||
        msgType.empty()) return {};

    const auto key = std::make_pair(gid, senderId);
    auto it = m_recvChains.find(key);
    if (it == m_recvChains.end()) {
        // No chain installed yet.  Caller log + drop; pre-announce
        // buffering is a separate concern tracked outside this layer.
        return {};
    }

    // Pick the right chain for the message's epoch:
    //   - current epoch: decrypt via `it->second.chain`
    //   - prev epoch within grace window: decrypt via `prevChain`
    //   - anything else: reject (stale or future)
    //
    // Refusing ahead-of-chain epochs is important — an attacker could
    // otherwise provoke arbitrarily many chain-advance operations by
    // claiming a future epoch number.
    SenderChain* chain = nullptr;
    if (it->second.epoch == epoch) {
        chain = &it->second.chain;
    } else if (it->second.prevChain.isValid() &&
                it->second.prevEpoch == epoch) {
        if (nowSecs() < it->second.prevExpiresAt) {
            chain = &it->second.prevChain;
        } else {
            // Grace window has expired — drop the prev chain so we
            // stop holding onto dead key material and subsequent
            // accesses fall through to the "epoch mismatch" path.
            it->second.prevChain.clearSkipped();
            it->second.prevChain = SenderChain{};
            it->second.prevEpoch = 0;
            it->second.prevExpiresAt = 0;
            P2P_WARN("[GROUP] grace window expired for "
                     << senderId.substr(0, 8) << "... in "
                     << gid.substr(0, 8) << "... epoch " << epoch);
        }
    }

    if (!chain) {
        P2P_WARN("[GROUP] decrypt: epoch mismatch for "
                 << senderId.substr(0, 8) << "... in "
                 << gid.substr(0, 8) << "... (chain @ "
                 << it->second.epoch << ", msg @ " << epoch << ")");
        return {};
    }

    Bytes msgKey = chain->messageKeyFor(idx);
    if (msgKey.size() != 32) {
        // Past the skipped-key LRU or beyond the per-call cap.
        return {};
    }

    const Bytes aad = buildGroupAad(msgType, senderId, gid, epoch, idx);
    Bytes pt = m_crypto.aeadDecrypt(msgKey, ciphertext, aad);
    sodium_memzero(msgKey.data(), msgKey.size());
    return pt;
}

GroupProtocol::Bytes
GroupProtocol::serializeMyChain(const std::string& gid) const
{
    auto it = m_mySendChains.find(gid);
    if (it == m_mySendChains.end()) return {};
    return it->second.chain.serialize();
}

void GroupProtocol::restoreMyChain(const std::string& gid,
                                     uint64_t epoch,
                                     const Bytes& chainBlob)
{
    if (gid.empty()) return;
    SenderChain chain = SenderChain::deserialize(chainBlob);
    if (!chain.isValid()) {
        P2P_WARN("[GROUP] restoreMyChain: invalid blob for "
                 << gid.substr(0, 8) << "...");
        return;
    }
    OutboundGroupState s;
    s.chain = std::move(chain);
    s.epoch = epoch;
    m_mySendChains[gid] = std::move(s);
    persistMyChain(gid);
}

// ── Private helpers ───────────────────────────────────────────────────────

GroupProtocol::Bytes
GroupProtocol::buildGroupAad(const std::string& msgType,
                              const std::string& fromId,
                              const std::string& gid,
                              uint64_t epoch,
                              uint32_t idx)
{
    Bytes aad;
    aad.reserve(msgType.size() + 1 + fromId.size() + 1 + gid.size() + 8 + 4);
    aad.insert(aad.end(), msgType.begin(), msgType.end());
    aad.push_back('\n');
    aad.insert(aad.end(), fromId.begin(), fromId.end());
    aad.push_back('\n');
    aad.insert(aad.end(), gid.begin(),    gid.end());
    // Little-endian encoding pinned so cross-platform senders and
    // receivers agree on the AAD bytes regardless of host endianness.
    for (int i = 0; i < 8; ++i)
        aad.push_back(static_cast<uint8_t>((epoch >> (8 * i)) & 0xFF));
    for (int i = 0; i < 4; ++i)
        aad.push_back(static_cast<uint8_t>((idx >> (8 * i)) & 0xFF));
    return aad;
}

GroupProtocol::GroupCiphertext
GroupProtocol::encryptForGroup(const std::string& msgType,
                                 const std::string& gid,
                                 const std::vector<std::string>& members,
                                 const nlohmann::json& plaintextJson)
{
    GroupCiphertext out;
    if (gid.empty() || msgType.empty()) return out;

    // Lazy-init: the first outbound send for this group (any type)
    // creates the chain + fans a skey_announce to each member through
    // their 1:1 ratchet.  Ordering matters — the announce must reach
    // each peer before the ciphertext we're about to produce, which
    // holds because both ride the same per-peer FIFO ratchet.
    auto it = m_mySendChains.find(gid);
    if (it == m_mySendChains.end()) {
        OutboundGroupState s;
        s.chain = SenderChain::freshOutbound();
        s.epoch = 0;
        it = m_mySendChains.emplace(gid, std::move(s)).first;
        sendSkeyAnnounce(gid, it->second.epoch,
                          it->second.chain.seed(), members);
    }
    OutboundGroupState& state = it->second;

    auto [idx, msgKey] = state.chain.next();
    persistMyChain(gid);

    const std::string me  = myId();
    const Bytes       aad = buildGroupAad(msgType, me, gid, state.epoch, idx);
    const std::string pt  = plaintextJson.dump();
    const Bytes       ptBytes(pt.begin(), pt.end());
    Bytes             ct  = m_crypto.aeadEncrypt(msgKey, ptBytes, aad);
    sodium_memzero(msgKey.data(), msgKey.size());

    if (ct.empty()) {
        P2P_WARN("[GROUP] aeadEncrypt failed for " << msgType << " in "
                 << gid.substr(0, 8) << "...");
        return out;
    }

    out.epoch         = state.epoch;
    out.idx           = idx;
    out.ciphertextB64 = CryptoEngine::toBase64Url(ct);
    return out;
}

void GroupProtocol::setSessionStore(SessionStore* store)
{
    m_store = store;
}

void GroupProtocol::restorePersistedChains()
{
    if (!m_store) return;

    const std::string me = myId();
    const auto rows = m_store->loadAllSenderChains();
    for (const auto& r : rows) {
        SenderChain chain = SenderChain::deserialize(r.chainBlob);
        if (!chain.isValid()) {
            P2P_WARN("[GROUP] skipping invalid persisted chain for "
                     << r.senderId.substr(0, 8) << "... in "
                     << r.groupId.substr(0, 8) << "...");
            continue;
        }

        if (r.senderId == me) {
            OutboundGroupState s;
            s.chain = std::move(chain);
            s.epoch = r.epoch;
            m_mySendChains[r.groupId] = std::move(s);
        } else {
            InboundChainState s;
            s.chain = std::move(chain);
            s.epoch = r.epoch;
            m_recvChains[std::make_pair(r.groupId, r.senderId)] = std::move(s);
        }
    }
    P2P_LOG("[GROUP] restored " << rows.size() << " persisted sender chain(s)");
}

void GroupProtocol::persistMyChain(const std::string& gid)
{
    if (!m_store) return;
    auto it = m_mySendChains.find(gid);
    if (it == m_mySendChains.end()) {
        // Chain was erased (e.g., after leaving the group) — remove
        // from disk too.  sender_id is our own peer_id.
        m_store->deleteSenderChain(gid, myId());
        return;
    }
    m_store->saveSenderChain(gid, myId(), it->second.epoch,
                              it->second.chain.serialize());
}

void GroupProtocol::persistRemoteChain(const std::string& gid,
                                         const std::string& senderId)
{
    if (!m_store) return;
    const auto key = std::make_pair(gid, senderId);
    auto it = m_recvChains.find(key);
    if (it == m_recvChains.end()) {
        m_store->deleteSenderChain(gid, senderId);
        return;
    }
    // Current chain only — prev-epoch grace-window chains are
    // ephemeral; losing them across a restart is acceptable (5-minute
    // window anyway, and the sender's new chain is already installed
    // for any post-rekey traffic).
    m_store->saveSenderChain(gid, senderId, it->second.epoch,
                              it->second.chain.serialize());
}

void GroupProtocol::sendSkeyAnnounce(const std::string& gid,
                                        uint64_t epoch,
                                        const Bytes& seed,
                                        const std::vector<std::string>& recipients)
{
    if (!m_sendSealed) return;
    if (seed.size() != 32) return;

    const std::string me = myId();
    const int64_t     ts = nowSecs();

    for (const std::string& peerIdRaw : recipients) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        // Each announce carries the full seed.  Per-recipient msgId
        // so envelope-level dedup stays granular — a relay retry of
        // Alice's announce to Bob doesn't collide with her announce
        // to Carol in anyone's seen-LRU.
        json payload = json::object();
        payload["from"]    = me;
        payload["type"]    = "group_skey_announce";
        payload["groupId"] = gid;
        payload["epoch"]   = epoch;
        payload["seed"]    = CryptoEngine::toBase64Url(seed);
        payload["ts"]      = ts;
        payload["msgId"]   = p2p::makeUuid();

        m_sendSealed(peerId, payload);
    }
}
