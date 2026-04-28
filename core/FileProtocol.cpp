#include "FileProtocol.hpp"

#include "CryptoEngine.hpp"
#include "FileTransferManager.hpp"
#include "SessionManager.hpp"
#include "SessionSealer.hpp"
#include "log.hpp"
#include "shared.hpp"
#include "uuid.hpp"

#include <sodium.h>

#include <chrono>
#include <filesystem>

using json = nlohmann::json;
namespace fs = std::filesystem;

using p2p::nowSecs;
using p2p::trimmed;

FileProtocol::FileProtocol(CryptoEngine& crypto,
                            SessionSealer& sealer,
                            FileTransferManager& ftm)
    : m_crypto(crypto), m_sealer(sealer), m_ftm(ftm) {}

std::string FileProtocol::myId() const
{
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
}

// ── Control-message send ──────────────────────────────────────────────────

void FileProtocol::sendControlMessage(const std::string& peerIdB64u,
                                       const nlohmann::json& msg)
{
    if (!m_sendEnvelope) return;

    json payload = msg;
    payload["from"]  = myId();
    payload["ts"]    = nowSecs();
    payload["msgId"] = p2p::makeUuid();

    const std::string ptStr = payload.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    Bytes sealed = m_sealer.sealForPeer(peerIdB64u, pt);
    if (sealed.empty()) {
        P2P_WARN("[FILE] BLOCKED — cannot seal " << msg.value("type", std::string())
                   << " for " << p2p::peerPrefix(peerIdB64u) << "...");
        return;
    }
    m_sendEnvelope(sealed);
}

// ── sendFile (1:1) ─────────────────────────────────────────────────────────

std::string FileProtocol::sendFile(const std::string& peerIdB64u,
                                    const std::string& fileName,
                                    const std::string& filePath)
{
    if (!m_sessionMgr || !m_sendEnvelope) return {};

    std::error_code ec;
    if (!fs::is_regular_file(filePath, ec)) return {};
    const int64_t fileSize = int64_t(fs::file_size(filePath, ec));
    if (ec || fileSize > FileTransferManager::kMaxFileBytes) return {};

    const Bytes fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) return {};

    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const std::string transferId = p2p::makeUuid();

    // Announce the upcoming transfer through the ratchet: fileHash +
    // chunkCount let the receiver allocate its partial-file bitmap and
    // verify the final hash without waiting for every chunk's metadata.
    json announce = json::object();
    announce["from"]        = myId();
    announce["type"]        = "file_key";
    announce["transferId"]  = transferId;
    announce["fileName"]    = fileName;
    announce["fileSize"]    = fileSize;
    announce["fileHash"]    = CryptoEngine::toBase64Url(fileHash);
    announce["chunkCount"]  = chunkCount;
    announce["ts"]          = nowSecs();

    const std::string ptStr = announce.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    Bytes sealedEnv = m_sealer.sealForPeer(peerIdB64u, pt);
    if (sealedEnv.empty()) {
        P2P_WARN("[FILE] BLOCKED — cannot seal file_key for " << p2p::peerPrefix(peerIdB64u) << "...");
        return {};
    }

    // Queue the outbound state BEFORE we put the file_key on the wire.
    // Otherwise the receiver's file_accept can race back faster than the
    // queue call completes and FTM sees "startOutboundStream: unknown
    // transferId" — a race latent in production and reliably reproduced
    // by in-process test mocks.
    //
    // Arch-review #4: derive the per-file key explicitly from the
    // ratchet key via HKDF(info = "peer2pear:file-key-v1:" || tid).
    // The raw ratchet key sits in m_sessionMgr->lastMessageKey() for
    // a brief window after sealForPeer; we capture + immediately
    // transform, then zero the intermediate.  The transferId binding
    // means a compromised ratchet-key snapshot can't be misapplied
    // to a different in-flight transfer.
    Bytes ratchetMsgKey = m_sessionMgr->lastMessageKey();
    Bytes fileKey = CryptoEngine::deriveFileKey(ratchetMsgKey, transferId);
    CryptoEngine::secureZero(ratchetMsgKey);
    m_ftm.queueOutboundFile(myId(), peerIdB64u,
                             fileKey, transferId, fileName, filePath,
                             fileSize, fileHash);
    CryptoEngine::secureZero(fileKey);

    m_sendEnvelope(sealedEnv);
    P2P_LOG("[FILE] file_key announced for " << p2p::peerPrefix(transferId) << "..."
             << " to " << p2p::peerPrefix(peerIdB64u) << "... size=" << fileSize);
    return transferId;
}

// ── sendGroupFile ─────────────────────────────────────────────────────────

std::string FileProtocol::sendGroupFile(const std::string& groupId,
                                         const std::string& groupName,
                                         const std::vector<std::string>& memberPeerIds,
                                         const std::string& fileName,
                                         const std::string& filePath)
{
    if (!m_sessionMgr || !m_sendEnvelope) return {};

    std::error_code ec;
    if (!fs::is_regular_file(filePath, ec)) return {};
    const int64_t fileSize = int64_t(fs::file_size(filePath, ec));
    if (ec || fileSize > FileTransferManager::kMaxFileBytes) return {};

    // Hash the file once up-front (streaming) and reuse for all members.
    const Bytes fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) return {};

    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const std::string me = myId();

    // Each member gets a unique transferId so consent is honored per
    // recipient.  The caller sees one group-level id for cancellation;
    // per-member callbacks fire with the per-member transferId.
    const std::string groupTransferId = p2p::makeUuid();
    std::vector<std::string> memberTids;
    memberTids.reserve(memberPeerIds.size());

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == me) continue;

        const std::string memberTid = p2p::makeUuid();

        json announce = json::object();
        announce["from"]        = me;
        announce["type"]        = "file_key";
        announce["transferId"]  = memberTid;
        announce["fileName"]    = fileName;
        announce["fileSize"]    = fileSize;
        announce["fileHash"]    = CryptoEngine::toBase64Url(fileHash);
        announce["chunkCount"]  = chunkCount;
        announce["ts"]          = nowSecs();
        announce["groupId"]     = groupId;
        announce["groupName"]   = groupName;

        const std::string ptStr = announce.dump();
        const Bytes pt(ptStr.begin(), ptStr.end());
        Bytes sealedEnv = m_sealer.sealForPeer(peerId, pt);
        if (sealedEnv.empty()) {
            P2P_WARN("[FILE] BLOCKED — cannot seal file_key for " << p2p::peerPrefix(peerId) << "...");
            continue;
        }

        // Queue BEFORE send — see sendFile for the race rationale.
        // Arch-review #4: explicit deriveFileKey with the member's
        // unique transferId so cross-member file-key mixups are
        // cryptographically impossible even with a serialized loop.
        Bytes ratchetMsgKey = m_sessionMgr->lastMessageKey();
        Bytes fileKey = CryptoEngine::deriveFileKey(ratchetMsgKey, memberTid);
        CryptoEngine::secureZero(ratchetMsgKey);
        m_ftm.queueOutboundFile(me, peerId, fileKey, memberTid, fileName,
                                 filePath, fileSize, fileHash,
                                 groupId, groupName);
        CryptoEngine::secureZero(fileKey);

        m_sendEnvelope(sealedEnv);
        P2P_LOG("[FILE] file_key announced for " << p2p::peerPrefix(memberTid) << "..."
                 << " to " << p2p::peerPrefix(peerId) << "... (group)");

        memberTids.push_back(memberTid);
    }

    if (!memberTids.empty())
        m_groupFileMembers[groupTransferId] = std::move(memberTids);

    return groupTransferId;
}

// ── Accept / decline / cancel ─────────────────────────────────────────────

void FileProtocol::acceptIncoming(const std::string& transferId, bool requireP2P)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) {
        P2P_WARN("[FILE] acceptIncoming: no pending transfer " << p2p::peerPrefix(transferId));
        return;
    }

    const std::string peerId   = it->second.peerId;
    const std::string compound = peerId + ":" + transferId;

    // Announce with the metadata locked at file_key time — NOT whatever
    // the sender might put in later chunks.
    if (!m_ftm.announceIncoming(peerId,
                                  transferId,
                                  it->second.fileName,
                                  it->second.fileSize, it->second.totalChunks,
                                  it->second.fileHash,
                                  it->second.fileKey,
                                  it->second.announcedTs,
                                  it->second.groupId,
                                  it->second.groupName)) {
        P2P_WARN("[FILE] acceptIncoming: announceIncoming failed for "
                   << p2p::peerPrefix(transferId));
        sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
        m_pendingIncomingFiles.erase(it);
        return;
    }

    // Move the stashed key into the active file-keys map so chunks decrypt.
    m_fileKeys[compound] = it->second.fileKey;

    sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
    m_pendingIncomingFiles.erase(it);

    json msg = json::object();
    msg["type"]       = "file_accept";
    msg["transferId"] = transferId;
    // Respect the receiver's global "no relay" preference, or the per-call override.
    if (requireP2P || m_requireP2P) msg["requireP2P"] = true;
    sendControlMessage(peerId, msg);
}

void FileProtocol::declineIncoming(const std::string& transferId)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) return;

    const std::string peerId = it->second.peerId;
    sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
    m_pendingIncomingFiles.erase(it);

    json msg = json::object();
    msg["type"]       = "file_decline";
    msg["transferId"] = transferId;
    // NO reason field — see privacy mitigations in the protocol spec.
    sendControlMessage(peerId, msg);

    if (onCanceled) onCanceled(transferId, true);  // receiver declined
}

void FileProtocol::cancel(const std::string& transferId)
{
    // Figure out which role we hold for this transferId and clean up + notify.

    // Group-level id we returned from sendGroupFile?  Fan the cancel
    // out to every per-member transferId underneath it.
    auto grpIt = m_groupFileMembers.find(transferId);
    if (grpIt != m_groupFileMembers.end()) {
        for (const std::string& memberTid : grpIt->second) {
            const std::string peer = m_ftm.outboundPeerFor(memberTid);
            if (peer.empty()) continue;  // already accepted/declined/streamed away
            m_ftm.abandonOutboundTransfer(memberTid);
            json msg = json::object();
            msg["type"]       = "file_cancel";
            msg["transferId"] = memberTid;
            sendControlMessage(peer, msg);
        }
        m_groupFileMembers.erase(grpIt);
        if (onCanceled) onCanceled(transferId, false);
        return;
    }

    // Outbound pending (sender canceling a queued-but-unaccepted send)?
    const std::string outboundPeer = m_ftm.outboundPeerFor(transferId);
    if (!outboundPeer.empty()) {
        m_ftm.abandonOutboundTransfer(transferId);
        json msg = json::object();
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendControlMessage(outboundPeer, msg);
        if (onCanceled) onCanceled(transferId, false);  // sender-initiated
        return;
    }

    // Inbound, pre-accept (user changed mind before answering prompt)?
    auto itPending = m_pendingIncomingFiles.find(transferId);
    if (itPending != m_pendingIncomingFiles.end()) {
        const std::string peerId = itPending->second.peerId;
        sodium_memzero(itPending->second.fileKey.data(), itPending->second.fileKey.size());
        m_pendingIncomingFiles.erase(itPending);
        json msg = json::object();
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendControlMessage(peerId, msg);
        if (onCanceled) onCanceled(transferId, true);   // receiver-initiated
        return;
    }

    // Inbound, in-progress (user canceled mid-stream)?
    const std::string inboundPeer = m_ftm.inboundPeerFor(transferId);
    if (!inboundPeer.empty()) {
        m_ftm.cancelInboundTransfer(transferId);
        json msg = json::object();
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendControlMessage(inboundPeer, msg);
        if (onCanceled) onCanceled(transferId, true);
    }
}

// ── Accessors ─────────────────────────────────────────────────────────────

void FileProtocol::eraseFileKey(const std::string& compoundKey)
{
    auto it = m_fileKeys.find(compoundKey);
    if (it != m_fileKeys.end()) {
        sodium_memzero(it->second.data(), it->second.size());
        m_fileKeys.erase(it);
    }
}

// Arch-review #5: consolidated helpers that used to be open-coded in
// ChatController.  They keep file-key + control-message state owned
// by FileProtocol so the file-transfer boundary is cohesive instead
// of spread across three classes.

void FileProtocol::sendFileAck(const std::string& peerIdB64u,
                                 const std::string& transferId)
{
    if (peerIdB64u.empty() || transferId.empty()) return;
    nlohmann::json ack = nlohmann::json::object();
    ack["type"]       = "file_ack";
    ack["transferId"] = transferId;
    sendControlMessage(peerIdB64u, ack);
}

void FileProtocol::installChunkSealCallback()
{
    // Route every outbound file chunk through SessionSealer so the
    // hard-block-on-key-change policy applies (Arch-review #2).
    m_ftm.setSealFn([this](const std::string& peerId,
                            const Bytes& payload)
                              -> Bytes {
        return m_sealer.sealPreEncryptedForPeer(peerId, payload);
    });
}

void FileProtocol::installIncomingKey(const std::string& peerIdB64u,
                                       const std::string& transferId,
                                       const Bytes& fileKey)
{
    if (peerIdB64u.empty() || transferId.empty() || fileKey.size() != 32) return;
    const std::string compound = peerIdB64u + ":" + transferId;
    m_fileKeys[compound] = fileKey;
}

void FileProtocol::eraseFileKeysFor(const std::string& transferId)
{
    if (transferId.empty()) return;
    const std::string suffix = ":" + transferId;
    auto it = m_fileKeys.begin();
    while (it != m_fileKeys.end()) {
        const auto& k = it->first;
        const bool ends = k.size() >= suffix.size() &&
                          k.compare(k.size() - suffix.size(), suffix.size(), suffix) == 0;
        if (ends || k == transferId) {
            sodium_memzero(it->second.data(), it->second.size());
            it = m_fileKeys.erase(it);
        } else {
            ++it;
        }
    }
}
