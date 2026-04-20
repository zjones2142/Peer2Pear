#include "ChatController.hpp"
#include "bytes_util.hpp"  // strBytes helper (Qt-free)
#ifdef PEER2PEAR_P2P
// QuicConnection is Qt-free (Phase 7d).  NiceConnection.hpp pulls in
// nice/agent.h, whose gio dependency uses `signals` as a struct member —
// clashes with Qt's `signals` macro.  Undef before, restore after so any
// Qt header later in the TU still compiles cleanly.
#undef signals
#include "NiceConnection.hpp"   // brings nice/agent.h (NICE_COMPONENT_STATE_*)
#include "QuicConnection.hpp"
#define signals Q_SIGNALS
#endif
// SqlCipherQuery is available via ChatController.hpp -> SqlCipherDb.hpp
#include <sodium.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include "log.hpp"
#include "uuid.hpp"

using nlohmann::json;

// Envelope header prefixes.  Both legacy prefixes (FROM: for text, FROMFC:
// for file chunks) were removed in the H1 fix (2026-04-19) — every outbound
// frame is now a sealed envelope and every inbound frame that isn't sealed
// is dropped by onEnvelope / onP2PDataReceived.
static const char kSealedPrefix[]   = "SEALED:";
static const char kSealedFCPrefix[] = "SEALEDFC:";

// ── Helpers ───────────────────────────────────────────────────────────────────

// Current unix time in seconds.  Replaces QDateTime::currentSecsSinceEpoch().
static int64_t nowSecs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

// Byte range starts-with / utility — replaces QByteArray::startsWith.
static bool bytesStartsWith(const Bytes& data, const char* prefix) {
    const size_t n = std::strlen(prefix);
    if (data.size() < n) return false;
    return std::memcmp(data.data(), prefix, n) == 0;
}

// Byte range past the given prefix, trimmed of leading whitespace / newlines.
// Replaces the QByteArray mid + trimmed idiom.
static Bytes bytesAfterPrefix(const Bytes& data, const char* prefix) {
    const size_t n = std::strlen(prefix);
    if (data.size() < n) return {};
    return Bytes(data.begin() + n, data.end());
}

// ── ChatController ────────────────────────────────────────────────────────────

ChatController::ChatController(IWebSocket& ws, IHttpClient& http,
                                ITimerFactory& timers)
    : m_relay(ws, http, timers, &m_crypto)
    , m_fileMgr(m_crypto)
    , m_timerFactory(&timers)
    , m_maintenanceTimer(timers.create())
{
    // RelayClient — plain class now; assign callbacks directly.
    m_relay.onStatus = [this](const std::string& s) {
        if (onStatus) onStatus(s);
    };
    m_relay.onEnvelopeReceived = [this](const RelayClient::Bytes& b) {
        onEnvelope(b);
    };
    m_relay.onPresenceChanged = [this](const std::string& pid, bool online) {
        if (onPresenceChanged) onPresenceChanged(pid, online);
    };
    m_relay.onConnected = [this]() { handleRelayConnected(); };

    // FileTransferManager callbacks — plain class; direct assignment.
    m_fileMgr.setSendFn([this](const std::string& /*peerId*/,
                               const FileTransferManager::Bytes& env) {
        m_relay.sendEnvelope(env);
    });
    m_fileMgr.onStatus = [this](const std::string& s) {
        if (onStatus) onStatus(s);
    };

    // Sender-side per-chunk progress passthrough.  FTM fires this after
    // every successful dispatchChunk; we just forward it — no file_ack
    // composition here because acks flow the other way (receiver → sender).
    m_fileMgr.onFileChunkSent = [this](const std::string& toPeerId,
                                        const std::string& transferId,
                                        const std::string& fileName,
                                        int64_t fileSize,
                                        int chunksSent, int chunksTotal,
                                        int64_t tsSecs,
                                        const std::string& groupId,
                                        const std::string& groupName) {
        if (onFileChunkSent) onFileChunkSent(
            toPeerId, transferId, fileName, fileSize,
            chunksSent, chunksTotal, tsSecs, groupId, groupName);
    };

    // fileChunkReceived fires from TWO callsites in FTM — one for progress/save,
    // one for the file_ack nudge.  Compose them into a single callback.
    m_fileMgr.onFileChunkReceived = [this](const std::string& fromPeerId,
                                            const std::string& transferId,
                                            const std::string& fileName,
                                            int64_t fileSize,
                                            int chunksReceived, int chunksTotal,
                                            const std::string& savedPath,
                                            int64_t tsSecs,
                                            const std::string& groupId,
                                            const std::string& groupName) {
        if (onFileChunkReceived) onFileChunkReceived(
            fromPeerId, transferId, fileName, fileSize,
            chunksReceived, chunksTotal,
            savedPath, tsSecs,
            groupId, groupName);

        // Phase 3: receiver finished writing and verified — send file_ack.
        if (chunksReceived == chunksTotal && !savedPath.empty()) {
            json ack = json::object();
            ack["type"]       = "file_ack";
            ack["transferId"] = transferId;
            sendFileControlMessage(fromPeerId, ack);
        }
    };

#ifdef PEER2PEAR_P2P
    m_fileMgr.onWantP2PConnection = [this](const std::string& peerId) {
        initiateP2PConnection(peerId);
    };
#endif

    // M1 fix: remove ratchet-derived file key when transfer completes.
    m_fileMgr.onTransferCompleted = [this](const std::string& transferId) {
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
    };

    m_fileMgr.onOutboundAbandoned = [this](const std::string& transferId, const std::string&) {
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);
    };

    m_fileMgr.onInboundCanceled = [this](const std::string& transferId, const std::string&) {
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);
    };

    m_fileMgr.onOutboundBlockedByPolicy =
        [this](const std::string& transferId, const std::string&, bool byReceiver) {
        if (onFileTransferBlocked) onFileTransferBlocked(transferId, byReceiver);
    };

    // Fix #5: rehydrate file keys from DB after loadPersistedTransfers().
    m_fileMgr.onIncomingFileKeyRestored =
        [this](const std::string& fromPeerId,
               const std::string& transferId,
               const FileTransferManager::Bytes& fileKey) {
        if (fileKey.size() != 32) return;
        const std::string compound = fromPeerId + ":" + transferId;
        m_fileKeys[compound] = fileKey;
        P2P_LOG("[FILE] restored file key for " << transferId.substr(0, 8)
                 << " from " << fromPeerId.substr(0, 8) << "...");
    };

    // Periodic maintenance — ITimer replaces the former QTimer.  Self-rearms.
    scheduleMaintenance();
}

void ChatController::scheduleMaintenance()
{
    if (!m_maintenanceTimer) return;
    m_maintenanceTimer->startSingleShot(30 * 1000, [this]{
        runMaintenance();
        scheduleMaintenance();  // re-arm
    });
}

void ChatController::runMaintenance()
{
    // H3 fix: reset per-sender rate limit counters
    m_envelopeCount.clear();
    m_fileRequestCount.clear();  // H3 audit-#2 fix: same poll-reset model

    // Purge stale incomplete transfers
    m_fileMgr.purgeStaleTransfers();
    m_fileMgr.purgeStaleOutbound();
    m_fileMgr.purgeStalePartialFiles();

    // H2/SEC9: prune stuck handshakes
    if (m_sessionStore) {
        const auto pruned = m_sessionStore->pruneStaleHandshakes();
        for (const std::string& peerId : pruned) {
            int count = ++m_handshakeFailCount[peerId];
            if (count >= 2 && onPeerMayNeedUpgrade)
                onPeerMayNeedUpgrade(peerId);
        }
    }

    // H5 fix: age out the persistent envelope-ID dedup table.
    pruneSeenEnvelopes();

#ifdef PEER2PEAR_P2P
    const int64_t now = nowSecs();
    std::vector<std::string> toRemove;
    for (auto it = m_p2pConnections.begin(); it != m_p2pConnections.end(); ++it) {
        if (it->second->isReady()) continue;
        auto ts = m_p2pCreatedSecs.find(it->first);
        const int64_t created = (ts != m_p2pCreatedSecs.end()) ? ts->second : now;
        if ((now - created) < kP2PCleanupGraceSecs) continue;
        toRemove.push_back(it->first);
    }
    for (const std::string &key : toRemove) {
        P2P_LOG("[ICE] Cleaning up stale connection to " << key.substr(0, 8) << "..."
                 << " (exceeded " << kP2PCleanupGraceSecs << "s grace)");
        delete m_p2pConnections[key];   // QuicConnection is plain class now (Phase 7d)
        m_p2pConnections.erase(key);
        m_p2pCreatedSecs.erase(key);
    }
#endif
}

void ChatController::setPassphrase(const std::string& pass)
{
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity();
}

void ChatController::setPassphrase(const std::string& pass, const Bytes& identityKey)
{
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity(identityKey);
}

void ChatController::setRelayUrl(const std::string& url)
{
    m_relay.setRelayUrl(url);
}

void ChatController::setDatabase(SqlCipherDb& db)
{
    // Guard against double-call: reset previous instances before reinitializing
    m_sessionMgr.reset();
    m_sessionStore.reset();
    m_dbPtr = &db;

    // Derive a 32-byte at-rest encryption key from the identity curve private key.
    // This key never leaves memory and is tied to the user's unlocked identity.
    using p2p::bridge::strBytes;
    std::vector<uint8_t> storeKey = CryptoEngine::hkdf(
        m_crypto.curvePriv(), {}, strBytes("session-store-at-rest"), 32);
    m_sessionStore = std::make_unique<SessionStore>(db, storeKey);
    CryptoEngine::secureZero(storeKey);

    // One-time migration: clear sessions when serialization format changes.
    // v5: ratchet init fix.  v6: PQ hybrid (Noise v4 + RatchetSession v2).
    // v7: sealed envelope v2 (recipient-bound AAD + envelope-id).
    {
        SqlCipherQuery q(db);
        q.prepare("SELECT value FROM settings WHERE key='ratchet_v7_cleared';");
        if (!q.exec() || !q.next()) {
            m_sessionStore->clearAll();
            SqlCipherQuery ins(db);
            ins.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('ratchet_v7_cleared','1');");
            ins.exec();
        }
    }

    m_sessionMgr = std::make_unique<SessionManager>(m_crypto, *m_sessionStore);

    // Phase 4: wire up file-transfer persistence and restore any in-flight state.
    m_fileMgr.setDatabase(&db);
    m_fileMgr.loadPersistedTransfers();
    m_fileMgr.purgeStalePartialFiles();

    // H5 fix: envelope-ID dedup survives restart when a DB is present.
    ensureSeenEnvelopesTable();
    // Safety-numbers store for out-of-band verification.
    ensureVerifiedPeersTable();

    // When SessionManager needs to send a handshake response, seal it and enqueue
    m_sessionMgr->setSendResponseFn([this](const std::string& peerId, const Bytes& blob) {
        // Convert peer's Ed25519 pub to X25519 for sealing
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0) return;

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        Bytes peerKemPub = lookupPeerKemPub(peerId);
        Bytes sealed = SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            blob, peerKemPub,
            m_crypto.dsaPub(), m_crypto.dsaPriv());
        if (sealed.empty()) return;
        P2P_LOG("[SEND MAILBOX] sealed handshake response to " << peerId.substr(0, 8) << "..."
                 << " " << (peerKemPub.empty() ? "(classical)" : "(hybrid PQ)"));

        // Inner wire: kSealedPrefix + "\n" + sealed
        Bytes inner;
        const size_t prefixLen = std::strlen(kSealedPrefix);
        inner.reserve(prefixLen + 1 + sealed.size());
        inner.insert(inner.end(),
                     reinterpret_cast<const uint8_t*>(kSealedPrefix),
                     reinterpret_cast<const uint8_t*>(kSealedPrefix) + prefixLen);
        inner.push_back('\n');
        inner.insert(inner.end(), sealed.begin(), sealed.end());

        m_relay.sendEnvelope(SealedEnvelope::wrapForRelay(peerEdPub, inner));
    });

    // M2 fix: Seal callback for file chunks — FTM speaks std types end-to-end.
    m_fileMgr.setSealFn([this](const std::string& peerId,
                               const FileTransferManager::Bytes& payload)
                              -> FileTransferManager::Bytes {
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
            return {};

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        sodium_memzero(peerCurvePub, sizeof(peerCurvePub));
        Bytes peerKemPub = lookupPeerKemPub(peerId);
        Bytes sealed = SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            payload, peerKemPub,
            m_crypto.dsaPub(), m_crypto.dsaPriv());
        if (sealed.empty()) return {};

        // Inner wire: kSealedFCPrefix + "\n" + sealed
        Bytes inner;
        const size_t prefixLen = std::strlen(kSealedFCPrefix);
        inner.reserve(prefixLen + 1 + sealed.size());
        inner.insert(inner.end(),
                     reinterpret_cast<const uint8_t*>(kSealedFCPrefix),
                     reinterpret_cast<const uint8_t*>(kSealedFCPrefix) + prefixLen);
        inner.push_back('\n');
        inner.insert(inner.end(), sealed.begin(), sealed.end());

        return SealedEnvelope::wrapForRelay(peerEdPub, inner);
    });
#ifdef PEER2PEAR_P2P
    // QUIC P2P file send callback: try sending file chunks directly via QUIC stream
    m_fileMgr.setP2PFileSendFn([this](const std::string& peerId,
                                       const FileTransferManager::Bytes& data) -> bool {
        auto it = m_p2pConnections.find(peerId);
        if (it != m_p2pConnections.end() &&
            it->second->isReady() &&
            it->second->quicActive()) {
            it->second->sendFileData(data);
            return true;
        }
        return false;  // fall back to mailbox
    });
#endif

}

std::string ChatController::myIdB64u() const
{
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
}

void ChatController::sendText(const std::string& peerIdB64u, const std::string& text)
{
    // Safety-numbers check happens inside sealForPeer — one choke point
    // covers 1:1 text, 1:1 avatar/file, group fan-outs, and group control
    // messages uniformly.  sealForPeer returns empty under hard-block,
    // which the caller interprets as "message not sent".

    json payload = json::object();
    payload["from"]  = myIdB64u();
    payload["type"]  = "text";
    payload["text"]  = text;
    payload["ts"]    = nowSecs();
    payload["msgId"] = p2p::makeUuid();

    const std::string ptStr = payload.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());

    // ── Sealed path (always required for text) ──────────────────────────────
    Bytes sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.empty()) {
        P2P_WARN("[SEND] BLOCKED — cannot seal text to " << peerIdB64u.substr(0, 8) << "...");
        if (onStatus) onStatus("Message not sent — encrypted session unavailable. Try again shortly.");
        return;
    }

#ifdef PEER2PEAR_P2P
    auto itConn = m_p2pConnections.find(peerIdB64u);
    if (itConn != m_p2pConnections.end() && itConn->second->isReady()) {
        P2P_LOG("[SEND P2P] sealed text to " << peerIdB64u.substr(0, 8) << "...");
        itConn->second->sendData(sealedEnv);
    } else
#endif
    {
        P2P_LOG("[SEND RELAY] sealed text to " << peerIdB64u.substr(0, 8) << "...");
        m_relay.sendEnvelope(sealedEnv);
#ifdef PEER2PEAR_P2P
        initiateP2PConnection(peerIdB64u);
#endif
    }
}

void ChatController::sendAvatar(const std::string& peerIdB64u,
                                const std::string& displayName,
                                const std::string& avatarB64)
{
    json payload = json::object();
    payload["from"]   = myIdB64u();
    payload["type"]   = "avatar";
    payload["name"]   = displayName;
    payload["avatar"] = avatarB64;
    sendSealedPayload(peerIdB64u, payload);   // S7 fix: use sealed path
}

// ── File transfer delegation ─────────────────────────────────────────────────

std::string ChatController::sendFile(const std::string& peerIdB64u,
                                     const std::string& fileName,
                                     const std::string& filePath)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(filePath, ec)) {
        if (onStatus) onStatus("File not found: " + filePath);
        return {};
    }
    const int64_t fileSize = int64_t(fs::file_size(filePath, ec));
    if (ec || fileSize > FileTransferManager::kMaxFileBytes) {
        if (onStatus) onStatus("File too large (max "
                               + std::to_string(FileTransferManager::kMaxFileBytes / (1024 * 1024))
                               + " MB).");
        return {};
    }

    // Streaming hash — one pass over the file, bounded RAM.
    const Bytes fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) {
        if (onStatus) onStatus("Could not hash file: " + fileName);
        return {};
    }
    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const std::string transferId = p2p::makeUuid();

    // Send file_key announcement through the ratchet to derive a forward-secret key.
    // The announcement now includes fileHash + chunkCount so the receiver can allocate
    // its partial-file bitmap and verify the final hash without waiting for every chunk's metadata.
    json announce = json::object();
    announce["from"]        = myIdB64u();
    announce["type"]        = "file_key";
    announce["transferId"]  = transferId;
    announce["fileName"]    = fileName;
    announce["fileSize"]    = fileSize;
    announce["fileHash"]    = CryptoEngine::toBase64Url(fileHash);
    announce["chunkCount"]  = chunkCount;
    announce["ts"]          = nowSecs();

    const std::string ptStr = announce.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    Bytes sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.empty()) {
        P2P_WARN("[FILE] BLOCKED — cannot seal file_key for " << peerIdB64u.substr(0, 8) << "...");
        if (onStatus) onStatus("File not sent — encrypted session unavailable.");
        return {};
    }

    m_relay.sendEnvelope(sealedEnv);

    Bytes fileKey = m_sessionMgr->lastMessageKey();
    P2P_LOG("[FILE] file_key announced for " << transferId.substr(0, 8) << "..."
             << " to " << peerIdB64u.substr(0, 8) << "... size=" << fileSize);

    // Phase 2: queue outbound state. Chunks don't fly until file_accept arrives.
    m_fileMgr.queueOutboundFile(myIdB64u(), peerIdB64u,
                                 fileKey, transferId, fileName, filePath,
                                 fileSize, fileHash);
    sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    return transferId;
}

std::string ChatController::sendGroupFile(const std::string& groupId,
                                          const std::string& groupName,
                                          const std::vector<std::string>& memberPeerIds,
                                          const std::string& fileName,
                                          const std::string& filePath)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(filePath, ec)) {
        if (onStatus) onStatus("File not found: " + filePath);
        return {};
    }
    const int64_t fileSize = int64_t(fs::file_size(filePath, ec));
    if (ec || fileSize > FileTransferManager::kMaxFileBytes) {
        if (onStatus) onStatus("File too large (max "
                               + std::to_string(FileTransferManager::kMaxFileBytes / (1024 * 1024))
                               + " MB).");
        return {};
    }

    // Hash the file once up-front (streaming) and reuse for all members.
    const Bytes fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) {
        if (onStatus) onStatus("Could not hash file: " + fileName);
        return {};
    }
    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const std::string myId = myIdB64u();

    // LC4 audit fix (2026-04-19): each member gets a unique transferId so
    // the sender can honor Phase 2 consent (queue-then-wait-for-file_accept)
    // independently per recipient, matching 1:1 behavior.  The caller sees
    // a single group-level transferId that fans out to all members for
    // cancellation; per-member callbacks (file_accept, file_ack, file_cancel
    // etc.) fire with the per-member transferId as they do for 1:1.
    const std::string groupTransferId = p2p::makeUuid();
    std::vector<std::string> memberTids;
    memberTids.reserve(memberPeerIds.size());

    for (const std::string& peerIdRaw : memberPeerIds) {
        // Trim leading/trailing whitespace (was QString::trimmed()).
        auto lb = peerIdRaw.find_first_not_of(" \t\r\n");
        if (lb == std::string::npos) continue;
        auto rb = peerIdRaw.find_last_not_of(" \t\r\n");
        const std::string peerId = peerIdRaw.substr(lb, rb - lb + 1);
        if (peerId.empty() || peerId == myId) continue;

        const std::string memberTid = p2p::makeUuid();

        json announce = json::object();
        announce["from"]        = myId;
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
        Bytes sealedEnv = sealForPeer(peerId, pt);
        if (sealedEnv.empty()) {
            P2P_WARN("[FILE] BLOCKED — cannot seal file_key for " << peerId.substr(0, 8) << "...");
            continue;
        }

        m_relay.sendEnvelope(sealedEnv);

        Bytes fileKey = m_sessionMgr->lastMessageKey();
        P2P_LOG("[FILE] file_key announced for " << memberTid.substr(0, 8) << "..."
                 << " to " << peerId.substr(0, 8) << "... (group)");

        // Queue — do not stream.  Chunks for this member fly only after that
        // member's file_accept arrives, identical to the 1:1 flow.
        m_fileMgr.queueOutboundFile(myId, peerId, fileKey, memberTid, fileName,
                                     filePath, fileSize, fileHash,
                                     groupId, groupName);
        sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix

        memberTids.push_back(memberTid);
    }

    if (!memberTids.empty())
        m_groupFileMembers[groupTransferId] = std::move(memberTids);

    if (onStatus) onStatus("'" + fileName + "' queued for group " + groupName
                           + " (awaiting per-member consent)");
    return groupTransferId;
}

void ChatController::connectToRelay()
{
    m_relay.connectToRelay();
}

void ChatController::disconnectFromRelay()
{
    m_relay.disconnectFromRelay();
}

void ChatController::handleRelayConnected()
{
    // The relay delivers stored mailbox envelopes on WS connect automatically.
    // No need to poll — envelopes arrive via push.
    P2P_LOG("[ChatController] Relay connected, envelopes will be pushed.");
    if (onRelayConnected) onRelayConnected();

    // Phase 4: for each incomplete incoming transfer, tell the sender which
    // chunks we still need so they can re-send them.
    const auto pendings = m_fileMgr.pendingResumptions();
    for (const auto& pr : pendings) {
        json chunks = json::array();
        for (uint32_t idx : pr.missingChunks) chunks.push_back(int(idx));
        json msg = json::object();
        msg["type"]       = "file_request";
        msg["transferId"] = pr.transferId;
        msg["chunks"]     = std::move(chunks);
        sendFileControlMessage(pr.peerId, msg);
        P2P_LOG("[FILE] requested resumption of "
                 << pr.transferId.substr(0, 8)
                 << " from " << pr.peerId.substr(0, 8) << "..."
                 << " missing " << int(pr.missingChunks.size()) << " chunks");
    }
}

void ChatController::subscribePresence(const std::vector<std::string>& peerIds)
{
    m_relay.subscribePresence(peerIds);
}

void ChatController::setSelfKeys(const std::vector<std::string>& keys) {
    m_selfKeys = keys;
}

#ifdef PEER2PEAR_P2P
void ChatController::setTurnServer(const std::string& host, int port,
                                    const std::string& username, const std::string& password)
{
    m_turnHost = host;
    m_turnPort = port;
    m_turnUser = username;
    m_turnPass = password;
    P2P_LOG("[ChatController] TURN server set: " << host << ":" << port);
}
#endif

void ChatController::checkPresence(const std::vector<std::string>& peerIds)
{
    std::vector<std::string> ids;
    m_relay.queryPresence(peerIds);
}

// ── Phase 2: file-transfer consent / cancel ──────────────────────────────────

void ChatController::sendFileControlMessage(const std::string& peerIdB64u,
                                             const nlohmann::json& msg)
{
    // Include a fresh msgId so the receiver can dedup any duplicated delivery.
    json payload = msg;
    payload["from"]  = myIdB64u();
    payload["ts"]    = nowSecs();
    payload["msgId"] = p2p::makeUuid();

    const std::string ptStr = payload.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    Bytes sealed = sealForPeer(peerIdB64u, pt);
    if (sealed.empty()) {
        P2P_WARN("[FILE] BLOCKED — cannot seal " << msg.value("type", std::string())
                   << " for " << peerIdB64u.substr(0, 8) << "...");
        return;
    }
    m_relay.sendEnvelope(sealed);
}

void ChatController::acceptFileTransfer(const std::string& transferId, bool requireP2P)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) {
        P2P_WARN("[FILE] acceptFileTransfer: no pending transfer " << transferId.substr(0, 8));
        return;
    }

    const std::string peerId   = it->second.peerId;
    const std::string compound = peerId + ":" + transferId;

    // Fix #3: announce with the metadata locked from file_key time — NOT from
    // whatever the sender might put in later chunks.
    if (!m_fileMgr.announceIncoming(peerId,
                                      transferId,
                                      it->second.fileName,
                                      it->second.fileSize, it->second.totalChunks,
                                      it->second.fileHash,
                                      it->second.fileKey,
                                      it->second.announcedTs,
                                      it->second.groupId,
                                      it->second.groupName)) {
        P2P_WARN("[FILE] acceptFileTransfer: announceIncoming failed for "
                   << transferId.substr(0, 8));
        sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
        m_pendingIncomingFiles.erase(it);
        return;
    }

    // Move the stashed key into the active file-keys map so chunks decrypt.
    m_fileKeys[compound] = it->second.fileKey;           // copy

    sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
    m_pendingIncomingFiles.erase(it);

    json msg = json::object();
    msg["type"]       = "file_accept";
    msg["transferId"] = transferId;
    // Respect the receiver's global "no relay" preference, or the per-call override.
    if (requireP2P || m_fileRequireP2P) msg["requireP2P"] = true;
    sendFileControlMessage(peerId, msg);
}

void ChatController::declineFileTransfer(const std::string& transferId)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) return;

    const std::string peerId = it->second.peerId;
    sodium_memzero(it->second.fileKey.data(), it->second.fileKey.size());
    m_pendingIncomingFiles.erase(it);

    json msg = json::object();
    msg["type"]       = "file_decline";
    msg["transferId"] = transferId;
    // NO reason field — see privacy mitigations §4 in the plan.
    sendFileControlMessage(peerId, msg);

    if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);  // receiver declined
}

void ChatController::cancelFileTransfer(const std::string& transferId)
{
    // Figure out which role we hold for this transferId and clean up + notify.

    // LC4: if this is the group-level id we returned from sendGroupFile,
    // fan out the cancel to every per-member transferId underneath it.
    auto grpIt = m_groupFileMembers.find(transferId);
    if (grpIt != m_groupFileMembers.end()) {
        for (const std::string& memberTid : grpIt->second) {
            const std::string peer = m_fileMgr.outboundPeerFor(memberTid);
            if (peer.empty()) continue;  // already accepted/declined/streamed away
            m_fileMgr.abandonOutboundTransfer(memberTid);
            json msg = json::object();
            msg["type"]       = "file_cancel";
            msg["transferId"] = memberTid;
            sendFileControlMessage(peer, msg);
        }
        m_groupFileMembers.erase(grpIt);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);
        return;
    }

    // Outbound pending (sender canceling a queued-but-unaccepted send)?
    const std::string outboundPeer = m_fileMgr.outboundPeerFor(transferId);
    if (!outboundPeer.empty()) {
        m_fileMgr.abandonOutboundTransfer(transferId);
        json msg = json::object();
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(outboundPeer, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);  // sender-initiated
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
        sendFileControlMessage(peerId, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);   // receiver-initiated
        return;
    }

    // Inbound, in-progress (user canceled mid-stream)?
    const std::string inboundPeer = m_fileMgr.inboundPeerFor(transferId);
    if (!inboundPeer.empty()) {
        m_fileMgr.cancelInboundTransfer(transferId);
        json msg = json::object();
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(inboundPeer, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);
    }
}

// Local helper: trim ASCII whitespace from both ends (replaces QString::trimmed).
static std::string trimmed(const std::string& s) {
    auto lb = s.find_first_not_of(" \t\r\n");
    if (lb == std::string::npos) return {};
    auto rb = s.find_last_not_of(" \t\r\n");
    return s.substr(lb, rb - lb + 1);
}

void ChatController::sendGroupMessageViaMailbox(const std::string& groupId,
                                                const std::string& groupName,
                                                const std::vector<std::string>& memberPeerIds,
                                                const std::string& text)
{
    const std::string myId  = myIdB64u();
    const int64_t     ts    = nowSecs();
    const std::string msgId = p2p::makeUuid();

    json membersArray = json::array();
    for (const std::string& key : memberPeerIds) {
        if (trimmed(key) == myId) continue;
        membersArray.push_back(key);
    }

    // G5 fix: monotonic per-group sequence counter
    const int64_t seq = ++m_groupSeqOut[groupId];

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == myId) continue;

        json payload = json::object();
        payload["from"]      = myId;
        payload["type"]      = "group_msg";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["text"]      = text;
        payload["ts"]        = ts;
        payload["msgId"]     = msgId;
        payload["seq"]       = seq;   // G5 fix

        const std::string ptStr = payload.dump();
        const Bytes pt(ptStr.begin(), ptStr.end());
        Bytes env = sealForPeer(peerId, pt);
        if (!env.empty()) {
            P2P_LOG("[SEND MAILBOX] sealed group_msg to " << peerId.substr(0, 8) << "...");
            m_relay.sendEnvelope(env);
        } else {
            P2P_WARN("[SEND] BLOCKED — cannot seal group_msg to " << peerId.substr(0, 8) << "...");
        }
    }
}

void ChatController::sendGroupLeaveNotification(const std::string& groupId,
                                                const std::string& groupName,
                                                const std::vector<std::string>& memberPeerIds)
{
    const std::string myId  = myIdB64u();
    const int64_t     ts    = nowSecs();
    const std::string msgId = p2p::makeUuid();

    // Include member list so receivers can update their local group member list
    json membersArray = json::array();
    for (const std::string& key : memberPeerIds)
        membersArray.push_back(key);

    for (const std::string& peerIdRaw : memberPeerIds) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == myId) continue;

        json payload = json::object();
        payload["from"]      = myId;
        payload["type"]      = "group_leave";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["ts"]        = ts;
        payload["msgId"]     = msgId;  // B2 fix: include msgId for dedup

        const std::string ptStr = payload.dump();
        const Bytes pt(ptStr.begin(), ptStr.end());
        Bytes env = sealForPeer(peerId, pt);
        if (!env.empty()) {
            P2P_LOG("[SEND MAILBOX] sealed group_leave to " << peerId.substr(0, 8) << "...");
            m_relay.sendEnvelope(env);
        } else {
            P2P_WARN("[SEND] BLOCKED — cannot seal group_leave to " << peerId.substr(0, 8) << "...");
        }
    }
}

// ── Private ───────────────────────────────────────────────────────────────────

bool ChatController::markSeen(const std::string& id)
{
    const std::string& idStd = id;
    if (m_seenIds.count(idStd)) return false;
    if (int(m_seenOrder.size()) >= kSeenIdsCap) {
        const int prune = kSeenIdsCap / 2;
        for (int i = 0; i < prune; ++i) m_seenIds.erase(m_seenOrder[i]);
        m_seenOrder.erase(m_seenOrder.begin(), m_seenOrder.begin() + prune);
    }
    m_seenIds.insert(idStd);
    m_seenOrder.push_back(idStd);
    return true;
}

// H5 fix (audit 2026-04-19): persistent envelope-ID dedup.  The in-memory
// LRU is a speed cache; the row in seen_envelopes is the source of truth
// across app restarts.  Only used for the outer envelope-level check; the
// ratchet chain counter still covers replayed session payloads once the
// envelope is past the gate.
bool ChatController::markSeenPersistent(const std::string& id)
{
    // Hot-path: already in memory this session.
    if (m_seenIds.count(id)) return false;

    if (m_dbPtr && m_dbPtr->isOpen()) {
        SqlCipherQuery sel(*m_dbPtr);
        if (sel.prepare("SELECT 1 FROM seen_envelopes WHERE id = :id;")) {
            sel.bindValue(":id", id);
            if (sel.exec() && sel.next()) {
                // Known from a previous process — cache it so the next
                // replay in this session hits the fast path.
                m_seenIds.insert(id);
                return false;
            }
        }

        SqlCipherQuery ins(*m_dbPtr);
        if (ins.prepare(
                "INSERT OR IGNORE INTO seen_envelopes(id, first_seen)"
                " VALUES(:id, :ts);")) {
            ins.bindValue(":id", id);
            ins.bindValue(":ts", static_cast<int64_t>(nowSecs()));
            ins.exec();
        }
    }

    // Add to the bounded in-memory LRU so later lookups this session stay cheap.
    if (int(m_seenOrder.size()) >= kSeenIdsCap) {
        const int prune = kSeenIdsCap / 2;
        for (int i = 0; i < prune; ++i) m_seenIds.erase(m_seenOrder[i]);
        m_seenOrder.erase(m_seenOrder.begin(), m_seenOrder.begin() + prune);
    }
    m_seenIds.insert(id);
    m_seenOrder.push_back(id);
    return true;
}

void ChatController::ensureSeenEnvelopesTable()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.exec(
        "CREATE TABLE IF NOT EXISTS seen_envelopes ("
        "  id         TEXT PRIMARY KEY,"
        "  first_seen INTEGER NOT NULL"
        ");"
    );
    q.exec(
        "CREATE INDEX IF NOT EXISTS idx_seen_envelopes_first_seen"
        " ON seen_envelopes(first_seen);"
    );
}

void ChatController::pruneSeenEnvelopes()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    const int64_t cutoff = nowSecs() - kSeenEnvelopesMaxAgeSecs;
    SqlCipherQuery q(*m_dbPtr);
    if (q.prepare("DELETE FROM seen_envelopes WHERE first_seen < :cutoff;")) {
        q.bindValue(":cutoff", cutoff);
        q.exec();
    }
}

// pollOnce removed — relay pushes envelopes via WebSocket.
// Maintenance tasks (handshake pruning, file key cleanup) moved to m_maintenanceTimer.

// ── Core sealing primitive ────────────────────────────────────────────────────
// Returns the sealed envelope bytes (SEALED:<version>\n<ciphertext>), or empty
// on failure.  Every outbound path should call this instead of inlining the
// encrypt→convert→seal→prefix logic.
Bytes ChatController::sealForPeer(const std::string& peerIdB64u,
                                  const Bytes& plaintext)
{
    if (!m_sessionMgr) return {};

    // Safety-numbers enforcement — applies to every user-initiated
    // outbound send because sealForPeer is the single choke point for
    // sendText / sendAvatar / sendGroupMessageViaMailbox / sendFile /
    // sendGroupFile / group control messages.  (The Noise handshake
    // response path bypasses sealForPeer and builds its envelope
    // directly via SessionManager's sendResponseFn callback, so
    // infrastructure traffic is never gated.)
    //
    // detectKeyChange fires onPeerKeyChanged once per session per peer.
    // When the hard-block toggle is on, a Mismatch returns empty here
    // and the caller sees "seal failed" → surfaces as a status message.
    if (detectKeyChange(peerIdB64u) && m_hardBlockOnKeyChange) {
        P2P_WARN("[SEND] BLOCKED — peer's safety number changed for "
                 << peerIdB64u.substr(0, 8) << "... (hard-block on)");
        return {};
    }

    // Pass peer's KEM pub so SessionManager can do hybrid Noise handshake if available
    Bytes peerKemPub = lookupPeerKemPub(peerIdB64u);
    Bytes sessionBlob = m_sessionMgr->encryptForPeer(peerIdB64u, plaintext, peerKemPub);
    if (sessionBlob.empty()) return {};

    Bytes peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
        return {};

    Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
    sodium_memzero(peerCurvePub, sizeof(peerCurvePub));  // G11 fix

    // Use hybrid seal if we know the peer's ML-KEM-768 public key (already looked up above)
    // Include ML-DSA-65 signature if we have DSA keys.
    Bytes sealed = SealedEnvelope::seal(
        recipientCurvePub, peerEdPub,
        m_crypto.identityPub(), m_crypto.identityPriv(),
        sessionBlob, peerKemPub,
        m_crypto.dsaPub(), m_crypto.dsaPriv());
    if (sealed.empty()) return {};

    // Inner wire: kSealedPrefix + "\n" + sealed
    Bytes inner;
    const size_t prefixLen = std::strlen(kSealedPrefix);
    inner.reserve(prefixLen + 1 + sealed.size());
    inner.insert(inner.end(),
                 reinterpret_cast<const uint8_t*>(kSealedPrefix),
                 reinterpret_cast<const uint8_t*>(kSealedPrefix) + prefixLen);
    inner.push_back('\n');
    inner.insert(inner.end(), sealed.begin(), sealed.end());

    // Wrap with relay routing header so /v1/send can route anonymously
    return SealedEnvelope::wrapForRelay(peerEdPub, inner);
}

// ── S3/S7/S8 fix: Sealed payload via mailbox, fail-closed ───────────────────
void ChatController::sendSealedPayload(const std::string& peerIdB64u,
                                       const nlohmann::json& payload)
{
    const std::string ptStr = payload.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    const std::string type = payload.value("type", std::string());

    Bytes env = sealForPeer(peerIdB64u, pt);
    if (!env.empty()) {
        P2P_LOG("[SEND MAILBOX] " << type << " to " << peerIdB64u.substr(0, 8) << "...");
        m_relay.sendEnvelope(env);
        return;
    }

    // Fail closed.  The old ICE-signaling fallback used the legacy
    // /mbox/enqueue endpoint with a plain-text ICE message wrapped only by
    // an AEAD keyed on a static DH secret — that endpoint is being removed
    // and the plaintext leak was always a privacy concern.  ICE messages
    // now go through the same sealed path as everything else; if the ratchet
    // can't seal, we defer the handshake instead of leaking SDP/IP candidates.
    P2P_WARN("[SEND] BLOCKED — cannot seal " << type
               << " to " << peerIdB64u.substr(0, 8) << "...");
}

#ifdef PEER2PEAR_P2P
// ── QUIC + ICE connection setup ──────────────────────────────────────────────
QuicConnection* ChatController::setupP2PConnection(const std::string& peerIdB64u, bool controlling)
{
    // QuicConnection is a plain class now (Phase 7d) — no Qt parent, no
    // signal/slot.  Lifetime is managed by m_p2pConnections raw pointer
    // ownership; runMaintenance() deletes stale entries.
    QuicConnection* conn = new QuicConnection(*m_timerFactory);
    if (!m_turnHost.empty())
        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
    m_p2pConnections[peerIdB64u] = conn;
    m_p2pCreatedSecs[peerIdB64u] = nowSecs();

    const std::string iceType = controlling ? "ice_offer" : "ice_answer";

    // Callbacks fire on the GLib worker thread (ICE) or msquic worker
    // (QUIC).  ChatController's downstream callbacks are thread-tolerant.
    conn->onLocalSdpReady = [this, peerIdB64u, iceType, conn](const std::string& sdp) {
        json p = json::object();
        p["type"] = iceType;
        p["from"] = myIdB64u();
        p["sdp"]  = sdp;
        p["quic"] = true;
        p["quic_fingerprint"] = conn->localQuicFingerprint();
        sendSealedPayload(peerIdB64u, p);
    };
    conn->onStateChanged = [this, peerIdB64u, conn](int state) {
        if (state == NICE_COMPONENT_STATE_READY) {
            const std::string mode = conn->quicActive() ? "QUIC" : "ICE";
            if (onStatus) onStatus("P2P ready (" + mode + ") with " + peerIdB64u);
            m_fileMgr.notifyP2PReady(peerIdB64u);
        } else if (state == NICE_COMPONENT_STATE_FAILED) {
            if (onStatus) onStatus("P2P failed for " + peerIdB64u);
        }
    };
    conn->onDataReceived = [this, peerIdB64u](const Bytes& d) {
        onP2PDataReceived(peerIdB64u, d);
    };
    conn->onFileDataReceived = [this, peerIdB64u](const Bytes& d) {
        m_fileMgr.handleFileEnvelope(peerIdB64u, d,
            [this](const std::string& id) { return markSeen(id); },
            m_fileKeys);
    };
    conn->initIce(controlling);
    return conn;
}

void ChatController::initiateP2PConnection(const std::string& peerIdB64u)
{
    if (m_p2pConnections.count(peerIdB64u)) return;
    setupP2PConnection(peerIdB64u, true);
}

void ChatController::onP2PDataReceived(const std::string& peerIdB64u, const Bytes& data)
{
    P2P_LOG("[ChatController] P2P data received from " << peerIdB64u.substr(0, 8) << "..."
             << " | size: " << data.size() << "B");

    // P2P data proves the peer is online right now
    if (onPresenceChanged) onPresenceChanged(peerIdB64u, true);

    // ── Sealed envelope over P2P ─────────────────────────────────────────────
    // Only sealed envelopes are accepted on the P2P transport.  The historical
    // static-ECDH fallback (H1 in the 2026-04 audit) was removed — it had no
    // forward secrecy and let a compromised identity key retroactively decrypt
    // every prior P2P text message.  Unsealed P2P frames are now dropped.
    if (bytesStartsWith(data, kSealedPrefix) || bytesStartsWith(data, kSealedFCPrefix)) {
        P2P_LOG("[RECV P2P] sealed envelope from " << peerIdB64u.substr(0, 8) << "...");
        onEnvelope(data);
        return;
    }

    P2P_WARN("[RECV P2P] dropping unsealed frame from " << peerIdB64u.substr(0, 8)
             << " (" << data.size() << "B) \u2014 sealed envelopes required (H1 fix)");
}
#endif // PEER2PEAR_P2P

void ChatController::onEnvelope(const Bytes& body)
{
    // Envelopes arrive via WebSocket push — no ACK needed, the relay
    // deletes stored envelopes on delivery.
    const std::string via = "RELAY";

    // Strip relay routing header if present (0x01 || recipientEdPub(32) || inner)
    Bytes data = body;
    if (!body.empty() && body[0] == 0x01 && body.size() > 33) {
        Bytes inner = SealedEnvelope::unwrapFromRelay(body);
        if (!inner.empty()) data = std::move(inner);
    }

    // Locate the newline delimiter separating header from the rest.
    auto nlIt = std::find(data.begin(), data.end(), uint8_t('\n'));
    if (nlIt == data.end()) return;
    const Bytes header(data.begin(), nlIt);
    const Bytes rest(nlIt + 1, data.end());

    // ── Sealed sender envelope ───────────────────────────────────────────────
    if (bytesStartsWith(header, kSealedPrefix) || bytesStartsWith(header, kSealedFCPrefix)) {
        const bool isFileChunk = bytesStartsWith(header, kSealedFCPrefix);

        P2P_LOG("[RECV " << via << "] sealed envelope | size: " << rest.size() << "B"
                 << (isFileChunk ? " (file chunk)" : ""));

        // Unseal to learn sender identity (pass KEM priv for hybrid PQ envelopes).
        // Binding recipientEdPub (our own identity) into AEAD AAD — if a relay
        // rewrote the outer routing pubkey, AEAD fails.
        UnsealResult unsealed = SealedEnvelope::unseal(
            m_crypto.curvePriv(), m_crypto.identityPub(),
            rest, m_crypto.kemPriv());
        if (!unsealed.valid) {
            P2P_WARN("[ChatController] Failed to unseal envelope");
            return;
        }

        const Bytes& unsealedSenderEdPub  = unsealed.senderEdPub;
        const Bytes& unsealedInnerPayload = unsealed.innerPayload;
        const Bytes& unsealedEnvelopeId   = unsealed.envelopeId;

        // Envelope-level replay protection (Fix #2): dedup on envelopeId.
        // The ratchet dedups its own chain messages, but control messages
        // outside the ratchet (file_accept, file_cancel, etc.) don't have that
        // protection. A malicious relay could redeliver the same sealed blob
        // and the receiver would happily reprocess it.
        if (unsealedEnvelopeId.size() == 16) {
            const std::string envKey = "env:" + CryptoEngine::toBase64Url(unsealedEnvelopeId);
            // H5 fix: persistent dedup so a relay-level replay after app
            // restart still gets dropped.
            if (!markSeenPersistent(envKey)) {
                P2P_LOG("[RECV " << via << "] dropping replayed envelope "
                         << envKey.substr(4, 8) << "...");
                return;
            }
        }

        std::string senderId = CryptoEngine::toBase64Url(unsealedSenderEdPub);
        P2P_LOG("[RECV " << via << "] unsealed OK | sender: " << senderId.substr(0, 8) << "..."
                 << " | inner: " << unsealedInnerPayload.size() << "B");

        // H3 fix: rate limit per sender to prevent CPU exhaustion via envelope flooding
        int& count = m_envelopeCount[senderId];
        if (++count > kMaxEnvelopesPerSenderPerPoll) {
            if (count == kMaxEnvelopesPerSenderPerPoll + 1)
                P2P_WARN("[RECV] rate limit hit for " << senderId.substr(0, 8) << "..."
                           << " — dropping further envelopes this cycle");
            return;
        }

        // M2 fix: Sealed file chunk — pass directly to FileTransferManager.
        // The inner payload is already encrypted with the ratchet-derived file key;
        // no session decrypt is needed (the sealed envelope just hides the sender).
        if (isFileChunk) {
            // M7 fix: verify we have at least one file_key from this sender
            // before allowing trial decryption. This prevents an attacker who can
            // craft valid sealed envelopes from causing unnecessary crypto work.
            bool hasKeyFromSender = false;
            const std::string senderPrefix = senderId + ":";
            for (const auto& kv : m_fileKeys) {
                if (kv.first.size() >= senderPrefix.size() &&
                    kv.first.compare(0, senderPrefix.size(), senderPrefix) == 0) {
                    hasKeyFromSender = true;
                    break;
                }
            }
            if (!hasKeyFromSender) {
                P2P_WARN("[RECV " << via << "] sealed file chunk from " << senderId.substr(0, 8) << "..."
                           << " — no file_key on record, dropping");
                return;
            }

            P2P_LOG("[RECV " << via << "] sealed file chunk from " << senderId.substr(0, 8) << "...");
            m_fileMgr.handleFileEnvelope(senderId, unsealedInnerPayload,
                [this](const std::string& id) { return markSeen(id); },
                m_fileKeys);
            return;
        }

        if (!m_sessionMgr) return; // can't process without session manager

        // Only emit "online" if the envelope is recent (within 2 minutes).
        // Old mailbox messages should not trigger false online presence.  (L3 fix)
        // Note: sealed envelopes carry no timestamp, so we infer freshness from
        // the transport — P2P is always live; mailbox may have stale messages.
        if (via == "P2P") if (onPresenceChanged) onPresenceChanged(senderId, true);

        // Decrypt session layer (Noise handshake or ratchet message)
        Bytes msgKey;  // M3 fix: capture message key directly from decrypt
        Bytes pt = m_sessionMgr->decryptFromPeer(senderId, unsealedInnerPayload, &msgKey);
        if (pt.empty()) {
            // Pre-key response (0x02) completes the Noise IK handshake and creates
            // a ratchet session inside decryptFromPeer(), but returns no user payload.
            // This is expected — future messages will use the ratchet session.
            const uint8_t innerType = unsealedInnerPayload.empty() ? 0 : unsealedInnerPayload[0];
            if (innerType == SessionManager::kPreKeyResponse || innerType == SessionManager::kHybridPreKeyResp) {
                P2P_LOG("[RECV " << via << "] handshake COMPLETED with " << senderId.substr(0, 8) << "...");
                // SEC9: handshake succeeded — clear failure counter
                m_handshakeFailCount.erase(senderId);

                // Announce our PQ KEM pub now that we have an authenticated channel
                announceKemPub(senderId);

            } else {
                P2P_LOG("[RECV " << via << "] session decrypt empty from " << senderId.substr(0, 8) << "...");
            }
            return;
        }

        // Dispatch based on the decrypted JSON payload
        // (same logic as legacy message handling below)
        const json o = json::parse(pt.begin(), pt.end(),
                                   /*cb=*/nullptr, /*allow_exceptions=*/false);
        if (!o.is_object()) return;
        const std::string type = o.value("type", std::string());

        const int64_t tsSecs = o.value("ts", int64_t(0));
        const std::string msgId = o.value("msgId", std::string());

        P2P_LOG("[RECV " << via << "] sealed type: " << type << " from " << senderId.substr(0, 8) << "...");

        // Safety-numbers check on inbound.  Fires onPeerKeyChanged at
        // most once per session; the hard-block toggle then refuses to
        // deliver to the app callbacks.  Only applies to previously-
        // verified peers — first-contact / unverified messages flow
        // through as before.
        if (detectKeyChange(senderId) && m_hardBlockOnKeyChange) {
            P2P_WARN("[RECV] dropping message from " << senderId.substr(0, 8)
                     << "... — hard-block on key change");
            return;
        }

        if (type == "text") {
            if (!msgId.empty() && !markSeen(msgId)) return;
            if (onMessageReceived) onMessageReceived(senderId,
                                 o.value("text", std::string()), tsSecs, msgId);
        } else if (type == "group_msg") {
            if (!msgId.empty() && !markSeen(msgId)) return;

            // G5 fix: sequence gap detection + L3 audit-#2 fix: reject
            // regressions.  Before L3, seq <= last_seen was silently
            // accepted — a relay that captured an old group_msg could
            // replay it after the msgId LRU evicted the original, and
            // the receiver would fire onGroupMessageReceived again.
            // Now any non-monotonic seq from a given (group, sender)
            // is dropped loudly.
            const std::string gid = o.value("groupId", std::string());
            if (o.contains("seq")) {
                const int64_t seq = o.value("seq", int64_t(0));
                const std::string seqKey = gid + ":" + senderId;
                auto sit = m_groupSeqIn.find(seqKey);
                if (sit != m_groupSeqIn.end()) {
                    const int64_t lastSeen = sit->second;
                    if (seq <= lastSeen) {
                        P2P_WARN("[GROUP] dropping non-monotonic seq from "
                                 << senderId.substr(0, 8) << "... in "
                                 << gid.substr(0, 8) << "... (got " << seq
                                 << ", last " << lastSeen << ") — L3 replay guard");
                        return;
                    }
                    const int64_t expected = lastSeen + 1;
                    if (seq > expected) {
                        P2P_WARN("[GROUP] seq gap from " << senderId.substr(0, 8) << "..."
                                   << " in " << gid.substr(0, 8) << "..."
                                   << " expected " << expected << " got " << seq);
                    }
                }
                m_groupSeqIn[seqKey] = seq;
            }

            std::vector<std::string> memberKeys;
            if (o.contains("members") && o["members"].is_array())
                for (const auto& v : o["members"])
                    if (v.is_string()) memberKeys.push_back(v.get<std::string>());

            // Fix #20: a valid sealed group_msg from X about group G adds X
            // (and the declared members) to our roster — this is ground
            // truth because the message is already authenticated.  We still
            // require sender ∈ members to avoid rogue "I'm messaging this
            // group but I'm not in it" bootstraps.
            //
            // H5 audit-#2 KNOWN LIMITATION: first-mover attack.  An
            // attacker who learns a groupId (e.g. by observing a shared
            // invite link) can race a legit sender by sending a
            // group_msg with themselves in the roster *before* the
            // legitimate creator's first message lands.  We accept the
            // first plausible roster and subsequent messages layer on
            // top.  The proper fix is a creator-signed genesis message
            // + signed invite chain (Sender Keys / MLS style — listed
            // under §11 Future extensions in PROTOCOL.md).  Mitigation
            // in the meantime: the UI should call setKnownGroupMembers()
            // on startup from its own persisted roster, which beats the
            // bootstrap path (isAuthorizedGroupSender checks that set).
            if (!gid.empty() && !senderId.empty()) {
                auto gmit = m_groupMembers.find(gid);
                if (gmit == m_groupMembers.end()) {
                    // Bootstrap: accept only if sender includes themselves.
                    const bool senderInList = std::find(memberKeys.begin(), memberKeys.end(), senderId) != memberKeys.end();
                    if (senderInList) {
                        m_groupMembers[gid] = std::set<std::string>(memberKeys.begin(), memberKeys.end());
                    }
                } else {
                    gmit->second.insert(senderId);
                }
            }

            if (onGroupMessageReceived) onGroupMessageReceived(senderId, gid,
                                       o.value("groupName", std::string()),
                                       memberKeys,
                                       o.value("text", std::string()), tsSecs, msgId);
        } else if (type == "group_leave") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // B2 fix: dedup
            const std::string gid = o.value("groupId", std::string());
            // Fix #20: a leave message may ONLY be self-leave — senders can't
            // announce that OTHER members left.  And the sender must have been
            // a known member of the group.
            if (!gid.empty() && !isAuthorizedGroupSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_leave from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            std::vector<std::string> memberKeys;
            if (o.contains("members") && o["members"].is_array())
                for (const auto& v : o["members"])
                    if (v.is_string()) memberKeys.push_back(v.get<std::string>());
            // The sender left — strike them from our roster so they can't push
            // further member-update / rename / avatar messages afterwards.
            auto gmIt = m_groupMembers.find(gid);
            if (gmIt != m_groupMembers.end())
                gmIt->second.erase(senderId);
            if (onGroupMemberLeft) onGroupMemberLeft(senderId, gid,
                                  o.value("groupName", std::string()),
                                  memberKeys, tsSecs, msgId);
        } else if (type == "avatar") {
            if (onAvatarReceived) onAvatarReceived(senderId,
                                 o.value("name", std::string()),
                                 o.value("avatar", std::string()));
        } else if (type == "group_rename") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const std::string gid = o.value("groupId", std::string());
            if (!gid.empty() && !isAuthorizedGroupSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_rename from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            if (onGroupRenamed) onGroupRenamed(gid, o.value("newName", std::string()));
        } else if (type == "group_avatar") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const std::string gid = o.value("groupId", std::string());
            if (!gid.empty() && !isAuthorizedGroupSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_avatar from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            if (onGroupAvatarReceived) onGroupAvatarReceived(gid, o.value("avatar", std::string()));
        } else if (type == "group_member_update") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // B3 fix: dedup
            const std::string gid   = o.value("groupId", std::string());
            const std::string gname = o.value("groupName", std::string());
            // Fix #20: reject member-list updates from peers that aren't
            // currently in our roster.  First-sight of a new group bootstraps
            // from the sender's proposed list only if the sender names
            // themselves as a member.
            std::vector<std::string> memberKeys;
            if (o.contains("members") && o["members"].is_array())
                for (const auto& v : o["members"])
                    if (v.is_string()) memberKeys.push_back(v.get<std::string>());

            if (!gid.empty()) {
                // LC5 cleanup (2026-04-19): m_groupBootstrapNeeded was never
                // populated anywhere in the code — the check was equivalent
                // to "is the group unknown".  Simplified accordingly.
                const bool bootstrap = !m_groupMembers.count(gid);
                if (bootstrap) {
                    // Sender must include themselves in the proposed list.
                    const bool senderInList = std::find(memberKeys.begin(), memberKeys.end(), senderId) != memberKeys.end();
                    if (!senderInList) {
                        P2P_WARN("[GROUP] rejecting bootstrap group_member_update"
                                   << " from " << senderId.substr(0, 8) << "..."
                                   << " \u2014 sender not in proposed member list");
                        return;
                    }
                    m_groupMembers[gid] = std::set<std::string>(memberKeys.begin(), memberKeys.end());
                } else if (!m_groupMembers[gid].count(senderId)) {
                    P2P_WARN("[GROUP] dropping group_member_update from non-member "
                               << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                    return;
                } else {
                    // Authorized update: merge in new members (conservative —
                    // we don't accept REMOVALS via this message type, only adds).
                    for (const std::string& m : memberKeys)
                        m_groupMembers[gid].insert(m);
                }
            }

            // Re-use the existing groupMessageReceived signal — the
            // ChatView::onIncomingGroupMessage handler already merges new
            // member keys into the group's key list.
            // Empty text means no chat bubble appears, but the key merge still happens.
            if (onGroupMessageReceived) onGroupMessageReceived(senderId, gid, gname, memberKeys,
                                      std::string(), tsSecs,
                                      msgId.empty() ? p2p::makeUuid() : msgId);
#ifdef PEER2PEAR_P2P
        } else if (type == "ice_offer") {
            P2P_LOG("[RECV " << via << "] ice_offer from " << senderId.substr(0, 8) << "...");
            // Skip if we already have a working P2P connection
            auto connIt = m_p2pConnections.find(senderId);
            if (connIt != m_p2pConnections.end() && connIt->second->isReady()) {
                P2P_LOG("[ICE] Already connected to " << senderId.substr(0, 8) << "... — ignoring ice_offer");
            } else {
                if (connIt == m_p2pConnections.end()) {
                    setupP2PConnection(senderId, false);
                    connIt = m_p2pConnections.find(senderId);
                }
                if (connIt != m_p2pConnections.end()) {
                    // Pass QUIC capability from signaling
                    if (o.value("quic", false)) {
                        connIt->second->setPeerSupportsQuic(
                            true, o.value("quic_fingerprint", std::string()));
                    }
                    connIt->second->setRemoteSdp(
                        o.value("sdp", std::string()));
                }
            }
        } else if (type == "ice_answer") {
            P2P_LOG("[RECV " << via << "] ice_answer from " << senderId.substr(0, 8) << "...");
            auto connIt = m_p2pConnections.find(senderId);
            if (connIt != m_p2pConnections.end() && !connIt->second->isReady()) {
                if (o.value("quic", false)) {
                    connIt->second->setPeerSupportsQuic(
                        true, o.value("quic_fingerprint", std::string()));
                }
                connIt->second->setRemoteSdp(
                    o.value("sdp", std::string()));
            }
#endif // PEER2PEAR_P2P
        } else if (type == "file_key") {
            // File key announcement. Phase 2: evaluate consent policy BEFORE
            // installing the key. Chunks that arrive before the user accepts
            // will fail to find a matching key and be dropped silently.
            const std::string transferId = o.value("transferId", std::string());
            const std::string fileName   = o.value("fileName", std::string("file"));
            const int64_t     fileSize   = o.value("fileSize", int64_t(0));
            const std::string gId        = o.value("groupId", std::string());
            const std::string gName      = o.value("groupName", std::string());

            if (transferId.empty() || msgKey.size() != 32) {
                sodium_memzero(msgKey.data(), msgKey.size());
                return;
            }

            const std::string compoundKey = senderId + ":" + transferId;

            // Evaluate global size policy.  Fix #6: the same thresholds apply
            // whether the file is 1:1 or group-scoped — previously group files
            // auto-accepted regardless, which let any group member push up to
            // the hard-max bytes to disk without the user's consent.
            // (Per-contact policy will be layered on top in a follow-up.)
            const int64_t fileSizeMB = fileSize / (1024 * 1024);
            bool autoAccept = false;
            bool autoDecline = false;
            if (fileSize > int64_t(m_fileHardMaxMB) * 1024 * 1024) {
                autoDecline = true;
            } else if (fileSize <= int64_t(m_fileAutoAcceptMaxMB) * 1024 * 1024) {
                autoAccept = true;
            }

            if (autoDecline) {
                P2P_LOG("[FILE] auto-decline " << fileName << " (" << fileSizeMB << "MB)"
                         << " from " << senderId.substr(0, 8) << "... — exceeds hard max");
                json declineMsg = json::object();
                declineMsg["type"]       = "file_decline";
                declineMsg["transferId"] = transferId;
                sendFileControlMessage(senderId, declineMsg);
                sodium_memzero(msgKey.data(), msgKey.size());
            } else if (autoAccept) {
                // Fix #3: announce the transfer to FileTransferManager FIRST so
                // it locks the announced fileSize/totalChunks/fileHash. Chunks
                // with mismatched metadata will be dropped.
                const Bytes announcedHash = CryptoEngine::fromBase64Url(o.value("fileHash", std::string()));
                const int announcedChunkCount = o.value("chunkCount", 0);
                const int64_t announcedTs     = o.value("ts", int64_t(0));

                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    P2P_WARN("[FILE] missing fileHash/chunkCount on file_key for "
                               << transferId.substr(0, 8) << " — dropping");
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                if (!m_fileMgr.announceIncoming(senderId, transferId, fileName,
                                                  fileSize, announcedChunkCount,
                                                  announcedHash, msgKey,
                                                  announcedTs, gId, gName)) {
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                // Install key so chunks can decrypt.
                m_fileKeys[compoundKey] = msgKey;  // M3+M4 fix
                sodium_memzero(msgKey.data(), msgKey.size());

                json acceptMsg = json::object();
                acceptMsg["type"]       = "file_accept";
                acceptMsg["transferId"] = transferId;
                if (m_fileRequireP2P) acceptMsg["requireP2P"] = true;
                sendFileControlMessage(senderId, acceptMsg);

                P2P_LOG("[FILE] auto-accept " << fileName << " (" << fileSizeMB << "MB)"
                         << " from " << senderId.substr(0, 8) << "...");
            } else {
                // Stash in pending — don't install key yet. User will accept/decline.
                // Fix #3: lock announced hash/chunkCount/ts now so acceptFileTransfer
                // can pass them to announceIncoming() unchanged.
                const Bytes announcedHash = CryptoEngine::fromBase64Url(o.value("fileHash", std::string()));
                const int announcedChunkCount = o.value("chunkCount", 0);
                const int64_t announcedTs     = o.value("ts", int64_t(0));
                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    P2P_WARN("[FILE] missing fileHash/chunkCount on file_key for "
                               << transferId.substr(0, 8) << " — dropping");
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                // H4 audit-#2 fix: cap the pending-incoming queue so a
                // flood of file_key messages in the prompt-size range
                // can't exhaust memory.  Drops the oldest entry (and
                // zeroes its stashed file key) when the cap is hit; in
                // practice the user's UI surface is already overloaded
                // long before this bound.
                if (m_pendingIncomingFiles.size() >= kMaxPendingIncomingFiles) {
                    auto oldest = m_pendingIncomingFiles.begin();
                    for (auto it = m_pendingIncomingFiles.begin();
                         it != m_pendingIncomingFiles.end(); ++it) {
                        if (it->second.announcedSecs < oldest->second.announcedSecs)
                            oldest = it;
                    }
                    sodium_memzero(oldest->second.fileKey.data(),
                                   oldest->second.fileKey.size());
                    P2P_WARN("[FILE] pending-incoming cap hit — evicting "
                             << oldest->first.substr(0, 8) << "... to make room");
                    m_pendingIncomingFiles.erase(oldest);
                }

                PendingIncoming p;
                p.peerId         = senderId;
                p.fileName       = fileName;
                p.fileSize       = fileSize;
                p.fileKey        = msgKey;
                p.fileHash       = announcedHash;
                p.totalChunks    = announcedChunkCount;
                p.announcedTs    = announcedTs;
                p.groupId        = gId;
                p.groupName      = gName;
                p.announcedSecs  = nowSecs();
                m_pendingIncomingFiles[transferId] = std::move(p);
                sodium_memzero(msgKey.data(), msgKey.size());

                P2P_LOG("[FILE] prompt needed for " << fileName << " (" << fileSizeMB << "MB)"
                         << " from " << senderId.substr(0, 8) << "...");
                if (onFileAcceptRequested) onFileAcceptRequested(senderId, transferId, fileName, fileSize);
            }

        } else if (type == "file_accept") {
            // Sender-side: receiver agreed to the transfer.
            const std::string transferId = o.value("transferId", std::string());
            const bool requireP2P        = o.value("requireP2P", false);
            if (!transferId.empty()) {
                // Sender's side of the "no relay" preference (global toggle).
                // Desktop surfaces this via the "Require direct connection"
                // setting too — not privacy-level yet; that can come later.
                const bool senderRequiresP2P = m_fileRequireP2P;

                // Is P2P ready for this peer right now?
                bool p2pReady = false;
#ifdef PEER2PEAR_P2P
                {
                    auto it = m_p2pConnections.find(senderId);
                    if (it != m_p2pConnections.end() && it->second->isReady())
                        p2pReady = true;
                }
#endif

                if (!m_fileMgr.startOutboundStream(transferId, requireP2P,
                                                    senderRequiresP2P, p2pReady)) {
                    P2P_WARN("[FILE] file_accept for unknown transferId "
                               << transferId.substr(0, 8));
                    return;
                }

#ifdef PEER2PEAR_P2P
                // If P2P isn't up yet and the file was large, kick off ICE so
                // the WaitingForP2P state has something to wait for.
                if (!p2pReady) initiateP2PConnection(senderId);
#endif
            }

        } else if (type == "file_decline") {
            // Sender-side: receiver refused. Drop outbound state, notify UI.
            const std::string transferId = o.value("transferId", std::string());
            if (!transferId.empty()) {
                m_fileMgr.abandonOutboundTransfer(transferId);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, true); // byReceiver
                if (onStatus) onStatus("File transfer declined by recipient.");
            }

        } else if (type == "file_ack") {
            // Sender-side: receiver confirmed delivery + hash ok.
            const std::string transferId = o.value("transferId", std::string());
            if (!transferId.empty()) {
                if (onFileTransferDelivered) onFileTransferDelivered(transferId);
                // Phase 4: drop sender-side state now that the transfer is acked.
                m_fileMgr.forgetSentTransfer(transferId);
            }

        } else if (type == "file_request") {
            // Receiver is asking us (sender) to re-send these chunk indices.
            // Phase 4 resumption path.
            const std::string transferId = o.value("transferId", std::string());
            const bool hasChunks = o.contains("chunks") && o["chunks"].is_array();
            if (transferId.empty() || !hasChunks || o["chunks"].empty()) return;

            // H3 audit-#2 fix: cap chunk-index arrays + rate-limit per
            // peer.  Before the cap, a malicious peer could request
            // thousands of chunks in a single message and force N disk
            // reads + AEAD encryptions.  Both bounds are conservative
            // ceilings — a legitimate resumption after a 100 MB transfer
            // is ≤ 416 chunks (100 MiB / 240 KiB), and legitimate clients
            // send file_request at most a few times per session.
            const size_t kMaxChunksPerRequest = 1024;
            if (o["chunks"].size() > kMaxChunksPerRequest) {
                P2P_WARN("[FILE] file_request from " << senderId.substr(0, 8) << "..."
                           << " has " << int(o["chunks"].size())
                           << " indices (cap " << int(kMaxChunksPerRequest) << ") — dropping");
                return;
            }
            constexpr int kMaxFileRequestsPerPoll = 4;
            int& rcount = m_fileRequestCount[senderId];
            if (++rcount > kMaxFileRequestsPerPoll) {
                if (rcount == kMaxFileRequestsPerPoll + 1) {
                    P2P_WARN("[FILE] file_request rate limit hit for "
                             << senderId.substr(0, 8) << "... — dropping further"
                             << " requests this cycle");
                }
                return;
            }

            std::vector<uint32_t> indices;
            indices.reserve(o["chunks"].size());
            for (const auto& v : o["chunks"]) {
                if (v.is_number_integer()) {
                    const int i = v.get<int>();
                    if (i >= 0) indices.push_back(uint32_t(i));
                }
            }
            if (!m_fileMgr.resendChunks(transferId, indices)) {
                P2P_WARN("[FILE] file_request for unknown transferId "
                           << transferId.substr(0, 8) << "...");
            }

        } else if (type == "file_cancel") {
            // Either side: the peer canceled. Figure out which role we're in.
            const std::string transferId = o.value("transferId", std::string());
            if (transferId.empty()) return;

            // Outbound (we're the sender)?
            if (!m_fileMgr.outboundPeerFor(transferId).empty()) {
                m_fileMgr.abandonOutboundTransfer(transferId);
                // Phase 4: also drop the sent-transfer DB row in case we were mid-stream.
                m_fileMgr.forgetSentTransfer(transferId);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, true); // canceled by receiver
                return;
            }
            // Also handle "sender was already streaming when receiver canceled":
            // m_outboundPending is empty, but m_sentTransfers has the record.
            m_fileMgr.forgetSentTransfer(transferId);

            // Inbound pending (we were about to prompt)?
            auto itPending = m_pendingIncomingFiles.find(transferId);
            if (itPending != m_pendingIncomingFiles.end()) {
                sodium_memzero(itPending->second.fileKey.data(), itPending->second.fileKey.size());
                m_pendingIncomingFiles.erase(itPending);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, false); // sender canceled
                return;
            }
            // Inbound in-progress (sender pulled the plug mid-stream)?
            if (!m_fileMgr.inboundPeerFor(transferId).empty()) {
                m_fileMgr.cancelInboundTransfer(transferId);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);
            }

        } else if (type == "kem_pub_announce") {
            // Post-quantum KEM public key exchange — store the peer's ML-KEM-768 pub
            Bytes kemPub = CryptoEngine::fromBase64Url(o.value("kem_pub_b64u", std::string()));
            if (kemPub.size() == 1184) {  // ML-KEM-768 pub key size
                m_peerKemPubs[senderId] = kemPub;
                // Persist to DB
                if (m_dbPtr && m_dbPtr->isOpen()) {
                    SqlCipherQuery q(*m_dbPtr);
                    q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:pid;");
                    q.bindValue(":kp",  kemPub);
                    q.bindValue(":pid", senderId);
                    q.exec();
                }
                P2P_LOG("[PQ] Stored ML-KEM-768 pub from " << senderId.substr(0, 8) << "..."
                         << " | hybrid sealing now active for this peer");
                // Reciprocate: send our KEM pub back if we haven't already
                if (m_crypto.hasPQKeys() && !lookupPeerKemPub(senderId).empty()) {
                    // They sent theirs, we have theirs — send ours if they might not have it
                    announceKemPub(senderId);
                }
            } else {
                P2P_WARN("[PQ] Invalid kem_pub_announce from " << senderId.substr(0, 8) << "..."
                           << " | size: " << kemPub.size() << " (expected 1184)");
            }
        } else if (type == "file_chunk") {
            // Sealed file_chunk in JSON payload shouldn't happen — file chunks
            // use SEALEDFC: prefix and are handled above before session decrypt.
            P2P_WARN("[RECV " << via << "] unexpected file_chunk in session payload from "
                       << senderId.substr(0, 8) << "...");
        }
        return;
    }

    // Any frame that isn't a SEALED: / SEALEDFC: envelope is dropped.
    //
    // H1 fix (2026-04-19): the legacy FROM: text path and the legacy FROMFC:
    // file-chunk path used to live here.  FROM: decrypted with a STATIC ECDH
    // key derived from the sender's long-term Ed25519 → Curve25519 pubkey, so
    // every message was retroactively readable by anyone who later stole
    // either party's identity key — no forward secrecy at all.  FROMFC: was
    // less bad (chunks still used the ratchet-derived file key) but it meant
    // file chunks bypassed the sealed-sender layer, leaking the sender's
    // pubkey to the relay in plaintext.  Both paths are now removed; the
    // sealed handler above covers every message type the app emits, and
    // clients that still expect the legacy wire format will be told off by
    // this log and will need to upgrade.
    P2P_WARN("[RECV " << via << "] dropping non-sealed envelope ("
             << header.size() << " header bytes) \u2014 sealed envelopes required (H1 fix)");
}

void ChatController::sendGroupRename(const std::string& groupId,
                                     const std::string& newName,
                                     const std::vector<std::string>& memberKeys)
{
    const std::string msgId = p2p::makeUuid();  // B5 fix
    json payload = json::object();
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_rename";
    payload["groupId"] = groupId;
    payload["newName"] = newName;
    payload["msgId"]   = msgId;                              // B5 fix
    payload["ts"]      = nowSecs();                           // B5 fix
    for (const std::string& key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupAvatar(const std::string& groupId,
                                     const std::string& avatarB64,
                                     const std::vector<std::string>& memberKeys)
{
    const std::string msgId = p2p::makeUuid();  // B5 fix
    json payload = json::object();
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_avatar";
    payload["groupId"] = groupId;
    payload["avatar"]  = avatarB64;
    payload["msgId"]   = msgId;                              // B5 fix
    payload["ts"]      = nowSecs();                          // B5 fix
    for (const std::string& key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupMemberUpdate(const std::string& groupId,
                                           const std::string& groupName,
                                           const std::vector<std::string>& memberKeys)
{
    const std::string myId = myIdB64u();
    const std::string msgId = p2p::makeUuid();  // B5 fix

    // Build the member array (excluding self, matching group_msg format)
    json membersArray = json::array();
    for (const std::string& key : memberKeys) {
        if (trimmed(key) == myId) continue;
        membersArray.push_back(key);
    }

    // Send to ALL members (including newly added ones) so everyone gets
    // the updated member list and new members discover the group.
    for (const std::string& peerIdRaw : memberKeys) {
        const std::string peerId = trimmed(peerIdRaw);
        if (peerId.empty() || peerId == myId) continue;

        json payload = json::object();
        payload["from"]      = myId;
        payload["type"]      = "group_member_update";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["msgId"]     = msgId;                       // B5 fix
        payload["ts"]        = nowSecs();

        sendSealedPayload(peerId, payload);
    }
}

// ── G3: Reset encrypted session ──────────────────────────────────────────────
void ChatController::resetSession(const std::string& peerIdB64u)
{
    if (m_sessionMgr) {
        m_sessionMgr->deleteSession(peerIdB64u);
        P2P_LOG("[SESSION] Reset ratchet session for " << peerIdB64u.substr(0, 8) << "...");
        if (onStatus) onStatus("Session reset — next message will establish a fresh handshake.");
    }
}

// ── Safety numbers / out-of-band key verification ───────────────────────────

void ChatController::ensureVerifiedPeersTable()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.exec(
        "CREATE TABLE IF NOT EXISTS verified_peers ("
        "  peer_id              TEXT PRIMARY KEY,"
        "  verified_at          INTEGER NOT NULL,"
        "  verified_fingerprint BLOB NOT NULL"
        ");"
    );
}

Bytes ChatController::loadVerifiedFingerprint(const std::string& peerIdB64u) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return {};
    SqlCipherQuery q(m_dbPtr->handle());
    if (!q.prepare("SELECT verified_fingerprint FROM verified_peers WHERE peer_id=:pid;"))
        return {};
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

void ChatController::saveVerifiedFingerprint(const std::string& peerIdB64u,
                                              const Bytes& fingerprint)
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    if (!q.prepare(
            "INSERT INTO verified_peers (peer_id, verified_at, verified_fingerprint)"
            " VALUES (:pid, :at, :fp)"
            " ON CONFLICT(peer_id) DO UPDATE SET"
            "   verified_at=excluded.verified_at,"
            "   verified_fingerprint=excluded.verified_fingerprint;"))
        return;
    q.bindValue(":pid", peerIdB64u);
    q.bindValue(":at",  nowSecs());
    q.bindValue(":fp",  fingerprint);
    q.exec();
}

void ChatController::deleteVerifiedPeer(const std::string& peerIdB64u)
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    if (!q.prepare("DELETE FROM verified_peers WHERE peer_id=:pid;"))
        return;
    q.bindValue(":pid", peerIdB64u);
    q.exec();
}

std::string ChatController::safetyNumber(const std::string& peerIdB64u) const
{
    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() != 32) return {};
    return CryptoEngine::safetyNumber(m_crypto.identityPub(), peerEd);
}

ChatController::PeerTrust ChatController::peerTrust(const std::string& peerIdB64u) const
{
    const Bytes stored = loadVerifiedFingerprint(peerIdB64u);
    if (stored.size() != 32) return PeerTrust::Unverified;

    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() != 32) return PeerTrust::Unverified;

    const Bytes current =
        CryptoEngine::safetyFingerprint(m_crypto.identityPub(), peerEd);
    return (current == stored) ? PeerTrust::Verified : PeerTrust::Mismatch;
}

bool ChatController::markPeerVerified(const std::string& peerIdB64u)
{
    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() != 32) return false;
    const Bytes fp =
        CryptoEngine::safetyFingerprint(m_crypto.identityPub(), peerEd);
    if (fp.size() != 32) return false;
    saveVerifiedFingerprint(peerIdB64u, fp);
    // A fresh mark clears the once-per-session warning so if the user
    // re-verifies and we later detect ANOTHER change they'll see it.
    m_keyChangeWarned.erase(peerIdB64u);
    return true;
}

void ChatController::unverifyPeer(const std::string& peerIdB64u)
{
    deleteVerifiedPeer(peerIdB64u);
    m_keyChangeWarned.erase(peerIdB64u);
}

bool ChatController::detectKeyChange(const std::string& peerIdB64u)
{
    const Bytes stored = loadVerifiedFingerprint(peerIdB64u);
    if (stored.size() != 32) return false;  // Unverified — not a mismatch

    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() != 32) return false;

    const Bytes current =
        CryptoEngine::safetyFingerprint(m_crypto.identityPub(), peerEd);
    if (current == stored) return false;

    // Mismatch.  Fire the callback at most once per session per peer.
    if (m_keyChangeWarned.insert(peerIdB64u).second) {
        if (onPeerKeyChanged) onPeerKeyChanged(peerIdB64u, stored, current);
        P2P_WARN("[SAFETY] key-change detected for " << peerIdB64u.substr(0, 8)
                 << "... (hardBlock=" << (m_hardBlockOnKeyChange ? "on" : "off") << ")");
    }
    return true;
}

// ── GAP5: Group sequence counter persistence ────────────────────────────────

void ChatController::setGroupSeqCounters(const std::map<std::string, int64_t>& seqOut,
                                          const std::map<std::string, int64_t>& seqIn)
{
    m_groupSeqOut = seqOut;
    m_groupSeqIn  = seqIn;
}

// ── Fix #20: group-membership authorization ──────────────────────────────────

void ChatController::setKnownGroupMembers(const std::string& groupId,
                                           const std::vector<std::string>& members)
{
    if (groupId.empty()) return;
    m_groupMembers[groupId] = std::set<std::string>(members.begin(), members.end());
}

bool ChatController::isAuthorizedGroupSender(const std::string& gid,
                                              const std::string& peerId) const
{
    if (gid.empty() || peerId.empty()) return false;
    auto it = m_groupMembers.find(gid);
    if (it == m_groupMembers.end()) {
        // H2 fix (2026-04-19): deny-by-default for unknown groups.
        //
        // Old behavior returned true here, which let any authenticated peer
        // send group_rename / group_avatar / group_leave for a group ID that
        // our roster hadn't yet loaded.  An attacker who guessed or observed
        // a gid (e.g., via a shared link) could rename the group or inject
        // a fake avatar before the legitimate roster arrived.
        //
        // Bootstrap is still possible: the group_msg handler does its own
        // sender-in-declared-members check and populates m_groupMembers
        // from that, so the first real group_msg admits everyone that
        // follows.  Control messages (rename/avatar/leave) that arrive
        // before any group_msg are now dropped — if a legitimate sender
        // races a rename ahead of their own group_msg, they'll just need
        // to retry after the roster establishes.
        return false;
    }
    return it->second.count(peerId) != 0;
}

// ---------------------------
// Post-Quantum KEM pub exchange
// ---------------------------

Bytes ChatController::lookupPeerKemPub(const std::string& peerIdB64u)
{
    // Check in-memory cache first
    auto it = m_peerKemPubs.find(peerIdB64u);
    if (it != m_peerKemPubs.end()) return it->second;

    // Load from DB
    if (!m_dbPtr || !m_dbPtr->isOpen()) return {};
    SqlCipherQuery q(m_dbPtr->handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:pid;");
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) {
        Bytes pub = q.valueBlob(0);
        if (!pub.empty()) {
            m_peerKemPubs[peerIdB64u] = pub;
            return pub;
        }
    }
    return {};
}

void ChatController::announceKemPub(const std::string& peerIdB64u)
{
    if (!m_crypto.hasPQKeys()) return;
    if (!m_sessionMgr) return;
    if (m_kemPubAnnounced.count(peerIdB64u)) return;  // already sent this session

    m_kemPubAnnounced.insert(peerIdB64u);

    json payload = json::object();
    payload["from"] = myIdB64u();
    payload["type"] = "kem_pub_announce";
    payload["kem_pub_b64u"] = CryptoEngine::toBase64Url(m_crypto.kemPub());
    payload["ts"] = nowSecs();

    sendSealedPayload(peerIdB64u, payload);
    P2P_LOG("[PQ] Announced ML-KEM-768 pub to " << peerIdB64u.substr(0, 8) << "...");
}
