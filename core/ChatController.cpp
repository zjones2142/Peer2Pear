#include "ChatController.hpp"
#include "bytes_util.hpp"  // strBytes helper (Qt-free)
#ifdef PEER2PEAR_P2P
// NiceConnection.hpp pulls in nice/agent.h, whose gio dependency uses
// `signals` as a struct member — clashes with Qt's `signals` macro.
// Undef before, restore after so any Qt header later in the TU still
// compiles cleanly.
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

// Envelope header prefixes.  Every outbound frame is a sealed envelope;
// every inbound frame that isn't sealed is dropped by onEnvelope /
// onP2PDataReceived.
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
#ifdef PEER2PEAR_P2P
    // Audit #3 L3: session-random 32-byte AEAD key for TURN creds.
    // Never persisted; never exposed outside this class.  Lifetime =
    // this ChatController instance, so creds from one process can't
    // be replayed against a later one.
    m_turnCredsKey.assign(32, 0);
    randombytes_buf(m_turnCredsKey.data(), m_turnCredsKey.size());
#endif
    // Forward the sealer's key-change event through ChatController's own
    // public callback surface — keeps the onPeerKeyChanged(peerId,
    // oldFp, newFp) signature stable for the C API + desktop.
    m_sealer.onPeerKeyChanged =
        [this](const std::string& peerId,
               const Bytes& oldFp, const Bytes& newFp) {
            if (onPeerKeyChanged) onPeerKeyChanged(peerId, oldFp, newFp);
        };

    // GroupProtocol fans out through sendSealedPayload, which itself
    // routes through m_sealer + m_relay.  Keep the choke-point
    // invariant: every outbound group byte still passes through
    // SessionSealer.sealForPeer.
    m_groupProto.setSendSealedFn(
        [this](const std::string& peerId, const nlohmann::json& payload) {
            sendSealedPayload(peerId, payload);
        });

    // FileProtocol needs a raw relay-send callback because sendFile
    // builds the file_key envelope + reads the ratchet's
    // lastMessageKey in one atomic step, and can't re-seal through
    // sendSealedPayload.  The sealing itself still goes through
    // m_sealer (which FileProtocol holds a reference to).
    m_fileProto.setSendEnvelopeFn(
        [this](const Bytes& env) { m_relay.sendEnvelope(env); });

    // Forward FileProtocol's transfer lifecycle callbacks to
    // ChatController's public surface.
    m_fileProto.onAcceptRequested =
        [this](const std::string& from, const std::string& tid,
               const std::string& fileName, int64_t fileSize) {
            if (onFileAcceptRequested)
                onFileAcceptRequested(from, tid, fileName, fileSize);
        };
    m_fileProto.onCanceled =
        [this](const std::string& tid, bool byReceiver) {
            if (onFileTransferCanceled) onFileTransferCanceled(tid, byReceiver);
        };
    m_fileProto.onDelivered =
        [this](const std::string& tid) {
            if (onFileTransferDelivered) onFileTransferDelivered(tid);
        };
    m_fileProto.onBlocked =
        [this](const std::string& tid, bool byReceiver) {
            if (onFileTransferBlocked) onFileTransferBlocked(tid, byReceiver);
        };

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

        // Receiver finished writing and verified — send file_ack.
        if (chunksReceived == chunksTotal && !savedPath.empty()) {
            json ack = json::object();
            ack["type"]       = "file_ack";
            ack["transferId"] = transferId;
            m_fileProto.sendControlMessage(fromPeerId, ack);
        }
    };

#ifdef PEER2PEAR_P2P
    m_fileMgr.onWantP2PConnection = [this](const std::string& peerId) {
        initiateP2PConnection(peerId);
    };
#endif

    // Remove ratchet-derived file key when transfer completes.
    m_fileMgr.onTransferCompleted = [this](const std::string& transferId) {
        const std::string suffix = ":" + transferId;
        auto it = m_fileProto.fileKeys().begin();
        while (it != m_fileProto.fileKeys().end()) {
            const auto& k = it->first;
            const bool ends = k.size() >= suffix.size() &&
                              k.compare(k.size() - suffix.size(), suffix.size(), suffix) == 0;
            if (ends || k == transferId) {
                sodium_memzero(it->second.data(), it->second.size());
                it = m_fileProto.fileKeys().erase(it);
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

    // Rehydrate file keys from DB after loadPersistedTransfers().
    m_fileMgr.onIncomingFileKeyRestored =
        [this](const std::string& fromPeerId,
               const std::string& transferId,
               const FileTransferManager::Bytes& fileKey) {
        if (fileKey.size() != 32) return;
        const std::string compound = fromPeerId + ":" + transferId;
        m_fileProto.fileKeys()[compound] = fileKey;
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
    // Reset per-sender rate limit counters.
    m_envelopeCount.clear();
    m_fileRequestCount.clear();

    // Purge stale incomplete transfers
    m_fileMgr.purgeStaleTransfers();
    m_fileMgr.purgeStaleOutbound();
    m_fileMgr.purgeStalePartialFiles();

    // Prune stuck handshakes.
    if (m_sessionStore) {
        const auto pruned = m_sessionStore->pruneStaleHandshakes();
        for (const std::string& peerId : pruned) {
            int count = ++m_handshakeFailCount[peerId];
            if (count >= 2 && onPeerMayNeedUpgrade)
                onPeerMayNeedUpgrade(peerId);
        }
    }

    // Age out the persistent envelope-ID dedup table.
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
        delete m_p2pConnections[key];
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

    // Hand the store to GroupProtocol so sender chains get persisted
    // on every advance and restored after restart.  Restore happens
    // here (before any group traffic flows) so inbound group_msgs that
    // arrive early find their chains already in memory.
    m_groupProto.setSessionStore(m_sessionStore.get());
    m_groupProto.restorePersistedChains();

    // Wire up file-transfer persistence and restore any in-flight state.
    m_fileMgr.setDatabase(&db);
    m_fileMgr.loadPersistedTransfers();
    m_fileMgr.purgeStalePartialFiles();

    // Envelope-ID dedup survives restart when a DB is present.
    ensureSeenEnvelopesTable();

    // Wire SessionSealer to the same DB + session manager.  Internally
    // this creates the verified_peers table on first open and registers
    // the onPeerKeyChanged forwarder.  All trust + sealing paths route
    // through m_sealer from here on.
    m_sealer.setDatabase(&db);
    m_sealer.setSessionManager(m_sessionMgr.get());
    m_fileProto.setSessionManager(m_sessionMgr.get());

    // When SessionManager needs to send a handshake response, seal it and enqueue
    m_sessionMgr->setSendResponseFn([this](const std::string& peerId, const Bytes& blob) {
        // Convert peer's Ed25519 pub to X25519 for sealing
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0) return;

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        Bytes peerKemPub = m_sealer.lookupPeerKemPub(peerId);
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

    // Seal callback for file chunks — FTM speaks std types end-to-end.
    m_fileMgr.setSealFn([this](const std::string& peerId,
                               const FileTransferManager::Bytes& payload)
                              -> FileTransferManager::Bytes {
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
            return {};

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        sodium_memzero(peerCurvePub, sizeof(peerCurvePub));
        Bytes peerKemPub = m_sealer.lookupPeerKemPub(peerId);
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
    Bytes sealedEnv = m_sealer.sealForPeer(peerIdB64u, pt);
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
    sendSealedPayload(peerIdB64u, payload);
}

// ── File transfer delegation ─────────────────────────────────────────────────
// All outbound paths + consent responses live on m_fileProto.  ChatController
// keeps wrappers so the public API + onStatus reporting stay stable.

std::string ChatController::sendFile(const std::string& peerIdB64u,
                                     const std::string& fileName,
                                     const std::string& filePath)
{
    std::string tid = m_fileProto.sendFile(peerIdB64u, fileName, filePath);
    if (tid.empty() && onStatus) {
        onStatus("File not sent — check size, path, or session state.");
    }
    return tid;
}

std::string ChatController::sendGroupFile(const std::string& groupId,
                                          const std::string& groupName,
                                          const std::vector<std::string>& memberPeerIds,
                                          const std::string& fileName,
                                          const std::string& filePath)
{
    std::string tid = m_fileProto.sendGroupFile(groupId, groupName, memberPeerIds,
                                                 fileName, filePath);
    if (tid.empty() && onStatus) {
        onStatus("File not sent — check size, path, or session state.");
    }
    if (!tid.empty() && onStatus) {
        onStatus("'" + fileName + "' queued for group " + groupName
                 + " (awaiting per-member consent)");
    }
    return tid;
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

    // For each incomplete incoming transfer, tell the sender which chunks
    // we still need so they can re-send them.
    const auto pendings = m_fileMgr.pendingResumptions();
    for (const auto& pr : pendings) {
        json chunks = json::array();
        for (uint32_t idx : pr.missingChunks) chunks.push_back(int(idx));
        json msg = json::object();
        msg["type"]       = "file_request";
        msg["transferId"] = pr.transferId;
        msg["chunks"]     = std::move(chunks);
        m_fileProto.sendControlMessage(pr.peerId, msg);
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

ChatController::~ChatController()
{
#ifdef PEER2PEAR_P2P
    // Audit #3 L3: make sure TURN creds + the session-AEAD key don't
    // linger in freed pages after the controller goes away.
    if (!m_turnCredsKey.empty()) CryptoEngine::secureZero(m_turnCredsKey);
    if (!m_turnUserCt.empty())   CryptoEngine::secureZero(m_turnUserCt);
    if (!m_turnPassCt.empty())   CryptoEngine::secureZero(m_turnPassCt);
#endif
}

#ifdef PEER2PEAR_P2P
void ChatController::setTurnServer(const std::string& host, int port,
                                    const std::string& username, const std::string& password)
{
    m_turnHost = host;
    m_turnPort = port;

    // Audit #3 L3: encrypt creds before they touch a long-lived member.
    // The ciphertext sits in m_turnUserCt / m_turnPassCt; the key is
    // session-ephemeral (m_turnCredsKey).  setupP2PConnection is the
    // only reader and zeroes its scratch buffers right after use.
    auto encCred = [this](const std::string& s) -> Bytes {
        if (s.empty()) return {};
        Bytes pt(s.begin(), s.end());
        Bytes ct = m_crypto.aeadEncrypt(m_turnCredsKey, pt);
        sodium_memzero(pt.data(), pt.size());
        return ct;
    };
    if (!m_turnUserCt.empty())
        sodium_memzero(m_turnUserCt.data(), m_turnUserCt.size());
    if (!m_turnPassCt.empty())
        sodium_memzero(m_turnPassCt.data(), m_turnPassCt.size());
    m_turnUserCt = encCred(username);
    m_turnPassCt = encCred(password);

    P2P_LOG("[ChatController] TURN server set: " << host << ":" << port);
}
#endif

void ChatController::checkPresence(const std::vector<std::string>& peerIds)
{
    std::vector<std::string> ids;
    m_relay.queryPresence(peerIds);
}

// ── File-transfer consent / cancel — see FileProtocol.cpp ───────────────────
// sendFileControlMessage, acceptFileTransfer, declineFileTransfer, and
// cancelFileTransfer all live on m_fileProto.  The public API surface above
// (acceptFileTransfer / declineFileTransfer / cancelFileTransfer) delegates
// inline.  The inbound file_* branches in onEnvelope read + mutate state
// via m_fileProto.fileKeys() / pendingIncoming() / sendControlMessage.

void ChatController::sendGroupMessageViaMailbox(const std::string& groupId,
                                                const std::string& groupName,
                                                const std::vector<std::string>& memberPeerIds,
                                                const std::string& text)
{
    m_groupProto.sendText(groupId, groupName, memberPeerIds, text);
}

void ChatController::sendGroupLeaveNotification(const std::string& groupId,
                                                const std::string& groupName,
                                                const std::vector<std::string>& memberPeerIds)
{
    m_groupProto.sendLeave(groupId, groupName, memberPeerIds);
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

// Persistent envelope-ID dedup.  The in-memory LRU is a speed cache; the
// row in seen_envelopes is the source of truth across app restarts.  Only
// used for the outer envelope-level check; the ratchet chain counter still
// covers replayed session payloads once the envelope is past the gate.
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
// ── Sealed payload via mailbox, fail-closed ───────────────────────────────
void ChatController::sendSealedPayload(const std::string& peerIdB64u,
                                       const nlohmann::json& payload)
{
    const std::string ptStr = payload.dump();
    const Bytes pt(ptStr.begin(), ptStr.end());
    const std::string type = payload.value("type", std::string());

    Bytes env = m_sealer.sealForPeer(peerIdB64u, pt);
    if (!env.empty()) {
        P2P_LOG("[SEND MAILBOX] " << type << " to " << peerIdB64u.substr(0, 8) << "...");
        m_relay.sendEnvelope(env);
        return;
    }

    // Fail closed.  ICE messages go through the same sealed path as
    // everything else; if the ratchet can't seal, we defer the handshake
    // instead of leaking SDP/IP candidates.
    P2P_WARN("[SEND] BLOCKED — cannot seal " << type
               << " to " << peerIdB64u.substr(0, 8) << "...");
}

#ifdef PEER2PEAR_P2P
// ── QUIC + ICE connection setup ──────────────────────────────────────────────
QuicConnection* ChatController::setupP2PConnection(const std::string& peerIdB64u, bool controlling)
{
    // Lifetime is managed by m_p2pConnections raw pointer ownership;
    // runMaintenance() deletes stale entries.
    QuicConnection* conn = new QuicConnection(*m_timerFactory);
    if (!m_turnHost.empty()) {
        // Audit #3 L3: decrypt TURN creds just-in-time into scratch
        // buffers, pass to QuicConnection, then zero.  QuicConnection
        // is expected to copy what it needs before returning.
        auto decCred = [this](const Bytes& ct) -> std::string {
            if (ct.empty()) return {};
            Bytes pt = m_crypto.aeadDecrypt(m_turnCredsKey, ct);
            if (pt.empty()) return {};
            std::string s(pt.begin(), pt.end());
            sodium_memzero(pt.data(), pt.size());
            return s;
        };
        std::string user = decCred(m_turnUserCt);
        std::string pass = decCred(m_turnPassCt);
        conn->setTurnServer(m_turnHost, m_turnPort, user, pass);
        sodium_memzero(const_cast<char*>(user.data()), user.size());
        sodium_memzero(const_cast<char*>(pass.data()), pass.size());
    }
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
            m_fileProto.fileKeys());
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
    // Only sealed envelopes are accepted on the P2P transport.  Unsealed
    // P2P frames are dropped — static-ECDH fallbacks lack forward secrecy
    // and would let a compromised identity key retroactively decrypt prior
    // P2P text messages.
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

        // Envelope-level replay protection: dedup on envelopeId.
        // The ratchet dedups its own chain messages, but control messages
        // outside the ratchet (file_accept, file_cancel, etc.) don't have
        // that protection.  A malicious relay could redeliver the same
        // sealed blob and the receiver would happily reprocess it.
        if (unsealedEnvelopeId.size() == 16) {
            const std::string envKey = "env:" + CryptoEngine::toBase64Url(unsealedEnvelopeId);
            // Persistent dedup so a relay-level replay after app restart
            // still gets dropped.
            if (!markSeenPersistent(envKey)) {
                P2P_LOG("[RECV " << via << "] dropping replayed envelope "
                         << envKey.substr(4, 8) << "...");
                return;
            }
        }

        std::string senderId = CryptoEngine::toBase64Url(unsealedSenderEdPub);
        P2P_LOG("[RECV " << via << "] unsealed OK | sender: " << senderId.substr(0, 8) << "..."
                 << " | inner: " << unsealedInnerPayload.size() << "B");

        // Rate limit per sender to prevent CPU exhaustion via envelope flooding.
        int& count = m_envelopeCount[senderId];
        if (++count > kMaxEnvelopesPerSenderPerPoll) {
            if (count == kMaxEnvelopesPerSenderPerPoll + 1)
                P2P_WARN("[RECV] rate limit hit for " << senderId.substr(0, 8) << "..."
                           << " — dropping further envelopes this cycle");
            return;
        }

        // Sealed file chunk — pass directly to FileTransferManager.
        // The inner payload is already encrypted with the ratchet-derived
        // file key; no session decrypt is needed (the sealed envelope just
        // hides the sender).
        if (isFileChunk) {
            // Verify we have at least one file_key from this sender before
            // allowing trial decryption.  This prevents an attacker who can
            // craft valid sealed envelopes from causing unnecessary crypto work.
            bool hasKeyFromSender = false;
            const std::string senderPrefix = senderId + ":";
            for (const auto& kv : m_fileProto.fileKeys()) {
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
                m_fileProto.fileKeys());
            return;
        }

        if (!m_sessionMgr) return; // can't process without session manager

        // Only emit "online" if the envelope is recent (within 2 minutes).
        // Old mailbox messages should not trigger false online presence.
        // Sealed envelopes carry no timestamp, so we infer freshness from
        // the transport — P2P is always live; mailbox may have stale messages.
        if (via == "P2P") if (onPresenceChanged) onPresenceChanged(senderId, true);

        // Decrypt session layer (Noise handshake or ratchet message).
        Bytes msgKey;  // capture message key directly from decrypt
        Bytes pt = m_sessionMgr->decryptFromPeer(senderId, unsealedInnerPayload, &msgKey);
        if (pt.empty()) {
            // Pre-key response (0x02) completes the Noise IK handshake and creates
            // a ratchet session inside decryptFromPeer(), but returns no user payload.
            // This is expected — future messages will use the ratchet session.
            const uint8_t innerType = unsealedInnerPayload.empty() ? 0 : unsealedInnerPayload[0];
            if (innerType == SessionManager::kPreKeyResponse || innerType == SessionManager::kHybridPreKeyResp) {
                P2P_LOG("[RECV " << via << "] handshake COMPLETED with " << senderId.substr(0, 8) << "...");
                // Handshake succeeded — clear failure counter.
                m_handshakeFailCount.erase(senderId);

                // Announce our PQ KEM pub now that we have an authenticated channel
                announceKemPub(senderId);

            } else {
                P2P_LOG("[RECV " << via << "] session decrypt empty from " << senderId.substr(0, 8) << "...");
            }
            return;
        }

        // Parse the decrypted JSON payload + hand off to the type
        // dispatcher.  Everything above this point is envelope plumbing
        // (unseal, dedup, decrypt, rate limit); everything below is
        // per-type routing.
        const json o = json::parse(pt.begin(), pt.end(),
                                   /*cb=*/nullptr, /*allow_exceptions=*/false);
        if (!o.is_object()) return;

        const std::string type = o.value("type", std::string());
        const int64_t tsSecs = o.value("ts", int64_t(0));
        const std::string msgId = o.value("msgId", std::string());

        P2P_LOG("[RECV " << via << "] sealed type: " << type << " from " << senderId.substr(0, 8) << "...");

        // Safety-numbers check on inbound.  Fires onPeerKeyChanged at
        // most once per session; the hard-block toggle then refuses to
        // deliver to the app callbacks.  Only applies to already-verified
        // peers — first-contact / unverified messages flow through.
        if (m_sealer.detectKeyChange(senderId) && m_sealer.hardBlockOnKeyChange()) {
            P2P_WARN("[RECV] dropping message from " << senderId.substr(0, 8)
                     << "... — hard-block on key change");
            return;
        }

        dispatchSealedPayload(o, senderId, tsSecs, msgId, via, std::move(msgKey));
        return;
    }

    // Any frame that isn't a SEALED: / SEALEDFC: envelope is dropped.
    // The sealed handler above covers every message type the app emits;
    // static-ECDH fallbacks would lack forward secrecy and unsealed file
    // chunks would leak the sender's pubkey to the relay in plaintext.
    P2P_WARN("[RECV " << via << "] dropping non-sealed envelope ("
             << header.size() << " header bytes) — sealed envelopes required");
}

// ── dispatchSealedPayload ───────────────────────────────────────────────────
// The inbound type-switch, split from onEnvelope so neither function is a
// 600-line god-method.  Called for every sealed envelope whose session
// decrypt succeeds (i.e., every inbound user message + every protocol
// control message).  Safety-number hard-block check has already run.
void ChatController::dispatchSealedPayload(const nlohmann::json& o,
                                            const std::string& senderId,
                                            int64_t tsSecs,
                                            const std::string& msgId,
                                            const std::string& via,
                                            Bytes msgKey)
{
        const std::string type = o.value("type", std::string());

        if (type == "text") {
            if (!msgId.empty() && !markSeen(msgId)) return;
            if (onMessageReceived) onMessageReceived(senderId,
                                 o.value("text", std::string()), tsSecs, msgId);
        } else if (type == "group_skey_announce") {
            // Sender-chain control message: a peer is distributing
            // the seed for their outbound SenderChain to us.  The
            // outer sealed envelope already authenticated the sender
            // (via their 1:1 ratchet), so we trust the payload to
            // identify them; we just need to install the chain so
            // future group_msg from this peer decrypts.
            if (!msgId.empty() && !markSeen(msgId)) return;

            const std::string gid    = o.value("groupId", std::string());
            const uint64_t    epoch  = o.value("epoch", uint64_t(0));
            const std::string seedB64 = o.value("seed", std::string());
            if (gid.empty() || seedB64.empty()) {
                P2P_WARN("[GROUP] malformed group_skey_announce from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            const Bytes seed = CryptoEngine::fromBase64Url(seedB64);
            m_groupProto.installRemoteChain(gid, senderId, epoch, seed);
            P2P_LOG("[GROUP] installed sender chain from "
                    << senderId.substr(0, 8) << "... for "
                    << gid.substr(0, 8) << "... epoch " << epoch);
        } else if (type == "group_msg") {
            if (!msgId.empty() && !markSeen(msgId)) return;

            // Wire format: ciphertext + skey_epoch + skey_idx.
            // Replay protection lives in the AAD binding
            // (from || gid || epoch || idx) — tampering any field
            // makes AEAD auth fail.
            const std::string gid      = o.value("groupId", std::string());
            const uint64_t    skeyEpoch = o.value("skey_epoch", uint64_t(0));
            const uint32_t    skeyIdx   = o.value("skey_idx", uint32_t(0));
            const std::string ctB64     = o.value("ciphertext", std::string());

            if (gid.empty() || ctB64.empty()) {
                P2P_WARN("[GROUP] malformed group_msg from "
                         << senderId.substr(0, 8) << "...");
                return;
            }

            std::vector<std::string> memberKeys;
            if (o.contains("members") && o["members"].is_array())
                for (const auto& v : o["members"])
                    if (v.is_string()) memberKeys.push_back(v.get<std::string>());

            // Decrypt the ciphertext BEFORE touching roster state.
            // If the chain isn't installed yet (skey_announce still in
            // flight) or decryption fails for any reason, reject the
            // message entirely rather than bootstrap a roster from a
            // payload we couldn't read.
            const Bytes ct = CryptoEngine::fromBase64Url(ctB64);
            const Bytes pt = m_groupProto.decryptGroupMessage(
                "group_msg", gid, senderId, skeyEpoch, skeyIdx, ct);
            if (pt.empty()) {
                P2P_WARN("[GROUP] decrypt failed for group_msg from "
                         << senderId.substr(0, 8) << "... in "
                         << gid.substr(0, 8) << "... epoch=" << skeyEpoch
                         << " idx=" << skeyIdx
                         << " (chain missing or AEAD auth failed)");
                return;
            }

            // A valid sealed group_msg from X about group G adds X
            // (and the declared members) to our roster.  Known
            // limitation: first-mover race on an unknown group (see
            // GroupProtocol); UIs should call setKnownGroupMembers at
            // startup from persisted state to beat the bootstrap path.
            m_groupProto.upsertMembersFromTrustedMessage(gid, senderId, memberKeys);

            // Parse the decrypted inner JSON for user content.  The
            // text field is the only user-facing payload today.
            std::string text;
            try {
                auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
                text = inner.value("text", std::string());
            } catch (...) {
                P2P_WARN("[GROUP] malformed inner plaintext in group_msg from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            if (onGroupMessageReceived) onGroupMessageReceived(senderId, gid,
                                       o.value("groupName", std::string()),
                                       memberKeys,
                                       text, tsSecs, msgId);
        } else if (type == "group_leave") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // dedup
            const std::string gid = o.value("groupId", std::string());
            // A leave message may ONLY be self-leave — senders can't
            // announce that OTHER members left.  And the sender must
            // have been a known member of the group.
            if (!gid.empty() && !m_groupProto.isAuthorizedSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_leave from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            // Audit #3 H2: groupName + members live inside the sender-
            // chain ciphertext now (matching every other group_* shape).
            // Decrypt before reading either; a bad ciphertext drops the
            // leave silently — same posture as group_rename / _avatar.
            const uint64_t    skeyEpoch = o.value("skey_epoch", uint64_t(0));
            const uint32_t    skeyIdx   = o.value("skey_idx", uint32_t(0));
            const std::string ctB64     = o.value("ciphertext", std::string());
            if (gid.empty() || ctB64.empty()) {
                P2P_WARN("[GROUP] malformed group_leave from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            const Bytes ct = CryptoEngine::fromBase64Url(ctB64);
            const Bytes pt = m_groupProto.decryptGroupMessage(
                "group_leave", gid, senderId, skeyEpoch, skeyIdx, ct);
            if (pt.empty()) {
                P2P_WARN("[GROUP] decrypt failed for group_leave from "
                         << senderId.substr(0, 8) << "... in "
                         << gid.substr(0, 8) << "...");
                return;
            }
            std::string groupName;
            std::vector<std::string> memberKeys;
            try {
                auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
                groupName = inner.value("groupName", std::string());
                if (inner.contains("members") && inner["members"].is_array())
                    for (const auto& v : inner["members"])
                        if (v.is_string()) memberKeys.push_back(v.get<std::string>());
            } catch (...) {
                P2P_WARN("[GROUP] malformed inner plaintext in group_leave");
                return;
            }
            // The sender left — strike them from our roster so they
            // can't push further member-update / rename / avatar
            // messages afterwards.  Also drop their sender-key chain:
            // they won't be sending new group_msg into this group and
            // keeping their chain material around is pointless.
            m_groupProto.removeMember(gid, senderId);
            m_groupProto.forgetRemoteChain(gid, senderId);
            if (onGroupMemberLeft) onGroupMemberLeft(senderId, gid,
                                  groupName,
                                  memberKeys, tsSecs, msgId);
        } else if (type == "avatar") {
            if (onAvatarReceived) onAvatarReceived(senderId,
                                 o.value("name", std::string()),
                                 o.value("avatar", std::string()));
        } else if (type == "group_rename") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // dedup
            const std::string gid = o.value("groupId", std::string());
            if (!gid.empty() && !m_groupProto.isAuthorizedSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_rename from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            const uint64_t    skeyEpoch = o.value("skey_epoch", uint64_t(0));
            const uint32_t    skeyIdx   = o.value("skey_idx", uint32_t(0));
            const std::string ctB64     = o.value("ciphertext", std::string());
            if (gid.empty() || ctB64.empty()) {
                P2P_WARN("[GROUP] malformed group_rename from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            const Bytes ct = CryptoEngine::fromBase64Url(ctB64);
            const Bytes pt = m_groupProto.decryptGroupMessage(
                "group_rename", gid, senderId, skeyEpoch, skeyIdx, ct);
            if (pt.empty()) {
                P2P_WARN("[GROUP] decrypt failed for group_rename from "
                         << senderId.substr(0, 8) << "... in "
                         << gid.substr(0, 8) << "...");
                return;
            }
            std::string newName;
            try {
                auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
                newName = inner.value("newName", std::string());
            } catch (...) {
                P2P_WARN("[GROUP] malformed inner plaintext in group_rename");
                return;
            }
            if (onGroupRenamed) onGroupRenamed(gid, newName);
        } else if (type == "group_avatar") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // dedup
            const std::string gid = o.value("groupId", std::string());
            if (!gid.empty() && !m_groupProto.isAuthorizedSender(gid, senderId)) {
                P2P_WARN("[GROUP] dropping group_avatar from non-member "
                           << senderId.substr(0, 8) << "... for " << gid.substr(0, 8));
                return;
            }
            const uint64_t    skeyEpoch = o.value("skey_epoch", uint64_t(0));
            const uint32_t    skeyIdx   = o.value("skey_idx", uint32_t(0));
            const std::string ctB64     = o.value("ciphertext", std::string());
            if (gid.empty() || ctB64.empty()) {
                P2P_WARN("[GROUP] malformed group_avatar from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            const Bytes ct = CryptoEngine::fromBase64Url(ctB64);
            const Bytes pt = m_groupProto.decryptGroupMessage(
                "group_avatar", gid, senderId, skeyEpoch, skeyIdx, ct);
            if (pt.empty()) {
                P2P_WARN("[GROUP] decrypt failed for group_avatar from "
                         << senderId.substr(0, 8) << "... in "
                         << gid.substr(0, 8) << "...");
                return;
            }
            std::string avatarB64;
            try {
                auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
                avatarB64 = inner.value("avatar", std::string());
            } catch (...) {
                P2P_WARN("[GROUP] malformed inner plaintext in group_avatar");
                return;
            }
            if (onGroupAvatarReceived) onGroupAvatarReceived(gid, avatarB64);
        } else if (type == "group_member_update") {
            if (!msgId.empty() && !markSeen(msgId)) return;  // dedup
            const std::string gid       = o.value("groupId", std::string());
            const uint64_t    skeyEpoch = o.value("skey_epoch", uint64_t(0));
            const uint32_t    skeyIdx   = o.value("skey_idx", uint32_t(0));
            const std::string ctB64     = o.value("ciphertext", std::string());

            // Decrypt the inner payload first — the groupName + members
            // fields are carried inside the sender-chain ciphertext,
            // bound to AAD including the "group_member_update" type.
            std::string gname;
            std::vector<std::string> memberKeys;
            if (gid.empty() || ctB64.empty()) {
                P2P_WARN("[GROUP] malformed group_member_update from "
                         << senderId.substr(0, 8) << "...");
                return;
            }
            const Bytes ct = CryptoEngine::fromBase64Url(ctB64);
            const Bytes pt = m_groupProto.decryptGroupMessage(
                "group_member_update", gid, senderId, skeyEpoch, skeyIdx, ct);
            if (pt.empty()) {
                P2P_WARN("[GROUP] decrypt failed for group_member_update from "
                         << senderId.substr(0, 8) << "... in "
                         << gid.substr(0, 8) << "...");
                return;
            }
            try {
                auto inner = nlohmann::json::parse(std::string(pt.begin(), pt.end()));
                gname = inner.value("groupName", std::string());
                if (inner.contains("members") && inner["members"].is_array())
                    for (const auto& v : inner["members"])
                        if (v.is_string()) memberKeys.push_back(v.get<std::string>());
            } catch (...) {
                P2P_WARN("[GROUP] malformed inner plaintext in group_member_update");
                return;
            }

            if (!gid.empty()) {
                // Bootstrap path: unknown group accepts the proposed
                // roster only if the sender names themselves.  Otherwise
                // the sender must already be in our roster.  Both paths
                // land on GroupProtocol helpers so the authorization
                // rule lives in one place.
                if (!m_groupProto.isAuthorizedSender(gid, senderId)) {
                    // Unknown group — try bootstrap: sender must include self.
                    const bool senderInList =
                        std::find(memberKeys.begin(), memberKeys.end(), senderId)
                        != memberKeys.end();
                    if (!senderInList) {
                        P2P_WARN("[GROUP] rejecting bootstrap group_member_update"
                                   << " from " << senderId.substr(0, 8) << "..."
                                   << " — sender not in proposed member list");
                        return;
                    }
                    m_groupProto.replaceMembers(gid, memberKeys);
                } else {
                    // Authorized update: add-only merge.  We deliberately
                    // don't accept REMOVALS via this message type — only
                    // group_leave from the leaving peer themselves drops
                    // someone from the roster.
                    m_groupProto.upsertMembersFromTrustedMessage(gid, senderId, memberKeys);
                }
            }

            // Re-use the existing groupMessageReceived signal — the
            // ChatView::onIncomingGroupMessage handler already merges new
            // member keys into the group's key list.  Empty text means
            // no chat bubble, but the roster merge still happens.
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
            // File key announcement.  Evaluate consent policy BEFORE
            // installing the key.  Chunks that arrive before the user
            // accepts will fail to find a matching key and be dropped silently.
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

            // Evaluate global size policy.  The same thresholds apply
            // whether the file is 1:1 or group-scoped — otherwise any
            // group member could push up to the hard-max bytes to disk
            // without the user's consent.
            // (Per-contact policy will be layered on top in a follow-up.)
            const int64_t fileSizeMB = fileSize / (1024 * 1024);
            bool autoAccept = false;
            bool autoDecline = false;
            if (fileSize > int64_t(m_fileProto.hardMaxMB()) * 1024 * 1024) {
                autoDecline = true;
            } else if (fileSize <= int64_t(m_fileProto.autoAcceptMaxMB()) * 1024 * 1024) {
                autoAccept = true;
            }

            if (autoDecline) {
                P2P_LOG("[FILE] auto-decline " << fileName << " (" << fileSizeMB << "MB)"
                         << " from " << senderId.substr(0, 8) << "... — exceeds hard max");
                json declineMsg = json::object();
                declineMsg["type"]       = "file_decline";
                declineMsg["transferId"] = transferId;
                m_fileProto.sendControlMessage(senderId, declineMsg);
                sodium_memzero(msgKey.data(), msgKey.size());
            } else if (autoAccept) {
                // Announce the transfer to FileTransferManager FIRST so
                // it locks the announced fileSize/totalChunks/fileHash.
                // Chunks with mismatched metadata will be dropped.
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
                m_fileProto.fileKeys()[compoundKey] = msgKey;
                sodium_memzero(msgKey.data(), msgKey.size());

                json acceptMsg = json::object();
                acceptMsg["type"]       = "file_accept";
                acceptMsg["transferId"] = transferId;
                if (m_fileProto.requireP2P()) acceptMsg["requireP2P"] = true;
                m_fileProto.sendControlMessage(senderId, acceptMsg);

                P2P_LOG("[FILE] auto-accept " << fileName << " (" << fileSizeMB << "MB)"
                         << " from " << senderId.substr(0, 8) << "...");
            } else {
                // Stash in pending — don't install key yet.  User will
                // accept/decline.  Lock announced hash/chunkCount/ts now
                // so acceptFileTransfer can pass them to
                // announceIncoming() unchanged.
                const Bytes announcedHash = CryptoEngine::fromBase64Url(o.value("fileHash", std::string()));
                const int announcedChunkCount = o.value("chunkCount", 0);
                const int64_t announcedTs     = o.value("ts", int64_t(0));
                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    P2P_WARN("[FILE] missing fileHash/chunkCount on file_key for "
                               << transferId.substr(0, 8) << " — dropping");
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                // Cap the pending-incoming queue so a flood of file_key
                // messages in the prompt-size range can't exhaust memory.
                // Drops the oldest entry (and zeroes its stashed file key)
                // when the cap is hit; in practice the user's UI surface
                // is already overloaded long before this bound.
                if (m_fileProto.pendingIncoming().size() >= FileProtocol::kMaxPendingIncomingFiles) {
                    auto oldest = m_fileProto.pendingIncoming().begin();
                    for (auto it = m_fileProto.pendingIncoming().begin();
                         it != m_fileProto.pendingIncoming().end(); ++it) {
                        if (it->second.announcedSecs < oldest->second.announcedSecs)
                            oldest = it;
                    }
                    sodium_memzero(oldest->second.fileKey.data(),
                                   oldest->second.fileKey.size());
                    P2P_WARN("[FILE] pending-incoming cap hit — evicting "
                             << oldest->first.substr(0, 8) << "... to make room");
                    m_fileProto.pendingIncoming().erase(oldest);
                }

                FileProtocol::PendingIncoming p;
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
                m_fileProto.pendingIncoming()[transferId] = std::move(p);
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
                const bool senderRequiresP2P = m_fileProto.requireP2P();

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
                // Drop sender-side state now that the transfer is acked.
                m_fileMgr.forgetSentTransfer(transferId);
            }

        } else if (type == "file_request") {
            // Receiver is asking us (sender) to re-send these chunk indices.
            const std::string transferId = o.value("transferId", std::string());
            const bool hasChunks = o.contains("chunks") && o["chunks"].is_array();
            if (transferId.empty() || !hasChunks || o["chunks"].empty()) return;

            // Cap chunk-index arrays + rate-limit per peer.  Without the
            // cap, a malicious peer could request thousands of chunks in
            // a single message and force N disk reads + AEAD encryptions.
            // Both bounds are conservative ceilings — a legitimate
            // resumption after a 100 MB transfer is ≤ 416 chunks
            // (100 MiB / 240 KiB), and legitimate clients send
            // file_request at most a few times per session.
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
                // Also drop the sent-transfer DB row in case we were mid-stream.
                m_fileMgr.forgetSentTransfer(transferId);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, true); // canceled by receiver
                return;
            }
            // Also handle "sender was already streaming when receiver canceled":
            // m_outboundPending is empty, but m_sentTransfers has the record.
            m_fileMgr.forgetSentTransfer(transferId);

            // Inbound pending (we were about to prompt)?
            auto itPending = m_fileProto.pendingIncoming().find(transferId);
            if (itPending != m_fileProto.pendingIncoming().end()) {
                sodium_memzero(itPending->second.fileKey.data(), itPending->second.fileKey.size());
                m_fileProto.pendingIncoming().erase(itPending);
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
                m_sealer.saveKemPub(senderId, kemPub);
                P2P_LOG("[PQ] Stored ML-KEM-768 pub from " << senderId.substr(0, 8) << "..."
                         << " | hybrid sealing now active for this peer");
                // Reciprocate: send our KEM pub back if we haven't already
                if (m_crypto.hasPQKeys() && !m_sealer.lookupPeerKemPub(senderId).empty()) {
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
}

void ChatController::sendGroupRename(const std::string& groupId,
                                     const std::string& newName,
                                     const std::vector<std::string>& memberKeys)
{
    m_groupProto.sendRename(groupId, newName, memberKeys);
}

void ChatController::sendGroupAvatar(const std::string& groupId,
                                     const std::string& avatarB64,
                                     const std::vector<std::string>& memberKeys)
{
    m_groupProto.sendAvatar(groupId, avatarB64, memberKeys);
}

void ChatController::sendGroupMemberUpdate(const std::string& groupId,
                                           const std::string& groupName,
                                           const std::vector<std::string>& memberKeys)
{
    m_groupProto.sendMemberUpdate(groupId, groupName, memberKeys);
}

// ── Reset encrypted session ──────────────────────────────────────────────────
void ChatController::resetSession(const std::string& peerIdB64u)
{
    if (m_sessionMgr) {
        m_sessionMgr->deleteSession(peerIdB64u);
        P2P_LOG("[SESSION] Reset ratchet session for " << peerIdB64u.substr(0, 8) << "...");
        if (onStatus) onStatus("Session reset — next message will establish a fresh handshake.");
    }
}

// ── Safety numbers: see SessionSealer.cpp ───────────────────────────────────
// The public trust API (peerTrust / markPeerVerified / unverifyPeer /
// safetyNumber / setHardBlockOnKeyChange / clearPeerKeyCache) is forwarded
// to m_sealer inline in ChatController.hpp.  The fingerprint cache +
// verified_peers DB helpers + detectKeyChange + onPeerKeyChanged callback
// all live on SessionSealer so sealForPeer has a single choke point.

// ── Group state: see GroupProtocol.cpp ──────────────────────────────────────
// Sequence counters + roster authorization + all send* methods live on
// GroupProtocol.  ChatController forwards through m_groupProto; onEnvelope
// queries m_groupProto.isAuthorizedSender / recordInboundSeq /
// upsertMembersFromTrustedMessage directly.

void ChatController::setKnownGroupMembers(const std::string& groupId,
                                           const std::vector<std::string>& members)
{
    m_groupProto.setKnownMembers(groupId, members);
}

// ── Post-Quantum KEM pub exchange ───────────────────────────────────────────
// lookupPeerKemPub + the KEM pub cache live on SessionSealer.  announceKemPub
// stays here because it builds a sealed payload and hands it to the relay;
// m_sealer tracks whether we've already announced to a given peer.

void ChatController::announceKemPub(const std::string& peerIdB64u)
{
    if (!m_crypto.hasPQKeys()) return;
    if (!m_sessionMgr) return;
    if (m_sealer.hasAnnouncedKemPubTo(peerIdB64u)) return;

    m_sealer.markKemPubAnnouncedTo(peerIdB64u);

    json payload = json::object();
    payload["from"] = myIdB64u();
    payload["type"] = "kem_pub_announce";
    payload["kem_pub_b64u"] = CryptoEngine::toBase64Url(m_crypto.kemPub());
    payload["ts"] = nowSecs();

    sendSealedPayload(peerIdB64u, payload);
    P2P_LOG("[PQ] Announced ML-KEM-768 pub to " << peerIdB64u.substr(0, 8) << "...");
}
