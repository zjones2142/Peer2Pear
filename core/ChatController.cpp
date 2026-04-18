#include "ChatController.hpp"
#include "qt_bridge_temp.hpp"   // TEMP: Qt↔std while SealedEnvelope is migrated
#ifdef PEER2PEAR_P2P
// GLib's gio headers use a struct member named 'signals' which clashes
// with Qt5's 'signals' macro. Include GLib first with the macro disabled,
// then restore it before pulling in the Qt-based QuicConnection header.
#undef signals
#include <glib.h>
#include <gio/gio.h>
#include <nice/agent.h>
#define signals Q_SIGNALS
#include "QuicConnection.hpp"
#endif
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>
#include <QFileInfo>
// SqlCipherQuery is available via ChatController.hpp -> SqlCipherDb.hpp
#include <sodium.h>

// Build the std-typed fileKeys map the migrated FileTransferManager expects.
// Copies each entry — callers invoke this once per chunk delivery which is
// bounded by session count (low double digits even in chatty groups).
static std::map<std::string, FileTransferManager::Bytes>
toStdFileKeys(const QMap<QString, QByteArray>& qm) {
    std::map<std::string, FileTransferManager::Bytes> out;
    for (auto it = qm.cbegin(); it != qm.cend(); ++it)
        out.emplace(it.key().toStdString(), p2p::bridge::toBytes(it.value()));
    return out;
}

// Envelope header prefixes (legacy + sealed)
static const QByteArray kMsgPrefix      = "FROM:";
static const QByteArray kFilePrefix     = "FROMFC:";
static const QByteArray kSealedPrefix   = "SEALED:";
static const QByteArray kSealedFCPrefix = "SEALEDFC:";

// ── Helpers ───────────────────────────────────────────────────────────────────

static QDateTime tsFromSecs(qint64 secs)
{
    return secs > 0
               ? QDateTime::fromSecsSinceEpoch(secs, QTimeZone::utc()).toLocalTime()
               : QDateTime::currentDateTime();
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
        if (onStatus) onStatus(QString::fromStdString(s));
    };
    m_relay.onEnvelopeReceived = [this](const RelayClient::Bytes& b) {
        onEnvelope(p2p::bridge::toQByteArray(b));
    };
    m_relay.onPresenceChanged = [this](const std::string& pid, bool online) {
        if (onPresenceChanged) onPresenceChanged(QString::fromStdString(pid), online);
    };
    m_relay.onConnected = [this]() { handleRelayConnected(); };

    // FileTransferManager callbacks — plain class; direct assignment.
    m_fileMgr.setSendFn([this](const std::string& /*peerId*/,
                               const FileTransferManager::Bytes& env) {
        m_relay.sendEnvelope(env);
    });
    m_fileMgr.onStatus = [this](const std::string& s) {
        if (onStatus) onStatus(QString::fromStdString(s));
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
            QString::fromStdString(fromPeerId),
            QString::fromStdString(transferId),
            QString::fromStdString(fileName),
            qint64(fileSize),
            chunksReceived, chunksTotal,
            QString::fromStdString(savedPath),
            QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime(),
            QString::fromStdString(groupId),
            QString::fromStdString(groupName));

        // Phase 3: receiver finished writing and verified — send file_ack.
        if (chunksReceived == chunksTotal && !savedPath.empty()) {
            QJsonObject ack;
            ack["type"]       = "file_ack";
            ack["transferId"] = QString::fromStdString(transferId);
            sendFileControlMessage(QString::fromStdString(fromPeerId), ack);
        }
    };

#ifdef PEER2PEAR_P2P
    m_fileMgr.onWantP2PConnection = [this](const std::string& peerId) {
        initiateP2PConnection(QString::fromStdString(peerId));
    };
#endif

    // M1 fix: remove ratchet-derived file key when transfer completes.
    m_fileMgr.onTransferCompleted = [this](const std::string& transferIdStd) {
        const QString transferId = QString::fromStdString(transferIdStd);
        const QString suffix = ":" + transferId;
        auto it = m_fileKeys.begin();
        while (it != m_fileKeys.end()) {
            if (it.key().endsWith(suffix) || it.key() == transferId) {
                sodium_memzero(it.value().data(), it.value().size());
                it = m_fileKeys.erase(it);
            } else {
                ++it;
            }
        }
    };

    m_fileMgr.onOutboundAbandoned = [this](const std::string& transferId, const std::string&) {
        if (onFileTransferCanceled) onFileTransferCanceled(QString::fromStdString(transferId), false);
    };

    m_fileMgr.onInboundCanceled = [this](const std::string& transferId, const std::string&) {
        if (onFileTransferCanceled) onFileTransferCanceled(QString::fromStdString(transferId), false);
    };

    m_fileMgr.onOutboundBlockedByPolicy =
        [this](const std::string& transferId, const std::string&, bool byReceiver) {
        if (onFileTransferBlocked) onFileTransferBlocked(QString::fromStdString(transferId), byReceiver);
    };

    // Fix #5: rehydrate file keys from DB after loadPersistedTransfers().
    m_fileMgr.onIncomingFileKeyRestored =
        [this](const std::string& fromPeerId,
               const std::string& transferId,
               const FileTransferManager::Bytes& fileKey) {
        if (fileKey.size() != 32) return;
        const QString compound = QString::fromStdString(fromPeerId) + ":"
                                  + QString::fromStdString(transferId);
        m_fileKeys[compound] = p2p::bridge::toQByteArray(fileKey);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] restored file key for" << QString::fromStdString(transferId).left(8)
                 << "from" << QString::fromStdString(fromPeerId).left(8) + "...";
#endif
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

    // Purge stale incomplete transfers
    m_fileMgr.purgeStaleTransfers();
    m_fileMgr.purgeStaleOutbound();
    m_fileMgr.purgeStalePartialFiles();

    // H2/SEC9: prune stuck handshakes
    if (m_sessionStore) {
        const auto pruned = m_sessionStore->pruneStaleHandshakes();
        for (const std::string& peerIdStd : pruned) {
            const QString peerId = QString::fromStdString(peerIdStd);
            int count = ++m_handshakeFailCount[peerId];
            if (count >= 2 && onPeerMayNeedUpgrade)
                onPeerMayNeedUpgrade(peerId);
        }
    }

#ifdef PEER2PEAR_P2P
    const qint64 nowSecs = QDateTime::currentSecsSinceEpoch();
    QStringList toRemove;
    for (auto it = m_p2pConnections.begin(); it != m_p2pConnections.end(); ++it) {
        if (it.value()->isReady()) continue;
        const qint64 created = m_p2pCreatedSecs.value(it.key(), nowSecs);
        if ((nowSecs - created) < kP2PCleanupGraceSecs) continue;
        toRemove << it.key();
    }
    for (const QString &key : toRemove) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[ICE] Cleaning up stale connection to" << key.left(8) + "..."
                 << "(exceeded" << kP2PCleanupGraceSecs << "s grace)";
#endif
        m_p2pConnections[key]->deleteLater();
        m_p2pConnections.remove(key);
        m_p2pCreatedSecs.remove(key);
    }
#endif
}

void ChatController::setPassphrase(const QString& pass)
{
    m_crypto.setPassphrase(pass.toStdString());
    m_crypto.ensureIdentity();
}

void ChatController::setPassphrase(const QString& pass, const QByteArray& identityKey)
{
    using p2p::bridge::toBytes;
    m_crypto.setPassphrase(pass.toStdString());
    m_crypto.ensureIdentity(toBytes(identityKey));
}

void ChatController::setRelayUrl(const QUrl& url)
{
    m_relay.setRelayUrl(url.toString().toStdString());
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

    // When SessionManager needs to send a handshake response, seal it and enqueue
    m_sessionMgr->setSendResponseFn([this](const std::string& peerIdStd, const Bytes& blob) {
        using namespace p2p::bridge;
        const QString peerId = QString::fromStdString(peerIdStd);
        // Convert peer's Ed25519 pub to X25519 for sealing
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerIdStd);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0) return;

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        QByteArray peerKemPub = lookupPeerKemPub(peerId);
        QByteArray sealed = toQByteArray(SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            blob, toBytes(peerKemPub),
            m_crypto.dsaPub(), m_crypto.dsaPriv()));
        if (sealed.isEmpty()) return;
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND MAILBOX] sealed handshake response to" << peerId.left(8) + "..."
                 << (peerKemPub.isEmpty() ? "(classical)" : "(hybrid PQ)");
#endif

        QByteArray inner = kSealedPrefix + "\n" + sealed;
        QByteArray env = toQByteArray(
            SealedEnvelope::wrapForRelay(peerEdPub, toBytes(inner)));
        m_relay.sendEnvelope(p2p::bridge::toBytes(env));
    });

    // M2 fix: Seal callback for file chunks — FTM now speaks std types.
    m_fileMgr.setSealFn([this](const std::string& peerIdStd,
                               const FileTransferManager::Bytes& payload)
                              -> FileTransferManager::Bytes {
        using namespace p2p::bridge;
        const QString peerId = QString::fromStdString(peerIdStd);
        Bytes peerEdPub = CryptoEngine::fromBase64Url(peerIdStd);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
            return {};

        Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
        sodium_memzero(peerCurvePub, sizeof(peerCurvePub));
        QByteArray peerKemPub = lookupPeerKemPub(peerId);
        Bytes sealed = SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            payload, toBytes(peerKemPub),
            m_crypto.dsaPub(), m_crypto.dsaPriv());
        if (sealed.empty()) return {};

        // Inner wire: kSealedFCPrefix + "\n" + sealed
        Bytes inner;
        inner.reserve(kSealedFCPrefix.size() + 1 + sealed.size());
        inner.insert(inner.end(),
                     reinterpret_cast<const uint8_t*>(kSealedFCPrefix.constData()),
                     reinterpret_cast<const uint8_t*>(kSealedFCPrefix.constData())
                        + kSealedFCPrefix.size());
        inner.push_back('\n');
        inner.insert(inner.end(), sealed.begin(), sealed.end());

        return SealedEnvelope::wrapForRelay(peerEdPub, inner);
    });
#ifdef PEER2PEAR_P2P
    // QUIC P2P file send callback: try sending file chunks directly via QUIC stream
    m_fileMgr.setP2PFileSendFn([this](const std::string& peerIdStd,
                                       const FileTransferManager::Bytes& data) -> bool {
        const QString peerId = QString::fromStdString(peerIdStd);
        if (m_p2pConnections.contains(peerId) &&
            m_p2pConnections[peerId]->isReady() &&
            m_p2pConnections[peerId]->quicActive()) {
            m_p2pConnections[peerId]->sendFileData(p2p::bridge::toQByteArray(data));
            return true;
        }
        return false;  // fall back to mailbox
    });
#endif

}

QString ChatController::myIdB64u() const
{
    return QString::fromStdString(CryptoEngine::toBase64Url(m_crypto.identityPub()));
}

void ChatController::sendText(const QString& peerIdB64u, const QString& text)
{
    QJsonObject payload;
    payload["from"]  = myIdB64u();
    payload["type"]  = "text";
    payload["text"]  = text;
    payload["ts"]    = QDateTime::currentSecsSinceEpoch();
    payload["msgId"] = QUuid::createUuid().toString(QUuid::WithoutBraces);

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);

    // ── Sealed path (always required for text) ──────────────────────────────
    QByteArray sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.isEmpty()) {
        qWarning() << "[SEND] BLOCKED — cannot seal text to" << peerIdB64u.left(8) + "...";
        if (onStatus) onStatus("Message not sent — encrypted session unavailable. Try again shortly.");
        return;
    }

#ifdef PEER2PEAR_P2P
    if (m_p2pConnections.contains(peerIdB64u) &&
        m_p2pConnections[peerIdB64u]->isReady()) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND P2P] sealed text to" << peerIdB64u.left(8) + "...";
#endif
        m_p2pConnections[peerIdB64u]->sendData(sealedEnv);
    } else
#endif
    {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND RELAY] sealed text to" << peerIdB64u.left(8) + "...";
#endif
        m_relay.sendEnvelope(p2p::bridge::toBytes(sealedEnv));
#ifdef PEER2PEAR_P2P
        initiateP2PConnection(peerIdB64u);
#endif
    }
}

void ChatController::sendAvatar(const QString& peerIdB64u,
                                const QString& displayName,
                                const QString& avatarB64)
{
    QJsonObject payload;
    payload["from"]   = myIdB64u();
    payload["type"]   = "avatar";
    payload["name"]   = displayName;
    payload["avatar"] = avatarB64;
    sendSealedPayload(peerIdB64u, payload);   // S7 fix: use sealed path
}

// ── File transfer delegation ─────────────────────────────────────────────────

QString ChatController::sendFile(const QString& peerIdB64u,
                                 const QString& fileName,
                                 const QString& filePath)
{
    QFileInfo finfo(filePath);
    if (!finfo.exists() || !finfo.isFile()) {
        if (onStatus) onStatus(QString("File not found: %1").arg(filePath));
        return {};
    }
    const qint64 fileSize = finfo.size();
    if (fileSize > FileTransferManager::kMaxFileBytes) {
        if (onStatus) onStatus(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    // Streaming hash — one pass over the file, bounded RAM.
    const QByteArray fileHash = p2p::bridge::toQByteArray(
        FileTransferManager::blake2b256File(filePath.toStdString()));
    if (fileHash.size() != 32) {
        if (onStatus) onStatus(QString("Could not hash file: %1").arg(fileName));
        return {};
    }
    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Send file_key announcement through the ratchet to derive a forward-secret key.
    // The announcement now includes fileHash + chunkCount so the receiver can allocate
    // its partial-file bitmap and verify the final hash without waiting for every chunk's metadata.
    QJsonObject announce;
    announce["from"]        = myIdB64u();
    announce["type"]        = "file_key";
    announce["transferId"]  = transferId;
    announce["fileName"]    = fileName;
    announce["fileSize"]    = fileSize;
    announce["fileHash"]    = QString::fromStdString(CryptoEngine::toBase64Url(p2p::bridge::toBytes(fileHash)));
    announce["chunkCount"]  = chunkCount;
    announce["ts"]          = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt = QJsonDocument(announce).toJson(QJsonDocument::Compact);
    QByteArray sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.isEmpty()) {
        qWarning() << "[FILE] BLOCKED — cannot seal file_key for" << peerIdB64u.left(8) + "...";
        if (onStatus) onStatus("File not sent — encrypted session unavailable.");
        return {};
    }

    m_relay.sendEnvelope(p2p::bridge::toBytes(sealedEnv));

    QByteArray fileKey = p2p::bridge::toQByteArray(m_sessionMgr->lastMessageKey());
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
             << "to" << peerIdB64u.left(8) + "..." << "size=" << fileSize;
#endif

    // Phase 2: queue outbound state. Chunks don't fly until file_accept arrives.
    using p2p::bridge::toBytes;
    m_fileMgr.queueOutboundFile(myIdB64u().toStdString(),
                                 peerIdB64u.toStdString(),
                                 toBytes(fileKey),
                                 transferId.toStdString(),
                                 fileName.toStdString(),
                                 filePath.toStdString(),
                                 int64_t(fileSize),
                                 toBytes(fileHash));
    sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    return transferId;
}

QString ChatController::sendGroupFile(const QString& groupId,
                                      const QString& groupName,
                                      const QStringList& memberPeerIds,
                                      const QString& fileName,
                                      const QString& filePath)
{
    QFileInfo finfo(filePath);
    if (!finfo.exists() || !finfo.isFile()) {
        if (onStatus) onStatus(QString("File not found: %1").arg(filePath));
        return {};
    }
    const qint64 fileSize = finfo.size();
    if (fileSize > FileTransferManager::kMaxFileBytes) {
        if (onStatus) onStatus(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    // Hash the file once up-front (streaming) and reuse for all members.
    const QByteArray fileHash = p2p::bridge::toQByteArray(
        FileTransferManager::blake2b256File(filePath.toStdString()));
    if (fileHash.size() != 32) {
        if (onStatus) onStatus(QString("Could not hash file: %1").arg(fileName));
        return {};
    }
    const int chunkCount = int((fileSize + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    const QString myId = myIdB64u();
    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Per-member file_key announcement, then per-member streamed send.
    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == myId) continue;

        QJsonObject announce;
        announce["from"]        = myId;
        announce["type"]        = "file_key";
        announce["transferId"]  = transferId;
        announce["fileName"]    = fileName;
        announce["fileSize"]    = fileSize;
        announce["fileHash"]    = QString::fromStdString(CryptoEngine::toBase64Url(p2p::bridge::toBytes(fileHash)));
        announce["chunkCount"]  = chunkCount;
        announce["ts"]          = QDateTime::currentSecsSinceEpoch();
        announce["groupId"]     = groupId;
        announce["groupName"]   = groupName;

        const QByteArray pt = QJsonDocument(announce).toJson(QJsonDocument::Compact);
        QByteArray sealedEnv = sealForPeer(peerId, pt);
        if (sealedEnv.isEmpty()) {
            qWarning() << "[FILE] BLOCKED — cannot seal file_key for" << peerId.left(8) + "...";
            continue;
        }

        m_relay.sendEnvelope(p2p::bridge::toBytes(sealedEnv));

        QByteArray fileKey = p2p::bridge::toQByteArray(m_sessionMgr->lastMessageKey());
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
                 << "to" << peerId.left(8) + "..." << "(group)";
#endif

        // NOTE: Phase 2 intentionally does NOT gate group files on per-member
        // consent. Each group member would need an independent file_accept
        // roundtrip, which complicates the N-way announcement model. Group
        // files stream immediately (old behavior), 1:1 files use the consent
        // gate. Group-member consent is future work.
        m_fileMgr.sendFileWithKey(myId.toStdString(), peerId.toStdString(),
                                  p2p::bridge::toBytes(fileKey),
                                  transferId.toStdString(),
                                  fileName.toStdString(),
                                  filePath.toStdString(),
                                  int64_t(fileSize),
                                  p2p::bridge::toBytes(fileHash),
                                  groupId.toStdString(),
                                  groupName.toStdString());
        sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    }

    if (onStatus) onStatus(QString("'%1' streamed in %2 chunk(s) -> group %3")
                    .arg(fileName).arg(chunkCount).arg(groupName));
    return transferId;
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
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[ChatController] Relay connected, envelopes will be pushed.";
#endif
    if (onRelayConnected) onRelayConnected();

    // Phase 4: for each incomplete incoming transfer, tell the sender which
    // chunks we still need so they can re-send them.
    const auto pendings = m_fileMgr.pendingResumptions();
    for (const auto& pr : pendings) {
        QJsonArray chunks;
        for (uint32_t idx : pr.missingChunks) chunks.append(int(idx));
        QJsonObject msg;
        msg["type"]       = "file_request";
        msg["transferId"] = QString::fromStdString(pr.transferId);
        msg["chunks"]     = chunks;
        sendFileControlMessage(QString::fromStdString(pr.peerId), msg);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] requested resumption of"
                 << QString::fromStdString(pr.transferId).left(8)
                 << "from" << QString::fromStdString(pr.peerId).left(8) + "..."
                 << "missing" << int(pr.missingChunks.size()) << "chunks";
#endif
    }
}

void ChatController::subscribePresence(const QStringList& peerIds)
{
    std::vector<std::string> ids;
    ids.reserve(peerIds.size());
    for (const QString& id : peerIds) ids.push_back(id.toStdString());
    m_relay.subscribePresence(ids);
}

void ChatController::setSelfKeys(const QStringList& keys) { m_selfKeys = keys; }

#ifdef PEER2PEAR_P2P
void ChatController::setTurnServer(const QString& host, int port,
                                    const QString& username, const QString& password)
{
    m_turnHost = host;
    m_turnPort = port;
    m_turnUser = username;
    m_turnPass = password;
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[ChatController] TURN server set:" << host << ":" << port;
#endif
}
#endif

void ChatController::checkPresence(const QStringList& peerIds)
{
    std::vector<std::string> ids;
    ids.reserve(peerIds.size());
    for (const QString& id : peerIds) ids.push_back(id.toStdString());
    m_relay.queryPresence(ids);
}

// ── Phase 2: file-transfer consent / cancel ──────────────────────────────────

void ChatController::sendFileControlMessage(const QString& peerIdB64u,
                                             const QJsonObject& msg)
{
    // Include a fresh msgId so the receiver can dedup any duplicated delivery.
    QJsonObject payload = msg;
    payload["from"]  = myIdB64u();
    payload["ts"]    = QDateTime::currentSecsSinceEpoch();
    payload["msgId"] = QUuid::createUuid().toString(QUuid::WithoutBraces);

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    QByteArray sealed = sealForPeer(peerIdB64u, pt);
    if (sealed.isEmpty()) {
        qWarning() << "[FILE] BLOCKED — cannot seal" << msg.value("type").toString()
                   << "for" << peerIdB64u.left(8) + "...";
        return;
    }
    m_relay.sendEnvelope(p2p::bridge::toBytes(sealed));
}

void ChatController::acceptFileTransfer(const QString& transferId, bool requireP2P)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) {
        qWarning() << "[FILE] acceptFileTransfer: no pending transfer" << transferId.left(8);
        return;
    }

    const QString peerId   = it->peerId;
    const QString compound = peerId + ":" + transferId;

    // Fix #3: announce with the metadata locked from file_key time — NOT from
    // whatever the sender might put in later chunks.
    if (!m_fileMgr.announceIncoming(peerId.toStdString(),
                                      transferId.toStdString(),
                                      it->fileName.toStdString(),
                                      int64_t(it->fileSize), it->totalChunks,
                                      p2p::bridge::toBytes(it->fileHash),
                                      p2p::bridge::toBytes(it->fileKey),
                                      int64_t(it->announcedTs),
                                      it->groupId.toStdString(),
                                      it->groupName.toStdString())) {
        qWarning() << "[FILE] acceptFileTransfer: announceIncoming failed for"
                   << transferId.left(8);
        sodium_memzero(it->fileKey.data(), it->fileKey.size());
        m_pendingIncomingFiles.erase(it);
        return;
    }

    // Move the stashed key into the active file-keys map so chunks decrypt.
    m_fileKeys[compound] = it->fileKey;           // copy

    sodium_memzero(it->fileKey.data(), it->fileKey.size());
    m_pendingIncomingFiles.erase(it);

    QJsonObject msg;
    msg["type"]       = "file_accept";
    msg["transferId"] = transferId;
    // Respect the receiver's global "no relay" preference, or the per-call override.
    if (requireP2P || m_fileRequireP2P) msg["requireP2P"] = true;
    sendFileControlMessage(peerId, msg);
}

void ChatController::declineFileTransfer(const QString& transferId)
{
    auto it = m_pendingIncomingFiles.find(transferId);
    if (it == m_pendingIncomingFiles.end()) return;

    const QString peerId = it->peerId;
    sodium_memzero(it->fileKey.data(), it->fileKey.size());
    m_pendingIncomingFiles.erase(it);

    QJsonObject msg;
    msg["type"]       = "file_decline";
    msg["transferId"] = transferId;
    // NO reason field — see privacy mitigations §4 in the plan.
    sendFileControlMessage(peerId, msg);

    if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);  // receiver declined
}

void ChatController::cancelFileTransfer(const QString& transferId)
{
    // Figure out which role we hold for this transferId and clean up + notify.

    // Outbound pending (sender canceling a queued-but-unaccepted send)?
    const QString outboundPeer = QString::fromStdString(
        m_fileMgr.outboundPeerFor(transferId.toStdString()));
    if (!outboundPeer.isEmpty()) {
        m_fileMgr.abandonOutboundTransfer(transferId.toStdString());
        QJsonObject msg;
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(outboundPeer, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);  // sender-initiated
        return;
    }

    // Inbound, pre-accept (user changed mind before answering prompt)?
    auto itPending = m_pendingIncomingFiles.find(transferId);
    if (itPending != m_pendingIncomingFiles.end()) {
        const QString peerId = itPending->peerId;
        sodium_memzero(itPending->fileKey.data(), itPending->fileKey.size());
        m_pendingIncomingFiles.erase(itPending);
        QJsonObject msg;
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(peerId, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);   // receiver-initiated
        return;
    }

    // Inbound, in-progress (user canceled mid-stream)?
    const QString inboundPeer = QString::fromStdString(
        m_fileMgr.inboundPeerFor(transferId.toStdString()));
    if (!inboundPeer.isEmpty()) {
        m_fileMgr.cancelInboundTransfer(transferId.toStdString());
        QJsonObject msg;
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(inboundPeer, msg);
        if (onFileTransferCanceled) onFileTransferCanceled(transferId, true);
    }
}

void ChatController::sendGroupMessageViaMailbox(const QString& groupId,
                                                const QString& groupName,
                                                const QStringList& memberPeerIds,
                                                const QString& text)
{
    const QString myId  = myIdB64u();
    const qint64  ts    = QDateTime::currentSecsSinceEpoch();
    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    QJsonArray membersArray;
    for (const QString &key : memberPeerIds) {
        if (key.trimmed() == myId) continue;
        membersArray.append(key);
    }

    // G5 fix: monotonic per-group sequence counter
    const qint64 seq = ++m_groupSeqOut[groupId];

    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == myId) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_msg";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["text"]      = text;
        payload["ts"]        = ts;
        payload["msgId"]     = msgId;
        payload["seq"]       = seq;   // G5 fix

        const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QByteArray env = sealForPeer(peerId, pt);
        if (!env.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SEND MAILBOX] sealed group_msg to" << peerId.left(8) + "...";
#endif
            m_relay.sendEnvelope(p2p::bridge::toBytes(env));
        } else {
            qWarning() << "[SEND] BLOCKED — cannot seal group_msg to" << peerId.left(8) + "...";
        }
    }
}

void ChatController::sendGroupLeaveNotification(const QString& groupId,
                                                const QString& groupName,
                                                const QStringList& memberPeerIds)
{
    const QString myId = myIdB64u();
    const qint64 ts = QDateTime::currentSecsSinceEpoch();
    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Include member list so receivers can update their local group member list
    QJsonArray membersArray;
    for (const QString &key : memberPeerIds)
        membersArray.append(key);

    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty()) continue;
        if (peerId.trimmed() == myId) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_leave";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["ts"]        = ts;
        payload["msgId"]     = msgId;  // B2 fix: include msgId for dedup

        const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QByteArray env = sealForPeer(peerId, pt);
        if (!env.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SEND MAILBOX] sealed group_leave to" << peerId.left(8) + "...";
#endif
            m_relay.sendEnvelope(p2p::bridge::toBytes(env));
        } else {
            qWarning() << "[SEND] BLOCKED — cannot seal group_leave to" << peerId.left(8) + "...";
        }
    }
}

// ── Private ───────────────────────────────────────────────────────────────────

bool ChatController::markSeen(const QString& id)
{
    if (m_seenIds.contains(id)) return false;
    if (m_seenOrder.size() >= kSeenIdsCap) {
        const int prune = kSeenIdsCap / 2;
        for (int i = 0; i < prune; ++i) m_seenIds.remove(m_seenOrder[i]);
        m_seenOrder.remove(0, prune);
    }
    m_seenIds.insert(id);
    m_seenOrder.append(id);
    return true;
}

// pollOnce removed — relay pushes envelopes via WebSocket.
// Maintenance tasks (handshake pruning, file key cleanup) moved to m_maintenanceTimer.

// ── Core sealing primitive ────────────────────────────────────────────────────
// Returns the sealed envelope bytes (SEALED:<version>\n<ciphertext>), or empty
// on failure.  Every outbound path should call this instead of inlining the
// encrypt→convert→seal→prefix logic.
QByteArray ChatController::sealForPeer(const QString& peerIdB64u,
                                       const QByteArray& plaintext)
{
    if (!m_sessionMgr) return {};
    // Pass peer's KEM pub so SessionManager can do hybrid Noise handshake if available
    QByteArray peerKemPub = lookupPeerKemPub(peerIdB64u);
    QByteArray sessionBlob = p2p::bridge::toQByteArray(m_sessionMgr->encryptForPeer(
        peerIdB64u.toStdString(), p2p::bridge::toBytes(plaintext), p2p::bridge::toBytes(peerKemPub)));
    if (sessionBlob.isEmpty()) return {};

    using namespace p2p::bridge;
    QByteArray peerEdPub = toQByteArray(CryptoEngine::fromBase64Url(peerIdB64u.toStdString()));
    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(
            peerCurvePub,
            reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0)
        return {};

    QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
    sodium_memzero(peerCurvePub, sizeof(peerCurvePub));  // G11 fix

    // Use hybrid seal if we know the peer's ML-KEM-768 public key (already looked up above)
    // Include ML-DSA-65 signature if we have DSA keys.
    // Bridge Qt ↔ std while SealedEnvelope is migrated (REFACTOR_PLAN.md).
    QByteArray sealed = toQByteArray(SealedEnvelope::seal(
        toBytes(recipientCurvePub), toBytes(peerEdPub),
        m_crypto.identityPub(), m_crypto.identityPriv(),
        toBytes(sessionBlob), toBytes(peerKemPub),
        m_crypto.dsaPub(), m_crypto.dsaPriv()));
    if (sealed.isEmpty()) return {};

    QByteArray inner = kSealedPrefix + "\n" + sealed;

    // Wrap with relay routing header so /v1/send can route anonymously
    return toQByteArray(SealedEnvelope::wrapForRelay(toBytes(peerEdPub), toBytes(inner)));
}

// ── S3/S7/S8 fix: Sealed payload via mailbox, fail-closed ───────────────────
void ChatController::sendSealedPayload(const QString& peerIdB64u,
                                       const QJsonObject& payload)
{
    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QString type = payload.value("type").toString();

    QByteArray env = sealForPeer(peerIdB64u, pt);
    if (!env.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND MAILBOX]" << type << "to" << peerIdB64u.left(8) + "...";
#endif
        m_relay.sendEnvelope(p2p::bridge::toBytes(env));
        return;
    }

    // Fail closed.  The old ICE-signaling fallback used the legacy
    // /mbox/enqueue endpoint with a plain-text ICE message wrapped only by
    // an AEAD keyed on a static DH secret — that endpoint is being removed
    // and the plaintext leak was always a privacy concern.  ICE messages
    // now go through the same sealed path as everything else; if the ratchet
    // can't seal, we defer the handshake instead of leaking SDP/IP candidates.
    qWarning() << "[SEND] BLOCKED — cannot seal" << type
               << "to" << peerIdB64u.left(8) + "...";
}

#ifdef PEER2PEAR_P2P
// ── QUIC + ICE connection setup ──────────────────────────────────────────────
QuicConnection* ChatController::setupP2PConnection(const QString& peerIdB64u, bool controlling)
{
    // ChatController isn't a QObject anymore (Phase 7b).  QuicConnection is
    // a QObject, so we pass nullptr for parent and lifetime-manage via
    // m_p2pConnections + deleteLater() in runMaintenance().
    //
    // Signal connects below use `conn` as the receiver so the connection
    // lifetime tracks the QuicConnection itself — when it's deleteLater'd,
    // all lambdas capturing `this` stop firing.
    QuicConnection* conn = new QuicConnection(nullptr);
    if (!m_turnHost.isEmpty())
        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
    m_p2pConnections[peerIdB64u] = conn;
    m_p2pCreatedSecs[peerIdB64u] = QDateTime::currentSecsSinceEpoch();

    const QString iceType = controlling ? "ice_offer" : "ice_answer";
    QObject::connect(conn, &QuicConnection::localSdpReady, conn,
            [this, peerIdB64u, iceType, conn](const QString& sdp) {
        QJsonObject p;
        p["type"] = iceType;
        p["from"] = myIdB64u();
        p["sdp"]  = sdp;
        p["quic"] = true;
        p["quic_fingerprint"] = conn->localQuicFingerprint();
        sendSealedPayload(peerIdB64u, p);
    });
    QObject::connect(conn, &QuicConnection::stateChanged, conn,
            [this, peerIdB64u, conn](int state) {
        if (state == NICE_COMPONENT_STATE_READY) {
            const QString mode = conn->quicActive() ? "QUIC" : "ICE";
            if (onStatus) onStatus("P2P ready (" + mode + ") with " + peerIdB64u);
            m_fileMgr.notifyP2PReady(peerIdB64u.toStdString());
        } else if (state == NICE_COMPONENT_STATE_FAILED) {
            if (onStatus) onStatus("P2P failed for " + peerIdB64u);
        }
    });
    QObject::connect(conn, &QuicConnection::dataReceived, conn,
            [this, peerIdB64u](const QByteArray& d) {
        onP2PDataReceived(peerIdB64u, d);
    });
    QObject::connect(conn, &QuicConnection::fileDataReceived, conn,
            [this, peerIdB64u](const QByteArray& d) {
        m_fileMgr.handleFileEnvelope(peerIdB64u.toStdString(),
            p2p::bridge::toBytes(d),
            [this](const std::string& id) { return markSeen(QString::fromStdString(id)); },
            toStdFileKeys(m_fileKeys));
    });
    conn->initIce(controlling);
    return conn;
}

void ChatController::initiateP2PConnection(const QString& peerIdB64u)
{
    if (m_p2pConnections.contains(peerIdB64u)) return;
    setupP2PConnection(peerIdB64u, true);
}

void ChatController::onP2PDataReceived(const QString& peerIdB64u, const QByteArray& data)
{
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[ChatController] P2P data received from" << peerIdB64u.left(8) + "..."
             << "| size:" << data.size() << "B";
#endif

    // P2P data proves the peer is online right now
    if (onPresenceChanged) onPresenceChanged(peerIdB64u, true);

    // ── Sealed envelope over P2P ─────────────────────────────────────────────
    if (data.startsWith(kSealedPrefix) || data.startsWith(kSealedFCPrefix)) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV P2P] sealed envelope from" << peerIdB64u.left(8) + "...";
#endif
        onEnvelope(data);
        return;
    }

    // ── File chunk received over P2P (legacy) ────────────────────────────────
    if (data.startsWith(kFilePrefix)) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV P2P] file chunk from" << peerIdB64u.left(8) + "...";
#endif
        onEnvelope(data);
        return;
    }

    // ── Try ratchet decrypt first (P2P with session) ─────────────────────────
    if (m_sessionMgr && m_sessionMgr->hasSession(peerIdB64u.toStdString())) {
        QByteArray pt = p2p::bridge::toQByteArray(m_sessionMgr->decryptFromPeer(
            peerIdB64u.toStdString(), p2p::bridge::toBytes(data)));
        if (!pt.isEmpty()) {
            const auto o = QJsonDocument::fromJson(pt).object();
            if (o.value("type").toString() == "text") {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV P2P] ratchet text from" << peerIdB64u.left(8) + "...";
#endif
                const QString msgId = o.value("msgId").toString();
                if (!msgId.isEmpty() && !markSeen(msgId)) return;
                if (onMessageReceived) onMessageReceived(peerIdB64u, o.value("text").toString(),
                                     tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
            }
            return;
        }
    }

    // ── Legacy encrypted JSON message ────────────────────────────────────────
    // SEC3: This path uses a static ECDH key with NO forward secrecy.
    // It exists for backward compatibility but should be disabled once
    // all peers support sealed/ratchet messaging.
    qWarning() << "[RECV P2P] legacy path (no forward secrecy) from"
               << peerIdB64u.left(8) + "... — peer should upgrade";
    using namespace p2p::bridge;
    const Bytes peerPub = CryptoEngine::fromBase64Url(peerIdB64u.toStdString());
    const QByteArray pt = toQByteArray(
        m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), toBytes(data)));
    if (pt.isEmpty()) return;

    const auto o = QJsonDocument::fromJson(pt).object();
    if (o.value("type").toString() != "text") return;

    const QString msgId = o.value("msgId").toString();
    if (!msgId.isEmpty() && !markSeen(msgId)) return;

    if (onMessageReceived) onMessageReceived(peerIdB64u, o.value("text").toString(),
                         tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
}
#endif // PEER2PEAR_P2P

void ChatController::onEnvelope(const QByteArray& body)
{
    // Envelopes arrive via WebSocket push — no ACK needed, the relay
    // deletes stored envelopes on delivery.
    const QString via = QStringLiteral("RELAY");

    // Strip relay routing header if present (0x01 || recipientEdPub(32) || inner)
    // Bridge Qt ↔ std while SealedEnvelope is migrated (REFACTOR_PLAN.md).
    const QByteArray data = [&]() -> QByteArray {
        if (!body.isEmpty() && static_cast<quint8>(body[0]) == 0x01 && body.size() > 33) {
            QByteArray inner = p2p::bridge::toQByteArray(
                SealedEnvelope::unwrapFromRelay(p2p::bridge::toBytes(body)));
            if (!inner.isEmpty()) return inner;
        }
        return body;
    }();

    const int nl = data.indexOf('\n');
    if (nl < 0) return;

    const QByteArray header = data.left(nl);
    const QByteArray rest   = data.mid(nl + 1);

    // ── Sealed sender envelope ───────────────────────────────────────────────
    if (header.startsWith(kSealedPrefix) || header.startsWith(kSealedFCPrefix)) {
        const bool isFileChunk = header.startsWith(kSealedFCPrefix);

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] sealed envelope | size:" << rest.size() << "B"
                 << (isFileChunk ? "(file chunk)" : "");
#endif

        // Unseal to learn sender identity (pass KEM priv for hybrid PQ envelopes).
        // Binding recipientEdPub (our own identity) into AEAD AAD — if a relay
        // rewrote the outer routing pubkey, AEAD fails.
        using p2p::bridge::toBytes;
        UnsealResult unsealed = SealedEnvelope::unseal(
            m_crypto.curvePriv(), m_crypto.identityPub(),
            toBytes(rest), m_crypto.kemPriv());
        if (!unsealed.valid) {
            qWarning() << "[ChatController] Failed to unseal envelope";
            return;
        }

        // Bridge unseal result fields back to QByteArray — see REFACTOR_PLAN.md.
        // These wrappers disappear when the consumers (SessionManager /
        // FileTransferManager / CryptoEngine) migrate off Qt.
        const QByteArray unsealedSenderEdPub  = p2p::bridge::toQByteArray(unsealed.senderEdPub);
        const QByteArray unsealedInnerPayload = p2p::bridge::toQByteArray(unsealed.innerPayload);
        const QByteArray unsealedEnvelopeId   = p2p::bridge::toQByteArray(unsealed.envelopeId);

        // Envelope-level replay protection (Fix #2): dedup on envelopeId.
        // The ratchet dedups its own chain messages, but control messages
        // outside the ratchet (file_accept, file_cancel, etc.) don't have that
        // protection. A malicious relay could redeliver the same sealed blob
        // and the receiver would happily reprocess it.
        if (unsealedEnvelopeId.size() == 16) {
            const QString envKey = "env:" + QString::fromStdString(
                CryptoEngine::toBase64Url(p2p::bridge::toBytes(unsealedEnvelopeId)));
            if (!markSeen(envKey)) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV" << via << "] dropping replayed envelope"
                         << envKey.mid(4, 8) + "...";
#endif
                return;
            }
        }

        QString senderId = QString::fromStdString(
            CryptoEngine::toBase64Url(p2p::bridge::toBytes(unsealedSenderEdPub)));
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] unsealed OK | sender:" << senderId.left(8) + "..."
                 << "| inner:" << unsealedInnerPayload.size() << "B";
#endif

        // H3 fix: rate limit per sender to prevent CPU exhaustion via envelope flooding
        int& count = m_envelopeCount[senderId];
        if (++count > kMaxEnvelopesPerSenderPerPoll) {
            if (count == kMaxEnvelopesPerSenderPerPoll + 1)
                qWarning() << "[RECV] rate limit hit for" << senderId.left(8) + "..."
                           << "— dropping further envelopes this cycle";
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
            const QString senderPrefix = senderId + ":";
            for (auto it = m_fileKeys.constBegin(); it != m_fileKeys.constEnd(); ++it) {
                if (it.key().startsWith(senderPrefix)) {
                    hasKeyFromSender = true;
                    break;
                }
            }
            if (!hasKeyFromSender) {
                qWarning() << "[RECV" << via << "] sealed file chunk from" << senderId.left(8) + "..."
                           << "— no file_key on record, dropping";
                return;
            }

#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[RECV" << via << "] sealed file chunk from" << senderId.left(8) + "...";
#endif
            m_fileMgr.handleFileEnvelope(senderId.toStdString(),
                p2p::bridge::toBytes(unsealedInnerPayload),
                [this](const std::string& id) { return markSeen(QString::fromStdString(id)); },
                toStdFileKeys(m_fileKeys));
            return;
        }

        if (!m_sessionMgr) return; // can't process without session manager

        // Only emit "online" if the envelope is recent (within 2 minutes).
        // Old mailbox messages should not trigger false online presence.  (L3 fix)
        // Note: sealed envelopes carry no timestamp, so we infer freshness from
        // the transport — P2P is always live; mailbox may have stale messages.
        if (via == "P2P") if (onPresenceChanged) onPresenceChanged(senderId, true);

        // Decrypt session layer (Noise handshake or ratchet message)
        Bytes msgKeyB;  // M3 fix: capture message key directly from decrypt
        Bytes ptB = m_sessionMgr->decryptFromPeer(senderId.toStdString(),
            p2p::bridge::toBytes(unsealedInnerPayload), &msgKeyB);
        QByteArray msgKey = p2p::bridge::toQByteArray(msgKeyB);
        QByteArray pt     = p2p::bridge::toQByteArray(ptB);
        if (pt.isEmpty()) {
            // Pre-key response (0x02) completes the Noise IK handshake and creates
            // a ratchet session inside decryptFromPeer(), but returns no user payload.
            // This is expected — future messages will use the ratchet session.
            const quint8 innerType = unsealedInnerPayload.isEmpty() ? 0 : static_cast<quint8>(unsealedInnerPayload[0]);
            if (innerType == SessionManager::kPreKeyResponse || innerType == SessionManager::kHybridPreKeyResp) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV" << via << "] handshake COMPLETED with" << senderId.left(8) + "...";
#endif
                // SEC9: handshake succeeded — clear failure counter
                m_handshakeFailCount.remove(senderId);

                // Announce our PQ KEM pub now that we have an authenticated channel
                announceKemPub(senderId);

            } else {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV" << via << "] session decrypt empty from" << senderId.left(8) + "...";
#endif
            }
            return;
        }

        // Dispatch based on the decrypted JSON payload
        // (same logic as legacy message handling below)
        const auto o = QJsonDocument::fromJson(pt).object();
        const QString type = o.value("type").toString();

        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsFromSecs(tsSecs);
        const QString msgId = o.value("msgId").toString();

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] sealed type:" << type << "from" << senderId.left(8) + "...";
#endif

        if (type == "text") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;
            if (onMessageReceived) onMessageReceived(senderId, o.value("text").toString(), ts, msgId);
        } else if (type == "group_msg") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;

            // G5 fix: sequence gap detection
            const QString gid = o.value("groupId").toString();
            if (o.contains("seq")) {
                const qint64 seq = o.value("seq").toVariant().toLongLong();
                const QString seqKey = gid + ":" + senderId;
                if (m_groupSeqIn.contains(seqKey)) {
                    const qint64 expected = m_groupSeqIn[seqKey] + 1;
                    if (seq > expected)
                        qWarning() << "[GROUP] seq gap from" << senderId.left(8) + "..."
                                   << "in" << gid.left(8) + "..."
                                   << "expected" << expected << "got" << seq;
                }
                m_groupSeqIn[seqKey] = seq;
            }

            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();

            // Fix #20: a valid sealed group_msg from X about group G adds X
            // (and the declared members) to our roster — this is ground
            // truth because the message is already authenticated.  We still
            // require sender ∈ members to avoid rogue "I'm messaging this
            // group but I'm not in it" bootstraps.
            if (!gid.isEmpty() && !senderId.isEmpty()) {
                if (!m_groupMembers.contains(gid)) {
                    // Bootstrap: accept only if sender includes themselves.
                    if (memberKeys.contains(senderId)) {
                        m_groupMembers[gid] =
                            QSet<QString>(memberKeys.begin(), memberKeys.end());
                    }
                } else {
                    m_groupMembers[gid].insert(senderId);
                }
            }

            if (onGroupMessageReceived) onGroupMessageReceived(senderId, gid,
                                       o.value("groupName").toString(),
                                       memberKeys, o.value("text").toString(), ts, msgId);
        } else if (type == "group_leave") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B2 fix: dedup
            const QString gid = o.value("groupId").toString();
            // Fix #20: a leave message may ONLY be self-leave — senders can't
            // announce that OTHER members left.  And the sender must have been
            // a known member of the group.
            if (!gid.isEmpty() && !isAuthorizedGroupSender(gid, senderId)) {
                qWarning() << "[GROUP] dropping group_leave from non-member"
                           << senderId.left(8) + "... for" << gid.left(8);
                return;
            }
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();
            // The sender left — strike them from our roster so they can't push
            // further member-update / rename / avatar messages afterwards.
            if (m_groupMembers.contains(gid))
                m_groupMembers[gid].remove(senderId);
            if (onGroupMemberLeft) onGroupMemberLeft(senderId, gid,
                                  o.value("groupName").toString(), memberKeys, ts, msgId);
        } else if (type == "avatar") {
            if (onAvatarReceived) onAvatarReceived(senderId, o.value("name").toString(), o.value("avatar").toString());
        } else if (type == "group_rename") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const QString gid = o.value("groupId").toString();
            if (!gid.isEmpty() && !isAuthorizedGroupSender(gid, senderId)) {
                qWarning() << "[GROUP] dropping group_rename from non-member"
                           << senderId.left(8) + "... for" << gid.left(8);
                return;
            }
            if (onGroupRenamed) onGroupRenamed(gid, o.value("newName").toString());
        } else if (type == "group_avatar") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const QString gid = o.value("groupId").toString();
            if (!gid.isEmpty() && !isAuthorizedGroupSender(gid, senderId)) {
                qWarning() << "[GROUP] dropping group_avatar from non-member"
                           << senderId.left(8) + "... for" << gid.left(8);
                return;
            }
            if (onGroupAvatarReceived) onGroupAvatarReceived(gid, o.value("avatar").toString());
        } else if (type == "group_member_update") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B3 fix: dedup
            const QString gid       = o.value("groupId").toString();
            const QString gname     = o.value("groupName").toString();
            // Fix #20: reject member-list updates from peers that aren't
            // currently in our roster.  First-sight of a new group bootstraps
            // from the sender's proposed list only if the sender names
            // themselves as a member.
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();

            if (!gid.isEmpty()) {
                const bool bootstrap = m_groupBootstrapNeeded.contains(gid)
                                       || !m_groupMembers.contains(gid);
                if (bootstrap) {
                    // Sender must include themselves in the proposed list.
                    if (!memberKeys.contains(senderId)) {
                        qWarning() << "[GROUP] rejecting bootstrap group_member_update"
                                   << "from" << senderId.left(8) + "..."
                                   << "— sender not in proposed member list";
                        return;
                    }
                    m_groupMembers[gid] = QSet<QString>(memberKeys.begin(), memberKeys.end());
                    m_groupBootstrapNeeded.remove(gid);
                } else if (!m_groupMembers[gid].contains(senderId)) {
                    qWarning() << "[GROUP] dropping group_member_update from non-member"
                               << senderId.left(8) + "... for" << gid.left(8);
                    return;
                } else {
                    // Authorized update: merge in new members (conservative —
                    // we don't accept REMOVALS via this message type, only adds).
                    for (const QString& m : memberKeys)
                        m_groupMembers[gid].insert(m);
                }
            }

            // Re-use the existing groupMessageReceived signal — the
            // ChatView::onIncomingGroupMessage handler already merges new
            // member keys into the group's key list.
            // Empty text means no chat bubble appears, but the key merge still happens.
            if (onGroupMessageReceived) onGroupMessageReceived(senderId, gid, gname, memberKeys,
                                      QString(), ts,
                                      msgId.isEmpty() ? QUuid::createUuid().toString(QUuid::WithoutBraces) : msgId);
#ifdef PEER2PEAR_P2P
        } else if (type == "ice_offer") {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[RECV" << via << "] ice_offer from" << senderId.left(8) + "...";
#endif
            // Skip if we already have a working P2P connection
            if (m_p2pConnections.contains(senderId) &&
                m_p2pConnections[senderId]->isReady()) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[ICE] Already connected to" << senderId.left(8) + "... — ignoring ice_offer";
#endif
            } else {
                if (!m_p2pConnections.contains(senderId))
                    setupP2PConnection(senderId, false);
                // Pass QUIC capability from signaling
                if (o.value("quic").toBool()) {
                    m_p2pConnections[senderId]->setPeerSupportsQuic(
                        true, o.value("quic_fingerprint").toString());
                }
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
            }
        } else if (type == "ice_answer") {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[RECV" << via << "] ice_answer from" << senderId.left(8) + "...";
#endif
            if (m_p2pConnections.contains(senderId) &&
                !m_p2pConnections[senderId]->isReady()) {
                if (o.value("quic").toBool()) {
                    m_p2pConnections[senderId]->setPeerSupportsQuic(
                        true, o.value("quic_fingerprint").toString());
                }
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
            }
#endif // PEER2PEAR_P2P
        } else if (type == "file_key") {
            // File key announcement. Phase 2: evaluate consent policy BEFORE
            // installing the key. Chunks that arrive before the user accepts
            // will fail to find a matching key and be dropped silently.
            const QString transferId = o.value("transferId").toString();
            const QString fileName   = o.value("fileName").toString("file");
            const qint64  fileSize   = o.value("fileSize").toVariant().toLongLong();
            const QString gId        = o.value("groupId").toString();
            const QString gName      = o.value("groupName").toString();

            if (transferId.isEmpty() || msgKey.size() != 32) {
                sodium_memzero(msgKey.data(), msgKey.size());
                return;
            }

            const QString compoundKey = senderId + ":" + transferId;

            // Evaluate global size policy.  Fix #6: the same thresholds apply
            // whether the file is 1:1 or group-scoped — previously group files
            // auto-accepted regardless, which let any group member push up to
            // the hard-max bytes to disk without the user's consent.
            // (Per-contact policy will be layered on top in a follow-up.)
            const qint64 fileSizeMB = fileSize / (1024 * 1024);
            bool autoAccept = false;
            bool autoDecline = false;
            if (fileSize > qint64(m_fileHardMaxMB) * 1024 * 1024) {
                autoDecline = true;
            } else if (fileSize <= qint64(m_fileAutoAcceptMaxMB) * 1024 * 1024) {
                autoAccept = true;
            }

            if (autoDecline) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[FILE] auto-decline" << fileName << "(" << fileSizeMB << "MB )"
                         << "from" << senderId.left(8) + "... — exceeds hard max";
#endif
                QJsonObject declineMsg;
                declineMsg["type"]       = "file_decline";
                declineMsg["transferId"] = transferId;
                sendFileControlMessage(senderId, declineMsg);
                sodium_memzero(msgKey.data(), msgKey.size());
            } else if (autoAccept) {
                // Fix #3: announce the transfer to FileTransferManager FIRST so
                // it locks the announced fileSize/totalChunks/fileHash. Chunks
                // with mismatched metadata will be dropped.
                const QByteArray announcedHash = p2p::bridge::toQByteArray(
                    CryptoEngine::fromBase64Url(o.value("fileHash").toString().toStdString()));
                const int announcedChunkCount = o.value("chunkCount").toInt(0);
                const qint64 announcedTs      = o.value("ts").toVariant().toLongLong();

                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    qWarning() << "[FILE] missing fileHash/chunkCount on file_key for"
                               << transferId.left(8) << "— dropping";
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                if (!m_fileMgr.announceIncoming(senderId.toStdString(),
                                                  transferId.toStdString(),
                                                  fileName.toStdString(),
                                                  int64_t(fileSize), announcedChunkCount,
                                                  p2p::bridge::toBytes(announcedHash),
                                                  p2p::bridge::toBytes(msgKey),
                                                  int64_t(announcedTs),
                                                  gId.toStdString(), gName.toStdString())) {
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                // Install key so chunks can decrypt.
                m_fileKeys[compoundKey] = msgKey;  // M3+M4 fix
                sodium_memzero(msgKey.data(), msgKey.size());

                QJsonObject acceptMsg;
                acceptMsg["type"]       = "file_accept";
                acceptMsg["transferId"] = transferId;
                if (m_fileRequireP2P) acceptMsg["requireP2P"] = true;
                sendFileControlMessage(senderId, acceptMsg);

#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[FILE] auto-accept" << fileName << "(" << fileSizeMB << "MB)"
                         << "from" << senderId.left(8) + "...";
#endif
            } else {
                // Stash in pending — don't install key yet. User will accept/decline.
                // Fix #3: lock announced hash/chunkCount/ts now so acceptFileTransfer
                // can pass them to announceIncoming() unchanged.
                const QByteArray announcedHash = p2p::bridge::toQByteArray(
                    CryptoEngine::fromBase64Url(o.value("fileHash").toString().toStdString()));
                const int announcedChunkCount = o.value("chunkCount").toInt(0);
                const qint64 announcedTs      = o.value("ts").toVariant().toLongLong();
                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    qWarning() << "[FILE] missing fileHash/chunkCount on file_key for"
                               << transferId.left(8) << "— dropping";
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                PendingIncoming p;
                p.peerId         = senderId;
                p.fileName       = fileName;
                p.fileSize       = fileSize;
                p.fileKey        = QByteArray(msgKey.constData(), msgKey.size());
                p.fileHash       = announcedHash;
                p.totalChunks    = announcedChunkCount;
                p.announcedTs    = announcedTs;
                p.groupId        = gId;
                p.groupName      = gName;
                p.announcedSecs  = QDateTime::currentSecsSinceEpoch();
                m_pendingIncomingFiles.insert(transferId, p);
                sodium_memzero(msgKey.data(), msgKey.size());

#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[FILE] prompt needed for" << fileName << "(" << fileSizeMB << "MB)"
                         << "from" << senderId.left(8) + "...";
#endif
                if (onFileAcceptRequested) onFileAcceptRequested(senderId, transferId, fileName, fileSize);
            }

        } else if (type == "file_accept") {
            // Sender-side: receiver agreed to the transfer.
            const QString transferId = o.value("transferId").toString();
            const bool requireP2P    = o.value("requireP2P").toBool(false);
            if (!transferId.isEmpty()) {
                // Sender's side of the "no relay" preference (global toggle).
                // Desktop surfaces this via the "Require direct connection"
                // setting too — not privacy-level yet; that can come later.
                const bool senderRequiresP2P = m_fileRequireP2P;

                // Is P2P ready for this peer right now?
                bool p2pReady = false;
#ifdef PEER2PEAR_P2P
                if (m_p2pConnections.contains(senderId) &&
                    m_p2pConnections[senderId]->isReady()) {
                    p2pReady = true;
                }
#endif

                if (!m_fileMgr.startOutboundStream(transferId.toStdString(), requireP2P,
                                                    senderRequiresP2P, p2pReady)) {
                    qWarning() << "[FILE] file_accept for unknown transferId"
                               << transferId.left(8);
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
            const QString transferId = o.value("transferId").toString();
            if (!transferId.isEmpty()) {
                m_fileMgr.abandonOutboundTransfer(transferId.toStdString());
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, true); // byReceiver
                if (onStatus) onStatus("File transfer declined by recipient.");
            }

        } else if (type == "file_ack") {
            // Sender-side: receiver confirmed delivery + hash ok.
            const QString transferId = o.value("transferId").toString();
            if (!transferId.isEmpty()) {
                if (onFileTransferDelivered) onFileTransferDelivered(transferId);
                // Phase 4: drop sender-side state now that the transfer is acked.
                m_fileMgr.forgetSentTransfer(transferId.toStdString());
            }

        } else if (type == "file_request") {
            // Receiver is asking us (sender) to re-send these chunk indices.
            // Phase 4 resumption path.
            const QString transferId = o.value("transferId").toString();
            const QJsonArray chunksArr = o.value("chunks").toArray();
            if (transferId.isEmpty() || chunksArr.isEmpty()) return;
            std::vector<uint32_t> indices;
            indices.reserve(size_t(chunksArr.size()));
            for (const QJsonValue& v : chunksArr) {
                const int i = v.toInt(-1);
                if (i >= 0) indices.push_back(uint32_t(i));
            }
            if (!m_fileMgr.resendChunks(transferId.toStdString(), indices)) {
                qWarning() << "[FILE] file_request for unknown transferId"
                           << transferId.left(8) + "...";
            }

        } else if (type == "file_cancel") {
            // Either side: the peer canceled. Figure out which role we're in.
            const QString transferId = o.value("transferId").toString();
            if (transferId.isEmpty()) return;

            // Outbound (we're the sender)?
            if (!m_fileMgr.outboundPeerFor(transferId.toStdString()).empty()) {
                m_fileMgr.abandonOutboundTransfer(transferId.toStdString());
                // Phase 4: also drop the sent-transfer DB row in case we were mid-stream.
                m_fileMgr.forgetSentTransfer(transferId.toStdString());
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, true); // canceled by receiver
                return;
            }
            // Also handle "sender was already streaming when receiver canceled":
            // m_outboundPending is empty, but m_sentTransfers has the record.
            m_fileMgr.forgetSentTransfer(transferId.toStdString());

            // Inbound pending (we were about to prompt)?
            auto itPending = m_pendingIncomingFiles.find(transferId);
            if (itPending != m_pendingIncomingFiles.end()) {
                sodium_memzero(itPending->fileKey.data(), itPending->fileKey.size());
                m_pendingIncomingFiles.erase(itPending);
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, false); // sender canceled
                return;
            }
            // Inbound in-progress (sender pulled the plug mid-stream)?
            if (!m_fileMgr.inboundPeerFor(transferId.toStdString()).empty()) {
                m_fileMgr.cancelInboundTransfer(transferId.toStdString());
                if (onFileTransferCanceled) onFileTransferCanceled(transferId, false);
            }

        } else if (type == "kem_pub_announce") {
            // Post-quantum KEM public key exchange — store the peer's ML-KEM-768 pub
            QByteArray kemPub = p2p::bridge::toQByteArray(
                CryptoEngine::fromBase64Url(o.value("kem_pub_b64u").toString().toStdString()));
            if (kemPub.size() == 1184) {  // ML-KEM-768 pub key size
                m_peerKemPubs[senderId] = kemPub;
                // Persist to DB
                if (m_dbPtr && m_dbPtr->isOpen()) {
                    SqlCipherQuery q(*m_dbPtr);
                    q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:pid;");
                    q.bindValue(":kp",  p2p::bridge::toBytes(kemPub));
                    q.bindValue(":pid", senderId.toStdString());
                    q.exec();
                }
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[PQ] Stored ML-KEM-768 pub from" << senderId.left(8) + "..."
                         << "| hybrid sealing now active for this peer";
#endif
                // Reciprocate: send our KEM pub back if we haven't already
                if (m_crypto.hasPQKeys() && !lookupPeerKemPub(senderId).isEmpty()) {
                    // They sent theirs, we have theirs — send ours if they might not have it
                    announceKemPub(senderId);
                }
            } else {
                qWarning() << "[PQ] Invalid kem_pub_announce from" << senderId.left(8) + "..."
                           << "| size:" << kemPub.size() << "(expected 1184)";
            }
        } else if (type == "file_chunk") {
            // Sealed file_chunk in JSON payload shouldn't happen — file chunks
            // use SEALEDFC: prefix and are handled above before session decrypt.
            qWarning() << "[RECV" << via << "] unexpected file_chunk in session payload from"
                       << senderId.left(8) + "...";
        }
        return;
    }

    // ── File chunk envelope ─────────────────────────────────────────────────
    if (header.startsWith(kFilePrefix)) {
        const QString fromId = QString::fromUtf8(header.mid(kFilePrefix.size())).trimmed();
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] file chunk from" << fromId.left(8) + "...";
#endif
        m_fileMgr.handleFileEnvelope(fromId.toStdString(),
            p2p::bridge::toBytes(rest),
            [this](const std::string& id) { return markSeen(QString::fromStdString(id)); },
            toStdFileKeys(m_fileKeys));
        return;
    }

    // ── Message envelope ──────────────────────────────────────────────────────
    if (!header.startsWith(kMsgPrefix)) return;

    const QString fromId = QString::fromUtf8(header.mid(kMsgPrefix.size())).trimmed();
    using namespace p2p::bridge;
    const Bytes peerPub = CryptoEngine::fromBase64Url(fromId.toStdString());
    const QByteArray pt = toQByteArray(
        m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), toBytes(rest)));
    if (pt.isEmpty()) return;

    const auto    o    = QJsonDocument::fromJson(pt).object();
    const QString type = o.value("type").toString();

    // S9 fix: Legacy receive path — only accept ICE signaling and text.
    // ICE is needed for P2P bootstrapping before a sealed session exists.
    // Text is accepted (with warning) for backward compat with older peers.
    // All other types (group_msg, avatar, group_rename, etc.) are rejected —
    // they must come through the sealed path where sender identity is verified.
#ifdef PEER2PEAR_P2P
    if (type != "ice_offer" && type != "ice_answer" && type != "text") {
#else
    if (type != "text") {
#endif
        qWarning() << "[RECV" << via << "] REJECTED legacy" << type
                   << "from" << fromId.left(8) + "..."
                   << "— must use sealed path";
        return;
    }

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[RECV" << via << "] legacy type:" << type << "from" << fromId.left(8) + "...";
#endif

    if (type == "text") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        // L3 fix: Only emit "online" if message is fresh (< 2 min old) or via P2P
        if (via == "P2P" ||
            (tsSecs > 0 && QDateTime::currentSecsSinceEpoch() - tsSecs < 120))
            if (onPresenceChanged) onPresenceChanged(fromId, true);
        const QString msgId = o.value("msgId").toString();
        if (!msgId.isEmpty() && !markSeen(msgId)) return;
        if (onMessageReceived) onMessageReceived(fromId, o.value("text").toString(),
                             tsFromSecs(tsSecs), msgId);
    }
#ifdef PEER2PEAR_P2P
    else if (type == "ice_offer") {
        if (m_p2pConnections.contains(fromId) &&
            m_p2pConnections[fromId]->isReady()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[ICE] Already connected to" << fromId.left(8) + "... — ignoring ice_offer";
#endif
        } else {
            if (!m_p2pConnections.contains(fromId))
                setupP2PConnection(fromId, false);
            if (o.value("quic").toBool()) {
                m_p2pConnections[fromId]->setPeerSupportsQuic(
                    true, o.value("quic_fingerprint").toString());
            }
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
        }
    } else if (type == "ice_answer") {
        if (m_p2pConnections.contains(fromId) &&
            !m_p2pConnections[fromId]->isReady()) {
            if (o.value("quic").toBool()) {
                m_p2pConnections[fromId]->setPeerSupportsQuic(
                    true, o.value("quic_fingerprint").toString());
            }
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
        }
    }
#endif // PEER2PEAR_P2P
}

void ChatController::sendGroupRename(const QString& groupId,
                                     const QString& newName,
                                     const QStringList& memberKeys)
{
    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);  // B5 fix
    QJsonObject payload;
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_rename";
    payload["groupId"] = groupId;
    payload["newName"] = newName;
    payload["msgId"]   = msgId;                                   // B5 fix
    payload["ts"]      = QDateTime::currentSecsSinceEpoch();      // B5 fix
    for (const QString &key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupAvatar(const QString& groupId,
                                     const QString& avatarB64,
                                     const QStringList& memberKeys)
{
    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);  // B5 fix
    QJsonObject payload;
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_avatar";
    payload["groupId"] = groupId;
    payload["avatar"]  = avatarB64;
    payload["msgId"]   = msgId;                                   // B5 fix
    payload["ts"]      = QDateTime::currentSecsSinceEpoch();      // B5 fix
    for (const QString &key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupMemberUpdate(const QString& groupId,
                                           const QString& groupName,
                                           const QStringList& memberKeys)
{
    const QString myId = myIdB64u();
    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);  // B5 fix

    // Build the member array (excluding self, matching group_msg format)
    QJsonArray membersArray;
    for (const QString &key : memberKeys) {
        if (key.trimmed() == myId) continue;
        membersArray.append(key);
    }

    // Send to ALL members (including newly added ones) so everyone gets
    // the updated member list and new members discover the group.
    for (const QString &peerId : memberKeys) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == myId) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_member_update";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["msgId"]     = msgId;                              // B5 fix
        payload["ts"]        = QDateTime::currentSecsSinceEpoch();

        sendSealedPayload(peerId, payload);
    }
}

// ── G3: Reset encrypted session ──────────────────────────────────────────────
void ChatController::resetSession(const QString& peerIdB64u)
{
    if (m_sessionMgr) {
        m_sessionMgr->deleteSession(peerIdB64u.toStdString());
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SESSION] Reset ratchet session for" << peerIdB64u.left(8) + "...";
#endif
        if (onStatus) onStatus("Session reset — next message will establish a fresh handshake.");
    }
}

// ── GAP5: Group sequence counter persistence ────────────────────────────────

void ChatController::setGroupSeqCounters(const QMap<QString, qint64>& seqOut,
                                          const QMap<QString, qint64>& seqIn)
{
    m_groupSeqOut = seqOut;
    m_groupSeqIn  = seqIn;
}

// ── Fix #20: group-membership authorization ──────────────────────────────────

void ChatController::setKnownGroupMembers(const QString& groupId,
                                           const QStringList& members)
{
    if (groupId.isEmpty()) return;
    m_groupMembers[groupId] = QSet<QString>(members.begin(), members.end());
    m_groupBootstrapNeeded.remove(groupId);
}

bool ChatController::isAuthorizedGroupSender(const QString& gid,
                                              const QString& peerId) const
{
    if (gid.isEmpty() || peerId.isEmpty()) return false;
    auto it = m_groupMembers.find(gid);
    if (it == m_groupMembers.end()) {
        // First time we've seen this group — no persisted roster from the
        // UI yet.  Permissive bootstrap: the next group_msg (which carries
        // a members list) will populate m_groupMembers.  If we reject
        // pre-bootstrap control messages here, a legit member whose
        // group_msg races behind a group_rename will be silently dropped.
        return true;
    }
    return it->contains(peerId);
}

// ---------------------------
// Post-Quantum KEM pub exchange
// ---------------------------

QByteArray ChatController::lookupPeerKemPub(const QString& peerIdB64u)
{
    // Check in-memory cache first
    auto it = m_peerKemPubs.find(peerIdB64u);
    if (it != m_peerKemPubs.end()) return it.value();

    // Load from DB
    if (!m_dbPtr || !m_dbPtr->isOpen()) return {};
    SqlCipherQuery q(m_dbPtr->handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:pid;");
    q.bindValue(":pid", peerIdB64u.toStdString());
    if (q.exec() && q.next()) {
        QByteArray pub = p2p::bridge::toQByteArray(q.valueBlob(0));
        if (!pub.isEmpty()) {
            m_peerKemPubs[peerIdB64u] = pub;
            return pub;
        }
    }
    return {};
}

void ChatController::announceKemPub(const QString& peerIdB64u)
{
    if (!m_crypto.hasPQKeys()) return;
    if (!m_sessionMgr) return;
    if (m_kemPubAnnounced.contains(peerIdB64u)) return;  // already sent this session

    m_kemPubAnnounced.insert(peerIdB64u);

    QJsonObject payload;
    payload["from"] = myIdB64u();
    payload["type"] = "kem_pub_announce";
    payload["kem_pub_b64u"] = QString::fromStdString(CryptoEngine::toBase64Url(m_crypto.kemPub()));
    payload["ts"] = QDateTime::currentSecsSinceEpoch();

    sendSealedPayload(peerIdB64u, payload);
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[PQ] Announced ML-KEM-768 pub to" << peerIdB64u.left(8) + "...";
#endif
}
