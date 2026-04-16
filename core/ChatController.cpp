#include "ChatController.hpp"
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

ChatController::ChatController(IWebSocket& ws, IHttpClient& http, QObject* parent)
    : QObject(parent)
    , m_relay(ws, http, &m_crypto, this)
    , m_fileMgr(m_crypto, this)
{
    // Relay signals
    connect(&m_relay, &RelayClient::status,           this, &ChatController::status);
    connect(&m_relay, &RelayClient::envelopeReceived, this, &ChatController::onEnvelope);
    connect(&m_relay, &RelayClient::presenceChanged,  this, &ChatController::presenceChanged);
    connect(&m_relay, &RelayClient::connected,        this, &ChatController::onRelayConnected);

    // FileTransferManager: provide send callback instead of MailboxClient ref
    m_fileMgr.setSendFn([this](const QString& peerId, const QByteArray& env) {
        m_relay.sendEnvelope(env);
    });

    // Forward FileTransferManager signals
    connect(&m_fileMgr, &FileTransferManager::status, this, &ChatController::status);
    connect(&m_fileMgr, &FileTransferManager::fileChunkReceived,
            this, &ChatController::fileChunkReceived);
#ifdef PEER2PEAR_P2P
    connect(&m_fileMgr, &FileTransferManager::wantP2PConnection,
            this, &ChatController::initiateP2PConnection);
#endif
    // M1 fix: remove ratchet-derived file key when transfer completes.
    // M4 fix: keys are stored as "senderId:transferId" — match on suffix.
    connect(&m_fileMgr, &FileTransferManager::transferCompleted,
            this, [this](const QString& transferId) {
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
    });

    // Phase 2: outbound-abandoned = sender gave up (timeout) or receiver declined.
    // We've already emitted fileTransferCanceled in the decline/cancel handlers,
    // but the timeout path only fires from FileTransferManager::purgeStaleOutbound().
    connect(&m_fileMgr, &FileTransferManager::outboundAbandoned,
            this, [this](const QString& transferId, const QString& /*peerId*/) {
        emit fileTransferCanceled(transferId, false); // sender-side timeout
    });

    // Phase 2: inbound canceled (sender sent file_cancel or local user canceled).
    // Same signal — UI removes the progress indicator.
    connect(&m_fileMgr, &FileTransferManager::inboundCanceled,
            this, [this](const QString& transferId, const QString& /*peerId*/) {
        // The cancel handler above already emitted fileTransferCanceled; this
        // catch covers cases where something else (e.g., future direct cancel
        // in FileTransferManager) triggers the cleanup.
        emit fileTransferCanceled(transferId, false);
    });

    // Phase 3: transport policy blocked the transfer after P2P wait expired.
    connect(&m_fileMgr, &FileTransferManager::outboundBlockedByPolicy,
            this, [this](const QString& transferId, const QString& /*peerId*/, bool byReceiver) {
        emit fileTransferBlocked(transferId, byReceiver);
    });

    // Fix #5: rehydrate file keys from DB after loadPersistedTransfers().
    // The receiver's partial-file bitmap is restored in FileTransferManager;
    // the fileKey that decrypts chunks lives here, so we restore it in sync.
    connect(&m_fileMgr, &FileTransferManager::incomingFileKeyRestored,
            this, [this](const QString& fromPeerId,
                         const QString& transferId,
                         const QByteArray& fileKey) {
        if (fileKey.size() != 32) return;
        const QString compound = fromPeerId + ":" + transferId;
        m_fileKeys[compound] = fileKey;
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] restored file key for" << transferId.left(8)
                 << "from" << fromPeerId.left(8) + "...";
#endif
    });

    // Phase 3: receiver finished writing and verified — send file_ack.
    connect(&m_fileMgr, &FileTransferManager::fileChunkReceived,
            this, [this](const QString& fromPeerId,
                         const QString& transferId,
                         const QString& /*fileName*/,
                         qint64 /*fileSize*/,
                         int chunksReceived,
                         int chunksTotal,
                         const QString& savedPath,
                         const QDateTime& /*ts*/,
                         const QString& /*groupId*/,
                         const QString& /*groupName*/) {
        // Full file landed + hash verified: savedPath is non-empty.
        // Hash failure emits with empty savedPath — don't ack in that case.
        if (chunksReceived == chunksTotal && !savedPath.isEmpty()) {
            QJsonObject ack;
            ack["type"]       = "file_ack";
            ack["transferId"] = transferId;
            sendFileControlMessage(fromPeerId, ack);
        }
    });

    // Periodic maintenance: handshake pruning, file key cleanup, ICE cleanup
    connect(&m_maintenanceTimer, &QTimer::timeout, this, [this]() {
        // H3 fix: reset per-sender rate limit counters
        m_envelopeCount.clear();

        // Purge stale incomplete transfers
        m_fileMgr.purgeStaleTransfers();
        // Phase 2: drop outbound transfers that never got a file_accept in 10 minutes
        m_fileMgr.purgeStaleOutbound();
        // Fix #21: don't rely on app restart to age out partial files / sent
        // records.  A long-running desktop session could accumulate stale
        // rows for weeks otherwise.  Cheap — just a few DB deletes by age.
        m_fileMgr.purgeStalePartialFiles();

        // H2/SEC9: prune stuck handshakes
        if (m_sessionStore) {
            const QStringList pruned = m_sessionStore->pruneStaleHandshakes();
            for (const QString &peerId : pruned) {
                int count = ++m_handshakeFailCount[peerId];
                if (count >= 2)
                    emit peerMayNeedUpgrade(peerId);
            }
        }

        // Fix #4: the old 30-min m_fileKeys TTL was removed.  File keys now
        // live as long as the FileTransferManager's DB-backed partial-transfer
        // row (7-day max).  When that purges, transferCompleted fires and the
        // key gets zeroed via the connect() in the constructor.

#ifdef PEER2PEAR_P2P
        // G4 fix: clean up failed ICE connections
        QStringList toRemove;
        for (auto it = m_p2pConnections.begin(); it != m_p2pConnections.end(); ++it) {
            if (!it.value()->isReady())
                toRemove << it.key();
        }
        for (const QString &key : toRemove) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[ICE] Cleaning up stale connection to" << key.left(8) + "...";
#endif
            m_p2pConnections[key]->deleteLater();
            m_p2pConnections.remove(key);
        }
#endif
    });
    m_maintenanceTimer.start(30 * 1000); // every 30 seconds
}

void ChatController::setPassphrase(const QString& pass)
{
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity();
}

void ChatController::setPassphrase(const QString& pass, const QByteArray& identityKey)
{
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity(identityKey);
}

void ChatController::setRelayUrl(const QUrl& url)
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
    QByteArray storeKey = CryptoEngine::hkdf(
        m_crypto.curvePriv(), {}, "session-store-at-rest", 32);
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
    m_sessionMgr->setSendResponseFn([this](const QString& peerId, const QByteArray& blob) {
        // Convert peer's Ed25519 pub to X25519 for sealing
        QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(
                peerCurvePub,
                reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0) return;

        QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
        QByteArray peerKemPub = lookupPeerKemPub(peerId);
        QByteArray sealed = SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            blob, peerKemPub, m_crypto.dsaPub(), m_crypto.dsaPriv());
        if (sealed.isEmpty()) return;
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND MAILBOX] sealed handshake response to" << peerId.left(8) + "..."
                 << (peerKemPub.isEmpty() ? "(classical)" : "(hybrid PQ)");
#endif

        QByteArray inner = kSealedPrefix + "\n" + sealed;
        QByteArray env = SealedEnvelope::wrapForRelay(peerEdPub, inner);
        m_relay.sendEnvelope(env);
    });

    // M2 fix: Set seal callback on FileTransferManager so file chunks get sealed envelopes.
    // This wraps the inner payload (already encrypted with ratchet-derived file key)
    // in a SealedEnvelope for metadata privacy — the relay never sees sender identity.
    m_fileMgr.setSealFn([this](const QString& peerId, const QByteArray& payload) -> QByteArray {
        QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(
                peerCurvePub,
                reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0)
            return {};

        QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
        sodium_memzero(peerCurvePub, sizeof(peerCurvePub));
        QByteArray peerKemPub = lookupPeerKemPub(peerId);
        QByteArray sealed = SealedEnvelope::seal(
            recipientCurvePub, peerEdPub,
            m_crypto.identityPub(), m_crypto.identityPriv(),
            payload, peerKemPub, m_crypto.dsaPub(), m_crypto.dsaPriv());
        if (sealed.isEmpty()) return {};

        QByteArray inner = kSealedFCPrefix + "\n" + sealed;
        return SealedEnvelope::wrapForRelay(peerEdPub, inner);
    });
#ifdef PEER2PEAR_P2P
    // QUIC P2P file send callback: try sending file chunks directly via QUIC stream
    m_fileMgr.setP2PFileSendFn([this](const QString& peerId, const QByteArray& data) -> bool {
        if (m_p2pConnections.contains(peerId) &&
            m_p2pConnections[peerId]->isReady() &&
            m_p2pConnections[peerId]->quicActive()) {
            m_p2pConnections[peerId]->sendFileData(data);
            return true;
        }
        return false;  // fall back to mailbox
    });
#endif

}

QString ChatController::myIdB64u() const
{
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
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
        emit status("Message not sent — encrypted session unavailable. Try again shortly.");
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
        m_relay.sendEnvelope(sealedEnv);
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
        emit status(QString("File not found: %1").arg(filePath));
        return {};
    }
    const qint64 fileSize = finfo.size();
    if (fileSize > FileTransferManager::kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    // Streaming hash — one pass over the file, bounded RAM.
    const QByteArray fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) {
        emit status(QString("Could not hash file: %1").arg(fileName));
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
    announce["fileHash"]    = CryptoEngine::toBase64Url(fileHash);
    announce["chunkCount"]  = chunkCount;
    announce["ts"]          = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt = QJsonDocument(announce).toJson(QJsonDocument::Compact);
    QByteArray sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.isEmpty()) {
        qWarning() << "[FILE] BLOCKED — cannot seal file_key for" << peerIdB64u.left(8) + "...";
        emit status("File not sent — encrypted session unavailable.");
        return {};
    }

    m_relay.sendEnvelope(sealedEnv);

    QByteArray fileKey = m_sessionMgr->lastMessageKey();
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
             << "to" << peerIdB64u.left(8) + "..." << "size=" << fileSize;
#endif

    // Phase 2: queue outbound state. Chunks don't fly until file_accept arrives.
    m_fileMgr.queueOutboundFile(myIdB64u(), peerIdB64u, fileKey,
                                 transferId, fileName, filePath,
                                 fileSize, fileHash);
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
        emit status(QString("File not found: %1").arg(filePath));
        return {};
    }
    const qint64 fileSize = finfo.size();
    if (fileSize > FileTransferManager::kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    // Hash the file once up-front (streaming) and reuse for all members.
    const QByteArray fileHash = FileTransferManager::blake2b256File(filePath);
    if (fileHash.size() != 32) {
        emit status(QString("Could not hash file: %1").arg(fileName));
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
        announce["fileHash"]    = CryptoEngine::toBase64Url(fileHash);
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

        m_relay.sendEnvelope(sealedEnv);

        QByteArray fileKey = m_sessionMgr->lastMessageKey();
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
                 << "to" << peerId.left(8) + "...";
#endif

        // NOTE: Phase 2 intentionally does NOT gate group files on per-member
        // consent. Each group member would need an independent file_accept
        // roundtrip, which complicates the N-way announcement model. Group
        // files stream immediately (old behavior), 1:1 files use the consent
        // gate. Group-member consent is future work.
        m_fileMgr.sendFileWithKey(myId, peerId, fileKey,
                                  transferId, fileName, filePath,
                                  fileSize, fileHash,
                                  groupId, groupName);
        sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    }

    emit status(QString("'%1' streamed in %2 chunk(s) -> group %3")
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

void ChatController::onRelayConnected()
{
    // The relay delivers stored mailbox envelopes on WS connect automatically.
    // No need to poll — envelopes arrive via push.
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[ChatController] Relay connected, envelopes will be pushed.";
#endif
    emit relayConnected();

    // Phase 4: for each incomplete incoming transfer, tell the sender which
    // chunks we still need so they can re-send them.
    const auto pendings = m_fileMgr.pendingResumptions();
    for (const auto& pr : pendings) {
        QJsonArray chunks;
        for (quint32 idx : pr.missingChunks) chunks.append(int(idx));
        QJsonObject msg;
        msg["type"]       = "file_request";
        msg["transferId"] = pr.transferId;
        msg["chunks"]     = chunks;
        sendFileControlMessage(pr.peerId, msg);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] requested resumption of" << pr.transferId.left(8)
                 << "from" << pr.peerId.left(8) + "..."
                 << "missing" << pr.missingChunks.size() << "chunks";
#endif
    }
}

void ChatController::subscribePresence(const QStringList& peerIds)
{
    m_relay.subscribePresence(peerIds);
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
    m_relay.queryPresence(peerIds);
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
    m_relay.sendEnvelope(sealed);
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
    if (!m_fileMgr.announceIncoming(peerId, transferId, it->fileName,
                                      it->fileSize, it->totalChunks,
                                      it->fileHash, it->fileKey, it->announcedTs,
                                      it->groupId, it->groupName)) {
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

    emit fileTransferCanceled(transferId, true);  // receiver declined
}

void ChatController::cancelFileTransfer(const QString& transferId)
{
    // Figure out which role we hold for this transferId and clean up + notify.

    // Outbound pending (sender canceling a queued-but-unaccepted send)?
    const QString outboundPeer = m_fileMgr.outboundPeerFor(transferId);
    if (!outboundPeer.isEmpty()) {
        m_fileMgr.abandonOutboundTransfer(transferId);
        QJsonObject msg;
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(outboundPeer, msg);
        emit fileTransferCanceled(transferId, false);  // sender-initiated
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
        emit fileTransferCanceled(transferId, true);   // receiver-initiated
        return;
    }

    // Inbound, in-progress (user canceled mid-stream)?
    const QString inboundPeer = m_fileMgr.inboundPeerFor(transferId);
    if (!inboundPeer.isEmpty()) {
        m_fileMgr.cancelInboundTransfer(transferId);
        QJsonObject msg;
        msg["type"]       = "file_cancel";
        msg["transferId"] = transferId;
        sendFileControlMessage(inboundPeer, msg);
        emit fileTransferCanceled(transferId, true);
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
            m_relay.sendEnvelope(env);
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
            m_relay.sendEnvelope(env);
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
    QByteArray sessionBlob = m_sessionMgr->encryptForPeer(peerIdB64u, plaintext, peerKemPub);
    if (sessionBlob.isEmpty()) return {};

    QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(
            peerCurvePub,
            reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0)
        return {};

    QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
    sodium_memzero(peerCurvePub, sizeof(peerCurvePub));  // G11 fix

    // Use hybrid seal if we know the peer's ML-KEM-768 public key (already looked up above)
    // Include ML-DSA-65 signature if we have DSA keys
    QByteArray sealed = SealedEnvelope::seal(
        recipientCurvePub, peerEdPub,
        m_crypto.identityPub(), m_crypto.identityPriv(),
        sessionBlob, peerKemPub, m_crypto.dsaPub(), m_crypto.dsaPriv());
    if (sealed.isEmpty()) return {};

    QByteArray inner = kSealedPrefix + "\n" + sealed;

    // Wrap with relay routing header so /v1/send can route anonymously
    return SealedEnvelope::wrapForRelay(peerEdPub, inner);
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
        m_relay.sendEnvelope(env);
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
    QuicConnection* conn = new QuicConnection(this);
    if (!m_turnHost.isEmpty())
        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
    m_p2pConnections[peerIdB64u] = conn;

    const QString iceType = controlling ? "ice_offer" : "ice_answer";
    connect(conn, &QuicConnection::localSdpReady, this, [this, peerIdB64u, iceType, conn](const QString& sdp) {
        QJsonObject p;
        p["type"] = iceType;
        p["from"] = myIdB64u();
        p["sdp"]  = sdp;
        // Advertise QUIC capability + fingerprint
        p["quic"] = true;
        p["quic_fingerprint"] = conn->localQuicFingerprint();
        sendSealedPayload(peerIdB64u, p);
    });
    connect(conn, &QuicConnection::stateChanged, this, [this, peerIdB64u, conn](int state) {
        if (state == NICE_COMPONENT_STATE_READY) {
            const QString mode = conn->quicActive() ? "QUIC" : "ICE";
            emit status("P2P ready (" + mode + ") with " + peerIdB64u);
            // Phase 3: flush any outbound file transfers waiting for P2P.
            m_fileMgr.notifyP2PReady(peerIdB64u);
        } else if (state == NICE_COMPONENT_STATE_FAILED) {
            emit status("P2P failed for " + peerIdB64u);
        }
    });
    connect(conn, &QuicConnection::dataReceived, this, [this, peerIdB64u](const QByteArray& d) {
        onP2PDataReceived(peerIdB64u, d);
    });
    connect(conn, &QuicConnection::fileDataReceived, this, [this, peerIdB64u](const QByteArray& d) {
        // File data received via QUIC file stream — route to FileTransferManager
        m_fileMgr.handleFileEnvelope(peerIdB64u, d,
            [this](const QString& id) { return markSeen(id); },
            m_fileKeys);
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
    emit presenceChanged(peerIdB64u, true);

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
    if (m_sessionMgr && m_sessionMgr->hasSession(peerIdB64u)) {
        QByteArray pt = m_sessionMgr->decryptFromPeer(peerIdB64u, data);
        if (!pt.isEmpty()) {
            const auto o = QJsonDocument::fromJson(pt).object();
            if (o.value("type").toString() == "text") {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV P2P] ratchet text from" << peerIdB64u.left(8) + "...";
#endif
                const QString msgId = o.value("msgId").toString();
                if (!msgId.isEmpty() && !markSeen(msgId)) return;
                emit messageReceived(peerIdB64u, o.value("text").toString(),
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
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray pt = m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), data);
    if (pt.isEmpty()) return;

    const auto o = QJsonDocument::fromJson(pt).object();
    if (o.value("type").toString() != "text") return;

    const QString msgId = o.value("msgId").toString();
    if (!msgId.isEmpty() && !markSeen(msgId)) return;

    emit messageReceived(peerIdB64u, o.value("text").toString(),
                         tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
}
#endif // PEER2PEAR_P2P

void ChatController::onEnvelope(const QByteArray& body)
{
    // Envelopes arrive via WebSocket push — no ACK needed, the relay
    // deletes stored envelopes on delivery.
    const QString via = QStringLiteral("RELAY");

    // Strip relay routing header if present (0x01 || recipientEdPub(32) || inner)
    const QByteArray data = [&]() -> QByteArray {
        if (!body.isEmpty() && static_cast<quint8>(body[0]) == 0x01 && body.size() > 33) {
            QByteArray inner = SealedEnvelope::unwrapFromRelay(body);
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
        UnsealResult unsealed = SealedEnvelope::unseal(
            m_crypto.curvePriv(), m_crypto.identityPub(), rest, m_crypto.kemPriv());
        if (!unsealed.valid) {
            qWarning() << "[ChatController] Failed to unseal envelope";
            return;
        }

        // Envelope-level replay protection (Fix #2): dedup on envelopeId.
        // The ratchet dedups its own chain messages, but control messages
        // outside the ratchet (file_accept, file_cancel, etc.) don't have that
        // protection. A malicious relay could redeliver the same sealed blob
        // and the receiver would happily reprocess it.
        if (unsealed.envelopeId.size() == 16) {
            const QString envKey = "env:" + CryptoEngine::toBase64Url(unsealed.envelopeId);
            if (!markSeen(envKey)) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV" << via << "] dropping replayed envelope"
                         << envKey.mid(4, 8) + "...";
#endif
                return;
            }
        }

        QString senderId = CryptoEngine::toBase64Url(unsealed.senderEdPub);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] unsealed OK | sender:" << senderId.left(8) + "..."
                 << "| inner:" << unsealed.innerPayload.size() << "B";
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
            m_fileMgr.handleFileEnvelope(senderId, unsealed.innerPayload,
                [this](const QString& id) { return markSeen(id); },
                m_fileKeys);
            return;
        }

        if (!m_sessionMgr) return; // can't process without session manager

        // Only emit "online" if the envelope is recent (within 2 minutes).
        // Old mailbox messages should not trigger false online presence.  (L3 fix)
        // Note: sealed envelopes carry no timestamp, so we infer freshness from
        // the transport — P2P is always live; mailbox may have stale messages.
        if (via == "P2P") emit presenceChanged(senderId, true);

        // Decrypt session layer (Noise handshake or ratchet message)
        QByteArray msgKey;  // M3 fix: capture message key directly from decrypt
        QByteArray pt = m_sessionMgr->decryptFromPeer(senderId, unsealed.innerPayload, &msgKey);
        if (pt.isEmpty()) {
            // Pre-key response (0x02) completes the Noise IK handshake and creates
            // a ratchet session inside decryptFromPeer(), but returns no user payload.
            // This is expected — future messages will use the ratchet session.
            const quint8 innerType = unsealed.innerPayload.isEmpty() ? 0 : static_cast<quint8>(unsealed.innerPayload[0]);
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
            emit messageReceived(senderId, o.value("text").toString(), ts, msgId);
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

            emit groupMessageReceived(senderId, gid,
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
            emit groupMemberLeft(senderId, gid,
                                  o.value("groupName").toString(), memberKeys, ts, msgId);
        } else if (type == "avatar") {
            emit avatarReceived(senderId, o.value("name").toString(), o.value("avatar").toString());
        } else if (type == "group_rename") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const QString gid = o.value("groupId").toString();
            if (!gid.isEmpty() && !isAuthorizedGroupSender(gid, senderId)) {
                qWarning() << "[GROUP] dropping group_rename from non-member"
                           << senderId.left(8) + "... for" << gid.left(8);
                return;
            }
            emit groupRenamed(gid, o.value("newName").toString());
        } else if (type == "group_avatar") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            const QString gid = o.value("groupId").toString();
            if (!gid.isEmpty() && !isAuthorizedGroupSender(gid, senderId)) {
                qWarning() << "[GROUP] dropping group_avatar from non-member"
                           << senderId.left(8) + "... for" << gid.left(8);
                return;
            }
            emit groupAvatarReceived(gid, o.value("avatar").toString());
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
            emit groupMessageReceived(senderId, gid, gname, memberKeys,
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
                const QByteArray announcedHash =
                    CryptoEngine::fromBase64Url(o.value("fileHash").toString());
                const int announcedChunkCount = o.value("chunkCount").toInt(0);
                const qint64 announcedTs      = o.value("ts").toVariant().toLongLong();

                if (announcedHash.size() != 32 || announcedChunkCount <= 0) {
                    qWarning() << "[FILE] missing fileHash/chunkCount on file_key for"
                               << transferId.left(8) << "— dropping";
                    sodium_memzero(msgKey.data(), msgKey.size());
                    return;
                }

                if (!m_fileMgr.announceIncoming(senderId, transferId, fileName,
                                                  fileSize, announcedChunkCount,
                                                  announcedHash, msgKey, announcedTs,
                                                  gId, gName)) {
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
                const QByteArray announcedHash =
                    CryptoEngine::fromBase64Url(o.value("fileHash").toString());
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
                emit fileAcceptRequested(senderId, transferId, fileName, fileSize);
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

                if (!m_fileMgr.startOutboundStream(transferId, requireP2P,
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
                m_fileMgr.abandonOutboundTransfer(transferId);
                emit fileTransferCanceled(transferId, true); // byReceiver
                emit status("File transfer declined by recipient.");
            }

        } else if (type == "file_ack") {
            // Sender-side: receiver confirmed delivery + hash ok.
            const QString transferId = o.value("transferId").toString();
            if (!transferId.isEmpty()) {
                emit fileTransferDelivered(transferId);
                // Phase 4: drop sender-side state now that the transfer is acked.
                m_fileMgr.forgetSentTransfer(transferId);
            }

        } else if (type == "file_request") {
            // Receiver is asking us (sender) to re-send these chunk indices.
            // Phase 4 resumption path.
            const QString transferId = o.value("transferId").toString();
            const QJsonArray chunksArr = o.value("chunks").toArray();
            if (transferId.isEmpty() || chunksArr.isEmpty()) return;
            QList<quint32> indices;
            indices.reserve(chunksArr.size());
            for (const QJsonValue& v : chunksArr) {
                const int i = v.toInt(-1);
                if (i >= 0) indices.append(quint32(i));
            }
            if (!m_fileMgr.resendChunks(transferId, indices)) {
                qWarning() << "[FILE] file_request for unknown transferId"
                           << transferId.left(8) + "...";
            }

        } else if (type == "file_cancel") {
            // Either side: the peer canceled. Figure out which role we're in.
            const QString transferId = o.value("transferId").toString();
            if (transferId.isEmpty()) return;

            // Outbound (we're the sender)?
            if (!m_fileMgr.outboundPeerFor(transferId).isEmpty()) {
                m_fileMgr.abandonOutboundTransfer(transferId);
                // Phase 4: also drop the sent-transfer DB row in case we were mid-stream.
                m_fileMgr.forgetSentTransfer(transferId);
                emit fileTransferCanceled(transferId, true); // canceled by receiver
                return;
            }
            // Also handle "sender was already streaming when receiver canceled":
            // m_outboundPending is empty, but m_sentTransfers has the record.
            m_fileMgr.forgetSentTransfer(transferId);

            // Inbound pending (we were about to prompt)?
            auto itPending = m_pendingIncomingFiles.find(transferId);
            if (itPending != m_pendingIncomingFiles.end()) {
                sodium_memzero(itPending->fileKey.data(), itPending->fileKey.size());
                m_pendingIncomingFiles.erase(itPending);
                emit fileTransferCanceled(transferId, false); // sender canceled
                return;
            }
            // Inbound in-progress (sender pulled the plug mid-stream)?
            if (!m_fileMgr.inboundPeerFor(transferId).isEmpty()) {
                m_fileMgr.cancelInboundTransfer(transferId);
                emit fileTransferCanceled(transferId, false);
            }

        } else if (type == "kem_pub_announce") {
            // Post-quantum KEM public key exchange — store the peer's ML-KEM-768 pub
            QByteArray kemPub = CryptoEngine::fromBase64Url(o.value("kem_pub_b64u").toString());
            if (kemPub.size() == 1184) {  // ML-KEM-768 pub key size
                m_peerKemPubs[senderId] = kemPub;
                // Persist to DB
                if (m_dbPtr && m_dbPtr->isOpen()) {
                    SqlCipherQuery q(*m_dbPtr);
                    q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:pid;");
                    q.bindValue(":kp", kemPub);
                    q.bindValue(":pid", senderId);
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
        m_fileMgr.handleFileEnvelope(fromId, rest,
            [this](const QString& id) { return markSeen(id); },
            m_fileKeys);
        return;
    }

    // ── Message envelope ──────────────────────────────────────────────────────
    if (!header.startsWith(kMsgPrefix)) return;

    const QString fromId = QString::fromUtf8(header.mid(kMsgPrefix.size())).trimmed();
    const QByteArray peerPub = CryptoEngine::fromBase64Url(fromId);
    const QByteArray pt = m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), rest);
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
            emit presenceChanged(fromId, true);
        const QString msgId = o.value("msgId").toString();
        if (!msgId.isEmpty() && !markSeen(msgId)) return;
        emit messageReceived(fromId, o.value("text").toString(),
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
        m_sessionMgr->deleteSession(peerIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SESSION] Reset ratchet session for" << peerIdB64u.left(8) + "...";
#endif
        emit status("Session reset — next message will establish a fresh handshake.");
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
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) {
        QByteArray pub = q.value(0).toByteArray();
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
    payload["kem_pub_b64u"] = CryptoEngine::toBase64Url(m_crypto.kemPub());
    payload["ts"] = QDateTime::currentSecsSinceEpoch();

    sendSealedPayload(peerIdB64u, payload);
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[PQ] Announced ML-KEM-768 pub to" << peerIdB64u.left(8) + "...";
#endif
}
