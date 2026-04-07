#include "ChatController.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>
#include <QtSql/QSqlQuery>
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

ChatController::ChatController(QObject* parent)
    : QObject(parent)
    , m_rvz(&m_crypto, this)
    , m_mbox(&m_crypto, this)
    , m_fileMgr(m_crypto, m_mbox, this)
{
    connect(&m_mbox, &MailboxClient::status,           this, &ChatController::status);
    connect(&m_rvz,  &RendezvousClient::status,        this, &ChatController::status);
    connect(&m_mbox, &MailboxClient::envelopeReceived, this, &ChatController::onEnvelope);
    connect(&m_pollTimer, &QTimer::timeout,            this, &ChatController::pollOnce);
    connect(&m_rvz,  &RendezvousClient::presenceResult, this, &ChatController::presenceChanged);

    // Forward FileTransferManager signals
    connect(&m_fileMgr, &FileTransferManager::status, this, &ChatController::status);
    connect(&m_fileMgr, &FileTransferManager::fileChunkReceived,
            this, &ChatController::fileChunkReceived);
    connect(&m_fileMgr, &FileTransferManager::wantP2PConnection,
            this, &ChatController::initiateP2PConnection);
    // M1 fix: remove ratchet-derived file key when transfer completes.
    // M4 fix: keys are stored as "senderId:transferId" — match on suffix.
    connect(&m_fileMgr, &FileTransferManager::transferCompleted,
            this, [this](const QString& transferId) {
        const QString suffix = ":" + transferId;
        auto it = m_fileKeys.begin();
        while (it != m_fileKeys.end()) {
            if (it.key().endsWith(suffix) || it.key() == transferId) {
                sodium_memzero(it.value().data(), it.value().size());
                m_fileKeyTimes.remove(it.key());  // M8 fix
                it = m_fileKeys.erase(it);
            } else {
                ++it;
            }
        }
    });

    // Refresh rendezvous registration every 50 seconds (TTL is 60s).
    // Short TTL means peers detect offline status within ~60s of app close.
    connect(&m_rvzRefreshTimer, &QTimer::timeout, this, [this]() {
        m_rvz.publish("present", 0, 60LL * 1000);
    });
    m_rvzRefreshTimer.setInterval(50 * 1000);

    // G4 fix: periodically clean up failed ICE connections (not READY after 60s)
    auto *iceCleanup = new QTimer(this);
    connect(iceCleanup, &QTimer::timeout, this, [this]() {
        QStringList toRemove;
        for (auto it = m_p2pConnections.begin(); it != m_p2pConnections.end(); ++it) {
            if (!it.value()->isReady() && !it.value()->isRunning()) {
                toRemove << it.key();
            }
        }
        for (const QString &key : toRemove) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[ICE] Cleaning up stale connection to" << key.left(8) + "...";
#endif
            m_p2pConnections[key]->deleteLater();
            m_p2pConnections.remove(key);
        }
    });
    iceCleanup->start(60 * 1000);
}

void ChatController::setPassphrase(const QString& pass)
{
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity();
}

void ChatController::setServerBaseUrl(const QUrl& base)
{
    m_rvz.setBaseUrl(base);
    m_mbox.setBaseUrl(base);
}

void ChatController::setDatabase(QSqlDatabase db)
{
    // Guard against double-call: reset previous instances before reinitializing
    m_sessionMgr.reset();
    m_sessionStore.reset();

    // Derive a 32-byte at-rest encryption key from the identity curve private key.
    // This key never leaves memory and is tied to the user's unlocked identity.
    QByteArray storeKey = CryptoEngine::hkdf(
        m_crypto.curvePriv(), {}, "session-store-at-rest", 32);
    m_sessionStore = std::make_unique<SessionStore>(db, storeKey);
    CryptoEngine::secureZero(storeKey);

    // One-time migration: clear sessions created with the buggy ratchet init
    {
        QSqlQuery q(db);
        q.prepare("SELECT value FROM settings WHERE key='ratchet_v5_cleared';");
        if (!q.exec() || !q.next()) {
            m_sessionStore->clearAll();
            QSqlQuery ins(db);
            ins.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('ratchet_v5_cleared','1');");
            ins.exec();
        }
    }

    m_sessionMgr = std::make_unique<SessionManager>(m_crypto, *m_sessionStore);

    // When SessionManager needs to send a handshake response, seal it and enqueue
    m_sessionMgr->setSendResponseFn([this](const QString& peerId, const QByteArray& blob) {
        // Convert peer's Ed25519 pub to X25519 for sealing
        QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerId);
        unsigned char peerCurvePub[32];
        if (crypto_sign_ed25519_pk_to_curve25519(
                peerCurvePub,
                reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0) return;

        QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
        QByteArray sealed = SealedEnvelope::seal(
            recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), blob);
        if (sealed.isEmpty()) return;
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND MAILBOX] sealed handshake response to" << peerId.left(8) + "...";
#endif

        QByteArray env = kSealedPrefix + "\n" + sealed;
        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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
        QByteArray sealed = SealedEnvelope::seal(
            recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), payload);
        if (sealed.isEmpty()) return {};

        return kSealedFCPrefix + "\n" + sealed;
    });
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

    if (m_p2pConnections.contains(peerIdB64u) &&
        m_p2pConnections[peerIdB64u]->isReady()) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND P2P] sealed text to" << peerIdB64u.left(8) + "...";
#endif
        m_p2pConnections[peerIdB64u]->sendData(sealedEnv);
    } else {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SEND MAILBOX] sealed text to" << peerIdB64u.left(8) + "...";
#endif
        m_mbox.enqueue(peerIdB64u, sealedEnv, 7LL * 24 * 60 * 60 * 1000);
        initiateP2PConnection(peerIdB64u);
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
                                 const QByteArray& fileData)
{
    if (fileData.size() > FileTransferManager::kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Send file_key announcement through the ratchet to derive a forward-secret key
    QJsonObject announce;
    announce["from"]       = myIdB64u();
    announce["type"]       = "file_key";
    announce["transferId"] = transferId;
    announce["fileName"]   = fileName;
    announce["fileSize"]   = fileData.size();
    announce["ts"]         = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt = QJsonDocument(announce).toJson(QJsonDocument::Compact);
    QByteArray sealedEnv = sealForPeer(peerIdB64u, pt);
    if (sealedEnv.isEmpty()) {
        qWarning() << "[FILE] BLOCKED — cannot seal file_key for" << peerIdB64u.left(8) + "...";
        emit status("File not sent — encrypted session unavailable.");
        return {};
    }

    // Send the announcement (always via mailbox for reliability)
    m_mbox.enqueue(peerIdB64u, sealedEnv, 7LL * 24 * 60 * 60 * 1000);

    // Extract the ratchet-derived key for chunk encryption
    QByteArray fileKey = m_sessionMgr->lastMessageKey();
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
             << "to" << peerIdB64u.left(8) + "...";
#endif

    const QString result = m_fileMgr.sendFileWithKey(myIdB64u(), peerIdB64u, fileKey,
                                                      transferId, fileName, fileData);
    sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    return result;
}

QString ChatController::sendGroupFile(const QString& groupId,
                                      const QString& groupName,
                                      const QStringList& memberPeerIds,
                                      const QString& fileName,
                                      const QByteArray& fileData)
{
    if (fileData.size() > FileTransferManager::kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(FileTransferManager::kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    const QString myId = myIdB64u();
    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Send per-member file_key announcements through the ratchet
    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == myId) continue;

        QJsonObject announce;
        announce["from"]       = myId;
        announce["type"]       = "file_key";
        announce["transferId"] = transferId;
        announce["fileName"]   = fileName;
        announce["fileSize"]   = fileData.size();
        announce["ts"]         = QDateTime::currentSecsSinceEpoch();
        announce["groupId"]    = groupId;
        announce["groupName"]  = groupName;

        const QByteArray pt = QJsonDocument(announce).toJson(QJsonDocument::Compact);
        QByteArray sealedEnv = sealForPeer(peerId, pt);
        if (sealedEnv.isEmpty()) {
            qWarning() << "[FILE] BLOCKED — cannot seal file_key for" << peerId.left(8) + "...";
            continue;
        }

        m_mbox.enqueue(peerId, sealedEnv, 7LL * 24 * 60 * 60 * 1000);

        QByteArray fileKey = m_sessionMgr->lastMessageKey();
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[FILE] file_key announced for" << transferId.left(8) + "..."
                 << "to" << peerId.left(8) + "...";
#endif

        m_fileMgr.sendFileWithKey(myId, peerId, fileKey,
                                  transferId, fileName, fileData,
                                  groupId, groupName);
        sodium_memzero(fileKey.data(), fileKey.size());  // L6 fix
    }

    const int totalChunks = int((fileData.size() + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);
    emit status(QString("'%1' queued in %2 chunk(s) -> group %3")
                    .arg(fileName).arg(totalChunks).arg(groupName));
    return transferId;
}

void ChatController::startPolling(int intervalMs)
{
    if (!m_pollTimer.isActive()) {
        m_pollTimer.start(intervalMs);
        // Publish our identity to the rendezvous server so peers can discover us.
        // host="present" is a non-empty marker — the lookup check treats any non-empty,
        // non-"0.0.0.0" host as "online".  TTL of 60s; we refresh every 50s.
        m_rvz.publish("present", 0, 60LL * 1000);
        m_rvzRefreshTimer.start();
        // Immediately drain the mailbox on startup rather than waiting for first tick
        pollOnce();
    }
}

void ChatController::stopPolling()
{
    m_pollTimer.stop();
    m_rvzRefreshTimer.stop();
    // Immediately expire our presence so peers see us as offline
    m_rvz.publish("", 0, 1);
}

void ChatController::setSelfKeys(const QStringList& keys) { m_selfKeys = keys; }

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

void ChatController::checkPresence(const QStringList& peerIds)
{
    for (const QString& id : peerIds) {
        if (!id.trimmed().isEmpty())
            m_rvz.checkPresence(id.trimmed());
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
            m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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

        const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QByteArray env = sealForPeer(peerId, pt);
        if (!env.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SEND MAILBOX] sealed group_leave to" << peerId.left(8) + "...";
#endif
            m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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

void ChatController::pollOnce()
{
    // H3 fix: reset per-sender rate limit counters each poll cycle
    m_envelopeCount.clear();

    // fetchAll retrieves every pending envelope in one authenticated request.
    // Falls back to single fetch() automatically if the server doesn't yet
    // support /mbox/fetch_all (404/405 response).
    m_mbox.fetchAll(myIdB64u());
    for (const QString &key : std::as_const(m_selfKeys)) {
        if (!key.trimmed().isEmpty() && key.trimmed() != myIdB64u()) m_mbox.fetchAll(key.trimmed());
    }

    // Purge stale incomplete transfers to bound memory usage
    m_fileMgr.purgeStaleTransfers();

    // H2 fix: prune stuck pending handshakes (5 min timeout, checked every poll)
    if (m_sessionStore)
        m_sessionStore->pruneStaleHandshakes();

    // M8 fix: purge orphaned file keys older than 30 minutes.
    // If a file_key announcement arrives but chunks never follow (sender crash,
    // network issue), the key would sit in memory indefinitely without this.
    {
        static constexpr qint64 kFileKeyMaxAgeSecs = 30 * 60;
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        auto it = m_fileKeyTimes.begin();
        while (it != m_fileKeyTimes.end()) {
            if ((now - it.value()) > kFileKeyMaxAgeSecs) {
                auto keyIt = m_fileKeys.find(it.key());
                if (keyIt != m_fileKeys.end()) {
                    sodium_memzero(keyIt.value().data(), keyIt.value().size());
                    m_fileKeys.erase(keyIt);
                }
                it = m_fileKeyTimes.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// ── Core sealing primitive ────────────────────────────────────────────────────
// Returns the sealed envelope bytes (SEALED:<version>\n<ciphertext>), or empty
// on failure.  Every outbound path should call this instead of inlining the
// encrypt→convert→seal→prefix logic.
QByteArray ChatController::sealForPeer(const QString& peerIdB64u,
                                       const QByteArray& plaintext)
{
    if (!m_sessionMgr) return {};
    QByteArray sessionBlob = m_sessionMgr->encryptForPeer(peerIdB64u, plaintext);
    if (sessionBlob.isEmpty()) return {};

    QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(
            peerCurvePub,
            reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0)
        return {};

    QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
    sodium_memzero(peerCurvePub, sizeof(peerCurvePub));  // G11 fix
    QByteArray sealed = SealedEnvelope::seal(
        recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), sessionBlob);
    if (sealed.isEmpty()) return {};

    return kSealedPrefix + "\n" + sealed;
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
        qDebug() << "[SEND MAILBOX] sealed" << type << "to" << peerIdB64u.left(8) + "...";
#endif
        m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
        return;
    }

    // ── Fail closed: only ICE signaling may fall back to legacy ─────────────
    // S10 fix: inlined legacy send — sendSignalingMessage() removed as standalone method
    if (type == "ice_offer" || type == "ice_answer") {
        qWarning() << "[SEND MAILBOX] legacy fallback for" << type
                    << "to" << peerIdB64u.left(8) + "..." << "(ICE signaling)";
        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
        const QByteArray key32  = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) return;
        const QByteArray icePt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        const QByteArray ct     = m_crypto.aeadEncrypt(key32, icePt);
        const QByteArray env    = kMsgPrefix + myIdB64u().toUtf8() + "\n" + ct;
        m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
        return;
    }

    qWarning() << "[SEND] BLOCKED — cannot seal" << type
               << "to" << peerIdB64u.left(8) + "...";
    emit status(QString("Could not send %1 — encrypted session unavailable. "
                        "Try sending a text message first to establish the session.")
                    .arg(type));
}

// ── L2 fix: shared ICE connection setup ──────────────────────────────────────
NiceConnection* ChatController::setupP2PConnection(const QString& peerIdB64u, bool controlling)
{
    NiceConnection* conn = new NiceConnection(this);
    if (!m_turnHost.isEmpty())
        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
    m_p2pConnections[peerIdB64u] = conn;

    const QString iceType = controlling ? "ice_offer" : "ice_answer";
    connect(conn, &NiceConnection::localSdpReady, this, [this, peerIdB64u, iceType](const QString& sdp) {
        QJsonObject p;
        p["type"] = iceType;
        p["from"] = myIdB64u();
        p["sdp"]  = sdp;
        sendSealedPayload(peerIdB64u, p);   // S8 fix: use sealed path for ICE signaling
    });
    connect(conn, &NiceConnection::stateChanged, this, [this, peerIdB64u](int state) {
        if      (state == NICE_COMPONENT_STATE_READY)  emit status("P2P ready with " + peerIdB64u);
        else if (state == NICE_COMPONENT_STATE_FAILED) emit status("P2P failed for " + peerIdB64u);
    });
    connect(conn, &NiceConnection::dataReceived, this, [this, peerIdB64u](const QByteArray& d) {
        onP2PDataReceived(peerIdB64u, d);
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
        onEnvelope(data, QString());
        return;
    }

    // ── File chunk received over P2P (legacy) ────────────────────────────────
    if (data.startsWith(kFilePrefix)) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV P2P] file chunk from" << peerIdB64u.left(8) + "...";
#endif
        onEnvelope(data, QString());
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
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[RECV P2P] legacy text from" << peerIdB64u.left(8) + "...";
#endif
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

void ChatController::onEnvelope(const QByteArray& body, const QString& envId)
{
    // NOTE: The server pops the envelope on fetch — ACK is a no-op kept only for
    // forward compatibility.  We do NOT call ack here to avoid the extra HTTP round-trip.
    Q_UNUSED(envId)

    // Determine transport: P2P forwards call us with empty envId
    const QString via = envId.isEmpty() ? "P2P" : "MAILBOX";

    const int nl = body.indexOf('\n');
    if (nl < 0) return;

    const QByteArray header = body.left(nl);
    const QByteArray rest   = body.mid(nl + 1);

    // ── Sealed sender envelope ───────────────────────────────────────────────
    if (header.startsWith(kSealedPrefix) || header.startsWith(kSealedFCPrefix)) {
        const bool isFileChunk = header.startsWith(kSealedFCPrefix);

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[RECV" << via << "] sealed envelope | size:" << rest.size() << "B"
                 << (isFileChunk ? "(file chunk)" : "");
#endif

        // Unseal to learn sender identity
        UnsealResult unsealed = SealedEnvelope::unseal(m_crypto.curvePriv(), rest);
        if (!unsealed.valid) {
            qWarning() << "[ChatController] Failed to unseal envelope";
            return;
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
            if (!unsealed.innerPayload.isEmpty() && static_cast<quint8>(unsealed.innerPayload[0]) == 0x02) {
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[RECV" << via << "] handshake COMPLETED with" << senderId.left(8) + "...";
#endif
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
            emit groupMessageReceived(senderId, gid,
                                       o.value("groupName").toString(),
                                       memberKeys, o.value("text").toString(), ts, msgId);
        } else if (type == "group_leave") {
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();
            emit groupMemberLeft(senderId, o.value("groupId").toString(),
                                  o.value("groupName").toString(), memberKeys, ts, msgId);
        } else if (type == "avatar") {
            emit avatarReceived(senderId, o.value("name").toString(), o.value("avatar").toString());
        } else if (type == "group_rename") {
            emit groupRenamed(o.value("groupId").toString(), o.value("newName").toString());
        } else if (type == "group_avatar") {
            emit groupAvatarReceived(o.value("groupId").toString(), o.value("avatar").toString());
        } else if (type == "group_member_update") {
            const QString gid       = o.value("groupId").toString();
            const QString gname     = o.value("groupName").toString();
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();

            // Re-use the existing groupMessageReceived signal — the
            // ChatView::onIncomingGroupMessage handler already merges new
            // member keys into the group's key list.
            // Empty text means no chat bubble appears, but the key merge still happens.
            emit groupMessageReceived(senderId, gid, gname, memberKeys,
                                      QString(),
                                      QDateTime::fromSecsSinceEpoch(
                                          o.value("ts").toVariant().toLongLong()),
                                      QUuid::createUuid().toString(QUuid::WithoutBraces));
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
                    setupP2PConnection(senderId, false);  // L2 fix
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
            }
        } else if (type == "ice_answer") {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[RECV" << via << "] ice_answer from" << senderId.left(8) + "...";
#endif
            if (m_p2pConnections.contains(senderId) &&
                !m_p2pConnections[senderId]->isReady())
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
        } else if (type == "file_key") {
            // File key announcement: store the ratchet-derived key for chunk decryption.
            // M4 fix: key on senderId:transferId to avoid collisions when multiple
            // senders use the same transferId (e.g., group file transfers).
            const QString transferId = o.value("transferId").toString();
            if (!transferId.isEmpty() && msgKey.size() == 32) {
                const QString compoundKey = senderId + ":" + transferId;
                m_fileKeys[compoundKey] = msgKey;  // M3+M4 fix
                m_fileKeyTimes[compoundKey] = QDateTime::currentSecsSinceEpoch();  // M8 fix
                sodium_memzero(msgKey.data(), msgKey.size());
#ifndef QT_NO_DEBUG_OUTPUT
                qDebug() << "[FILE] stored ratchet key for transfer" << transferId.left(8) + "..."
                         << "from" << senderId.left(8) + "...";
#endif
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
    if (type != "ice_offer" && type != "ice_answer" && type != "text") {
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
    } else if (type == "ice_offer") {
        if (m_p2pConnections.contains(fromId) &&
            m_p2pConnections[fromId]->isReady()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[ICE] Already connected to" << fromId.left(8) + "... — ignoring ice_offer";
#endif
        } else {
            if (!m_p2pConnections.contains(fromId))
                setupP2PConnection(fromId, false);  // L2 fix
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
        }
    } else if (type == "ice_answer") {
        if (m_p2pConnections.contains(fromId) &&
            !m_p2pConnections[fromId]->isReady())
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
    }
}

void ChatController::sendGroupRename(const QString& groupId,
                                     const QString& newName,
                                     const QStringList& memberKeys)
{
    QJsonObject payload;
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_rename";
    payload["groupId"] = groupId;
    payload["newName"] = newName;
    for (const QString &key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupAvatar(const QString& groupId,
                                     const QString& avatarB64,
                                     const QStringList& memberKeys)
{
    QJsonObject payload;
    payload["from"]    = myIdB64u();
    payload["type"]    = "group_avatar";
    payload["groupId"] = groupId;
    payload["avatar"]  = avatarB64;
    for (const QString &key : memberKeys)
        sendSealedPayload(key, payload);   // S7 fix
}

void ChatController::sendGroupMemberUpdate(const QString& groupId,
                                           const QString& groupName,
                                           const QStringList& memberKeys)
{
    const QString myId = myIdB64u();

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
