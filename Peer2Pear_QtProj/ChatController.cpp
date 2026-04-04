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
            qDebug() << "[ICE] Cleaning up stale connection to" << key.left(8) + "...";
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
        qDebug() << "[SEND MAILBOX] sealed handshake response to" << peerId.left(8) + "...";

        QByteArray env = kSealedPrefix + "\n" + sealed;
        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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

    // ── Sealed Ratchet path (preferred) ──────────────────────────────────────
    if (m_sessionMgr) {
        QByteArray sessionBlob = m_sessionMgr->encryptForPeer(peerIdB64u, pt);
        if (!sessionBlob.isEmpty()) {
            // Convert peer's Ed25519 pub to X25519 for sealing
            QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
            unsigned char peerCurvePub[32];
            if (crypto_sign_ed25519_pk_to_curve25519(
                    peerCurvePub,
                    reinterpret_cast<const unsigned char*>(peerEdPub.constData())) == 0) {

                QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
                QByteArray sealed = SealedEnvelope::seal(
                    recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), sessionBlob);

                if (!sealed.isEmpty()) {
                    if (m_p2pConnections.contains(peerIdB64u) &&
                        m_p2pConnections[peerIdB64u]->isReady()) {
                        qDebug() << "[SEND P2P] sealed text to" << peerIdB64u.left(8) + "..."
                                 << "| size:" << sealed.size() << "B";
                        m_p2pConnections[peerIdB64u]->sendData(kSealedPrefix + "\n" + sealed);
                    } else {
                        QByteArray env = kSealedPrefix + "\n" + sealed;
                        qDebug() << "[SEND MAILBOX] sealed text to" << peerIdB64u.left(8) + "..."
                                 << "| size:" << env.size() << "B";
                        m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
                        initiateP2PConnection(peerIdB64u);
                    }
                    return;
                }
            }
        }
    }

    // ── Legacy path (fallback) ───────────────────────────────────────────────
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray ct      = m_crypto.aeadEncrypt(m_crypto.deriveSharedKey32(peerPub), pt);

    if (m_p2pConnections.contains(peerIdB64u) && m_p2pConnections[peerIdB64u]->isReady()) {
        qDebug() << "[SEND P2P] legacy text to" << peerIdB64u.left(8) + "...";
        m_p2pConnections[peerIdB64u]->sendData(ct);
    } else {
        qDebug() << "[SEND MAILBOX] legacy text to" << peerIdB64u.left(8) + "...";
        sendSignalingMessage(peerIdB64u, payload);
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
    sendSignalingMessage(peerIdB64u, payload);
}

// ── File transfer delegation ─────────────────────────────────────────────────

QString ChatController::sendFile(const QString& peerIdB64u,
                                 const QString& fileName,
                                 const QByteArray& fileData)
{
    return m_fileMgr.sendFile(myIdB64u(), peerIdB64u, fileName, fileData);
}

QString ChatController::sendGroupFile(const QString& groupId,
                                      const QString& groupName,
                                      const QStringList& memberPeerIds,
                                      const QString& fileName,
                                      const QByteArray& fileData)
{
    return m_fileMgr.sendGroupFile(myIdB64u(), groupId, groupName,
                                   memberPeerIds, fileName, fileData);
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
    qDebug() << "[ChatController] TURN server set:" << host << ":" << port;
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
        if (key.trimmed() == myId) continue; // don't include yourself in member list
        membersArray.append(key);
    }
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

        const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);

        // Sealed Ratchet path
        if (m_sessionMgr) {
            QByteArray sessionBlob = m_sessionMgr->encryptForPeer(peerId, pt);
            if (!sessionBlob.isEmpty()) {
                QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerId);
                unsigned char peerCurvePub[32];
                if (crypto_sign_ed25519_pk_to_curve25519(
                        peerCurvePub,
                        reinterpret_cast<const unsigned char*>(peerEdPub.constData())) == 0) {
                    QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
                    QByteArray sealed = SealedEnvelope::seal(
                        recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), sessionBlob);
                    if (!sealed.isEmpty()) {
                        QByteArray env = kSealedPrefix + "\n" + sealed;
                        qDebug() << "[SEND MAILBOX] sealed group_msg to" << peerId.left(8) + "...";
                        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
                        continue;
                    }
                }
            }
        }

        // Legacy fallback
        qDebug() << "[SEND MAILBOX] legacy group_msg to" << peerId.left(8) + "...";
        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        const QByteArray ct  = m_crypto.aeadEncrypt(key32, pt);
        const QByteArray env = kMsgPrefix + myId.toUtf8() + "\n" + ct;
        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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

        // Sealed Ratchet path
        if (m_sessionMgr) {
            QByteArray sessionBlob = m_sessionMgr->encryptForPeer(peerId, pt);
            if (!sessionBlob.isEmpty()) {
                QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerId);
                unsigned char peerCurvePub[32];
                if (crypto_sign_ed25519_pk_to_curve25519(
                        peerCurvePub,
                        reinterpret_cast<const unsigned char*>(peerEdPub.constData())) == 0) {
                    QByteArray recipientCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);
                    QByteArray sealed = SealedEnvelope::seal(
                        recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(), sessionBlob);
                    if (!sealed.isEmpty()) {
                        qDebug() << "[SEND MAILBOX] sealed group_leave to" << peerId.left(8) + "...";
                        QByteArray env = kSealedPrefix + "\n" + sealed;
                        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
                        continue;
                    }
                }
            }
        }

        // Legacy fallback
        qDebug() << "[SEND MAILBOX] legacy group_leave to" << peerId.left(8) + "...";
        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        const QByteArray ct  = m_crypto.aeadEncrypt(key32, pt);
        const QByteArray env = QByteArray("FROM:") + myId.toUtf8() + "\n" + ct;
        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
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
    // fetchAll retrieves every pending envelope in one authenticated request.
    // Falls back to single fetch() automatically if the server doesn't yet
    // support /mbox/fetch_all (404/405 response).
    m_mbox.fetchAll(myIdB64u());
    for (const QString &key : std::as_const(m_selfKeys)) {
        if (!key.trimmed().isEmpty() && key.trimmed() != myIdB64u()) m_mbox.fetchAll(key.trimmed());
    }

    // Purge stale incomplete transfers to bound memory usage
    m_fileMgr.purgeStaleTransfers();
}

void ChatController::sendSignalingMessage(const QString& peerIdB64u,
                                          const QJsonObject& payload)
{
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
    if (key32.size() != 32) return;

    const QByteArray pt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray ct  = m_crypto.aeadEncrypt(key32, pt);
    const QByteArray env = kMsgPrefix + myIdB64u().toUtf8() + "\n" + ct;
    m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
}

void ChatController::initiateP2PConnection(const QString& peerIdB64u)
{
    if (m_p2pConnections.contains(peerIdB64u)) return;

    NiceConnection* conn = new NiceConnection(this);
    if (!m_turnHost.isEmpty())
        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
    m_p2pConnections[peerIdB64u] = conn;

    connect(conn, &NiceConnection::localSdpReady, this, [this, peerIdB64u](const QString& sdp) {
        QJsonObject p; p["type"]="ice_offer"; p["from"]=myIdB64u(); p["sdp"]=sdp;
        sendSignalingMessage(peerIdB64u, p);
    });
    connect(conn, &NiceConnection::stateChanged, this, [this, peerIdB64u](int state) {
        if      (state == NICE_COMPONENT_STATE_READY)  emit status("P2P ready with " + peerIdB64u);
        else if (state == NICE_COMPONENT_STATE_FAILED) emit status("P2P failed for " + peerIdB64u);
    });
    connect(conn, &NiceConnection::dataReceived, this, [this, peerIdB64u](const QByteArray& ct) {
        onP2PDataReceived(peerIdB64u, ct);
    });
    conn->initIce(true);
}

void ChatController::onP2PDataReceived(const QString& peerIdB64u, const QByteArray& data)
{
    qDebug() << "[ChatController] P2P data received from" << peerIdB64u.left(8) + "..."
             << "| size:" << data.size() << "B";

    // P2P data proves the peer is online right now
    emit presenceChanged(peerIdB64u, true);

    // ── Sealed envelope over P2P ─────────────────────────────────────────────
    if (data.startsWith(kSealedPrefix) || data.startsWith(kSealedFCPrefix)) {
        qDebug() << "[RECV P2P] sealed envelope from" << peerIdB64u.left(8) + "...";
        onEnvelope(data, QString());
        return;
    }

    // ── File chunk received over P2P (legacy) ────────────────────────────────
    if (data.startsWith(kFilePrefix)) {
        qDebug() << "[RECV P2P] file chunk from" << peerIdB64u.left(8) + "...";
        onEnvelope(data, QString());
        return;
    }

    // ── Try ratchet decrypt first (P2P with session) ─────────────────────────
    if (m_sessionMgr && m_sessionMgr->hasSession(peerIdB64u)) {
        QByteArray pt = m_sessionMgr->decryptFromPeer(peerIdB64u, data);
        if (!pt.isEmpty()) {
            const auto o = QJsonDocument::fromJson(pt).object();
            if (o.value("type").toString() == "text") {
                qDebug() << "[RECV P2P] ratchet text from" << peerIdB64u.left(8) + "...";
                const QString msgId = o.value("msgId").toString();
                if (!msgId.isEmpty() && !markSeen(msgId)) return;
                emit messageReceived(peerIdB64u, o.value("text").toString(),
                                     tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
            }
            return;
        }
    }

    // ── Legacy encrypted JSON message ────────────────────────────────────────
    qDebug() << "[RECV P2P] legacy text from" << peerIdB64u.left(8) + "...";
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
        if (!m_sessionMgr) return; // can't process without session manager

        qDebug() << "[RECV" << via << "] sealed envelope | size:" << rest.size() << "B";

        // Unseal to learn sender identity
        UnsealResult unsealed = SealedEnvelope::unseal(m_crypto.curvePriv(), rest);
        if (!unsealed.valid) {
            qWarning() << "[ChatController] Failed to unseal envelope";
            return;
        }

        QString senderId = CryptoEngine::toBase64Url(unsealed.senderEdPub);
        qDebug() << "[RECV" << via << "] unsealed OK | sender:" << senderId.left(8) + "..."
                 << "| inner:" << unsealed.innerPayload.size() << "B";

        // Only emit "online" if the envelope is recent (within 2 minutes).
        // Old mailbox messages should not trigger false online presence.  (L3 fix)
        // Note: sealed envelopes carry no timestamp, so we infer freshness from
        // the transport — P2P is always live; mailbox may have stale messages.
        if (via == "P2P") emit presenceChanged(senderId, true);

        // Decrypt session layer (Noise handshake or ratchet message)
        QByteArray pt = m_sessionMgr->decryptFromPeer(senderId, unsealed.innerPayload);
        if (pt.isEmpty()) {
            // Pre-key response (0x02) completes the Noise IK handshake and creates
            // a ratchet session inside decryptFromPeer(), but returns no user payload.
            // This is expected — future messages will use the ratchet session.
            if (!unsealed.innerPayload.isEmpty() && static_cast<quint8>(unsealed.innerPayload[0]) == 0x02)
                qDebug() << "[RECV" << via << "] handshake COMPLETED with" << senderId.left(8) + "...";
            else
                qDebug() << "[RECV" << via << "] session decrypt empty from" << senderId.left(8) + "...";
            return;
        }

        // Dispatch based on the decrypted JSON payload
        // (same logic as legacy message handling below)
        const auto o = QJsonDocument::fromJson(pt).object();
        const QString type = o.value("type").toString();

        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsFromSecs(tsSecs);
        const QString msgId = o.value("msgId").toString();

        qDebug() << "[RECV" << via << "] sealed type:" << type << "from" << senderId.left(8) + "...";

        if (type == "text") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;
            emit messageReceived(senderId, o.value("text").toString(), ts, msgId);
        } else if (type == "group_msg") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();
            emit groupMessageReceived(senderId, o.value("groupId").toString(),
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
        } else if (type == "ice_offer") {
            qDebug() << "[RECV" << via << "] ice_offer from" << senderId.left(8) + "...";
            // Skip if we already have a working P2P connection
            if (m_p2pConnections.contains(senderId) &&
                m_p2pConnections[senderId]->isReady()) {
                qDebug() << "[ICE] Already connected to" << senderId.left(8) + "... — ignoring ice_offer";
            } else {
                if (!m_p2pConnections.contains(senderId)) {
                    NiceConnection* conn = new NiceConnection(this);
                    if (!m_turnHost.isEmpty())
                        conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
                    m_p2pConnections[senderId] = conn;
                    connect(conn, &NiceConnection::localSdpReady, this, [this, senderId](const QString& sdp) {
                        QJsonObject p; p["type"]="ice_answer"; p["from"]=myIdB64u(); p["sdp"]=sdp;
                        sendSignalingMessage(senderId, p);
                    });
                    connect(conn, &NiceConnection::stateChanged, this, [this, senderId](int state) {
                        if (state == NICE_COMPONENT_STATE_READY)
                            emit status("P2P ready with " + senderId);
                    });
                    connect(conn, &NiceConnection::dataReceived, this, [this, senderId](const QByteArray& d) {
                        onP2PDataReceived(senderId, d);
                    });
                    conn->initIce(false);
                }
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
            }
        } else if (type == "ice_answer") {
            qDebug() << "[RECV" << via << "] ice_answer from" << senderId.left(8) + "...";
            if (m_p2pConnections.contains(senderId) &&
                !m_p2pConnections[senderId]->isReady())
                m_p2pConnections[senderId]->setRemoteSdp(o.value("sdp").toString());
        } else if (type == "file_chunk") {
            // Sealed file chunk — handle metadata and chunk data from JSON
            // (for sealed path, the chunk data is embedded in the session payload)
            // This would require different wire format for sealed files — deferred
        }
        return;
    }

    // ── File chunk envelope ─────────────────────────────────────────────────
    if (header.startsWith(kFilePrefix)) {
        const QString fromId = QString::fromUtf8(header.mid(kFilePrefix.size())).trimmed();
        qDebug() << "[RECV" << via << "] file chunk from" << fromId.left(8) + "...";
        m_fileMgr.handleFileEnvelope(fromId, rest,
            [this](const QString& id) { return markSeen(id); });
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
    qDebug() << "[RECV" << via << "] legacy type:" << type << "from" << fromId.left(8) + "...";

    const qint64 tsSecs = o.value("ts").toVariant().toLongLong();

    // L3 fix: Only emit "online" if message is fresh (< 2 min old) or via P2P
    if (via == "P2P" ||
        (tsSecs > 0 && QDateTime::currentSecsSinceEpoch() - tsSecs < 120))
        emit presenceChanged(fromId, true);
    const QDateTime ts = tsSecs > 0
                             ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime()
                             : QDateTime::currentDateTime();

    const QString msgId = o.value("msgId").toString();

    if (type == "text") {
        if (!msgId.isEmpty() && !markSeen(msgId)) return;
        emit messageReceived(fromId, o.value("text").toString(),
                             tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
    } else if (type == "ice_offer") {
        // Skip if we already have a working P2P connection
        if (m_p2pConnections.contains(fromId) &&
            m_p2pConnections[fromId]->isReady()) {
            qDebug() << "[ICE] Already connected to" << fromId.left(8) + "... — ignoring ice_offer";
        } else {
            if (!m_p2pConnections.contains(fromId)) {
                NiceConnection* conn = new NiceConnection(this);
                if (!m_turnHost.isEmpty())
                    conn->setTurnServer(m_turnHost, m_turnPort, m_turnUser, m_turnPass);
                m_p2pConnections[fromId] = conn;
                connect(conn, &NiceConnection::localSdpReady, this, [this, fromId](const QString& sdp) {
                    QJsonObject p; p["type"]="ice_answer"; p["from"]=myIdB64u(); p["sdp"]=sdp;
                    sendSignalingMessage(fromId, p);
                });
                connect(conn, &NiceConnection::stateChanged, this, [this, fromId](int state) {
                    if (state == NICE_COMPONENT_STATE_READY)
                        emit status("P2P ready with " + fromId);
                });
                connect(conn, &NiceConnection::dataReceived, this, [this, fromId](const QByteArray& d) {
                    onP2PDataReceived(fromId, d);
                });
                conn->initIce(false);
            }
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
        }
    } else if (type == "ice_answer") {
        if (m_p2pConnections.contains(fromId) &&
            !m_p2pConnections[fromId]->isReady())
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());

    } else if (type == "group_msg") {
        if (!msgId.isEmpty() && !markSeen(msgId)) return;
        QStringList memberKeys;
        for (const QJsonValue &v : o.value("members").toArray())
            memberKeys << v.toString();
        emit groupMessageReceived(
            fromId,
            o.value("groupId").toString(),
            o.value("groupName").toString(),
            memberKeys,
            o.value("text").toString(),
            ts,
            msgId
            );
    } else if (type == "group_leave") {
        QStringList memberKeys;
        for (const QJsonValue &v : o.value("members").toArray())
            memberKeys << v.toString();

        emit groupMemberLeft(
            fromId,
            o.value("groupId").toString(),
            o.value("groupName").toString(),
            memberKeys,
            ts,
            msgId);
    } else if (type == "avatar") {
        emit avatarReceived(fromId,
                            o.value("name").toString(),
                            o.value("avatar").toString());
    } else if (type == "group_rename") {
        emit groupRenamed(o.value("groupId").toString(),
                          o.value("newName").toString());
    } else if (type == "group_avatar") {
        emit groupAvatarReceived(o.value("groupId").toString(),
                                 o.value("avatar").toString());
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
        sendSignalingMessage(key, payload);
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
        sendSignalingMessage(key, payload);
}
