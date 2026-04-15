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
                m_fileKeyTimes.remove(it.key());  // M8 fix
                it = m_fileKeys.erase(it);
            } else {
                ++it;
            }
        }
    });

    // Periodic maintenance: handshake pruning, file key cleanup, ICE cleanup
    connect(&m_maintenanceTimer, &QTimer::timeout, this, [this]() {
        // H3 fix: reset per-sender rate limit counters
        m_envelopeCount.clear();

        // Purge stale incomplete transfers
        m_fileMgr.purgeStaleTransfers();

        // H2/SEC9: prune stuck handshakes
        if (m_sessionStore) {
            const QStringList pruned = m_sessionStore->pruneStaleHandshakes();
            for (const QString &peerId : pruned) {
                int count = ++m_handshakeFailCount[peerId];
                if (count >= 2)
                    emit peerMayNeedUpgrade(peerId);
            }
        }

        // M8 fix: purge orphaned file keys older than 30 minutes
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
    {
        SqlCipherQuery q(db);
        q.prepare("SELECT value FROM settings WHERE key='ratchet_v6_cleared';");
        if (!q.exec() || !q.next()) {
            m_sessionStore->clearAll();
            SqlCipherQuery ins(db);
            ins.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('ratchet_v6_cleared','1');");
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
        QByteArray peerKemPub = lookupPeerKemPub(peerId);
        QByteArray sealed = SealedEnvelope::seal(
            recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(),
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
            recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(),
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
    m_relay.sendEnvelope(sealedEnv);

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

        m_relay.sendEnvelope(sealedEnv);

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
        recipientCurvePub, m_crypto.identityPub(), m_crypto.identityPriv(),
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
        qDebug() << "[SEND MAILBOX] sealed" << type << "to" << peerIdB64u.left(8) + "...";
#endif
        m_relay.sendEnvelope(env);
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
        m_relay.sendEnvelopeTo(peerIdB64u, env);
        return;
    }

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

        // Unseal to learn sender identity (pass KEM priv for hybrid PQ envelopes)
        UnsealResult unsealed = SealedEnvelope::unseal(
            m_crypto.curvePriv(), rest, m_crypto.kemPriv());
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
            emit groupMessageReceived(senderId, gid,
                                       o.value("groupName").toString(),
                                       memberKeys, o.value("text").toString(), ts, msgId);
        } else if (type == "group_leave") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B2 fix: dedup
            QStringList memberKeys;
            for (const QJsonValue &v : o.value("members").toArray())
                memberKeys << v.toString();
            emit groupMemberLeft(senderId, o.value("groupId").toString(),
                                  o.value("groupName").toString(), memberKeys, ts, msgId);
        } else if (type == "avatar") {
            emit avatarReceived(senderId, o.value("name").toString(), o.value("avatar").toString());
        } else if (type == "group_rename") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            emit groupRenamed(o.value("groupId").toString(), o.value("newName").toString());
        } else if (type == "group_avatar") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B5 fix: dedup
            emit groupAvatarReceived(o.value("groupId").toString(), o.value("avatar").toString());
        } else if (type == "group_member_update") {
            if (!msgId.isEmpty() && !markSeen(msgId)) return;  // B3 fix: dedup
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
