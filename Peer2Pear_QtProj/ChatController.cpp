#include "ChatController.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>
#include <sodium.h>

// ── Chunk size ────────────────────────────────────────────────────────────────
// The server enforces MAX_ENVELOPE_BYTES = 256 KB (262 144 bytes).
//
// Per-envelope overhead budget:
//   "FROMFC:<43-char-key>\n"          =  51 bytes  (header)
//   4-byte big-endian metaLen field   =   4 bytes
//   encMeta (JSON ~250 B + AEAD 40 B) = ~290 bytes
//   encChunk AEAD overhead            =  40 bytes
//   ─────────────────────────────────────────────
//   Total fixed overhead              = ~385 bytes
//
// Max plaintext chunk = 262 144 - 385 = ~261 759 bytes.
// We use 240 KB = 245 760 bytes for a comfortable margin.
// A 25 MB file therefore travels in at most ceil(25600 / 240) = 107 chunks.
static constexpr qint64 kChunkBytes   = 240LL * 1024;   // 245 760 bytes
static constexpr qint64 kMaxFileBytes =  25LL * 1024 * 1024;

// Envelope header prefixes
static const QByteArray kMsgPrefix  = "FROM:";
static const QByteArray kFilePrefix = "FROMFC:";

// ── Helpers ───────────────────────────────────────────────────────────────────

static QByteArray pack32(quint32 v)
{
    QByteArray b(4, 0);
    b[0] = char((v >> 24) & 0xFF);
    b[1] = char((v >> 16) & 0xFF);
    b[2] = char((v >>  8) & 0xFF);
    b[3] = char( v        & 0xFF);
    return b;
}

static quint32 unpack32(const QByteArray &b, int offset = 0)
{
    return (quint8(b[offset])   << 24)
    | (quint8(b[offset+1]) << 16)
        | (quint8(b[offset+2]) <<  8)
        |  quint8(b[offset+3]);
}

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
{
    connect(&m_mbox, &MailboxClient::status,           this, &ChatController::status);
    connect(&m_rvz,  &RendezvousClient::status,        this, &ChatController::status);
    connect(&m_mbox, &MailboxClient::envelopeReceived, this, &ChatController::onEnvelope);
    connect(&m_pollTimer, &QTimer::timeout,            this, &ChatController::pollOnce);
    connect(&m_rvz,  &RendezvousClient::presenceResult, this, &ChatController::presenceChanged);

    // Refresh rendezvous registration every 9 minutes (TTL is 10 min)
    connect(&m_rvzRefreshTimer, &QTimer::timeout, this, [this]() {
        m_rvz.publish("3.141.14.234", 0, 10LL * 60 * 1000);
    });
    m_rvzRefreshTimer.setInterval(9 * 60 * 1000);
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

    const QByteArray pt      = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray ct      = m_crypto.aeadEncrypt(m_crypto.deriveSharedKey32(peerPub), pt);

    if (m_p2pConnections.contains(peerIdB64u) && m_p2pConnections[peerIdB64u]->isReady()) {
        // P2P ready — send directly, skip the mailbox relay
        m_p2pConnections[peerIdB64u]->sendData(ct);
    } else {
        // No P2P — relay via mailbox and start ICE negotiation
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

// ── BLAKE2b-256 hash ─────────────────────────────────────────────────────────

QByteArray ChatController::blake2b256(const QByteArray& data)
{
    QByteArray hash(32, 0);
    crypto_generichash(reinterpret_cast<unsigned char*>(hash.data()), 32,
                       reinterpret_cast<const unsigned char*>(data.constData()),
                       static_cast<unsigned long long>(data.size()),
                       nullptr, 0);
    return hash;
}

// ── Reliable chunk sender (mailbox-primary, P2P-assist) ─────────────────────
//
// File chunks ALWAYS go through the mailbox for guaranteed delivery.
// UDP (the transport beneath ICE/libnice) cannot reliably carry 240 KB+
// datagrams — IP fragmentation drops are silent and unrecoverable.
//
// When a P2P connection is also ready we *additionally* send via P2P as
// a latency optimisation.  The receiver's per-chunk dedup
// ("transferId:chunkIndex") ensures only one copy is processed.

void ChatController::sendFileChunkEnvelope(const QString& peerIdB64u,
                                           const QByteArray& /* key32 */,
                                           const QByteArray& env)
{
    // Always enqueue to mailbox — reliable delivery over HTTP
    m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);

    // Initiate P2P for future text messages (but don't rely on it for files)
    if (!m_p2pConnections.contains(peerIdB64u))
        initiateP2PConnection(peerIdB64u);
}

QString ChatController::sendFile(const QString& peerIdB64u,
                                 const QString& fileName,
                                 const QByteArray& fileData)
{
    if (fileData.size() > kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
    if (key32.size() != 32) {
        emit status("Cannot derive shared key for: " + peerIdB64u);
        return {};
    }

    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const qint64  ts         = QDateTime::currentSecsSinceEpoch();
    const qint64  fileSize   = fileData.size();
    const int totalChunks    = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    // Compute BLAKE2b-256 integrity hash over the entire plaintext file
    const QByteArray fileHash = blake2b256(fileData);
    const QString fileHashB64u = CryptoEngine::toBase64Url(fileHash);

    for (int i = 0; i < totalChunks; ++i) {
        const qint64     offset   = qint64(i) * kChunkBytes;
        const QByteArray chunk    = fileData.mid(int(offset), int(kChunkBytes));

        QJsonObject meta;
        meta["from"]        = myIdB64u();
        meta["type"]        = "file_chunk";
        meta["transferId"]  = transferId;
        meta["chunkIndex"]  = i;
        meta["totalChunks"] = totalChunks;
        meta["fileName"]    = fileName;
        meta["fileSize"]    = fileSize;
        meta["ts"]          = ts;
        meta["fileHash"]    = fileHashB64u;

        const QByteArray metaJson = QJsonDocument(meta).toJson(QJsonDocument::Compact);
        const QByteArray encMeta  = m_crypto.aeadEncrypt(key32, metaJson);
        const QByteArray encChunk = m_crypto.aeadEncrypt(key32, chunk);

        // Wire format: FROMFC:<senderId>\n<4-byte metaLen><encMeta><encChunk>
        const QByteArray env = kFilePrefix + myIdB64u().toUtf8() + "\n"
                               + pack32(quint32(encMeta.size()))
                               + encMeta
                               + encChunk;

        sendFileChunkEnvelope(peerIdB64u, key32, env);
    }

    emit status(QString("'%1' queued in %2 chunk(s) → %3")
                    .arg(fileName).arg(totalChunks).arg(peerIdB64u));
    return transferId;
}

QString ChatController::sendGroupFile(const QString& groupId,
                                      const QString& groupName,
                                      const QStringList& memberPeerIds,
                                      const QString& fileName,
                                      const QByteArray& fileData)
{
    if (fileData.size() > kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(kMaxFileBytes / (1024 * 1024)));
        return {};
    }

    const QString myId       = myIdB64u();
    const QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const qint64  ts         = QDateTime::currentSecsSinceEpoch();
    const qint64  fileSize   = fileData.size();
    const int totalChunks    = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    // Compute BLAKE2b-256 integrity hash over the entire plaintext file
    const QByteArray fileHash = blake2b256(fileData);
    const QString fileHashB64u = CryptoEngine::toBase64Url(fileHash);

    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == myId) continue;

        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        for (int i = 0; i < totalChunks; ++i) {
            const qint64     offset   = qint64(i) * kChunkBytes;
            const QByteArray chunk    = fileData.mid(int(offset), int(kChunkBytes));

            QJsonObject meta;
            meta["from"]        = myId;
            meta["type"]        = "file_chunk";
            meta["transferId"]  = transferId;
            meta["chunkIndex"]  = i;
            meta["totalChunks"] = totalChunks;
            meta["fileName"]    = fileName;
            meta["fileSize"]    = fileSize;
            meta["ts"]          = ts;
            meta["fileHash"]    = fileHashB64u;
            meta["groupId"]     = groupId;
            meta["groupName"]   = groupName;

            const QByteArray metaJson = QJsonDocument(meta).toJson(QJsonDocument::Compact);
            const QByteArray encMeta  = m_crypto.aeadEncrypt(key32, metaJson);
            const QByteArray encChunk = m_crypto.aeadEncrypt(key32, chunk);

            const QByteArray env = kFilePrefix + myId.toUtf8() + "\n"
                                   + pack32(quint32(encMeta.size()))
                                   + encMeta
                                   + encChunk;

            sendFileChunkEnvelope(peerId, key32, env);
        }
    }

    emit status(QString("'%1' queued in %2 chunk(s) → group %3")
                    .arg(fileName).arg(totalChunks).arg(groupName));
    return transferId;
}

void ChatController::startPolling(int intervalMs)
{
    if (!m_pollTimer.isActive()) {
        m_pollTimer.start(intervalMs);
        // Publish our identity to the rendezvous server so peers can discover us.
        // host="0.0.0.0" is a placeholder — the server records the request's source IP.
        // TTL of 10 minutes; we refresh on every poll start.
        m_rvz.publish("3.141.14.234", 0, 10LL * 60 * 1000);
        m_rvzRefreshTimer.start();
        // Immediately drain the mailbox on startup rather than waiting for first tick
        pollOnce();
    }
}

void ChatController::stopPolling()
{
    m_pollTimer.stop();
    m_rvzRefreshTimer.stop();   // stop advertising presence to rendezvous
}

void ChatController::setSelfKeys(const QStringList& keys) { m_selfKeys = keys; }

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

        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_msg";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["text"]      = text;
        payload["ts"]        = ts;
        payload["msgId"]     = msgId;

        const QByteArray pt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
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

        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_leave";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["members"]   = membersArray;
        payload["ts"]        = ts;

        const QByteArray pt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
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
    for (const QString &key : m_selfKeys) {
        if (!key.trimmed().isEmpty() && key.trimmed() != myIdB64u()) m_mbox.fetchAll(key.trimmed());
    }

    // Purge stale incomplete transfers to bound memory usage
    purgeStaleTransfers();
}

void ChatController::purgeStaleTransfers()
{
    static constexpr qint64 kMaxTransferAgeSecs = 30 * 60;  // 30 minutes
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    auto it = m_incomingTransfers.begin();
    while (it != m_incomingTransfers.end()) {
        if (it->createdSecs > 0 && (now - it->createdSecs) > kMaxTransferAgeSecs) {
            emit status(QString("Purged stale transfer '%1' (%2/%3 chunks) after 30 min.")
                            .arg(it->fileName)
                            .arg(it->chunks.size())
                            .arg(it->totalChunks));
            it = m_incomingTransfers.erase(it);
        } else {
            ++it;
        }
    }
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
    // ── File chunk received over P2P ─────────────────────────────────────────
    // P2P file chunks arrive in the same wire format as mailbox envelopes:
    // FROMFC:<senderId>\n<4-byte metaLen><encMeta><encChunk>
    if (data.startsWith(kFilePrefix)) {
        // Re-use onEnvelope which already handles the full wire format
        onEnvelope(data, QString());
        return;
    }

    // ── Encrypted JSON message (text, etc.) ──────────────────────────────────
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

    const int nl = body.indexOf('\n');
    if (nl < 0) return;

    const QByteArray header = body.left(nl);
    const QByteArray rest   = body.mid(nl + 1);

    // ── File chunk envelope ───────────────────────────────────────────────────
    if (header.startsWith(kFilePrefix)) {
        const QString fromId = QString::fromUtf8(header.mid(kFilePrefix.size())).trimmed();
        if (rest.size() < 4) return;

        const quint32 metaLen = unpack32(rest, 0);
        if (rest.size() - 4 < int(metaLen)) return;

        const QByteArray encMeta  = rest.mid(4, int(metaLen));
        const QByteArray encChunk = rest.mid(4 + int(metaLen));

        const QByteArray peerPub  = CryptoEngine::fromBase64Url(fromId);
        const QByteArray key32    = m_crypto.deriveSharedKey32(peerPub);
        const QByteArray metaJson = m_crypto.aeadDecrypt(key32, encMeta);
        if (metaJson.isEmpty()) return;

        const QJsonObject meta   = QJsonDocument::fromJson(metaJson).object();
        const QString transferId = meta.value("transferId").toString();
        const int chunkIndex     = meta.value("chunkIndex").toInt(-1);
        const int totalChunks    = meta.value("totalChunks").toInt(0);
        if (transferId.isEmpty() || chunkIndex < 0 || totalChunks <= 0) return;

        // ── Receive-side limits ──────────────────────────────────────────────
        const qint64 claimedSize = meta.value("fileSize").toVariant().toLongLong();
        // Reject files that exceed the same 25 MB limit we enforce on send
        if (claimedSize > kMaxFileBytes || totalChunks > (kMaxFileBytes / kChunkBytes + 1)) {
            emit status(QString("Rejected incoming file: claimed size %1 exceeds limit.")
                            .arg(claimedSize));
            return;
        }
        // Cap concurrent in-progress transfers to prevent memory exhaustion
        static constexpr int kMaxConcurrentTransfers = 50;
        if (!m_incomingTransfers.contains(transferId)
            && m_incomingTransfers.size() >= kMaxConcurrentTransfers) {
            emit status("Too many concurrent incoming transfers — dropping chunk.");
            return;
        }

        // Per-chunk dedup: "<transferId>:<chunkIndex>"
        if (!markSeen(transferId + ":" + QString::number(chunkIndex))) return;

        const QByteArray chunkData = m_crypto.aeadDecrypt(key32, encChunk);
        if (chunkData.isEmpty()) return;

        // ── Reassembly ────────────────────────────────────────────────────────
        IncomingTransfer &xfer = m_incomingTransfers[transferId];
        if (xfer.totalChunks == 0) {
            xfer.fromId      = fromId;
            // Strip path separators to prevent directory traversal attacks
            QString rawName  = meta.value("fileName").toString("file");
            rawName = rawName.section('/', -1).section('\\', -1);
            xfer.fileName    = rawName.isEmpty() ? "file" : rawName;
            xfer.fileSize    = meta.value("fileSize").toVariant().toLongLong();
            xfer.totalChunks = totalChunks;
            xfer.ts          = tsFromSecs(meta.value("ts").toVariant().toLongLong());
            xfer.fileHash    = CryptoEngine::fromBase64Url(meta.value("fileHash").toString());
            xfer.groupId     = meta.value("groupId").toString();
            xfer.groupName   = meta.value("groupName").toString();
            xfer.createdSecs = QDateTime::currentSecsSinceEpoch();
        }
        xfer.chunks[chunkIndex] = chunkData;

        const int received = xfer.chunks.size();

        if (received < totalChunks) {
            // Progress update only — no file data yet
            emit fileChunkReceived(fromId, transferId, xfer.fileName,
                                   xfer.fileSize, received, totalChunks,
                                   QByteArray{}, xfer.ts,
                                   xfer.groupId, xfer.groupName);
        } else {
            // Reassemble in chunk order and free reassembly memory immediately
            QByteArray assembled;
            assembled.reserve(int(xfer.fileSize));
            for (int i = 0; i < totalChunks; ++i)
                assembled.append(xfer.chunks.value(i));

            const IncomingTransfer completed = xfer;
            m_incomingTransfers.remove(transferId);

            // Verify BLAKE2b-256 integrity hash if the sender included one
            if (!completed.fileHash.isEmpty()) {
                const QByteArray actualHash = blake2b256(assembled);
                if (actualHash != completed.fileHash) {
                    emit status(QString("⚠ File '%1' integrity check FAILED — data corrupted.")
                                    .arg(completed.fileName));
                    // Still emit so the UI can show the failure
                    emit fileChunkReceived(fromId, transferId, completed.fileName,
                                           completed.fileSize, totalChunks, totalChunks,
                                           QByteArray{}, completed.ts,
                                           completed.groupId, completed.groupName);
                    return;
                }
            }

            emit fileChunkReceived(fromId, transferId, completed.fileName,
                                   completed.fileSize, totalChunks, totalChunks,
                                   assembled, completed.ts,
                                   completed.groupId, completed.groupName);
        }
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

    const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
    const QDateTime ts = tsSecs > 0
                             ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime()
                             : QDateTime::currentDateTime();

    const QString msgId = o.value("msgId").toString();

    if (type == "text") {
        const QString msgId = o.value("msgId").toString();
        if (!msgId.isEmpty() && !markSeen(msgId)) return;
        emit messageReceived(fromId, o.value("text").toString(),
                             tsFromSecs(o.value("ts").toVariant().toLongLong()), msgId);
    } else if (type == "ice_offer") {
        if (!m_p2pConnections.contains(fromId)) {
            NiceConnection* conn = new NiceConnection(this);
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
    } else if (type == "ice_answer") {
        if (m_p2pConnections.contains(fromId))
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
    } else if (o.value("type").toString() == "group_leave") {
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
