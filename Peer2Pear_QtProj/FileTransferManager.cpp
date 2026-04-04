#include "FileTransferManager.hpp"
#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>
#include <sodium.h>

// ── Wire helpers ─────────────────────────────────────────────────────────────

static const QByteArray kFilePrefix = "FROMFC:";

static QByteArray pack32(quint32 v)
{
    QByteArray b(4, 0);
    b[0] = char((v >> 24) & 0xFF);
    b[1] = char((v >> 16) & 0xFF);
    b[2] = char((v >>  8) & 0xFF);
    b[3] = char( v        & 0xFF);
    return b;
}

static quint32 unpack32(const QByteArray& b, int offset = 0)
{
    // G6 fix: bounds check before reading 4 bytes
    if (b.size() < offset + 4) return 0;
    return (quint8(b[offset])     << 24)
         | (quint8(b[offset + 1]) << 16)
         | (quint8(b[offset + 2]) <<  8)
         |  quint8(b[offset + 3]);
}

static QDateTime tsFromSecs(qint64 secs)
{
    return secs > 0
               ? QDateTime::fromSecsSinceEpoch(secs, QTimeZone::utc()).toLocalTime()
               : QDateTime::currentDateTime();
}

// ── FileTransferManager ──────────────────────────────────────────────────────

FileTransferManager::FileTransferManager(CryptoEngine& crypto, MailboxClient& mbox,
                                         QObject* parent)
    : QObject(parent)
    , m_crypto(crypto)
    , m_mbox(mbox)
{}

QByteArray FileTransferManager::blake2b256(const QByteArray& data)
{
    QByteArray hash(32, 0);
    crypto_generichash(reinterpret_cast<unsigned char*>(hash.data()), 32,
                       reinterpret_cast<const unsigned char*>(data.constData()),
                       static_cast<unsigned long long>(data.size()),
                       nullptr, 0);
    return hash;
}

// ── Reliable chunk sender (mailbox-primary) ─────────────────────────────────
//
// File chunks ALWAYS go through the mailbox for guaranteed delivery.
// UDP (the transport beneath ICE/libnice) cannot reliably carry 240 KB+
// datagrams — IP fragmentation drops are silent and unrecoverable.
//
// After sending, a wantP2PConnection signal is emitted so that future
// text messages can use the low-latency P2P path. The receiver's per-chunk
// dedup ("transferId:chunkIndex") ensures only one copy is processed.

void FileTransferManager::sendChunkEnvelopes(const QString& senderIdB64u,
                                             const QString& peerIdB64u,
                                             const QByteArray& key32,
                                             const QByteArray& fileData,
                                             const QString& transferId,
                                             const QString& fileName,
                                             const QString& fileHashB64u,
                                             qint64 ts,
                                             const QString& groupId,
                                             const QString& groupName)
{
    const qint64 fileSize   = fileData.size();
    const int totalChunks   = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    for (int i = 0; i < totalChunks; ++i) {
        const qint64     offset = qint64(i) * kChunkBytes;
        const QByteArray chunk  = fileData.mid(int(offset), int(kChunkBytes));

        QJsonObject meta;
        meta["from"]        = senderIdB64u;
        meta["type"]        = "file_chunk";
        meta["transferId"]  = transferId;
        meta["chunkIndex"]  = i;
        meta["totalChunks"] = totalChunks;
        meta["fileName"]    = fileName;
        meta["fileSize"]    = fileSize;
        meta["ts"]          = ts;
        meta["fileHash"]    = fileHashB64u;
        if (!groupId.isEmpty()) {
            meta["groupId"]   = groupId;
            meta["groupName"] = groupName;
        }

        const QByteArray metaJson = QJsonDocument(meta).toJson(QJsonDocument::Compact);
        const QByteArray encMeta  = m_crypto.aeadEncrypt(key32, metaJson);
        const QByteArray encChunk = m_crypto.aeadEncrypt(key32, chunk);

        // Wire format: FROMFC:<senderId>\n<4-byte metaLen><encMeta><encChunk>
        const QByteArray env = kFilePrefix + senderIdB64u.toUtf8() + "\n"
                               + pack32(quint32(encMeta.size()))
                               + encMeta
                               + encChunk;

        m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
    }

    // Kick off P2P for future text messages (files always go via mailbox)
    emit wantP2PConnection(peerIdB64u);
}

// ── Send file (1-to-1) ──────────────────────────────────────────────────────

QString FileTransferManager::sendFile(const QString& senderIdB64u,
                                      const QString& peerIdB64u,
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

    const QString transferId   = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const qint64  ts           = QDateTime::currentSecsSinceEpoch();
    // Compute BLAKE2b-256 integrity hash over the entire plaintext file
    const QString fileHashB64u = CryptoEngine::toBase64Url(blake2b256(fileData));
    const int totalChunks      = int((fileData.size() + kChunkBytes - 1) / kChunkBytes);

    sendChunkEnvelopes(senderIdB64u, peerIdB64u, key32, fileData,
                       transferId, fileName, fileHashB64u, ts);

    emit status(QString("'%1' queued in %2 chunk(s) -> %3")
                    .arg(fileName).arg(totalChunks).arg(peerIdB64u));
    return transferId;
}

// ── Send file (group) ────────────────────────────────────────────────────────

QString FileTransferManager::sendGroupFile(const QString& senderIdB64u,
                                           const QString& groupId,
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

    const QString transferId   = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const qint64  ts           = QDateTime::currentSecsSinceEpoch();
    // Compute BLAKE2b-256 integrity hash over the entire plaintext file
    const QString fileHashB64u = CryptoEngine::toBase64Url(blake2b256(fileData));
    const int totalChunks      = int((fileData.size() + kChunkBytes - 1) / kChunkBytes);

    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty() || peerId.trimmed() == senderIdB64u) continue;

        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        sendChunkEnvelopes(senderIdB64u, peerId, key32, fileData,
                           transferId, fileName, fileHashB64u, ts,
                           groupId, groupName);
    }

    emit status(QString("'%1' queued in %2 chunk(s) -> group %3")
                    .arg(fileName).arg(totalChunks).arg(groupName));
    return transferId;
}

// ── Handle incoming file chunk ───────────────────────────────────────────────

bool FileTransferManager::handleFileEnvelope(const QString& fromId,
                                             const QByteArray& payload,
                                             std::function<bool(const QString&)> markSeen)
{
    if (payload.size() < 4) return false;

    const quint32 metaLen = unpack32(payload, 0);
    if (payload.size() - 4 < int(metaLen)) return false;

    const QByteArray encMeta  = payload.mid(4, int(metaLen));
    const QByteArray encChunk = payload.mid(4 + int(metaLen));

    const QByteArray peerPub  = CryptoEngine::fromBase64Url(fromId);
    const QByteArray key32    = m_crypto.deriveSharedKey32(peerPub);
    const QByteArray metaJson = m_crypto.aeadDecrypt(key32, encMeta);
    if (metaJson.isEmpty()) return false;

    const QJsonObject meta   = QJsonDocument::fromJson(metaJson).object();
    const QString transferId = meta.value("transferId").toString();
    const int chunkIndex     = meta.value("chunkIndex").toInt(-1);
    const int totalChunks    = meta.value("totalChunks").toInt(0);
    if (transferId.isEmpty() || chunkIndex < 0 || totalChunks <= 0) return false;

    // ── Receive-side limits ──────────────────────────────────────────────────
    const qint64 claimedSize = meta.value("fileSize").toVariant().toLongLong();
    if (claimedSize > kMaxFileBytes || totalChunks > (kMaxFileBytes / kChunkBytes + 1)) {
        emit status(QString("Rejected incoming file: claimed size %1 exceeds limit.")
                        .arg(claimedSize));
        return true;
    }
    if (!m_incomingTransfers.contains(transferId)
        && m_incomingTransfers.size() >= kMaxConcurrentTransfers) {
        emit status("Too many concurrent incoming transfers — dropping chunk.");
        return true;
    }

    // Per-chunk dedup: "<transferId>:<chunkIndex>"
    if (!markSeen(transferId + ":" + QString::number(chunkIndex))) return true;

    const QByteArray chunkData = m_crypto.aeadDecrypt(key32, encChunk);
    if (chunkData.isEmpty()) return true;

    // ── Reassembly ───────────────────────────────────────────────────────────
    IncomingTransfer& xfer = m_incomingTransfers[transferId];
    if (xfer.totalChunks == 0) {
        xfer.fromId      = fromId;
        // Strip path separators to prevent directory traversal
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
        emit fileChunkReceived(fromId, transferId, xfer.fileName,
                               xfer.fileSize, received, totalChunks,
                               QByteArray{}, xfer.ts,
                               xfer.groupId, xfer.groupName);
    } else {
        // Reassemble in chunk order
        QByteArray assembled;
        assembled.reserve(int(xfer.fileSize));
        for (int i = 0; i < totalChunks; ++i)
            assembled.append(xfer.chunks.value(i));

        const IncomingTransfer completed = xfer;
        m_incomingTransfers.remove(transferId);

        // Verify BLAKE2b-256 integrity hash
        if (!completed.fileHash.isEmpty()) {
            const QByteArray actualHash = blake2b256(assembled);
            if (actualHash != completed.fileHash) {
                emit status(QString("File '%1' integrity check FAILED — data corrupted.")
                                .arg(completed.fileName));
                emit fileChunkReceived(fromId, transferId, completed.fileName,
                                       completed.fileSize, totalChunks, totalChunks,
                                       QByteArray{}, completed.ts,
                                       completed.groupId, completed.groupName);
                return true;
            }
        }

        emit fileChunkReceived(fromId, transferId, completed.fileName,
                               completed.fileSize, totalChunks, totalChunks,
                               assembled, completed.ts,
                               completed.groupId, completed.groupName);
    }
    return true;
}

// ── Stale transfer purge ─────────────────────────────────────────────────────

void FileTransferManager::purgeStaleTransfers()
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
