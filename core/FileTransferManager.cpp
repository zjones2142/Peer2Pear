#include "FileTransferManager.hpp"
#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QDebug>
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

FileTransferManager::FileTransferManager(CryptoEngine& crypto, QObject* parent)
    : QObject(parent)
    , m_crypto(crypto)
{
    // Default partial-file directory: <DownloadLocation>/Peer2Pear/.partial/
    const QString dl = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    m_partialDir = dl + "/Peer2Pear/.partial";
}

void FileTransferManager::setPartialFileDir(const QString& dir)
{
    m_partialDir = dir;
}

// ── BLAKE2b-256 helpers ─────────────────────────────────────────────────────

QByteArray FileTransferManager::blake2b256(const QByteArray& data)
{
    QByteArray hash(32, 0);
    crypto_generichash(reinterpret_cast<unsigned char*>(hash.data()), 32,
                       reinterpret_cast<const unsigned char*>(data.constData()),
                       static_cast<unsigned long long>(data.size()),
                       nullptr, 0);
    return hash;
}

QByteArray FileTransferManager::blake2b256File(const QString& filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "[FileTransfer] blake2b256File: cannot open" << filePath;
        return {};
    }

    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 32);

    // 64 KB read buffer — bounded RAM regardless of file size.
    QByteArray buf(64 * 1024, Qt::Uninitialized);
    while (!f.atEnd()) {
        const qint64 n = f.read(buf.data(), buf.size());
        if (n < 0) {
            qWarning() << "[FileTransfer] blake2b256File: read error on" << filePath;
            return {};
        }
        if (n == 0) break;
        crypto_generichash_update(&st,
            reinterpret_cast<const unsigned char*>(buf.constData()),
            static_cast<unsigned long long>(n));
    }
    f.close();

    QByteArray hash(32, 0);
    crypto_generichash_final(&st, reinterpret_cast<unsigned char*>(hash.data()), 32);
    return hash;
}

// ── Partial-file path helpers ───────────────────────────────────────────────

QString FileTransferManager::partialPathFor(const QString& transferId)
{
    QDir().mkpath(m_partialDir);
    return m_partialDir + "/" + transferId + ".partial";
}

QString FileTransferManager::finalPathFor(const QString& fileName, const QString& transferId)
{
    // Strip path separators to prevent directory traversal.
    QString safe = QFileInfo(fileName).fileName();
    if (safe.isEmpty()) safe = "file";

    const QString baseDir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
                            + "/Peer2Pear/" + transferId;
    QDir().mkpath(baseDir);
    return baseDir + "/" + safe;
}

// ── Send one chunk with routing mode ────────────────────────────────────────

bool FileTransferManager::dispatchChunk(const QString& senderIdB64u,
                                         const QString& peerIdB64u,
                                         const QByteArray& innerPayload,
                                         RoutingMode mode)
{
    // 1. Try P2P QUIC file stream (reliable, framed, congestion-controlled).
    if (m_p2pFileSendFn && m_p2pFileSendFn(peerIdB64u, innerPayload))
        return true;

    // P2POnly mode: refuse relay fallback, drop the chunk.
    if (mode == RoutingMode::P2POnly)
        return false;

    // 2. Sealed relay envelope (metadata privacy).
    if (m_sealFn) {
        QByteArray sealedEnv = m_sealFn(peerIdB64u, innerPayload);
        if (!sealedEnv.isEmpty()) {
            if (m_sendFn) m_sendFn(peerIdB64u, sealedEnv);
            return true;
        }
        qWarning() << "[FileTransfer] Seal failed — chunk BLOCKED";
        return false;
    }

    // 3. Legacy fallback (no seal callback set).
    const QByteArray env = kFilePrefix + senderIdB64u.toUtf8() + "\n" + innerPayload;
    if (m_sendFn) m_sendFn(peerIdB64u, env);
    return true;
}

// ── Stream chunks from disk ─────────────────────────────────────────────────
//
// This is the memory-critical path. We NEVER hold the entire file in RAM.
// Open the source file once, seek+read one chunk at a time, encrypt, dispatch,
// let the chunk go out of scope before reading the next.

void FileTransferManager::sendChunkEnvelopes(const QString& senderIdB64u,
                                              const QString& peerIdB64u,
                                              const QByteArray& key32,
                                              const QString& filePath,
                                              qint64 fileSize,
                                              const QString& transferId,
                                              const QString& fileName,
                                              const QString& fileHashB64u,
                                              qint64 ts,
                                              RoutingMode mode,
                                              const QString& groupId,
                                              const QString& groupName)
{
    QFile src(filePath);
    if (!src.open(QIODevice::ReadOnly)) {
        qWarning() << "[FileTransfer] Cannot open" << filePath << "for streaming";
        emit status(QString("Cannot read file: %1").arg(fileName));
        return;
    }

    const int totalChunks = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    QByteArray chunk;  // reused buffer — one allocation for the whole loop
    chunk.reserve(int(kChunkBytes));

    for (int i = 0; i < totalChunks; ++i) {
        const qint64 offset = qint64(i) * kChunkBytes;
        const qint64 remaining = fileSize - offset;
        const qint64 toRead = qMin<qint64>(kChunkBytes, remaining);

        // Seek + read this chunk only. Prior chunks are freed.
        src.seek(offset);
        chunk.resize(int(toRead));
        const qint64 n = src.read(chunk.data(), toRead);
        if (n != toRead) {
            qWarning() << "[FileTransfer] Short read at chunk" << i
                       << "of" << transferId.left(8);
            break;
        }

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

        // Inner payload: <4-byte metaLen><encMeta><encChunk>
        const QByteArray innerPayload = pack32(quint32(encMeta.size()))
                                        + encMeta
                                        + encChunk;

        if (!dispatchChunk(senderIdB64u, peerIdB64u, innerPayload, mode)) {
            // P2POnly mode and P2P went away mid-stream. Abandon the transfer —
            // partial delivery with missing chunks would be confusing.
            qWarning() << "[FileTransfer] P2P lost mid-stream at chunk" << i
                       << "— aborting transfer" << transferId.left(8);
            src.close();
            emit status(QString("Transfer interrupted: direct connection lost."));
            return;
        }
    }

    src.close();

    // Kick off P2P for future messages
    emit wantP2PConnection(peerIdB64u);
}

// ── Send file with ratchet-derived key ──────────────────────────────────────

QString FileTransferManager::sendFileWithKey(const QString& senderIdB64u,
                                              const QString& peerIdB64u,
                                              const QByteArray& fileKey,
                                              const QString& transferId,
                                              const QString& fileName,
                                              const QString& filePath,
                                              qint64 fileSize,
                                              const QByteArray& fileHash,
                                              const QString& groupId,
                                              const QString& groupName)
{
    if (fileSize > kMaxFileBytes) {
        emit status(QString("File too large (max %1 MB).")
                        .arg(kMaxFileBytes / (1024 * 1024)));
        return {};
    }
    if (fileKey.size() != 32) {
        emit status("Invalid file encryption key.");
        return {};
    }
    if (fileHash.size() != 32) {
        emit status("Invalid file hash (must be 32 bytes).");
        return {};
    }
    if (!QFileInfo::exists(filePath)) {
        emit status(QString("File not found: %1").arg(filePath));
        return {};
    }

    const qint64  ts           = QDateTime::currentSecsSinceEpoch();
    const QString fileHashB64u = CryptoEngine::toBase64Url(fileHash);
    const int     totalChunks  = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    sendChunkEnvelopes(senderIdB64u, peerIdB64u, fileKey, filePath, fileSize,
                       transferId, fileName, fileHashB64u, ts,
                       RoutingMode::Auto,
                       groupId, groupName);

    if (groupId.isEmpty()) {
        emit status(QString("'%1' streamed in %2 chunk(s) -> %3")
                        .arg(fileName).arg(totalChunks).arg(peerIdB64u));
    }
    return transferId;
}

// ── Handle incoming file chunk ───────────────────────────────────────────────

bool FileTransferManager::handleFileEnvelope(const QString& fromId,
                                              const QByteArray& payload,
                                              std::function<bool(const QString&)> markSeen,
                                              const QMap<QString, QByteArray>& fileKeys)
{
    if (payload.size() < 4) return false;

    const quint32 metaLen = unpack32(payload, 0);
    if (payload.size() - 4 < int(metaLen)) return false;

    const QByteArray encMeta  = payload.mid(4, int(metaLen));
    const QByteArray encChunk = payload.mid(4 + int(metaLen));

    // ── Key selection: ratchet keys only (L8 fix) ──────────────────────────
    QByteArray metaJson;
    QByteArray key32;

    for (auto it = fileKeys.begin(); it != fileKeys.end(); ++it) {
        if (it.value().size() != 32) continue;
        metaJson = m_crypto.aeadDecrypt(it.value(), encMeta);
        if (!metaJson.isEmpty()) {
            key32 = it.value();
            break;
        }
    }
    if (metaJson.isEmpty()) {
        qWarning() << "[FileTransfer] No ratchet key found for file chunk from"
                   << fromId.left(8) + "...";
        return false;
    }

    const QJsonObject meta   = QJsonDocument::fromJson(metaJson).object();
    const QString transferId = meta.value("transferId").toString();
    const int chunkIndex     = meta.value("chunkIndex").toInt(-1);
    const int totalChunks    = meta.value("totalChunks").toInt(0);
    if (transferId.isEmpty()
        || totalChunks <= 0
        || chunkIndex < 0
        || chunkIndex >= totalChunks) return false;

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

    // ── Disk-backed assembly ────────────────────────────────────────────────
    auto& xferPtr = m_incomingTransfers[transferId];
    if (!xferPtr) {
        // First chunk of this transfer — create and initialize.
        xferPtr = std::make_shared<IncomingTransfer>();
        IncomingTransfer& xfer = *xferPtr;
        xfer.fromId      = fromId;
        QString rawName  = meta.value("fileName").toString("file");
        rawName          = rawName.section('/', -1).section('\\', -1);
        xfer.fileName    = rawName.isEmpty() ? "file" : rawName;
        xfer.fileSize    = meta.value("fileSize").toVariant().toLongLong();
        xfer.totalChunks = totalChunks;
        xfer.ts          = tsFromSecs(meta.value("ts").toVariant().toLongLong());
        xfer.fileHash    = CryptoEngine::fromBase64Url(meta.value("fileHash").toString());
        xfer.groupId     = meta.value("groupId").toString();
        xfer.groupName   = meta.value("groupName").toString();
        xfer.createdSecs = QDateTime::currentSecsSinceEpoch();
        xfer.partialPath = partialPathFor(transferId);
        xfer.finalPath   = finalPathFor(xfer.fileName, transferId);
        xfer.receivedChunks = QBitArray(totalChunks);  // all false

        // Open partial file for read/write (truncate any stale content).
        xfer.partialFile = std::make_unique<QFile>(xfer.partialPath);
        if (!xfer.partialFile->open(QIODevice::ReadWrite | QIODevice::Truncate)) {
            qWarning() << "[FileTransfer] Cannot open partial file"
                       << xfer.partialPath << "—" << xfer.partialFile->errorString();
            const QString fname = xfer.fileName;
            m_incomingTransfers.remove(transferId);
            emit status(QString("Cannot write to disk: %1").arg(fname));
            return true;
        }

        // Phase 4: persist the initial row so a crash before any chunk writes
        // still leaves us a record to resume from. No bits set yet.
        persistIncomingFull(transferId, xfer, key32);
    }
    IncomingTransfer& xfer = *xferPtr;

    // Already received this chunk? (dedup above should have caught it, but
    // double-check the bitmap in case of an out-of-band retry.)
    if (chunkIndex < xfer.receivedChunks.size() && xfer.receivedChunks.testBit(chunkIndex)) {
        return true;
    }

    // Write chunk at its correct offset — no RAM accumulation.
    const qint64 offset = qint64(chunkIndex) * kChunkBytes;
    if (!xfer.partialFile->seek(offset) ||
        xfer.partialFile->write(chunkData) != chunkData.size()) {
        qWarning() << "[FileTransfer] Write failed for chunk" << chunkIndex
                   << "of" << transferId.left(8);
        return true;
    }
    xfer.partialFile->flush();
    xfer.receivedChunks.setBit(chunkIndex);
    xfer.chunksReceivedCount++;

    // Phase 4: update DB bitmap after each successful write so we can resume
    // after a crash with at worst one chunk of lost work.
    persistIncomingFull(transferId, xfer, key32);

    const int received = xfer.chunksReceivedCount;

    if (received < totalChunks) {
        emit fileChunkReceived(fromId, transferId, xfer.fileName,
                               xfer.fileSize, received, totalChunks,
                               QString{}, xfer.ts,
                               xfer.groupId, xfer.groupName);
        return true;
    }

    // ── All chunks received ─────────────────────────────────────────────────
    xfer.partialFile->close();

    // Capture values we need before removing the entry.
    const QString fileName    = xfer.fileName;
    const qint64  fileSize    = xfer.fileSize;
    const QString groupId     = xfer.groupId;
    const QString groupName   = xfer.groupName;
    const QDateTime tsCopy    = xfer.ts;
    const QByteArray expected = xfer.fileHash;
    const QString partialPath = xfer.partialPath;
    const QString finalPath   = xfer.finalPath;

    m_incomingTransfers.remove(transferId);
    emit transferCompleted(transferId);  // M1: let ChatController zero the key

    // Verify integrity by streaming the completed file from disk.
    if (!expected.isEmpty()) {
        const QByteArray actual = blake2b256File(partialPath);
        if (actual != expected) {
            QFile::remove(partialPath);
            // Phase 4: hash failure → drop the DB row. No resumption of
            // a corrupted transfer.
            deleteIncomingRow(transferId);
            emit status(QString("File '%1' integrity check FAILED — discarded.").arg(fileName));
            emit fileChunkReceived(fromId, transferId, fileName,
                                   fileSize, totalChunks, totalChunks,
                                   QString{}, tsCopy, groupId, groupName);
            return true;
        }
    }

    // Move partial → final. If target exists, overwrite.
    QFile::remove(finalPath);
    if (!QFile::rename(partialPath, finalPath)) {
        qWarning() << "[FileTransfer] Rename failed"
                   << partialPath << "->" << finalPath;
        emit status(QString("Could not save file: %1").arg(fileName));
        return true;
    }

    // Phase 4: transfer done + hash verified — drop persistent state.
    deleteIncomingRow(transferId);

    emit fileChunkReceived(fromId, transferId, fileName,
                           fileSize, totalChunks, totalChunks,
                           finalPath, tsCopy, groupId, groupName);
    return true;
}

// ── Stale transfer purge ─────────────────────────────────────────────────────

void FileTransferManager::purgeStaleTransfers()
{
    static constexpr qint64 kMaxTransferAgeSecs = 30 * 60;  // 30 minutes
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    auto it = m_incomingTransfers.begin();
    while (it != m_incomingTransfers.end()) {
        auto& xferPtr = it.value();
        if (xferPtr && xferPtr->createdSecs > 0 &&
            (now - xferPtr->createdSecs) > kMaxTransferAgeSecs) {
            const QString tid = it.key();
            emit status(QString("Purged stale transfer '%1' (%2/%3 chunks) after 30 min.")
                            .arg(xferPtr->fileName)
                            .arg(xferPtr->chunksReceivedCount)
                            .arg(xferPtr->totalChunks));

            // Close and delete the partial file — don't leak disk.
            if (xferPtr->partialFile) {
                xferPtr->partialFile->close();
                xferPtr->partialFile.reset();
            }
            if (!xferPtr->partialPath.isEmpty())
                QFile::remove(xferPtr->partialPath);

            // Phase 4: also drop the DB row — no resumption of a stale transfer.
            deleteIncomingRow(tid);

            it = m_incomingTransfers.erase(it);
            emit transferCompleted(tid);  // M1: key cleanup on purge
        } else {
            ++it;
        }
    }
}

// ── Phase 2: outbound consent gate ──────────────────────────────────────────

void FileTransferManager::queueOutboundFile(const QString& senderIdB64u,
                                             const QString& peerIdB64u,
                                             const QByteArray& fileKey,
                                             const QString& transferId,
                                             const QString& fileName,
                                             const QString& filePath,
                                             qint64 fileSize,
                                             const QByteArray& fileHash,
                                             const QString& groupId,
                                             const QString& groupName)
{
    if (fileKey.size() != 32 || fileHash.size() != 32) {
        qWarning() << "[FileTransfer] queueOutboundFile: bad key/hash length";
        return;
    }
    OutboundTransfer out;
    out.senderId   = senderIdB64u;
    out.peerId     = peerIdB64u;
    out.fileKey    = QByteArray(fileKey.constData(), fileKey.size()); // owned copy
    out.fileName   = fileName;
    out.filePath   = filePath;
    out.fileSize   = fileSize;
    out.fileHash   = fileHash;
    out.groupId    = groupId;
    out.groupName  = groupName;
    out.queuedSecs = QDateTime::currentSecsSinceEpoch();
    m_outboundPending.insert(transferId, out);
}

bool FileTransferManager::startOutboundStream(const QString& transferId,
                                                bool requireP2P,
                                                bool senderRequiresP2P,
                                                bool p2pReadyNow)
{
    auto it = m_outboundPending.find(transferId);
    if (it == m_outboundPending.end()) {
        qWarning() << "[FileTransfer] startOutboundStream: unknown transferId"
                   << transferId.left(8);
        return false;
    }

    // Re-check the file still exists.
    if (!QFileInfo::exists(it->filePath)) {
        const QString name = it->fileName;
        const QString peer = it->peerId;
        emit status(QString("File vanished before accept: %1").arg(name));
        sodium_memzero(it->fileKey.data(), it->fileKey.size());
        m_outboundPending.erase(it);
        emit outboundAbandoned(transferId, peer);
        return false;
    }

    const bool requiresP2P = requireP2P || senderRequiresP2P;
    const bool isLarge     = it->fileSize > kLargeFileBytes;

    // ── Decision matrix ────────────────────────────────────────────────────
    //
    // Small file:      stream immediately with relay fallback (Auto mode).
    // Large + P2P up:  stream via P2P now.
    // Large + no P2P + neither requires P2P: stream via sealed relay (Auto).
    // Large + no P2P + someone requires P2P: park waiting for P2P; abort after
    //                                         kP2PReadyWaitSecs if still no P2P.

    if (!isLarge) {
        // Small file — current behavior: dispatch now, per-chunk fallback.
        OutboundTransfer out = *it;
        m_outboundPending.erase(it);

        const qint64  ts           = QDateTime::currentSecsSinceEpoch();
        const QString fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int     totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        // Phase 4: record the sent transfer for resumption before chunks fly.
        registerSentTransfer(out.senderId, out.peerId, transferId, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           transferId, out.fileName, fileHashB64u, ts,
                           RoutingMode::Auto,
                           out.groupId, out.groupName);

        if (out.groupId.isEmpty()) {
            emit status(QString("'%1' streamed in %2 chunk(s) -> %3")
                            .arg(out.fileName).arg(totalChunks).arg(out.peerId));
        }
        sodium_memzero(out.fileKey.data(), out.fileKey.size());
        return true;
    }

    // Large file path — record the transport policy first.
    it->receiverRequiresP2P = requireP2P;
    it->senderRequiresP2P   = senderRequiresP2P;

    if (p2pReadyNow) {
        // Stream via P2P now. If either side required P2P, use P2POnly to
        // refuse mid-stream relay fallback.
        OutboundTransfer out = *it;
        m_outboundPending.erase(it);

        const qint64  ts           = QDateTime::currentSecsSinceEpoch();
        const QString fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int     totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        const RoutingMode mode = requiresP2P ? RoutingMode::P2POnly
                                             : RoutingMode::Auto;

        // Phase 4: record the sent transfer for resumption before chunks fly.
        registerSentTransfer(out.senderId, out.peerId, transferId, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           transferId, out.fileName, fileHashB64u, ts,
                           mode,
                           out.groupId, out.groupName);

        if (out.groupId.isEmpty()) {
            emit status(QString("'%1' streamed in %2 chunk(s) -> %3 (P2P)")
                            .arg(out.fileName).arg(totalChunks).arg(out.peerId));
        }
        sodium_memzero(out.fileKey.data(), out.fileKey.size());
        return true;
    }

    // Large file + no P2P yet → park in WaitingForP2P state.
    it->stage            = OutboundStage::WaitingForP2P;
    it->waitStartedSecs  = QDateTime::currentSecsSinceEpoch();

    emit status(QString("Waiting for direct connection to send '%1'...")
                    .arg(it->fileName));
    return true;
}

QList<QString> FileTransferManager::notifyP2PReady(const QString& peerIdB64u)
{
    QList<QString> flushed;
    // Iterate collecting first — we'll flush after, since streaming mutates the map.
    QList<QString> toFlush;
    for (auto it = m_outboundPending.begin(); it != m_outboundPending.end(); ++it) {
        if (it->stage == OutboundStage::WaitingForP2P && it->peerId == peerIdB64u) {
            toFlush << it.key();
        }
    }

    for (const QString& tid : toFlush) {
        auto it = m_outboundPending.find(tid);
        if (it == m_outboundPending.end()) continue;

        OutboundTransfer out = *it;
        m_outboundPending.erase(it);

        const qint64  ts           = QDateTime::currentSecsSinceEpoch();
        const QString fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int     totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        const bool requiresP2P = out.receiverRequiresP2P || out.senderRequiresP2P;
        const RoutingMode mode = requiresP2P ? RoutingMode::P2POnly
                                             : RoutingMode::Auto;

        // Phase 4: record the sent transfer for resumption before chunks fly.
        registerSentTransfer(out.senderId, out.peerId, tid, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           tid, out.fileName, fileHashB64u, ts,
                           mode,
                           out.groupId, out.groupName);

        if (out.groupId.isEmpty()) {
            emit status(QString("'%1' streamed in %2 chunk(s) -> %3 (P2P ready)")
                            .arg(out.fileName).arg(totalChunks).arg(out.peerId));
        }
        sodium_memzero(out.fileKey.data(), out.fileKey.size());
        flushed << tid;
    }

    return flushed;
}

void FileTransferManager::abandonOutboundTransfer(const QString& transferId)
{
    auto it = m_outboundPending.find(transferId);
    if (it == m_outboundPending.end()) return;
    const QString peerId = it->peerId;
    sodium_memzero(it->fileKey.data(), it->fileKey.size());
    m_outboundPending.erase(it);
    emit outboundAbandoned(transferId, peerId);
}

void FileTransferManager::cancelInboundTransfer(const QString& transferId)
{
    auto it = m_incomingTransfers.find(transferId);
    if (it == m_incomingTransfers.end()) return;

    auto& xferPtr = it.value();
    const QString peerId = xferPtr ? xferPtr->fromId : QString();

    if (xferPtr && xferPtr->partialFile) {
        xferPtr->partialFile->close();
        xferPtr->partialFile.reset();
    }
    if (xferPtr && !xferPtr->partialPath.isEmpty())
        QFile::remove(xferPtr->partialPath);

    // Phase 4: drop the DB row immediately — canceled transfers leave no trail.
    deleteIncomingRow(transferId);

    m_incomingTransfers.erase(it);
    emit inboundCanceled(transferId, peerId);
    emit transferCompleted(transferId);  // M1: let ChatController zero the key
}

QString FileTransferManager::outboundPeerFor(const QString& transferId) const
{
    auto it = m_outboundPending.find(transferId);
    return (it == m_outboundPending.end()) ? QString() : it->peerId;
}

QString FileTransferManager::inboundPeerFor(const QString& transferId) const
{
    auto it = m_incomingTransfers.find(transferId);
    if (it == m_incomingTransfers.end() || !it.value()) return {};
    return it.value()->fromId;
}

void FileTransferManager::purgeStaleOutbound()
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    auto it = m_outboundPending.begin();
    while (it != m_outboundPending.end()) {
        // Phase 3: WaitingForP2P entries have their own shorter deadline.
        if (it->stage == OutboundStage::WaitingForP2P &&
            it->waitStartedSecs > 0 &&
            (now - it->waitStartedSecs) > kP2PReadyWaitSecs) {

            const QString tid       = it.key();
            const QString peerId    = it->peerId;
            const QString name      = it->fileName;
            const bool receiverReq  = it->receiverRequiresP2P;
            const bool senderReq    = it->senderRequiresP2P;
            const bool requiresP2P  = receiverReq || senderReq;

            if (requiresP2P) {
                // No relay fallback — abort with transport policy error.
                emit status(QString("Direct connection unavailable for '%1' — "
                                    "transfer aborted (privacy level blocks relay fallback).")
                                .arg(name));
                sodium_memzero(it->fileKey.data(), it->fileKey.size());
                // Capture enough to emit after erase.
                const bool byReceiver = receiverReq && !senderReq;
                it = m_outboundPending.erase(it);
                emit outboundBlockedByPolicy(tid, peerId, byReceiver);
                continue;
            }

            // Neither side requires P2P — fall back to sealed relay.
            OutboundTransfer out = *it;
            it = m_outboundPending.erase(it);

            emit status(QString("Direct connection timed out for '%1' — streaming via relay.")
                            .arg(name));

            const qint64  ts           = QDateTime::currentSecsSinceEpoch();
            const QString fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);

            // Phase 4: record the sent transfer for resumption before chunks fly.
            registerSentTransfer(out.senderId, out.peerId, tid, out.fileName,
                                 out.filePath, out.fileSize, out.fileHash, out.fileKey,
                                 out.groupId, out.groupName);

            sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                               out.filePath, out.fileSize,
                               tid, out.fileName, fileHashB64u, ts,
                               RoutingMode::Auto,
                               out.groupId, out.groupName);
            sodium_memzero(out.fileKey.data(), out.fileKey.size());
            continue;
        }

        // Plain outbound-pending (no file_accept yet): older 10-minute timeout.
        if (it->stage == OutboundStage::Queued &&
            it->queuedSecs > 0 &&
            (now - it->queuedSecs) > kOutboundPendingTimeoutSecs) {
            const QString tid = it.key();
            const QString peerId = it->peerId;
            emit status(QString("Outbound file '%1' timed out — peer didn't respond.")
                            .arg(it->fileName));
            sodium_memzero(it->fileKey.data(), it->fileKey.size());
            it = m_outboundPending.erase(it);
            emit outboundAbandoned(tid, peerId);
            continue;
        }

        ++it;
    }
}

// ── Phase 4: Persistence + resumption ───────────────────────────────────────

void FileTransferManager::setDatabase(SqlCipherDb* db)
{
    m_dbPtr = db;
    if (m_dbPtr && m_dbPtr->isOpen()) {
        ensurePhase4Tables();
    }
}

void FileTransferManager::ensurePhase4Tables()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);

    // Incoming partial transfers: survives app restart so receiver can resume.
    q.exec(
        "CREATE TABLE IF NOT EXISTS file_transfers_in ("
        "  transfer_id     TEXT PRIMARY KEY,"
        "  peer_id         TEXT NOT NULL,"
        "  file_name       TEXT NOT NULL,"
        "  file_size       INTEGER NOT NULL,"
        "  total_chunks    INTEGER NOT NULL,"
        "  file_hash       BLOB,"
        "  file_key        BLOB NOT NULL,"      // 32 bytes
        "  group_id        TEXT,"
        "  group_name      TEXT,"
        "  partial_path    TEXT NOT NULL,"
        "  final_path      TEXT NOT NULL,"
        "  received_bitmap BLOB NOT NULL,"      // QBitArray serialized
        "  created_secs    INTEGER NOT NULL,"
        "  ts_secs         INTEGER"
        ");"
    );

    // Outbound transfers in flight: kept so we can answer file_request calls
    // for resumption when the receiver reconnects.
    q.exec(
        "CREATE TABLE IF NOT EXISTS file_transfers_out ("
        "  transfer_id   TEXT PRIMARY KEY,"
        "  sender_id     TEXT NOT NULL,"
        "  peer_id       TEXT NOT NULL,"
        "  file_name     TEXT NOT NULL,"
        "  file_path     TEXT NOT NULL,"
        "  file_size     INTEGER NOT NULL,"
        "  file_hash     BLOB NOT NULL,"
        "  file_key      BLOB NOT NULL,"
        "  group_id      TEXT,"
        "  group_name    TEXT,"
        "  created_secs  INTEGER NOT NULL"
        ");"
    );
}

// Serialize a QBitArray to a compact blob.  Format: [4-byte bit count BE][packed bytes].
static QByteArray bitArrayToBlob(const QBitArray& bits)
{
    QByteArray blob;
    const quint32 n = quint32(bits.size());
    blob.resize(4);
    blob[0] = char((n >> 24) & 0xFF);
    blob[1] = char((n >> 16) & 0xFF);
    blob[2] = char((n >>  8) & 0xFF);
    blob[3] = char( n        & 0xFF);
    const int nbytes = (int(n) + 7) / 8;
    QByteArray packed(nbytes, 0);
    for (int i = 0; i < int(n); ++i) {
        if (bits.testBit(i)) {
            packed[i / 8] = char(quint8(packed[i / 8]) | (1u << (i % 8)));
        }
    }
    blob.append(packed);
    return blob;
}

static QBitArray blobToBitArray(const QByteArray& blob)
{
    if (blob.size() < 4) return {};
    const quint32 n = (quint32(quint8(blob[0])) << 24) |
                      (quint32(quint8(blob[1])) << 16) |
                      (quint32(quint8(blob[2])) <<  8) |
                       quint32(quint8(blob[3]));
    if (blob.size() < 4 + int((n + 7) / 8)) return {};
    QBitArray bits{qsizetype(n)};
    const char* packed = blob.constData() + 4;
    for (int i = 0; i < int(n); ++i) {
        if (quint8(packed[i / 8]) & (1u << (i % 8))) bits.setBit(i);
    }
    return bits;
}

void FileTransferManager::persistIncomingFull(const QString& transferId,
                                                const IncomingTransfer& xfer,
                                                const QByteArray& fileKey) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    if (fileKey.size() != 32) return;   // guard against empty-key probing

    SqlCipherQuery q(*m_dbPtr);
    if (!q.prepare(
        "INSERT OR REPLACE INTO file_transfers_in "
        "(transfer_id, peer_id, file_name, file_size, total_chunks, file_hash, "
        " file_key, group_id, group_name, partial_path, final_path, "
        " received_bitmap, created_secs, ts_secs) "
        "VALUES (:tid, :peer, :name, :size, :chunks, :hash, :key, :gid, :gname, "
        "        :ppath, :fpath, :bmap, :created, :ts);")) return;
    q.bindValue(":tid",     transferId);
    q.bindValue(":peer",    xfer.fromId);
    q.bindValue(":name",    xfer.fileName);
    q.bindValue(":size",    xfer.fileSize);
    q.bindValue(":chunks",  xfer.totalChunks);
    q.bindValue(":hash",    xfer.fileHash);
    q.bindValue(":key",     fileKey);
    q.bindValue(":gid",     xfer.groupId);
    q.bindValue(":gname",   xfer.groupName);
    q.bindValue(":ppath",   xfer.partialPath);
    q.bindValue(":fpath",   xfer.finalPath);
    q.bindValue(":bmap",    bitArrayToBlob(xfer.receivedChunks));
    q.bindValue(":created", xfer.createdSecs);
    q.bindValue(":ts",      xfer.ts.toSecsSinceEpoch());
    q.exec();
}

void FileTransferManager::deleteIncomingRow(const QString& transferId) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.prepare("DELETE FROM file_transfers_in WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    q.exec();
}

void FileTransferManager::deleteSentRow(const QString& transferId) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.prepare("DELETE FROM file_transfers_out WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    q.exec();
}

void FileTransferManager::forgetSentTransfer(const QString& transferId)
{
    auto it = m_sentTransfers.find(transferId);
    if (it != m_sentTransfers.end()) {
        if (!it->fileKey.isEmpty())
            sodium_memzero(it->fileKey.data(), it->fileKey.size());
        m_sentTransfers.erase(it);
    }
    deleteSentRow(transferId);
}

void FileTransferManager::registerSentTransfer(const QString& senderIdB64u,
                                                 const QString& peerIdB64u,
                                                 const QString& transferId,
                                                 const QString& fileName,
                                                 const QString& filePath,
                                                 qint64 fileSize,
                                                 const QByteArray& fileHash,
                                                 const QByteArray& fileKey,
                                                 const QString& groupId,
                                                 const QString& groupName)
{
    SentTransfer s;
    s.senderId     = senderIdB64u;
    s.peerId       = peerIdB64u;
    s.fileName     = fileName;
    s.filePath     = filePath;
    s.fileSize     = fileSize;
    s.fileHash     = fileHash;
    s.fileKey      = QByteArray(fileKey.constData(), fileKey.size());
    s.groupId      = groupId;
    s.groupName    = groupName;
    s.createdSecs  = QDateTime::currentSecsSinceEpoch();
    m_sentTransfers.insert(transferId, s);

    if (m_dbPtr && m_dbPtr->isOpen()) {
        SqlCipherQuery q(*m_dbPtr);
        if (q.prepare(
            "INSERT OR REPLACE INTO file_transfers_out "
            "(transfer_id, sender_id, peer_id, file_name, file_path, file_size, "
            " file_hash, file_key, group_id, group_name, created_secs) "
            "VALUES (:tid, :sid, :peer, :name, :path, :size, :hash, :key, "
            "        :gid, :gname, :created);")) {
            q.bindValue(":tid",     transferId);
            q.bindValue(":sid",     senderIdB64u);
            q.bindValue(":peer",    peerIdB64u);
            q.bindValue(":name",    fileName);
            q.bindValue(":path",    filePath);
            q.bindValue(":size",    fileSize);
            q.bindValue(":hash",    fileHash);
            q.bindValue(":key",     s.fileKey);
            q.bindValue(":gid",     groupId);
            q.bindValue(":gname",   groupName);
            q.bindValue(":created", s.createdSecs);
            q.exec();
        }
    }
}

void FileTransferManager::loadPersistedTransfers()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;

    // ── Restore incoming transfers (receiver side) ──────────────────────────
    {
        SqlCipherQuery q(*m_dbPtr);
        if (q.prepare("SELECT transfer_id, peer_id, file_name, file_size, total_chunks, "
                      "       file_hash, group_id, group_name, partial_path, final_path, "
                      "       received_bitmap, created_secs, ts_secs "
                      "FROM file_transfers_in;") && q.exec()) {
            while (q.next()) {
                const QString tid      = q.value(0).toString();
                const QString peerId   = q.value(1).toString();
                const QString fname    = q.value(2).toString();
                const qint64  fsize    = q.value(3).toLongLong();
                const int     chunks   = q.value(4).toInt();
                const QByteArray fhash = q.value(5).toByteArray();
                const QString gid      = q.value(6).toString();
                const QString gname    = q.value(7).toString();
                const QString ppath    = q.value(8).toString();
                const QString fpath    = q.value(9).toString();
                const QByteArray bmap  = q.value(10).toByteArray();
                const qint64 created   = q.value(11).toLongLong();
                const qint64 tsSecs    = q.value(12).toLongLong();

                // Partial file must still exist on disk. If user deleted it
                // out of band, drop the row and move on.
                if (!QFileInfo::exists(ppath)) {
                    deleteIncomingRow(tid);
                    continue;
                }

                auto xferPtr = std::make_shared<IncomingTransfer>();
                xferPtr->fromId       = peerId;
                xferPtr->fileName     = fname;
                xferPtr->fileSize     = fsize;
                xferPtr->totalChunks  = chunks;
                xferPtr->fileHash     = fhash;
                xferPtr->groupId      = gid;
                xferPtr->groupName    = gname;
                xferPtr->partialPath  = ppath;
                xferPtr->finalPath    = fpath;
                xferPtr->receivedChunks = blobToBitArray(bmap);
                xferPtr->createdSecs  = created;
                xferPtr->ts           = tsFromSecs(tsSecs);

                // Count bits set.
                int set = 0;
                for (int i = 0; i < xferPtr->receivedChunks.size(); ++i)
                    if (xferPtr->receivedChunks.testBit(i)) ++set;
                xferPtr->chunksReceivedCount = set;

                // Re-open partial file (preserve contents — no truncate).
                xferPtr->partialFile = std::make_unique<QFile>(ppath);
                if (!xferPtr->partialFile->open(QIODevice::ReadWrite)) {
                    qWarning() << "[FileTransfer] loadPersisted: cannot reopen"
                               << ppath << "—" << xferPtr->partialFile->errorString();
                    deleteIncomingRow(tid);
                    continue;
                }

                m_incomingTransfers.insert(tid, xferPtr);
            }
        }
    }

    // ── Restore sent transfers (sender side) ────────────────────────────────
    {
        SqlCipherQuery q(*m_dbPtr);
        if (q.prepare("SELECT transfer_id, sender_id, peer_id, file_name, file_path, "
                      "       file_size, file_hash, file_key, group_id, group_name, "
                      "       created_secs FROM file_transfers_out;") && q.exec()) {
            while (q.next()) {
                const QString tid   = q.value(0).toString();
                SentTransfer s;
                s.senderId    = q.value(1).toString();
                s.peerId      = q.value(2).toString();
                s.fileName    = q.value(3).toString();
                s.filePath    = q.value(4).toString();
                s.fileSize    = q.value(5).toLongLong();
                s.fileHash    = q.value(6).toByteArray();
                s.fileKey     = q.value(7).toByteArray();
                s.groupId     = q.value(8).toString();
                s.groupName   = q.value(9).toString();
                s.createdSecs = q.value(10).toLongLong();

                // If the original file is gone or the key got corrupted, drop it.
                if (!QFileInfo::exists(s.filePath) || s.fileKey.size() != 32) {
                    deleteSentRow(tid);
                    continue;
                }
                m_sentTransfers.insert(tid, s);
            }
        }
    }
}

QList<FileTransferManager::PendingResumption>
FileTransferManager::pendingResumptions() const
{
    QList<PendingResumption> out;
    for (auto it = m_incomingTransfers.begin(); it != m_incomingTransfers.end(); ++it) {
        const auto& xferPtr = it.value();
        if (!xferPtr || xferPtr->chunksReceivedCount >= xferPtr->totalChunks) continue;

        PendingResumption pr;
        pr.transferId = it.key();
        pr.peerId     = xferPtr->fromId;
        for (int i = 0; i < xferPtr->receivedChunks.size(); ++i) {
            if (!xferPtr->receivedChunks.testBit(i))
                pr.missingChunks << quint32(i);
        }
        if (!pr.missingChunks.isEmpty()) out << pr;
    }
    return out;
}

bool FileTransferManager::resendChunks(const QString& transferId,
                                        const QList<quint32>& chunkIndices)
{
    auto itSent = m_sentTransfers.find(transferId);
    if (itSent == m_sentTransfers.end()) {
        qWarning() << "[FileTransfer] resendChunks: no sender record for"
                   << transferId.left(8);
        return false;
    }
    SentTransfer& s = itSent.value();
    if (!QFileInfo::exists(s.filePath)) {
        qWarning() << "[FileTransfer] resendChunks: source file gone"
                   << s.filePath;
        return false;
    }

    QFile src(s.filePath);
    if (!src.open(QIODevice::ReadOnly)) {
        qWarning() << "[FileTransfer] resendChunks: cannot open" << s.filePath;
        return false;
    }

    const int totalChunks = int((s.fileSize + kChunkBytes - 1) / kChunkBytes);
    const QString fileHashB64u = CryptoEngine::toBase64Url(s.fileHash);
    const qint64  ts = QDateTime::currentSecsSinceEpoch();

    QByteArray chunk;
    chunk.reserve(int(kChunkBytes));

    for (quint32 i : chunkIndices) {
        if (int(i) >= totalChunks) continue;  // bogus index — ignore

        const qint64 offset    = qint64(i) * kChunkBytes;
        const qint64 remaining = s.fileSize - offset;
        const qint64 toRead    = qMin<qint64>(kChunkBytes, remaining);

        src.seek(offset);
        chunk.resize(int(toRead));
        if (src.read(chunk.data(), toRead) != toRead) {
            qWarning() << "[FileTransfer] resendChunks: short read at chunk" << i;
            break;
        }

        QJsonObject meta;
        meta["from"]        = s.senderId;
        meta["type"]        = "file_chunk";
        meta["transferId"]  = transferId;
        meta["chunkIndex"]  = int(i);
        meta["totalChunks"] = totalChunks;
        meta["fileName"]    = s.fileName;
        meta["fileSize"]    = s.fileSize;
        meta["ts"]          = ts;
        meta["fileHash"]    = fileHashB64u;
        if (!s.groupId.isEmpty()) {
            meta["groupId"]   = s.groupId;
            meta["groupName"] = s.groupName;
        }

        const QByteArray metaJson = QJsonDocument(meta).toJson(QJsonDocument::Compact);
        const QByteArray encMeta  = m_crypto.aeadEncrypt(s.fileKey, metaJson);
        const QByteArray encChunk = m_crypto.aeadEncrypt(s.fileKey, chunk);
        const QByteArray inner    = pack32(quint32(encMeta.size())) + encMeta + encChunk;

        dispatchChunk(s.senderId, s.peerId, inner, RoutingMode::Auto);
    }

    src.close();
    return true;
}

void FileTransferManager::purgeStalePartialFiles()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 cutoff = now - kPartialFileMaxAgeSecs;

    SqlCipherQuery qSel(*m_dbPtr);
    QStringList toDelete;
    QStringList pathsToRemove;
    if (qSel.prepare("SELECT transfer_id, partial_path, created_secs "
                      "FROM file_transfers_in WHERE created_secs < :cutoff;")) {
        qSel.bindValue(":cutoff", cutoff);
        if (qSel.exec()) {
            while (qSel.next()) {
                toDelete << qSel.value(0).toString();
                pathsToRemove << qSel.value(1).toString();
            }
        }
    }
    for (int i = 0; i < toDelete.size(); ++i) {
        QFile::remove(pathsToRemove[i]);
        deleteIncomingRow(toDelete[i]);
    }

    // Also purge stale sent-transfer records (source file kept by user, but
    // our record of the file key shouldn't live forever).
    SqlCipherQuery qDel(*m_dbPtr);
    if (qDel.prepare("DELETE FROM file_transfers_out WHERE created_secs < :cutoff;")) {
        qDel.bindValue(":cutoff", cutoff);
        qDel.exec();
    }
}
