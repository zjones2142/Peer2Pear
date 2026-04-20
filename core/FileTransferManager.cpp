#include "FileTransferManager.hpp"
#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"

#include <sodium.h>
#include <nlohmann/json.hpp>

#include "log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <utility>

using json = nlohmann::json;
namespace fs = std::filesystem;

// ── Downloads-dir default ──────────────────────────────────────────────────
//
// Desktop looks up QStandardPaths::DownloadLocation; mobile hosts must set
// the partial directory explicitly via setPartialFileDir().  Wrapped in
// #ifdef QT_CORE_LIB so iOS builds don't pick up Qt here.
#ifdef QT_CORE_LIB
#include <QStandardPaths>
namespace {
std::string defaultDownloadsDir() {
    const QString dl = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    return dl.toStdString();
}
}
#else
namespace {
std::string defaultDownloadsDir() { return {}; }
}
#endif

// ── Wire helpers ────────────────────────────────────────────────────────────

// kFilePrefix (FROMFC:) was removed in the H1 fix (2026-04-19).  FTM
// only emits sealed chunks now — the ChatController-provided m_sealFn
// wraps them in SEALEDFC: envelopes before handing them to m_sendFn.

namespace {

inline void appendBE32(FileTransferManager::Bytes& dst, uint32_t v) {
    dst.push_back(uint8_t((v >> 24) & 0xFF));
    dst.push_back(uint8_t((v >> 16) & 0xFF));
    dst.push_back(uint8_t((v >>  8) & 0xFF));
    dst.push_back(uint8_t( v        & 0xFF));
}

inline uint32_t readBE32(const FileTransferManager::Bytes& b, size_t off = 0) {
    if (b.size() < off + 4) return 0;
    return (uint32_t(b[off])     << 24)
         | (uint32_t(b[off + 1]) << 16)
         | (uint32_t(b[off + 2]) <<  8)
         |  uint32_t(b[off + 3]);
}

inline int64_t nowSecs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Slice out a sub-range of Bytes.  Safe for out-of-range; returns empty.
FileTransferManager::Bytes slice(const FileTransferManager::Bytes& b,
                                  size_t off, size_t len) {
    if (off > b.size()) return {};
    const size_t n = std::min(len, b.size() - off);
    return FileTransferManager::Bytes(b.begin() + off, b.begin() + off + n);
}

FileTransferManager::Bytes tail(const FileTransferManager::Bytes& b, size_t off) {
    if (off >= b.size()) return {};
    return FileTransferManager::Bytes(b.begin() + off, b.end());
}

// First 8 chars of a peer/transfer ID plus ellipsis (logging only).
std::string idPrefix(const std::string& id) {
    const size_t n = std::min<size_t>(8, id.size());
    return id.substr(0, n);
}

// Derive a safe filename — strip any directory components.
std::string safeBasename(const std::string& fileName) {
    fs::path p(fileName);
    std::string base = p.filename().string();
    if (base.empty()) base = "file";
    return base;
}

// Generate a UUID-like identifier (32 hex chars + 4 hyphens) via libsodium.
std::string makeUuid() {
    uint8_t bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    // RFC 4122 v4 bits (high nibble of byte 6 = 4; high bits of byte 8 = 10)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2],  bytes[3],
        bytes[4], bytes[5], bytes[6],  bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

}  // anonymous namespace

// ── FileTransferManager ──────────────────────────────────────────────────────

FileTransferManager::FileTransferManager(CryptoEngine& crypto)
    : m_crypto(crypto)
{
    // Default partial-file directory: <DownloadLocation>/Peer2Pear/.partial/
    const std::string dl = defaultDownloadsDir();
    m_partialDir = dl.empty() ? std::string(".partial") : dl + "/Peer2Pear/.partial";
}

void FileTransferManager::setPartialFileDir(const std::string& dir)
{
    m_partialDir = dir;
}

// ── BLAKE2b-256 helpers ─────────────────────────────────────────────────────

FileTransferManager::Bytes FileTransferManager::blake2b256(const Bytes& data)
{
    Bytes hash(32, 0);
    crypto_generichash(hash.data(), 32,
                       data.data(),
                       data.size(),
                       nullptr, 0);
    return hash;
}

FileTransferManager::Bytes FileTransferManager::blake2b256File(const std::string& filePath)
{
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) {
        P2P_WARN("[FileTransfer] blake2b256File: cannot open"
                   << filePath);
        return {};
    }

    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 32);

    // 64 KB read buffer — bounded RAM regardless of file size.
    std::vector<char> buf(64 * 1024);
    while (f.good() && !f.eof()) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n <= 0) break;
        crypto_generichash_update(&st,
            reinterpret_cast<const unsigned char*>(buf.data()),
            static_cast<unsigned long long>(n));
    }
    if (f.bad()) {
        P2P_WARN("[FileTransfer] blake2b256File: read error on"
                   << filePath);
        return {};
    }

    Bytes hash(32, 0);
    crypto_generichash_final(&st, hash.data(), 32);
    return hash;
}

// ── Partial-file path helpers ───────────────────────────────────────────────

std::string FileTransferManager::partialPathFor(const std::string& transferId)
{
    std::error_code ec;
    fs::create_directories(m_partialDir, ec);
    return m_partialDir + "/" + transferId + ".partial";
}

std::string FileTransferManager::finalPathFor(const std::string& fileName,
                                               const std::string& transferId)
{
    const std::string safe = safeBasename(fileName);

    const std::string dl = defaultDownloadsDir();
    const std::string baseDir = (dl.empty() ? m_partialDir : dl)
                                + "/Peer2Pear/" + transferId;
    std::error_code ec;
    fs::create_directories(baseDir, ec);
    return baseDir + "/" + safe;
}

// ── Send one chunk with routing mode ────────────────────────────────────────

bool FileTransferManager::dispatchChunk(const std::string& /*senderIdB64u*/,
                                         const std::string& peerIdB64u,
                                         const Bytes& innerPayload,
                                         RoutingMode mode)
{
    // 1. Try P2P QUIC file stream (reliable, framed, congestion-controlled).
    if (m_p2pFileSendFn && m_p2pFileSendFn(peerIdB64u, innerPayload))
        return true;

    // P2POnly mode: refuse relay fallback, drop the chunk.
    if (mode == RoutingMode::P2POnly)
        return false;

    // 2. Sealed relay envelope (metadata privacy + sender anonymity).
    //
    // The H1 fix (2026-04-19) removed the "legacy FROMFC: plaintext-prefix
    // fallback" that used to live below this block.  If no seal callback is
    // installed, we now refuse to send rather than emit a FROMFC: envelope
    // that leaks the sender's pubkey on the wire.  ChatController installs
    // m_sealFn as part of setDatabase(), so this is normally always set.
    if (!m_sealFn) {
        P2P_WARN("[FileTransfer] No seal callback set — chunk BLOCKED (H1 fix: sealed-only)");
        return false;
    }

    Bytes sealedEnv = m_sealFn(peerIdB64u, innerPayload);
    if (sealedEnv.empty()) {
        P2P_WARN("[FileTransfer] Seal failed — chunk BLOCKED");
        return false;
    }
    if (m_sendFn) m_sendFn(peerIdB64u, sealedEnv);
    return true;
}

// ── Stream chunks from disk ─────────────────────────────────────────────────

void FileTransferManager::sendChunkEnvelopes(const std::string& senderIdB64u,
                                              const std::string& peerIdB64u,
                                              const Bytes& key32,
                                              const std::string& filePath,
                                              int64_t fileSize,
                                              const std::string& transferId,
                                              const std::string& fileName,
                                              const std::string& fileHashB64u,
                                              int64_t ts,
                                              RoutingMode mode,
                                              const std::string& groupId,
                                              const std::string& groupName)
{
    std::ifstream src(filePath, std::ios::binary);
    if (!src.is_open()) {
        P2P_WARN("[FileTransfer] Cannot open"
                   << filePath << "for streaming");
        if (onStatus) onStatus(std::string("Cannot read file: ") + fileName);
        return;
    }

    const int totalChunks = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    Bytes chunk;  // reused buffer — one allocation for the whole loop
    chunk.reserve(size_t(kChunkBytes));

    for (int i = 0; i < totalChunks; ++i) {
        // Fix #12: sender-side cancel check.
        if (m_abortedTransfers.count(transferId)) {
            P2P_LOG("[FileTransfer] aborted mid-stream at chunk" << i
                     << "of" << idPrefix(transferId));
            m_abortedTransfers.erase(transferId);
            return;
        }

        // Fix #16: live privacy-level upgrade.
        const RoutingMode effectiveMode =
            (mode == RoutingMode::P2POnly || m_senderRequiresP2PLive)
                ? RoutingMode::P2POnly
                : mode;

        const int64_t offset    = int64_t(i) * kChunkBytes;
        const int64_t remaining = fileSize - offset;
        const int64_t toRead    = std::min<int64_t>(kChunkBytes, remaining);

        // Seek + read this chunk only.
        src.seekg(offset);
        chunk.assign(size_t(toRead), 0);
        src.read(reinterpret_cast<char*>(chunk.data()), std::streamsize(toRead));
        if (src.gcount() != toRead) {
            P2P_WARN("[FileTransfer] Short read at chunk" << i
                       << "of" << idPrefix(transferId));
            break;
        }

        json meta;
        meta["from"]        = senderIdB64u;
        meta["type"]        = "file_chunk";
        meta["transferId"]  = transferId;
        meta["chunkIndex"]  = i;
        meta["totalChunks"] = totalChunks;
        meta["fileName"]    = fileName;
        meta["fileSize"]    = fileSize;
        meta["ts"]          = ts;
        meta["fileHash"]    = fileHashB64u;
        if (!groupId.empty()) {
            meta["groupId"]   = groupId;
            meta["groupName"] = groupName;
        }

        const std::string metaJsonStr = meta.dump();
        const Bytes metaJson(metaJsonStr.begin(), metaJsonStr.end());
        const Bytes encMeta  = m_crypto.aeadEncrypt(key32, metaJson);
        const Bytes encChunk = m_crypto.aeadEncrypt(key32, chunk);

        // Inner payload: <4-byte metaLen><encMeta><encChunk>
        Bytes innerPayload;
        innerPayload.reserve(4 + encMeta.size() + encChunk.size());
        appendBE32(innerPayload, uint32_t(encMeta.size()));
        innerPayload.insert(innerPayload.end(), encMeta.begin(), encMeta.end());
        innerPayload.insert(innerPayload.end(), encChunk.begin(), encChunk.end());

        if (!dispatchChunk(senderIdB64u, peerIdB64u, innerPayload, effectiveMode)) {
            P2P_WARN("[FileTransfer] P2P lost mid-stream at chunk" << i
                       << "— aborting transfer" << idPrefix(transferId));
            if (onStatus) onStatus(std::string("Transfer interrupted: direct connection lost."));
            return;
        }
    }

    // Kick off P2P for future messages
    if (onWantP2PConnection) onWantP2PConnection(peerIdB64u);
}

// ── Send file with ratchet-derived key ──────────────────────────────────────

std::string FileTransferManager::sendFileWithKey(const std::string& senderIdB64u,
                                                  const std::string& peerIdB64u,
                                                  const Bytes& fileKey,
                                                  const std::string& transferId,
                                                  const std::string& fileName,
                                                  const std::string& filePath,
                                                  int64_t fileSize,
                                                  const Bytes& fileHash,
                                                  const std::string& groupId,
                                                  const std::string& groupName)
{
    if (fileSize > kMaxFileBytes) {
        if (onStatus) onStatus(std::string("File too large (max ")
                    + std::to_string(kMaxFileBytes / (1024 * 1024)) + " MB).");
        return {};
    }
    if (fileKey.size() != 32) {
        if (onStatus) onStatus(std::string("Invalid file encryption key."));
        return {};
    }
    if (fileHash.size() != 32) {
        if (onStatus) onStatus(std::string("Invalid file hash (must be 32 bytes)."));
        return {};
    }
    if (!fs::exists(filePath)) {
        if (onStatus) onStatus(std::string("File not found: ") + filePath);
        return {};
    }

    const int64_t     ts           = nowSecs();
    const std::string fileHashB64u = CryptoEngine::toBase64Url(fileHash);
    const int         totalChunks  = int((fileSize + kChunkBytes - 1) / kChunkBytes);

    sendChunkEnvelopes(senderIdB64u, peerIdB64u, fileKey, filePath, fileSize,
                       transferId, fileName, fileHashB64u, ts,
                       RoutingMode::Auto,
                       groupId, groupName);

    if (groupId.empty()) {
        if (onStatus) onStatus("'" + fileName + "' streamed in " + std::to_string(totalChunks)
                    + " chunk(s) -> " + peerIdB64u);
    }
    return transferId;
}

// ── Announce-first: lock metadata at file_key time (Fix #3) ─────────────────

bool FileTransferManager::announceIncoming(const std::string& fromId,
                                            const std::string& transferId,
                                            const std::string& fileName,
                                            int64_t fileSize,
                                            int totalChunks,
                                            const Bytes& fileHash,
                                            const Bytes& fileKey,
                                            int64_t announcedTsSecs,
                                            const std::string& groupId,
                                            const std::string& groupName)
{
    if (transferId.empty() || totalChunks <= 0 ||
        fileSize <= 0 || fileSize > kMaxFileBytes ||
        fileHash.size() != 32 || fileKey.size() != 32) {
        P2P_WARN("[FileTransfer] announceIncoming: invalid args for"
                   << idPrefix(transferId));
        return false;
    }

    const int expectedChunks = int((fileSize + kChunkBytes - 1) / kChunkBytes);
    if (totalChunks != expectedChunks) {
        P2P_WARN("[FileTransfer] announceIncoming: totalChunks"
                   << totalChunks << "doesn't match fileSize"
                   << int64_t(fileSize) << "(expected" << expectedChunks << ")");
        return false;
    }

    if (m_incomingTransfers.count(transferId)) {
        return true;
    }

    if (static_cast<int>(m_incomingTransfers.size()) >= kMaxConcurrentTransfers) {
        if (onStatus) onStatus(std::string("Too many concurrent incoming transfers — dropping announce."));
        return false;
    }

    auto xferPtr = std::make_shared<IncomingTransfer>();
    IncomingTransfer& xfer = *xferPtr;

    const std::string safeName = safeBasename(fileName);

    xfer.fromId       = fromId;
    xfer.fileName     = safeName;
    xfer.fileSize     = fileSize;
    xfer.totalChunks  = totalChunks;
    xfer.tsSecs       = announcedTsSecs > 0 ? announcedTsSecs : nowSecs();
    xfer.fileHash     = fileHash;
    xfer.groupId      = groupId;
    xfer.groupName    = groupName;
    xfer.createdSecs  = nowSecs();
    xfer.partialPath  = partialPathFor(transferId);
    xfer.finalPath    = finalPathFor(xfer.fileName, transferId);
    xfer.receivedChunks.assign(size_t(totalChunks), false);

    xfer.partialFile = std::make_unique<std::fstream>(xfer.partialPath,
        std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc);
    if (!xfer.partialFile->is_open()) {
        P2P_WARN("[FileTransfer] announceIncoming: cannot open partial file"
                   << xfer.partialPath);
        if (onStatus) onStatus(std::string("Cannot write to disk: ") + xfer.fileName);
        return false;
    }

    m_incomingTransfers[transferId] = xferPtr;

    // Phase 4: persist so we can resume after a crash before any chunk arrives.
    persistIncomingFull(transferId, xfer, fileKey);
    return true;
}

// ── Handle incoming file chunk ───────────────────────────────────────────────

bool FileTransferManager::handleFileEnvelope(const std::string& fromId,
                                              const Bytes& payload,
                                              std::function<bool(const std::string&)> markSeen,
                                              const std::map<std::string, Bytes>& fileKeys)
{
    if (payload.size() < 4) return false;

    const uint32_t metaLen = readBE32(payload, 0);
    if (payload.size() - 4 < size_t(metaLen)) return false;

    const Bytes encMeta  = slice(payload, 4, metaLen);
    const Bytes encChunk = tail (payload, 4 + size_t(metaLen));

    // ── Key selection: ratchet keys only (L8 fix) ──────────────────────────
    Bytes metaJson;
    Bytes key32;

    for (const auto& [peer, key] : fileKeys) {
        (void)peer;
        if (key.size() != 32) continue;
        metaJson = m_crypto.aeadDecrypt(key, encMeta);
        if (!metaJson.empty()) {
            key32 = key;
            break;
        }
    }
    if (metaJson.empty()) {
        P2P_WARN("[FileTransfer] No ratchet key found for file chunk from"
                   << idPrefix(fromId) + "...");
        return false;
    }

    json meta;
    try {
        meta = json::parse(std::string(metaJson.begin(), metaJson.end()));
    } catch (...) { return false; }
    if (!meta.is_object()) return false;

    const std::string transferId = meta.value("transferId", "");
    const int chunkIndex         = meta.value("chunkIndex",  -1);
    const int claimedTotal       = meta.value("totalChunks",  0);
    if (transferId.empty()
        || claimedTotal <= 0
        || chunkIndex < 0
        || chunkIndex >= claimedTotal) return false;

    auto itXfer = m_incomingTransfers.find(transferId);
    if (itXfer == m_incomingTransfers.end() || !itXfer->second) {
        P2P_WARN("[FileTransfer] chunk for unannounced transfer"
                   << idPrefix(transferId) << "from" << idPrefix(fromId) + "... — dropped");
        return true;
    }

    IncomingTransfer& xfer = *itXfer->second;

    // Metadata must match the locked announcement.
    const int64_t claimedSize = meta.value("fileSize", int64_t(0));
    const Bytes   claimedHash = CryptoEngine::fromBase64Url(
        meta.value("fileHash", std::string()));
    if (claimedTotal != xfer.totalChunks ||
        claimedSize  != xfer.fileSize ||
        (xfer.fileHash.size() == 32 && !claimedHash.empty() && claimedHash != xfer.fileHash)) {
        P2P_WARN("[FileTransfer] chunk metadata disagrees with announce for"
                   << idPrefix(transferId) << "— dropped."
                   << "claimed(size/chunks)=" << int64_t(claimedSize) << "/" << claimedTotal
                   << "vs announced=" << int64_t(xfer.fileSize) << "/" << xfer.totalChunks);
        return true;
    }

    // Per-chunk dedup: "<transferId>:<chunkIndex>"
    const std::string dedupKey = transferId + ":" + std::to_string(chunkIndex);
    if (!markSeen(dedupKey)) return true;

    const Bytes chunkData = m_crypto.aeadDecrypt(key32, encChunk);
    if (chunkData.empty()) return true;

    // Each plaintext chunk except possibly the last must equal kChunkBytes.
    const int64_t expectedLen =
        (chunkIndex == xfer.totalChunks - 1)
            ? (xfer.fileSize - int64_t(chunkIndex) * kChunkBytes)
            : kChunkBytes;
    if (int64_t(chunkData.size()) != expectedLen) {
        P2P_WARN("[FileTransfer] chunk" << chunkIndex << "has wrong plaintext size"
                   << int64_t(chunkData.size()) << "(expected" << int64_t(expectedLen) << ")");
        return true;
    }

    // Guard against the partial file being closed (e.g., after completion).
    if (!xfer.partialFile || !xfer.partialFile->is_open()) {
        P2P_WARN("[FileTransfer] chunk for closed partial file"
                   << idPrefix(transferId) << "— dropped");
        return true;
    }

    // Already received? (dedup above should have caught it, but double-check.)
    if (chunkIndex < int(xfer.receivedChunks.size()) && xfer.receivedChunks[chunkIndex]) {
        return true;
    }

    // Write chunk at its correct offset — no RAM accumulation.
    const int64_t offset = int64_t(chunkIndex) * kChunkBytes;
    xfer.partialFile->seekp(std::streamoff(offset));
    xfer.partialFile->write(reinterpret_cast<const char*>(chunkData.data()),
                             std::streamsize(chunkData.size()));
    if (!xfer.partialFile->good()) {
        P2P_WARN("[FileTransfer] Write failed for chunk" << chunkIndex
                   << "of" << idPrefix(transferId));
        return true;
    }
    xfer.partialFile->flush();
    xfer.receivedChunks[chunkIndex] = true;
    xfer.chunksReceivedCount++;

    // Phase 4: update DB bitmap after each successful write so we can resume.
    persistIncomingFull(transferId, xfer, key32);

    const int received    = xfer.chunksReceivedCount;
    const int totalOfXfer = xfer.totalChunks;

    if (received < totalOfXfer) {
        if (onFileChunkReceived) onFileChunkReceived(fromId, transferId, xfer.fileName,
                               xfer.fileSize, received, totalOfXfer,
                               std::string{}, xfer.tsSecs,
                               xfer.groupId, xfer.groupName);
        return true;
    }

    // ── All chunks received ─────────────────────────────────────────────────
    xfer.partialFile->close();

    // Capture values we need before removing the entry.
    const std::string fileName    = xfer.fileName;
    const int64_t     fileSize    = xfer.fileSize;
    const std::string groupId     = xfer.groupId;
    const std::string groupName   = xfer.groupName;
    const int64_t     tsCopy      = xfer.tsSecs;
    const Bytes       expected    = xfer.fileHash;
    const std::string partialPath = xfer.partialPath;
    const std::string finalPath   = xfer.finalPath;

    m_incomingTransfers.erase(itXfer);
    if (onTransferCompleted) onTransferCompleted(transferId);  // M1: let ChatController zero the key

    // Verify integrity by streaming the completed file from disk.
    if (!expected.empty()) {
        const Bytes actual = blake2b256File(partialPath);
        if (actual != expected) {
            std::error_code ec;
            fs::remove(partialPath, ec);
            deleteIncomingRow(transferId);
            if (onStatus) onStatus("File '" + fileName + "' integrity check FAILED — discarded.");
            if (onFileChunkReceived) onFileChunkReceived(fromId, transferId, fileName,
                                   fileSize, totalOfXfer, totalOfXfer,
                                   std::string{}, tsCopy, groupId, groupName);
            return true;
        }
    }

    // Move partial → final. If target exists, overwrite.
    std::error_code ec;
    fs::remove(finalPath, ec);
    ec.clear();
    fs::rename(partialPath, finalPath, ec);
    if (ec) {
        P2P_WARN("[FileTransfer] Rename failed"
                   << partialPath << "->"
                   << finalPath);
        if (onStatus) onStatus(std::string("Could not save file: ") + fileName);
        return true;
    }

    // Phase 4: transfer done + hash verified — drop persistent state.
    deleteIncomingRow(transferId);

    if (onFileChunkReceived) onFileChunkReceived(fromId, transferId, fileName,
                           fileSize, totalOfXfer, totalOfXfer,
                           finalPath, tsCopy, groupId, groupName);
    return true;
}

// ── Stale transfer purge ─────────────────────────────────────────────────────

void FileTransferManager::purgeStaleTransfers()
{
    const int64_t now = nowSecs();
    for (auto it = m_incomingTransfers.begin(); it != m_incomingTransfers.end(); ) {
        auto& xferPtr = it->second;
        if (xferPtr && xferPtr->createdSecs > 0 &&
            (now - xferPtr->createdSecs) > kMaxTransferAgeSecs) {
            const std::string tid = it->first;
            if (onStatus) onStatus("Purged stale transfer '" + xferPtr->fileName + "' ("
                        + std::to_string(xferPtr->chunksReceivedCount) + "/"
                        + std::to_string(xferPtr->totalChunks) + " chunks) after 30 min.");

            if (xferPtr->partialFile) {
                xferPtr->partialFile->close();
                xferPtr->partialFile.reset();
            }
            if (!xferPtr->partialPath.empty()) {
                std::error_code ec;
                fs::remove(xferPtr->partialPath, ec);
            }

            deleteIncomingRow(tid);

            it = m_incomingTransfers.erase(it);
            if (onTransferCompleted) onTransferCompleted(tid);
        } else {
            ++it;
        }
    }
}

// ── Phase 2: outbound consent gate ──────────────────────────────────────────

void FileTransferManager::queueOutboundFile(const std::string& senderIdB64u,
                                             const std::string& peerIdB64u,
                                             const Bytes& fileKey,
                                             const std::string& transferId,
                                             const std::string& fileName,
                                             const std::string& filePath,
                                             int64_t fileSize,
                                             const Bytes& fileHash,
                                             const std::string& groupId,
                                             const std::string& groupName)
{
    if (fileKey.size() != 32 || fileHash.size() != 32) {
        P2P_WARN("[FileTransfer] queueOutboundFile: bad key/hash length");
        return;
    }
    OutboundTransfer out;
    out.senderId   = senderIdB64u;
    out.peerId     = peerIdB64u;
    out.fileKey    = fileKey;         // owned copy
    out.fileName   = fileName;
    out.filePath   = filePath;
    out.fileSize   = fileSize;
    out.fileHash   = fileHash;
    out.groupId    = groupId;
    out.groupName  = groupName;
    out.queuedSecs = nowSecs();
    m_outboundPending[transferId] = std::move(out);
}

bool FileTransferManager::startOutboundStream(const std::string& transferId,
                                                bool requireP2P,
                                                bool senderRequiresP2P,
                                                bool p2pReadyNow)
{
    auto it = m_outboundPending.find(transferId);
    if (it == m_outboundPending.end()) {
        P2P_WARN("[FileTransfer] startOutboundStream: unknown transferId"
                   << idPrefix(transferId));
        return false;
    }

    if (!fs::exists(it->second.filePath)) {
        const std::string name = it->second.fileName;
        const std::string peer = it->second.peerId;
        if (onStatus) onStatus(std::string("File vanished before accept: ") + name);
        CryptoEngine::secureZero(it->second.fileKey);
        m_outboundPending.erase(it);
        if (onOutboundAbandoned) onOutboundAbandoned(transferId, peer);
        return false;
    }

    const bool requiresP2P = requireP2P || senderRequiresP2P;
    const bool isLarge     = it->second.fileSize > kLargeFileBytes;

    if (!isLarge) {
        OutboundTransfer out = std::move(it->second);
        m_outboundPending.erase(it);

        const int64_t     ts           = nowSecs();
        const std::string fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int         totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        registerSentTransfer(out.senderId, out.peerId, transferId, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           transferId, out.fileName, fileHashB64u, ts,
                           RoutingMode::Auto,
                           out.groupId, out.groupName);

        if (out.groupId.empty()) {
            if (onStatus) onStatus("'" + out.fileName + "' streamed in "
                        + std::to_string(totalChunks) + " chunk(s) -> " + out.peerId);
        }
        CryptoEngine::secureZero(out.fileKey);
        return true;
    }

    // Large file path — record the transport policy first.
    it->second.receiverRequiresP2P = requireP2P;
    it->second.senderRequiresP2P   = senderRequiresP2P;

    if (p2pReadyNow) {
        OutboundTransfer out = std::move(it->second);
        m_outboundPending.erase(it);

        const int64_t     ts           = nowSecs();
        const std::string fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int         totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        const RoutingMode mode = requiresP2P ? RoutingMode::P2POnly : RoutingMode::Auto;

        registerSentTransfer(out.senderId, out.peerId, transferId, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           transferId, out.fileName, fileHashB64u, ts,
                           mode,
                           out.groupId, out.groupName);

        if (out.groupId.empty()) {
            if (onStatus) onStatus("'" + out.fileName + "' streamed in "
                        + std::to_string(totalChunks) + " chunk(s) -> " + out.peerId + " (P2P)");
        }
        CryptoEngine::secureZero(out.fileKey);
        return true;
    }

    // Large file + no P2P yet → park in WaitingForP2P state.
    it->second.stage           = OutboundStage::WaitingForP2P;
    it->second.waitStartedSecs = nowSecs();

    if (onStatus) onStatus("Waiting for direct connection to send '" + it->second.fileName + "'...");
    return true;
}

std::vector<std::string>
FileTransferManager::notifyP2PReady(const std::string& peerIdB64u)
{
    std::vector<std::string> flushed;
    std::vector<std::string> toFlush;
    for (auto& [tid, out] : m_outboundPending) {
        if (out.stage == OutboundStage::WaitingForP2P && out.peerId == peerIdB64u) {
            toFlush.push_back(tid);
        }
    }

    for (const std::string& tid : toFlush) {
        auto it = m_outboundPending.find(tid);
        if (it == m_outboundPending.end()) continue;

        OutboundTransfer out = std::move(it->second);
        m_outboundPending.erase(it);

        const int64_t     ts           = nowSecs();
        const std::string fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);
        const int         totalChunks  = int((out.fileSize + kChunkBytes - 1) / kChunkBytes);

        const bool requiresP2P = out.receiverRequiresP2P || out.senderRequiresP2P;
        const RoutingMode mode = requiresP2P ? RoutingMode::P2POnly : RoutingMode::Auto;

        registerSentTransfer(out.senderId, out.peerId, tid, out.fileName,
                             out.filePath, out.fileSize, out.fileHash, out.fileKey,
                             out.groupId, out.groupName);

        sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                           out.filePath, out.fileSize,
                           tid, out.fileName, fileHashB64u, ts,
                           mode,
                           out.groupId, out.groupName);

        if (out.groupId.empty()) {
            if (onStatus) onStatus("'" + out.fileName + "' streamed in "
                        + std::to_string(totalChunks) + " chunk(s) -> "
                        + out.peerId + " (P2P ready)");
        }
        CryptoEngine::secureZero(out.fileKey);
        flushed.push_back(tid);
    }

    return flushed;
}

void FileTransferManager::abandonOutboundTransfer(const std::string& transferId)
{
    auto it = m_outboundPending.find(transferId);
    if (it != m_outboundPending.end()) {
        const std::string peerId = it->second.peerId;
        CryptoEngine::secureZero(it->second.fileKey);
        m_outboundPending.erase(it);
        if (onOutboundAbandoned) onOutboundAbandoned(transferId, peerId);
    }
    m_abortedTransfers.insert(transferId);
}

void FileTransferManager::cancelInboundTransfer(const std::string& transferId)
{
    auto it = m_incomingTransfers.find(transferId);
    if (it == m_incomingTransfers.end()) return;

    auto& xferPtr = it->second;
    const std::string peerId = xferPtr ? xferPtr->fromId : std::string();

    if (xferPtr && xferPtr->partialFile) {
        xferPtr->partialFile->close();
        xferPtr->partialFile.reset();
    }
    if (xferPtr && !xferPtr->partialPath.empty()) {
        std::error_code ec;
        fs::remove(xferPtr->partialPath, ec);
    }

    deleteIncomingRow(transferId);

    m_incomingTransfers.erase(it);
    if (onInboundCanceled) onInboundCanceled(transferId, peerId);
    if (onTransferCompleted) onTransferCompleted(transferId);
}

std::string FileTransferManager::outboundPeerFor(const std::string& transferId) const
{
    auto it = m_outboundPending.find(transferId);
    return (it == m_outboundPending.end()) ? std::string() : it->second.peerId;
}

std::string FileTransferManager::inboundPeerFor(const std::string& transferId) const
{
    auto it = m_incomingTransfers.find(transferId);
    if (it == m_incomingTransfers.end() || !it->second) return {};
    return it->second->fromId;
}

void FileTransferManager::purgeStaleOutbound()
{
    const int64_t now = nowSecs();
    for (auto it = m_outboundPending.begin(); it != m_outboundPending.end(); ) {
        // Phase 3: WaitingForP2P entries have their own shorter deadline.
        if (it->second.stage == OutboundStage::WaitingForP2P &&
            it->second.waitStartedSecs > 0 &&
            (now - it->second.waitStartedSecs) > kP2PReadyWaitSecs) {

            const std::string tid       = it->first;
            const std::string peerId    = it->second.peerId;
            const std::string name      = it->second.fileName;
            const bool receiverReq      = it->second.receiverRequiresP2P;
            const bool senderReq        = it->second.senderRequiresP2P;
            const bool requiresP2P      = receiverReq || senderReq;

            if (requiresP2P) {
                if (onStatus) onStatus("Direct connection unavailable for '" + name
                            + "' — transfer aborted (privacy level blocks relay fallback).");
                CryptoEngine::secureZero(it->second.fileKey);
                const bool byReceiver = receiverReq && !senderReq;
                it = m_outboundPending.erase(it);
                if (onOutboundBlockedByPolicy) onOutboundBlockedByPolicy(tid, peerId, byReceiver);
                continue;
            }

            OutboundTransfer out = std::move(it->second);
            it = m_outboundPending.erase(it);

            if (onStatus) onStatus("Direct connection timed out for '" + name + "' — streaming via relay.");

            const int64_t     ts           = nowSecs();
            const std::string fileHashB64u = CryptoEngine::toBase64Url(out.fileHash);

            registerSentTransfer(out.senderId, out.peerId, tid, out.fileName,
                                 out.filePath, out.fileSize, out.fileHash, out.fileKey,
                                 out.groupId, out.groupName);

            sendChunkEnvelopes(out.senderId, out.peerId, out.fileKey,
                               out.filePath, out.fileSize,
                               tid, out.fileName, fileHashB64u, ts,
                               RoutingMode::Auto,
                               out.groupId, out.groupName);
            CryptoEngine::secureZero(out.fileKey);
            continue;
        }

        // Plain outbound-pending (no file_accept yet): older 10-minute timeout.
        if (it->second.stage == OutboundStage::Queued &&
            it->second.queuedSecs > 0 &&
            (now - it->second.queuedSecs) > kOutboundPendingTimeoutSecs) {
            const std::string tid = it->first;
            const std::string peerId = it->second.peerId;
            if (onStatus) onStatus("Outbound file '" + it->second.fileName
                        + "' timed out — peer didn't respond.");
            CryptoEngine::secureZero(it->second.fileKey);
            it = m_outboundPending.erase(it);
            if (onOutboundAbandoned) onOutboundAbandoned(tid, peerId);
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

    q.exec(
        "CREATE TABLE IF NOT EXISTS file_transfers_in ("
        "  transfer_id     TEXT PRIMARY KEY,"
        "  peer_id         TEXT NOT NULL,"
        "  file_name       TEXT NOT NULL,"
        "  file_size       INTEGER NOT NULL,"
        "  total_chunks    INTEGER NOT NULL,"
        "  file_hash       BLOB,"
        "  file_key        BLOB NOT NULL,"
        "  group_id        TEXT,"
        "  group_name      TEXT,"
        "  partial_path    TEXT NOT NULL,"
        "  final_path      TEXT NOT NULL,"
        "  received_bitmap BLOB NOT NULL,"
        "  created_secs    INTEGER NOT NULL,"
        "  ts_secs         INTEGER"
        ");"
    );

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

// Serialize a std::vector<bool> to a compact blob.  Format:
//   [4-byte bit count BE][packed bytes].  Byte-compatible with the prior
//   QBitArray-based format so existing DB rows decode cleanly.
static FileTransferManager::Bytes bitArrayToBlob(const std::vector<bool>& bits)
{
    FileTransferManager::Bytes blob(4 + (bits.size() + 7) / 8, 0);
    const uint32_t n = uint32_t(bits.size());
    blob[0] = uint8_t((n >> 24) & 0xFF);
    blob[1] = uint8_t((n >> 16) & 0xFF);
    blob[2] = uint8_t((n >>  8) & 0xFF);
    blob[3] = uint8_t( n        & 0xFF);
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i])
            blob[4 + i / 8] = uint8_t(blob[4 + i / 8] | (1u << (i % 8)));
    }
    return blob;
}

static std::vector<bool> blobToBitArray(const FileTransferManager::Bytes& blob)
{
    if (blob.size() < 4) return {};
    const uint32_t n = (uint32_t(blob[0]) << 24) |
                       (uint32_t(blob[1]) << 16) |
                       (uint32_t(blob[2]) <<  8) |
                        uint32_t(blob[3]);
    if (blob.size() < 4 + size_t((n + 7) / 8)) return {};
    std::vector<bool> bits(n, false);
    for (uint32_t i = 0; i < n; ++i) {
        if (blob[4 + i / 8] & (1u << (i % 8))) bits[i] = true;
    }
    return bits;
}

void FileTransferManager::persistIncomingFull(const std::string& transferId,
                                                const IncomingTransfer& xfer,
                                                const Bytes& fileKey) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    if (fileKey.size() != 32) return;

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
    q.bindValue(":size",    int64_t(xfer.fileSize));
    q.bindValue(":chunks",  xfer.totalChunks);
    q.bindValue(":hash",    xfer.fileHash);
    q.bindValue(":key",     fileKey);
    q.bindValue(":gid",     xfer.groupId);
    q.bindValue(":gname",   xfer.groupName);
    q.bindValue(":ppath",   xfer.partialPath);
    q.bindValue(":fpath",   xfer.finalPath);
    q.bindValue(":bmap",    bitArrayToBlob(xfer.receivedChunks));
    q.bindValue(":created", int64_t(xfer.createdSecs));
    q.bindValue(":ts",      int64_t(xfer.tsSecs));
    q.exec();
}

void FileTransferManager::deleteIncomingRow(const std::string& transferId) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.prepare("DELETE FROM file_transfers_in WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    q.exec();
}

void FileTransferManager::deleteSentRow(const std::string& transferId) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.prepare("DELETE FROM file_transfers_out WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    q.exec();
}

void FileTransferManager::forgetSentTransfer(const std::string& transferId)
{
    auto it = m_sentTransfers.find(transferId);
    if (it != m_sentTransfers.end()) {
        CryptoEngine::secureZero(it->second.fileKey);
        m_sentTransfers.erase(it);
    }
    deleteSentRow(transferId);

    m_abortedTransfers.insert(transferId);
}

void FileTransferManager::setSenderRequiresP2P(bool require)
{
    m_senderRequiresP2PLive = require;
}

void FileTransferManager::registerSentTransfer(const std::string& senderIdB64u,
                                                 const std::string& peerIdB64u,
                                                 const std::string& transferId,
                                                 const std::string& fileName,
                                                 const std::string& filePath,
                                                 int64_t fileSize,
                                                 const Bytes& fileHash,
                                                 const Bytes& fileKey,
                                                 const std::string& groupId,
                                                 const std::string& groupName)
{
    SentTransfer s;
    s.senderId     = senderIdB64u;
    s.peerId       = peerIdB64u;
    s.fileName     = fileName;
    s.filePath     = filePath;
    s.fileSize     = fileSize;
    s.fileHash     = fileHash;
    s.fileKey      = fileKey;
    s.groupId      = groupId;
    s.groupName    = groupName;
    s.createdSecs  = nowSecs();
    m_sentTransfers[transferId] = s;

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
            q.bindValue(":size",    int64_t(fileSize));
            q.bindValue(":hash",    fileHash);
            q.bindValue(":key",     fileKey);
            q.bindValue(":gid",     groupId);
            q.bindValue(":gname",   groupName);
            q.bindValue(":created", int64_t(s.createdSecs));
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
                      "       file_hash, file_key, group_id, group_name, partial_path, "
                      "       final_path, received_bitmap, created_secs, ts_secs "
                      "FROM file_transfers_in;") && q.exec()) {
            while (q.next()) {
                const std::string tid      = q.valueText(0);
                const std::string peerId   = q.valueText(1);
                const std::string fname    = q.valueText(2);
                const int64_t     fsize    = q.valueInt64(3);
                const int         chunks   = q.valueInt(4);
                const Bytes       fhash    = q.valueBlob(5);
                const Bytes       fkey     = q.valueBlob(6);
                const std::string gid      = q.valueText(7);
                const std::string gname    = q.valueText(8);
                const std::string ppath    = q.valueText(9);
                const std::string fpath    = q.valueText(10);
                const Bytes       bmap     = q.valueBlob(11);
                const int64_t     created  = q.valueInt64(12);
                const int64_t     tsSecs   = q.valueInt64(13);

                if (!fs::exists(ppath)) {
                    deleteIncomingRow(tid);
                    continue;
                }

                auto xferPtr = std::make_shared<IncomingTransfer>();
                xferPtr->fromId         = peerId;
                xferPtr->fileName       = fname;
                xferPtr->fileSize       = fsize;
                xferPtr->totalChunks    = chunks;
                xferPtr->fileHash       = fhash;
                xferPtr->groupId        = gid;
                xferPtr->groupName      = gname;
                xferPtr->partialPath    = ppath;
                xferPtr->finalPath      = fpath;
                xferPtr->receivedChunks = blobToBitArray(bmap);
                xferPtr->createdSecs    = created;
                xferPtr->tsSecs         = tsSecs;

                int set = 0;
                for (bool b : xferPtr->receivedChunks) if (b) ++set;
                xferPtr->chunksReceivedCount = set;

                // Re-open partial file R/W without truncation.
                xferPtr->partialFile = std::make_unique<std::fstream>(ppath,
                    std::ios::in | std::ios::out | std::ios::binary);
                if (!xferPtr->partialFile->is_open()) {
                    P2P_WARN("[FileTransfer] loadPersisted: cannot reopen"
                               << ppath);
                    deleteIncomingRow(tid);
                    continue;
                }

                m_incomingTransfers[tid] = xferPtr;

                // Fix #5: hand the restored fileKey back to ChatController.
                if (fkey.size() == 32) {
                    if (onIncomingFileKeyRestored) onIncomingFileKeyRestored(peerId, tid, fkey);
                }
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
                const std::string tid = q.valueText(0);
                SentTransfer s;
                s.senderId    = q.valueText(1);
                s.peerId      = q.valueText(2);
                s.fileName    = q.valueText(3);
                s.filePath    = q.valueText(4);
                s.fileSize    = q.valueInt64(5);
                s.fileHash    = q.valueBlob(6);
                s.fileKey     = q.valueBlob(7);
                s.groupId     = q.valueText(8);
                s.groupName   = q.valueText(9);
                s.createdSecs = q.valueInt64(10);

                if (!fs::exists(s.filePath) || s.fileKey.size() != 32) {
                    deleteSentRow(tid);
                    continue;
                }
                m_sentTransfers[tid] = std::move(s);
            }
        }
    }
}

std::vector<FileTransferManager::PendingResumption>
FileTransferManager::pendingResumptions() const
{
    std::vector<PendingResumption> out;
    for (const auto& [tid, xferPtr] : m_incomingTransfers) {
        if (!xferPtr || xferPtr->chunksReceivedCount >= xferPtr->totalChunks) continue;

        PendingResumption pr;
        pr.transferId = tid;
        pr.peerId     = xferPtr->fromId;
        for (size_t i = 0; i < xferPtr->receivedChunks.size(); ++i) {
            if (!xferPtr->receivedChunks[i])
                pr.missingChunks.push_back(uint32_t(i));
        }
        if (!pr.missingChunks.empty()) out.push_back(std::move(pr));
    }
    return out;
}

bool FileTransferManager::resendChunks(const std::string& transferId,
                                        const std::vector<uint32_t>& chunkIndices)
{
    auto itSent = m_sentTransfers.find(transferId);
    if (itSent == m_sentTransfers.end()) {
        P2P_WARN("[FileTransfer] resendChunks: no sender record for"
                   << idPrefix(transferId));
        return false;
    }
    SentTransfer& s = itSent->second;
    if (!fs::exists(s.filePath)) {
        P2P_WARN("[FileTransfer] resendChunks: source file gone"
                   << s.filePath);
        return false;
    }

    std::ifstream src(s.filePath, std::ios::binary);
    if (!src.is_open()) {
        P2P_WARN("[FileTransfer] resendChunks: cannot open"
                   << s.filePath);
        return false;
    }

    const int totalChunks = int((s.fileSize + kChunkBytes - 1) / kChunkBytes);
    const std::string fileHashB64u = CryptoEngine::toBase64Url(s.fileHash);
    const int64_t ts = nowSecs();

    Bytes chunk;
    chunk.reserve(size_t(kChunkBytes));

    for (uint32_t i : chunkIndices) {
        if (int(i) >= totalChunks) continue;

        const int64_t offset    = int64_t(i) * kChunkBytes;
        const int64_t remaining = s.fileSize - offset;
        const int64_t toRead    = std::min<int64_t>(kChunkBytes, remaining);

        src.seekg(offset);
        chunk.assign(size_t(toRead), 0);
        src.read(reinterpret_cast<char*>(chunk.data()), std::streamsize(toRead));
        if (src.gcount() != toRead) {
            P2P_WARN("[FileTransfer] resendChunks: short read at chunk" << i);
            break;
        }

        json meta;
        meta["from"]        = s.senderId;
        meta["type"]        = "file_chunk";
        meta["transferId"]  = transferId;
        meta["chunkIndex"]  = int(i);
        meta["totalChunks"] = totalChunks;
        meta["fileName"]    = s.fileName;
        meta["fileSize"]    = s.fileSize;
        meta["ts"]          = ts;
        meta["fileHash"]    = fileHashB64u;
        if (!s.groupId.empty()) {
            meta["groupId"]   = s.groupId;
            meta["groupName"] = s.groupName;
        }

        const std::string metaJsonStr = meta.dump();
        const Bytes metaJson(metaJsonStr.begin(), metaJsonStr.end());
        const Bytes encMeta  = m_crypto.aeadEncrypt(s.fileKey, metaJson);
        const Bytes encChunk = m_crypto.aeadEncrypt(s.fileKey, chunk);

        Bytes inner;
        inner.reserve(4 + encMeta.size() + encChunk.size());
        appendBE32(inner, uint32_t(encMeta.size()));
        inner.insert(inner.end(), encMeta.begin(), encMeta.end());
        inner.insert(inner.end(), encChunk.begin(), encChunk.end());

        dispatchChunk(s.senderId, s.peerId, inner, RoutingMode::Auto);
    }

    return true;
}

void FileTransferManager::purgeStalePartialFiles()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    const int64_t now = nowSecs();
    const int64_t cutoffIn  = now - kPartialFileMaxAgeSecs;   // L6: 3 days for receiver
    const int64_t cutoffOut = now - kSentTransferMaxAgeSecs;  // L6: 12h for sender

    SqlCipherQuery qSel(*m_dbPtr);
    std::vector<std::string> toDelete;
    std::vector<std::string> pathsToRemove;
    if (qSel.prepare("SELECT transfer_id, partial_path, created_secs "
                      "FROM file_transfers_in WHERE created_secs < :cutoff;")) {
        qSel.bindValue(":cutoff", int64_t(cutoffIn));
        if (qSel.exec()) {
            while (qSel.next()) {
                toDelete.push_back(qSel.valueText(0));
                pathsToRemove.push_back(qSel.valueText(1));
            }
        }
    }
    for (size_t i = 0; i < toDelete.size(); ++i) {
        std::error_code ec;
        fs::remove(pathsToRemove[i], ec);
        deleteIncomingRow(toDelete[i]);
    }

    SqlCipherQuery qDel(*m_dbPtr);
    if (qDel.prepare("DELETE FROM file_transfers_out WHERE created_secs < :cutoff;")) {
        qDel.bindValue(":cutoff", int64_t(cutoffOut));
        qDel.exec();
    }

    const int64_t memCutoff = cutoffOut;
    for (auto it = m_sentTransfers.begin(); it != m_sentTransfers.end(); ) {
        if (it->second.createdSecs > 0 && it->second.createdSecs < memCutoff) {
            CryptoEngine::secureZero(it->second.fileKey);
            it = m_sentTransfers.erase(it);
        } else {
            ++it;
        }
    }
}
