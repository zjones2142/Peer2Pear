// test_file_transfer.cpp — tests for FileTransferManager.
//
// FileTransferManager streams a file in 240 KB chunks, each one encrypted
// with a per-file AEAD key and tagged with a BLAKE2b-256 file hash.  This
// file locks in the *end-to-end* receiver contract:
//
//   - Streaming hash (blake2b256File) matches the one-shot version over
//     the same bytes, including empty files and multi-chunk files.
//   - A full file survives a sender → wire → receiver round-trip, both
//     when chunks arrive in order and when the network reorders them.
//   - Announcing the wrong hash causes the receiver to discard the file
//     rather than silently accept corrupted content.
//   - Partial transfers persist to the DB so a receiver that's restarted
//     mid-transfer reports the missing chunks via pendingResumptions().
//
// These are integration-style tests: they wire two FileTransferManager
// instances together via capture-lambdas for the SealFn/SendFn hooks.
// The "sender" runs sendFileWithKey() and the lambdas drop the inner
// payloads into a vector.  The "receiver" calls announceIncoming() and
// then handleFileEnvelope() on each captured payload.
//
// Successfully-completed transfers are renamed into the OS Downloads
// directory — see cleanupSavedPath() below.  The transferId is random
// per test so there's no collision with real user files.

#include "FileTransferManager.hpp"
#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

using p2p_test::makeTempPath;

Bytes randomBytes(size_t n) {
    Bytes b(n);
    randombytes_buf(b.data(), n);
    return b;
}

void writeFile(const std::string& path, const Bytes& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            std::streamsize(bytes.size()));
    f.close();
    ASSERT_TRUE(f.good()) << "failed writing " << path;
}

Bytes readFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return Bytes((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
}

// Completed transfers get dropped into ~/Downloads/Peer2Pear/<transferId>/.
// Remove that subdirectory to keep the user's Downloads folder clean.
void cleanupSavedPath(const std::string& savedPath) {
    if (savedPath.empty()) return;
    const fs::path p = savedPath;
    std::error_code ec;
    fs::remove_all(p.parent_path(), ec);  // .../Peer2Pear/<transferId>/
}

class Bootstrap : public ::testing::Environment {
public:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};
::testing::Environment* const kBootstrap =
    ::testing::AddGlobalTestEnvironment(new Bootstrap);

}  // namespace

// ── 1. Streaming hash matches one-shot hash over the same buffer ──────────

TEST(FileTransferManager, Blake2b256FileMatchesBuffer) {
    const std::string path = makeTempPath("p2p-ft-hash", ".bin");
    const Bytes bytes = randomBytes(4096 + 123);
    writeFile(path, bytes);

    const Bytes byBuf  = FileTransferManager::blake2b256(bytes);
    const Bytes byFile = FileTransferManager::blake2b256File(path);
    ASSERT_EQ(byBuf.size(), 32u);
    EXPECT_EQ(byBuf, byFile);

    fs::remove(path);
}

// ── 2. Hashing an empty file produces the canonical empty-input hash ──────

TEST(FileTransferManager, Blake2b256HandlesEmptyFile) {
    const std::string path = makeTempPath("p2p-ft-empty", ".bin");
    writeFile(path, {});

    const Bytes fromBuf  = FileTransferManager::blake2b256({});
    const Bytes fromFile = FileTransferManager::blake2b256File(path);
    ASSERT_EQ(fromBuf.size(), 32u);
    EXPECT_EQ(fromBuf, fromFile);

    fs::remove(path);
}

// ── 3. Streaming hash covers files larger than the read buffer ────────────
// If the streaming implementation read only the first N KB (classic bug),
// a file past that threshold would still produce a hash — but it'd be the
// wrong one.  Use a file larger than the chunk size to catch that.

TEST(FileTransferManager, Blake2b256HandlesMultiChunkFile) {
    const std::string path = makeTempPath("p2p-ft-big", ".bin");
    const Bytes bytes = randomBytes(size_t(FileTransferManager::kChunkBytes) * 2 + 7);
    writeFile(path, bytes);

    EXPECT_EQ(FileTransferManager::blake2b256(bytes),
              FileTransferManager::blake2b256File(path));

    fs::remove(path);
}

// Shared fixture for the integration tests below: builds a sender FTM whose
// dispatch lambdas capture every inner payload into a vector, and a receiver
// FTM ready to accept announceIncoming() + handleFileEnvelope().  A shared
// partial directory is set so resumption tests can rebuild the receiver on
// top of the same partial file.
class FileTransferRoundTrip : public ::testing::Test {
protected:
    CryptoEngine                       crypto;
    std::unique_ptr<FileTransferManager> sender;
    std::unique_ptr<FileTransferManager> receiver;
    std::string                        partialDir;
    std::string                        srcFile;
    std::string                        senderPeerId = "senderPeer";
    std::string                        receiverPeerId = "receiverPeer";
    std::string                        transferId;

    // Wire capture.
    struct Wire { std::string peerId; Bytes payload; };
    std::vector<Wire> wire;

    // Receiver callback observations.
    std::string  savedPath;
    bool         transferCompletedFired = false;
    std::string  lastStatus;

    void SetUp() override {
        partialDir = makeTempPath("p2p-ft-partial", "");
        fs::create_directories(partialDir);

        sender = std::make_unique<FileTransferManager>(crypto);
        sender->setPartialFileDir(partialDir);
        sender->setSealFn([](const std::string&, const Bytes& inner) {
            // Identity "seal" — the wire-level sealing is tested elsewhere.
            return inner;
        });
        sender->setSendFn([this](const std::string& peer, const Bytes& env) {
            wire.push_back({peer, env});
        });

        receiver = std::make_unique<FileTransferManager>(crypto);
        receiver->setPartialFileDir(partialDir);
        receiver->onFileChunkReceived =
            [this](const std::string&, const std::string&, const std::string&,
                   int64_t, int, int, const std::string& saved, int64_t,
                   const std::string&, const std::string&) {
                if (!saved.empty()) savedPath = saved;
            };
        receiver->onTransferCompleted =
            [this](const std::string&) { transferCompletedFired = true; };
        receiver->onStatus =
            [this](const std::string& s) { lastStatus = s; };

        // Make a unique transferId per test; also used to clean up savedPath.
        uint8_t rnd[8];
        randombytes_buf(rnd, sizeof(rnd));
        char tid[32];
        std::snprintf(tid, sizeof(tid),
                      "xfer-%02x%02x%02x%02x%02x%02x%02x%02x",
                      rnd[0], rnd[1], rnd[2], rnd[3],
                      rnd[4], rnd[5], rnd[6], rnd[7]);
        transferId = tid;
    }

    void TearDown() override {
        sender.reset();
        receiver.reset();
        if (!srcFile.empty()) fs::remove(srcFile);
        cleanupSavedPath(savedPath);
        std::error_code ec;
        fs::remove_all(partialDir, ec);
    }

    // Build a test source file with known bytes and return (path, hash, bytes).
    Bytes prepareSource(size_t sizeBytes) {
        srcFile = makeTempPath("p2p-ft-src", ".bin");
        const Bytes bytes = randomBytes(sizeBytes);
        writeFile(srcFile, bytes);
        return bytes;
    }

    // Drive the sender; returns the outbound transferId.
    std::string runSend(const Bytes& fileKey, const Bytes& fileHash,
                        int64_t fileSize, const std::string& fileName) {
        return sender->sendFileWithKey(
            senderPeerId, receiverPeerId, fileKey,
            transferId, fileName, srcFile, fileSize, fileHash);
    }
};

// ── 4. Full round-trip, chunks delivered in order ─────────────────────────

// ── Sender-side progress: fires once per dispatched chunk ─────────────────
// onFileChunkSent must fire exactly totalChunks times with a monotonically
// increasing chunksSent counter, ending at chunksSent == totalChunks.  This
// is what UIs use to draw a progress bar for files THEY send — inbound
// progress already has onFileChunkReceived coverage above.

TEST_F(FileTransferRoundTrip, SenderSideProgressFiresOncePerChunk) {
    std::vector<std::pair<int, int>> progress; // (sent, total)
    std::string lastTo;
    std::string lastTid;
    sender->onFileChunkSent =
        [&](const std::string& to, const std::string& tid,
            const std::string&, int64_t, int sent, int total,
            int64_t, const std::string&, const std::string&) {
            lastTo  = to;
            lastTid = tid;
            progress.emplace_back(sent, total);
        };

    const Bytes fileKey  = randomBytes(32);
    const Bytes bytes    = prepareSource(size_t(FileTransferManager::kChunkBytes) * 3 + 128);
    const Bytes fileHash = FileTransferManager::blake2b256(bytes);
    const int   totalChunks = int((bytes.size() + FileTransferManager::kChunkBytes - 1)
                                  / FileTransferManager::kChunkBytes);

    ASSERT_EQ(runSend(fileKey, fileHash, int64_t(bytes.size()), "sent-progress.bin"),
              transferId);

    // Exactly one callback per chunk.
    ASSERT_EQ(int(progress.size()), totalChunks);

    // chunksSent runs 1..totalChunks monotonically; chunksTotal is constant.
    for (int i = 0; i < totalChunks; ++i) {
        EXPECT_EQ(progress[i].first,  i + 1);
        EXPECT_EQ(progress[i].second, totalChunks);
    }
    EXPECT_EQ(lastTo,  receiverPeerId);
    EXPECT_EQ(lastTid, transferId);
}

TEST_F(FileTransferRoundTrip, FileRoundTripInOrderReassembles) {
    const Bytes fileKey  = randomBytes(32);
    const Bytes bytes    = prepareSource(size_t(FileTransferManager::kChunkBytes) + 1024);
    const Bytes fileHash = FileTransferManager::blake2b256(bytes);
    const int   totalChunks = int((bytes.size() + FileTransferManager::kChunkBytes - 1)
                                  / FileTransferManager::kChunkBytes);
    const std::string fileName = "hello.bin";

    // Announce before sending (receiver must know the expected hash).
    ASSERT_TRUE(receiver->announceIncoming(
        senderPeerId, transferId, fileName, int64_t(bytes.size()),
        totalChunks, fileHash, fileKey, 0));

    // Run the sender — captures chunks in `wire`.
    ASSERT_EQ(runSend(fileKey, fileHash, int64_t(bytes.size()), fileName), transferId);
    ASSERT_EQ(int(wire.size()), totalChunks);

    // Deliver in order.
    auto markSeen = [](const std::string&) { return true; };
    const std::map<std::string, Bytes> fileKeys = {{senderPeerId, fileKey}};
    for (const auto& w : wire) {
        EXPECT_TRUE(receiver->handleFileEnvelope(w.peerId, w.payload, markSeen, fileKeys));
    }

    EXPECT_TRUE(transferCompletedFired);
    ASSERT_FALSE(savedPath.empty()) << "final savedPath was never set";
    EXPECT_EQ(readFileBytes(savedPath), bytes);
    EXPECT_EQ(FileTransferManager::blake2b256File(savedPath), fileHash);
}

// ── 5. Round-trip with chunks delivered in reverse order ──────────────────
// The receiver writes each chunk at its correct file offset, so the final
// bytes should match regardless of arrival order.  Also confirms the
// hash-on-complete check operates on the full reassembled file rather than
// on an in-memory concat in arrival order.

TEST_F(FileTransferRoundTrip, FileRoundTripOutOfOrderReassembles) {
    const Bytes fileKey  = randomBytes(32);
    const Bytes bytes    = prepareSource(size_t(FileTransferManager::kChunkBytes) * 2 + 37);
    const Bytes fileHash = FileTransferManager::blake2b256(bytes);
    const int   totalChunks = int((bytes.size() + FileTransferManager::kChunkBytes - 1)
                                  / FileTransferManager::kChunkBytes);

    ASSERT_TRUE(receiver->announceIncoming(
        senderPeerId, transferId, "reverse.bin", int64_t(bytes.size()),
        totalChunks, fileHash, fileKey, 0));

    ASSERT_EQ(runSend(fileKey, fileHash, int64_t(bytes.size()), "reverse.bin"), transferId);
    ASSERT_EQ(int(wire.size()), totalChunks);

    auto markSeen = [](const std::string&) { return true; };
    const std::map<std::string, Bytes> fileKeys = {{senderPeerId, fileKey}};
    std::reverse(wire.begin(), wire.end());
    for (const auto& w : wire) {
        EXPECT_TRUE(receiver->handleFileEnvelope(w.peerId, w.payload, markSeen, fileKeys));
    }

    EXPECT_TRUE(transferCompletedFired);
    ASSERT_FALSE(savedPath.empty());
    EXPECT_EQ(readFileBytes(savedPath), bytes);
}

// ── 6. Hash mismatch: receiver discards the file rather than saving it ────
// Two integrity layers exist:
//   (a) chunk-metadata check — drops any chunk whose meta.fileHash doesn't
//       match the announced hash (catches a rogue sender reusing chunks
//       from a different transfer).
//   (b) reassembly check — after all chunks are on disk, re-hashes the
//       full file and aborts if it doesn't match the announced hash.
//
// This test targets layer (b): announce + sender-metadata agree on a
// WRONG hash, so chunks pass (a) but the reassembled file hashes to the
// *real* value and the announce doesn't match.  The partial file must be
// removed and savedPath reported empty.

TEST_F(FileTransferRoundTrip, HashMismatchDiscardsFile) {
    const Bytes fileKey = randomBytes(32);
    const Bytes bytes   = prepareSource(size_t(FileTransferManager::kChunkBytes) + 100);

    // Use a wrong-but-self-consistent hash so chunk-metadata still matches
    // the announce — we want the *final reassembly* check to trip.
    Bytes wrongHash(32);
    randombytes_buf(wrongHash.data(), wrongHash.size());

    const int totalChunks = int((bytes.size() + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);

    ASSERT_TRUE(receiver->announceIncoming(
        senderPeerId, transferId, "tampered.bin", int64_t(bytes.size()),
        totalChunks, wrongHash, fileKey, 0));

    // Sender also uses wrongHash so chunk meta agrees with the announce.
    ASSERT_EQ(runSend(fileKey, wrongHash, int64_t(bytes.size()), "tampered.bin"), transferId);

    auto markSeen = [](const std::string&) { return true; };
    const std::map<std::string, Bytes> fileKeys = {{senderPeerId, fileKey}};
    for (const auto& w : wire) {
        EXPECT_TRUE(receiver->handleFileEnvelope(w.peerId, w.payload, markSeen, fileKeys));
    }

    EXPECT_TRUE(transferCompletedFired) << "transfer should still fire 'completed' to clean up";
    EXPECT_TRUE(savedPath.empty()) << "savedPath must be empty after a hash mismatch";
    EXPECT_NE(lastStatus.find("integrity check FAILED"), std::string::npos)
        << "onStatus should flag integrity failure; got: " << lastStatus;
}

// ── 7. Partial-transfer persistence enables resumption after restart ──────
// Feed some (but not all) chunks through a receiver with a DB attached.
// Destroy the receiver, rebuild it on the same DB + partial dir, call
// loadPersistedTransfers(), and verify pendingResumptions() reports the
// right transferId + missing chunk indices.

TEST_F(FileTransferRoundTrip, ResumptionListsMissingChunksAfterRestart) {
    const Bytes fileKey = randomBytes(32);
    const Bytes bytes   = prepareSource(size_t(FileTransferManager::kChunkBytes) * 3);
    const Bytes fileHash = FileTransferManager::blake2b256(bytes);
    const int totalChunks = int((bytes.size() + FileTransferManager::kChunkBytes - 1)
                                / FileTransferManager::kChunkBytes);
    ASSERT_EQ(totalChunks, 3);

    // Attach a fresh DB to the receiver so the partial transfer persists.
    const std::string dbPath = makeTempPath("p2p-ft-resume", ".db");
    SqlCipherDb db;
    SqlCipherDb::Bytes dbKey(32);
    randombytes_buf(dbKey.data(), dbKey.size());
    ASSERT_TRUE(db.open(dbPath, dbKey)) << db.lastError();
    receiver->setDatabase(&db);

    ASSERT_TRUE(receiver->announceIncoming(
        senderPeerId, transferId, "resumable.bin", int64_t(bytes.size()),
        totalChunks, fileHash, fileKey, 0));

    ASSERT_EQ(runSend(fileKey, fileHash, int64_t(bytes.size()), "resumable.bin"), transferId);
    ASSERT_EQ(int(wire.size()), 3);

    // Deliver only chunks 0 and 2 — leave 1 missing.
    auto markSeen = [](const std::string&) { return true; };
    const std::map<std::string, Bytes> fileKeys = {{senderPeerId, fileKey}};
    EXPECT_TRUE(receiver->handleFileEnvelope(wire[0].peerId, wire[0].payload, markSeen, fileKeys));
    EXPECT_TRUE(receiver->handleFileEnvelope(wire[2].peerId, wire[2].payload, markSeen, fileKeys));
    EXPECT_FALSE(transferCompletedFired);  // still waiting on chunk 1

    // Simulate a restart: throw away the receiver, build a new one on the
    // same DB + partial dir.
    receiver.reset();

    auto fresh = std::make_unique<FileTransferManager>(crypto);
    fresh->setPartialFileDir(partialDir);
    fresh->setDatabase(&db);
    fresh->loadPersistedTransfers();

    const auto pending = fresh->pendingResumptions();
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].transferId, transferId);
    EXPECT_EQ(pending[0].peerId, senderPeerId);
    ASSERT_EQ(pending[0].missingChunks.size(), 1u);
    EXPECT_EQ(pending[0].missingChunks[0], 1u);

    // Ownership of cleanup: swap back so TearDown tears down the active receiver.
    receiver = std::move(fresh);
    db.close();
    fs::remove(dbPath);
}

// ── 8. announceIncoming() rejects nonsense metadata ───────────────────────

TEST_F(FileTransferRoundTrip, AnnounceRejectsInvalidArgs) {
    const Bytes fileKey  = randomBytes(32);
    const Bytes fileHash = randomBytes(32);
    constexpr int64_t kFileSize = 1024;
    // Correct totalChunks for 1024 B with kChunkBytes-sized chunks = 1.

    // Wrong totalChunks for the claimed size.
    EXPECT_FALSE(receiver->announceIncoming(
        senderPeerId, transferId, "bad.bin", kFileSize,
        /*totalChunks=*/999, fileHash, fileKey, 0));

    // Wrong file-hash length.
    EXPECT_FALSE(receiver->announceIncoming(
        senderPeerId, transferId, "bad.bin", kFileSize,
        /*totalChunks=*/1, Bytes(16, 0), fileKey, 0));

    // Wrong file-key length.
    EXPECT_FALSE(receiver->announceIncoming(
        senderPeerId, transferId, "bad.bin", kFileSize,
        /*totalChunks=*/1, fileHash, Bytes(10, 0), 0));

    // Zero-byte file.
    EXPECT_FALSE(receiver->announceIncoming(
        senderPeerId, transferId, "empty.bin", /*fileSize=*/0,
        /*totalChunks=*/0, fileHash, fileKey, 0));

    // File beyond the size cap.
    EXPECT_FALSE(receiver->announceIncoming(
        senderPeerId, transferId, "huge.bin",
        FileTransferManager::kMaxFileBytes + 1,
        /*totalChunks=*/1, fileHash, fileKey, 0));
}
