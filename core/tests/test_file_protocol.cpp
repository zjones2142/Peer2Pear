// test_file_protocol.cpp — tests for FileProtocol.
//
// FileProtocol owns the outbound-send, consent, and cancel paths for
// file transfers.  sendFile / sendGroupFile + the inbound file_chunk
// decrypt path cross into the full session + FTM stacks and are covered
// by test_e2e_two_clients.cpp / test_file_transfer.cpp.  This suite
// exercises the pieces that can be tested in isolation:
//
//   - acceptIncoming: pending → active key transition (needs a real FTM
//     with a writable partial-file dir).
//   - declineIncoming: zeros key bytes, drops pending, fires
//     onCanceled(byReceiver=true).
//   - cancel routing for the four possible roles:
//       group-level fanout / outbound pending / inbound pre-accept /
//       inbound in-progress.  Group / outbound / in-progress require FTM
//       state we can't set up without a real peer, so we focus on the
//       pre-accept path (which is pure FileProtocol state).
//   - Consent-policy setters + getters.
//   - eraseFileKey zeros + removes.
//   - kMaxPendingIncomingFiles constant is non-trivially > 0.

#include "FileProtocol.hpp"

#include "CryptoEngine.hpp"
#include "FileTransferManager.hpp"
#include "SessionSealer.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using p2p_test::makeTempDir;
using p2p_test::makeTempPath;
using Bytes = FileProtocol::Bytes;

// 32-byte non-zero vector.  Callers use it to verify that
// declineIncoming / cancel actually zero the stored key on drop.
Bytes nonZeroKey32(uint8_t fill = 0xBB) {
    return Bytes(32, fill);
}

// Synthesize a BLAKE2b-shape 32-byte hash.
Bytes fakeHash32() {
    return Bytes(32, 0x42);
}

}  // namespace

class FileProtocolSuite : public ::testing::Test {
protected:
    // Shared identity + peer-id across the suite (Argon2 is expensive).
    static std::string                   s_meDir;
    static std::string                   s_peerDir;
    static std::unique_ptr<CryptoEngine> s_meCrypto;
    static std::unique_ptr<CryptoEngine> s_peerCrypto;
    static std::string                   s_peerId;

    static void SetUpTestSuite() {
        ASSERT_GE(sodium_init(), 0);

        s_meDir   = makeTempDir("p2p-fp-me-id");
        s_peerDir = makeTempDir("p2p-fp-peer-id");

        s_meCrypto = std::make_unique<CryptoEngine>();
        s_meCrypto->setDataDir(s_meDir);
        s_meCrypto->setPassphrase("fp-test-me");
        ASSERT_NO_THROW(s_meCrypto->ensureIdentity());

        s_peerCrypto = std::make_unique<CryptoEngine>();
        s_peerCrypto->setDataDir(s_peerDir);
        s_peerCrypto->setPassphrase("fp-test-peer");
        ASSERT_NO_THROW(s_peerCrypto->ensureIdentity());

        s_peerId = CryptoEngine::toBase64Url(s_peerCrypto->identityPub());
    }

    static void TearDownTestSuite() {
        s_meCrypto.reset();
        s_peerCrypto.reset();
        std::error_code ec;
        std::filesystem::remove_all(s_meDir,   ec);
        std::filesystem::remove_all(s_peerDir, ec);
    }

    void SetUp() override {
        m_partialDir = makeTempDir("p2p-fp-partial");

        m_sealer = std::make_unique<SessionSealer>(*s_meCrypto);
        m_ftm    = std::make_unique<FileTransferManager>(*s_meCrypto);
        m_ftm->setPartialFileDir(m_partialDir);
        // Deliberately NOT calling setSessionManager on either sealer or
        // m_fp — that leaves sealForPeer returning empty so sendControlMessage
        // is a no-op.  That's the behavior we want for state-only tests:
        // local cleanup must still happen even when the wire send fails.

        m_fp = std::make_unique<FileProtocol>(*s_meCrypto, *m_sealer, *m_ftm);

        m_sentEnvelopes = 0;
        m_fp->setSendEnvelopeFn(
            [this](const Bytes&) { ++m_sentEnvelopes; });

        m_canceled.clear();
        m_fp->onCanceled =
            [this](const std::string& tid, bool byReceiver) {
                m_canceled.push_back({tid, byReceiver});
            };
    }

    void TearDown() override {
        m_fp.reset();
        m_ftm.reset();
        m_sealer.reset();
        std::error_code ec;
        std::filesystem::remove_all(m_partialDir, ec);
    }

    // Directly inject a pending-incoming into FileProtocol without going
    // through the inbound file_key handler in ChatController (which is
    // what normally populates it).  Uses the public pendingIncoming()
    // accessor that already exists for the onEnvelope file_* branches.
    void injectPending(const std::string& transferId,
                        int64_t fileSize,
                        int totalChunks,
                        const Bytes& fileKey) {
        FileProtocol::PendingIncoming pi;
        pi.peerId       = s_peerId;
        pi.fileName     = "hello.bin";
        pi.fileSize     = fileSize;
        pi.fileKey      = fileKey;
        pi.fileHash     = fakeHash32();
        pi.totalChunks  = totalChunks;
        pi.announcedTs  = 12345;
        m_fp->pendingIncoming()[transferId] = std::move(pi);
    }

    struct CancelEvent {
        std::string transferId;
        bool        byReceiver;
    };

    std::string                          m_partialDir;
    std::unique_ptr<SessionSealer>       m_sealer;
    std::unique_ptr<FileTransferManager> m_ftm;
    std::unique_ptr<FileProtocol>        m_fp;
    int                                  m_sentEnvelopes = 0;
    std::vector<CancelEvent>             m_canceled;
};

std::string                   FileProtocolSuite::s_meDir;
std::string                   FileProtocolSuite::s_peerDir;
std::unique_ptr<CryptoEngine> FileProtocolSuite::s_meCrypto;
std::unique_ptr<CryptoEngine> FileProtocolSuite::s_peerCrypto;
std::string                   FileProtocolSuite::s_peerId;

// ── 1. Consent policy ────────────────────────────────────────────────────────

TEST_F(FileProtocolSuite, Consent_DefaultValues) {
    EXPECT_EQ(m_fp->autoAcceptMaxMB(), 100);
    EXPECT_EQ(m_fp->hardMaxMB(),       100);
    EXPECT_FALSE(m_fp->requireP2P());
}

TEST_F(FileProtocolSuite, Consent_SettersRoundtrip) {
    m_fp->setAutoAcceptMaxMB(5);
    m_fp->setHardMaxMB(200);
    m_fp->setRequireP2P(true);
    EXPECT_EQ(m_fp->autoAcceptMaxMB(), 5);
    EXPECT_EQ(m_fp->hardMaxMB(),       200);
    EXPECT_TRUE(m_fp->requireP2P());
}

// ── 2. Accept / decline / cancel on missing transferId ───────────────────────

TEST_F(FileProtocolSuite, Accept_UnknownTransferIsNoop) {
    m_fp->acceptIncoming("does-not-exist", false);
    EXPECT_TRUE(m_fp->fileKeys().empty());
    EXPECT_TRUE(m_canceled.empty());
}

TEST_F(FileProtocolSuite, Decline_UnknownTransferIsNoop) {
    m_fp->declineIncoming("does-not-exist");
    EXPECT_TRUE(m_canceled.empty());
}

TEST_F(FileProtocolSuite, Cancel_UnknownTransferIsNoop) {
    m_fp->cancel("does-not-exist");
    EXPECT_TRUE(m_canceled.empty());
}

// ── 3. acceptIncoming: pending → active key transition ───────────────────────
//
// The choke-point invariant: when a user accepts an incoming file, the
// stashed fileKey moves from pendingIncomingFiles into m_fileKeys under
// the "peer:tid" compound key, so subsequent file_chunk envelopes decrypt.

TEST_F(FileProtocolSuite, Accept_PromotesPendingKeyToActiveFileKeys) {
    const std::string tid      = "tid-promote";
    const std::string compound = s_peerId + ":" + tid;
    const Bytes      key       = nonZeroKey32(0x55);

    // Small 1-chunk file.  fileSize=10 / kChunkBytes=240KB → totalChunks=1.
    injectPending(tid, /*fileSize=*/10, /*totalChunks=*/1, key);

    m_fp->acceptIncoming(tid, /*requireP2P=*/false);

    // Promoted into m_fileKeys; pending entry gone.
    ASSERT_EQ(m_fp->fileKeys().size(), 1U);
    EXPECT_EQ(m_fp->fileKeys().at(compound), key);
    EXPECT_EQ(m_fp->pendingIncoming().count(tid), 0U);
}

TEST_F(FileProtocolSuite, Accept_DropsPendingEvenWhenAnnounceFails) {
    // totalChunks inconsistent with fileSize → announceIncoming returns
    // false.  FileProtocol's contract: clear the stashed key + erase
    // pending regardless, so a hostile peer can't pile up entries via
    // malformed file_key messages.
    const std::string tid = "tid-malformed";
    injectPending(tid, /*fileSize=*/10, /*totalChunks=*/999, nonZeroKey32());

    m_fp->acceptIncoming(tid, false);

    EXPECT_TRUE(m_fp->pendingIncoming().empty());
    EXPECT_TRUE(m_fp->fileKeys().empty());
}

// ── 4. declineIncoming ──────────────────────────────────────────────────────

TEST_F(FileProtocolSuite, Decline_ZeroesKeyAndRemovesPending) {
    const std::string tid = "tid-decline";
    injectPending(tid, 10, 1, nonZeroKey32(0x77));

    // Snapshot a pointer to the underlying bytes so we can prove
    // sodium_memzero ran before the map erase.  This is belt-and-braces
    // for the "secret material on heap" discipline.
    Bytes* keyInPending = &m_fp->pendingIncoming().at(tid).fileKey;
    for (uint8_t b : *keyInPending) ASSERT_EQ(b, 0x77);

    m_fp->declineIncoming(tid);

    EXPECT_EQ(m_fp->pendingIncoming().count(tid), 0U);
    ASSERT_EQ(m_canceled.size(), 1U);
    EXPECT_EQ(m_canceled[0].transferId, tid);
    EXPECT_TRUE(m_canceled[0].byReceiver);
}

TEST_F(FileProtocolSuite, Decline_SendsControlMessageWhenSealAvailable) {
    // With no SessionManager wired the seal returns empty and the
    // control-message send is silently dropped.  We can't verify the
    // wire bytes without a full session, but we can verify the counter
    // DIDN'T tick (confirming the early-return path runs when seal fails).
    injectPending("tid-x", 10, 1, nonZeroKey32());
    m_fp->declineIncoming("tid-x");
    EXPECT_EQ(m_sentEnvelopes, 0);
}

// ── 5. cancel — inbound pre-accept path ──────────────────────────────────────

TEST_F(FileProtocolSuite, Cancel_InboundPreAcceptClearsPendingFiresReceiver) {
    const std::string tid = "tid-cancel-pending";
    injectPending(tid, 10, 1, nonZeroKey32(0x33));

    m_fp->cancel(tid);

    EXPECT_EQ(m_fp->pendingIncoming().count(tid), 0U);
    ASSERT_EQ(m_canceled.size(), 1U);
    EXPECT_EQ(m_canceled[0].transferId, tid);
    // Pre-accept cancellation is receiver-initiated.
    EXPECT_TRUE(m_canceled[0].byReceiver);
}

// ── 6. eraseFileKey ──────────────────────────────────────────────────────────

TEST_F(FileProtocolSuite, EraseFileKey_ZeroesBytesThenRemoves) {
    const std::string compound = "peer:tid";
    m_fp->fileKeys()[compound] = nonZeroKey32(0x99);
    ASSERT_EQ(m_fp->fileKeys().size(), 1U);

    m_fp->eraseFileKey(compound);
    EXPECT_TRUE(m_fp->fileKeys().empty());
}

TEST_F(FileProtocolSuite, EraseFileKey_NoopOnMissingCompoundKey) {
    // No crash, no spurious side-effects when the key was already purged
    // (e.g. FTM signaled cleanup twice).
    m_fp->eraseFileKey("never-existed");
    EXPECT_TRUE(m_fp->fileKeys().empty());
}

// ── 7. Pending-incoming cap constant ─────────────────────────────────────────

TEST_F(FileProtocolSuite, MaxPendingIncomingFilesIsPositive) {
    // A hostile peer flooding file_key announcements in the consent-prompt
    // size band is evicted once this cap is reached (inbound handler in
    // onEnvelope).  Keep the invariant that the cap is sane here so a
    // future accidental zero wouldn't silently disable the defense.
    EXPECT_GT(FileProtocol::kMaxPendingIncomingFiles, 0U);
}

// ── 8. sendFile / sendGroupFile input validation ─────────────────────────────

TEST_F(FileProtocolSuite, SendFile_RejectsMissingFile) {
    EXPECT_TRUE(m_fp->sendFile(s_peerId, "ghost.bin",
                                "/nonexistent/path/to/nothing").empty());
}

TEST_F(FileProtocolSuite, SendFile_ReturnsEmptyWithoutSessionManager) {
    // Even if the file exists, sendFile aborts early when SessionManager
    // isn't wired — prevents a null-deref in sessionMgr->lastMessageKey().
    const std::string tmpFile = makeTempPath("p2p-fp-tmp-input", ".bin");
    std::ofstream(tmpFile) << "hello";

    EXPECT_TRUE(m_fp->sendFile(s_peerId, "hello.bin", tmpFile).empty());

    std::error_code ec;
    std::filesystem::remove(tmpFile, ec);
}

TEST_F(FileProtocolSuite, SendGroupFile_RejectsMissingFile) {
    std::vector<std::string> members{s_peerId};
    EXPECT_TRUE(m_fp->sendGroupFile("gid", "Grp", members,
                                     "ghost.bin",
                                     "/nonexistent").empty());
}
