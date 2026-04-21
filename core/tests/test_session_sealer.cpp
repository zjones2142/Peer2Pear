// test_session_sealer.cpp — tests for SessionSealer.
//
// SessionSealer is the single choke point for outbound sealing + safety-
// number enforcement.  This suite exercises the pieces that DON'T require
// a live peer session:
//   - trust-state transitions (Unverified / Verified / Mismatch)
//   - the mutable fingerprint cache's invalidation on DB writes
//   - detectKeyChange's once-per-session callback guard + reset on
//     markPeerVerified
//   - safetyNumber() format sanity + invalid-input handling
//   - KEM-pub store (size validation + in-memory lookup)
//   - hasAnnouncedKemPubTo / markKemPubAnnouncedTo session guard
//
// The sealForPeer round-trip (Noise IK + SealedEnvelope) is covered by
// test_e2e_two_clients.cpp; trying to unit-test it would duplicate the
// whole session stack.
//
// Identity bootstrap (~1.3 s of Argon2) happens once via SetUpTestSuite.

#include "SessionSealer.hpp"

#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace {

using p2p_test::makeTempDir;
using p2p_test::makeTempPath;
using Bytes = SessionSealer::Bytes;

SqlCipherDb::Bytes randomKey32() {
    SqlCipherDb::Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

// Overwrite the verified_fingerprint blob in-place so the next trust
// check sees a stored-vs-current mismatch.  Callers must clearPeerKeyCache()
// on the SessionSealer afterwards — the cache memoizes across DB reads.
void corruptStoredFingerprint(SqlCipherDb& db, const std::string& peerIdB64u) {
    SqlCipherQuery q(db);
    ASSERT_TRUE(q.prepare(
        "UPDATE verified_peers SET verified_fingerprint=:fp WHERE peer_id=:pid;"));
    Bytes garbage(32, 0xAA);
    q.bindValue(":fp",  garbage);
    q.bindValue(":pid", peerIdB64u);
    ASSERT_TRUE(q.exec());
}

}  // namespace

class SessionSealerSuite : public ::testing::Test {
protected:
    // Identities + a second "peer" identity live across the whole suite.
    static std::string                   s_meDir;
    static std::string                   s_peerDir;
    static std::unique_ptr<CryptoEngine> s_meCrypto;
    static std::unique_ptr<CryptoEngine> s_peerCrypto;
    static std::string                   s_peerIdB64u;

    static void SetUpTestSuite() {
        ASSERT_GE(sodium_init(), 0);

        s_meDir   = makeTempDir("p2p-sealer-me-id");
        s_peerDir = makeTempDir("p2p-sealer-peer-id");

        s_meCrypto = std::make_unique<CryptoEngine>();
        s_meCrypto->setDataDir(s_meDir);
        s_meCrypto->setPassphrase("sealer-test-me");
        ASSERT_NO_THROW(s_meCrypto->ensureIdentity());

        s_peerCrypto = std::make_unique<CryptoEngine>();
        s_peerCrypto->setDataDir(s_peerDir);
        s_peerCrypto->setPassphrase("sealer-test-peer");
        ASSERT_NO_THROW(s_peerCrypto->ensureIdentity());

        s_peerIdB64u = CryptoEngine::toBase64Url(s_peerCrypto->identityPub());
    }

    static void TearDownTestSuite() {
        s_meCrypto.reset();
        s_peerCrypto.reset();
        std::error_code ec;
        std::filesystem::remove_all(s_meDir,   ec);
        std::filesystem::remove_all(s_peerDir, ec);
    }

    // Per-test DB + sealer.  Fresh for every case.
    void SetUp() override {
        m_dbPath = makeTempPath("p2p-sealer-db", ".db");
        m_db = std::make_unique<SqlCipherDb>();
        ASSERT_TRUE(m_db->open(m_dbPath, randomKey32()));

        // Need a contacts table for saveKemPub / lookupPeerKemPub.  The
        // full schema lives in SessionStore; here we create just the
        // single column SessionSealer touches.
        SqlCipherQuery q(*m_db);
        ASSERT_TRUE(q.exec(
            "CREATE TABLE IF NOT EXISTS contacts ("
            "  peer_id TEXT PRIMARY KEY,"
            "  kem_pub BLOB"
            ");"));
        // Insert a row for the test peer so UPDATE kem_pub has a target.
        SqlCipherQuery ins(*m_db);
        ASSERT_TRUE(ins.prepare(
            "INSERT OR IGNORE INTO contacts (peer_id) VALUES (:pid);"));
        ins.bindValue(":pid", s_peerIdB64u);
        ASSERT_TRUE(ins.exec());

        m_sealer = std::make_unique<SessionSealer>(*s_meCrypto);
        m_sealer->setDatabase(m_db.get());
    }

    void TearDown() override {
        m_sealer.reset();
        m_db.reset();
        std::error_code ec;
        std::filesystem::remove(m_dbPath, ec);
    }

    std::string                    m_dbPath;
    std::unique_ptr<SqlCipherDb>   m_db;
    std::unique_ptr<SessionSealer> m_sealer;
};

std::string                   SessionSealerSuite::s_meDir;
std::string                   SessionSealerSuite::s_peerDir;
std::unique_ptr<CryptoEngine> SessionSealerSuite::s_meCrypto;
std::unique_ptr<CryptoEngine> SessionSealerSuite::s_peerCrypto;
std::string                   SessionSealerSuite::s_peerIdB64u;

// ── 1. Trust-state transitions ───────────────────────────────────────────────

TEST_F(SessionSealerSuite, PeerTrust_DefaultsToUnverified) {
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);
}

TEST_F(SessionSealerSuite, MarkPeerVerified_FlipsTrustToVerified) {
    EXPECT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Verified);
}

TEST_F(SessionSealerSuite, UnverifyPeer_RevertsToUnverified) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    m_sealer->unverifyPeer(s_peerIdB64u);
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);
}

TEST_F(SessionSealerSuite, MarkPeerVerified_RejectsInvalidPeerId) {
    EXPECT_FALSE(m_sealer->markPeerVerified("not-base64url!"));
    EXPECT_FALSE(m_sealer->markPeerVerified(""));
}

TEST_F(SessionSealerSuite, PeerTrust_InvalidPeerIdReportsUnverified) {
    // Any peerId that doesn't decode to 32 bytes Ed25519 cannot be
    // classified as Verified or Mismatch — peerTrust collapses to
    // Unverified rather than surfacing "invalid".
    EXPECT_EQ(m_sealer->peerTrust("x"),
              SessionSealer::PeerTrust::Unverified);
    EXPECT_EQ(m_sealer->peerTrust(""),
              SessionSealer::PeerTrust::Unverified);
}

// ── 2. Fingerprint cache invalidation ────────────────────────────────────────

TEST_F(SessionSealerSuite, Cache_ReflectsExternalDBWriteAfterClear) {
    // Read-through populates the cache as Unverified first.
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);

    // Write verified_peers directly via SQL (bypassing markPeerVerified),
    // then prove the cache DOESN'T notice without an explicit clear.
    SqlCipherQuery q(*m_db);
    ASSERT_TRUE(q.prepare(
        "INSERT INTO verified_peers (peer_id, verified_at, verified_fingerprint)"
        " VALUES (:pid, :at, :fp);"));
    // Pre-compute the *correct* fingerprint so the trust check sees
    // stored == current → Verified.  Pulling via safetyFingerprint keeps
    // us in lockstep with SessionSealer's internal derivation.
    const Bytes correctFp = CryptoEngine::safetyFingerprint(
        s_meCrypto->identityPub(), s_peerCrypto->identityPub());
    q.bindValue(":pid", s_peerIdB64u);
    q.bindValue(":at",  int64_t(1000));
    q.bindValue(":fp",  correctFp);
    ASSERT_TRUE(q.exec());

    // Before clear: stale cached entry still reports Unverified.
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);

    // After clear: fresh DB read picks up the row → Verified.
    m_sealer->clearPeerKeyCache();
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Verified);
}

TEST_F(SessionSealerSuite, Cache_InvalidatedByMarkVerified) {
    // Populate the cache as Unverified, then mark verified through the
    // normal API.  No manual cache clear — saveVerifiedFingerprint must
    // drop the stale entry itself.
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Verified);
}

TEST_F(SessionSealerSuite, Cache_InvalidatedByUnverify) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Verified);
    m_sealer->unverifyPeer(s_peerIdB64u);
    // A stale Verified cache entry after unverify would be a security
    // regression — that direction silently upgrades trust the user
    // explicitly revoked.
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Unverified);
}

// ── 3. detectKeyChange + once-per-session guard ──────────────────────────────

TEST_F(SessionSealerSuite, DetectKeyChange_NoopWhenUnverified) {
    EXPECT_FALSE(m_sealer->detectKeyChange(s_peerIdB64u));
}

TEST_F(SessionSealerSuite, DetectKeyChange_NoopWhenVerifiedAndMatching) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    EXPECT_FALSE(m_sealer->detectKeyChange(s_peerIdB64u));
}

TEST_F(SessionSealerSuite, DetectKeyChange_FiresOnceOnMismatch) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));

    // Simulate tampering: overwrite the stored fingerprint out-of-band.
    corruptStoredFingerprint(*m_db, s_peerIdB64u);
    m_sealer->clearPeerKeyCache();

    int fireCount = 0;
    std::string capturedPeer;
    m_sealer->onPeerKeyChanged =
        [&](const std::string& pid, const Bytes&, const Bytes&) {
            ++fireCount;
            capturedPeer = pid;
        };

    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));

    // The callback carries user-visible noise, so it MUST fire exactly
    // once per session per peer even when the mismatch is polled repeatedly.
    EXPECT_EQ(fireCount, 1);
    EXPECT_EQ(capturedPeer, s_peerIdB64u);
    EXPECT_EQ(m_sealer->peerTrust(s_peerIdB64u),
              SessionSealer::PeerTrust::Mismatch);
}

TEST_F(SessionSealerSuite, DetectKeyChange_ReArmedByMarkPeerVerified) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    corruptStoredFingerprint(*m_db, s_peerIdB64u);
    m_sealer->clearPeerKeyCache();

    int fireCount = 0;
    m_sealer->onPeerKeyChanged =
        [&](const std::string&, const Bytes&, const Bytes&) { ++fireCount; };

    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_EQ(fireCount, 1);

    // User re-verifies → stored now matches current → warning armed again.
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    EXPECT_FALSE(m_sealer->detectKeyChange(s_peerIdB64u));

    // Now simulate *another* key change.  Because markPeerVerified cleared
    // m_keyChangeWarned, the callback should fire a second time.
    corruptStoredFingerprint(*m_db, s_peerIdB64u);
    m_sealer->clearPeerKeyCache();
    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_EQ(fireCount, 2);
}

TEST_F(SessionSealerSuite, DetectKeyChange_ReArmedByUnverify) {
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    corruptStoredFingerprint(*m_db, s_peerIdB64u);
    m_sealer->clearPeerKeyCache();

    int fireCount = 0;
    m_sealer->onPeerKeyChanged =
        [&](const std::string&, const Bytes&, const Bytes&) { ++fireCount; };

    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_EQ(fireCount, 1);

    // unverify should also clear the session guard; otherwise a user who
    // un-verifies and re-verifies the same peer would never see a future
    // mismatch warning.
    m_sealer->unverifyPeer(s_peerIdB64u);
    ASSERT_TRUE(m_sealer->markPeerVerified(s_peerIdB64u));
    corruptStoredFingerprint(*m_db, s_peerIdB64u);
    m_sealer->clearPeerKeyCache();
    EXPECT_TRUE(m_sealer->detectKeyChange(s_peerIdB64u));
    EXPECT_EQ(fireCount, 2);
}

// ── 4. Hard-block toggle ─────────────────────────────────────────────────────

TEST_F(SessionSealerSuite, HardBlock_DefaultsOff) {
    EXPECT_FALSE(m_sealer->hardBlockOnKeyChange());
}

TEST_F(SessionSealerSuite, HardBlock_ToggleRoundtrips) {
    m_sealer->setHardBlockOnKeyChange(true);
    EXPECT_TRUE(m_sealer->hardBlockOnKeyChange());
    m_sealer->setHardBlockOnKeyChange(false);
    EXPECT_FALSE(m_sealer->hardBlockOnKeyChange());
}

// ── 5. Safety-number display string ──────────────────────────────────────────

TEST_F(SessionSealerSuite, SafetyNumber_SixtyDigitsForValidPeer) {
    const std::string sn = m_sealer->safetyNumber(s_peerIdB64u);
    // 12 groups of 5 digits separated by 11 single spaces = 71 chars total.
    EXPECT_EQ(sn.size(), 71U);

    // Digit / space layout check.
    int digits = 0, spaces = 0;
    for (char c : sn) {
        if (c == ' ') ++spaces;
        else {
            ASSERT_GE(c, '0');
            ASSERT_LE(c, '9');
            ++digits;
        }
    }
    EXPECT_EQ(digits, 60);
    EXPECT_EQ(spaces, 11);
}

TEST_F(SessionSealerSuite, SafetyNumber_SymmetricAcrossParties) {
    // Safety numbers must be identical on both sides — the input to BLAKE2b
    // is sorted so neither party depends on who's "us".
    const std::string myView = m_sealer->safetyNumber(s_peerIdB64u);

    SessionSealer peerSealer(*s_peerCrypto);
    // No DB needed — safetyNumber is a pure function of the two pubs.
    const std::string peerView = peerSealer.safetyNumber(
        CryptoEngine::toBase64Url(s_meCrypto->identityPub()));

    EXPECT_EQ(myView, peerView);
    EXPECT_FALSE(myView.empty());
}

TEST_F(SessionSealerSuite, SafetyNumber_EmptyForInvalidPeerId) {
    EXPECT_TRUE(m_sealer->safetyNumber("not-a-peer").empty());
    EXPECT_TRUE(m_sealer->safetyNumber("").empty());
}

// ── 6. KEM pub store ─────────────────────────────────────────────────────────

TEST_F(SessionSealerSuite, KemPub_LookupMissingReturnsEmpty) {
    EXPECT_TRUE(m_sealer->lookupPeerKemPub(s_peerIdB64u).empty());
}

TEST_F(SessionSealerSuite, KemPub_SaveThenLookupRoundtrips) {
    Bytes kemPub(1184, 0x42);  // ML-KEM-768 pub size
    m_sealer->saveKemPub(s_peerIdB64u, kemPub);
    Bytes got = m_sealer->lookupPeerKemPub(s_peerIdB64u);
    EXPECT_EQ(got, kemPub);
}

TEST_F(SessionSealerSuite, KemPub_RejectsWrongSize) {
    // Undersized + oversized blobs must be dropped.  A real peer will
    // always send 1184 bytes; accepting anything else risks mixing a
    // malformed blob into the Noise handshake.
    m_sealer->saveKemPub(s_peerIdB64u, Bytes(100, 0x01));
    EXPECT_TRUE(m_sealer->lookupPeerKemPub(s_peerIdB64u).empty());

    m_sealer->saveKemPub(s_peerIdB64u, Bytes(2000, 0x02));
    EXPECT_TRUE(m_sealer->lookupPeerKemPub(s_peerIdB64u).empty());
}

TEST_F(SessionSealerSuite, KemPub_SurvivesFreshSealerInstance) {
    Bytes kemPub(1184, 0x37);
    m_sealer->saveKemPub(s_peerIdB64u, kemPub);

    // Drop the sealer + its in-memory m_peerKemPubs cache.  A new sealer
    // with the same DB should still find the pub (it's in contacts.kem_pub).
    m_sealer.reset();
    SessionSealer fresh(*s_meCrypto);
    fresh.setDatabase(m_db.get());
    EXPECT_EQ(fresh.lookupPeerKemPub(s_peerIdB64u), kemPub);
}

// ── 7. Announce-once KEM-pub guard ───────────────────────────────────────────

TEST_F(SessionSealerSuite, KemPubAnnounced_DefaultsFalse) {
    EXPECT_FALSE(m_sealer->hasAnnouncedKemPubTo(s_peerIdB64u));
}

TEST_F(SessionSealerSuite, KemPubAnnounced_SetAndReadBack) {
    m_sealer->markKemPubAnnouncedTo(s_peerIdB64u);
    EXPECT_TRUE(m_sealer->hasAnnouncedKemPubTo(s_peerIdB64u));

    // Independent peer — should still be unflagged.
    EXPECT_FALSE(m_sealer->hasAnnouncedKemPubTo("other-peer-id"));
}

TEST_F(SessionSealerSuite, KemPubAnnounced_ResetsOnFreshInstance) {
    // The guard is in-memory only (not persisted): a new session must
    // re-announce so a peer that reinstalled learns our current KEM pub.
    m_sealer->markKemPubAnnouncedTo(s_peerIdB64u);
    m_sealer.reset();

    SessionSealer fresh(*s_meCrypto);
    fresh.setDatabase(m_db.get());
    EXPECT_FALSE(fresh.hasAnnouncedKemPubTo(s_peerIdB64u));
}

// ── 8. sealForPeer input validation ──────────────────────────────────────────

TEST_F(SessionSealerSuite, SealForPeer_EmptyWithoutSessionManager) {
    // No m_sessionMgr wired → must return empty, not crash.
    Bytes pt = {1, 2, 3};
    EXPECT_TRUE(m_sealer->sealForPeer(s_peerIdB64u, pt).empty());
}
