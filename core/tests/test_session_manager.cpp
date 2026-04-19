// test_session_manager.cpp — Tier 5 tests for SessionManager.
//
// SessionManager ties together three pieces that have been tested in
// isolation in earlier tiers:
//   - CryptoEngine identities (Tier 1)
//   - SQLCipher-backed SessionStore (Tier 2, via DatabaseManager tables)
//   - RatchetSession double-ratchet (Tier 4)
// plus the Noise IK handshake on top.  This tier verifies the whole stack
// works end-to-end between two *independent* SessionManager instances —
// the thing a real Alice ↔ Bob exchange actually looks like.
//
// Identities are expensive to bootstrap (~1.3 s of Argon2 each), so the
// fixture creates them once in SetUpTestSuite and reuses them across cases.
// Everything else (databases, stores, managers) is fresh per test.

#include "SessionManager.hpp"
#include "SessionStore.hpp"
#include "SqlCipherDb.hpp"
#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

std::string makeTempPath(const char* tag, const char* suffix) {
    namespace fs = std::filesystem;
    (void)sodium_init();
    uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x%s",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7], suffix);
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove_all(p);
    return p.string();
}

SqlCipherDb::Bytes randomKey32() {
    SqlCipherDb::Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

Bytes bytesOf(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

// Per-party runtime plumbing bundled so tests can set two of these up.
struct Party {
    std::string                    peerId;    // self's base64url Ed25519 pub
    std::string                    dbPath;
    std::unique_ptr<SqlCipherDb>   db;
    std::unique_ptr<SessionStore>  store;
    std::unique_ptr<SessionManager> mgr;
    std::vector<Bytes>             outgoing;  // handshake responses captured from sendResponseFn
};

}  // namespace

class SessionManagerSuite : public ::testing::Test {
protected:
    // Identities live across the whole suite (Argon2 bootstraps are slow).
    static std::string s_aliceDir;
    static std::string s_bobDir;
    static std::unique_ptr<CryptoEngine> s_aliceCrypto;
    static std::unique_ptr<CryptoEngine> s_bobCrypto;

    static void SetUpTestSuite() {
        namespace fs = std::filesystem;
        ASSERT_GE(sodium_init(), 0);

        s_aliceDir = makeTempPath("p2p-sm-alice-id", "");
        s_bobDir   = makeTempPath("p2p-sm-bob-id", "");
        fs::create_directories(s_aliceDir);
        fs::create_directories(s_bobDir);

        s_aliceCrypto = std::make_unique<CryptoEngine>();
        s_aliceCrypto->setDataDir(s_aliceDir);
        s_aliceCrypto->setPassphrase("alice-test-only");
        ASSERT_NO_THROW(s_aliceCrypto->ensureIdentity());

        s_bobCrypto = std::make_unique<CryptoEngine>();
        s_bobCrypto->setDataDir(s_bobDir);
        s_bobCrypto->setPassphrase("bob-test-only");
        ASSERT_NO_THROW(s_bobCrypto->ensureIdentity());
    }

    static void TearDownTestSuite() {
        s_aliceCrypto.reset();
        s_bobCrypto.reset();
        std::filesystem::remove_all(s_aliceDir);
        std::filesystem::remove_all(s_bobDir);
    }

    // Per-test DB + SessionManager plumbing.
    Party alice;
    Party bob;

    // Build a Party around an existing CryptoEngine — fresh DB, store, manager.
    Party makeParty(const std::string& tag, CryptoEngine& crypto, const std::string& peerId) {
        Party p;
        p.peerId  = peerId;
        p.dbPath  = makeTempPath(("p2p-sm-" + tag).c_str(), ".db");
        p.db      = std::make_unique<SqlCipherDb>();
        if (!p.db->open(p.dbPath, randomKey32())) {
            ADD_FAILURE() << "open() failed for " << tag << ": " << p.db->lastError();
        }
        // SessionStore requires a 32-byte key — all blobs are app-level
        // AEAD-encrypted before hitting SQLCipher.  An empty key makes
        // every save silently drop to an empty BLOB, so a test that tries
        // to reload state finds nothing.
        p.store = std::make_unique<SessionStore>(*p.db, randomKey32());
        p.store->createTables();
        p.mgr   = std::make_unique<SessionManager>(crypto, *p.store);
        return p;
    }

    void SetUp() override {
        alice = makeParty("alice", *s_aliceCrypto,
                          CryptoEngine::toBase64Url(s_aliceCrypto->identityPub()));
        bob   = makeParty("bob", *s_bobCrypto,
                          CryptoEngine::toBase64Url(s_bobCrypto->identityPub()));

        // Wire each side's send-response callback to capture Noise msg2 blobs.
        auto wire = [](Party& self) {
            self.mgr->setSendResponseFn(
                [&self](const std::string&, const Bytes& blob) {
                    self.outgoing.push_back(blob);
                });
        };
        wire(alice);
        wire(bob);
    }

    void TearDown() override {
        alice.mgr.reset();
        bob.mgr.reset();
        alice.store.reset();
        bob.store.reset();
        if (alice.db) alice.db->close();
        if (bob.db)   bob.db->close();
        alice.db.reset();
        bob.db.reset();
        std::filesystem::remove(alice.dbPath);
        std::filesystem::remove(bob.dbPath);
    }
};

std::string SessionManagerSuite::s_aliceDir;
std::string SessionManagerSuite::s_bobDir;
std::unique_ptr<CryptoEngine> SessionManagerSuite::s_aliceCrypto;
std::unique_ptr<CryptoEngine> SessionManagerSuite::s_bobCrypto;

// ── 1. Classical Noise IK pre-key handshake, end-to-end ───────────────────
// Alice → Bob (pre-key msg 0x01 + initial payload)
// Bob → Alice (pre-key response 0x02, captured via callback)
// The payload round-trips and both sides have a session when done.

TEST_F(SessionManagerSuite, ClassicalPreKeyRoundTrip) {
    const Bytes pt = bytesOf("hello from alice");
    const Bytes msg1 = alice.mgr->encryptForPeer(bob.peerId, pt);
    ASSERT_FALSE(msg1.empty());
    EXPECT_EQ(msg1[0], SessionManager::kPreKeyMsg)
        << "classical handshake should carry the 0x01 type byte";

    const Bytes decoded = bob.mgr->decryptFromPeer(alice.peerId, msg1);
    EXPECT_EQ(decoded, pt);

    ASSERT_EQ(bob.outgoing.size(), 1u) << "Bob should have produced exactly one pre-key response";
    EXPECT_EQ(bob.outgoing[0][0], SessionManager::kPreKeyResponse);

    // Alice consumes Bob's response to complete her side of the handshake.
    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);

    EXPECT_TRUE(alice.mgr->hasSession(bob.peerId));
    EXPECT_TRUE(bob.mgr->hasSession(alice.peerId));
}

// ── 2. Hybrid PQ (ML-KEM-768) handshake round-trip ────────────────────────
// When the initiator passes a valid peerKemPub AND has PQ keys of her own,
// the handshake switches to the 0x04/0x05 type bytes and the underlying
// Noise IK derivation mixes the KEM shared secret into the chaining key.

TEST_F(SessionManagerSuite, HybridPreKeyRoundTrip) {
    ASSERT_TRUE(s_aliceCrypto->hasPQKeys());
    ASSERT_TRUE(s_bobCrypto->hasPQKeys());

    const Bytes pt = bytesOf("hybrid hi");
    const Bytes msg1 = alice.mgr->encryptForPeer(bob.peerId, pt, s_bobCrypto->kemPub());
    ASSERT_FALSE(msg1.empty());
    EXPECT_EQ(msg1[0], SessionManager::kHybridPreKeyMsg)
        << "hybrid handshake should carry the 0x04 type byte";

    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, msg1), pt);

    ASSERT_EQ(bob.outgoing.size(), 1u);
    EXPECT_EQ(bob.outgoing[0][0], SessionManager::kHybridPreKeyResp);

    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);

    EXPECT_TRUE(alice.mgr->hasSession(bob.peerId));
    EXPECT_TRUE(bob.mgr->hasSession(alice.peerId));
}

// ── 3. Ratchet takeover: after handshake, subsequent messages use 0x03 ────
// Proves the Noise handshake actually seeded a usable Double Ratchet state —
// not just that the first exchange worked.

TEST_F(SessionManagerSuite, RatchetTakesOverAfterHandshake) {
    // Complete the initial handshake first.
    const Bytes first = alice.mgr->encryptForPeer(bob.peerId, bytesOf("first"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, first), bytesOf("first"));
    ASSERT_EQ(bob.outgoing.size(), 1u);
    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);
    ASSERT_TRUE(alice.mgr->hasSession(bob.peerId));
    ASSERT_TRUE(bob.mgr->hasSession(alice.peerId));

    // Now Alice sends a second message — should be a pure ratchet message.
    const Bytes second = alice.mgr->encryptForPeer(bob.peerId, bytesOf("second"));
    ASSERT_FALSE(second.empty());
    EXPECT_EQ(second[0], SessionManager::kRatchetMsg)
        << "second send after handshake must use the ratchet, not re-handshake";

    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, second), bytesOf("second"));

    // And Bob's reply, likewise.
    const Bytes reply = bob.mgr->encryptForPeer(alice.peerId, bytesOf("reply"));
    ASSERT_FALSE(reply.empty());
    EXPECT_EQ(reply[0], SessionManager::kRatchetMsg);
    EXPECT_EQ(alice.mgr->decryptFromPeer(bob.peerId, reply), bytesOf("reply"));
}

// ── 4. A multi-turn conversation round-trips in both directions ───────────
// Exercises several DH ratchet steps on top of the post-handshake ratchet.

TEST_F(SessionManagerSuite, BidirectionalConversation) {
    // Complete handshake.
    const Bytes a1 = alice.mgr->encryptForPeer(bob.peerId, bytesOf("A#1"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, a1), bytesOf("A#1"));
    ASSERT_EQ(bob.outgoing.size(), 1u);
    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);

    // Now run a short conversation.
    struct Turn { bool aliceSends; const char* text; };
    const Turn turns[] = {
        {false, "B#1"}, {true,  "A#2"}, {false, "B#2"},
        {true,  "A#3"}, {false, "B#3"}, {true,  "A#4"},
    };
    for (const auto& t : turns) {
        const Bytes pt = bytesOf(t.text);
        if (t.aliceSends) {
            const Bytes wire = alice.mgr->encryptForPeer(bob.peerId, pt);
            ASSERT_FALSE(wire.empty()) << t.text;
            EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, wire), pt) << t.text;
        } else {
            const Bytes wire = bob.mgr->encryptForPeer(alice.peerId, pt);
            ASSERT_FALSE(wire.empty()) << t.text;
            EXPECT_EQ(alice.mgr->decryptFromPeer(bob.peerId, wire), pt) << t.text;
        }
    }
}

// ── 5. Session persists across a SessionManager rebuild ───────────────────
// The receiver's manager is destroyed and rebuilt on top of the same
// SqlCipher-backed SessionStore, simulating an app restart.  The ratchet
// state must reload and keep decrypting.

TEST_F(SessionManagerSuite, SessionPersistsAcrossManagerRebuild) {
    // Complete handshake.
    const Bytes first = alice.mgr->encryptForPeer(bob.peerId, bytesOf("before-restart"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, first), bytesOf("before-restart"));
    ASSERT_EQ(bob.outgoing.size(), 1u);
    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);

    // One post-handshake ratchet round to advance state.
    const Bytes warm = alice.mgr->encryptForPeer(bob.peerId, bytesOf("warm-up"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, warm), bytesOf("warm-up"));

    // Tear down Bob's manager, leave the DB + store intact; rebuild manager.
    bob.mgr.reset();
    bob.mgr = std::make_unique<SessionManager>(*s_bobCrypto, *bob.store);

    // Alice sends; rebuilt Bob must still decrypt.
    const Bytes next = alice.mgr->encryptForPeer(bob.peerId, bytesOf("after-restart"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, next), bytesOf("after-restart"));
    EXPECT_TRUE(bob.mgr->hasSession(alice.peerId));
}

// ── 6. deleteSession removes both the cache entry and the persisted row ───

TEST_F(SessionManagerSuite, DeleteSessionForgetsPeer) {
    // Complete handshake so both sides have a session.
    const Bytes first = alice.mgr->encryptForPeer(bob.peerId, bytesOf("hi"));
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, first), bytesOf("hi"));
    ASSERT_EQ(bob.outgoing.size(), 1u);
    (void)alice.mgr->decryptFromPeer(bob.peerId, bob.outgoing[0]);
    ASSERT_TRUE(alice.mgr->hasSession(bob.peerId));

    alice.mgr->deleteSession(bob.peerId);
    EXPECT_FALSE(alice.mgr->hasSession(bob.peerId));

    // Rebuild Alice's manager on the same store — still no session.
    alice.mgr.reset();
    alice.mgr = std::make_unique<SessionManager>(*s_aliceCrypto, *alice.store);
    EXPECT_FALSE(alice.mgr->hasSession(bob.peerId));
}

// ── 7. Malformed and unknown-type inputs don't crash or decrypt ───────────

TEST_F(SessionManagerSuite, MalformedInputReturnsEmpty) {
    // Empty blob.
    EXPECT_TRUE(bob.mgr->decryptFromPeer(alice.peerId, {}).empty());

    // Unknown type byte 0x7F.
    Bytes junk(64, 0x00);
    junk[0] = 0x7F;
    EXPECT_TRUE(bob.mgr->decryptFromPeer(alice.peerId, junk).empty());

    // Claim pre-key type but truncate before msg1 length field.
    Bytes tiny;
    tiny.push_back(SessionManager::kPreKeyMsg);
    EXPECT_TRUE(bob.mgr->decryptFromPeer(alice.peerId, tiny).empty());

    // Ratchet message without an existing session is impossible to decode.
    Bytes fakeRatchet(64, 0xAA);
    fakeRatchet[0] = SessionManager::kRatchetMsg;
    EXPECT_TRUE(bob.mgr->decryptFromPeer(alice.peerId, fakeRatchet).empty());
    EXPECT_FALSE(bob.mgr->hasSession(alice.peerId))
        << "a bogus ratchet message must not spuriously create a session";
}

// ── 8. Additional pre-key messages: Alice can pipeline messages while the
// handshake is in flight (0x06 type with a counter), all decryptable on Bob's
// side once he completes msg1.  This is the "offline delivery" path.

TEST_F(SessionManagerSuite, AdditionalPreKeyMessagesDeliverInOrder) {
    // Alice encrypts msg 1 — triggers handshake init + prekey payload.
    const Bytes m1 = alice.mgr->encryptForPeer(bob.peerId, bytesOf("m1"));
    ASSERT_FALSE(m1.empty());
    EXPECT_EQ(m1[0], SessionManager::kPreKeyMsg);

    // Before Bob sees anything, Alice sends a second message — should be an
    // additional pre-key (type 0x06), not another full handshake.
    const Bytes m2 = alice.mgr->encryptForPeer(bob.peerId, bytesOf("m2"));
    ASSERT_FALSE(m2.empty());
    EXPECT_EQ(m2[0], SessionManager::kAdditionalPreKey)
        << "second pre-handshake send should use the additional-prekey path (0x06)";

    // Bob processes msg1 first — gets the chaining key.
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, m1), bytesOf("m1"));
    // Then the additional pre-key message (same chaining key, different counter).
    EXPECT_EQ(bob.mgr->decryptFromPeer(alice.peerId, m2), bytesOf("m2"));
}
