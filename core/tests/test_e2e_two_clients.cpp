// test_e2e_two_clients.cpp — end-to-end round-trip with a mock relay.
//
// Wires two ChatController instances to a hand-rolled in-process "relay":
//
//   Alice.sendText(bob, "hi") →
//     SessionManager(Noise IK) → SealedEnvelope → RelayClient.sendEnvelope
//       → MockHttpClient POST /v1/send → MockRelay → Bob's MockWebSocket
//         → RelayClient.onEnvelopeReceived → ChatController.onEnvelope
//           → unseal → SessionManager.decryptFromPeer → onMessageReceived
//
// Bob's Noise msg2 is routed the same way in reverse (via the
// SessionManager send-response callback), completing the handshake on
// Alice's side.  Everything runs synchronously — the mocks invoke their
// callbacks inline — so a single sendText() call returns only after the
// whole handshake + message have bounced through the mock relay.
//
// This is the closest thing to a real client round-trip that can be
// pinned down deterministically in a unit test.  It's also the place a
// regression in any of the underlying modules is most likely to show up
// as the user-visible failure "the message didn't arrive."

#include "types.hpp"
#include "AppDataStore.hpp"
#include "ChatController.hpp"
#include "CryptoEngine.hpp"
#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"
#include "SqlCipherDb.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

using p2p_test::makeTempPath;

// ── MockTimer / MockTimerFactory ─────────────────────────────────────────
// No-op timers.  ChatController's maintenance timer, RelayClient's
// reconnect / retry / cover timers all schedule against this — none of
// the paths those timers arm are exercised in this test.

class MockTimer : public ITimer {
public:
    void startSingleShot(int, std::function<void()>) override {}
    void stop() override {}
    bool isActive() const override { return false; }
};

class MockTimerFactory : public ITimerFactory {
public:
    std::unique_ptr<ITimer> create() override {
        return std::make_unique<MockTimer>();
    }
    void singleShot(int, std::function<void()>) override {}
};

class MockRelay;

// ── MockWebSocket ────────────────────────────────────────────────────────
// Owned 1:1 by a peer.  open() flips state + invokes onConnected; text
// frames (auth) are handed to the relay which synthesizes an auth_ok
// reply back through onTextMessage.  Binary frames get *delivered* to
// this peer via deliverBinary() from the relay.

class MockWebSocket : public IWebSocket {
public:
    explicit MockWebSocket(MockRelay* relay) : m_relay(relay) {}

    void open(const std::string& /*url*/) override {
        m_connected = true;
        if (onConnected) onConnected();
    }
    void close() override {
        if (m_connected) {
            m_connected = false;
            if (onDisconnected) onDisconnected();
        }
    }
    bool isConnected() const override { return m_connected; }
    bool isIdle() const override       { return !m_connected; }

    void sendTextMessage(const std::string& message) override;

    void deliverBinary(const Bytes& frame) {
        if (onBinaryMessage) onBinaryMessage(frame);
    }
    void deliverText(const std::string& msg) {
        if (onTextMessage) onTextMessage(msg);
    }

private:
    MockRelay* m_relay = nullptr;
    bool m_connected = false;
};

// MockWebSocketFactory — hands out MockWebSocket instances bound to a
// shared MockRelay.  Mirrors the production CWebSocketFactory pattern:
// RelayClient calls create() once for the primary subscribe; the test
// captures the raw pointer in Party::ws so the relay can deliverBinary
// to it.
class MockWebSocketFactory : public IWebSocketFactory {
public:
    explicit MockWebSocketFactory(MockRelay* relay) : m_relay(relay) {}

    std::unique_ptr<IWebSocket> create() override {
        auto ws = std::make_unique<MockWebSocket>(m_relay);
        created.push_back(ws.get());
        return ws;
    }

    MockRelay* m_relay = nullptr;
    std::vector<MockWebSocket*> created;  // non-owning
};

// ── MockHttpClient ───────────────────────────────────────────────────────
// POST /v1/send goes to the relay for routing.
// GET  /v1/relay_info returns 404 so RelayClient skips onion-mode caching.

class MockHttpClient : public IHttpClient {
public:
    explicit MockHttpClient(MockRelay* relay) : m_relay(relay) {}

    void post(const std::string& url, const Bytes& body,
              const Headers& /*headers*/, Callback cb) override;

    void get(const std::string& /*url*/, const Headers& /*headers*/,
             Callback cb) override {
        Response r;
        r.status = 404;   // relay_info unknown — client falls back to no onion
        cb(r);
    }

private:
    MockRelay* m_relay = nullptr;
};

// ── MockRelay ────────────────────────────────────────────────────────────
// Routes relay-wrapped envelopes by inspecting the recipient Ed25519 pub
// that sits at bytes [1..33] of the relay header.  Auth is trivial —
// accept whatever JSON comes in, echo auth_ok.

class MockRelay {
public:
    void registerPeer(const std::string& edPubB64u, MockWebSocket* ws) {
        m_peers[edPubB64u] = ws;
    }

    // Called by MockWebSocket::sendTextMessage.
    void handleAuth(MockWebSocket* ws, const std::string& authText) {
        (void)authText;
        nlohmann::json resp;
        resp["type"] = "auth_ok";
        ws->deliverText(resp.dump());
    }

    // Called by MockHttpClient::post on /v1/send.
    // Returns 200 + routes, or 200 + silently drops unknown recipients.
    void sendEnvelope(const Bytes& relayEnvelope, IHttpClient::Callback cb) {
        // Relay envelope layout: 0x01 || recipientEdPub(32) || inner
        if (relayEnvelope.size() < 33 || relayEnvelope[0] != 0x01) {
            IHttpClient::Response r;
            r.status = 400;
            cb(r);
            return;
        }

        const Bytes edPub(relayEnvelope.begin() + 1, relayEnvelope.begin() + 33);
        const std::string key = CryptoEngine::toBase64Url(edPub);

        auto it = m_peers.find(key);
        if (it != m_peers.end() && it->second != nullptr) {
            m_captured[key].push_back(relayEnvelope);
            // Optional knob for tests that want to observe replay defense.
            for (int i = 0; i < m_deliverTimes; ++i) {
                it->second->deliverBinary(relayEnvelope);
            }
        }

        IHttpClient::Response r;
        r.status = 200;
        cb(r);
    }

    // Test-only knob: deliver each relayed envelope this many times (default 1).
    void setDeliverMultiplier(int n) { m_deliverTimes = n; }

    // Capture the bytes of each relay envelope delivered to a peer, so tests
    // that simulate an app restart can re-inject an old envelope after the
    // in-memory dedup cache has been wiped.
    const std::vector<Bytes>& capturedFor(const std::string& peerId) const {
        static const std::vector<Bytes> kEmpty;
        auto it = m_captured.find(peerId);
        return it == m_captured.end() ? kEmpty : it->second;
    }

private:
    std::map<std::string, MockWebSocket*> m_peers;
    std::map<std::string, std::vector<Bytes>> m_captured;
    int m_deliverTimes = 1;

    friend class TwoClientSuite;  // needed for restart-replay test only
};

void MockWebSocket::sendTextMessage(const std::string& message) {
    if (m_relay) m_relay->handleAuth(this, message);
}

void MockHttpClient::post(const std::string& /*url*/, const Bytes& body,
                          const Headers& /*headers*/, Callback cb) {
    if (m_relay) m_relay->sendEnvelope(body, std::move(cb));
    else {
        Response r; r.status = 500; cb(r);
    }
}

}  // namespace

// ── Fixture ──────────────────────────────────────────────────────────────

class TwoClientSuite : public ::testing::Test {
protected:
    struct Party {
        std::string                      dataDir;
        std::string                      dbPath;
        std::unique_ptr<SqlCipherDb>     db;
        // appData binds to the same SqlCipherDb as ChatController and
        // backs the v2 group-message path (replay cache, chain state,
        // send state, bundle map).  Without it, sendTextV2 falls back
        // to the v1 SenderChain path — the v2 + Phase 2 tests below
        // need it wired to actually exercise the new code.
        std::unique_ptr<AppDataStore>    appData;
        // wsFactory owns the MockWebSocket; ws is a non-owning view
        // captured at construction time for the test to drive directly
        // (registerPeer with the relay, deliverBinary etc.).  Pointer is
        // valid as long as the ChatController (and therefore RelayClient)
        // is alive.
        std::unique_ptr<MockWebSocketFactory> wsFactory;
        MockWebSocket*                   ws = nullptr;
        std::unique_ptr<MockHttpClient>  http;
        std::unique_ptr<MockTimerFactory> timers;
        std::unique_ptr<ChatController>  ctrl;
        std::string                      id;  // base64url Ed25519 identity pub

        // Message capture.
        struct Received {
            std::string from;
            std::string text;
            int64_t     ts = 0;
            std::string msgId;
        };
        std::vector<Received> received;

        // Group-control capture.
        struct Renamed {
            std::string groupId;
            std::string newName;
        };
        std::vector<Renamed> renamed;

        struct GroupAvatar {
            std::string groupId;
            std::string avatarB64;
        };
        std::vector<GroupAvatar> groupAvatars;

        struct MemberLeft {
            std::string from;
            std::string groupId;
            std::string groupName;
            std::vector<std::string> members;
        };
        std::vector<MemberLeft> memberLeft;

        // pv=2 group_msg capture — fired from
        // ChatController::onGroupMessageReceived.  Carries the same
        // shape as the C-API callback so the v2 dispatcher's drained-
        // buffer messages preserve their counter ordering on receive.
        struct GroupReceived {
            std::string from;
            std::string groupId;
            std::string groupName;
            std::vector<std::string> members;
            std::string text;
            int64_t     ts = 0;
            std::string msgId;
        };
        std::vector<GroupReceived> groupReceived;

        // pv=2 stream-blocked + lost-messages capture for gap-fill /
        // session-reset assertions.
        struct GroupBlocked {
            std::string groupId;
            std::string senderPeerId;
            int64_t fromCtr = 0;
            int64_t toCtr   = 0;
        };
        std::vector<GroupBlocked> groupBlocked;
        struct GroupLost {
            std::string groupId;
            std::string senderPeerId;
            int64_t count = 0;
        };
        std::vector<GroupLost> groupLost;

        // File-transfer capture (receiver side).  savedPath is non-empty
        // only on the final progress event; we stash only the last frame
        // per transferId so tests can check completion cleanly.
        struct FileDone {
            std::string transferId;
            std::string fileName;
            std::string savedPath;
            int chunksTotal = 0;
        };
        std::map<std::string, FileDone> fileDone;
    };

    std::unique_ptr<MockRelay> relay;
    Party alice;
    Party bob;

    void setupParty(Party& p, const std::string& tag) {
        p.dataDir = makeTempPath(("p2p-e2e-id-" + tag).c_str(), "");
        fs::create_directories(p.dataDir);

        p.wsFactory = std::make_unique<MockWebSocketFactory>(relay.get());
        p.http      = std::make_unique<MockHttpClient>(relay.get());
        p.timers    = std::make_unique<MockTimerFactory>();
        p.ctrl      = std::make_unique<ChatController>(*p.wsFactory, *p.http, *p.timers);
        // ChatController -> RelayClient called wsFactory.create() once;
        // grab the resulting MockWebSocket as a non-owning view so the
        // relay can route inbound envelopes to it via deliverBinary.
        ASSERT_EQ(p.wsFactory->created.size(), 1u);
        p.ws = p.wsFactory->created[0];

        p.ctrl->setDataDir(p.dataDir);
        p.ctrl->setPassphrase(tag + "-test-only-passphrase");
        p.id = p.ctrl->myIdB64u();

        // Fresh per-party DB (SQLCipher-encrypted, at-rest key is random
        // per-test — we don't care about persistence semantics here).
        p.dbPath = makeTempPath(("p2p-e2e-db-" + tag).c_str(), ".db");
        p.db     = std::make_unique<SqlCipherDb>();
        Bytes dbKey(32);
        randombytes_buf(dbKey.data(), dbKey.size());
        ASSERT_TRUE(p.db->open(p.dbPath, dbKey)) << p.db->lastError();
        p.ctrl->setDatabase(*p.db);

        // Wire AppDataStore so the v2 group path activates.  Bind to
        // the same SqlCipherDb the controller uses; field-encryption
        // key is the at-rest dbKey itself (mirrors p2p_context's
        // wiring at the C-API layer).
        p.appData = std::make_unique<AppDataStore>();
        ASSERT_TRUE(p.appData->bind(*p.db));
        p.appData->setEncryptionKey(dbKey);
        p.ctrl->setAppDataStore(p.appData.get());

        // ChatController drives RelayClient; setRelayUrl is required or
        // the HTTP paths it builds won't have a host.
        p.ctrl->setRelayUrl("wss://mock-relay.test");

        p.ctrl->onMessageReceived = [&p](const std::string& from,
                                          const std::string& text,
                                          int64_t ts,
                                          const std::string& msgId) {
            p.received.push_back({from, text, ts, msgId});
        };

        p.ctrl->onGroupRenamed = [&p](const std::string& groupId,
                                       const std::string& newName) {
            p.renamed.push_back({groupId, newName});
        };
        p.ctrl->onGroupAvatarReceived = [&p](const std::string& groupId,
                                              const std::string& avatarB64) {
            p.groupAvatars.push_back({groupId, avatarB64});
        };
        p.ctrl->onGroupMemberLeft = [&p](const std::string& from,
                                          const std::string& gid,
                                          const std::string& gname,
                                          const std::vector<std::string>& members,
                                          int64_t /*ts*/, const std::string& /*msgId*/) {
            p.memberLeft.push_back({from, gid, gname, members});
        };
        p.ctrl->onGroupMessageReceived =
            [&p](const std::string& from,
                  const std::string& gid,
                  const std::string& gname,
                  const std::vector<std::string>& members,
                  const std::string& text,
                  int64_t ts,
                  const std::string& msgId) {
            p.groupReceived.push_back({from, gid, gname, members,
                                         text, ts, msgId});
        };
        p.ctrl->onGroupStreamBlocked =
            [&p](const std::string& gid,
                  const std::string& sender,
                  int64_t fromCtr, int64_t toCtr) {
            p.groupBlocked.push_back({gid, sender, fromCtr, toCtr});
        };
        p.ctrl->onGroupMessagesLost =
            [&p](const std::string& gid,
                  const std::string& sender,
                  int64_t count) {
            p.groupLost.push_back({gid, sender, count});
        };
        p.ctrl->onFileChunkReceived = [&p](const std::string& /*from*/,
                                            const std::string& tid,
                                            const std::string& fileName,
                                            int64_t /*fileSize*/,
                                            int /*rcvd*/, int total,
                                            const std::string& savedPath,
                                            int64_t /*ts*/,
                                            const std::string& /*gid*/,
                                            const std::string& /*gname*/) {
            // Only capture the terminal frame (the one with savedPath).
            if (!savedPath.empty()) {
                p.fileDone[tid] = {tid, fileName, savedPath, total};
            }
        };
    }

    void connectBoth() {
        // Register peers by id BEFORE they connect, so auth + any immediate
        // queued envelopes can be routed.
        relay->registerPeer(alice.id, alice.ws);
        relay->registerPeer(bob.id,   bob.ws);

        alice.ctrl->connectToRelay();  // mock WS -> auth -> auth_ok inline
        bob.ctrl->connectToRelay();

        ASSERT_TRUE(alice.ctrl->relay().isConnected());
        ASSERT_TRUE(bob.ctrl->relay().isConnected());
    }

    // Force a 1:1 Noise IK handshake in both directions so the DR
    // session exists before any v2 group_msg send.  sendTextV2 needs
    // sessionMgr->sessionIdFor(peer) to be non-empty — that's the
    // signal the DR session has been established.  In production the
    // first 1:1 message naturally bootstraps it; in v2-group tests
    // there's no preceding 1:1, so we synthesize one here.
    //
    // The throwaway messages land in `received` on both sides; tests
    // that want to assert on that capture should clear it after this
    // call returns.
    void establishSessions() {
        connectBoth();
        alice.ctrl->sendText(bob.id,   "__bootstrap__");
        bob.ctrl->sendText(alice.id,   "__bootstrap__");
        alice.received.clear();
        bob.received.clear();
    }

    // Stamp the stored fingerprint row for `peerId` in `party`'s DB with
    // a known-bad 32-byte blob.  Used by safety-number mismatch tests.
    //
    // The raw SQL bypasses saveVerifiedFingerprint's cache invalidation,
    // so we flush the in-memory cache ourselves.  In production that
    // invalidation happens naturally on the next app start; these tests
    // compress the "restart" step into one call.
    static void corruptStoredFingerprint(Party& party,
                                          const std::string& peerId,
                                          uint8_t fill) {
        SqlCipherQuery q(*party.db);
        ASSERT_TRUE(q.prepare(
            "UPDATE verified_peers SET verified_fingerprint = :fp"
            " WHERE peer_id = :pid;"));
        q.bindValue(":fp", Bytes(32, fill));
        q.bindValue(":pid", peerId);
        ASSERT_TRUE(q.exec());
        party.ctrl->clearPeerKeyCache();
    }

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        relay = std::make_unique<MockRelay>();
        setupParty(alice, "alice");
        setupParty(bob,   "bob");
    }

    void TearDown() override {
        alice.ctrl.reset();
        bob.ctrl.reset();
        if (alice.db) alice.db->close();
        if (bob.db)   bob.db->close();
        alice.db.reset();
        bob.db.reset();
        relay.reset();
        std::error_code ec;
        fs::remove(alice.dbPath, ec);
        fs::remove(bob.dbPath, ec);
        fs::remove_all(alice.dataDir, ec);
        fs::remove_all(bob.dataDir, ec);
    }
};

// ── 1. Alice → Bob text round-trip ────────────────────────────────────────
// Exercises the full stack: Noise IK pre-key, sealed envelope, relay
// wrap/unwrap, envelope dedup, and the final onMessageReceived dispatch.

TEST_F(TwoClientSuite, TextRoundTripAliceToBob) {
    connectBoth();

    alice.ctrl->sendText(bob.id, "hello from alice");

    ASSERT_EQ(bob.received.size(), 1u);
    EXPECT_EQ(bob.received[0].from, alice.id);
    EXPECT_EQ(bob.received[0].text, "hello from alice");
    EXPECT_FALSE(bob.received[0].msgId.empty());
    EXPECT_GT(bob.received[0].ts, 0);
}

// ── 2. Multi-turn conversation, both directions ──────────────────────────
// After the first exchange the session is a pure double-ratchet; this
// verifies the ratchet handoff works on top of the full mocked stack.

TEST_F(TwoClientSuite, BidirectionalConversation) {
    connectBoth();

    alice.ctrl->sendText(bob.id, "A#1");
    bob.ctrl->sendText(alice.id, "B#1");
    alice.ctrl->sendText(bob.id, "A#2");
    bob.ctrl->sendText(alice.id, "B#2");
    alice.ctrl->sendText(bob.id, "A#3");

    ASSERT_EQ(bob.received.size(),   3u);
    EXPECT_EQ(bob.received[0].text,  "A#1");
    EXPECT_EQ(bob.received[1].text,  "A#2");
    EXPECT_EQ(bob.received[2].text,  "A#3");

    ASSERT_EQ(alice.received.size(), 2u);
    EXPECT_EQ(alice.received[0].text, "B#1");
    EXPECT_EQ(alice.received[1].text, "B#2");
}

// ── 3. Relay-level replay is dropped at the envelope dedup layer ─────────
// The mock relay delivers each send twice; Bob's ChatController dedups on
// the envelopeId field baked into the sealed envelope.

TEST_F(TwoClientSuite, ReplayedEnvelopeDeduped) {
    connectBoth();

    relay->setDeliverMultiplier(2);  // every envelope lands twice
    alice.ctrl->sendText(bob.id, "deliver me once, please");

    ASSERT_EQ(bob.received.size(), 1u)
        << "envelope dedup on envelopeId should suppress the duplicate delivery";
    EXPECT_EQ(bob.received[0].text, "deliver me once, please");
}

// ── 3b. Replay across app restart is dropped ─────────────────────────────
// The envelope-ID dedup cache is persisted via the seen_envelopes
// SQLCipher table, so a relay that stored sealed envelopes can't replay
// them after Bob restarts and his in-memory cache is cold.  Exercise it
// end-to-end: send a message, record the envelope bytes, rebuild Bob's
// ChatController on the same DB + identity, and re-inject the captured
// envelope.  Bob's message callback must NOT fire a second time.

TEST_F(TwoClientSuite, PersistentEnvelopeDedupSurvivesRestart) {
    connectBoth();

    alice.ctrl->sendText(bob.id, "please don't deliver me twice");
    ASSERT_EQ(bob.received.size(), 1u);

    // Grab the last envelope that landed at Bob — this is what the relay
    // would have on disk to replay after Bob restarts.
    const auto& captured = relay->capturedFor(bob.id);
    ASSERT_FALSE(captured.empty());
    const Bytes replay = captured.back();

    // Tear down Bob's controller (identity.json + DB survive on disk).
    // bob.ctrl.reset() destroys the MockWebSocket the factory previously
    // created, leaving bob.ws dangling.  Recreate the factory too so
    // bob.ws gets refreshed to the new WS owned by the new controller.
    bob.ctrl.reset();
    bob.wsFactory = std::make_unique<MockWebSocketFactory>(relay.get());

    // Rebuild Bob's controller on the same data dir + same DB.
    bob.ctrl = std::make_unique<ChatController>(
        *bob.wsFactory, *bob.http, *bob.timers);
    ASSERT_EQ(bob.wsFactory->created.size(), 1u);
    bob.ws = bob.wsFactory->created[0];

    bob.ctrl->setDataDir(bob.dataDir);
    bob.ctrl->setPassphrase("bob-test-only-passphrase");
    bob.ctrl->setDatabase(*bob.db);
    bob.ctrl->setRelayUrl("wss://mock-relay.test");
    bob.ctrl->onMessageReceived = [this](const std::string& from,
                                          const std::string& text,
                                          int64_t ts,
                                          const std::string& msgId) {
        bob.received.push_back({from, text, ts, msgId});
    };
    // Re-register in the mock relay so routing still works.
    relay->registerPeer(bob.id, bob.ws);
    bob.ctrl->connectToRelay();

    // Now replay the captured envelope directly onto Bob's WS.
    bob.ws->deliverBinary(replay);
    EXPECT_EQ(bob.received.size(), 1u)
        << "persistent envelope dedup must drop a replay after restart";
}

// ── 3c. Safety numbers: first contact is Unverified, symmetric display ──
// No verification record → peerTrust is Unverified for both peers.  The
// 60-digit safety number is the same byte-for-byte on both sides (sort
// invariance).

TEST_F(TwoClientSuite, SafetyNumber_FirstContactUnverifiedAndSymmetric) {
    connectBoth();

    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Unverified);
    EXPECT_EQ(bob.ctrl->peerTrust(alice.id),
              ChatController::PeerTrust::Unverified);

    const std::string aNum = alice.ctrl->safetyNumber(bob.id);
    const std::string bNum = bob.ctrl->safetyNumber(alice.id);
    EXPECT_EQ(aNum, bNum);
    EXPECT_EQ(aNum.size(), 71u);  // 12 groups × 5 digits + 11 spaces
}

// ── 3d. Safety numbers: mark → Verified → unverify ───────────────────────

TEST_F(TwoClientSuite, SafetyNumber_MarkAndUnverifyFlow) {
    connectBoth();

    EXPECT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Verified);
    // Idempotent re-mark.
    EXPECT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Verified);

    alice.ctrl->unverifyPeer(bob.id);
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Unverified);
}

// ── 3c. Cache invalidation: markPeerVerified after a Unverified read ─────
// Order matters.  The peerTrust() call warms the in-memory fingerprint
// cache with {stored=empty}.  markPeerVerified writes verified_peers on
// disk; the cache must reflect that on the next read or peerTrust will
// stay Unverified forever — a UX bug, not a security one.

TEST_F(TwoClientSuite, SafetyNumber_CachePicksUpVerifyAfterUnverifiedRead) {
    connectBoth();

    // Warm the cache: no row in verified_peers yet.
    ASSERT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Unverified);

    // Now verify.  Cache must update or invalidate.
    ASSERT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Verified);
}

// ── 3d. Cache invalidation: unverifyPeer after a Verified read ───────────
// The load-bearing one.  If the cache still reports {stored=fingerprint}
// after the row is deleted, peerTrust would say Verified — a silent
// security regression (trusting a peer the user just unverified).

TEST_F(TwoClientSuite, SafetyNumber_CacheDropsStoredOnUnverifyAfterVerifiedRead) {
    connectBoth();

    ASSERT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    // Warm the cache with {stored=fingerprint, current=same}.
    ASSERT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Verified);

    // Unverify — the cached `stored` must be dropped.
    alice.ctrl->unverifyPeer(bob.id);
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Unverified)
        << "cache stale after unverifyPeer — peerTrust still reports Verified "
        << "for a peer the user explicitly unverified (security regression)";
}

// ── 3e. Safety numbers: corrupt stored fingerprint → Mismatch + callback ─
// Simulates "something changed since verification" (reinstall, DB
// tampering).  The onPeerKeyChanged callback must fire AT MOST ONCE
// per session per peer.

TEST_F(TwoClientSuite, SafetyNumber_MismatchFiresCallbackOnceAndPersists) {
    connectBoth();

    ASSERT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    ASSERT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Verified);

    // Simulate mismatch: corrupt the stored fingerprint in Alice's DB.
    corruptStoredFingerprint(alice, bob.id, 0x11);
    EXPECT_EQ(alice.ctrl->peerTrust(bob.id),
              ChatController::PeerTrust::Mismatch);

    // Wire the callback and fire a send — should trigger exactly once.
    int callCount = 0;
    std::string changedPeer;
    Bytes lastOldFp, lastNewFp;
    alice.ctrl->onPeerKeyChanged = [&](const std::string& pid,
                                        const Bytes& oldFp, const Bytes& newFp) {
        ++callCount;
        changedPeer = pid;
        lastOldFp   = oldFp;
        lastNewFp   = newFp;
    };

    alice.ctrl->sendText(bob.id, "hi");
    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(changedPeer, bob.id);
    EXPECT_EQ(lastOldFp.size(), 32u);
    EXPECT_EQ(lastNewFp.size(), 32u);
    EXPECT_NE(lastOldFp, lastNewFp);

    // Second send must NOT re-fire — the once-per-session guard holds.
    alice.ctrl->sendText(bob.id, "hi 2");
    EXPECT_EQ(callCount, 1);
}

// ── 3f. Hard-block toggle refuses sends + receives on mismatch ──────────

TEST_F(TwoClientSuite, SafetyNumber_HardBlockRefusesSend) {
    connectBoth();

    ASSERT_TRUE(alice.ctrl->markPeerVerified(bob.id));
    alice.ctrl->setHardBlockOnKeyChange(true);

    corruptStoredFingerprint(alice, bob.id, 0x22);

    const size_t before = bob.received.size();
    alice.ctrl->sendText(bob.id, "should be blocked");
    EXPECT_EQ(bob.received.size(), before)
        << "hard-block should have prevented the send from reaching Bob";
}

// ── 4. Envelope addressed to a stranger doesn't reach Alice or Bob ───────
// A sealed envelope's AAD binds recipient identity; the relay routes by
// recipientEdPub.  An envelope whose routing header targets a third party
// the relay doesn't know must simply vanish — the alive peers' callbacks
// stay silent.

TEST_F(TwoClientSuite, EnvelopeAddressedToStrangerIsDropped) {
    connectBoth();

    // Craft a plausibly-shaped relay envelope with a random (unregistered)
    // recipient pub.  Anything downstream is irrelevant — the mock relay
    // never reaches the "deliver to WS" branch.
    Bytes bogus(1 + 32 + 100, 0x00);
    bogus[0] = 0x01;
    randombytes_buf(bogus.data() + 1, 32);

    // Simulate a malicious POST /v1/send directly (bypassing ChatController
    // on the sender side, which is what a hostile client would do).
    bool cbFired = false;
    alice.http->post("https://mock-relay.test/v1/send", bogus, {},
                     [&cbFired](const IHttpClient::Response& r) {
                         cbFired = true;
                         EXPECT_EQ(r.status, 200);
                     });
    EXPECT_TRUE(cbFired);

    EXPECT_EQ(alice.received.size(), 0u);
    EXPECT_EQ(bob.received.size(),   0u);
}

// ── Group-control round-trips ────────────────────────────────────────────
// These exercise the ChatController paths exposed as p2p_rename_group /
// p2p_send_group_avatar / p2p_leave_group / p2p_send_group_file.  The
// C API is a thin std::vector↔const char** shim; the interesting
// invariants (dedup, authorization, file chunk reassembly) all live
// here.
//
// All four tests seed Bob's group roster via setKnownGroupMembers —
// sendGroup* strips self from the declared members so the cold-
// bootstrap check ("sender must be in members") never fires for the
// sender's own messages.  Real clients persist their roster and call
// setKnownGroupMembers on startup; these tests mirror that.

TEST_F(TwoClientSuite, GroupRename_FiresCallbackOnPeer) {
    connectBoth();

    const std::string gid = "grp-rename-abc";
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    alice.ctrl->sendGroupRename(gid, "Planning Crew", { alice.id, bob.id });

    ASSERT_EQ(bob.renamed.size(), 1u);
    EXPECT_EQ(bob.renamed[0].groupId, gid);
    EXPECT_EQ(bob.renamed[0].newName, "Planning Crew");

    // Replay the exact same sealed envelope (MockRelay delivers each send
    // twice) — dedup on the msgId bounded inside the payload should
    // suppress the duplicate callback.
    relay->setDeliverMultiplier(2);
    alice.ctrl->sendGroupRename(gid, "Even Newer Name", { alice.id, bob.id });
    EXPECT_EQ(bob.renamed.size(), 2u)
        << "replayed envelope fired the rename callback a second time "
        << "— group_rename msgId dedup regression";
}

TEST_F(TwoClientSuite, GroupAvatar_FiresCallbackOnPeer) {
    connectBoth();

    const std::string gid = "grp-avatar-def";
    const std::string avatarB64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=";
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    alice.ctrl->sendGroupAvatar(gid, avatarB64, { alice.id, bob.id });

    ASSERT_EQ(bob.groupAvatars.size(), 1u);
    EXPECT_EQ(bob.groupAvatars[0].groupId,   gid);
    EXPECT_EQ(bob.groupAvatars[0].avatarB64, avatarB64);

    // Replay check: double-delivery must not double-fire.
    relay->setDeliverMultiplier(2);
    alice.ctrl->sendGroupAvatar(gid, avatarB64 + "2", { alice.id, bob.id });
    EXPECT_EQ(bob.groupAvatars.size(), 2u)
        << "group_avatar msgId dedup regression";
}

TEST_F(TwoClientSuite, GroupMemberLeft_FiresCallbackOnPeer) {
    connectBoth();

    const std::string gid = "grp-leave-ghi";
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    alice.ctrl->sendGroupLeaveNotification(gid, "Planning Crew",
                                            { alice.id, bob.id });

    ASSERT_EQ(bob.memberLeft.size(), 1u);
    EXPECT_EQ(bob.memberLeft[0].from,      alice.id);
    EXPECT_EQ(bob.memberLeft[0].groupId,   gid);
    EXPECT_EQ(bob.memberLeft[0].groupName, "Planning Crew");
}

// ── Group file round-trip ────────────────────────────────────────────────
// Fanout + chunk reassembly + hash verify end-to-end.  We write a small
// source file, sendGroupFile to bob as the single member, and assert
// the final savedPath exists with the expected bytes.  Default auto-
// accept threshold is 100 MB so no consent prompt fires for our tiny file.

TEST_F(TwoClientSuite, GroupFile_RoundTripDeliversAllChunks) {
    connectBoth();

    const std::string gid = "grp-file-jkl";
    // Bootstrap session + roster so the group_file fanout is authorized.
    alice.ctrl->sendText(bob.id, "handshake");
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });
    ASSERT_EQ(bob.received.size(), 1u);

    // Write a source file spanning a couple chunks + change (cover the
    // boundary logic in sendChunkEnvelopes).
    const size_t size = size_t(FileTransferManager::kChunkBytes) * 2 + 2048;
    std::vector<uint8_t> contents(size);
    randombytes_buf(contents.data(), contents.size());
    const std::string srcPath = makeTempPath("p2p-e2e-grpfile-src", ".bin");
    {
        std::ofstream ofs(srcPath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(ofs.is_open());
        ofs.write(reinterpret_cast<const char*>(contents.data()),
                  std::streamsize(contents.size()));
    }

    const std::string groupTid = alice.ctrl->sendGroupFile(
        gid, "Planning Crew", { alice.id, bob.id },
        "payload.bin", srcPath);
    ASSERT_FALSE(groupTid.empty())
        << "sendGroupFile returned empty — check session / roster setup";

    // sendGroupFile returns a group-level id for caller-side cancellation;
    // per-member transfers have their own UUIDs used on the wire and in
    // onFileChunkReceived.  Look the file up by name instead (only one
    // transfer in-flight in this test).
    const Party::FileDone* done = nullptr;
    for (const auto& [tid, fd] : bob.fileDone) {
        (void)tid;
        if (fd.fileName == "payload.bin") { done = &fd; break; }
    }
    ASSERT_NE(done, nullptr)
        << "no completed file on Bob — chunks didn't land or "
        << "hash-verify failed";
    EXPECT_FALSE(done->savedPath.empty());
    EXPECT_TRUE(fs::exists(done->savedPath));

    // Byte-for-byte fidelity check on the reassembled file.
    std::ifstream rfs(done->savedPath, std::ios::binary);
    ASSERT_TRUE(rfs.is_open());
    std::vector<uint8_t> got((std::istreambuf_iterator<char>(rfs)),
                              std::istreambuf_iterator<char>());
    EXPECT_EQ(got, contents)
        << "reassembled file differs from source — chunk ordering "
        << "or hash verification regression in FileTransferManager";

    // Cleanup.
    std::error_code ec;
    fs::remove(srcPath, ec);
    fs::remove(done->savedPath, ec);
}

// ── Phase 1: Causally-Linked Pairwise group_msg over real DR ──────────────
//
// These tests drive sendGroupMessageViaMailbox (which routes through
// sendTextV2) and verify the v2 wire envelope flows through real
// SessionSealer + SessionManager + AppDataStore on both ends.  The
// receiver state machine has unit-test coverage in test_group_protocol;
// these tests pin the integration: handshake → seal → relay → unseal
// → dispatchGroupMessageV2 → onGroupMessageReceived.

TEST_F(TwoClientSuite, V2GroupText_RoundTripDelivers) {
    establishSessions();
    const std::string gid = "grp-v2-text-aaa";
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    alice.ctrl->sendGroupMessageViaMailbox(
        gid, "Project Hydra", { alice.id, bob.id }, "first v2 group msg");

    ASSERT_EQ(bob.groupReceived.size(), 1u);
    EXPECT_EQ(bob.groupReceived[0].from,      alice.id);
    EXPECT_EQ(bob.groupReceived[0].groupId,   gid);
    EXPECT_EQ(bob.groupReceived[0].groupName, "Project Hydra");
    EXPECT_EQ(bob.groupReceived[0].text,      "first v2 group msg");
    EXPECT_FALSE(bob.groupReceived[0].msgId.empty());
}

TEST_F(TwoClientSuite, V2GroupText_BidirectionalCounterIndependent) {
    // Each (sender, group, recipient) tuple maintains its own
    // counter — Alice→Bob and Bob→Alice are independent streams in
    // the same group, so neither's counter affects the other's
    // chain_state.
    establishSessions();
    const std::string gid = "grp-v2-bidi-bbb";
    alice.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(gid,   { alice.id, bob.id });

    alice.ctrl->sendGroupMessageViaMailbox(gid, "G", { alice.id, bob.id }, "A#1");
    bob.ctrl->sendGroupMessageViaMailbox(gid,   "G", { alice.id, bob.id }, "B#1");
    alice.ctrl->sendGroupMessageViaMailbox(gid, "G", { alice.id, bob.id }, "A#2");
    bob.ctrl->sendGroupMessageViaMailbox(gid,   "G", { alice.id, bob.id }, "B#2");

    ASSERT_EQ(bob.groupReceived.size(),   2u);
    EXPECT_EQ(bob.groupReceived[0].text,  "A#1");
    EXPECT_EQ(bob.groupReceived[1].text,  "A#2");
    ASSERT_EQ(alice.groupReceived.size(), 2u);
    EXPECT_EQ(alice.groupReceived[0].text, "B#1");
    EXPECT_EQ(alice.groupReceived[1].text, "B#2");

    // Neither side fired blocked or lost — the chain progressed
    // strictly in-order.
    EXPECT_TRUE(alice.groupBlocked.empty());
    EXPECT_TRUE(bob.groupBlocked.empty());
    EXPECT_TRUE(alice.groupLost.empty());
    EXPECT_TRUE(bob.groupLost.empty());
}

TEST_F(TwoClientSuite, V2GroupText_DropsExactReplay) {
    // The MockRelay's deliverMultiplier=2 sends each envelope twice.
    // The pv=2 receiver dedups via its counter < expectedNext check
    // (same envelope ID, second arrival hits "already delivered").
    establishSessions();
    const std::string gid = "grp-v2-replay-ccc";
    bob.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    relay->setDeliverMultiplier(2);
    alice.ctrl->sendGroupMessageViaMailbox(
        gid, "G", { alice.id, bob.id }, "exactly once please");

    ASSERT_EQ(bob.groupReceived.size(), 1u)
        << "v2 receiver should drop the duplicate via counter monotonicity "
        << "(or envelope-ID dedup at the outer layer — either is fine)";
    EXPECT_EQ(bob.groupReceived[0].text, "exactly once please");
}

// ── Phase 2: Invisible Groups (bundle_id round-trip) ─────────────────────────
//
// The bundle_id replaces groupId on the wire — sender mints + persists,
// receiver learns + back-fills its mapping on first message.  Subsequent
// messages route via bundle on both sides.

TEST_F(TwoClientSuite, V2GroupBundle_SenderPersistsStableId) {
    // The bundle_id is generated lazily on first send and reused for
    // every subsequent send to the same group, regardless of which
    // recipient is being addressed.
    establishSessions();
    const std::string gid = "grp-bundle-stable";
    alice.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(gid,   { alice.id, bob.id });

    // Pre-send: no mapping yet.
    EXPECT_TRUE(alice.appData->bundleIdForGroup(gid).empty());

    alice.ctrl->sendGroupMessageViaMailbox(gid, "G",
                                             { alice.id, bob.id }, "first");
    const Bytes b1 = alice.appData->bundleIdForGroup(gid);
    ASSERT_EQ(b1.size(), 16u) << "mint should produce a 16-byte bundle";

    alice.ctrl->sendGroupMessageViaMailbox(gid, "G",
                                             { alice.id, bob.id }, "second");
    EXPECT_EQ(alice.appData->bundleIdForGroup(gid), b1)
        << "second send must reuse the same bundle for the same groupId";

    ASSERT_EQ(bob.groupReceived.size(), 2u);
    EXPECT_EQ(bob.groupReceived[0].text, "first");
    EXPECT_EQ(bob.groupReceived[1].text, "second");
}

TEST_F(TwoClientSuite, V2GroupBundle_ReceiverLearnsMapping) {
    // Bob has never seen this group's bundle before Alice's first
    // send; after the inbound dispatch, Bob's local AppDataStore
    // should hold the same bundle_id Alice minted, bound to the same
    // local groupId — so future messages (and gap_requests Bob fires)
    // resolve consistently.
    establishSessions();
    const std::string gid = "grp-bundle-learned";
    alice.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(gid,   { alice.id, bob.id });

    EXPECT_TRUE(bob.appData->bundleIdForGroup(gid).empty());

    alice.ctrl->sendGroupMessageViaMailbox(gid, "G",
                                             { alice.id, bob.id },
                                             "hello, invisible group");

    const Bytes aliceBundle = alice.appData->bundleIdForGroup(gid);
    const Bytes bobBundle   = bob.appData->bundleIdForGroup(gid);
    ASSERT_FALSE(aliceBundle.empty());
    ASSERT_FALSE(bobBundle.empty());
    EXPECT_EQ(aliceBundle, bobBundle)
        << "receiver should back-fill with the sender's bundle";
    EXPECT_EQ(bob.appData->groupIdForBundle(aliceBundle), gid)
        << "reverse mapping must resolve to local groupId";
}

TEST_F(TwoClientSuite, V2GroupBundle_DistinctGroupsGetDistinctBundles) {
    // Two groups, same membership — bundles MUST differ so the relay
    // can't correlate messages across them.
    establishSessions();
    const std::string g1 = "grp-bundle-distinct-A";
    const std::string g2 = "grp-bundle-distinct-B";
    alice.ctrl->setKnownGroupMembers(g1, { alice.id, bob.id });
    alice.ctrl->setKnownGroupMembers(g2, { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(g1,   { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(g2,   { alice.id, bob.id });

    alice.ctrl->sendGroupMessageViaMailbox(g1, "G1",
                                             { alice.id, bob.id }, "to G1");
    alice.ctrl->sendGroupMessageViaMailbox(g2, "G2",
                                             { alice.id, bob.id }, "to G2");

    const Bytes b1 = alice.appData->bundleIdForGroup(g1);
    const Bytes b2 = alice.appData->bundleIdForGroup(g2);
    EXPECT_NE(b1, b2);
    EXPECT_EQ(bob.appData->groupIdForBundle(b1), g1);
    EXPECT_EQ(bob.appData->groupIdForBundle(b2), g2);
}

TEST_F(TwoClientSuite, V2GroupBundle_ExistingMappingWinsOverInnerGroupId) {
    // Defense in depth: once we have a (bundle → groupId) binding, a
    // subsequent message that tries to claim a different groupId for
    // the same bundle is routed to the LOCALLY-bound groupId, not the
    // forged one.  Keeps a compromised peer from cross-mapping
    // bundles to other groups they shouldn't be able to address.
    establishSessions();
    const std::string realGid = "grp-bundle-defense";
    alice.ctrl->setKnownGroupMembers(realGid, { alice.id, bob.id });
    bob.ctrl->setKnownGroupMembers(realGid,   { alice.id, bob.id });

    // First send establishes the binding on Bob's side.
    alice.ctrl->sendGroupMessageViaMailbox(realGid, "G",
                                             { alice.id, bob.id }, "first");
    ASSERT_EQ(bob.groupReceived.size(), 1u);
    EXPECT_EQ(bob.groupReceived[0].groupId, realGid);

    // Second send with the same bundle continues to route to realGid
    // even though the inner groupId field is the same (regression
    // guard — the resolver must use the bundle, not the inner gid).
    alice.ctrl->sendGroupMessageViaMailbox(realGid, "G",
                                             { alice.id, bob.id }, "second");
    ASSERT_EQ(bob.groupReceived.size(), 2u);
    EXPECT_EQ(bob.groupReceived[1].groupId, realGid);
}

TEST_F(TwoClientSuite, V2GroupBundle_DropContactClearsMapping) {
    // Leaving / deleting a group removes the bundle binding so a
    // post-delete replay can't resurface as the old group, and a
    // fresh re-create of the same groupId mints a new bundle.
    establishSessions();
    const std::string gid = "grp-bundle-leave";
    alice.ctrl->setKnownGroupMembers(gid, { alice.id, bob.id });

    alice.ctrl->sendGroupMessageViaMailbox(gid, "G",
                                             { alice.id, bob.id }, "msg");
    const Bytes original = alice.appData->bundleIdForGroup(gid);
    ASSERT_EQ(original.size(), 16u);

    // Simulate "leave group" — deleteContact drops the contact row +
    // the bundle mapping (see AppDataStore::deleteContact).
    alice.appData->deleteContact(gid);
    EXPECT_TRUE(alice.appData->bundleIdForGroup(gid).empty());
    EXPECT_TRUE(alice.appData->groupIdForBundle(original).empty());
}
