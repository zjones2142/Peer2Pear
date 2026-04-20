// test_e2e_two_clients.cpp — Tier 7: end-to-end round-trip with a mock relay.
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
// future regression in *any* of the earlier-tier modules is most likely
// to show up as the user-visible failure "the message didn't arrive."

#include "ChatController.hpp"
#include "CryptoEngine.hpp"
#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"
#include "SqlCipherDb.hpp"

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
using Bytes = std::vector<uint8_t>;

namespace {

// Temp-path helper consistent with the other test binaries.
std::string makeTempPath(const char* tag, const char* suffix) {
    (void)sodium_init();
    uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char buf[80];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x%s",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7], suffix);
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove_all(p);
    return p.string();
}

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
        std::unique_ptr<MockWebSocket>   ws;
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
    };

    std::unique_ptr<MockRelay> relay;
    Party alice;
    Party bob;

    void setupParty(Party& p, const std::string& tag) {
        p.dataDir = makeTempPath(("p2p-e2e-id-" + tag).c_str(), "");
        fs::create_directories(p.dataDir);

        p.ws     = std::make_unique<MockWebSocket>(relay.get());
        p.http   = std::make_unique<MockHttpClient>(relay.get());
        p.timers = std::make_unique<MockTimerFactory>();
        p.ctrl   = std::make_unique<ChatController>(*p.ws, *p.http, *p.timers);

        p.ctrl->setDataDir(p.dataDir);
        p.ctrl->setPassphrase(tag + "-test-only-passphrase");
        p.id = p.ctrl->myIdB64u();

        // Fresh per-party DB (SQLCipher-encrypted, at-rest key is random
        // per-test — we don't care about persistence semantics here).
        p.dbPath = makeTempPath(("p2p-e2e-db-" + tag).c_str(), ".db");
        p.db     = std::make_unique<SqlCipherDb>();
        SqlCipherDb::Bytes dbKey(32);
        randombytes_buf(dbKey.data(), dbKey.size());
        ASSERT_TRUE(p.db->open(p.dbPath, dbKey)) << p.db->lastError();
        p.ctrl->setDatabase(*p.db);

        // ChatController drives RelayClient; setRelayUrl is required or
        // the HTTP paths it builds won't have a host.
        p.ctrl->setRelayUrl("wss://mock-relay.test");

        p.ctrl->onMessageReceived = [&p](const std::string& from,
                                          const std::string& text,
                                          int64_t ts,
                                          const std::string& msgId) {
            p.received.push_back({from, text, ts, msgId});
        };
    }

    void connectBoth() {
        // Register peers by id BEFORE they connect, so auth + any immediate
        // queued envelopes can be routed.
        relay->registerPeer(alice.id, alice.ws.get());
        relay->registerPeer(bob.id,   bob.ws.get());

        alice.ctrl->connectToRelay();  // mock WS -> auth -> auth_ok inline
        bob.ctrl->connectToRelay();

        ASSERT_TRUE(alice.ctrl->relay().isConnected());
        ASSERT_TRUE(bob.ctrl->relay().isConnected());
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
// the envelopeId field baked into the sealed envelope (Fix #2).

TEST_F(TwoClientSuite, ReplayedEnvelopeDeduped) {
    connectBoth();

    relay->setDeliverMultiplier(2);  // every envelope lands twice
    alice.ctrl->sendText(bob.id, "deliver me once, please");

    ASSERT_EQ(bob.received.size(), 1u)
        << "envelope dedup on envelopeId should suppress the duplicate delivery";
    EXPECT_EQ(bob.received[0].text, "deliver me once, please");
}

// ── 3b. Replay across app restart is dropped (H5 audit fix) ─────────────
// Before the fix, the envelope-ID dedup cache lived only in RAM — a relay
// that stored sealed envelopes could replay them after Bob restarted and
// his cache was cold.  The seen_envelopes SQLCipher table now makes the
// dedup survive restart.  Exercise it end-to-end: send a message, record
// the envelope bytes, rebuild Bob's ChatController on the same DB +
// identity, and re-inject the captured envelope.  Bob's message callback
// must NOT fire a second time.

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
    bob.ctrl.reset();

    // Rebuild Bob's controller on the same data dir + same DB + same WS.
    // The DB pointer is still valid because we kept bob.db alive.
    bob.ctrl = std::make_unique<ChatController>(*bob.ws, *bob.http, *bob.timers);
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
    relay->registerPeer(bob.id, bob.ws.get());
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
    {
        SqlCipherQuery q(*alice.db);
        ASSERT_TRUE(q.prepare(
            "UPDATE verified_peers SET verified_fingerprint = :fp"
            " WHERE peer_id = :pid;"));
        q.bindValue(":fp", Bytes(32, 0x11));  // definitely not the real FP
        q.bindValue(":pid", bob.id);
        ASSERT_TRUE(q.exec());
    }
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

    // Corrupt Alice's stored fingerprint for Bob.
    {
        SqlCipherQuery q(*alice.db);
        ASSERT_TRUE(q.prepare(
            "UPDATE verified_peers SET verified_fingerprint = :fp"
            " WHERE peer_id = :pid;"));
        q.bindValue(":fp", Bytes(32, 0x22));
        q.bindValue(":pid", bob.id);
        ASSERT_TRUE(q.exec());
    }

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
