// test_relay_cover_traffic.cpp — cover traffic during silence.
//
// RelayClient::sendCoverEnvelope must not return early when no contacts
// are online — a relay operator observing a sudden drop to zero outgoing
// envelopes could infer "all this user's contacts just went offline."
// The fix is to self-address the cover packet so the outbound rate stays
// constant regardless of peer state.
//
// This binary wires a real RelayClient directly (not via ChatController)
// to a minimal set of mocks:
//   - FireableTimerFactory captures pending callbacks so the test can
//     drive the cover timer deterministically (MockTimer in the E2E
//     binary no-ops, which is fine there but kills this test).
//   - CapturingHttpClient records every POST body so we can inspect the
//     envelope the client *would* have put on the wire.
//   - SimpleWebSocket completes the auth handshake inline.
//
// The single test enables cover traffic, fires the timer with zero
// known peers, and asserts the captured envelope is self-addressed.

#include "RelayClient.hpp"
#include "CryptoEngine.hpp"
#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

namespace {

using p2p_test::makeTempDir;

// ── Fireable timer ──────────────────────────────────────────────────────
// Stores the most-recently-scheduled callback; fire() invokes it inline.
// Shared state lives in the factory so a test can drive the next pending
// callback regardless of which ITimer instance it came from.

struct TimerPoolState {
    std::deque<std::function<void()>> pending;
};

class FireableTimer : public ITimer {
public:
    explicit FireableTimer(TimerPoolState* pool) : m_pool(pool) {}

    void startSingleShot(int /*delayMs*/, std::function<void()> cb) override {
        m_cb = std::move(cb);
        m_active = true;
        m_pool->pending.push_back([this] {
            if (!m_active || !m_cb) return;
            m_active = false;
            auto cb = std::move(m_cb);
            cb();
        });
    }
    void stop() override { m_active = false; m_cb = nullptr; }
    bool isActive() const override { return m_active; }

private:
    TimerPoolState*       m_pool = nullptr;
    std::function<void()> m_cb;
    bool                  m_active = false;
};

class FireableTimerFactory : public ITimerFactory {
public:
    std::unique_ptr<ITimer> create() override {
        return std::make_unique<FireableTimer>(&m_pool);
    }
    void singleShot(int /*delayMs*/, std::function<void()> cb) override {
        m_pool.pending.push_back(std::move(cb));
    }

    // Fire the next scheduled callback.  Returns false if the queue is
    // empty.  Each fire may itself enqueue more callbacks (e.g. the cover
    // timer reschedules itself after each send).
    bool fireNext() {
        if (m_pool.pending.empty()) return false;
        auto cb = std::move(m_pool.pending.front());
        m_pool.pending.pop_front();
        if (cb) cb();
        return true;
    }

    size_t pendingCount() const { return m_pool.pending.size(); }

private:
    TimerPoolState m_pool;
};

// ── Capturing HTTP client ───────────────────────────────────────────────

class CapturingHttpClient : public IHttpClient {
public:
    struct Post { std::string url; Bytes body; };
    std::vector<Post> posts;

    void post(const std::string& url, const Bytes& body,
              const Headers& /*headers*/, Callback cb) override {
        posts.push_back({url, body});
        Response r; r.status = 200;
        cb(r);
    }
    void get(const std::string& /*url*/, const Headers& /*headers*/,
             Callback cb) override {
        Response r; r.status = 404;  // no relay_info → skip onion caching
        cb(r);
    }
};

// ── Simple WebSocket: auth_ok on any text frame ─────────────────────────

class SimpleWebSocket : public IWebSocket {
public:
    std::string lastOpenUrl;
    std::vector<std::string> sentTexts;  // captures outbound text frames

    void open(const std::string& url) override {
        lastOpenUrl = url;
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
    bool isIdle() const override { return !m_connected; }

    void sendTextMessage(const std::string& message) override {
        sentTexts.push_back(message);
        // Only the first text frame is auth — subsequent frames
        // (push_register, presence_query, etc.) don't need a reply.
        if (m_authReplied) return;
        m_authReplied = true;
        nlohmann::json r;
        r["type"] = "auth_ok";
        if (onTextMessage) onTextMessage(r.dump());
    }

private:
    bool m_connected = false;
    bool m_authReplied = false;
};

}  // namespace

// ── The test ────────────────────────────────────────────────────────────

TEST(RelayCoverTraffic, SelfAddressedFallbackWhenNoPeersOnline) {
    ASSERT_GE(sodium_init(), 0);

    // Identity needs to be real — RelayClient signs the auth tuple and
    // uses identityPub() for the self-cover fallback.
    const std::string dataDir = makeTempDir("p2p-cover");
    CryptoEngine crypto;
    crypto.setDataDir(dataDir);
    crypto.setPassphrase("cover-test-only-passphrase");
    ASSERT_NO_THROW(crypto.ensureIdentity());
    const Bytes selfEdPub = crypto.identityPub();
    ASSERT_EQ(selfEdPub.size(), 32u);

    FireableTimerFactory timers;
    CapturingHttpClient  http;
    SimpleWebSocket      ws;
    RelayClient          relay(ws, http, timers, &crypto);

    relay.setRelayUrl("wss://mock-relay.test");

    // Connect + authenticate inline — the SimpleWebSocket replies auth_ok
    // on the first text frame.
    relay.connectToRelay();
    ASSERT_TRUE(relay.isConnected());

    // Known-peers list is empty by construction — without the self-
    // address fallback the cover-traffic path would silently drop every
    // cover packet.
    http.posts.clear();  // discard anything queued by refreshRelayInfo etc.

    relay.setCoverTrafficInterval(1);  // arms the cover timer

    // The first fire of the cover timer must emit a self-addressed
    // envelope.  Subsequent fires may enqueue more; we only need the
    // first POST to observe the fallback.
    while (timers.fireNext() && http.posts.empty()) { /* drain */ }
    ASSERT_FALSE(http.posts.empty())
        << "cover traffic produced no POST — self-address fallback missing";

    const Bytes& body = http.posts.front().body;
    ASSERT_GT(body.size(), 33u) << "envelope too short to contain a routing header";
    EXPECT_EQ(body[0], 0x01) << "relay envelopes start with 0x01 routing version";

    const Bytes routedTo(body.begin() + 1, body.begin() + 33);
    EXPECT_EQ(routedTo, selfEdPub)
        << "with zero online peers, cover envelope must be self-addressed";

    // Stop the cover timer so teardown doesn't leave callbacks pending.
    relay.setCoverTrafficInterval(0);
    fs::remove_all(dataDir);
}

// Arch-review #9: cover traffic must cover all three padding buckets.
// Pre-fix cover only hit 2 KiB and 256 KiB, which meant a relay
// observing "this client never emits 16 KiB envelopes" could
// fingerprint a user who never sends medium-sized real traffic.
// This test runs enough cover fires to see every bucket, then
// verifies each one showed up at least once at privacy level 2
// (uniform mode) and each one showed up at privacy level 1
// (bandwidth-biased mode still allocates the medium bucket 30%).
TEST(RelayCoverTraffic, CoverHitsAllThreePaddingBucketsAtBothLevels) {
    ASSERT_GE(sodium_init(), 0);

    constexpr size_t kBucketSmall  =   2 * 1024;
    constexpr size_t kBucketMedium =  16 * 1024;
    constexpr size_t kBucketLarge  = 256 * 1024;

    auto runLevel = [&](int level) {
        const std::string dataDir = makeTempDir("p2p-cover-dist");
        CryptoEngine crypto;
        crypto.setDataDir(dataDir);
        crypto.setPassphrase("cover-dist-passphrase");
        ASSERT_NO_THROW(crypto.ensureIdentity());

        FireableTimerFactory timers;
        CapturingHttpClient  http;
        SimpleWebSocket      ws;
        RelayClient          relay(ws, http, timers, &crypto);
        relay.setRelayUrl("wss://mock-relay.test");
        relay.connectToRelay();
        ASSERT_TRUE(relay.isConnected());
        http.posts.clear();
        relay.setPrivacyLevel(level);

        // Fire ~300 cover events; with either mode, probabilities
        // make a missed bucket vanishingly unlikely (biased mode has
        // 10% large → P(miss) ≈ 0.9^300 ≈ 10^-14).
        size_t smallCount = 0, mediumCount = 0, largeCount = 0;
        for (int i = 0; i < 300; ++i) {
            if (!timers.fireNext()) break;
        }
        for (const auto& p : http.posts) {
            switch (p.body.size()) {
                case kBucketSmall:  ++smallCount; break;
                case kBucketMedium: ++mediumCount; break;
                case kBucketLarge:  ++largeCount; break;
                default: break;  // retry queue / other — ignore
            }
        }
        EXPECT_GT(smallCount,  0u) << "level " << level << ": small bucket never hit";
        EXPECT_GT(mediumCount, 0u) << "level " << level << ": medium bucket never hit";
        EXPECT_GT(largeCount,  0u) << "level " << level << ": large bucket never hit";

        relay.setPrivacyLevel(0);  // stops the cover timer
        fs::remove_all(dataDir);
    };

    runLevel(1);
    runLevel(2);
}

// ── setRelayUrl refuses non-TLS URLs ─────────────────────────────────────
// An http:// or ws:// URL would silently downgrade the transport to
// cleartext.  Only https:// / wss:// are accepted for production URLs;
// http:// / ws:// on localhost is tolerated for dev convenience.
//
// The observable: connectToRelay() asks the IWebSocket to open the
// configured URL.  A rejected URL leaves m_relayUrl empty, so ws.open
// is called with an empty-ish path — we check the scheme on what the
// ws actually received.

TEST(RelayUrlScheme, RejectsNonTlsUrls) {
    struct Case { const char* url; bool shouldAccept; };
    const Case cases[] = {
        {"https://relay.peer2pear.org",   true },
        {"wss://relay.peer2pear.org",     true },
        {"http://relay.peer2pear.org",    false},  // silent downgrade
        {"ws://relay.peer2pear.org",      false},
        {"ftp://relay.peer2pear.org",     false},
        {"http://localhost:8443",         true },  // dev exception
        {"ws://127.0.0.1:8443",           true },
    };

    for (const auto& c : cases) {
        FireableTimerFactory timers;
        CapturingHttpClient  http;
        SimpleWebSocket      ws;
        CryptoEngine         crypto;
        RelayClient          relay(ws, http, timers, &crypto);

        // Detach the onConnected callback so RelayClient::authenticate()
        // never runs (it would try to sign with an uninitialised identity
        // and crash).  We only need to observe the URL passed to open().
        ws.onConnected = nullptr;

        relay.setRelayUrl(c.url);
        relay.connectToRelay();

        const bool sawTlsOpen =
            ws.lastOpenUrl.rfind("wss://",  0) == 0 ||
            ws.lastOpenUrl.rfind("https://", 0) == 0;
        const bool sawAnyOpen = !ws.lastOpenUrl.empty();
        const bool sawDevOpen =
            ws.lastOpenUrl.rfind("ws://localhost",  0) == 0 ||
            ws.lastOpenUrl.rfind("ws://127.0.0.1",  0) == 0 ||
            ws.lastOpenUrl.rfind("http://localhost", 0) == 0;

        if (c.shouldAccept) {
            EXPECT_TRUE(sawAnyOpen) << "accepted url=\"" << c.url << "\" but WS.open never fired";
            EXPECT_TRUE(sawTlsOpen || sawDevOpen)
                << "accepted url=\"" << c.url << "\" produced ws.open(\""
                << ws.lastOpenUrl << "\")";
        } else {
            // A rejected URL leaves m_relayUrl empty.  connectToRelay
            // would then ws.open("ws:///v1/receive") or similar path-
            // only garbage — we want NO host in the opened URL.
            const bool hostlessOrEmpty =
                ws.lastOpenUrl.empty() ||
                ws.lastOpenUrl.find("://") == std::string::npos ||
                ws.lastOpenUrl.find("://relay.peer2pear.org") == std::string::npos;
            EXPECT_TRUE(hostlessOrEmpty)
                << "rejected url=\"" << c.url
                << "\" leaked through to ws.open(\"" << ws.lastOpenUrl << "\")";
        }
    }
}

// Audit #3 test gap: push token registration E2E.  A call to
// RelayClient::registerPushToken on a connected relay must produce
// exactly one push_register text frame with the right shape.  An
// unconnected client should cache the token and replay it on the
// next auth_ok (separate concern — tested inside RelayClient's
// auth path; this test only pins the connected path).
TEST(PushRegistration, SendsPushRegisterFrameOnConnectedRelay) {
    ASSERT_GE(sodium_init(), 0);

    const std::string dataDir = makeTempDir("p2p-push-e2e");
    CryptoEngine crypto;
    crypto.setDataDir(dataDir);
    crypto.setPassphrase("push-test-passphrase");
    ASSERT_NO_THROW(crypto.ensureIdentity());

    FireableTimerFactory timers;
    CapturingHttpClient  http;
    SimpleWebSocket      ws;
    RelayClient          relay(ws, http, timers, &crypto);

    relay.setRelayUrl("wss://mock-relay.test");
    relay.connectToRelay();
    ASSERT_TRUE(relay.isConnected());

    // Clear the auth frame so we can find the push_register frame alone.
    const size_t framesBeforePush = ws.sentTexts.size();

    relay.registerPushToken("ios", "deadbeefcafef00d");

    ASSERT_GT(ws.sentTexts.size(), framesBeforePush)
        << "registerPushToken did not send a frame while connected";

    // The newest frame must be the push_register payload with the
    // right platform + token.
    const std::string& pushFrame = ws.sentTexts.back();
    auto j = nlohmann::json::parse(pushFrame);
    EXPECT_EQ(j.value("type",     std::string()), "push_register");
    EXPECT_EQ(j.value("platform", std::string()), "ios");
    EXPECT_EQ(j.value("token",    std::string()), "deadbeefcafef00d");

    // Empty token → unregister.  Also goes on the wire as push_register
    // with empty token (relay interprets empty as delete).
    relay.registerPushToken("ios", "");
    const std::string& unregFrame = ws.sentTexts.back();
    auto jEmpty = nlohmann::json::parse(unregFrame);
    EXPECT_EQ(jEmpty.value("type",     std::string()), "push_register");
    EXPECT_EQ(jEmpty.value("token",    std::string()), "");

    fs::remove_all(dataDir);
}
