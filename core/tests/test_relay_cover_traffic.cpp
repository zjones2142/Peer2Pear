// test_relay_cover_traffic.cpp — M5 audit: cover traffic during silence.
//
// Before the fix, RelayClient::sendCoverEnvelope returned early when no
// contacts were online — a relay operator observing the sudden drop to
// zero outgoing envelopes could infer "all this user's contacts just
// went offline."  The M5 recommendation is to self-address the cover
// packet so the outbound rate stays constant regardless of peer state.
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

std::string makeTempDir(const char* tag) {
    (void)sodium_init();
    uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7]);
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove_all(p);
    fs::create_directories(p);
    return p.string();
}

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
    bool isIdle() const override { return !m_connected; }

    void sendTextMessage(const std::string& /*message*/) override {
        nlohmann::json r;
        r["type"] = "auth_ok";
        if (onTextMessage) onTextMessage(r.dump());
    }

private:
    bool m_connected = false;
};

}  // namespace

// ── The test ────────────────────────────────────────────────────────────

TEST(RelayCoverTraffic, SelfAddressedFallbackWhenNoPeersOnline) {
    ASSERT_GE(sodium_init(), 0);

    // Identity needs to be real — RelayClient signs the auth tuple and
    // uses identityPub() for the M5 self-cover fallback.
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

    // Known-peers list is empty by construction — the M5 pre-fix path
    // would silently drop every cover packet.
    http.posts.clear();  // discard anything queued by refreshRelayInfo etc.

    relay.setCoverTrafficInterval(1);  // arms the cover timer

    // The first fire of the cover timer must emit a self-addressed
    // envelope.  Subsequent fires may enqueue more; we only need the
    // first POST to observe the fix.
    while (timers.fireNext() && http.posts.empty()) { /* drain */ }
    ASSERT_FALSE(http.posts.empty())
        << "cover traffic produced no POST — M5 fallback missing";

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
