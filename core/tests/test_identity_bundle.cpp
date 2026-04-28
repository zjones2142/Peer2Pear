// test_identity_bundle.cpp — high-value security tests for
// the relay-mediated identity bundle path (Tier 1 of
// project_pq_messaging.md).
//
// The CryptoEngine sign/verify primitives + the canonical-message
// byte-exactness are covered in test_crypto_engine.cpp.  This
// binary covers the END-TO-END verify pipeline that runs inside
// `RelayClient::fetchIdentityBundle`'s callback when a peer's
// bundle arrives from the relay:
//
//   parse JSON → check ed25519_id_b64u matches request → decode
//   kem_pub + sig → verify sig under requested id → return kem_pub
//   (or empty on any failure).
//
// A buggy verifier here is a security-critical hole — a hostile
// relay could substitute a different bundle.  These tests inject
// crafted responses via a mock IHttpClient and verify the
// callback receives empty bytes for every tamper case.

#include "types.hpp"
#include "RelayClient.hpp"
#include "CryptoEngine.hpp"
#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

using p2p_test::makeTempDir;

// ── Minimal IHttpClient that lets each test pre-program the
// response to the next GET / POST and capture what was sent.

class ScriptedHttpClient : public IHttpClient {
public:
    // What the next get()/post() call should return.  Set per-test.
    Response nextGet;
    Response nextPost;

    // Captured request data for assertions.
    std::string lastGetUrl;
    std::string lastPostUrl;
    Bytes       lastPostBody;

    void post(const std::string& url, const Bytes& body,
              const Headers& /*headers*/, Callback cb) override {
        lastPostUrl  = url;
        lastPostBody = body;
        cb(nextPost);
    }
    void get(const std::string& url, const Headers& /*headers*/,
             Callback cb) override {
        lastGetUrl = url;
        cb(nextGet);
    }
};

// Minimal IWebSocket / Factory / Timer stubs — RelayClient's
// constructor needs them but the identity-bundle methods don't
// touch the WS / timer paths.

class NopWebSocket : public IWebSocket {
public:
    void open(const std::string& /*url*/) override {}
    void close() override {}
    bool isConnected() const override { return false; }
    bool isIdle()      const override { return true; }
    void sendTextMessage(const std::string& /*m*/) override {}
};

class NopWebSocketFactory : public IWebSocketFactory {
public:
    std::unique_ptr<IWebSocket> create() override {
        return std::make_unique<NopWebSocket>();
    }
};

class NopTimer : public ITimer {
public:
    void startSingleShot(int /*delayMs*/, std::function<void()> /*cb*/) override {}
    void stop() override {}
    bool isActive() const override { return false; }
};

class NopTimerFactory : public ITimerFactory {
public:
    std::unique_ptr<ITimer> create() override {
        return std::make_unique<NopTimer>();
    }
    void singleShot(int /*delayMs*/, std::function<void()> /*cb*/) override {}
};

// ── Test fixture ───────────────────────────────────────────────
//
// Each test:
//   1. Stands up a real CryptoEngine (so `signIdentityBundle` and
//      `verifyIdentityBundle` use real Ed25519).
//   2. Pre-signs a "good" bundle for a fictional peer.
//   3. Configures `ScriptedHttpClient` to return a (possibly
//      tampered) response.
//   4. Calls `RelayClient::fetchIdentityBundle` and asserts
//      whether the callback got the expected kem_pub or empty.

struct GoldenBundle {
    std::string idB64u;     // requested peer id (43 chars b64url)
    Bytes       kemPub;     // 1184 bytes
    uint64_t    tsDay;
    Bytes       sig;        // 64 bytes
};

GoldenBundle makeBundle(uint8_t kemFill) {
    // Generate a fresh Ed25519 keypair via libsodium for the
    // peer.  Sign a kem_pub of known fill so we can identify it
    // in callback assertions.
    Bytes pub(crypto_sign_PUBLICKEYBYTES, 0);
    Bytes priv(crypto_sign_SECRETKEYBYTES, 0);
    crypto_sign_keypair(pub.data(), priv.data());

    GoldenBundle b;
    b.idB64u = CryptoEngine::toBase64Url(pub);
    b.kemPub.assign(1184, kemFill);
    b.tsDay  = 20571;

    // Build canonical message + sign with libsodium (matches
    // CryptoEngine::signIdentityBundle byte-for-byte; covered by
    // test_crypto_engine).
    const std::string canonical =
        "P2P_IDENTITY_v1|" + b.idB64u + "|" +
        CryptoEngine::toBase64Url(b.kemPub) + "|" +
        std::to_string(b.tsDay);
    b.sig.assign(64, 0);
    crypto_sign_detached(
        b.sig.data(), nullptr,
        reinterpret_cast<const uint8_t*>(canonical.data()),
        canonical.size(),
        priv.data());
    return b;
}

std::string bundleToJson(const GoldenBundle& b) {
    json o = {
        {"v",                1},
        {"ed25519_id_b64u",  b.idB64u},
        {"kem_pub_b64u",     CryptoEngine::toBase64Url(b.kemPub)},
        {"ts_day",           b.tsDay},
        {"sig_b64u",         CryptoEngine::toBase64Url(b.sig)},
    };
    return o.dump();
}

IHttpClient::Response okJson(const std::string& body) {
    IHttpClient::Response r;
    r.status = 200;
    r.body.assign(body.begin(), body.end());
    return r;
}

struct Harness {
    std::string            dataDir;
    CryptoEngine           crypto;
    NopTimerFactory        timers;
    ScriptedHttpClient     http;
    NopWebSocketFactory    wsFactory;
    std::unique_ptr<RelayClient> relay;

    Harness() {
        if (sodium_init() < 0) ADD_FAILURE() << "sodium_init failed";
        dataDir = makeTempDir("p2p-id-bundle-test");
        crypto.setDataDir(dataDir);
        crypto.setPassphrase("identity-bundle-test-passphrase");
        EXPECT_NO_THROW(crypto.ensureIdentity());
        relay = std::make_unique<RelayClient>(wsFactory, http, timers, &crypto);
        relay->setRelayUrl("https://test-relay.invalid");
    }
    ~Harness() { fs::remove_all(dataDir); }
};

// Helper: synchronous fetch via RelayClient's async API.
// ScriptedHttpClient invokes the callback inline so we can
// just block on a captured optional.
Bytes syncFetch(Harness& h, const std::string& peerId) {
    std::optional<Bytes> got;
    h.relay->fetchIdentityBundle(peerId,
        [&](const Bytes& kp) { got = kp; });
    EXPECT_TRUE(got.has_value())
        << "callback should have been invoked synchronously by ScriptedHttpClient";
    return got.value_or(Bytes{});
}

}  // anonymous namespace

// ── Tests ──────────────────────────────────────────────────────────────

TEST(IdentityBundleFetch, HappyPath_StoresKemPubOnValidResponse) {
    Harness h;
    const GoldenBundle b = makeBundle(0xAA);
    h.http.nextGet = okJson(bundleToJson(b));

    const Bytes got = syncFetch(h, b.idB64u);
    EXPECT_EQ(got, b.kemPub);
    EXPECT_NE(h.http.lastGetUrl.find("/v1/identity/" + b.idB64u),
              std::string::npos);
}

TEST(IdentityBundleFetch, RejectsBadSignature) {
    Harness h;
    GoldenBundle b = makeBundle(0xAA);
    b.sig[0] ^= 0x01;   // flip one bit — sig now invalid

    h.http.nextGet = okJson(bundleToJson(b));
    EXPECT_TRUE(syncFetch(h, b.idB64u).empty())
        << "tampered sig must not pass through to caller";
}

TEST(IdentityBundleFetch, RejectsResponseIdMismatch) {
    Harness h;
    const GoldenBundle b1 = makeBundle(0xAA);   // we'll request this id
    const GoldenBundle b2 = makeBundle(0xBB);   // relay returns this bundle instead

    h.http.nextGet = okJson(bundleToJson(b2));
    EXPECT_TRUE(syncFetch(h, b1.idB64u).empty())
        << "response.ed25519_id_b64u != requested id must be rejected "
        << "(relay-substitution defense)";
}

TEST(IdentityBundleFetch, RejectsWrongKemPubSize) {
    Harness h;
    GoldenBundle b = makeBundle(0xAA);
    // Re-sign a bundle whose kem_pub is the WRONG SIZE.  The
    // signature will verify (canonical-message bytes are
    // self-consistent), but the verifier still rejects because
    // we explicitly check kem_pub.size() != 1184.
    Bytes pub(crypto_sign_PUBLICKEYBYTES, 0);
    Bytes priv(crypto_sign_SECRETKEYBYTES, 0);
    crypto_sign_keypair(pub.data(), priv.data());
    const std::string idB64u = CryptoEngine::toBase64Url(pub);
    Bytes shortKemPub(64, 0xAA);   // way too small
    const std::string canonical =
        "P2P_IDENTITY_v1|" + idB64u + "|" +
        CryptoEngine::toBase64Url(shortKemPub) + "|0";
    Bytes sig(64, 0);
    crypto_sign_detached(sig.data(), nullptr,
        reinterpret_cast<const uint8_t*>(canonical.data()),
        canonical.size(), priv.data());

    json o = {
        {"v",               1},
        {"ed25519_id_b64u", idB64u},
        {"kem_pub_b64u",    CryptoEngine::toBase64Url(shortKemPub)},
        {"ts_day",          0},
        {"sig_b64u",        CryptoEngine::toBase64Url(sig)},
    };
    h.http.nextGet = okJson(o.dump());
    EXPECT_TRUE(syncFetch(h, idB64u).empty())
        << "kem_pub size mismatch must be rejected even if sig is valid";
}

TEST(IdentityBundleFetch, RejectsServerError) {
    Harness h;
    h.http.nextGet.status = 500;
    h.http.nextGet.body   = {};
    EXPECT_TRUE(syncFetch(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").empty());
}

TEST(IdentityBundleFetch, RejectsNotFound) {
    Harness h;
    h.http.nextGet.status = 404;
    EXPECT_TRUE(syncFetch(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").empty());
}

TEST(IdentityBundleFetch, RejectsNetworkError) {
    Harness h;
    h.http.nextGet.error = "connection refused";
    h.http.nextGet.status = 0;
    EXPECT_TRUE(syncFetch(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").empty());
}

TEST(IdentityBundleFetch, RejectsMalformedJson) {
    Harness h;
    IHttpClient::Response r;
    r.status = 200;
    const std::string garbage = "not actually json {{{";
    r.body.assign(garbage.begin(), garbage.end());
    h.http.nextGet = r;
    EXPECT_TRUE(syncFetch(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").empty());
}

TEST(IdentityBundleFetch, RejectsMissingFields) {
    Harness h;
    // Valid JSON but missing kem_pub_b64u + sig_b64u entirely.
    IHttpClient::Response r;
    r.status = 200;
    const std::string body = R"({"v":1,"ed25519_id_b64u":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ts_day":1})";
    r.body.assign(body.begin(), body.end());
    h.http.nextGet = r;
    EXPECT_TRUE(syncFetch(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").empty());
}

// ── Publish path ───────────────────────────────────────────────

TEST(IdentityBundlePublish, SendsCorrectJsonAndReportsSuccess) {
    Harness h;
    const GoldenBundle b = makeBundle(0xAA);

    h.http.nextPost.status = 200;
    h.http.nextPost.body   = {};

    bool gotOk = false;
    h.relay->publishIdentityBundle(
        b.idB64u, b.kemPub, b.tsDay, b.sig,
        [&](bool ok) { gotOk = ok; });
    EXPECT_TRUE(gotOk);

    // Inspect captured POST body for wire-format correctness.
    const std::string body(h.http.lastPostBody.begin(),
                            h.http.lastPostBody.end());
    json sent = json::parse(body);
    EXPECT_EQ(sent["v"],                1);
    EXPECT_EQ(sent["ed25519_id_b64u"],  b.idB64u);
    EXPECT_EQ(sent["kem_pub_b64u"],     CryptoEngine::toBase64Url(b.kemPub));
    EXPECT_EQ(sent["ts_day"],           b.tsDay);
    EXPECT_EQ(sent["sig_b64u"],         CryptoEngine::toBase64Url(b.sig));
    EXPECT_NE(h.http.lastPostUrl.find("/v1/identity"),
              std::string::npos);
}

TEST(IdentityBundlePublish, ReportsFailureOnNon200) {
    Harness h;
    const GoldenBundle b = makeBundle(0xAA);

    h.http.nextPost.status = 400;
    h.http.nextPost.body.assign({'b', 'a', 'd'});

    bool gotOk = true;
    h.relay->publishIdentityBundle(
        b.idB64u, b.kemPub, b.tsDay, b.sig,
        [&](bool ok) { gotOk = ok; });
    EXPECT_FALSE(gotOk);
}

TEST(IdentityBundlePublish, ReportsFailureOnNetworkError) {
    Harness h;
    const GoldenBundle b = makeBundle(0xAA);

    h.http.nextPost.error  = "no route to host";
    h.http.nextPost.status = 0;

    bool gotOk = true;
    h.relay->publishIdentityBundle(
        b.idB64u, b.kemPub, b.tsDay, b.sig,
        [&](bool ok) { gotOk = ok; });
    EXPECT_FALSE(gotOk);
}
