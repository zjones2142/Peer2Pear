// test_c_api_e2e.cpp — Tier 7 end-to-end through the C FFI.
//
// test_e2e_two_clients.cpp exercises the same round-trips at the
// ChatController level.  This file pins them at the peer2pear.h
// boundary — the only surface iOS + Android ever see.
//
// Architecture: two p2p_context instances, each with its own
// p2p_platform vtable whose callbacks route through a shared
// MockRelay that lives in this file.
//
// Reentrancy note: every p2p_* FFI call takes the ctx's ctrlMu
// (C2 audit fix).  The platform vtable is invoked from *inside*
// those FFI entry points — so synchronously calling p2p_ws_on_*
// or p2p_http_response on the SAME ctx is a same-thread recursive
// mutex acquire (std::mutex is non-recursive → undefined behaviour
// / abort).  We therefore push every callback onto a per-platform
// delivery queue and `pump()` it after each FFI call; by then the
// entry point has released ctrlMu and the pump thread can acquire
// it cleanly.  Cross-ctx delivery (e.g. alice → bob) lands on bob's
// DIFFERENT ctrlMu and could in principle run inline, but we route
// it through the same queue for uniformity + to match real platform
// behaviour where WS deliveries are always async.

#include "peer2pear.h"
#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string makeTempDir(const char* tag) {
    (void)sodium_init();
    uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char buf[80];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7]);
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove_all(p);
    fs::create_directories(p);
    return p.string();
}

// ── Delivery queue ───────────────────────────────────────────────────────
// FIFO of closures to run on the main (test) thread.  Platform callbacks
// push, the test pumps.  Keeps everything single-threaded and
// deterministic — no sleep loops, no race conditions.

struct DeliveryQueue {
    std::mutex mu;
    std::deque<std::function<void()>> q;

    void push(std::function<void()> fn) {
        std::lock_guard<std::mutex> lk(mu);
        q.push_back(std::move(fn));
    }
    bool pop(std::function<void()>& out) {
        std::lock_guard<std::mutex> lk(mu);
        if (q.empty()) return false;
        out = std::move(q.front());
        q.pop_front();
        return true;
    }
    bool empty() {
        std::lock_guard<std::mutex> lk(mu);
        return q.empty();
    }
};

// ── Mock relay + per-context platform state ──────────────────────────────

struct MockPlatform;

struct MockRelay {
    std::mutex mu;
    std::map<std::string, MockPlatform*> peers;

    void registerPeer(const std::string& edPubB64u, MockPlatform* pl) {
        std::lock_guard<std::mutex> lk(mu);
        peers[edPubB64u] = pl;
    }

    MockPlatform* lookup(const std::string& edPubB64u) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = peers.find(edPubB64u);
        return it == peers.end() ? nullptr : it->second;
    }
};

struct MockPlatform {
    MockRelay*   relay   = nullptr;
    p2p_context* ctx     = nullptr;
    std::string  peerId;
    std::atomic<bool> connected{false};
    std::atomic<int>  nextReqId{1};
    DeliveryQueue queue;   // work headed back to this ctx
};

// ── Platform vtable callbacks ────────────────────────────────────────────
// Every one of these pushes work onto the platform's queue instead of
// calling p2p_* directly.  The test's pump() loop drains the queue
// after the FFI entry point returns and ctrlMu is released.

extern "C" {

void mockWsOpen(const char* /*url*/, void* pctx) {
    auto* mp = static_cast<MockPlatform*>(pctx);
    mp->queue.push([mp]() {
        mp->connected.store(true);
        p2p_ws_on_connected(mp->ctx);
    });
}
void mockWsClose(void* pctx) {
    auto* mp = static_cast<MockPlatform*>(pctx);
    mp->queue.push([mp]() {
        if (mp->connected.exchange(false)) {
            p2p_ws_on_disconnected(mp->ctx);
        }
    });
}
void mockWsSendText(const char* message, void* pctx) {
    // Client only sends auth JSON.  Synthesize auth_ok and queue it for
    // delivery back to the same ctx.
    auto* mp = static_cast<MockPlatform*>(pctx);
    (void)message;
    mp->queue.push([mp]() {
        nlohmann::json resp;
        resp["type"] = "auth_ok";
        const std::string body = resp.dump();
        p2p_ws_on_text(mp->ctx, body.c_str());
    });
}
int mockWsIsConnected(void* pctx) {
    return static_cast<MockPlatform*>(pctx)->connected.load() ? 1 : 0;
}
int mockWsIsIdle(void* pctx) {
    return static_cast<MockPlatform*>(pctx)->connected.load() ? 0 : 1;
}

// Relay wire format: byte 0 = 0x01, bytes 1-32 = recipient Ed25519 pub,
// bytes 33+ = sealed ciphertext.
int mockHttpPost(const char* url,
                 const uint8_t* body, int bodyLen,
                 const char** /*hKeys*/, const char** /*hVals*/,
                 int /*hCount*/,
                 void* pctx) {
    auto* mp = static_cast<MockPlatform*>(pctx);
    const int reqId = mp->nextReqId.fetch_add(1);
    std::string u = url ? url : "";

    if (u.find("/v1/send") != std::string::npos && body && bodyLen >= 33 &&
        body[0] == 0x01) {
        std::vector<uint8_t> edPub(body + 1, body + 33);
        std::string key = CryptoEngine::toBase64Url(edPub);
        MockPlatform* recipient = mp->relay->lookup(key);
        if (recipient && recipient->ctx) {
            std::vector<uint8_t> payload(body, body + bodyLen);
            recipient->queue.push([recipient, payload]() {
                if (!recipient->connected.load()) return;
                p2p_ws_on_binary(recipient->ctx,
                                 payload.data(),
                                 int(payload.size()));
            });
        }
    }
    // No p2p_http_response — CHttpClient's pending cb stays orphaned,
    // which is fine because neither the send nor the connect paths
    // block on the status code.
    return reqId;
}

}  // extern "C"

p2p_platform buildPlatform(MockPlatform* mp) {
    p2p_platform p{};
    p.ws_open         = &mockWsOpen;
    p.ws_close        = &mockWsClose;
    p.ws_send_text    = &mockWsSendText;
    p.ws_is_connected = &mockWsIsConnected;
    p.ws_is_idle      = &mockWsIsIdle;
    p.http_post       = &mockHttpPost;
    p.platform_ctx    = mp;
    return p;
}

}  // namespace

// ── Fixture ──────────────────────────────────────────────────────────────

class CApiE2ESuite : public ::testing::Test {
protected:
    struct Party {
        std::string                    dataDir;
        std::unique_ptr<MockPlatform>  platform;
        p2p_context*                   ctx = nullptr;
        std::string                    id;
    };

    std::unique_ptr<MockRelay> relay;
    Party alice;
    Party bob;

    // Per-party capture of observable state.
    struct Captured {
        std::vector<std::tuple<std::string /*from*/, std::string /*text*/>> messages;
        struct GM { std::string from, groupId, groupName, text; };
        std::vector<GM> groupMessages;
        std::vector<std::pair<std::string, std::string>> renamed;   // gid, newName
        std::vector<std::pair<std::string, std::string>> avatars;   // gid, b64
        struct ML {
            std::string from, groupId, groupName;
            std::vector<std::string> members;
        };
        std::vector<ML> memberLeft;
    };
    Captured aliceCap;
    Captured bobCap;

    void setupParty(Party& p, Captured* cap, const std::string& tag) {
        p.dataDir  = makeTempDir(("p2p-capi-e2e-" + tag).c_str());
        p.platform = std::make_unique<MockPlatform>();
        p.platform->relay = relay.get();

        p.ctx = p2p_create(p.dataDir.c_str(), buildPlatform(p.platform.get()));
        ASSERT_NE(p.ctx, nullptr);
        p.platform->ctx = p.ctx;

        ASSERT_EQ(p2p_set_passphrase_v2(p.ctx, (tag + "-pass-only-tests").c_str()), 0);

        const char* idC = p2p_my_id(p.ctx);
        ASSERT_NE(idC, nullptr);
        p.id = idC;
        ASSERT_EQ(p.id.size(), 43u);
        p.platform->peerId = p.id;

        p2p_set_relay_url(p.ctx, "wss://mock-relay.test");

        // Observers.  `ud` points at the Captured struct for this party.
        p2p_set_on_message(p.ctx, [](const char* from, const char* text,
                                     int64_t /*ts*/, const char* /*msgId*/,
                                     void* ud) {
            auto* c = static_cast<Captured*>(ud);
            c->messages.emplace_back(
                from ? from : "", text ? text : "");
        }, cap);

        p2p_set_on_group_message(p.ctx, [](const char* from, const char* gid,
                                            const char* gname, const char** /*members*/,
                                            const char* text, int64_t /*ts*/,
                                            const char* /*msgId*/, void* ud) {
            auto* c = static_cast<Captured*>(ud);
            c->groupMessages.push_back({
                from ? from : "",
                gid ? gid : "",
                gname ? gname : "",
                text ? text : ""});
        }, cap);

        p2p_set_on_group_renamed(p.ctx, [](const char* gid, const char* newName,
                                           void* ud) {
            auto* c = static_cast<Captured*>(ud);
            c->renamed.emplace_back(
                gid ? gid : "", newName ? newName : "");
        }, cap);

        p2p_set_on_group_avatar(p.ctx, [](const char* gid, const char* avatar,
                                          void* ud) {
            auto* c = static_cast<Captured*>(ud);
            c->avatars.emplace_back(
                gid ? gid : "", avatar ? avatar : "");
        }, cap);

        p2p_set_on_group_member_left(p.ctx, [](const char* from, const char* gid,
                                                const char* gname,
                                                const char** members,
                                                int64_t /*ts*/, const char* /*msgId*/,
                                                void* ud) {
            auto* c = static_cast<Captured*>(ud);
            Captured::ML ml;
            ml.from      = from ? from : "";
            ml.groupId   = gid ? gid : "";
            ml.groupName = gname ? gname : "";
            if (members) for (const char** q = members; *q; ++q) ml.members.emplace_back(*q);
            c->memberLeft.push_back(std::move(ml));
        }, cap);
    }

    // Run queued work until both parties are quiescent.  Each iteration
    // drains a snapshot of the queue so newly-enqueued work (follow-ups
    // from a running callback) gets processed on the next pass.  Caps
    // iterations so a bug that endlessly re-enqueues doesn't hang.
    void pumpAll() {
        for (int iter = 0; iter < 64; ++iter) {
            bool any = false;
            for (Party* party : { &alice, &bob }) {
                std::function<void()> fn;
                while (party->platform && party->platform->queue.pop(fn)) {
                    fn();
                    any = true;
                }
            }
            if (!any) return;
        }
        FAIL() << "pumpAll did not reach quiescence after 64 passes";
    }

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        relay = std::make_unique<MockRelay>();
        setupParty(alice, &aliceCap, "alice");
        setupParty(bob,   &bobCap,   "bob");

        relay->registerPeer(alice.id, alice.platform.get());
        relay->registerPeer(bob.id,   bob.platform.get());

        p2p_connect(alice.ctx);
        p2p_connect(bob.ctx);
        pumpAll();  // flush connect / auth_ok back to both ctxs
    }

    void TearDown() override {
        if (alice.ctx) { p2p_destroy(alice.ctx); alice.ctx = nullptr; }
        if (bob.ctx)   { p2p_destroy(bob.ctx);   bob.ctx   = nullptr; }
        relay.reset();
        std::error_code ec;
        fs::remove_all(alice.dataDir, ec);
        fs::remove_all(bob.dataDir,   ec);
    }

    // Convenience: send 1:1 text + pump.
    void sendText(Party& from, const std::string& toId, const std::string& text) {
        ASSERT_EQ(p2p_send_text(from.ctx, toId.c_str(), text.c_str()), 0);
        pumpAll();
    }

    // Helper: build a NULL-terminated member array from a vector of IDs.
    struct Members {
        std::vector<std::string> strings;
        std::vector<const char*> cArr;  // NULL-terminated
    };
    Members buildMembers(std::initializer_list<std::string> ids) {
        Members m;
        m.strings.assign(ids);
        m.cArr.reserve(ids.size() + 1);
        for (auto& s : m.strings) m.cArr.push_back(s.c_str());
        m.cArr.push_back(nullptr);
        return m;
    }
};

// ── 1. 1:1 text round-trip ───────────────────────────────────────────────

TEST_F(CApiE2ESuite, TextRoundTripAliceToBob) {
    sendText(alice, bob.id, "hello from alice");

    ASSERT_EQ(bobCap.messages.size(), 1u);
    EXPECT_EQ(std::get<0>(bobCap.messages[0]), alice.id);
    EXPECT_EQ(std::get<1>(bobCap.messages[0]), "hello from alice");
}

// ── 2. Group text round-trip via p2p_send_group_text ─────────────────────
// Also warms up the Noise session so the later tests can ride on an
// existing ratchet without re-bootstrapping each time.

TEST_F(CApiE2ESuite, GroupTextRoundTripAliceToBob) {
    sendText(alice, bob.id, "bootstrap");
    ASSERT_EQ(bobCap.messages.size(), 1u);

    const std::string gid = "test-group-1";
    const std::string gname = "Weekend Plans";
    auto mem = buildMembers({ bob.id });

    ASSERT_EQ(p2p_send_group_text(alice.ctx, gid.c_str(), gname.c_str(),
                                   mem.cArr.data(), "group hello"), 0);
    pumpAll();

    ASSERT_EQ(bobCap.groupMessages.size(), 1u);
    EXPECT_EQ(bobCap.groupMessages[0].from,      alice.id);
    EXPECT_EQ(bobCap.groupMessages[0].groupId,   gid);
    EXPECT_EQ(bobCap.groupMessages[0].groupName, gname);
    EXPECT_EQ(bobCap.groupMessages[0].text,      "group hello");
}

// Helper: pre-seed a group's roster on `party` via the C API.
// H2 audit-#2: control messages (rename / avatar / leave) are deny-by-
// default until the recipient's ChatController has learned the group's
// member set.  sendGroupText strips self from the declared members so
// the receiver's cold-bootstrap check fails; real clients persist
// their own roster and call p2p_set_known_group_members on startup.
// This helper mirrors that for tests.
static void seedGroup(p2p_context* ctx, const std::string& gid,
                      std::initializer_list<std::string> members) {
    std::vector<std::string> m(members);
    std::vector<const char*> cArr;
    cArr.reserve(m.size() + 1);
    for (auto& s : m) cArr.push_back(s.c_str());
    cArr.push_back(nullptr);
    p2p_set_known_group_members(ctx, gid.c_str(), cArr.data());
}

// ── 3. p2p_rename_group → recipient's on_group_renamed fires ────────────

TEST_F(CApiE2ESuite, GroupRenameDeliversToOtherSide) {
    sendText(alice, bob.id, "bootstrap");

    const std::string gid = "test-group-rename";
    auto mem = buildMembers({ bob.id });
    seedGroup(bob.ctx, gid, { alice.id, bob.id });

    ASSERT_EQ(p2p_rename_group(alice.ctx, gid.c_str(), "Planning Crew",
                                mem.cArr.data()), 0);
    pumpAll();

    ASSERT_EQ(bobCap.renamed.size(), 1u);
    EXPECT_EQ(bobCap.renamed[0].first,  gid);
    EXPECT_EQ(bobCap.renamed[0].second, "Planning Crew");
}

// ── 4. p2p_send_group_avatar → recipient's on_group_avatar fires ────────

TEST_F(CApiE2ESuite, GroupAvatarDeliversToOtherSide) {
    sendText(alice, bob.id, "bootstrap");

    const std::string gid = "test-group-avatar";
    const std::string avatarB64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=";
    auto mem = buildMembers({ bob.id });
    seedGroup(bob.ctx, gid, { alice.id, bob.id });

    ASSERT_EQ(p2p_send_group_avatar(alice.ctx, gid.c_str(),
                                     avatarB64.c_str(), mem.cArr.data()), 0);
    pumpAll();

    ASSERT_EQ(bobCap.avatars.size(), 1u);
    EXPECT_EQ(bobCap.avatars[0].first,  gid);
    EXPECT_EQ(bobCap.avatars[0].second, avatarB64);
}

// ── 5. p2p_leave_group → recipient's on_group_member_left fires ──────────

TEST_F(CApiE2ESuite, GroupLeaveDeliversToOtherSide) {
    sendText(alice, bob.id, "bootstrap");

    const std::string gid = "test-group-leave";
    auto mem = buildMembers({ bob.id });
    seedGroup(bob.ctx, gid, { alice.id, bob.id });

    ASSERT_EQ(p2p_leave_group(alice.ctx, gid.c_str(), "Some Group",
                               mem.cArr.data()), 0);
    pumpAll();

    ASSERT_EQ(bobCap.memberLeft.size(), 1u);
    EXPECT_EQ(bobCap.memberLeft[0].from,    alice.id);
    EXPECT_EQ(bobCap.memberLeft[0].groupId, gid);
}
