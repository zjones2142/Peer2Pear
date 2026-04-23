// test_c_api.cpp — surface tests for the public C FFI.
//
// The mobile clients (iOS Swift, Android JNI) go through peer2pear.h, not
// the C++ classes directly.  This file pins the contract the FFI exposes:
//
//   * p2p_set_passphrase_v2 routes callers to the v5 unified Argon2id
//     derivation (one Argon2 call + HKDF) instead of the legacy per-key
//     Argon2 path that p2p_set_passphrase uses.
//
// Goals (keep the surface small):
//   1. v2 succeeds, creates a v5 identity.json on disk, and p2p_my_id
//      returns a 43-char base64url peer id.
//   2. Calling v2 again on the same data_dir + passphrase in a fresh
//      context recovers the same peer id (identity persisted & the v2
//      code path unlocks it).
//   3. v2 with a wrong passphrase against an existing identity returns
//      non-zero rather than silently creating a new identity.
//   4. v2 rejects null / empty passphrase and a data_dir-less context.
//
// The platform vtable is zero-initialised — no WS / HTTP work happens
// during these tests, just identity bootstrapping.

#include "peer2pear.h"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <future>
#include <string>

namespace fs = std::filesystem;

namespace {

using p2p_test::makeTempDir;

// All-null platform is fine for identity-only tests — nothing in the
// passphrase path touches WS or HTTP.
p2p_platform nullPlatform() {
    p2p_platform p{};
    return p;
}

}  // namespace

// ── 1. Fresh data dir: v2 creates a v5 identity and yields a peer id ─────

TEST(CApi, SetPassphraseV2CreatesIdentityAndPeerId) {
    const std::string dir = makeTempDir("p2p-capi-fresh");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    ASSERT_EQ(p2p_set_passphrase_v2(ctx, "correct horse battery staple"), 0);

    const char* idC = p2p_my_id(ctx);
    ASSERT_NE(idC, nullptr);
    const std::string id = idC;
    EXPECT_EQ(id.size(), 43u) << "Ed25519 pub encodes to 43 chars unpadded base64url";
    EXPECT_TRUE(fs::exists(dir + "/keys/identity.json"));

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

// ── 2. Persistence: same data dir + same passphrase → same peer id ───────

TEST(CApi, SetPassphraseV2PersistsAndReloadsSamePeerId) {
    const std::string dir = makeTempDir("p2p-capi-persist");
    const std::string pass = "another-test-only-passphrase";

    std::string firstId;
    {
        p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(p2p_set_passphrase_v2(ctx, pass.c_str()), 0);
        firstId = p2p_my_id(ctx);
        ASSERT_EQ(firstId.size(), 43u);
        p2p_destroy(ctx);
    }
    {
        p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(p2p_set_passphrase_v2(ctx, pass.c_str()), 0)
            << "reopening the same data_dir with the same passphrase must succeed";
        EXPECT_EQ(std::string(p2p_my_id(ctx)), firstId);
        p2p_destroy(ctx);
    }

    fs::remove_all(dir);
}

// ── 3. Wrong passphrase against an existing identity returns non-zero ────
// If v2 silently minted a fresh identity on passphrase mismatch, a user
// who mistypes their passphrase would generate a new peer id and lose
// their conversation history.  Fail loudly instead.

TEST(CApi, SetPassphraseV2RejectsWrongPassphrase) {
    const std::string dir = makeTempDir("p2p-capi-wrongpass");

    {
        p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(p2p_set_passphrase_v2(ctx, "original-passphrase"), 0);
        p2p_destroy(ctx);
    }
    {
        p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
        ASSERT_NE(ctx, nullptr);
        EXPECT_NE(p2p_set_passphrase_v2(ctx, "totally-different-passphrase"), 0);
        p2p_destroy(ctx);
    }

    fs::remove_all(dir);
}

// ── 3b. Passphrase shorter than P2P_MIN_PASSPHRASE_BYTES is rejected ────
// Library-side strength floor.  Platform UIs should enforce stronger
// requirements before calling, but a caller that skips that step shouldn't
// be able to mint a one-character-passphrase identity.

TEST(CApi, SetPassphraseV2RejectsWeakPassphrase) {
    const std::string dir = makeTempDir("p2p-capi-weakpass");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    // Each of these is < P2P_MIN_PASSPHRASE_BYTES (8).
    const char* tooShort[] = { "a", "short", "1234567" };
    for (const char* s : tooShort) {
        EXPECT_NE(p2p_set_passphrase_v2(ctx, s), 0)
            << "expected rejection for passphrase \"" << s << "\" ("
            << std::strlen(s) << " bytes)";
    }

    // Exactly at the floor should be accepted (well, by length — this one
    // has no other failure mode in a fresh data_dir).
    EXPECT_EQ(p2p_set_passphrase_v2(ctx, "12345678"), 0);

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

// ── Group C API surface ────────────────────────────────────────────────
// The group action / callback surface exists so mobile clients can
// rename / leave / file-send / avatar / update-members in groups.
// Full round-trip (action → network → peer's callback) requires two
// contexts + a mock relay harness like test_e2e_two_clients.cpp — we
// do that in the ChatController-level tests.  At the C API layer we
// pin the contract: setters install without error, actions reject
// null/empty args with -1 and accept well-formed args with 0.

TEST(CApi, GroupCallbackSettersAreCallableAndSafe) {
    const std::string dir = makeTempDir("p2p-capi-grpcb");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(p2p_set_passphrase_v2(ctx, "test-only-passphrase"), 0);

    // Install each new callback — they must register without touching
    // any other state.  We don't invoke them here; this simply pins the
    // signatures against ABI drift.
    p2p_set_on_group_member_left(ctx,
        [](const char*, const char*, const char*, const char**,
           int64_t, const char*, void*) {}, nullptr);
    p2p_set_on_group_renamed(ctx,
        [](const char*, const char*, void*) {}, nullptr);
    p2p_set_on_group_avatar(ctx,
        [](const char*, const char*, void*) {}, nullptr);

    // Re-installing to nullptr clears the slot — must not crash.
    p2p_set_on_group_member_left(ctx, nullptr, nullptr);
    p2p_set_on_group_renamed(ctx, nullptr, nullptr);
    p2p_set_on_group_avatar(ctx, nullptr, nullptr);

    // A NULL context on any setter is a no-op (not a crash).
    p2p_set_on_group_member_left(nullptr, nullptr, nullptr);
    p2p_set_on_group_renamed(nullptr, nullptr, nullptr);
    p2p_set_on_group_avatar(nullptr, nullptr, nullptr);

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

TEST(CApi, GroupActionsValidateArguments) {
    const std::string dir = makeTempDir("p2p-capi-grpargs");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(p2p_set_passphrase_v2(ctx, "test-only-passphrase"), 0);

    const char* emptyMembers[] = { nullptr };
    const char* members[] = { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              nullptr };

    // Null ctx — every action must return its error sentinel (-1 / nullptr).
    EXPECT_EQ(p2p_rename_group(nullptr, "g", "new", emptyMembers), -1);
    EXPECT_EQ(p2p_leave_group(nullptr, "g", "n", emptyMembers), -1);
    EXPECT_EQ(p2p_send_group_avatar(nullptr, "g", "a", emptyMembers), -1);
    EXPECT_EQ(p2p_update_group_members(nullptr, "g", "n", emptyMembers), -1);
    EXPECT_EQ(p2p_send_group_file(nullptr, "g", "n", members, "f", "/tmp/x"),
              nullptr);

    // Null required arg → -1 / nullptr.  group_name is optional and
    // tolerated as NULL where documented; group_id + members are required.
    EXPECT_EQ(p2p_rename_group(ctx, nullptr, "new", members), -1);
    EXPECT_EQ(p2p_rename_group(ctx, "g", nullptr, members), -1);
    EXPECT_EQ(p2p_rename_group(ctx, "g", "new", nullptr), -1);

    EXPECT_EQ(p2p_leave_group(ctx, nullptr, "n", members), -1);
    EXPECT_EQ(p2p_leave_group(ctx, "g", "n", nullptr), -1);

    EXPECT_EQ(p2p_send_group_avatar(ctx, nullptr, "a", members), -1);
    EXPECT_EQ(p2p_send_group_avatar(ctx, "g", nullptr, members), -1);
    EXPECT_EQ(p2p_send_group_avatar(ctx, "g", "a", nullptr), -1);

    EXPECT_EQ(p2p_update_group_members(ctx, nullptr, "n", members), -1);
    EXPECT_EQ(p2p_update_group_members(ctx, "g", "n", nullptr), -1);

    EXPECT_EQ(p2p_send_group_file(ctx, nullptr, "n", members, "f", "/tmp/x"),
              nullptr);
    EXPECT_EQ(p2p_send_group_file(ctx, "g", "n", nullptr, "f", "/tmp/x"),
              nullptr);
    EXPECT_EQ(p2p_send_group_file(ctx, "g", "n", members, nullptr, "/tmp/x"),
              nullptr);
    EXPECT_EQ(p2p_send_group_file(ctx, "g", "n", members, "f", nullptr),
              nullptr);

    // Well-formed args with empty roster — rename/avatar/update_members
    // fire the control send loop with zero members (no-op, but the call
    // itself must succeed).  leave_group likewise.
    EXPECT_EQ(p2p_rename_group(ctx, "g", "new", emptyMembers), 0);
    EXPECT_EQ(p2p_leave_group(ctx, "g", "n", emptyMembers), 0);
    EXPECT_EQ(p2p_send_group_avatar(ctx, "g", "a", emptyMembers), 0);
    EXPECT_EQ(p2p_update_group_members(ctx, "g", "n", emptyMembers), 0);

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

// Two-context round-trips (action-on-alice → callback-on-bob) live in
// test_c_api_e2e.cpp; the surface tests above only pin the setter + arg
// contract of each new entry point.

// ── 4. Null / empty passphrase and missing data_dir are rejected ─────────

TEST(CApi, SetPassphraseV2RejectsBadArguments) {
    const std::string dir = makeTempDir("p2p-capi-badargs");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    EXPECT_NE(p2p_set_passphrase_v2(nullptr, "x"), 0);
    EXPECT_NE(p2p_set_passphrase_v2(ctx, nullptr), 0);
    EXPECT_NE(p2p_set_passphrase_v2(ctx, ""),      0);

    p2p_destroy(ctx);

    // A context created without a data_dir should also reject v2 — the salt
    // file has nowhere to live.  (p2p_create allows a NULL data_dir for now
    // because some future flows may defer it; lock that behavior down here
    // so no caller accidentally depends on it.)
    p2p_context* ctxNoDir = p2p_create(nullptr, nullPlatform());
    ASSERT_NE(ctxNoDir, nullptr);
    EXPECT_NE(p2p_set_passphrase_v2(ctxNoDir, "whatever"), 0);
    p2p_destroy(ctxNoDir);

    fs::remove_all(dir);
}

// ── 5. FFI null/length guards (Audit #3 C1) ──────────────────────────────
// A buggy or hostile platform adapter could pass (NULL, anything),
// (anything, negative), or (NULL, 0).  Constructing the inner Bytes
// vector under those conditions would be UB even on (nullptr, 0)
// because pointer arithmetic on null is undefined.  These tests pin
// the no-crash contract for both binary-WS and HTTP-response entry
// points.

TEST(CApi, WsOnBinaryRejectsMalformedInputs) {
    const std::string dir = makeTempDir("p2p-capi-fficrash");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    // Each of these would have been UB pre-fix; now they're silent no-ops.
    p2p_ws_on_binary(nullptr, nullptr, 0);
    p2p_ws_on_binary(ctx,     nullptr, 0);
    p2p_ws_on_binary(ctx,     nullptr, 16);     // null with positive len
    p2p_ws_on_binary(ctx,     nullptr, -1);     // null + negative
    const uint8_t buf[1] = {0};
    p2p_ws_on_binary(ctx,     buf,     -1);     // valid ptr + negative
    p2p_ws_on_binary(ctx,     buf,     0);      // empty frame, valid ptr

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

// Audit #3 test gap: p2p_app_load_contacts must not deadlock if its
// callback re-enters another p2p_app_* function.  The fix snapshots
// the rows under ctrlMu and releases before firing callbacks.  A
// regression (moving the callback back inside the lock) deadlocks
// here because std::mutex is non-recursive; we bound the call with
// a watchdog future.
struct ReentrancyState {
    p2p_context* ctx;
    int          count;
};

extern "C" void deadlockProbeCb(const char* peer_id,
                                 const char* name,
                                 const char* subtitle,
                                 const char* const* keys,
                                 int is_blocked,
                                 int is_group,
                                 const char* group_id,
                                 const char* avatar_b64,
                                 int64_t last_active_secs,
                                 int in_address_book,
                                 void* ud)
{
    (void)name; (void)subtitle; (void)keys; (void)is_blocked;
    (void)is_group; (void)group_id; (void)avatar_b64;
    (void)last_active_secs; (void)in_address_book;
    auto* s = static_cast<ReentrancyState*>(ud);
    // Re-enter the C API from inside the callback.  A non-recursive
    // ctrlMu held across the callback would deadlock here.  Use
    // p2p_app_save_contact — a no-op semantic update (same row)
    // that still grabs ctrlMu and exercises the reentrant path.
    const char* noKeys[] = {nullptr};
    (void)p2p_app_save_contact(s->ctx, peer_id, "Alice-updated", "",
                                noKeys, 0, 0, "", "", 0, 1);
    s->count++;
}

TEST(CApi, LoadContactsCallbackReentrancyDoesNotDeadlock) {
    const std::string dir = makeTempDir("p2p-capi-reentrant");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(p2p_set_passphrase_v2(ctx, "testpass"), 0);

    // Seed three contacts so the callback fires multiple times.
    const char* keys[] = {nullptr};
    p2p_app_save_contact(ctx, "peer1", "Alice", "", keys, 0, 0, "", "", 0, 1);
    p2p_app_save_contact(ctx, "peer2", "Bob",   "", keys, 0, 0, "", "", 0, 1);
    p2p_app_save_contact(ctx, "peer3", "Carol", "", keys, 0, 0, "", "", 0, 1);

    ReentrancyState state{ctx, 0};
    auto fut = std::async(std::launch::async, [&]() {
        p2p_app_load_contacts(ctx, &deadlockProbeCb, &state);
    });
    // 5 s is generous — a deadlock here would never resolve.
    auto status = fut.wait_for(std::chrono::seconds(5));
    ASSERT_EQ(status, std::future_status::ready)
        << "p2p_app_load_contacts deadlocked on reentrant callback";

    EXPECT_EQ(state.count, 3) << "callback fired for every contact";

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

// Audit #3 test gap: p2p_check_presence + p2p_subscribe_presence must
// reject count<0 without hitting the reserve(size_t) underflow (which
// would allocate ~SIZE_MAX bytes on a 64-bit host).  Also pins the
// count=0 no-op.
TEST(CApi, PresenceRejectsNegativeAndZeroCount) {
    const std::string dir = makeTempDir("p2p-capi-presence");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    const char* peerIds[] = {"alice", "bob"};

    // Each of these would have underflowed reserve() pre-fix.  The
    // C API accepts null peer_ids as "ignore the rest" too.
    p2p_check_presence(nullptr, peerIds, 2);
    p2p_check_presence(ctx, nullptr, 2);
    p2p_check_presence(ctx, peerIds, -1);
    p2p_check_presence(ctx, peerIds, 0);
    p2p_check_presence(ctx, peerIds, -2147483648); // INT_MIN

    p2p_subscribe_presence(nullptr, peerIds, 2);
    p2p_subscribe_presence(ctx, nullptr, 2);
    p2p_subscribe_presence(ctx, peerIds, -1);
    p2p_subscribe_presence(ctx, peerIds, 0);
    p2p_subscribe_presence(ctx, peerIds, -1000000);

    p2p_destroy(ctx);
    fs::remove_all(dir);
}

TEST(CApi, HttpResponseRejectsMalformedInputs) {
    const std::string dir = makeTempDir("p2p-capi-httpcrash");
    p2p_context* ctx = p2p_create(dir.c_str(), nullPlatform());
    ASSERT_NE(ctx, nullptr);

    // No request was ever issued, so the request_id won't match — the
    // downstream onResponse() will look it up + bail.  But the
    // pre-lookup boundary guards in p2p_http_response are what we're
    // pinning here: malformed (body, body_len) must not crash.
    p2p_http_response(nullptr, 0, 200, nullptr, 0,    nullptr);
    p2p_http_response(ctx,     0, 200, nullptr, 0,    nullptr);
    p2p_http_response(ctx,     0, 200, nullptr, 16,   nullptr);   // null + positive
    p2p_http_response(ctx,     0, 500, nullptr, -1,   "boom");    // null + negative
    const uint8_t body[1] = {0};
    p2p_http_response(ctx,     0, 200, body,    -1,   nullptr);   // valid ptr + neg
    p2p_http_response(ctx,     0, 200, body,    0,    nullptr);   // empty body OK

    p2p_destroy(ctx);
    fs::remove_all(dir);
}
