// test_c_api.cpp — surface tests for the public C FFI.
//
// The mobile clients (iOS Swift, Android JNI) go through peer2pear.h, not
// the C++ classes directly.  This file pins the contract the FFI exposes,
// starting with the H4 audit fix:
//
//   * p2p_set_passphrase_v2 routes callers to the v5 unified Argon2id
//     derivation (one Argon2 call + HKDF) instead of the legacy per-key
//     Argon2 path that p2p_set_passphrase uses.  Mobile clients pinned
//     to the legacy API couldn't upgrade their identities.
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

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

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
// M3 audit fix: library-side strength floor.  Platform UIs should enforce
// stronger requirements before calling, but a caller that skips that step
// shouldn't be able to mint a one-character-passphrase identity.

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

// ── Round-trip: rename triggers onGroupRenamed when the control message
// bounces through the sender's own decrypt path.  The sender's
// ChatController wires its own sendSealedPayload → (in this single-
// context setup) the message goes nowhere because there's no wire, but
// the callback setter contract is pinned by the earlier tests.  Full
// bidirectional round-trip coverage lives in the E2E suite that stands
// up two ChatControllers with a mock relay — extending it to exercise
// the C API directly is blocked on plumbing p2p_platform through the
// mock harness (a separate piece of work).

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
