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
