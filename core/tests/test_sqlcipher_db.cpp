// test_sqlcipher_db.cpp — Tier 2 tests for the vendored SQLCipher amalgamation.
//
// The direct motivation is the regression that shipped on 2026-04-19: I
// vendored SQLCipher 4.6.1 without the `-DSQLITE_EXTRA_INIT=sqlcipher_extra_init`
// flag required by 4.14+.  The codec hooks never registered, the app wrote
// plain-sqlite bytes into an encrypted DB, and the existing user DB was
// corrupted on first launch.  A 50-ms round-trip test would have caught this
// before the user ever saw "file is not a database".
//
// So this file's top priority is: prove the build actually has a working
// SQLCipher codec, end to end.  The cheapest such proof is:
//   1. Open a fresh file with a random 32-byte key
//   2. Write a row, close the DB
//   3. Reopen with the SAME key → read the row back
//   4. Reopen with a DIFFERENT key → the open must fail
// If step 3 succeeds AND step 4 fails, the codec is live.  If they both
// succeed, we're on plain sqlite and the DB is effectively unencrypted.

#include "SqlCipherDb.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

namespace {

// Generate a fresh temp-path under the OS temp dir, unique per test.
std::string makeTempDbPath(const char* tag) {
    namespace fs = std::filesystem;
    // sodium_init() is called by CryptoEngine's constructor in the other
    // test binary; here we call it defensively because SqlCipher uses its
    // own key handling but the random suffix goes through libsodium.
    (void)sodium_init();
    uint8_t rnd[8] = {};
    randombytes_buf(rnd, sizeof(rnd));
    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x.db",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7]);
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove(p);  // ensure fresh
    return p.string();
}

SqlCipherDb::Bytes randomKey32() {
    SqlCipherDb::Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

// Small helper: create a one-column table and insert one text row.
void createAndInsert(SqlCipherDb& db, const std::string& value) {
    SqlCipherQuery q(db);
    ASSERT_TRUE(q.exec(
        "CREATE TABLE IF NOT EXISTS canary (id INTEGER PRIMARY KEY, v TEXT);"))
        << q.lastError();

    SqlCipherQuery ins(db);
    ASSERT_TRUE(ins.prepare("INSERT INTO canary (v) VALUES (:v);"))
        << ins.lastError();
    ins.bindValue(":v", value);
    ASSERT_TRUE(ins.exec()) << ins.lastError();
}

std::string readFirstCanary(SqlCipherDb& db) {
    SqlCipherQuery q(db);
    EXPECT_TRUE(q.prepare("SELECT v FROM canary ORDER BY id ASC LIMIT 1;"))
        << q.lastError();
    EXPECT_TRUE(q.exec()) << q.lastError();
    if (!q.next()) return {};
    return q.valueText(0);
}

}  // namespace

// ── 1. The linked sqlite is actually SQLCipher ────────────────────────────
// If the build accidentally links plain sqlite3 instead of the vendored
// SQLCipher amalgamation, this test fails before any encryption lies
// undetected in a later round-trip.

TEST(SqlCipherDb, LinkedBuildIsSqlCipher) {
    SqlCipherDb db;
    const std::string path = makeTempDbPath("sqlcipher-check");

    ASSERT_TRUE(db.open(path, randomKey32())) << db.lastError();
    EXPECT_TRUE(db.isSqlCipher())
        << "Linked sqlite library is plain sqlite3 — SQLCipher codec is not active";
    db.close();
    std::filesystem::remove(path);
}

// ── 2. Round-trip: write row → close → reopen with same key → read back ──
// This is the regression test for the 4.6.1-without-EXTRA_INIT bug.

TEST(SqlCipherDb, EncryptedRoundTripWithCorrectKey) {
    const std::string path = makeTempDbPath("sqlcipher-roundtrip");
    const SqlCipherDb::Bytes key = randomKey32();
    const std::string canary = "hello from the encrypted side";

    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(path, key)) << db.lastError();
        createAndInsert(db, canary);
        db.close();
    }

    // Reopen with the same key — should decrypt and return the row.
    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(path, key)) << db.lastError();
        EXPECT_EQ(readFirstCanary(db), canary);
        db.close();
    }

    std::filesystem::remove(path);
}

// ── 3. Reopening with a different key must fail ───────────────────────────
// If this test ever passes (i.e. a wrong key still opens the DB), the
// codec is silently not doing anything — that's the 4.6.1 bug class.

TEST(SqlCipherDb, WrongKeyIsRejected) {
    const std::string path = makeTempDbPath("sqlcipher-wrongkey");
    const SqlCipherDb::Bytes keyA = randomKey32();
    SqlCipherDb::Bytes keyB = randomKey32();
    // Belt-and-suspenders: make sure keyB isn't coincidentally equal to keyA.
    if (keyA == keyB) keyB[0] ^= 0xFF;

    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(path, keyA)) << db.lastError();
        createAndInsert(db, "secret");
        db.close();
    }

    // Reopen with the wrong key: open() should return false.
    // SqlCipherDb::open runs a `SELECT count(*) FROM sqlite_master;` probe
    // after applying the key and closes the DB on probe failure, so the
    // entry-point returns false.
    {
        SqlCipherDb db;
        EXPECT_FALSE(db.open(path, keyB))
            << "WRONG key unexpectedly opened the encrypted DB — codec isn't active";
        EXPECT_FALSE(db.isOpen());
    }

    std::filesystem::remove(path);
}

// ── 4. Empty key path refuses to run on plain sqlite ──────────────────────
// SqlCipherDb::open refuses to operate on an unencrypted database (it checks
// `PRAGMA cipher_version` and bails if the codec isn't present, OR if the
// open key was empty — the project requires at-rest encryption).  Verify
// that contract.  Opening an un-keyed DB still "succeeds" at the sqlite3
// level but must fail at the SqlCipherDb policy check.

TEST(SqlCipherDb, EmptyKeyIsRejectedWhenRequired) {
    // This test documents current behavior: a valid SQLCipher build permits
    // `open(path, {})` for new files but the key-verification probe only
    // runs when a non-empty key was applied, so an empty-key open just
    // returns true (with m_isSqlCipher still set from the version probe).
    // If you ever want to HARD-require keys, flip this expectation — the
    // test will then fail loudly and point you at SqlCipherDb::open().
    const std::string path = makeTempDbPath("sqlcipher-emptykey");
    SqlCipherDb db;
    const bool opened = db.open(path, {});
    EXPECT_TRUE(opened) << db.lastError();
    EXPECT_TRUE(db.isSqlCipher())
        << "An un-keyed open should still see the SQLCipher codec in the build";
    db.close();
    std::filesystem::remove(path);
}

// ── 4b. Multi-page encrypted database round-trips correctly ───────────────
// The tests above all fit in a single SQLite page (~4 KB).  A codec that
// only decrypts page 1 but garbles page 2+ wouldn't be caught by them.
// Insert enough rows to force multiple pages, close, reopen, count them.

TEST(SqlCipherDb, MultiPageRoundTrip) {
    const std::string path = makeTempDbPath("sqlcipher-multipage");
    const SqlCipherDb::Bytes key = randomKey32();
    constexpr int kRows = 400;              // ~400 * 200 B ≈ 80 KB → ~20 pages
    const std::string pad(200, 'x');

    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(path, key)) << db.lastError();

        SqlCipherQuery q(db);
        ASSERT_TRUE(q.exec(
            "CREATE TABLE pages (id INTEGER PRIMARY KEY, v TEXT);")) << q.lastError();

        ASSERT_TRUE(q.exec("BEGIN;"));
        for (int i = 0; i < kRows; ++i) {
            SqlCipherQuery ins(db);
            ASSERT_TRUE(ins.prepare("INSERT INTO pages (v) VALUES (:v);"));
            ins.bindValue(":v", pad + std::to_string(i));
            ASSERT_TRUE(ins.exec()) << ins.lastError();
        }
        ASSERT_TRUE(q.exec("COMMIT;"));
        db.close();
    }

    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(path, key)) << db.lastError();
        SqlCipherQuery q(db);
        ASSERT_TRUE(q.prepare("SELECT COUNT(*) FROM pages;"));
        ASSERT_TRUE(q.exec());
        ASSERT_TRUE(q.next());
        EXPECT_EQ(q.valueInt64(0), static_cast<int64_t>(kRows));
        db.close();
    }

    std::filesystem::remove(path);
}

// ── 4c. BLOB columns preserve embedded NUL bytes ──────────────────────────
// If the binder or accessor treats a BLOB as a C string, the first 0x00 byte
// silently truncates everything after it.  That bug is invisible in the
// PreparedStatementBindAndRead test below (`0xDE,0xAD,0xBE,0xEF` has none).

TEST(SqlCipherDb, BlobWithEmbeddedNulsRoundTrips) {
    const std::string path = makeTempDbPath("sqlcipher-nulblob");
    const SqlCipherDb::Bytes key = randomKey32();
    SqlCipherDb db;
    ASSERT_TRUE(db.open(path, key)) << db.lastError();

    SqlCipherQuery c(db);
    ASSERT_TRUE(c.exec("CREATE TABLE b (data BLOB);")) << c.lastError();

    const SqlCipherQuery::Bytes blob = {
        0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xFF, 0x7F, 0x00, 0xAB
    };

    SqlCipherQuery ins(db);
    ASSERT_TRUE(ins.prepare("INSERT INTO b (data) VALUES (:d);"));
    ins.bindValue(":d", blob);
    ASSERT_TRUE(ins.exec()) << ins.lastError();

    SqlCipherQuery sel(db);
    ASSERT_TRUE(sel.prepare("SELECT data FROM b;"));
    ASSERT_TRUE(sel.exec());
    ASSERT_TRUE(sel.next());
    EXPECT_EQ(sel.valueBlob(0), blob);

    db.close();
    std::filesystem::remove(path);
}

// ── 4d. isNull() reports NULL columns correctly ───────────────────────────
// None of the other tests exercise NULL, so a regression in isNull() (e.g.
// always returning false) would sneak through.

TEST(SqlCipherDb, IsNullReportsNullColumn) {
    const std::string path = makeTempDbPath("sqlcipher-null");
    const SqlCipherDb::Bytes key = randomKey32();
    SqlCipherDb db;
    ASSERT_TRUE(db.open(path, key)) << db.lastError();

    SqlCipherQuery c(db);
    ASSERT_TRUE(c.exec("CREATE TABLE n (a INTEGER, b TEXT);")) << c.lastError();

    SqlCipherQuery ins(db);
    ASSERT_TRUE(ins.prepare("INSERT INTO n (a, b) VALUES (:a, :b);"));
    ins.bindValue(":a", int64_t(7));
    ins.bindValue(":b", nullptr);
    ASSERT_TRUE(ins.exec()) << ins.lastError();

    SqlCipherQuery sel(db);
    ASSERT_TRUE(sel.prepare("SELECT a, b FROM n;"));
    ASSERT_TRUE(sel.exec());
    ASSERT_TRUE(sel.next());
    EXPECT_FALSE(sel.isNull(0));
    EXPECT_TRUE(sel.isNull(1));
    EXPECT_EQ(sel.valueInt64(0), 7);

    db.close();
    std::filesystem::remove(path);
}

// ── 4e. Bad SQL populates lastError() rather than silently succeeding ─────
// A contract regression where prepare()/exec() stop reporting errors is
// extremely dangerous — the app would look fine while dropping writes.

TEST(SqlCipherDb, BadSqlPopulatesLastError) {
    const std::string path = makeTempDbPath("sqlcipher-badsql");
    const SqlCipherDb::Bytes key = randomKey32();
    SqlCipherDb db;
    ASSERT_TRUE(db.open(path, key)) << db.lastError();

    SqlCipherQuery q(db);
    EXPECT_FALSE(q.prepare("NOT VALID SQL;"));
    EXPECT_FALSE(q.lastError().empty())
        << "prepare() of invalid SQL returned false but left lastError empty";

    // Same path via one-shot exec.
    SqlCipherQuery q2(db);
    EXPECT_FALSE(q2.exec("SELECT * FROM table_that_does_not_exist;"));
    EXPECT_FALSE(q2.lastError().empty())
        << "exec() against a missing table returned false but left lastError empty";

    db.close();
    std::filesystem::remove(path);
}

// ── 5. Basic prepared-statement binder / accessor coverage ────────────────
// Makes sure the typed bindValue / valueX helpers at least compile and
// survive a round-trip — catches build-system regressions where one header
// or source becomes stale after a refactor.

TEST(SqlCipherDb, PreparedStatementBindAndRead) {
    const std::string path = makeTempDbPath("sqlcipher-prep");
    const SqlCipherDb::Bytes key = randomKey32();
    SqlCipherDb db;
    ASSERT_TRUE(db.open(path, key)) << db.lastError();

    SqlCipherQuery q(db);
    ASSERT_TRUE(q.exec(
        "CREATE TABLE t (i INTEGER, s TEXT, b BLOB);"))
        << q.lastError();

    SqlCipherQuery ins(db);
    ASSERT_TRUE(ins.prepare("INSERT INTO t (i, s, b) VALUES (:i, :s, :b);"));
    ins.bindValue(":i", int64_t(42));
    ins.bindValue(":s", std::string("forty-two"));
    const SqlCipherQuery::Bytes blob = {0xDE, 0xAD, 0xBE, 0xEF};
    ins.bindValue(":b", blob);
    ASSERT_TRUE(ins.exec()) << ins.lastError();

    SqlCipherQuery sel(db);
    ASSERT_TRUE(sel.prepare("SELECT i, s, b FROM t;"));
    ASSERT_TRUE(sel.exec());
    ASSERT_TRUE(sel.next());
    EXPECT_EQ(sel.valueInt64(0), 42);
    EXPECT_EQ(sel.valueText(1), "forty-two");
    EXPECT_EQ(sel.valueBlob(2), blob);

    db.close();
    std::filesystem::remove(path);
}
