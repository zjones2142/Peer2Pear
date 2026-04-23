// test_app_data_store.cpp — unit tests for AppDataStore.
//
// Coverage:
//   - Round-trip for each table (contact / message / setting / file / seq)
//   - Per-field encryption: encrypt → readback → decrypt returns plaintext
//   - Legacy-key fallback: row written with key A decrypts after switching
//     to key B with A in legacyKeys
//   - FK cascade: deleteContact wipes the peer's messages
//   - Group seq counter UPSERT preserves other direction's entries
//   - Empty-peer-id / empty-key guards
//
// Uses a fresh SqlCipherDb per test (no Argon2 bootstrap needed — the
// store only requires an open handle).

#include "AppDataStore.hpp"

#include "SqlCipherDb.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <sodium.h>
#include <sqlite3.h>

#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace {

using p2p_test::makeTempDir;

SqlCipherDb::Bytes randomKey32() {
    SqlCipherDb::Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

// Open a fresh SQLCipher-encrypted DB in a unique tmp dir and bind an
// AppDataStore with `key` as the per-field key.  Returns the pair so
// the test can manipulate both.
struct TestEnv {
    std::string dir;
    std::unique_ptr<SqlCipherDb> db;
    std::unique_ptr<AppDataStore> store;
};

TestEnv makeEnv(const SqlCipherDb::Bytes& dbKey,
                const SqlCipherDb::Bytes& fieldKey) {
    TestEnv e;
    e.dir = makeTempDir("app-data");
    e.db  = std::make_unique<SqlCipherDb>();
    const auto path = e.dir + "/app.db";
    EXPECT_TRUE(e.db->open(path, dbKey));
    e.store = std::make_unique<AppDataStore>();
    EXPECT_TRUE(e.store->bind(*e.db));
    if (!fieldKey.empty()) e.store->setEncryptionKey(fieldKey);
    return e;
}

} // namespace

TEST(AppDataStore, ContactRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "abc123";
    c.name       = "Alice";
    c.subtitle   = "online";
    c.keys       = {"k1", "k2"};
    c.isBlocked  = false;
    c.isGroup    = false;
    c.avatarB64  = "PNGbytes";
    c.lastActiveSecs = 1700000000;
    ASSERT_TRUE(env.store->saveContact(c));

    std::vector<AppDataStore::Contact> loaded;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c2) {
        loaded.push_back(c2);
    });
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_EQ(loaded[0].peerIdB64u, "abc123");
    EXPECT_EQ(loaded[0].name,       "Alice");
    EXPECT_EQ(loaded[0].subtitle,   "online");
    ASSERT_EQ(loaded[0].keys.size(), 2u);
    EXPECT_EQ(loaded[0].keys[0],    "k1");
    EXPECT_EQ(loaded[0].keys[1],    "k2");
    EXPECT_EQ(loaded[0].avatarB64,  "PNGbytes");
    EXPECT_EQ(loaded[0].lastActiveSecs, 1700000000);
}

TEST(AppDataStore, MessageRoundTripAndOrdering) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "peer1";
    c.name = "Bob";
    env.store->saveContact(c);

    // Insert in reverse-chronological order to prove the ORDER BY works.
    AppDataStore::Message a{true,  "hello",    1700000002, "id-a", ""};
    AppDataStore::Message b{false, "hi back",  1700000001, "id-b", ""};
    env.store->saveMessage("peer1", a);
    env.store->saveMessage("peer1", b);

    std::vector<AppDataStore::Message> loaded;
    env.store->loadMessages("peer1", [&](const AppDataStore::Message& m) {
        loaded.push_back(m);
    });
    ASSERT_EQ(loaded.size(), 2u);
    EXPECT_EQ(loaded[0].text, "hi back");    // earlier ts
    EXPECT_EQ(loaded[1].text, "hello");      // later ts
    EXPECT_TRUE(loaded[1].sent);
    EXPECT_EQ(loaded[0].msgId, "id-b");
}

TEST(AppDataStore, SaveMessageBumpsLastActive) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u    = "peer2";
    c.name          = "Carol";
    c.lastActiveSecs = 0;
    env.store->saveContact(c);

    AppDataStore::Message m{true, "ping", 1700000003, "id", ""};
    env.store->saveMessage("peer2", m);

    std::vector<AppDataStore::Contact> after;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c2) {
        after.push_back(c2);
    });
    ASSERT_EQ(after.size(), 1u);
    EXPECT_GT(after[0].lastActiveSecs, 0);   // bumped to now(-ish)
}

TEST(AppDataStore, DeleteContactCascadesMessages) {
    // FK cascade is the fix for desktop DBM's behaviour where
    // deleteContact left orphan rows in messages.  PRAGMA foreign_keys=ON
    // is set by AppDataStore::bind().
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "del-me";
    c.name = "Mallory";
    env.store->saveContact(c);
    env.store->saveMessage("del-me",
                            {true, "goodbye", 1700000004, "id", ""});

    ASSERT_TRUE(env.store->deleteContact("del-me"));

    int msgCount = 0;
    env.store->loadMessages("del-me",
                             [&](const AppDataStore::Message&) { ++msgCount; });
    EXPECT_EQ(msgCount, 0);
}

TEST(AppDataStore, DeleteMessagesLeavesContactIntact) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u = "keep-me";
    c.name = "Dave";
    env.store->saveContact(c);
    env.store->saveMessage("keep-me",
                            {true, "text", 1700000005, "id", ""});

    ASSERT_TRUE(env.store->deleteMessages("keep-me"));

    int contactCount = 0;
    env.store->loadAllContacts([&](const AppDataStore::Contact&) { ++contactCount; });
    EXPECT_EQ(contactCount, 1);
    int msgCount = 0;
    env.store->loadMessages("keep-me",
                             [&](const AppDataStore::Message&) { ++msgCount; });
    EXPECT_EQ(msgCount, 0);
}

TEST(AppDataStore, EncryptedFieldsAreOpaqueInRawStorage) {
    // Prove that the stored column is actually ciphertext — a raw
    // sqlite SELECT returning TEXT shouldn't contain the plaintext.
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u = "enc-check";
    c.name       = "UNIQUE_SENTINEL_NAME_42";
    env.store->saveContact(c);

    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(env.db->handle(),
        "SELECT name FROM contacts WHERE peer_id='enc-check';",
        -1, &stmt, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const std::string raw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);

    // Arch-review #1b: new writes emit `ENC2:` (AAD-bound).  Legacy
    // `ENC:` rows continue to decrypt but aren't written anymore.
    EXPECT_EQ(raw.substr(0, 5), "ENC2:");
    EXPECT_EQ(raw.find("UNIQUE_SENTINEL_NAME_42"), std::string::npos);
}

// Arch-review #1b: an attacker with SQLCipher write access must not
// be able to swap an ENC2-blob from one row/column into another.  The
// AAD binds `<table>|<column>|<row-key>`, so a swap flips one of
// those fields and AEAD verification fails.
TEST(AppDataStore, RowSwapAcrossColumnsFailsAadCheck) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact a;
    a.peerIdB64u = "peer-A";
    a.name       = "AliceName";
    a.subtitle   = "AliceSubtitle";
    ASSERT_TRUE(env.store->saveContact(a));

    // Copy the encrypted `name` blob into `subtitle` (column swap
    // within the same row).  A pre-#1b build would decrypt this fine.
    sqlite3_stmt* read = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(env.db->handle(),
        "SELECT name FROM contacts WHERE peer_id='peer-A';",
        -1, &read, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(read), SQLITE_ROW);
    const std::string nameCt = reinterpret_cast<const char*>(sqlite3_column_text(read, 0));
    sqlite3_finalize(read);

    sqlite3_stmt* write = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(env.db->handle(),
        "UPDATE contacts SET subtitle=? WHERE peer_id='peer-A';",
        -1, &write, nullptr), SQLITE_OK);
    sqlite3_bind_text(write, 1, nameCt.c_str(), int(nameCt.size()), SQLITE_TRANSIENT);
    ASSERT_EQ(sqlite3_step(write), SQLITE_DONE);
    sqlite3_finalize(write);

    std::vector<AppDataStore::Contact> out;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c) { out.push_back(c); });
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].name, "AliceName");
    EXPECT_EQ(out[0].subtitle, std::string{})
        << "swapped blob must fail to decrypt — AAD mismatch";
}

// Same but across peer rows (peer-A.name → peer-B.name).  AAD
// includes the row-key (peer_id), so this swap also fails.
TEST(AppDataStore, RowSwapAcrossPeersFailsAadCheck) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact a;
    a.peerIdB64u = "peer-A";
    a.name       = "AliceName";
    AppDataStore::Contact b;
    b.peerIdB64u = "peer-B";
    b.name       = "BobName";
    ASSERT_TRUE(env.store->saveContact(a));
    ASSERT_TRUE(env.store->saveContact(b));

    sqlite3_stmt* read = nullptr;
    sqlite3_prepare_v2(env.db->handle(),
        "SELECT name FROM contacts WHERE peer_id='peer-A';",
        -1, &read, nullptr);
    sqlite3_step(read);
    const std::string aliceCt = reinterpret_cast<const char*>(sqlite3_column_text(read, 0));
    sqlite3_finalize(read);

    sqlite3_stmt* write = nullptr;
    sqlite3_prepare_v2(env.db->handle(),
        "UPDATE contacts SET name=? WHERE peer_id='peer-B';",
        -1, &write, nullptr);
    sqlite3_bind_text(write, 1, aliceCt.c_str(), int(aliceCt.size()), SQLITE_TRANSIENT);
    sqlite3_step(write);
    sqlite3_finalize(write);

    std::vector<AppDataStore::Contact> out;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c) { out.push_back(c); });

    AppDataStore::Contact* bob = nullptr;
    for (auto& c : out) if (c.peerIdB64u == "peer-B") bob = &c;
    ASSERT_NE(bob, nullptr);
    EXPECT_EQ(bob->name, std::string{})
        << "cross-peer blob swap must fail AAD check";
}

TEST(AppDataStore, LegacyKeyFallback) {
    // Write a row with key A, then rebind the store with key B while
    // declaring A as a legacy key.  Read should still succeed.
    const auto dbKey   = randomKey32();
    const auto fieldKeyA = randomKey32();
    const auto fieldKeyB = randomKey32();

    const auto dir = makeTempDir("app-data-legacy");
    const auto dbPath = dir + "/legacy.db";

    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(dbPath, dbKey));
        AppDataStore store;
        ASSERT_TRUE(store.bind(db));
        store.setEncryptionKey(fieldKeyA);
        AppDataStore::Contact c;
        c.peerIdB64u = "rotate";
        c.name       = "OldNameCiphertext";
        ASSERT_TRUE(store.saveContact(c));
    }
    {
        SqlCipherDb db;
        ASSERT_TRUE(db.open(dbPath, dbKey));
        AppDataStore store;
        ASSERT_TRUE(store.bind(db));
        store.setEncryptionKey(fieldKeyB, {fieldKeyA}); // A is legacy
        std::vector<AppDataStore::Contact> out;
        store.loadAllContacts([&](const AppDataStore::Contact& c) { out.push_back(c); });
        ASSERT_EQ(out.size(), 1u);
        EXPECT_EQ(out[0].name, "OldNameCiphertext");
    }
}

TEST(AppDataStore, SettingsRoundTripAndDefault) {
    auto env = makeEnv(randomKey32(), {}); // no field-key: settings are plaintext
    EXPECT_EQ(env.store->loadSetting("missing", "fallback"), "fallback");
    env.store->saveSetting("theme", "dark");
    EXPECT_EQ(env.store->loadSetting("theme"), "dark");
    env.store->saveSetting("theme", "light"); // overwrite
    EXPECT_EQ(env.store->loadSetting("theme"), "light");
}

TEST(AppDataStore, GroupSeqCountersDirectionIndependent) {
    // UPSERT-per-entry means writing direction=0 (out) shouldn't touch
    // direction=1 (in) rows — bug caught in desktop DBM's DELETE-all-and-
    // reinsert implementation (which only affected one direction per
    // call but felt suspicious).
    auto env = makeEnv(randomKey32(), {});
    env.store->saveGroupSeqOut({{"gA", 10}, {"gB", 20}});
    env.store->saveGroupSeqIn ({{"gA",  1}, {"gB",  2}});

    auto out = env.store->loadGroupSeqOut();
    auto in  = env.store->loadGroupSeqIn();
    EXPECT_EQ(out.at("gA"), 10);
    EXPECT_EQ(out.at("gB"), 20);
    EXPECT_EQ(in.at("gA"),  1);
    EXPECT_EQ(in.at("gB"),  2);

    // Update out, confirm in untouched.
    env.store->saveGroupSeqOut({{"gA", 99}});
    out = env.store->loadGroupSeqOut();
    in  = env.store->loadGroupSeqIn();
    EXPECT_EQ(out.at("gA"), 99);
    EXPECT_EQ(in.at("gA"),  1);
    EXPECT_EQ(in.at("gB"),  2);
}

TEST(AppDataStore, FileRecordRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::FileRecord r;
    r.transferId     = "tx1";
    r.chatKey        = "peer-ck";
    r.fileName       = "doc.pdf";
    r.fileSize       = 1024;
    r.peerIdB64u     = "peer-ck";
    r.peerName       = "Eve";
    r.timestampSecs  = 1700000006;
    r.sent           = true;
    r.status         = 3;
    r.chunksTotal    = 10;
    r.chunksComplete = 10;
    r.savedPath      = "/tmp/doc.pdf";
    ASSERT_TRUE(env.store->saveFileRecord("peer-ck", r));

    std::vector<AppDataStore::FileRecord> out;
    env.store->loadFileRecords("peer-ck",
        [&](const AppDataStore::FileRecord& fr) { out.push_back(fr); });
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].fileName,  "doc.pdf");
    EXPECT_EQ(out[0].peerName,  "Eve");
    EXPECT_EQ(out[0].savedPath, "/tmp/doc.pdf");
    EXPECT_EQ(out[0].status,    3);
}

TEST(AppDataStore, SaveMessageAutoCreatesContactStubForFK) {
    // Regression: PRAGMA foreign_keys=ON makes the messages.peer_id FK
    // active, so saveMessage MUST guarantee a contacts row exists or
    // the INSERT silently fails.  iOS hit this when a stranger's first
    // inbound message landed before any addContact call — the message
    // never got persisted and reappeared as missing on next launch.
    auto env = makeEnv(randomKey32(), randomKey32());

    // No saveContact first.
    AppDataStore::Message m{false, "hi from stranger", 1700000010, "id-x", ""};
    ASSERT_TRUE(env.store->saveMessage("stranger-peer", m));

    // The stub row should exist now, not in the address book.
    std::vector<AppDataStore::Contact> contacts;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c) {
        contacts.push_back(c);
    });
    ASSERT_EQ(contacts.size(), 1u);
    EXPECT_EQ(contacts[0].peerIdB64u,    "stranger-peer");
    EXPECT_FALSE(contacts[0].inAddressBook);

    // Message should round-trip.
    std::vector<AppDataStore::Message> msgs;
    env.store->loadMessages("stranger-peer", [&](const AppDataStore::Message& m2) {
        msgs.push_back(m2);
    });
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].text, "hi from stranger");

    // Stub-then-addContact should NOT clobber the address-book status:
    // saveMessage's INSERT OR IGNORE leaves the existing row alone.
    AppDataStore::Contact promoted;
    promoted.peerIdB64u    = "stranger-peer";
    promoted.name          = "Now Named";
    promoted.inAddressBook = true;
    ASSERT_TRUE(env.store->saveContact(promoted));

    AppDataStore::Message m2{true, "now we're friends", 1700000011, "id-y", ""};
    ASSERT_TRUE(env.store->saveMessage("stranger-peer", m2));

    contacts.clear();
    env.store->loadAllContacts([&](const AppDataStore::Contact& c) {
        contacts.push_back(c);
    });
    ASSERT_EQ(contacts.size(), 1u);
    EXPECT_EQ(contacts[0].name,         "Now Named");
    EXPECT_TRUE(contacts[0].inAddressBook);   // preserved through second saveMessage
}

TEST(AppDataStore, EmptyPeerIdGuards) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u = "";  // invalid
    EXPECT_FALSE(env.store->saveContact(c));
    EXPECT_FALSE(env.store->saveMessage("", {true, "x", 0, "", ""}));
    EXPECT_FALSE(env.store->deleteMessages(""));
    EXPECT_FALSE(env.store->deleteContact(""));
}
