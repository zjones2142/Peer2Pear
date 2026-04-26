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

Bytes randomKey32() {
    Bytes k(32);
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

TestEnv makeEnv(const Bytes& dbKey,
                const Bytes& fieldKey) {
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

// Convenience: insert a conversations row with kind='group' under the
// given id.  Required before any group_* CRUD test that references
// `group_id` — the v3 FK constraint now sweeps group_* rows when the
// parent conversation goes away.
void makeGroupConv(TestEnv& e, const std::string& id) {
    AppDataStore::Conversation c;
    c.id   = id;
    c.kind = AppDataStore::ConversationKind::Group;
    EXPECT_TRUE(e.store->saveConversation(c));
}

// Convenience: ensure a direct conversation exists for `peerId` and
// return its id (the freshly-minted UUID).  Used by message tests
// that need a stable conversation_id to write to.
std::string makeDirectConv(TestEnv& e, const std::string& peerId) {
    return e.store->findOrCreateDirectConversation(peerId);
}

} // namespace

TEST(AppDataStore, ContactRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u     = "abc123";
    c.name           = "Alice";
    c.subtitle       = "online";
    c.avatarB64      = "PNGbytes";
    c.muted          = false;
    c.lastActiveSecs = 1700000000;
    ASSERT_TRUE(env.store->saveContact(c));

    std::vector<AppDataStore::Contact> loaded;
    env.store->loadAllContacts([&](const AppDataStore::Contact& c2) {
        loaded.push_back(c2);
    });
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_EQ(loaded[0].peerIdB64u,    "abc123");
    EXPECT_EQ(loaded[0].name,          "Alice");
    EXPECT_EQ(loaded[0].subtitle,      "online");
    EXPECT_EQ(loaded[0].avatarB64,     "PNGbytes");
    EXPECT_FALSE(loaded[0].muted);
    EXPECT_EQ(loaded[0].lastActiveSecs, 1700000000);
}

TEST(AppDataStore, MessageRoundTripAndOrdering) {
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string convId = makeDirectConv(env, "peer1");

    // Insert in reverse-chronological order to prove the ORDER BY works.
    AppDataStore::Message a{true,  "hello",    1700000002, "id-a", "",      ""};
    AppDataStore::Message b{false, "hi back",  1700000001, "id-b", "peer1", ""};
    env.store->saveMessage(convId, a);
    env.store->saveMessage(convId, b);

    std::vector<AppDataStore::Message> loaded;
    env.store->loadMessages(convId, [&](const AppDataStore::Message& m) {
        loaded.push_back(m);
    });
    ASSERT_EQ(loaded.size(), 2u);
    EXPECT_EQ(loaded[0].text, "hi back");    // earlier ts
    EXPECT_EQ(loaded[1].text, "hello");      // later ts
    EXPECT_TRUE(loaded[1].sent);
    EXPECT_EQ(loaded[0].msgId,    "id-b");
    EXPECT_EQ(loaded[0].senderId, "peer1");
    EXPECT_EQ(loaded[1].senderId, "");        // outbound: empty senderId
}

TEST(AppDataStore, SaveMessageBumpsConversationLastActive) {
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string convId = makeDirectConv(env, "peer2");

    AppDataStore::Message m{true, "ping", 1700000003, "id", "", ""};
    env.store->saveMessage(convId, m);

    AppDataStore::Conversation c;
    ASSERT_TRUE(env.store->loadConversation(convId, c));
    EXPECT_EQ(c.lastActiveSecs, 1700000003);
}

TEST(AppDataStore, SaveMessageBumpsContactLastActiveOnInbound) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u    = "peer-inbound";
    c.name          = "Carol";
    c.lastActiveSecs = 0;
    env.store->saveContact(c);

    const std::string convId = makeDirectConv(env, "peer-inbound");
    // Inbound message — sender_id matches the contact peer_id.
    AppDataStore::Message m{false, "ping", 1700000003, "id", "peer-inbound", ""};
    env.store->saveMessage(convId, m);

    AppDataStore::Contact loaded;
    ASSERT_TRUE(env.store->loadContact("peer-inbound", loaded));
    EXPECT_EQ(loaded.lastActiveSecs, 1700000003);
}

TEST(AppDataStore, DeleteContactDoesNotCascadeMessages) {
    // v3 design: contact deletion is address-book curation only.
    // Chat history (conversations + messages) lives in its own
    // namespace and is unaffected.  Use deleteConversation for that.
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "leave-history";
    c.name = "Mallory";
    env.store->saveContact(c);
    const std::string convId = makeDirectConv(env, "leave-history");
    env.store->saveMessage(convId,
                            {true, "goodbye", 1700000004, "id", "", ""});

    ASSERT_TRUE(env.store->deleteContact("leave-history"));

    // Contact gone.
    AppDataStore::Contact loaded;
    EXPECT_FALSE(env.store->loadContact("leave-history", loaded));

    // Conversation + its messages remain.
    int msgCount = 0;
    env.store->loadMessages(convId,
                             [&](const AppDataStore::Message&) { ++msgCount; });
    EXPECT_EQ(msgCount, 1);
}

TEST(AppDataStore, DeleteConversationCascadesMessages) {
    // FK ON DELETE CASCADE on messages.conversation_id sweeps the
    // thread's history when the conversation is removed.  PRAGMA
    // foreign_keys=ON is set per-connection by SqlCipherDb::open.
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string convId = makeDirectConv(env, "drop-thread");
    env.store->saveMessage(convId,
                            {true, "first",  1700000004, "m1", "", ""});
    env.store->saveMessage(convId,
                            {true, "second", 1700000005, "m2", "", ""});

    ASSERT_TRUE(env.store->deleteConversation(convId));

    int msgCount = 0;
    env.store->loadMessages(convId,
                             [&](const AppDataStore::Message&) { ++msgCount; });
    EXPECT_EQ(msgCount, 0);
}

TEST(AppDataStore, DeleteMessagesLeavesConversationIntact) {
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string convId = makeDirectConv(env, "keep-thread");
    env.store->saveMessage(convId,
                            {true, "text", 1700000005, "id", "", ""});

    ASSERT_TRUE(env.store->deleteMessages(convId));

    AppDataStore::Conversation c;
    EXPECT_TRUE(env.store->loadConversation(convId, c))
        << "conversation row should still exist after wiping messages";
    int msgCount = 0;
    env.store->loadMessages(convId,
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

    // New writes emit `ENC2:` (AAD-bound).  Legacy `ENC:` rows
    // continue to decrypt but aren't written anymore.
    EXPECT_EQ(raw.substr(0, 5), "ENC2:");
    EXPECT_EQ(raw.find("UNIQUE_SENTINEL_NAME_42"), std::string::npos);
}

// An attacker with SQLCipher write access must not be able to swap
// an ENC2-blob from one row/column into another.  The AAD binds
// `<table>|<column>|<row-key>`, so a swap flips one of those fields
// and AEAD verification fails.
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

TEST(AppDataStore, StrangerFirstMessageCreatesConversationOnly) {
    // v3 design: a peer messaging us out of the blue gets a
    // conversation row but does NOT auto-create a contact.  Address
    // book curation is user-driven only.  Caller (ChatController)
    // is responsible for calling findOrCreateDirectConversation
    // before saveMessage; we test the AppDataStore primitive here.
    auto env = makeEnv(randomKey32(), randomKey32());

    const std::string convId = env.store->findOrCreateDirectConversation("stranger");
    ASSERT_FALSE(convId.empty());

    AppDataStore::Message m{false, "hi from stranger", 1700000010, "id-x",
                              "stranger", ""};
    ASSERT_TRUE(env.store->saveMessage(convId, m));

    // No contact row was created — strangers must be added explicitly.
    int contactCount = 0;
    env.store->loadAllContacts(
        [&](const AppDataStore::Contact&) { ++contactCount; });
    EXPECT_EQ(contactCount, 0);

    // Message round-trips.
    std::vector<AppDataStore::Message> msgs;
    env.store->loadMessages(convId, [&](const AppDataStore::Message& m2) {
        msgs.push_back(m2);
    });
    ASSERT_EQ(msgs.size(), 1u);
    EXPECT_EQ(msgs[0].text, "hi from stranger");
    EXPECT_EQ(msgs[0].senderId, "stranger");

    // Calling findOrCreateDirectConversation again returns the SAME id.
    EXPECT_EQ(env.store->findOrCreateDirectConversation("stranger"), convId);
}

TEST(AppDataStore, EmptyIdGuards) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::Contact c;
    c.peerIdB64u = "";
    EXPECT_FALSE(env.store->saveContact(c));
    EXPECT_FALSE(env.store->deleteContact(""));
    EXPECT_FALSE(env.store->saveMessage("", {true, "x", 0, "", "", ""}));
    EXPECT_FALSE(env.store->deleteMessages(""));
    EXPECT_TRUE(env.store->findOrCreateDirectConversation("").empty());
    EXPECT_FALSE(env.store->deleteConversation(""));
}

// ── Phase 1: Causally-Linked Pairwise schema ────────────────────────────────
//
// These tests pin the CRUD surface for the three new tables that
// back the redesigned group-messaging protocol:
//   group_replay_cache  — sender's already-sent envelopes (7d TTL)
//   group_chain_state   — receiver's per-(group, sender) state machine
//   group_msg_buffer    — out-of-order msgs held during a gap

namespace {

Bytes makeSessionId(uint8_t marker) {
    return Bytes(8, marker);
}
Bytes makePrevHash(uint8_t marker) {
    return Bytes(16, marker);
}

}  // namespace

TEST(AppDataStore, ReplayCacheRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());

    const std::string peer = "bob";
    const std::string gid  = "group1";
    makeGroupConv(env, gid);  // FK target for group_replay_cache.group_id
    const Bytes sid = makeSessionId(0xA1);
    const Bytes env5 = {0x01, 0x02, 0x03, 0x04, 0x05};

    ASSERT_TRUE(env.store->addReplayCacheEntry(peer, gid, sid, 5, env5, 1000));
    EXPECT_EQ(env.store->loadReplayCacheEntry(peer, gid, sid, 5), env5);
    EXPECT_TRUE(env.store->loadReplayCacheEntry(peer, gid, sid, 999).empty())
        << "miss returns empty Bytes, never throws";

    EXPECT_TRUE(env.store->dropReplayCacheEntry(peer, gid, sid, 5));
    EXPECT_TRUE(env.store->loadReplayCacheEntry(peer, gid, sid, 5).empty())
        << "drop should remove the cached envelope";
}

TEST(AppDataStore, ReplayCacheRangeStreamsInCounterOrder) {
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string peer = "bob";
    const std::string gid  = "group1";
    makeGroupConv(env, gid);
    const Bytes sid = makeSessionId(0xB2);

    // Insert out-of-order, expect ascending iteration.
    env.store->addReplayCacheEntry(peer, gid, sid, 7, {0x07}, 1000);
    env.store->addReplayCacheEntry(peer, gid, sid, 5, {0x05}, 1000);
    env.store->addReplayCacheEntry(peer, gid, sid, 6, {0x06}, 1000);
    env.store->addReplayCacheEntry(peer, gid, sid, 9, {0x09}, 1000);  // outside range

    std::vector<int64_t> seenCounters;
    std::vector<Bytes> seenBytes;
    env.store->loadReplayCacheRange(peer, gid, sid, 5, 7,
        [&](int64_t c, const Bytes& b) {
            seenCounters.push_back(c);
            seenBytes.push_back(b);
        });

    ASSERT_EQ(seenCounters.size(), 3u);
    EXPECT_EQ(seenCounters[0], 5);
    EXPECT_EQ(seenCounters[1], 6);
    EXPECT_EQ(seenCounters[2], 7);
    EXPECT_EQ(seenBytes[0], (Bytes{0x05}));
    EXPECT_EQ(seenBytes[2], (Bytes{0x07}));
}

TEST(AppDataStore, ReplayCacheIsolatedByPeerAndSession) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid1 = makeSessionId(0xC3);
    const Bytes sid2 = makeSessionId(0xD4);

    env.store->addReplayCacheEntry("bob",   "g", sid1, 5, {0x10}, 1000);
    env.store->addReplayCacheEntry("carol", "g", sid1, 5, {0x20}, 1000);
    env.store->addReplayCacheEntry("bob",   "g", sid2, 5, {0x30}, 1000);

    EXPECT_EQ(env.store->loadReplayCacheEntry("bob",   "g", sid1, 5), (Bytes{0x10}));
    EXPECT_EQ(env.store->loadReplayCacheEntry("carol", "g", sid1, 5), (Bytes{0x20}));
    EXPECT_EQ(env.store->loadReplayCacheEntry("bob",   "g", sid2, 5), (Bytes{0x30}))
        << "different session_id is a different cache slot";
}

TEST(AppDataStore, ReplayCachePurgeOlderThanCutoff) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0xE5);

    // Three rows at increasing ages.
    env.store->addReplayCacheEntry("p", "g", sid, 1, {0x01}, /*sent_at=*/100);
    env.store->addReplayCacheEntry("p", "g", sid, 2, {0x02}, /*sent_at=*/200);
    env.store->addReplayCacheEntry("p", "g", sid, 3, {0x03}, /*sent_at=*/300);

    // Cutoff at 250 should remove rows with sent_at < 250 (rows 1 and 2).
    const int dropped = env.store->purgeReplayCacheOlderThan(250);
    EXPECT_EQ(dropped, 2);
    EXPECT_TRUE(env.store->loadReplayCacheEntry("p", "g", sid, 1).empty());
    EXPECT_TRUE(env.store->loadReplayCacheEntry("p", "g", sid, 2).empty());
    EXPECT_FALSE(env.store->loadReplayCacheEntry("p", "g", sid, 3).empty());
}

TEST(AppDataStore, ChainStateRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "group1");

    AppDataStore::ChainState s;
    s.sessionId    = makeSessionId(0xF6);
    s.expectedNext = 47;
    s.lastHash     = makePrevHash(0x42);
    s.blockedSince = 1700000000;
    s.gapFrom      = 5;
    s.gapTo        = 10;
    s.lastRetryAt  = 1700000010;
    s.retryCount   = 3;

    ASSERT_TRUE(env.store->saveChainState("group1", "alice", s));

    AppDataStore::ChainState loaded;
    ASSERT_TRUE(env.store->loadChainState("group1", "alice", loaded));
    EXPECT_EQ(loaded.sessionId,    s.sessionId);
    EXPECT_EQ(loaded.expectedNext, 47);
    EXPECT_EQ(loaded.lastHash,     s.lastHash);
    EXPECT_EQ(loaded.blockedSince, 1700000000);
    EXPECT_EQ(loaded.gapFrom,      5);
    EXPECT_EQ(loaded.gapTo,        10);
    EXPECT_EQ(loaded.lastRetryAt,  1700000010);
    EXPECT_EQ(loaded.retryCount,   3);
}

TEST(AppDataStore, ChainStateUpsertsInPlace) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");

    AppDataStore::ChainState s;
    s.sessionId = makeSessionId(0x07);
    s.expectedNext = 1;
    env.store->saveChainState("g", "alice", s);

    s.expectedNext = 5;  // simulate after delivering 4 messages
    s.lastHash     = makePrevHash(0x88);
    env.store->saveChainState("g", "alice", s);

    AppDataStore::ChainState loaded;
    ASSERT_TRUE(env.store->loadChainState("g", "alice", loaded));
    EXPECT_EQ(loaded.expectedNext, 5);
    EXPECT_EQ(loaded.lastHash,     makePrevHash(0x88));
}

TEST(AppDataStore, ChainStateMissReturnsFalse) {
    auto env = makeEnv(randomKey32(), randomKey32());
    AppDataStore::ChainState loaded;
    EXPECT_FALSE(env.store->loadChainState("never", "anyone", loaded));
}

TEST(AppDataStore, ChainStateDropRemovesRow) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    AppDataStore::ChainState s;
    s.sessionId = makeSessionId(0x09);
    env.store->saveChainState("g", "alice", s);

    EXPECT_TRUE(env.store->dropChainState("g", "alice"));

    AppDataStore::ChainState loaded;
    EXPECT_FALSE(env.store->loadChainState("g", "alice", loaded))
        << "dropChainState must remove the row";
}

TEST(AppDataStore, BufferRoundTripPreservesContent) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x11);
    const Bytes ph  = makePrevHash(0x22);

    const Bytes envHash = makePrevHash(0xEE);
    ASSERT_TRUE(env.store->addBufferEntry(
        "g", "alice", sid, /*counter=*/7, ph, envHash, /*msgId=*/"abc-uuid",
        /*body=*/"hello world", /*senderName=*/"Alice", /*receivedAt=*/1234));

    std::vector<AppDataStore::BufferedMessage> rows;
    env.store->loadBufferRange("g", "alice", sid, 7, 7,
        [&](const AppDataStore::BufferedMessage& m) { rows.push_back(m); });

    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].counter,        7);
    EXPECT_EQ(rows[0].prevHash,       ph);
    EXPECT_EQ(rows[0].sealedEnvHash,  envHash);
    EXPECT_EQ(rows[0].msgId,          "abc-uuid");
    EXPECT_EQ(rows[0].body,           "hello world");
    EXPECT_EQ(rows[0].senderName,     "Alice");
    EXPECT_EQ(rows[0].receivedAt,     1234);
}

TEST(AppDataStore, BufferRangeIsCounterAscending) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x33);

    env.store->addBufferEntry("g", "a", sid, 9, {}, {}, "m9", "i", "Alice", 0);
    env.store->addBufferEntry("g", "a", sid, 6, {}, {}, "m6", "f", "Alice", 0);
    env.store->addBufferEntry("g", "a", sid, 7, {}, {}, "m7", "g", "Alice", 0);

    std::vector<int64_t> seen;
    env.store->loadBufferRange("g", "a", sid, 5, 10,
        [&](const AppDataStore::BufferedMessage& m) { seen.push_back(m.counter); });
    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[0], 6);
    EXPECT_EQ(seen[1], 7);
    EXPECT_EQ(seen[2], 9);
}

TEST(AppDataStore, BufferDropRangeRemovesOnlyRequestedCounters) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x44);

    env.store->addBufferEntry("g", "a", sid, 5, {}, {}, "m5", "five",  "A", 0);
    env.store->addBufferEntry("g", "a", sid, 6, {}, {}, "m6", "six",   "A", 0);
    env.store->addBufferEntry("g", "a", sid, 7, {}, {}, "m7", "seven", "A", 0);

    EXPECT_EQ(env.store->dropBufferRange("g", "a", sid, 5, 6), 2);

    std::vector<AppDataStore::BufferedMessage> remaining;
    env.store->loadBufferRange("g", "a", sid, 0, 100,
        [&](const AppDataStore::BufferedMessage& m) { remaining.push_back(m); });
    ASSERT_EQ(remaining.size(), 1u);
    EXPECT_EQ(remaining[0].counter, 7);
}

TEST(AppDataStore, BufferDropForSessionWipesOnlyOldSession) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sidOld = makeSessionId(0x55);
    const Bytes sidNew = makeSessionId(0x66);

    env.store->addBufferEntry("g", "a", sidOld, 1, {}, {}, "mo1", "old1", "A", 0);
    env.store->addBufferEntry("g", "a", sidOld, 2, {}, {}, "mo2", "old2", "A", 0);
    env.store->addBufferEntry("g", "a", sidNew, 1, {}, {}, "mn1", "new1", "A", 0);

    const int wiped = env.store->dropBufferForSession("g", "a", sidOld);
    EXPECT_EQ(wiped, 2);

    // sidNew rows should survive.
    std::vector<AppDataStore::BufferedMessage> survivors;
    env.store->loadBufferRange("g", "a", sidNew, 0, 100,
        [&](const AppDataStore::BufferedMessage& m) { survivors.push_back(m); });
    ASSERT_EQ(survivors.size(), 1u);
    EXPECT_EQ(survivors[0].body, "new1");
}

TEST(AppDataStore, BufferBodyIsEncryptedAtRest) {
    // The buffer's `body` column must use field-level encryption so a
    // raw SQLCipher dump (page-level decrypted) doesn't leak plaintext.
    // Same defense the messages.text column already passes.
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x77);
    const std::string secret = "diary entry: I love peer2pear";

    env.store->addBufferEntry("g", "a", sid, 1, {}, {}, "m1", secret, "Alice", 0);

    SqlCipherQuery raw(env.db->handle());
    raw.prepare("SELECT body FROM group_msg_buffer WHERE group_id='g';");
    ASSERT_TRUE(raw.exec());
    ASSERT_TRUE(raw.next());
    const std::string stored = raw.valueText(0);
    EXPECT_NE(stored, secret) << "body must not appear plaintext at rest";
    EXPECT_EQ(stored.rfind("ENC", 0), 0u)
        << "body should carry the ENC: encryption-tag prefix";
}

// ── group_send_state ────────────────────────────────────────────────────────

TEST(AppDataStore, SendStateMissReturnsDefault) {
    auto env = makeEnv(randomKey32(), randomKey32());
    // No FK target needed — missing-row path doesn't INSERT.
    AppDataStore::SendState s{42, makePrevHash(0xFF)};  // dirty initial
    EXPECT_TRUE(env.store->loadSendState(
        "bob", "g", makeSessionId(0x01), s));
    EXPECT_EQ(s.nextCounter, 1) << "missing row defaults to nextCounter=1";
    EXPECT_TRUE(s.lastHash.empty()) << "missing row defaults to empty lastHash";
}

TEST(AppDataStore, SendStateRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x88);
    const Bytes hash = makePrevHash(0xAB);

    AppDataStore::SendState s;
    s.nextCounter = 47;
    s.lastHash    = hash;
    ASSERT_TRUE(env.store->saveSendState("bob", "g", sid, s));

    AppDataStore::SendState loaded;
    ASSERT_TRUE(env.store->loadSendState("bob", "g", sid, loaded));
    EXPECT_EQ(loaded.nextCounter, 47);
    EXPECT_EQ(loaded.lastHash,    hash);
}

TEST(AppDataStore, SendStateUpsertsInPlace) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x99);

    AppDataStore::SendState s;
    s.nextCounter = 1;
    env.store->saveSendState("bob", "g", sid, s);

    s.nextCounter = 2;
    s.lastHash    = makePrevHash(0xCC);
    env.store->saveSendState("bob", "g", sid, s);

    AppDataStore::SendState loaded;
    env.store->loadSendState("bob", "g", sid, loaded);
    EXPECT_EQ(loaded.nextCounter, 2);
    EXPECT_EQ(loaded.lastHash,    makePrevHash(0xCC));
}

TEST(AppDataStore, SendStateIsolatedByPeerAndSession) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid1 = makeSessionId(0x10);
    const Bytes sid2 = makeSessionId(0x20);

    AppDataStore::SendState s;
    s.nextCounter = 5;
    env.store->saveSendState("bob",   "g", sid1, s);
    s.nextCounter = 10;
    env.store->saveSendState("carol", "g", sid1, s);
    s.nextCounter = 99;
    env.store->saveSendState("bob",   "g", sid2, s);

    AppDataStore::SendState a, b, c;
    env.store->loadSendState("bob",   "g", sid1, a);
    env.store->loadSendState("carol", "g", sid1, b);
    env.store->loadSendState("bob",   "g", sid2, c);
    EXPECT_EQ(a.nextCounter, 5);
    EXPECT_EQ(b.nextCounter, 10);
    EXPECT_EQ(c.nextCounter, 99) << "different session_id is a different row";
}

TEST(AppDataStore, SendStateDropRemovesRow) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g");
    const Bytes sid = makeSessionId(0x11);

    AppDataStore::SendState s;
    s.nextCounter = 7;
    env.store->saveSendState("bob", "g", sid, s);

    EXPECT_TRUE(env.store->dropSendState("bob", "g", sid));

    AppDataStore::SendState loaded;
    env.store->loadSendState("bob", "g", sid, loaded);
    EXPECT_EQ(loaded.nextCounter, 1)
        << "drop should remove the row; subsequent load returns default";
}

// ── group_bundle_map (Phase 2, Invisible Groups) ────────────────────────────

TEST(AppDataStore, BundleMapMissReturnsEmpty) {
    auto env = makeEnv(randomKey32(), randomKey32());
    EXPECT_TRUE(env.store->bundleIdForGroup("nope").empty());
    EXPECT_TRUE(env.store->groupIdForBundle(Bytes(16, 0x42)).empty());
}

TEST(AppDataStore, BundleMapEnsureMintsStable16BId) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");

    Bytes b1 = env.store->ensureBundleIdForGroup("g1");
    ASSERT_EQ(b1.size(), 16u) << "bundle_id is 16 random bytes";

    // Idempotent: second call returns the same id.
    Bytes b2 = env.store->ensureBundleIdForGroup("g1");
    EXPECT_EQ(b1, b2);

    // Round-trip via the reverse lookup.
    EXPECT_EQ(env.store->groupIdForBundle(b1), "g1");
}

TEST(AppDataStore, BundleMapDistinctGroupsGetDistinctIds) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");
    makeGroupConv(env, "g2");

    Bytes a = env.store->ensureBundleIdForGroup("g1");
    Bytes b = env.store->ensureBundleIdForGroup("g2");
    EXPECT_NE(a, b);
    EXPECT_EQ(env.store->groupIdForBundle(a), "g1");
    EXPECT_EQ(env.store->groupIdForBundle(b), "g2");
}

TEST(AppDataStore, BundleMapAddMappingPreservesProvidedId) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");

    // Receiver path: a peer's group_member_update tells us the bundle_id
    // for a group we already know about.
    const Bytes provided = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    EXPECT_TRUE(env.store->addBundleMapping("g1", provided, 1700000000));
    EXPECT_EQ(env.store->bundleIdForGroup("g1"), provided);
    EXPECT_EQ(env.store->groupIdForBundle(provided), "g1");
}

TEST(AppDataStore, BundleMapAddIsIdempotent) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");

    const Bytes id1 = Bytes(16, 0xAA);
    EXPECT_TRUE(env.store->addBundleMapping("g1", id1, 100));

    // Second add for same group_id is a no-op (INSERT OR IGNORE) — the
    // existing row wins so callers converge on a single id.
    EXPECT_TRUE(env.store->addBundleMapping("g1", Bytes(16, 0xBB), 200));
    EXPECT_EQ(env.store->bundleIdForGroup("g1"), id1);
}

TEST(AppDataStore, BundleMapDropRemovesBothDirections) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");

    Bytes b = env.store->ensureBundleIdForGroup("g1");
    EXPECT_TRUE(env.store->dropBundleMapping("g1"));
    EXPECT_TRUE(env.store->bundleIdForGroup("g1").empty());
    EXPECT_TRUE(env.store->groupIdForBundle(b).empty());
}

TEST(AppDataStore, BundleMapEmptyGuards) {
    auto env = makeEnv(randomKey32(), randomKey32());
    EXPECT_TRUE(env.store->bundleIdForGroup("").empty());
    EXPECT_TRUE(env.store->groupIdForBundle({}).empty());
    EXPECT_TRUE(env.store->ensureBundleIdForGroup("").empty());
    EXPECT_FALSE(env.store->addBundleMapping("",   Bytes(16, 1), 0));
    EXPECT_FALSE(env.store->addBundleMapping("g1", Bytes{}, 0));
    EXPECT_FALSE(env.store->dropBundleMapping(""));
}

TEST(AppDataStore, BundleMapBundleUniqueAcrossGroups) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "g1");
    makeGroupConv(env, "g2");

    const Bytes shared = Bytes(16, 0xCD);
    EXPECT_TRUE(env.store->addBundleMapping("g1", shared, 1));
    // UNIQUE INDEX on bundle_id rejects the second insert; INSERT OR
    // IGNORE returns true (no SQL error) but no row is added.
    EXPECT_TRUE(env.store->addBundleMapping("g2", shared, 2));
    EXPECT_EQ(env.store->groupIdForBundle(shared), "g1");
    EXPECT_TRUE(env.store->bundleIdForGroup("g2").empty());
}

// ── Phase 3: Conversations + members ────────────────────────────────────────

TEST(AppDataStore, ConversationDirectRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Conversation c;
    c.id            = "uuid-direct-1";
    c.kind          = AppDataStore::ConversationKind::Direct;
    c.directPeerId  = "alice";
    c.muted         = true;
    c.lastActiveSecs = 1700000123;
    c.inChatList    = false;
    ASSERT_TRUE(env.store->saveConversation(c));

    AppDataStore::Conversation loaded;
    ASSERT_TRUE(env.store->loadConversation("uuid-direct-1", loaded));
    EXPECT_EQ(loaded.kind,           AppDataStore::ConversationKind::Direct);
    EXPECT_EQ(loaded.directPeerId,   "alice");
    EXPECT_TRUE (loaded.muted);
    EXPECT_FALSE(loaded.inChatList);
    EXPECT_EQ(loaded.lastActiveSecs, 1700000123);
}

TEST(AppDataStore, ConversationGroupHoldsEncryptedName) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Conversation c;
    c.id              = "uuid-group-1";
    c.kind            = AppDataStore::ConversationKind::Group;
    c.groupName       = "Project Hydra";
    c.groupAvatarB64  = "AVATAR_B64_BLOB";
    ASSERT_TRUE(env.store->saveConversation(c));

    // Round-trip plaintext.
    AppDataStore::Conversation loaded;
    ASSERT_TRUE(env.store->loadConversation("uuid-group-1", loaded));
    EXPECT_EQ(loaded.groupName,      "Project Hydra");
    EXPECT_EQ(loaded.groupAvatarB64, "AVATAR_B64_BLOB");

    // Raw column should be ENC2: ciphertext, not plaintext.
    SqlCipherQuery raw(env.db->handle());
    raw.prepare("SELECT group_name FROM conversations WHERE id='uuid-group-1';");
    ASSERT_TRUE(raw.exec()); ASSERT_TRUE(raw.next());
    const std::string stored = raw.valueText(0);
    EXPECT_EQ(stored.substr(0, 5), "ENC2:");
    EXPECT_EQ(stored.find("Project Hydra"), std::string::npos);
}

TEST(AppDataStore, FindOrCreateDirectIsIdempotent) {
    auto env = makeEnv(randomKey32(), randomKey32());

    const std::string a = env.store->findOrCreateDirectConversation("peer-A");
    const std::string b = env.store->findOrCreateDirectConversation("peer-A");
    EXPECT_FALSE(a.empty());
    EXPECT_EQ(a, b) << "second call must return the same conversation id";

    // The membership row was created.
    std::vector<std::string> members;
    env.store->loadConversationMembers(a, [&](const std::string& p) {
        members.push_back(p);
    });
    ASSERT_EQ(members.size(), 1u);
    EXPECT_EQ(members[0], "peer-A");
}

TEST(AppDataStore, FindOrCreateDirectDistinctPeersGetDistinctIds) {
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string a = env.store->findOrCreateDirectConversation("peer-A");
    const std::string b = env.store->findOrCreateDirectConversation("peer-B");
    EXPECT_FALSE(a.empty());
    EXPECT_FALSE(b.empty());
    EXPECT_NE(a, b);
}

TEST(AppDataStore, ConversationMembersSetReplacesAtomically) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "uuid-grp");

    ASSERT_TRUE(env.store->setConversationMembers("uuid-grp",
        {"alice", "bob", "carol"}));

    std::vector<std::string> first;
    env.store->loadConversationMembers("uuid-grp",
        [&](const std::string& p) { first.push_back(p); });
    ASSERT_EQ(first.size(), 3u);
    // ORDER BY peer_id ASC — stable, easy to assert against.
    EXPECT_EQ(first[0], "alice");
    EXPECT_EQ(first[1], "bob");
    EXPECT_EQ(first[2], "carol");

    // Replace with a different roster.
    ASSERT_TRUE(env.store->setConversationMembers("uuid-grp",
        {"dave", "alice"}));
    std::vector<std::string> after;
    env.store->loadConversationMembers("uuid-grp",
        [&](const std::string& p) { after.push_back(p); });
    ASSERT_EQ(after.size(), 2u);
    EXPECT_EQ(after[0], "alice");
    EXPECT_EQ(after[1], "dave");
}

TEST(AppDataStore, ConversationMembersAddRemove) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "uuid-grp");

    EXPECT_TRUE (env.store->addConversationMember("uuid-grp", "alice"));
    EXPECT_TRUE (env.store->addConversationMember("uuid-grp", "alice"));  // dup-tolerant
    EXPECT_TRUE (env.store->addConversationMember("uuid-grp", "bob"));
    EXPECT_TRUE (env.store->removeConversationMember("uuid-grp", "alice"));
    EXPECT_FALSE(env.store->removeConversationMember("uuid-grp", "alice"));  // already gone

    std::vector<std::string> remaining;
    env.store->loadConversationMembers("uuid-grp",
        [&](const std::string& p) { remaining.push_back(p); });
    ASSERT_EQ(remaining.size(), 1u);
    EXPECT_EQ(remaining[0], "bob");
}

TEST(AppDataStore, DeleteConversationCascadesMembers) {
    auto env = makeEnv(randomKey32(), randomKey32());
    makeGroupConv(env, "uuid-grp");
    env.store->setConversationMembers("uuid-grp", {"alice", "bob"});

    ASSERT_TRUE(env.store->deleteConversation("uuid-grp"));

    int count = 0;
    env.store->loadConversationMembers("uuid-grp",
        [&](const std::string&) { ++count; });
    EXPECT_EQ(count, 0);
}

TEST(AppDataStore, ContactAndConversationMuteAreIndependent) {
    // Contact-mute is the cross-thread person mute; conversation-mute
    // is the per-thread mute.  They don't overwrite each other —
    // notification logic ORs them at delivery time.
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "alice";
    c.name = "Alice";
    env.store->saveContact(c);
    const std::string convId = makeDirectConv(env, "alice");

    EXPECT_TRUE(env.store->setContactMuted("alice", true));
    AppDataStore::Conversation conv;
    ASSERT_TRUE(env.store->loadConversation(convId, conv));
    EXPECT_FALSE(conv.muted) << "contact-mute must not set conversation-mute";

    AppDataStore::Contact reloaded;
    ASSERT_TRUE(env.store->loadContact("alice", reloaded));
    EXPECT_TRUE(reloaded.muted);

    // Reverse: muting the conversation must not flip contact.muted.
    EXPECT_TRUE(env.store->setContactMuted("alice", false));
    EXPECT_TRUE(env.store->setConversationMuted(convId, true));
    ASSERT_TRUE(env.store->loadContact("alice", reloaded));
    ASSERT_TRUE(env.store->loadConversation(convId, conv));
    EXPECT_FALSE(reloaded.muted);
    EXPECT_TRUE (conv.muted);
}

TEST(AppDataStore, ConversationsListedInLastActiveOrder) {
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Conversation old;
    old.id = "u-old"; old.kind = AppDataStore::ConversationKind::Direct;
    old.directPeerId = "p1"; old.lastActiveSecs = 100;
    env.store->saveConversation(old);

    AppDataStore::Conversation recent;
    recent.id = "u-recent"; recent.kind = AppDataStore::ConversationKind::Direct;
    recent.directPeerId = "p2"; recent.lastActiveSecs = 200;
    env.store->saveConversation(recent);

    std::vector<std::string> seen;
    env.store->loadAllConversations(
        [&](const AppDataStore::Conversation& c) { seen.push_back(c.id); });
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen[0], "u-recent");
    EXPECT_EQ(seen[1], "u-old");
}

TEST(AppDataStore, InboundMessageAutoUnhidesConversation) {
    // Phase 3e: a conversation the user explicitly archived
    // (in_chat_list=0) pops back into the chat list when the
    // other party messages us.  Outbound saves don't auto-unhide.
    auto env = makeEnv(randomKey32(), randomKey32());
    const std::string convId = makeDirectConv(env, "alice");
    ASSERT_TRUE(env.store->setConversationInChatList(convId, false));

    // Outbound: stays hidden.
    env.store->saveMessage(convId,
        {/*sent=*/true, "hi anyway", 100, "m1", /*senderId=*/"", ""});
    AppDataStore::Conversation c;
    ASSERT_TRUE(env.store->loadConversation(convId, c));
    EXPECT_FALSE(c.inChatList) << "outbound to a hidden chat keeps it hidden";

    // Inbound: pops back.
    env.store->saveMessage(convId,
        {/*sent=*/false, "ping", 200, "m2", /*senderId=*/"alice", ""});
    ASSERT_TRUE(env.store->loadConversation(convId, c));
    EXPECT_TRUE(c.inChatList) << "inbound on a hidden chat must auto-unhide";
}

// ── Phase 3h: blocked_keys (block decoupled from contacts) ──────────────────

TEST(AppDataStore, BlockedKeyRoundTrip) {
    auto env = makeEnv(randomKey32(), randomKey32());

    EXPECT_FALSE(env.store->isBlockedKey("alice"));
    ASSERT_TRUE(env.store->addBlockedKey("alice", 100));
    EXPECT_TRUE(env.store->isBlockedKey("alice"));

    ASSERT_TRUE(env.store->removeBlockedKey("alice"));
    EXPECT_FALSE(env.store->isBlockedKey("alice"));
    EXPECT_FALSE(env.store->removeBlockedKey("alice"))
        << "remove on missing row returns false";
}

TEST(AppDataStore, BlockedKeyAddIsIdempotent) {
    // Re-blocking refreshes the timestamp without error.
    auto env = makeEnv(randomKey32(), randomKey32());
    EXPECT_TRUE(env.store->addBlockedKey("alice", 100));
    EXPECT_TRUE(env.store->addBlockedKey("alice", 200));
    EXPECT_TRUE(env.store->isBlockedKey("alice"));

    std::vector<std::pair<std::string, int64_t>> rows;
    env.store->loadAllBlockedKeys(
        [&](const std::string& p, int64_t t) { rows.emplace_back(p, t); });
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].first,  "alice");
    EXPECT_EQ(rows[0].second, 200) << "re-block should refresh timestamp";
}

TEST(AppDataStore, BlockedKeysAreOrthogonalToContacts) {
    // A blocked key with no contacts row stands on its own; a contact
    // without a blocked_keys row is unblocked.  Block doesn't touch
    // contacts and contacts don't touch blocked_keys.
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Contact c;
    c.peerIdB64u = "alice";
    c.name = "Alice";
    env.store->saveContact(c);

    // Block a stranger (no contact row); contact for alice stays unblocked.
    env.store->addBlockedKey("stranger", 100);
    EXPECT_TRUE(env.store->isBlockedKey("stranger"));
    EXPECT_FALSE(env.store->isBlockedKey("alice"));

    AppDataStore::Contact loaded;
    EXPECT_TRUE(env.store->loadContact("alice", loaded));
    EXPECT_FALSE(env.store->loadContact("stranger", loaded))
        << "blocking didn't auto-create a contact row";

    // Block the curated contact too — both block records coexist with
    // the address-book entry untouched.
    env.store->addBlockedKey("alice", 200);
    EXPECT_TRUE(env.store->isBlockedKey("alice"));
    EXPECT_TRUE(env.store->loadContact("alice", loaded));
    EXPECT_EQ(loaded.name, "Alice")
        << "block didn't mutate the curated contact's name";
}

TEST(AppDataStore, BlockedKeysListedInInsertionOrder) {
    auto env = makeEnv(randomKey32(), randomKey32());
    env.store->addBlockedKey("third",  300);
    env.store->addBlockedKey("first",  100);
    env.store->addBlockedKey("second", 200);

    std::vector<std::string> order;
    env.store->loadAllBlockedKeys(
        [&](const std::string& p, int64_t) { order.push_back(p); });
    ASSERT_EQ(order.size(), 3u);
    EXPECT_EQ(order[0], "first");
    EXPECT_EQ(order[1], "second");
    EXPECT_EQ(order[2], "third");
}

TEST(AppDataStore, BlockedKeyEmptyGuards) {
    auto env = makeEnv(randomKey32(), randomKey32());
    EXPECT_FALSE(env.store->addBlockedKey("", 0));
    EXPECT_FALSE(env.store->removeBlockedKey(""));
    EXPECT_FALSE(env.store->isBlockedKey(""));
}

TEST(AppDataStore, DirectPeerIdIsUniquePerPeer) {
    // Partial UNIQUE index: at most one direct conversation per peer.
    auto env = makeEnv(randomKey32(), randomKey32());

    AppDataStore::Conversation a;
    a.id = "u-1"; a.kind = AppDataStore::ConversationKind::Direct;
    a.directPeerId = "alice";
    ASSERT_TRUE(env.store->saveConversation(a));

    AppDataStore::Conversation b;
    b.id = "u-2"; b.kind = AppDataStore::ConversationKind::Direct;
    b.directPeerId = "alice";  // collides
    EXPECT_FALSE(env.store->saveConversation(b));

    // Multiple groups (NULL direct_peer_id) coexist fine.
    AppDataStore::Conversation g1, g2;
    g1.id = "g-1"; g1.kind = AppDataStore::ConversationKind::Group;
    g2.id = "g-2"; g2.kind = AppDataStore::ConversationKind::Group;
    EXPECT_TRUE(env.store->saveConversation(g1));
    EXPECT_TRUE(env.store->saveConversation(g2));
}
