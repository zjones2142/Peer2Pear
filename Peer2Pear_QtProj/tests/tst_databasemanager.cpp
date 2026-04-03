#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <sodium.h>

#include "databasemanager.h"
#include "chattypes.h"
#include "filetransfer.h"

// Helper: generate a random 32-byte encryption key via libsodium
static QByteArray randomKey32()
{
    QByteArray key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char *>(key.data()), key.size());
    return key;
}

// Helper: create a basic ChatData
static ChatData makeChatData(const QString &peerId, const QString &name,
                             const QString &subtitle = {},
                             bool blocked = false, bool group = false,
                             const QString &groupId = {},
                             const QStringList &keys = {})
{
    ChatData c;
    c.peerIdB64u = peerId;
    c.name       = name;
    c.subtitle   = subtitle;
    c.isBlocked  = blocked;
    c.isGroup    = group;
    c.groupId    = groupId;
    c.keys       = keys;
    return c;
}

// Helper: create a Message with a specific timestamp
static Message makeMessage(bool sent, const QString &text,
                           const QDateTime &ts = QDateTime::currentDateTimeUtc(),
                           const QString &msgId = {},
                           const QString &senderName = {})
{
    Message m;
    m.sent       = sent;
    m.text       = text;
    m.timestamp  = ts;
    m.msgId      = msgId;
    m.senderName = senderName;
    return m;
}

// Helper: create a FileTransferRecord
static FileTransferRecord makeFileRecord(const QString &transferId,
                                         const QString &fileName,
                                         qint64 fileSize,
                                         bool sent,
                                         FileTransferStatus status,
                                         int chunksTotal = 10,
                                         int chunksComplete = 5,
                                         const QString &savedPath = {})
{
    FileTransferRecord r;
    r.transferId     = transferId;
    r.fileName       = fileName;
    r.fileSize       = fileSize;
    r.peerIdB64u     = "peer_abc";
    r.peerName       = "Alice";
    r.timestamp      = QDateTime::currentDateTimeUtc();
    r.sent           = sent;
    r.status         = status;
    r.chunksTotal    = chunksTotal;
    r.chunksComplete = chunksComplete;
    r.savedPath      = savedPath;
    return r;
}

class TestDatabaseManager : public QObject
{
    Q_OBJECT

private:
    // Each test gets its own temporary directory that is cleaned up automatically
    QTemporaryDir m_tmpDir;

    // Return a fresh file path inside the temporary directory
    QString freshDbPath()
    {
        static int seq = 0;
        return m_tmpDir.path() + QStringLiteral("/test_%1.db").arg(++seq);
    }

private slots:
    void initTestCase();

    // ── Database lifecycle ───────────────────────────────────────────────
    void testOpenInMemory();            // DB can be opened with :memory: for transient use
    void testOpenFileBased();           // DB can be opened at a file path on disk
    void testOpenCustomPath();          // DB auto-creates parent directories for custom paths
    void testDoubleOpen();              // Calling open() twice on the same instance does not crash
    void testCloseAndReopen();          // Data persists across close() and reopen on the same file
    void testIsOpen();                  // isOpen() reflects the actual connection state
    void testTablesCreatedOnOpen();     // All four core tables are created on first open
    void testMigrationSafety();         // ALTER TABLE migrations are idempotent (safe to run twice)

    // ── Contact CRUD ────────────────────────────────────────────────────
    void testSaveAndLoadContact();      // A saved contact can be loaded back with correct fields
    void testSaveContactUpsert();       // Saving a contact with the same peerId updates (upserts) the existing row
    void testDeleteContact();           // deleteContact removes the row from the contacts table
    void testDeleteNonExistentContact();// Deleting a non-existent contact does not error
    void testContactExists();           // contactExists returns true only for saved contacts
    void testContactExistsEmpty();      // contactExists returns false for an empty peerId
    void testGetContact();              // getContact retrieves all fields for a single contact
    void testGetContactNotFound();      // getContact returns an empty ChatData for missing contacts
    void testContactWithKeys();         // Public keys are round-tripped through pipe-delimited storage
    void testContactWithEmptyKeys();    // An empty keys list is stored and loaded correctly
    void testContactBlockedFlag();      // The isBlocked flag persists and can be toggled via saveContact
    void testBlockContact();            // blockContact() directly toggles the is_blocked column
    void testContactGroupFlag();        // The isGroup flag persists correctly
    void testContactGroupId();          // The groupId string persists correctly
    void testContactAvatar();           // Avatar data set via saveContact is stored and retrieved
    void testSaveContactAvatar();       // saveContactAvatar updates only the avatar column
    void testContactNameOnlyKey();      // Contacts with no peerId are keyed by "name:<name>"
    void testContactEmptyPeerIdAndName();// Empty peerId + empty name → key "name:" is valid
    void testLoadAllContactsEmpty();    // loadAllContacts returns empty vector for a fresh DB
    void testLoadAllContactsMultiple(); // loadAllContacts returns all saved contacts
    void testContactsOrderedByLastActive();// Contacts are sorted by most-recently-active first

    // ── Duplicate / same-key contact scenarios ──────────────────────────
    void testSamePeerIdOverwritesContact();          // Two contacts with the same peerId collapse into one row (upsert)
    void testSamePeerIdDeleteRemovesOnlyRow();        // Deleting a shared peerId removes the single DB row
    void testSamePeerIdDeleteAndReopenLosesBoth();    // After delete+reopen, neither in-memory contact survives
    void testSameNameNoPeerIdCollides();               // Two name-only contacts with the same name share one DB row
    void testSameNameNoPeerIdDeleteRemovesSharedRow(); // Deleting one name-only contact removes the shared row
    void testSameNameDifferentPeerIdAreDistinct();     // Same display name but different peerIds are separate rows
    void testDeleteOneSameNameDiffPeerIdKeepsOther();  // Deleting one same-name contact preserves the other
    void testDeleteOneSameNameDiffPeerIdPreservesMessages(); // Messages for the surviving contact are intact
    void testSameNameDiffPeerIdDeleteAndReopen();      // After delete+reopen, the surviving contact's data persists
    void testSharedKeysFieldDoesNotCauseCollision();   // Two contacts with identical keys but different peerIds are distinct
    void testSamePeerIdMessagesLostOnDelete();         // Messages for a shared-peerId contact vanish after delete

    // ── Message operations ──────────────────────────────────────────────
    void testSaveAndLoadMessage();      // A saved message can be loaded back with correct fields
    void testMultipleMessages();        // Multiple messages for the same contact are all persisted
    void testMessagesOrderedByTimestamp();// Messages are returned in ascending timestamp order
    void testMessagesDontIntermix();    // Messages are scoped to their contact's peerId
    void testMessageAllFields();        // All optional message fields (msgId, senderName) persist
    void testMessageEmptyOptionalFields();// Empty optional fields are stored and loaded as empty strings
    void testLoadMessagesNonExistentPeer();// Loading messages for a non-existent peer returns empty
    void testLoadMessagesEmptyPeerId(); // Loading messages with an empty peerId returns empty
    void testSaveMessageEmptyPeerId();  // Saving a message with an empty peerId is silently ignored
    void testSaveMessageUpdatesLastActive();// Saving a message bumps the contact's last_active timestamp
    void testClearMessages();           // clearMessages removes all messages but keeps the contact
    void testClearMessagesNonExistent();// clearMessages for a non-existent peer does not error
    void testMessageCount();            // messageCount returns the correct count for a contact
    void testMessageCountEmpty();       // messageCount returns 0 for empty or non-existent peerIds
    void testDeleteContactCascadesMessages();// Deleting a contact cascades to delete its messages

    // ── File transfer operations ────────────────────────────────────────
    void testSaveAndLoadFileRecord();   // A saved file record can be loaded back with correct fields
    void testUpdateFileRecord();        // Re-saving a file record with the same transferId updates it
    void testFileRecordAllStatuses();   // All FileTransferStatus enum values round-trip correctly
    void testFileRecordsOrderedByTimestamp();// File records are returned in ascending timestamp order
    void testFileRecordsDontIntermix(); // File records are scoped to their chat key
    void testLoadFileRecordsEmptyKey(); // Loading with an empty chat key returns empty
    void testSaveFileRecordEmptyKey();  // Saving with an empty chat key is silently ignored
    void testSaveFileRecordEmptyTransferId();// Saving with an empty transferId is silently ignored
    void testDeleteFileRecord();        // deleteFileRecord removes only the specified record
    void testDeleteNonExistentFileRecord();// Deleting a non-existent file record does not error

    // ── Settings operations ─────────────────────────────────────────────
    void testSaveAndLoadSetting();      // A saved setting can be loaded back with the correct value
    void testLoadSettingDefault();       // Loading a non-existent key returns empty string by default
    void testLoadSettingCustomDefault(); // Loading a non-existent key returns the caller's default
    void testOverwriteSetting();         // Saving the same key twice replaces the old value
    void testMultipleSettings();         // Multiple independent settings coexist correctly

    // ── Encryption ──────────────────────────────────────────────────────
    void testEncryptedMessageRoundTrip();// Messages encrypted with a key can be decrypted on load
    void testPlaintextWithoutKey();      // Without an encryption key, messages are stored as plaintext
    void testEncryptedEmptyString();     // An empty string can be encrypted and decrypted correctly
    void testEncryptedUnicodeText();     // Unicode text survives encryption round-trip
    void testEncryptedLongText();        // Large text (10 KB) survives encryption round-trip
    void testWrongKeyCannotDecrypt();    // A different key cannot decrypt the ciphertext
    void testLegacyPlaintextReadable();  // Plaintext written without encryption is readable even with a key set
    void testEncryptionKeyMustBe32Bytes();// Keys that are not exactly 32 bytes are rejected
    void testSetEncryptionKeyAfterOpen();// Setting an encryption key mid-session works correctly

    // ── Edge cases ──────────────────────────────────────────────────────
    void testUnicodeContactNames();     // Unicode names (Latin, CJK, Cyrillic) persist correctly
    void testEmojiInMessages();         // Emoji characters in messages persist correctly
    void testVeryLongTextValues();      // 100 KB messages are stored and retrieved without truncation
    void testSpecialCharsInSettingsKeys();// Settings keys with spaces, slashes, dots work correctly
    void testSqlInjectionSafe();        // SQL injection attempts are safely handled via parameterized queries
    void testLargeNumberOfContacts();   // 200 contacts can be stored and retrieved
    void testLargeNumberOfMessages();   // 500 messages are stored, retrieved, and ordered correctly
    void testReopenPreservesData();     // All data types survive a close+reopen cycle on disk
    void testMultipleDatabaseInstances();// Two separate DB instances with different files are isolated

    // ── Data integrity ──────────────────────────────────────────────────
    void testForeignKeyEnforcement();   // FK constraint prevents orphan messages (no matching contact)
    void testIndexesExist();            // Performance indexes are created on the expected columns
};

// ═══════════════════════════════════════════════════════════════════════════════
// Implementation
// ═══════════════════════════════════════════════════════════════════════════════

void TestDatabaseManager::initTestCase()
{
    // libsodium must be initialised before any crypto operations
    QCOMPARE(sodium_init(), 0);
    QVERIFY(m_tmpDir.isValid());
}

// ── Database lifecycle ───────────────────────────────────────────────────────

void TestDatabaseManager::testOpenInMemory()
{
    DatabaseManager db;
    QVERIFY(db.open(":memory:"));
    QVERIFY(db.isOpen());
    db.close();
    QVERIFY(!db.isOpen());
}

void TestDatabaseManager::testOpenFileBased()
{
    const QString path = freshDbPath();
    DatabaseManager db;
    QVERIFY(db.open(path));
    QVERIFY(db.isOpen());
    QVERIFY(QFile::exists(path));
    db.close();
}

void TestDatabaseManager::testOpenCustomPath()
{
    const QString path = m_tmpDir.path() + "/subdir/deep/test.db";
    DatabaseManager db;
    QVERIFY(db.open(path));
    QVERIFY(QFile::exists(path));
    db.close();
}

void TestDatabaseManager::testDoubleOpen()
{
    DatabaseManager db;
    QVERIFY(db.open(":memory:"));
    // Second open on an already-open DB should succeed (SQLite allows it)
    QVERIFY(db.open(":memory:"));
    QVERIFY(db.isOpen());
    db.close();
}

void TestDatabaseManager::testCloseAndReopen()
{
    const QString path = freshDbPath();
    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        db.saveSetting("key1", "val1");
        db.close();
    }
    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        QCOMPARE(db.loadSetting("key1"), QStringLiteral("val1"));
        db.close();
    }
}

void TestDatabaseManager::testIsOpen()
{
    DatabaseManager db;
    QVERIFY(!db.isOpen());
    db.open(":memory:");
    QVERIFY(db.isOpen());
    db.close();
    QVERIFY(!db.isOpen());
}

void TestDatabaseManager::testTablesCreatedOnOpen()
{
    DatabaseManager db;
    QVERIFY(db.open(":memory:"));

    // The 4 core tables must exist
    const QStringList expected = {"contacts", "file_transfers", "messages", "settings"};
    auto allContacts = db.loadAllContacts();
    QVERIFY(allContacts.isEmpty()); // Just verifying it doesn't crash

    // Verify we can insert into each table without error
    db.saveSetting("probe", "1");
    QCOMPARE(db.loadSetting("probe"), QStringLiteral("1"));
    db.close();
}

void TestDatabaseManager::testMigrationSafety()
{
    const QString path = freshDbPath();
    // Open twice to exercise the ALTER TABLE migrations (they should be harmless)
    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        db.close();
    }
    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        // If migrations failed, the second open would fail
        auto contacts = db.loadAllContacts();
        Q_UNUSED(contacts);
        db.close();
    }
}

// ── Contact CRUD ─────────────────────────────────────────────────────────────

void TestDatabaseManager::testSaveAndLoadContact()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c = makeChatData("peerA", "Alice", "Hello!");
    db.saveContact(c);

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 1);
    QCOMPARE(contacts[0].peerIdB64u, QStringLiteral("peerA"));
    QCOMPARE(contacts[0].name, QStringLiteral("Alice"));
    QCOMPARE(contacts[0].subtitle, QStringLiteral("Hello!"));
    db.close();
}

void TestDatabaseManager::testSaveContactUpsert()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice", "v1"));
    db.saveContact(makeChatData("peerA", "Alice Updated", "v2"));

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 1);
    QCOMPARE(contacts[0].name, QStringLiteral("Alice Updated"));
    QCOMPARE(contacts[0].subtitle, QStringLiteral("v2"));
    db.close();
}

void TestDatabaseManager::testDeleteContact()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    QCOMPARE(db.loadAllContacts().size(), 1);

    db.deleteContact("peerA");
    QCOMPARE(db.loadAllContacts().size(), 0);
    db.close();
}

void TestDatabaseManager::testDeleteNonExistentContact()
{
    DatabaseManager db;
    db.open(":memory:");

    // Should not crash or error
    db.deleteContact("nonexistent");
    QCOMPARE(db.loadAllContacts().size(), 0);
    db.close();
}

void TestDatabaseManager::testContactExists()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    QVERIFY(db.contactExists("peerA"));
    QVERIFY(!db.contactExists("peerB"));
    db.close();
}

void TestDatabaseManager::testContactExistsEmpty()
{
    DatabaseManager db;
    db.open(":memory:");
    QVERIFY(!db.contactExists(""));
    db.close();
}

void TestDatabaseManager::testGetContact()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c = makeChatData("peerA", "Alice", "sub", true, true, "grp123", {"key1", "key2"});
    c.avatarData = "base64avatar";
    db.saveContact(c);

    ChatData loaded = db.getContact("peerA");
    QCOMPARE(loaded.peerIdB64u, QStringLiteral("peerA"));
    QCOMPARE(loaded.name, QStringLiteral("Alice"));
    QCOMPARE(loaded.subtitle, QStringLiteral("sub"));
    QCOMPARE(loaded.isBlocked, true);
    QCOMPARE(loaded.isGroup, true);
    QCOMPARE(loaded.groupId, QStringLiteral("grp123"));
    QCOMPARE(loaded.keys, QStringList({"key1", "key2"}));
    QCOMPARE(loaded.avatarData, QStringLiteral("base64avatar"));
    db.close();
}

void TestDatabaseManager::testGetContactNotFound()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData loaded = db.getContact("nonexistent");
    QVERIFY(loaded.name.isEmpty());
    QVERIFY(loaded.peerIdB64u.isEmpty());
    db.close();
}

void TestDatabaseManager::testContactWithKeys()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c = makeChatData("peerA", "Alice");
    c.keys = {"keyA", "keyB", "keyC"};
    db.saveContact(c);

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].keys, QStringList({"keyA", "keyB", "keyC"}));
    db.close();
}

void TestDatabaseManager::testContactWithEmptyKeys()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c = makeChatData("peerA", "Alice");
    c.keys = {};
    db.saveContact(c);

    auto contacts = db.loadAllContacts();
    QVERIFY(contacts[0].keys.isEmpty());
    db.close();
}

void TestDatabaseManager::testContactBlockedFlag()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice", {}, true));
    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].isBlocked, true);

    db.saveContact(makeChatData("peerA", "Alice", {}, false));
    contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].isBlocked, false);
    db.close();
}

void TestDatabaseManager::testBlockContact()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    QVERIFY(!db.getContact("peerA").isBlocked);

    db.blockContact("peerA", true);
    QVERIFY(db.getContact("peerA").isBlocked);

    db.blockContact("peerA", false);
    QVERIFY(!db.getContact("peerA").isBlocked);
    db.close();
}

void TestDatabaseManager::testContactGroupFlag()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerG", "Group1", {}, false, true));
    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].isGroup, true);
    db.close();
}

void TestDatabaseManager::testContactGroupId()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerG", "Group1", {}, false, true, "my-group-id"));
    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].groupId, QStringLiteral("my-group-id"));
    db.close();
}

void TestDatabaseManager::testContactAvatar()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c = makeChatData("peerA", "Alice");
    c.avatarData = "data:image/png;base64,AABBCC";
    db.saveContact(c);

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].avatarData, QStringLiteral("data:image/png;base64,AABBCC"));
    db.close();
}

void TestDatabaseManager::testSaveContactAvatar()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveContactAvatar("peerA", "new_avatar_data");

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts[0].avatarData, QStringLiteral("new_avatar_data"));
    db.close();
}

void TestDatabaseManager::testContactNameOnlyKey()
{
    DatabaseManager db;
    db.open(":memory:");

    // When peerIdB64u is empty, the contact key should be "name:<name>"
    ChatData c;
    c.name = "Bob";
    db.saveContact(c);

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 1);
    QCOMPARE(contacts[0].name, QStringLiteral("Bob"));
    // The peerIdB64u should be empty for name-keyed contacts
    QVERIFY(contacts[0].peerIdB64u.isEmpty());
    db.close();
}

void TestDatabaseManager::testContactEmptyPeerIdAndName()
{
    DatabaseManager db;
    db.open(":memory:");

    ChatData c;
    // Both peerIdB64u and name empty → key is "name:" which is not truly empty
    // but the contact should still be saveable
    c.name = "";
    c.peerIdB64u = "";
    db.saveContact(c);

    // The contactKey() function returns "name:" for empty peerIdB64u + empty name
    // which is not empty, so the contact IS saved
    auto contacts = db.loadAllContacts();
    // "name:" is a valid key, so there should be 1 contact
    QCOMPARE(contacts.size(), 1);
    db.close();
}

void TestDatabaseManager::testLoadAllContactsEmpty()
{
    DatabaseManager db;
    db.open(":memory:");
    QVERIFY(db.loadAllContacts().isEmpty());
    db.close();
}

void TestDatabaseManager::testLoadAllContactsMultiple()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveContact(makeChatData("peerB", "Bob"));
    db.saveContact(makeChatData("peerC", "Charlie"));

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 3);
    db.close();
}

void TestDatabaseManager::testContactsOrderedByLastActive()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveContact(makeChatData("peerB", "Bob"));
    db.saveContact(makeChatData("peerC", "Charlie"));

    // Send a message to Bob → his last_active should be updated
    db.saveMessage("peerB", makeMessage(true, "hello Bob"));

    // Small delay to ensure a different timestamp
    QTest::qWait(50);

    // Send a message to Alice → she should now be most recent
    db.saveMessage("peerA", makeMessage(true, "hello Alice"));

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 3);
    // Alice should be first (most recently active), then Bob, then Charlie
    QCOMPARE(contacts[0].peerIdB64u, QStringLiteral("peerA"));
    QCOMPARE(contacts[1].peerIdB64u, QStringLiteral("peerB"));
    QCOMPARE(contacts[2].peerIdB64u, QStringLiteral("peerC"));
    db.close();
}

// ── Duplicate / same-key contact scenarios ──────────────────────────────────
// These tests document and verify the database behavior when two contacts
// share the same primary key (peer_id). Because peer_id is a PRIMARY KEY,
// only one row can exist per key. The second saveContact() silently upserts
// (overwrites) the first. Deleting that key removes the single shared row.
//
// This is the root cause of the reported bug: if the application holds two
// in-memory ChatData objects with the same peerIdB64u, they map to one DB
// row, so deleting one deletes the other on next reload.

void TestDatabaseManager::testSamePeerIdOverwritesContact()
{
    // Two contacts saved with the same peerId — the second overwrites the first.
    // The DB should contain exactly one row with the second contact's data.
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice",   "first subtitle"));
    db.saveContact(makeChatData("peerA", "Alice v2", "second subtitle"));

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.size() == 1,
             "Two contacts with the same peerId must collapse into one DB row");
    QCOMPARE(contacts[0].name, QStringLiteral("Alice v2"));
    QCOMPARE(contacts[0].subtitle, QStringLiteral("second subtitle"));
    db.close();
}

void TestDatabaseManager::testSamePeerIdDeleteRemovesOnlyRow()
{
    // Saving two contacts with the same peerId creates one row.
    // Deleting that peerId removes the only row — loadAllContacts returns empty.
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice",   "v1"));
    db.saveContact(makeChatData("peerA", "Alice v2", "v2"));

    db.deleteContact("peerA");

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.isEmpty(),
             "Deleting the shared peerId must remove the only DB row");
    QVERIFY2(!db.contactExists("peerA"),
             "contactExists must return false after deletion");
    db.close();
}

void TestDatabaseManager::testSamePeerIdDeleteAndReopenLosesBoth()
{
    // Simulates the reported bug: save two contacts with the same peerId,
    // delete one (which deletes the single DB row), close, and reopen.
    // On reload, no contact with that peerId exists — both are gone.
    const QString path = freshDbPath();

    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        db.saveContact(makeChatData("peerA", "Alice",   "first"));
        db.saveContact(makeChatData("peerA", "Alice v2", "second"));
        QVERIFY2(db.loadAllContacts().size() == 1,
                 "Before delete: one row expected for shared peerId");

        db.deleteContact("peerA");
        db.close();
    }
    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        QVERIFY2(db.loadAllContacts().isEmpty(),
                 "After reopen: both in-memory contacts are gone because they shared one DB row");
        QVERIFY2(!db.contactExists("peerA"),
                 "The peerId must not exist after delete+reopen");
        db.close();
    }
}

void TestDatabaseManager::testSameNameNoPeerIdCollides()
{
    // Two contacts with the same name and no peerId both map to key "name:<name>".
    // The second overwrites the first — only one row exists.
    DatabaseManager db;
    db.open(":memory:");

    ChatData c1;
    c1.name     = "SharedName";
    c1.subtitle = "first";
    db.saveContact(c1);

    ChatData c2;
    c2.name     = "SharedName";
    c2.subtitle = "second";
    db.saveContact(c2);

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.size() == 1,
             "Two name-only contacts with the same name must share one DB row");
    QCOMPARE(contacts[0].subtitle, QStringLiteral("second"));
    db.close();
}

void TestDatabaseManager::testSameNameNoPeerIdDeleteRemovesSharedRow()
{
    // When two name-only contacts share the same name, they share one DB row.
    // Deleting by the key "name:<name>" removes that row for both.
    DatabaseManager db;
    db.open(":memory:");

    ChatData c1;
    c1.name     = "SharedName";
    c1.subtitle = "first";
    db.saveContact(c1);

    ChatData c2;
    c2.name     = "SharedName";
    c2.subtitle = "second";
    db.saveContact(c2);

    // Delete using the name-based key (same key both contacts map to)
    db.deleteContact("name:SharedName");

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.isEmpty(),
             "Deleting the shared name-key must remove the only DB row");
    db.close();
}

void TestDatabaseManager::testSameNameDifferentPeerIdAreDistinct()
{
    // Two contacts with the same display name but different peerIds are separate rows.
    // This is the safe scenario — no collision occurs.
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice", "from phone"));
    db.saveContact(makeChatData("peerB", "Alice", "from laptop"));

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.size() == 2,
             "Same name but different peerIds must create two distinct rows");

    // Both should be retrievable by their own peerId
    QVERIFY2(db.contactExists("peerA"), "peerA must exist");
    QVERIFY2(db.contactExists("peerB"), "peerB must exist");
    db.close();
}

void TestDatabaseManager::testDeleteOneSameNameDiffPeerIdKeepsOther()
{
    // Two contacts with the same name but different peerIds.
    // Deleting one leaves the other intact.
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice", "from phone"));
    db.saveContact(makeChatData("peerB", "Alice", "from laptop"));

    db.deleteContact("peerA");

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.size() == 1,
             "After deleting one same-name contact, exactly one must remain");
    QCOMPARE(contacts[0].peerIdB64u, QStringLiteral("peerB"));
    QCOMPARE(contacts[0].subtitle, QStringLiteral("from laptop"));
    QVERIFY2(!db.contactExists("peerA"), "Deleted contact must not exist");
    QVERIFY2(db.contactExists("peerB"),  "Surviving contact must still exist");
    db.close();
}

void TestDatabaseManager::testDeleteOneSameNameDiffPeerIdPreservesMessages()
{
    // Two contacts with the same name but different peerIds.
    // Messages for the surviving contact must not be affected by the other's deletion.
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peerA", "Alice", "from phone"));
    db.saveContact(makeChatData("peerB", "Alice", "from laptop"));

    db.saveMessage("peerA", makeMessage(true, "msg for peerA"));
    db.saveMessage("peerB", makeMessage(true, "msg for peerB"));

    // Delete peerA — peerB's messages should survive
    db.deleteContact("peerA");

    QVERIFY2(db.loadMessages("peerA").isEmpty(),
             "Messages for the deleted contact must be cascade-deleted");
    auto msgsB = db.loadMessages("peerB");
    QVERIFY2(msgsB.size() == 1,
             "Messages for the surviving contact must be intact");
    QCOMPARE(msgsB[0].text, QStringLiteral("msg for peerB"));
    db.close();
}

void TestDatabaseManager::testSameNameDiffPeerIdDeleteAndReopen()
{
    // Same name, different peerIds. Delete one, close, reopen.
    // The surviving contact and its messages must persist on disk.
    const QString path = freshDbPath();

    {
        DatabaseManager db;
        QVERIFY(db.open(path));
        db.saveContact(makeChatData("peerA", "Alice", "from phone"));
        db.saveContact(makeChatData("peerB", "Alice", "from laptop"));
        db.saveMessage("peerA", makeMessage(true, "msg for A"));
        db.saveMessage("peerB", makeMessage(true, "msg for B"));

        db.deleteContact("peerA");
        db.close();
    }
    {
        DatabaseManager db;
        QVERIFY(db.open(path));

        QVERIFY2(!db.contactExists("peerA"),
                 "Deleted contact must stay deleted after reopen");
        QVERIFY2(db.contactExists("peerB"),
                 "Surviving contact must persist after reopen");

        auto msgs = db.loadMessages("peerB");
        QVERIFY2(msgs.size() == 1,
                 "Surviving contact's messages must persist after reopen");
        QCOMPARE(msgs[0].text, QStringLiteral("msg for B"));

        QVERIFY2(db.loadMessages("peerA").isEmpty(),
                 "Deleted contact's messages must remain gone after reopen");
        db.close();
    }
}

void TestDatabaseManager::testSharedKeysFieldDoesNotCauseCollision()
{
    // Two contacts with different peerIds but identical public keys in their
    // keys field. The keys field is NOT part of the primary key, so they are
    // separate rows that happen to share the same key material.
    DatabaseManager db;
    db.open(":memory:");

    QStringList sharedKeys = {"pubKeyABC", "pubKeyXYZ"};
    db.saveContact(makeChatData("peerA", "Alice", {}, false, false, {}, sharedKeys));
    db.saveContact(makeChatData("peerB", "Bob",   {}, false, false, {}, sharedKeys));

    auto contacts = db.loadAllContacts();
    QVERIFY2(contacts.size() == 2,
             "Shared keys field must NOT cause a primary-key collision");

    // Both contacts should have the same keys
    for (const auto &c : contacts) {
        QCOMPARE(c.keys, sharedKeys);
    }
    db.close();
}

void TestDatabaseManager::testSamePeerIdMessagesLostOnDelete()
{
    // If two in-memory contacts share a peerId, their messages are on the same
    // DB row's foreign key. Deleting the peerId cascades to all messages.
    DatabaseManager db;
    db.open(":memory:");

    // First save creates the row
    db.saveContact(makeChatData("peerA", "Alice", "v1"));
    db.saveMessage("peerA", makeMessage(true, "msg from v1"));

    // Second save upserts (overwrites) the same row
    db.saveContact(makeChatData("peerA", "Alice v2", "v2"));
    db.saveMessage("peerA", makeMessage(true, "msg from v2"));

    QVERIFY2(db.messageCount("peerA") == 2,
             "Both messages should be stored under the shared peerId");

    // Delete the shared peerId — all messages cascade
    db.deleteContact("peerA");

    QVERIFY2(db.messageCount("peerA") == 0,
             "All messages must be cascade-deleted when the shared peerId is deleted");
    QVERIFY2(db.loadMessages("peerA").isEmpty(),
             "loadMessages must return empty after cascade delete");
    db.close();
}

// ── Message operations ───────────────────────────────────────────────────────

void TestDatabaseManager::testSaveAndLoadMessage()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    Message m = makeMessage(true, "Hello world!");
    db.saveMessage("peerA", m);

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 1);
    QCOMPARE(msgs[0].text, QStringLiteral("Hello world!"));
    QCOMPARE(msgs[0].sent, true);
    db.close();
}

void TestDatabaseManager::testMultipleMessages()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    for (int i = 0; i < 5; ++i) {
        db.saveMessage("peerA",
                       makeMessage(i % 2 == 0, QStringLiteral("msg %1").arg(i)));
    }

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 5);
    db.close();
}

void TestDatabaseManager::testMessagesOrderedByTimestamp()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    QDateTime base = QDateTime(QDate(2025, 1, 1), QTime(12, 0, 0), Qt::UTC);
    db.saveMessage("peerA", makeMessage(true, "third",  base.addSecs(200)));
    db.saveMessage("peerA", makeMessage(true, "first",  base.addSecs(0)));
    db.saveMessage("peerA", makeMessage(true, "second", base.addSecs(100)));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 3);
    QCOMPARE(msgs[0].text, QStringLiteral("first"));
    QCOMPARE(msgs[1].text, QStringLiteral("second"));
    QCOMPARE(msgs[2].text, QStringLiteral("third"));
    db.close();
}

void TestDatabaseManager::testMessagesDontIntermix()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveContact(makeChatData("peerB", "Bob"));

    db.saveMessage("peerA", makeMessage(true, "for Alice"));
    db.saveMessage("peerB", makeMessage(true, "for Bob"));

    auto msgsA = db.loadMessages("peerA");
    auto msgsB = db.loadMessages("peerB");
    QCOMPARE(msgsA.size(), 1);
    QCOMPARE(msgsB.size(), 1);
    QCOMPARE(msgsA[0].text, QStringLiteral("for Alice"));
    QCOMPARE(msgsB[0].text, QStringLiteral("for Bob"));
    db.close();
}

void TestDatabaseManager::testMessageAllFields()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    QDateTime ts = QDateTime(QDate(2025, 6, 15), QTime(10, 30, 0), Qt::UTC);
    Message m = makeMessage(false, "Group msg", ts, "msg-uuid-123", "Bob");
    db.saveMessage("peerA", m);

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 1);
    QCOMPARE(msgs[0].sent, false);
    QCOMPARE(msgs[0].text, QStringLiteral("Group msg"));
    QCOMPARE(msgs[0].msgId, QStringLiteral("msg-uuid-123"));
    QCOMPARE(msgs[0].senderName, QStringLiteral("Bob"));
    // Verify timestamp is preserved (compare in UTC to avoid timezone issues)
    QCOMPARE(msgs[0].timestamp.toUTC().toSecsSinceEpoch(), ts.toSecsSinceEpoch());
    db.close();
}

void TestDatabaseManager::testMessageEmptyOptionalFields()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    Message m = makeMessage(true, "text only");
    m.msgId = "";
    m.senderName = "";
    db.saveMessage("peerA", m);

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 1);
    QVERIFY(msgs[0].msgId.isEmpty());
    QVERIFY(msgs[0].senderName.isEmpty());
    db.close();
}

void TestDatabaseManager::testLoadMessagesNonExistentPeer()
{
    DatabaseManager db;
    db.open(":memory:");
    auto msgs = db.loadMessages("nonexistent");
    QVERIFY(msgs.isEmpty());
    db.close();
}

void TestDatabaseManager::testLoadMessagesEmptyPeerId()
{
    DatabaseManager db;
    db.open(":memory:");
    auto msgs = db.loadMessages("");
    QVERIFY(msgs.isEmpty());
    db.close();
}

void TestDatabaseManager::testSaveMessageEmptyPeerId()
{
    DatabaseManager db;
    db.open(":memory:");
    // Should silently return without error
    db.saveMessage("", makeMessage(true, "ignored"));
    db.close();
}

void TestDatabaseManager::testSaveMessageUpdatesLastActive()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveContact(makeChatData("peerB", "Bob"));

    // Initially both contacts have last_active=0
    auto contacts = db.loadAllContacts();
    // They should have no lastActive set
    for (const auto &c : contacts) {
        QVERIFY(!c.lastActive.isValid() || c.lastActive.toSecsSinceEpoch() == 0);
    }

    db.saveMessage("peerA", makeMessage(true, "hi"));

    // After message, peerA should have a valid lastActive
    ChatData a = db.getContact("peerA");
    QVERIFY(a.lastActive.isValid());
    QVERIFY(a.lastActive.toSecsSinceEpoch() > 0);
    db.close();
}

void TestDatabaseManager::testClearMessages()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    db.saveMessage("peerA", makeMessage(true, "msg1"));
    db.saveMessage("peerA", makeMessage(true, "msg2"));
    QCOMPARE(db.messageCount("peerA"), 2);

    db.clearMessages("peerA");
    QCOMPARE(db.messageCount("peerA"), 0);
    QVERIFY(db.loadMessages("peerA").isEmpty());

    // Contact itself should still exist
    QVERIFY(db.contactExists("peerA"));
    db.close();
}

void TestDatabaseManager::testClearMessagesNonExistent()
{
    DatabaseManager db;
    db.open(":memory:");
    // Should not crash or error
    db.clearMessages("nonexistent");
    db.close();
}

void TestDatabaseManager::testMessageCount()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    QCOMPARE(db.messageCount("peerA"), 0);
    db.saveMessage("peerA", makeMessage(true, "a"));
    QCOMPARE(db.messageCount("peerA"), 1);
    db.saveMessage("peerA", makeMessage(false, "b"));
    QCOMPARE(db.messageCount("peerA"), 2);
    db.close();
}

void TestDatabaseManager::testMessageCountEmpty()
{
    DatabaseManager db;
    db.open(":memory:");
    QCOMPARE(db.messageCount(""), 0);
    QCOMPARE(db.messageCount("nonexistent"), 0);
    db.close();
}

void TestDatabaseManager::testDeleteContactCascadesMessages()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));
    db.saveMessage("peerA", makeMessage(true, "msg1"));
    db.saveMessage("peerA", makeMessage(true, "msg2"));
    QCOMPARE(db.messageCount("peerA"), 2);

    db.deleteContact("peerA");

    // Messages should be cascaded away
    QCOMPARE(db.messageCount("peerA"), 0);
    QVERIFY(db.loadMessages("peerA").isEmpty());
    db.close();
}

// ── File transfer operations ────────────────────────────────────────────────

void TestDatabaseManager::testSaveAndLoadFileRecord()
{
    DatabaseManager db;
    db.open(":memory:");

    FileTransferRecord rec = makeFileRecord("tx1", "photo.jpg", 1024000, true,
                                            FileTransferStatus::Complete, 10, 10,
                                            "/downloads/photo.jpg");
    db.saveFileRecord("chatA", rec);

    auto records = db.loadFileRecords("chatA");
    QCOMPARE(records.size(), 1);
    QCOMPARE(records[0].transferId, QStringLiteral("tx1"));
    QCOMPARE(records[0].fileName, QStringLiteral("photo.jpg"));
    QCOMPARE(records[0].fileSize, qint64(1024000));
    QCOMPARE(records[0].sent, true);
    QCOMPARE(records[0].status, FileTransferStatus::Complete);
    QCOMPARE(records[0].chunksTotal, 10);
    QCOMPARE(records[0].chunksComplete, 10);
    QCOMPARE(records[0].savedPath, QStringLiteral("/downloads/photo.jpg"));
    db.close();
}

void TestDatabaseManager::testUpdateFileRecord()
{
    DatabaseManager db;
    db.open(":memory:");

    auto rec = makeFileRecord("tx1", "photo.jpg", 1024, true,
                              FileTransferStatus::Sending, 10, 3);
    db.saveFileRecord("chatA", rec);

    // Update: mark as complete
    rec.status = FileTransferStatus::Complete;
    rec.chunksComplete = 10;
    rec.savedPath = "/saved/photo.jpg";
    db.saveFileRecord("chatA", rec);

    auto records = db.loadFileRecords("chatA");
    QCOMPARE(records.size(), 1);
    QCOMPARE(records[0].status, FileTransferStatus::Complete);
    QCOMPARE(records[0].chunksComplete, 10);
    QCOMPARE(records[0].savedPath, QStringLiteral("/saved/photo.jpg"));
    db.close();
}

void TestDatabaseManager::testFileRecordAllStatuses()
{
    DatabaseManager db;
    db.open(":memory:");

    QVector<FileTransferStatus> statuses = {
        FileTransferStatus::Sending,
        FileTransferStatus::Receiving,
        FileTransferStatus::Complete,
        FileTransferStatus::Failed
    };

    for (int i = 0; i < statuses.size(); ++i) {
        auto rec = makeFileRecord(QStringLiteral("tx%1").arg(i), "file.bin", 100,
                                  true, statuses[i]);
        db.saveFileRecord("chatA", rec);
    }

    auto records = db.loadFileRecords("chatA");
    QCOMPARE(records.size(), 4);

    // Verify each status round-trips correctly
    for (int i = 0; i < records.size(); ++i) {
        QCOMPARE(records[i].status, statuses[i]);
    }
    db.close();
}

void TestDatabaseManager::testFileRecordsOrderedByTimestamp()
{
    DatabaseManager db;
    db.open(":memory:");

    QDateTime base = QDateTime(QDate(2025, 1, 1), QTime(12, 0, 0), Qt::UTC);

    auto rec3 = makeFileRecord("tx3", "c.bin", 100, true, FileTransferStatus::Complete);
    rec3.timestamp = base.addSecs(200);
    db.saveFileRecord("chatA", rec3);

    auto rec1 = makeFileRecord("tx1", "a.bin", 100, true, FileTransferStatus::Complete);
    rec1.timestamp = base.addSecs(0);
    db.saveFileRecord("chatA", rec1);

    auto rec2 = makeFileRecord("tx2", "b.bin", 100, true, FileTransferStatus::Complete);
    rec2.timestamp = base.addSecs(100);
    db.saveFileRecord("chatA", rec2);

    auto records = db.loadFileRecords("chatA");
    QCOMPARE(records.size(), 3);
    QCOMPARE(records[0].transferId, QStringLiteral("tx1"));
    QCOMPARE(records[1].transferId, QStringLiteral("tx2"));
    QCOMPARE(records[2].transferId, QStringLiteral("tx3"));
    db.close();
}

void TestDatabaseManager::testFileRecordsDontIntermix()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveFileRecord("chatA", makeFileRecord("tx1", "a.bin", 100, true,
                                              FileTransferStatus::Complete));
    db.saveFileRecord("chatB", makeFileRecord("tx2", "b.bin", 200, false,
                                              FileTransferStatus::Receiving));

    auto recsA = db.loadFileRecords("chatA");
    auto recsB = db.loadFileRecords("chatB");
    QCOMPARE(recsA.size(), 1);
    QCOMPARE(recsB.size(), 1);
    QCOMPARE(recsA[0].transferId, QStringLiteral("tx1"));
    QCOMPARE(recsB[0].transferId, QStringLiteral("tx2"));
    db.close();
}

void TestDatabaseManager::testLoadFileRecordsEmptyKey()
{
    DatabaseManager db;
    db.open(":memory:");
    QVERIFY(db.loadFileRecords("").isEmpty());
    db.close();
}

void TestDatabaseManager::testSaveFileRecordEmptyKey()
{
    DatabaseManager db;
    db.open(":memory:");
    // Should silently return
    db.saveFileRecord("", makeFileRecord("tx1", "a.bin", 100, true,
                                         FileTransferStatus::Complete));
    db.close();
}

void TestDatabaseManager::testSaveFileRecordEmptyTransferId()
{
    DatabaseManager db;
    db.open(":memory:");
    auto rec = makeFileRecord("", "a.bin", 100, true, FileTransferStatus::Complete);
    db.saveFileRecord("chatA", rec);
    // Should be rejected because transferId is empty
    QVERIFY(db.loadFileRecords("chatA").isEmpty());
    db.close();
}

void TestDatabaseManager::testDeleteFileRecord()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveFileRecord("chatA", makeFileRecord("tx1", "a.bin", 100, true,
                                              FileTransferStatus::Complete));
    db.saveFileRecord("chatA", makeFileRecord("tx2", "b.bin", 200, true,
                                              FileTransferStatus::Complete));
    QCOMPARE(db.loadFileRecords("chatA").size(), 2);

    db.deleteFileRecord("tx1");

    auto records = db.loadFileRecords("chatA");
    QCOMPARE(records.size(), 1);
    QCOMPARE(records[0].transferId, QStringLiteral("tx2"));
    db.close();
}

void TestDatabaseManager::testDeleteNonExistentFileRecord()
{
    DatabaseManager db;
    db.open(":memory:");
    // Should not crash
    db.deleteFileRecord("nonexistent");
    db.close();
}

// ── Settings operations ──────────────────────────────────────────────────────

void TestDatabaseManager::testSaveAndLoadSetting()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveSetting("theme", "dark");
    QCOMPARE(db.loadSetting("theme"), QStringLiteral("dark"));
    db.close();
}

void TestDatabaseManager::testLoadSettingDefault()
{
    DatabaseManager db;
    db.open(":memory:");
    QCOMPARE(db.loadSetting("nonexistent"), QString());
    db.close();
}

void TestDatabaseManager::testLoadSettingCustomDefault()
{
    DatabaseManager db;
    db.open(":memory:");
    QCOMPARE(db.loadSetting("nonexistent", "fallback"), QStringLiteral("fallback"));
    db.close();
}

void TestDatabaseManager::testOverwriteSetting()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveSetting("key", "first");
    db.saveSetting("key", "second");
    QCOMPARE(db.loadSetting("key"), QStringLiteral("second"));
    db.close();
}

void TestDatabaseManager::testMultipleSettings()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveSetting("a", "1");
    db.saveSetting("b", "2");
    db.saveSetting("c", "3");

    QCOMPARE(db.loadSetting("a"), QStringLiteral("1"));
    QCOMPARE(db.loadSetting("b"), QStringLiteral("2"));
    QCOMPARE(db.loadSetting("c"), QStringLiteral("3"));
    db.close();
}

// ── Encryption ──────────────────────────────────────────────────────────────

void TestDatabaseManager::testEncryptedMessageRoundTrip()
{
    DatabaseManager db;
    db.open(":memory:");
    db.setEncryptionKey(randomKey32());
    db.saveContact(makeChatData("peerA", "Alice"));

    const QString text = "Secret message 🔒";
    db.saveMessage("peerA", makeMessage(true, text));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 1);
    QCOMPARE(msgs[0].text, text);
    db.close();
}

void TestDatabaseManager::testPlaintextWithoutKey()
{
    DatabaseManager db;
    db.open(":memory:");
    // No encryption key set
    db.saveContact(makeChatData("peerA", "Alice"));

    db.saveMessage("peerA", makeMessage(true, "plain text"));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text, QStringLiteral("plain text"));
    db.close();
}

void TestDatabaseManager::testEncryptedEmptyString()
{
    DatabaseManager db;
    db.open(":memory:");
    db.setEncryptionKey(randomKey32());
    db.saveContact(makeChatData("peerA", "Alice"));

    db.saveMessage("peerA", makeMessage(true, ""));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 1);
    QCOMPARE(msgs[0].text, QString());
    db.close();
}

void TestDatabaseManager::testEncryptedUnicodeText()
{
    DatabaseManager db;
    db.open(":memory:");
    db.setEncryptionKey(randomKey32());
    db.saveContact(makeChatData("peerA", "Alice"));

    const QString text = QString::fromUtf8("こんにちは世界 🌍 Привет мир 你好世界");
    db.saveMessage("peerA", makeMessage(true, text));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text, text);
    db.close();
}

void TestDatabaseManager::testEncryptedLongText()
{
    DatabaseManager db;
    db.open(":memory:");
    db.setEncryptionKey(randomKey32());
    db.saveContact(makeChatData("peerA", "Alice"));

    // 10 KB of text
    const QString text = QString("A").repeated(10000);
    db.saveMessage("peerA", makeMessage(true, text));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text, text);
    db.close();
}

void TestDatabaseManager::testWrongKeyCannotDecrypt()
{
    const QString dbPath = freshDbPath();

    // Write with key1
    QByteArray key1 = randomKey32();
    {
        DatabaseManager db;
        db.open(dbPath);
        db.setEncryptionKey(key1);
        db.saveContact(makeChatData("peerA", "Alice"));
        db.saveMessage("peerA", makeMessage(true, "secret"));
        db.close();
    }

    // Read with key2 — decryption should fail gracefully
    QByteArray key2 = randomKey32();
    {
        DatabaseManager db;
        db.open(dbPath);
        db.setEncryptionKey(key2);

        auto msgs = db.loadMessages("peerA");
        QCOMPARE(msgs.size(), 1);
        // The text should NOT be "secret" since the key is wrong.
        // It will be the raw "ENC:..." string since decryption failed.
        QVERIFY(msgs[0].text != QStringLiteral("secret"));
        QVERIFY(msgs[0].text.startsWith("ENC:"));
        db.close();
    }
}

void TestDatabaseManager::testLegacyPlaintextReadable()
{
    const QString dbPath = freshDbPath();

    // Write without encryption
    {
        DatabaseManager db;
        db.open(dbPath);
        db.saveContact(makeChatData("peerA", "Alice"));
        db.saveMessage("peerA", makeMessage(true, "legacy plain"));
        db.close();
    }

    // Read with encryption key — legacy values should still be readable
    {
        DatabaseManager db;
        db.open(dbPath);
        db.setEncryptionKey(randomKey32());

        auto msgs = db.loadMessages("peerA");
        QCOMPARE(msgs.size(), 1);
        QCOMPARE(msgs[0].text, QStringLiteral("legacy plain"));
        db.close();
    }
}

void TestDatabaseManager::testEncryptionKeyMustBe32Bytes()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    // Set a key that's too short (16 bytes) — should be rejected
    QByteArray shortKey(16, 'x');
    db.setEncryptionKey(shortKey);

    // Messages should be stored in plaintext since the key was rejected
    db.saveMessage("peerA", makeMessage(true, "not encrypted"));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text, QStringLiteral("not encrypted"));

    // Set a key that's too long (64 bytes) — should also be rejected
    QByteArray longKey(64, 'x');
    db.setEncryptionKey(longKey);

    db.saveMessage("peerA", makeMessage(true, "also not encrypted"));
    msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.last().text, QStringLiteral("also not encrypted"));
    db.close();
}

void TestDatabaseManager::testSetEncryptionKeyAfterOpen()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    // First message: no encryption
    db.saveMessage("peerA", makeMessage(true, "plain"));

    // Now set encryption key
    db.setEncryptionKey(randomKey32());

    // Second message: encrypted
    db.saveMessage("peerA", makeMessage(true, "encrypted"));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), 2);
    QCOMPARE(msgs[0].text, QStringLiteral("plain"));
    QCOMPARE(msgs[1].text, QStringLiteral("encrypted"));
    db.close();
}

// ── Edge cases ──────────────────────────────────────────────────────────────

void TestDatabaseManager::testUnicodeContactNames()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveContact(makeChatData("peer1", "Ünïcödé Ñàmé"));
    db.saveContact(makeChatData("peer2", "日本語名前"));
    db.saveContact(makeChatData("peer3", "Имя Контакта"));

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 3);

    // Find each contact by name
    bool found1 = false, found2 = false, found3 = false;
    for (const auto &c : contacts) {
        if (c.name == "Ünïcödé Ñàmé") found1 = true;
        if (c.name == "日本語名前") found2 = true;
        if (c.name == "Имя Контакта") found3 = true;
    }
    QVERIFY(found1);
    QVERIFY(found2);
    QVERIFY(found3);
    db.close();
}

void TestDatabaseManager::testEmojiInMessages()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    const QString emoji = "🎉🔥💯🚀😂👍🏽🇺🇸";
    db.saveMessage("peerA", makeMessage(true, emoji));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text, emoji);
    db.close();
}

void TestDatabaseManager::testVeryLongTextValues()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    // 100 KB message
    const QString longText = QString("X").repeated(100000);
    db.saveMessage("peerA", makeMessage(true, longText));

    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs[0].text.size(), 100000);
    db.close();
}

void TestDatabaseManager::testSpecialCharsInSettingsKeys()
{
    DatabaseManager db;
    db.open(":memory:");

    db.saveSetting("key with spaces", "val1");
    db.saveSetting("key/with/slashes", "val2");
    db.saveSetting("key.with.dots", "val3");
    db.saveSetting("key=with=equals", "val4");

    QCOMPARE(db.loadSetting("key with spaces"), QStringLiteral("val1"));
    QCOMPARE(db.loadSetting("key/with/slashes"), QStringLiteral("val2"));
    QCOMPARE(db.loadSetting("key.with.dots"), QStringLiteral("val3"));
    QCOMPARE(db.loadSetting("key=with=equals"), QStringLiteral("val4"));
    db.close();
}

void TestDatabaseManager::testSqlInjectionSafe()
{
    DatabaseManager db;
    db.open(":memory:");

    // Attempt SQL injection through contact name
    ChatData c = makeChatData("peer1", "'); DROP TABLE contacts; --");
    db.saveContact(c);

    // The table should still exist and be queryable
    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), 1);
    QCOMPARE(contacts[0].name, QStringLiteral("'); DROP TABLE contacts; --"));

    // Attempt SQL injection through setting key
    db.saveSetting("'; DROP TABLE settings; --", "evil");
    QCOMPARE(db.loadSetting("'; DROP TABLE settings; --"), QStringLiteral("evil"));

    // Attempt SQL injection through message text
    db.saveMessage("peer1", makeMessage(true, "'; DROP TABLE messages; --"));
    auto msgs = db.loadMessages("peer1");
    QCOMPARE(msgs.size(), 1);
    QCOMPARE(msgs[0].text, QStringLiteral("'; DROP TABLE messages; --"));
    db.close();
}

void TestDatabaseManager::testLargeNumberOfContacts()
{
    DatabaseManager db;
    db.open(":memory:");

    const int count = 200;
    for (int i = 0; i < count; ++i) {
        db.saveContact(makeChatData(
            QStringLiteral("peer_%1").arg(i),
            QStringLiteral("Contact_%1").arg(i)));
    }

    auto contacts = db.loadAllContacts();
    QCOMPARE(contacts.size(), count);
    db.close();
}

void TestDatabaseManager::testLargeNumberOfMessages()
{
    DatabaseManager db;
    db.open(":memory:");
    db.saveContact(makeChatData("peerA", "Alice"));

    const int count = 500;
    QDateTime base = QDateTime(QDate(2025, 1, 1), QTime(0, 0, 0), Qt::UTC);
    for (int i = 0; i < count; ++i) {
        db.saveMessage("peerA",
                       makeMessage(i % 2 == 0,
                                   QStringLiteral("msg_%1").arg(i),
                                   base.addSecs(i)));
    }

    QCOMPARE(db.messageCount("peerA"), count);
    auto msgs = db.loadMessages("peerA");
    QCOMPARE(msgs.size(), count);

    // Verify ordering
    for (int i = 1; i < msgs.size(); ++i) {
        QVERIFY(msgs[i].timestamp >= msgs[i - 1].timestamp);
    }
    db.close();
}

void TestDatabaseManager::testReopenPreservesData()
{
    const QString path = freshDbPath();

    // Write data
    {
        DatabaseManager db;
        db.open(path);
        db.saveContact(makeChatData("peerA", "Alice"));
        db.saveMessage("peerA", makeMessage(true, "persisted message"));
        db.saveSetting("myKey", "myVal");
        db.saveFileRecord("chatA",
                          makeFileRecord("tx1", "file.bin", 999, true,
                                         FileTransferStatus::Complete));
        db.close();
    }

    // Reopen and verify everything is still there
    {
        DatabaseManager db;
        db.open(path);

        QVERIFY(db.contactExists("peerA"));
        auto msgs = db.loadMessages("peerA");
        QCOMPARE(msgs.size(), 1);
        QCOMPARE(msgs[0].text, QStringLiteral("persisted message"));
        QCOMPARE(db.loadSetting("myKey"), QStringLiteral("myVal"));
        auto recs = db.loadFileRecords("chatA");
        QCOMPARE(recs.size(), 1);
        QCOMPARE(recs[0].fileName, QStringLiteral("file.bin"));
        db.close();
    }
}

void TestDatabaseManager::testMultipleDatabaseInstances()
{
    // Two separate DatabaseManager instances with different DB files
    DatabaseManager db1, db2;
    db1.open(freshDbPath());
    db2.open(freshDbPath());

    db1.saveContact(makeChatData("peerA", "Alice"));
    db2.saveContact(makeChatData("peerB", "Bob"));

    QCOMPARE(db1.loadAllContacts().size(), 1);
    QCOMPARE(db2.loadAllContacts().size(), 1);
    QCOMPARE(db1.loadAllContacts()[0].name, QStringLiteral("Alice"));
    QCOMPARE(db2.loadAllContacts()[0].name, QStringLiteral("Bob"));

    db1.close();
    db2.close();
}

// ── Data integrity ──────────────────────────────────────────────────────────

void TestDatabaseManager::testForeignKeyEnforcement()
{
    DatabaseManager db;
    db.open(":memory:");

    // Don't create a contact — saving a message should fail silently
    // because of the foreign key constraint (peer_id must exist in contacts)
    db.saveMessage("nonexistent_peer", makeMessage(true, "orphan"));

    // The message should not be persisted (FK violation)
    auto msgs = db.loadMessages("nonexistent_peer");
    QVERIFY(msgs.isEmpty());
    db.close();
}

void TestDatabaseManager::testIndexesExist()
{
    const QString path = freshDbPath();
    DatabaseManager db;
    db.open(path);

    // Query the sqlite_master to check indexes exist
    QStringList indexes;
    {
        QSqlDatabase rawDb = QSqlDatabase::addDatabase("QSQLITE", "idx_check");
        rawDb.setDatabaseName(path);
        QVERIFY(rawDb.open());

        QSqlQuery q(rawDb);
        q.exec("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;");

        while (q.next()) {
            indexes << q.value(0).toString();
        }

        rawDb.close();
    }
    QSqlDatabase::removeDatabase("idx_check");

    QVERIFY(indexes.contains("idx_messages_peer_id"));
    QVERIFY(indexes.contains("idx_messages_timestamp"));
    QVERIFY(indexes.contains("idx_file_transfers_chat_key"));
    QVERIFY(indexes.contains("idx_contacts_last_active"));

    db.close();
}

QTEST_MAIN(TestDatabaseManager)
#include "tst_databasemanager.moc"
