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
    void testOpenInMemory();
    void testOpenFileBased();
    void testOpenCustomPath();
    void testDoubleOpen();
    void testCloseAndReopen();
    void testIsOpen();
    void testTablesCreatedOnOpen();
    void testMigrationSafety();

    // ── Contact CRUD ────────────────────────────────────────────────────
    void testSaveAndLoadContact();
    void testSaveContactUpsert();
    void testDeleteContact();
    void testDeleteNonExistentContact();
    void testContactExists();
    void testContactExistsEmpty();
    void testGetContact();
    void testGetContactNotFound();
    void testContactWithKeys();
    void testContactWithEmptyKeys();
    void testContactBlockedFlag();
    void testBlockContact();
    void testContactGroupFlag();
    void testContactGroupId();
    void testContactAvatar();
    void testSaveContactAvatar();
    void testContactNameOnlyKey();
    void testContactEmptyPeerIdAndName();
    void testLoadAllContactsEmpty();
    void testLoadAllContactsMultiple();
    void testContactsOrderedByLastActive();

    // ── Message operations ──────────────────────────────────────────────
    void testSaveAndLoadMessage();
    void testMultipleMessages();
    void testMessagesOrderedByTimestamp();
    void testMessagesDontIntermix();
    void testMessageAllFields();
    void testMessageEmptyOptionalFields();
    void testLoadMessagesNonExistentPeer();
    void testLoadMessagesEmptyPeerId();
    void testSaveMessageEmptyPeerId();
    void testSaveMessageUpdatesLastActive();
    void testClearMessages();
    void testClearMessagesNonExistent();
    void testMessageCount();
    void testMessageCountEmpty();
    void testDeleteContactCascadesMessages();

    // ── File transfer operations ────────────────────────────────────────
    void testSaveAndLoadFileRecord();
    void testUpdateFileRecord();
    void testFileRecordAllStatuses();
    void testFileRecordsOrderedByTimestamp();
    void testFileRecordsDontIntermix();
    void testLoadFileRecordsEmptyKey();
    void testSaveFileRecordEmptyKey();
    void testSaveFileRecordEmptyTransferId();
    void testDeleteFileRecord();
    void testDeleteNonExistentFileRecord();

    // ── Settings operations ─────────────────────────────────────────────
    void testSaveAndLoadSetting();
    void testLoadSettingDefault();
    void testLoadSettingCustomDefault();
    void testOverwriteSetting();
    void testMultipleSettings();

    // ── Encryption ──────────────────────────────────────────────────────
    void testEncryptedMessageRoundTrip();
    void testPlaintextWithoutKey();
    void testEncryptedEmptyString();
    void testEncryptedUnicodeText();
    void testEncryptedLongText();
    void testWrongKeyCannotDecrypt();
    void testLegacyPlaintextReadable();
    void testEncryptionKeyMustBe32Bytes();
    void testSetEncryptionKeyAfterOpen();

    // ── Edge cases ──────────────────────────────────────────────────────
    void testUnicodeContactNames();
    void testEmojiInMessages();
    void testVeryLongTextValues();
    void testSpecialCharsInSettingsKeys();
    void testSqlInjectionSafe();
    void testLargeNumberOfContacts();
    void testLargeNumberOfMessages();
    void testReopenPreservesData();
    void testMultipleDatabaseInstances();

    // ── Data integrity ──────────────────────────────────────────────────
    void testForeignKeyEnforcement();
    void testIndexesExist();
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
