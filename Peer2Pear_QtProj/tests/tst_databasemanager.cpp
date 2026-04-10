// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — DatabaseManager Unit Tests
// ════════════════════════════════════════════════════════════════════════════
//
// DatabaseManager hardcodes the connection name "peer2pear_conn" and the
// DB path to AppDataLocation/peer2PearUser.db. Creating multiple instances
// causes "duplicate connection name" warnings and data leaking between tests.
//
// Fix: ONE shared DatabaseManager, wipe all rows between tests.
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <QSqlQuery>
#include <sodium.h>

#include "../databasemanager.h"
#include "../chattypes.h"
#include "../filetransfer.h"

class TestDatabaseManager : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void cleanup();   // runs after EVERY test function

    void openAndCloseSucceeds();

    void saveAndLoadContact();
    void saveContactOverwrites();
    void deleteContactRemovesFromList();
    void loadEmptyContactsReturnsEmptyList();
    void saveContactAvatar();

    void saveAndLoadMessages();
    void multipleMessagesPreserveOrder();
    void loadMessagesForNonExistentPeerReturnsEmpty();

    void saveAndLoadSetting();
    void loadMissingSettingReturnsDefault();
    void overwriteSetting();

    void saveAndLoadFileRecord();
    void deleteFileRecordRemovesEntry();
    void loadFileRecordsForWrongKeyReturnsEmpty();

    void encryptedContactRoundTrip();

private:
    DatabaseManager m_mgr;
};

void TestDatabaseManager::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize");
    QVERIFY2(m_mgr.open(), "DatabaseManager must open successfully");
}

void TestDatabaseManager::cleanupTestCase()
{
    m_mgr.close();
}

// Wipe all rows after every test so each test starts with a clean DB
void TestDatabaseManager::cleanup()
{
    QSqlDatabase db = m_mgr.database();
    QSqlQuery q(db);
    q.exec("DELETE FROM messages;");
    q.exec("DELETE FROM file_transfers;");
    q.exec("DELETE FROM contacts;");
    q.exec("DELETE FROM settings;");
}

void TestDatabaseManager::openAndCloseSucceeds()
{
    // Already opened in initTestCase — just verify database() works
    QVERIFY(m_mgr.database().isOpen());
}

// ═══════════════════════════════════════════════════════════════════════════
// Contacts
// ═══════════════════════════════════════════════════════════════════════════

void TestDatabaseManager::saveAndLoadContact()
{
    ChatData cd;
    cd.name = "Alice";
    cd.peerIdB64u = "alice-key-123";
    cd.keys = {"alice-key-123"};
    cd.isGroup = false;
    m_mgr.saveContact(cd);

    auto contacts = m_mgr.loadAllContacts();
    bool found = false;
    for (const auto &c : contacts) {
        if (c.peerIdB64u == "alice-key-123") {
            QCOMPARE(c.name, QString("Alice"));
            found = true;
        }
    }
    QVERIFY2(found, "Saved contact must be loadable");
}

void TestDatabaseManager::saveContactOverwrites()
{
    ChatData cd;
    cd.name = "Bob";
    cd.peerIdB64u = "bob-key-456";
    cd.keys = {"bob-key-456"};
    m_mgr.saveContact(cd);

    cd.name = "Bobby";
    m_mgr.saveContact(cd);

    auto contacts = m_mgr.loadAllContacts();
    for (const auto &c : contacts) {
        if (c.peerIdB64u == "bob-key-456") {
            QCOMPARE(c.name, QString("Bobby"));
        }
    }
}

void TestDatabaseManager::deleteContactRemovesFromList()
{
    ChatData cd;
    cd.name = "DeleteMe";
    cd.peerIdB64u = "delete-key-789";
    cd.keys = {"delete-key-789"};
    m_mgr.saveContact(cd);
    m_mgr.deleteContact("delete-key-789");

    auto contacts = m_mgr.loadAllContacts();
    for (const auto &c : contacts) {
        QVERIFY2(c.peerIdB64u != "delete-key-789", "Deleted contact must not appear");
    }
}

void TestDatabaseManager::loadEmptyContactsReturnsEmptyList()
{
    // cleanup() already wiped the DB — should be empty
    auto contacts = m_mgr.loadAllContacts();
    QCOMPARE(contacts.size(), 0);
}

void TestDatabaseManager::saveContactAvatar()
{
    ChatData cd;
    cd.name = "AvatarUser";
    cd.peerIdB64u = "avatar-key";
    cd.keys = {"avatar-key"};
    m_mgr.saveContact(cd);
    m_mgr.saveContactAvatar("avatar-key", "iVBORw0KGgo=");

    auto contacts = m_mgr.loadAllContacts();
    for (const auto &c : contacts) {
        if (c.peerIdB64u == "avatar-key") {
            QCOMPARE(c.avatarData, QString("iVBORw0KGgo="));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Messages
// ═══════════════════════════════════════════════════════════════════════════

void TestDatabaseManager::saveAndLoadMessages()
{
    ChatData cd;
    cd.name = "MsgUser";
    cd.peerIdB64u = "msg-key";
    cd.keys = {"msg-key"};
    m_mgr.saveContact(cd);

    Message msg;
    msg.sent = true;
    msg.text = "Hello from test!";
    msg.timestamp = QDateTime::currentDateTimeUtc();
    msg.msgId = "test-msg-001";
    msg.senderName = "Me";
    m_mgr.saveMessage("msg-key", msg);

    auto messages = m_mgr.loadMessages("msg-key");
    QVERIFY2(!messages.isEmpty(), "At least one message should be loaded");

    bool found = false;
    for (const auto &m : messages) {
        if (m.msgId == "test-msg-001") {
            QCOMPARE(m.text, QString("Hello from test!"));
            QVERIFY(m.sent);
            found = true;
        }
    }
    QVERIFY2(found, "Saved message must be loadable by msgId");
}

void TestDatabaseManager::multipleMessagesPreserveOrder()
{
    ChatData cd;
    cd.peerIdB64u = "order-key";
    cd.name = "OrderTest";
    cd.keys = {"order-key"};
    m_mgr.saveContact(cd);

    for (int i = 0; i < 5; ++i) {
        Message m;
        m.sent = (i % 2 == 0);
        m.text = QString("msg-%1").arg(i);
        m.timestamp = QDateTime::currentDateTimeUtc().addSecs(i);
        m.msgId = QString("order-%1").arg(i);
        m_mgr.saveMessage("order-key", m);
    }

    auto messages = m_mgr.loadMessages("order-key");
    QCOMPARE(messages.size(), 5);
}

void TestDatabaseManager::loadMessagesForNonExistentPeerReturnsEmpty()
{
    auto messages = m_mgr.loadMessages("nonexistent-key");
    QVERIFY(messages.isEmpty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Settings
// ═══════════════════════════════════════════════════════════════════════════

void TestDatabaseManager::saveAndLoadSetting()
{
    m_mgr.saveSetting("theme", "dark");
    QString val = m_mgr.loadSetting("theme");
    QCOMPARE(val, QString("dark"));
}

void TestDatabaseManager::loadMissingSettingReturnsDefault()
{
    QString val = m_mgr.loadSetting("nonexistent", "fallback");
    QCOMPARE(val, QString("fallback"));
}

void TestDatabaseManager::overwriteSetting()
{
    m_mgr.saveSetting("lang", "en");
    m_mgr.saveSetting("lang", "fr");
    QString val = m_mgr.loadSetting("lang");
    QCOMPARE(val, QString("fr"));
}

// ═══════════════════════════════════════════════════════════════════════════
// File Records
// ═══════════════════════════════════════════════════════════════════════════

void TestDatabaseManager::saveAndLoadFileRecord()
{
    FileTransferRecord rec;
    rec.transferId = "xfer-001";
    rec.fileName = "photo.png";
    rec.fileSize = 1024 * 100;
    rec.peerIdB64u = "file-peer";
    rec.peerName = "Alice";
    rec.timestamp = QDateTime::currentDateTimeUtc();
    rec.sent = true;
    rec.status = FileTransferStatus::Complete;
    rec.chunksTotal = 1;
    rec.chunksComplete = 1;
    rec.savedPath = "/downloads/photo.png";

    m_mgr.saveFileRecord("file-peer", rec);

    auto records = m_mgr.loadFileRecords("file-peer");
    QVERIFY2(!records.isEmpty(), "File record should be loaded");

    bool found = false;
    for (const auto &r : records) {
        if (r.transferId == "xfer-001") {
            QCOMPARE(r.fileName, QString("photo.png"));
            QCOMPARE(r.fileSize, qint64(1024 * 100));
            found = true;
        }
    }
    QVERIFY2(found, "Saved file record must be retrievable");
}

void TestDatabaseManager::deleteFileRecordRemovesEntry()
{
    FileTransferRecord rec;
    rec.transferId = "xfer-del";
    rec.fileName = "delete-me.txt";
    rec.fileSize = 100;
    rec.timestamp = QDateTime::currentDateTimeUtc();
    rec.sent = false;
    rec.status = FileTransferStatus::Complete;
    rec.chunksTotal = 1;
    rec.chunksComplete = 1;
    m_mgr.saveFileRecord("del-peer", rec);

    m_mgr.deleteFileRecord("xfer-del");

    auto records = m_mgr.loadFileRecords("del-peer");
    for (const auto &r : records) {
        QVERIFY2(r.transferId != "xfer-del", "Deleted file record must not appear");
    }
}

void TestDatabaseManager::loadFileRecordsForWrongKeyReturnsEmpty()
{
    auto records = m_mgr.loadFileRecords("no-such-key");
    QVERIFY(records.isEmpty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Encrypted Fields
// ══════════════════════���════════════════════════════════════════════════════

void TestDatabaseManager::encryptedContactRoundTrip()
{
    QByteArray encKey(32, '\xAA');
    m_mgr.setEncryptionKey(encKey);

    ChatData cd;
    cd.name = "Encrypted Alice";
    cd.peerIdB64u = "enc-alice-key";
    cd.keys = {"enc-alice-key"};
    m_mgr.saveContact(cd);

    auto contacts = m_mgr.loadAllContacts();
    bool found = false;
    for (const auto &c : contacts) {
        if (c.peerIdB64u == "enc-alice-key") {
            QCOMPARE(c.name, QString("Encrypted Alice"));
            found = true;
        }
    }
    QVERIFY2(found, "Encrypted contact must be loadable with correct key");
}

QTEST_MAIN(TestDatabaseManager)
#include "tst_databasemanager.moc"
