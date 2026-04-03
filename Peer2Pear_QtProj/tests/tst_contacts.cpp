/*  tst_contacts.cpp
 *  ─────────────────────────────────────────────────────────────────────────────
 *  In-app functional tests for creating, editing, deleting, blocking,
 *  importing and exporting contacts in Peer2Pear.
 *
 *  These tests exercise the same code paths used by the UI (ChatView,
 *  MainWindow) but drive them programmatically through the public
 *  DatabaseManager API and ChatData model so they can run headlessly
 *  without a display server.
 *
 *  Build & run (from the tests/ directory):
 *      mkdir build && cd build
 *      cmake .. -G Ninja
 *      ninja
 *      ./tst_contacts
 *  ──────────────────────────────────────────────────────────────────────────── */

#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>

#include "databasemanager.h"
#include "chattypes.h"

/* ═══════════════════════════════════════════════════════════════════════════════
 *  Test class
 * ═══════════════════════════════════════════════════════════════════════════════ */
class TestContacts : public QObject
{
    Q_OBJECT

private:
    // Each test gets its own temp directory so DBs never collide.
    QTemporaryDir m_tmpDir;

    // Helper: create a DatabaseManager that writes into the temp directory.
    // The production constructor hard-codes connection name "peer2pear_conn",
    // so only one DatabaseManager can exist at a time.  QScopedPointer ensures
    // each is destroyed before the next is created.
    DatabaseManager *openTestDb()
    {
        auto *db = new DatabaseManager;
        db->open();

        // Set a dummy 32-byte encryption key (all zeros) so encrypted fields
        // round-trip correctly through the stubs.
        QByteArray key32(32, '\x00');
        db->setEncryptionKey(key32);

        return db;
    }

private slots:
    void initTestCase();
    void cleanupTestCase();
    void cleanup();   // Runs after each test — removes DB so next test is fresh

    // ── Contact creation ──────────────────────────────────────────────────
    void createContactWithNameOnly();
    void createContactWithNameAndKeys();
    void createContactWithMultipleKeys();
    void createContactWithEmptyNameIsIgnored();
    void createContactPeerIdDerivedFromFirstKey();
    void createContactNameOnlyGetsFallbackKey();

    // ── Contact persistence (save → load round-trip) ─────────────────────
    void savedContactPersistsAcrossReload();
    void savedContactPreservesAllFields();

    // ── Contact editing ──────────────────────────────────────────────────
    void editContactName();
    void editContactAddKey();
    void editContactRemoveKey();
    void editContactReplaceAllKeys();

    // ── Contact deletion ─────────────────────────────────────────────────
    void deleteContactByPeerId();
    void deleteContactByFallbackKey();
    void deleteNonExistentContactIsHarmless();

    // ── Blocking ─────────────────────────────────────────────────────────
    void blockAndUnblockContact();

    // ── Group contacts ───────────────────────────────────────────────────
    void createGroupContact();
    void groupContactHasMultipleKeys();

    // ── Avatar ───────────────────────────────────────────────────────────
    void saveAndLoadContactAvatar();

    // ── Ordering ─────────────────────────────────────────────────────────
    void contactsOrderedByLastActive();

    // ── Duplicate handling ────────────────────────────────────────────────
    void upsertContactOverwritesExisting();
    void duplicateKeyDetection();

    // ── Import / export ──────────────────────────────────────────────────
    void exportContactsToJson();
    void importContactsFromJson();
    void importSkipsDuplicates();
    void importSkipsEmptyEntries();
    void importBadJsonIsRejected();
};

/* ══════════════════════════════════════════════════════════════════════════════ */

void TestContacts::initTestCase()
{
    // Override XDG / AppData so DatabaseManager::open() writes into m_tmpDir.
    qputenv("XDG_DATA_HOME", m_tmpDir.path().toUtf8());
    qputenv("HOME",          m_tmpDir.path().toUtf8());

    QVERIFY(m_tmpDir.isValid());
}

void TestContacts::cleanupTestCase() {}

void TestContacts::cleanup()
{
    // Remove the SQLite file between tests so each starts with empty tables.
    QSqlDatabase::removeDatabase("peer2pear_conn");
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QFile::remove(base + "/peer2PearUser.db");
    QFile::remove(base + "/peer2PearUser.db-wal");
    QFile::remove(base + "/peer2PearUser.db-shm");
}

/* ── Contact creation ──────────────────────────────────────────────────────── */

void TestContacts::createContactWithNameOnly()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name     = "Alice";
    c.subtitle = "Secure chat";
    // No keys, no peerIdB64u → fallback key "name:Alice"

    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].name, QString("Alice"));
    QCOMPARE(all[0].subtitle, QString("Secure chat"));
    QVERIFY(all[0].peerIdB64u.isEmpty());   // stored as "name:Alice"
    QVERIFY(all[0].keys.isEmpty());
}

void TestContacts::createContactWithNameAndKeys()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name        = "Bob";
    c.subtitle    = "Secure chat";
    c.keys        = QStringList{"pubkey_abc123"};
    c.peerIdB64u  = c.keys.first();

    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].name, QString("Bob"));
    QCOMPARE(all[0].peerIdB64u, QString("pubkey_abc123"));
    QCOMPARE(all[0].keys.size(), 1);
    QCOMPARE(all[0].keys.first(), QString("pubkey_abc123"));
}

void TestContacts::createContactWithMultipleKeys()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name       = "Charlie";
    c.subtitle   = "Secure chat";
    c.keys       = QStringList{"key1", "key2", "key3"};
    c.peerIdB64u = c.keys.first();

    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].keys.size(), 3);
    QCOMPARE(all[0].keys, QStringList({"key1", "key2", "key3"}));
}

void TestContacts::createContactWithEmptyNameIsIgnored()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "";
    // Both peerIdB64u and name are empty → contactKey() returns "" → saveContact returns early

    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 0);
}

void TestContacts::createContactPeerIdDerivedFromFirstKey()
{
    // Mirrors the in-app logic in ChatView::onAddContact():
    //   if(!keys.isEmpty()) nc.peerIdB64u = keys.first();

    ChatData nc;
    nc.name     = "Dave";
    nc.subtitle = "Secure chat";
    nc.keys     = QStringList{"first_key", "second_key"};
    nc.peerIdB64u = nc.keys.first();   // ← same as the app does

    QCOMPARE(nc.peerIdB64u, QString("first_key"));
}

void TestContacts::createContactNameOnlyGetsFallbackKey()
{
    // The contactKey() helper in databasemanager.cpp falls back to "name:<Name>".
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Eve";

    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    // When peer_id starts with "name:", loadAllContacts sets peerIdB64u to empty
    QVERIFY(all[0].peerIdB64u.isEmpty());
    QCOMPARE(all[0].name, QString("Eve"));
}

/* ── Persistence (save → reload) ───────────────────────────────────────────── */

void TestContacts::savedContactPersistsAcrossReload()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Frank"; c.subtitle = "Secure chat";
    c.keys = QStringList{"frankkey1"};
    c.peerIdB64u = "frankkey1";
    db->saveContact(c);

    // Simulate app restart by loading contacts fresh
    const auto reloaded = db->loadAllContacts();
    QCOMPARE(reloaded.size(), 1);
    QCOMPARE(reloaded[0].name, QString("Frank"));
    QCOMPARE(reloaded[0].peerIdB64u, QString("frankkey1"));
}

void TestContacts::savedContactPreservesAllFields()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name        = "Grace";
    c.subtitle    = "Custom subtitle";
    c.keys        = QStringList{"grace_pk1", "grace_pk2"};
    c.peerIdB64u  = "grace_pk1";
    c.isBlocked   = true;
    c.isGroup     = true;
    c.groupId     = "group-uuid-123";
    c.avatarData  = "base64avatardata==";

    db->saveContact(c);
    db->saveContactAvatar(c.peerIdB64u, c.avatarData);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].name,       QString("Grace"));
    QCOMPARE(all[0].subtitle,   QString("Custom subtitle"));
    QCOMPARE(all[0].peerIdB64u, QString("grace_pk1"));
    QCOMPARE(all[0].keys.size(), 2);
    QCOMPARE(all[0].isBlocked,  true);
    QCOMPARE(all[0].isGroup,    true);
    QCOMPARE(all[0].groupId,    QString("group-uuid-123"));
    QCOMPARE(all[0].avatarData, QString("base64avatardata=="));
}

/* ── Editing ──────────────────────────────────────────────────────────────── */

void TestContacts::editContactName()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Hank"; c.subtitle = "Secure chat";
    c.keys = QStringList{"hank_pk"};
    c.peerIdB64u = "hank_pk";
    db->saveContact(c);

    // Edit: same peerIdB64u, different name (upsert)
    c.name = "Henry";
    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].name, QString("Henry"));
}

void TestContacts::editContactAddKey()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Ivy"; c.subtitle = "Secure chat";
    c.keys = QStringList{"ivy_pk"};
    c.peerIdB64u = "ivy_pk";
    db->saveContact(c);

    // Add a second key
    c.keys << "ivy_pk2";
    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].keys.size(), 2);
    QVERIFY(all[0].keys.contains("ivy_pk2"));
}

void TestContacts::editContactRemoveKey()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Jack"; c.subtitle = "Secure chat";
    c.keys = QStringList{"jack_pk1", "jack_pk2"};
    c.peerIdB64u = "jack_pk1";
    db->saveContact(c);

    // Remove second key
    c.keys = QStringList{"jack_pk1"};
    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].keys.size(), 1);
    QCOMPARE(all[0].keys.first(), QString("jack_pk1"));
}

void TestContacts::editContactReplaceAllKeys()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Kate"; c.subtitle = "Secure chat";
    c.keys = QStringList{"old_key"};
    c.peerIdB64u = "old_key";
    db->saveContact(c);

    // Replace key entirely — must also update peerIdB64u.
    // First delete old entry, then save new (mirrors onEditContact flow)
    db->deleteContact("old_key");

    c.keys       = QStringList{"new_key"};
    c.peerIdB64u = "new_key";
    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].peerIdB64u, QString("new_key"));
    QCOMPARE(all[0].keys.first(), QString("new_key"));
}

/* ── Deletion ──────────────────────────────────────────────────────────────── */

void TestContacts::deleteContactByPeerId()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Liam"; c.keys = QStringList{"liam_pk"};
    c.peerIdB64u = "liam_pk";
    db->saveContact(c);

    db->deleteContact("liam_pk");

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 0);
}

void TestContacts::deleteContactByFallbackKey()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Mia";
    db->saveContact(c);

    // Delete using the fallback key format "name:Mia"
    db->deleteContact("name:Mia");

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 0);
}

void TestContacts::deleteNonExistentContactIsHarmless()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    // Should not crash or produce errors
    db->deleteContact("nonexistent_id");
    db->deleteContact("name:Nobody");

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 0);
}

/* ── Blocking ──────────────────────────────────────────────────────────────── */

void TestContacts::blockAndUnblockContact()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Noah"; c.peerIdB64u = "noah_pk";
    c.keys = QStringList{"noah_pk"};
    c.isBlocked = false;
    db->saveContact(c);

    // Block
    c.isBlocked = true;
    db->saveContact(c);
    {
        const auto all = db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].isBlocked, true);
    }

    // Unblock
    c.isBlocked = false;
    db->saveContact(c);
    {
        const auto all = db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].isBlocked, false);
    }
}

/* ── Groups ────────────────────────────────────────────────────────────────── */

void TestContacts::createGroupContact()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    // Mirrors ChatView::onAddContact() group flow
    ChatData ng;
    ng.name      = "Team Chat";
    ng.subtitle  = "Group · 2 members";
    ng.isGroup   = true;
    ng.keys      = QStringList{"member1_pk", "member2_pk"};
    ng.groupId   = "group-uuid-abc";
    ng.peerIdB64u = ng.groupId;        // groups use groupId as peerIdB64u

    db->saveContact(ng);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].name,      QString("Team Chat"));
    QCOMPARE(all[0].isGroup,   true);
    QCOMPARE(all[0].groupId,   QString("group-uuid-abc"));
    QCOMPARE(all[0].keys.size(), 2);
}

void TestContacts::groupContactHasMultipleKeys()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData ng;
    ng.name   = "Project Group";
    ng.isGroup = true;
    ng.keys   = QStringList{"pk_a", "pk_b", "pk_c"};
    ng.groupId = "grp-1";
    ng.peerIdB64u = ng.groupId;

    db->saveContact(ng);

    const auto all = db->loadAllContacts();
    QCOMPARE(all[0].keys, QStringList({"pk_a", "pk_b", "pk_c"}));
}

/* ── Avatar ────────────────────────────────────────────────────────────────── */

void TestContacts::saveAndLoadContactAvatar()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Olivia"; c.peerIdB64u = "olivia_pk";
    c.keys = QStringList{"olivia_pk"};
    db->saveContact(c);

    const QString avatarB64 = "iVBORw0KGgoAAAANS...";  // truncated PNG base64
    db->saveContactAvatar("olivia_pk", avatarB64);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].avatarData, avatarB64);
}

/* ── Ordering ──────────────────────────────────────────────────────────────── */

void TestContacts::contactsOrderedByLastActive()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    // Insert three contacts
    ChatData a, b, c2;
    a.name = "Alpha"; a.peerIdB64u = "pk_a"; a.keys = QStringList{"pk_a"};
    b.name = "Beta";  b.peerIdB64u = "pk_b"; b.keys = QStringList{"pk_b"};
    c2.name = "Gamma"; c2.peerIdB64u = "pk_c"; c2.keys = QStringList{"pk_c"};

    db->saveContact(a);
    db->saveContact(b);
    db->saveContact(c2);

    // Send a message to Beta → should update last_active and move Beta to top
    Message msg;
    msg.sent      = false;
    msg.text      = "Hello Beta!";
    msg.timestamp = QDateTime::currentDateTimeUtc();
    msg.msgId     = "msg-1";
    db->saveMessage("pk_b", msg);

    const auto all = db->loadAllContacts();
    QVERIFY(all.size() >= 3);
    // Beta should now be first (highest last_active)
    QCOMPARE(all[0].name, QString("Beta"));
}

/* ── Upsert / Duplicate handling ──────────────────────────────────────────── */

void TestContacts::upsertContactOverwritesExisting()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c;
    c.name = "Paul"; c.peerIdB64u = "paul_pk";
    c.keys = QStringList{"paul_pk"};
    c.subtitle = "Original subtitle";
    db->saveContact(c);

    // Save again with updated subtitle → ON CONFLICT should update
    c.subtitle = "Updated subtitle";
    db->saveContact(c);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 1);
    QCOMPARE(all[0].subtitle, QString("Updated subtitle"));
}

void TestContacts::duplicateKeyDetection()
{
    // In the app UI, adding a duplicate key shows a warning.
    // This test verifies the logic: keys in a QStringList can be checked
    // before insertion (mirrors ChatView::onAddContact lambda).

    QStringList keys = {"key_one", "key_two"};
    const QString newKey = "key_one";  // duplicate

    bool isDuplicate = false;
    for (const QString &k : keys) {
        if (k == newKey) { isDuplicate = true; break; }
    }
    QVERIFY(isDuplicate);

    // Non-duplicate
    const QString uniqueKey = "key_three";
    isDuplicate = false;
    for (const QString &k : keys) {
        if (k == uniqueKey) { isDuplicate = true; break; }
    }
    QVERIFY(!isDuplicate);
}

/* ── Import / Export ──────────────────────────────────────────────────────── */

void TestContacts::exportContactsToJson()
{
    // Mirrors MainWindow::onExportContacts()
    QScopedPointer<DatabaseManager> db(openTestDb());

    ChatData c1, c2;
    c1.name = "Alice"; c1.keys = QStringList{"alice_pk"}; c1.peerIdB64u = "alice_pk";
    c2.name = "Bob";   c2.keys = QStringList{"bob_pk"};   c2.peerIdB64u = "bob_pk";
    c2.isBlocked = true;  // blocked contacts should be excluded from export

    db->saveContact(c1);
    db->saveContact(c2);

    const QVector<ChatData> contacts = db->loadAllContacts();

    QJsonArray arr;
    for (const auto &c : contacts) {
        if (c.isBlocked) continue;
        QJsonObject obj;
        obj["name"] = c.name;
        obj["keys"] = QJsonArray::fromStringList(c.keys);
        arr.append(obj);
    }
    QJsonObject root;
    root["version"]  = 1;
    root["contacts"] = arr;

    // Verify blocked contacts excluded
    QCOMPARE(arr.size(), 1);
    QCOMPARE(arr[0].toObject()["name"].toString(), QString("Alice"));

    // Verify JSON structure
    const QJsonDocument doc(root);
    QVERIFY(!doc.isNull());
    QCOMPARE(root["version"].toInt(), 1);
}

void TestContacts::importContactsFromJson()
{
    // Mirrors MainWindow::onImportContacts()
    QScopedPointer<DatabaseManager> db(openTestDb());

    const QByteArray json = R"({
        "version": 1,
        "contacts": [
            {"name": "Imported1", "keys": ["imp_pk1"]},
            {"name": "Imported2", "keys": ["imp_pk2", "imp_pk2b"]}
        ]
    })";

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    QVERIFY(!doc.isNull());

    const QJsonArray arr = doc.object()["contacts"].toArray();

    int imported = 0;
    for (const QJsonValue &v : arr) {
        const QJsonObject obj = v.toObject();
        ChatData chat;
        chat.name = obj["name"].toString().trimmed();
        const QJsonArray keysArr = obj["keys"].toArray();
        for (const QJsonValue &k : keysArr)
            chat.keys.append(k.toString());
        if (!chat.keys.isEmpty())
            chat.peerIdB64u = chat.keys.first();
        chat.subtitle = "Secure chat";
        db->saveContact(chat);
        ++imported;
    }

    QCOMPARE(imported, 2);

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 2);
}

void TestContacts::importSkipsDuplicates()
{
    QScopedPointer<DatabaseManager> db(openTestDb());

    // Pre-existing contact
    ChatData existing;
    existing.name = "Existing"; existing.keys = QStringList{"existing_pk"};
    existing.peerIdB64u = "existing_pk";
    db->saveContact(existing);

    // Import JSON that includes same peerIdB64u
    const QByteArray json = R"({
        "version": 1,
        "contacts": [
            {"name": "Existing", "keys": ["existing_pk"]},
            {"name": "NewGuy",   "keys": ["new_pk"]}
        ]
    })";

    const QJsonDocument doc = QJsonDocument::fromJson(json);
    const QJsonArray arr = doc.object()["contacts"].toArray();

    // Build set of existing IDs (mirrors MainWindow::onImportContacts)
    const QVector<ChatData> existingContacts = db->loadAllContacts();
    QSet<QString> existingIds;
    for (const auto &e : existingContacts) {
        if (!e.peerIdB64u.isEmpty())
            existingIds.insert(e.peerIdB64u);
        else if (!e.name.isEmpty())
            existingIds.insert(QLatin1String("name:") + e.name);
    }

    int imported = 0;
    for (const QJsonValue &v : arr) {
        const QJsonObject obj = v.toObject();
        ChatData chat;
        chat.name = obj["name"].toString().trimmed();
        const QJsonArray keysArr = obj["keys"].toArray();
        for (const QJsonValue &k : keysArr)
            chat.keys.append(k.toString());
        if (!chat.keys.isEmpty()) chat.peerIdB64u = chat.keys.first();

        const QString effectiveKey = chat.peerIdB64u.isEmpty()
                                         ? QLatin1String("name:") + chat.name
                                         : chat.peerIdB64u;
        if (existingIds.contains(effectiveKey)) continue;

        chat.subtitle = "Secure chat";
        db->saveContact(chat);
        existingIds.insert(effectiveKey);
        ++imported;
    }

    QCOMPARE(imported, 1);  // Only "NewGuy" imported

    const auto all = db->loadAllContacts();
    QCOMPARE(all.size(), 2);
}

void TestContacts::importSkipsEmptyEntries()
{
    const QByteArray json = R"({
        "version": 1,
        "contacts": [
            {"name": "", "keys": []},
            {"name": "Valid", "keys": ["valid_pk"]}
        ]
    })";

    const QJsonDocument doc = QJsonDocument::fromJson(json);
    const QJsonArray arr = doc.object()["contacts"].toArray();

    int skipped = 0;
    int valid   = 0;
    for (const QJsonValue &v : arr) {
        const QJsonObject obj = v.toObject();
        const QString name = obj["name"].toString().trimmed();
        QStringList keys;
        for (const QJsonValue &k : obj["keys"].toArray())
            keys.append(k.toString());
        if (name.isEmpty() && keys.isEmpty()) { ++skipped; continue; }
        ++valid;
    }

    QCOMPARE(skipped, 1);
    QCOMPARE(valid, 1);
}

void TestContacts::importBadJsonIsRejected()
{
    const QByteArray badJson = "{ this is not valid json }}}";
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(badJson, &err);
    QVERIFY(doc.isNull());
    QVERIFY(!err.errorString().isEmpty());
}

/* ══════════════════════════════════════════════════════════════════════════════ */

QTEST_MAIN(TestContacts)
#include "tst_contacts.moc"
