/* ============================================================================
 *  tst_contacts.cpp — Contact management test suite for Peer2Pear
 *
 *  Build (from the tests/ directory):
 *      mkdir build && cd build
 *      cmake .. -G Ninja
 *      ninja
 *      ./tst_contacts
 *
 *  No vcpkg or libsodium installation is required — lightweight sodium stubs
 *  are linked instead.  Tests use an in-memory SQLite database (:memory:) so
 *  nothing is written to disk.
 * ========================================================================= */

#include <QtTest/QtTest>
#include <QVector>
#include <QString>
#include <QStringList>
#include <QDateTime>

#include "databasemanager.h"
#include "chattypes.h"

// ─── Helper: build a ChatData with sensible defaults ─────────────────────────
static ChatData makeContact(const QString &name,
                            const QStringList &keys = {},
                            bool isBlocked = false,
                            bool isGroup = false,
                            const QString &groupId = {})
{
    ChatData c;
    c.name      = name;
    c.subtitle  = isGroup ? QStringLiteral("Group") : QStringLiteral("Secure chat");
    c.keys      = keys;
    c.isBlocked = isBlocked;
    c.isGroup   = isGroup;
    c.groupId   = groupId;
    if (!keys.isEmpty())
        c.peerIdB64u = keys.first();
    if (isGroup && !groupId.isEmpty())
        c.peerIdB64u = groupId;
    return c;
}

// ─── Helper: mirrors the static contactKey() in databasemanager.cpp ──────────
static QString expectedContactKey(const ChatData &c)
{
    if (!c.peerIdB64u.isEmpty()) return c.peerIdB64u;
    return QStringLiteral("name:") + c.name;
}

// =============================================================================
class TestContacts : public QObject
{
    Q_OBJECT

private:
    // Each test gets a fresh in-memory DB via init()/cleanup().
    DatabaseManager *m_db = nullptr;

private slots:
    // ── Per-test setup / teardown ────────────────────────────────────────────
    void init()
    {
        m_db = new DatabaseManager;
        QVERIFY(m_db->open(":memory:"));
    }
    void cleanup()
    {
        delete m_db;
        m_db = nullptr;
    }

    // =====================================================================
    //  A.  Basic addition
    // =====================================================================

    void addContactWithSingleKey()
    {
        ChatData c = makeContact("Alice", {"KEY_ALICE"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("Alice"));
        QCOMPARE(all[0].peerIdB64u, QStringLiteral("KEY_ALICE"));
        QCOMPARE(all[0].keys.size(), 1);
        QCOMPARE(all[0].keys.first(), QStringLiteral("KEY_ALICE"));
    }

    void addContactWithMultipleKeys()
    {
        ChatData c = makeContact("Bob", {"KEY_B1", "KEY_B2", "KEY_B3"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].peerIdB64u, QStringLiteral("KEY_B1"));
        QCOMPARE(all[0].keys.size(), 3);
        QCOMPARE(all[0].keys, QStringList({"KEY_B1", "KEY_B2", "KEY_B3"}));
    }

    void addContactWithoutKey()
    {
        ChatData c = makeContact("Charlie");          // no keys
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("Charlie"));
        QVERIFY(all[0].peerIdB64u.isEmpty());         // stored as "name:Charlie"
        QVERIFY(all[0].keys.isEmpty());
    }

    void addMultipleDistinctContacts()
    {
        m_db->saveContact(makeContact("Alice", {"KEY_A"}));
        m_db->saveContact(makeContact("Bob",   {"KEY_B"}));
        m_db->saveContact(makeContact("Carol"));

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 3);
    }

    // =====================================================================
    //  B.  Basic deletion
    // =====================================================================

    void deleteContactByKey()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);
        QCOMPARE(m_db->loadAllContacts().size(), 1);

        m_db->deleteContact("KEY_A");
        QCOMPARE(m_db->loadAllContacts().size(), 0);
    }

    void deleteNameOnlyContact()
    {
        ChatData c = makeContact("NoKeyContact");
        m_db->saveContact(c);
        QCOMPARE(m_db->loadAllContacts().size(), 1);

        m_db->deleteContact("name:NoKeyContact");
        QCOMPARE(m_db->loadAllContacts().size(), 0);
    }

    void deleteNonExistentContact()
    {
        // Should not crash or corrupt DB
        m_db->saveContact(makeContact("Alice", {"KEY_A"}));
        m_db->deleteContact("DOES_NOT_EXIST");
        QCOMPARE(m_db->loadAllContacts().size(), 1);   // Alice still there
    }

    void deleteThenReAdd()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);
        m_db->deleteContact("KEY_A");
        QCOMPARE(m_db->loadAllContacts().size(), 0);

        // Re-add the same contact
        m_db->saveContact(c);
        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("Alice"));
    }

    // =====================================================================
    //  C.  Cascading message deletion
    // =====================================================================

    void deleteContactCascadesMessages()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);

        Message msg;
        msg.sent      = true;
        msg.text      = "Hello!";
        msg.timestamp = QDateTime::currentDateTimeUtc();
        msg.msgId     = "msg1";
        m_db->saveMessage("KEY_A", msg);
        QCOMPARE(m_db->loadMessages("KEY_A").size(), 1);

        m_db->deleteContact("KEY_A");
        QCOMPARE(m_db->loadMessages("KEY_A").size(), 0);
    }

    // =====================================================================
    //  D.  Bug reproduction — duplicate key collision
    //      Two contacts that share the same first key map to the same
    //      peer_id in SQLite (PRIMARY KEY).  The second save UPSERTS over
    //      the first, so on reload only the latest survives.
    // =====================================================================

    void bugDuplicateKeyOverwrite()
    {
        ChatData alice = makeContact("Alice", {"SAME_KEY"});
        ChatData bob   = makeContact("Bob",   {"SAME_KEY"});

        m_db->saveContact(alice);
        m_db->saveContact(bob);

        // DB has only one row — Bob overwrote Alice (UPSERT on peer_id)
        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("Bob"));
    }

    void bugDeleteSharedKeyRemovesBoth()
    {
        // Simulates the reported bug:
        //  1. Two contacts added in-memory with the same key
        //  2. Only one DB row exists (UPSERT)
        //  3. Deleting one removes the single DB row
        //  4. On refresh (loadAllContacts) BOTH are gone

        QVector<ChatData> inMemory;
        ChatData alice = makeContact("Alice", {"SAME_KEY"});
        ChatData bob   = makeContact("Bob",   {"SAME_KEY"});
        inMemory.append(alice);
        inMemory.append(bob);

        m_db->saveContact(alice);
        m_db->saveContact(bob);

        // User deletes "Alice" at index 0 in the UI
        const QString dbKey = inMemory[0].peerIdB64u.isEmpty()
                                  ? "name:" + inMemory[0].name
                                  : inMemory[0].peerIdB64u;
        m_db->deleteContact(dbKey);
        inMemory.remove(0);

        // In-memory list still has Bob
        QCOMPARE(inMemory.size(), 1);
        QCOMPARE(inMemory[0].name, QStringLiteral("Bob"));

        // But the DB row is gone because Alice and Bob shared the same key
        auto fromDb = m_db->loadAllContacts();
        QCOMPARE(fromDb.size(), 0);   // Bob is also gone — this is the bug
    }

    // =====================================================================
    //  E.  Bug reproduction — name-only collision
    //      Two contacts with the same name and no keys map to the same
    //      "name:<name>" key.
    // =====================================================================

    void bugNameOnlyCollision()
    {
        ChatData c1 = makeContact("SameName");
        ChatData c2 = makeContact("SameName");

        m_db->saveContact(c1);
        m_db->saveContact(c2);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);   // second overwrote first
    }

    // =====================================================================
    //  F.  Bug reproduction — add contact with key must not crash
    //      Verifies that saving a contact whose peerIdB64u is a non-empty
    //      key string works without error.
    // =====================================================================

    void addContactWithKeyNoCrash()
    {
        // Various key formats that should all be accepted
        const QStringList testKeys = {
            "abcdef1234567890",
            "dGhpcyBpcyBhIGJhc2U2NCBrZXk",          // base64-ish
            "dGhpcyBpcyBhIGJhc2U2NHVybCBrZXk",      // base64url-ish
            "AAAA",                                    // very short
            QString(512, 'X'),                         // long key
        };

        for (const QString &k : testKeys) {
            DatabaseManager db;
            QVERIFY(db.open(":memory:"));

            ChatData c = makeContact("TestUser", {k});
            db.saveContact(c);

            auto all = db.loadAllContacts();
            QCOMPARE(all.size(), 1);
            QCOMPARE(all[0].peerIdB64u, k);
            QCOMPARE(all[0].keys.first(), k);
        }
    }

    // =====================================================================
    //  G.  Edge cases
    // =====================================================================

    void emptyNameWithKey()
    {
        ChatData c = makeContact("", {"KEY_X"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].peerIdB64u, QStringLiteral("KEY_X"));
    }

    void emptyNameNoKey()
    {
        // contactKey("","") returns "name:" — an odd but valid DB key.
        // saveContact allows it because key is not empty.
        ChatData c = makeContact("");
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        // The loaded contact should have empty peerIdB64u (it starts with "name:")
        QVERIFY(all[0].peerIdB64u.isEmpty());
    }

    void whitespaceOnlyName()
    {
        // In the UI, names are trimmed; test that saving a whitespace name
        // doesn't cause issues at the DB level.
        ChatData c = makeContact("   ");
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
    }

    void specialCharactersInName()
    {
        ChatData c = makeContact("O'Reilly <Bob> & \"friends\" 100%", {"KEY_S"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("O'Reilly <Bob> & \"friends\" 100%"));
    }

    void unicodeName()
    {
        ChatData c = makeContact(QString::fromUtf8("田中太郎 🔐"), {"KEY_U"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QString::fromUtf8("田中太郎 🔐"));
    }

    void keyLooksLikeNamePrefix()
    {
        // A key that starts with "name:" should still be stored as a normal
        // key-based contact and not be confused with a name-only contact.
        ChatData c = makeContact("Alice", {"name:Eve"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        // loadAllContacts strips "name:" prefix from peerIdB64u — verify the
        // contact is treated as name-only (bug: key collides with name format)
        QVERIFY(all[0].peerIdB64u.isEmpty());
    }

    void pipeCharacterInKey()
    {
        // Keys are joined with '|' for storage — a key containing '|' would
        // be split into multiple keys on reload.  Verify this edge case.
        ChatData c = makeContact("PipeUser", {"KEY|WITH|PIPES"});
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        // Keys are stored pipe-separated, so this single key becomes 3 on reload
        // (this is a known limitation — documents the behavior)
        QCOMPARE(all[0].keys.size(), 3);
    }

    void emptyKeyInList()
    {
        // Passing an empty string in the keys list
        ChatData c;
        c.name = "EmptyKeyUser";
        c.subtitle = "Secure chat";
        c.keys = {""};
        c.peerIdB64u = "";    // first key is empty
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        // peerIdB64u was empty, so contactKey() used "name:EmptyKeyUser"
        QVERIFY(all[0].peerIdB64u.isEmpty());
    }

    // =====================================================================
    //  H.  Contact update (UPSERT behavior)
    // =====================================================================

    void updateContactName()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);

        c.name = "Alice Updated";
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].name, QStringLiteral("Alice Updated"));
    }

    void updateContactKeys()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);

        c.keys = {"KEY_A", "KEY_A2"};
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].keys.size(), 2);
    }

    // =====================================================================
    //  I.  Blocked contacts
    // =====================================================================

    void blockedContactRoundTrip()
    {
        ChatData c = makeContact("Blocked", {"KEY_BLK"}, /*isBlocked=*/true);
        m_db->saveContact(c);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QVERIFY(all[0].isBlocked);
    }

    void toggleBlockStatus()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);
        QVERIFY(!m_db->loadAllContacts()[0].isBlocked);

        c.isBlocked = true;
        m_db->saveContact(c);
        QVERIFY(m_db->loadAllContacts()[0].isBlocked);

        c.isBlocked = false;
        m_db->saveContact(c);
        QVERIFY(!m_db->loadAllContacts()[0].isBlocked);
    }

    // =====================================================================
    //  J.  Group contacts
    // =====================================================================

    void groupContactRoundTrip()
    {
        ChatData g = makeContact("Team Chat",
                                 {"MEMBER_KEY_1", "MEMBER_KEY_2"},
                                 /*isBlocked=*/false,
                                 /*isGroup=*/true,
                                 /*groupId=*/"grp-uuid-1234");
        m_db->saveContact(g);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QVERIFY(all[0].isGroup);
        QCOMPARE(all[0].groupId, QStringLiteral("grp-uuid-1234"));
        QCOMPARE(all[0].peerIdB64u, QStringLiteral("grp-uuid-1234"));
        QCOMPARE(all[0].keys.size(), 2);
    }

    void deleteGroupContact()
    {
        ChatData g = makeContact("Team", {}, false, true, "grp-1");
        m_db->saveContact(g);
        QCOMPARE(m_db->loadAllContacts().size(), 1);

        m_db->deleteContact("grp-1");
        QCOMPARE(m_db->loadAllContacts().size(), 0);
    }

    // =====================================================================
    //  K.  Avatar
    // =====================================================================

    void saveAndLoadAvatar()
    {
        ChatData c = makeContact("Alice", {"KEY_A"});
        m_db->saveContact(c);

        m_db->saveContactAvatar("KEY_A", "iVBORw0KGgoAAAANSUhEUg==");

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);
        QCOMPARE(all[0].avatarData, QStringLiteral("iVBORw0KGgoAAAANSUhEUg=="));
    }

    void avatarOnNonExistentContact()
    {
        // Should not crash
        m_db->saveContactAvatar("DOES_NOT_EXIST", "data");
        QCOMPARE(m_db->loadAllContacts().size(), 0);
    }

    // =====================================================================
    //  L.  Ordering
    // =====================================================================

    void contactsOrderedByLastActive()
    {
        ChatData a = makeContact("Alice", {"KEY_A"});
        ChatData b = makeContact("Bob",   {"KEY_B"});
        ChatData c = makeContact("Carol", {"KEY_C"});
        m_db->saveContact(a);
        m_db->saveContact(b);
        m_db->saveContact(c);

        // Send a message to Bob — this updates last_active
        Message msg;
        msg.sent = true;
        msg.text = "hi";
        msg.timestamp = QDateTime::currentDateTimeUtc();
        msg.msgId = "m1";
        m_db->saveMessage("KEY_B", msg);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 3);
        // Bob should be first (most recent last_active)
        QCOMPARE(all[0].name, QStringLiteral("Bob"));
    }

    // =====================================================================
    //  M.  Stress / bulk
    // =====================================================================

    void addAndDeleteManyContacts()
    {
        const int N = 100;
        for (int i = 0; i < N; ++i)
            m_db->saveContact(makeContact(
                QString("User%1").arg(i),
                {QString("KEY_%1").arg(i)}));

        QCOMPARE(m_db->loadAllContacts().size(), N);

        for (int i = 0; i < N; ++i)
            m_db->deleteContact(QString("KEY_%1").arg(i));

        QCOMPARE(m_db->loadAllContacts().size(), 0);
    }

    // =====================================================================
    //  N.  Simulating in-memory + DB divergence
    //      (the "delete both contacts on refresh" bug scenario)
    // =====================================================================

    void simulateInMemoryDbDivergence()
    {
        // This test simulates the ChatView in-memory vector behaviour.
        // Two contacts with different names but the same key are added.
        // The DB only ever has one row (UPSERT).  Deleting either one
        // removes the single DB row, and on "refresh" (loadAllContacts)
        // the other contact disappears.

        QVector<ChatData> memChats;
        ChatData c1 = makeContact("Contact1", {"SHARED_KEY"});
        ChatData c2 = makeContact("Contact2", {"SHARED_KEY"});

        // Simulate addContact for c1
        memChats.append(c1);
        m_db->saveContact(c1);

        // Simulate addContact for c2
        memChats.append(c2);
        m_db->saveContact(c2);

        // In-memory: 2 contacts.  DB: 1 row (Contact2 overwrote Contact1).
        QCOMPARE(memChats.size(), 2);
        QCOMPARE(m_db->loadAllContacts().size(), 1);

        // User deletes Contact2 (index 1 in memChats)
        const int deleteIndex = 1;
        const QString dbKey = memChats[deleteIndex].peerIdB64u.isEmpty()
                                  ? "name:" + memChats[deleteIndex].name
                                  : memChats[deleteIndex].peerIdB64u;
        m_db->deleteContact(dbKey);
        memChats.remove(deleteIndex);

        // In-memory: 1 contact (Contact1).  DB: 0 rows.
        QCOMPARE(memChats.size(), 1);
        QCOMPARE(memChats[0].name, QStringLiteral("Contact1"));
        QCOMPARE(m_db->loadAllContacts().size(), 0);   // Contact1 gone on refresh

        // This demonstrates the bug: the user sees Contact1 in the UI
        // but after a refresh it vanishes.
    }

    // =====================================================================
    //  O.  Same name, different keys — should be distinct contacts
    // =====================================================================

    void sameNameDifferentKeys()
    {
        ChatData c1 = makeContact("Alice", {"KEY_1"});
        ChatData c2 = makeContact("Alice", {"KEY_2"});

        m_db->saveContact(c1);
        m_db->saveContact(c2);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 2);   // different peer_id, both survive
    }

    void differentNameSameKey()
    {
        ChatData c1 = makeContact("Alice", {"KEY_SAME"});
        ChatData c2 = makeContact("Bob",   {"KEY_SAME"});

        m_db->saveContact(c1);
        m_db->saveContact(c2);

        auto all = m_db->loadAllContacts();
        QCOMPARE(all.size(), 1);   // second overwrites first (same peer_id)
        QCOMPARE(all[0].name, QStringLiteral("Bob"));
    }

    // =====================================================================
    //  P.  Settings round-trip (used by contact-related flows)
    // =====================================================================

    void settingsRoundTrip()
    {
        m_db->saveSetting("displayName", "MyUser");
        QCOMPARE(m_db->loadSetting("displayName"), QStringLiteral("MyUser"));
    }

    void settingsDefault()
    {
        QCOMPARE(m_db->loadSetting("nonexistent", "fallback"),
                 QStringLiteral("fallback"));
    }
};

QTEST_MAIN(TestContacts)
#include "tst_contacts.moc"
