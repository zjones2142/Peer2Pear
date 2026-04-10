// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — SessionStore Unit Tests
// ════════════════════════════════════════════════════════════════════════════
//
// IMPORTANT: SessionStore's encryptBlob/decryptBlob are intentionally
// asymmetric when no storeKey is provided:
//   - encryptBlob() returns plaintext unchanged (no-op)
//   - decryptBlob() returns {} (fail-safe — won't return unverified data)
//
// All tests MUST provide a 32-byte storeKey for round-trip to work.
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <sodium.h>

#include "../SessionStore.hpp"

// Shared 32-byte key used for all tests (required for encrypt/decrypt symmetry)
static const QByteArray kTestStoreKey(32, '\xAA');

class TestSessionStore : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();

    // ── Session CRUD ─────────────────────────────────────────────────────────
    void saveAndLoadSession();
    void loadNonExistentSessionReturnsEmpty();
    void deleteSessionRemovesData();
    void overwriteSessionUpdatesData();

    // ── Encrypted Store ──────────────────────────────────────────────────────
    void encryptedSaveAndLoad();
    void encryptedStoreWithWrongKeyReturnsEmpty();

    // ── Skipped Keys (only deleteSkippedKeysForPeer remains) ─────────────────
    void deleteSkippedKeysForPeerDoesNotCrashOnEmptyTable();

    // ── Pending Handshakes ───────────────────────────────────────────────────
    void saveAndLoadPendingHandshake();
    void deletePendingHandshakeRemovesData();
    void pruneStaleHandshakesRemovesOld();
    void loadNonExistentHandshakeReturnsEmpty();

    // ── Clear All ────────────────────────────────────────────────────────────
    void clearAllRemovesEverything();

private:
    int m_dbCounter = 0;
    QSqlDatabase createTempDb(const QString& connName);
};

void TestSessionStore::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize");
}

QSqlDatabase TestSessionStore::createTempDb(const QString& connName)
{
    QString name = connName + QString::number(++m_dbCounter);
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", name);
    db.setDatabaseName(":memory:");
    db.open();
    return db;
}

// ═══════════════════════════════════════════════════════════════════════════
// Session CRUD
// ═══════════════════════════════════════════════════════════════════════════

void TestSessionStore::saveAndLoadSession()
{
    auto db = createTempDb("ss-save-load");
    SessionStore store(db, kTestStoreKey);

    QByteArray blob(100, '\xAB');
    store.saveSession("peer-a", blob);

    QByteArray loaded = store.loadSession("peer-a");
    QCOMPARE(loaded, blob);
}

void TestSessionStore::loadNonExistentSessionReturnsEmpty()
{
    auto db = createTempDb("ss-nonexist");
    SessionStore store(db, kTestStoreKey);

    QByteArray loaded = store.loadSession("nobody");
    QVERIFY(loaded.isEmpty());
}

void TestSessionStore::deleteSessionRemovesData()
{
    auto db = createTempDb("ss-delete");
    SessionStore store(db, kTestStoreKey);

    store.saveSession("peer-del", QByteArray(50, '\x01'));
    store.deleteSession("peer-del");

    QByteArray loaded = store.loadSession("peer-del");
    QVERIFY(loaded.isEmpty());
}

void TestSessionStore::overwriteSessionUpdatesData()
{
    auto db = createTempDb("ss-overwrite");
    SessionStore store(db, kTestStoreKey);

    store.saveSession("peer-ow", QByteArray(32, '\x01'));
    store.saveSession("peer-ow", QByteArray(32, '\x02'));

    QByteArray loaded = store.loadSession("peer-ow");
    QCOMPARE(loaded, QByteArray(32, '\x02'));
}

// ═══════════════════════════════════════════════════════════════════════════
// Encrypted Store
// ═══════════════════════════════════════════════════════════════════════════

void TestSessionStore::encryptedSaveAndLoad()
{
    auto db = createTempDb("ss-enc");
    QByteArray key(32, '\xBB');
    SessionStore store(db, key);

    QByteArray blob(64, '\xCC');
    store.saveSession("peer-enc", blob);

    QByteArray loaded = store.loadSession("peer-enc");
    QCOMPARE(loaded, blob);
}

void TestSessionStore::encryptedStoreWithWrongKeyReturnsEmpty()
{
    auto db = createTempDb("ss-enc-wrong");
    QByteArray key1(32, '\x01');
    QByteArray key2(32, '\x02');

    {
        SessionStore store(db, key1);
        store.saveSession("peer-wrong", QByteArray(32, '\xCC'));
    }

    SessionStore store2(db, key2);
    QByteArray loaded = store2.loadSession("peer-wrong");
    QVERIFY2(loaded.isEmpty(), "Decryption with wrong key must return empty");
}

// ═══════════════════════════════════════════════════════════════════════════
// Skipped Keys
// ═══════════════════════════════════════════════════════════════════════════

void TestSessionStore::deleteSkippedKeysForPeerDoesNotCrashOnEmptyTable()
{
    auto db = createTempDb("ss-skip-empty");
    SessionStore store(db, kTestStoreKey);

    // Calling on a peer with no rows must not crash
    store.deleteSkippedKeysForPeer("nonexistent-peer");

    // Manually insert a row to verify the DELETE actually works
    QSqlQuery q(db);
    q.prepare(
        "INSERT INTO skipped_message_keys (peer_id, dh_pub, msg_num, message_key, created_at)"
        " VALUES (:pid, :dh, :num, :key, :ts);"
        );
    q.bindValue(":pid", "peer-skip");
    q.bindValue(":dh", QByteArray(32, '\x11'));
    q.bindValue(":num", 5);
    q.bindValue(":key", QByteArray(32, '\x22'));
    q.bindValue(":ts", QDateTime::currentSecsSinceEpoch());
    QVERIFY(q.exec());

    // Verify the row exists
    QSqlQuery check(db);
    check.prepare("SELECT COUNT(*) FROM skipped_message_keys WHERE peer_id=:pid;");
    check.bindValue(":pid", "peer-skip");
    QVERIFY(check.exec() && check.next());
    QCOMPARE(check.value(0).toInt(), 1);

    // Now delete and verify it's gone
    store.deleteSkippedKeysForPeer("peer-skip");

    QSqlQuery verify(db);
    verify.prepare("SELECT COUNT(*) FROM skipped_message_keys WHERE peer_id=:pid;");
    verify.bindValue(":pid", "peer-skip");
    QVERIFY(verify.exec() && verify.next());
    QCOMPARE(verify.value(0).toInt(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Pending Handshakes
// ═══════════════════════════════════════════════════════════════════════════

void TestSessionStore::saveAndLoadPendingHandshake()
{
    auto db = createTempDb("ss-hs-save");
    SessionStore store(db, kTestStoreKey);

    QByteArray blob(80, '\xEE');
    store.savePendingHandshake("peer-hs", 0, blob);

    int roleOut = -1;
    QByteArray loaded = store.loadPendingHandshake("peer-hs", roleOut);
    QCOMPARE(loaded, blob);
    QCOMPARE(roleOut, 0);
}

void TestSessionStore::deletePendingHandshakeRemovesData()
{
    auto db = createTempDb("ss-hs-del");
    SessionStore store(db, kTestStoreKey);

    store.savePendingHandshake("peer-hsd", 1, QByteArray(40, '\xFF'));
    store.deletePendingHandshake("peer-hsd");

    int roleOut = -1;
    QByteArray loaded = store.loadPendingHandshake("peer-hsd", roleOut);
    QVERIFY(loaded.isEmpty());
}

void TestSessionStore::pruneStaleHandshakesRemovesOld()
{
    auto db = createTempDb("ss-hs-prune");
    SessionStore store(db, kTestStoreKey);

    store.savePendingHandshake("peer-stale", 0, QByteArray(50, '\xDD'));

    // maxAgeSecs = -1 makes the cutoff 1 second in the future,
    // so the just-created handshake (created_at == now) satisfies
    // created_at < (now + 1) and gets pruned.
    store.pruneStaleHandshakes(-1);

    int roleOut = -1;
    QByteArray loaded = store.loadPendingHandshake("peer-stale", roleOut);
    QVERIFY2(loaded.isEmpty(), "Stale handshake must be pruned");
}

void TestSessionStore::loadNonExistentHandshakeReturnsEmpty()
{
    auto db = createTempDb("ss-hs-none");
    SessionStore store(db, kTestStoreKey);

    int roleOut = -1;
    QByteArray loaded = store.loadPendingHandshake("nobody", roleOut);
    QVERIFY(loaded.isEmpty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Clear All
// ═══════════════════════════════════════════════════════════════════════════

void TestSessionStore::clearAllRemovesEverything()
{
    auto db = createTempDb("ss-clear-all");
    SessionStore store(db, kTestStoreKey);

    store.saveSession("peer1", QByteArray(32, '\x01'));
    store.savePendingHandshake("peer1", 0, QByteArray(32, '\x04'));

    store.clearAll();

    QVERIFY(store.loadSession("peer1").isEmpty());
    int r;
    QVERIFY(store.loadPendingHandshake("peer1", r).isEmpty());
}

QTEST_MAIN(TestSessionStore)
#include "tst_sessionstore.moc"
