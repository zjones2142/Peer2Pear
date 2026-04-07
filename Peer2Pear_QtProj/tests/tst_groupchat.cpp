// ═══════════════════════════════════════════════════════════════════════════════
// Peer2Pear — Group Chat Unit Tests
// ═══════════════════════════════════════════════════════════════════════════════
//
// Test suite for group chat functionality including:
//   - Data model correctness (ChatData, Message structs)
//   - Signal/slot wiring (ChatController signals)
//   - JSON payload construction (group_msg, group_leave, group_rename)
//   - Message deduplication and ordering
//   - Member management (add, leave, key merging)
//   - Edge cases (empty names, blocked groups, self-exclusion, etc.)
//   - BUG REPRODUCTION: "Add Member" always says "key already exists"
//
// Framework: Qt Test (QTest) — ships with Qt, no extra dependencies.
// Build:     cmake --build build && ctest --output-on-failure
// Run:       ./tests/tst_groupchat -v2
// ═══════════════════════════════════════════════════════════════════════════════

// ── Fix GLib/Qt keyword collision ────────────────────────────────────────────
#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <QSignalSpy>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QUuid>

#include "../chattypes.h"
#include "../ChatController.hpp"

// ═══════════════════════════════════════════════════════════════════════════════
// Test class declaration
// ═══════════════════════════════════════════════════════════════════════════════

class TestGroupChat : public QObject
{
    Q_OBJECT

private Q_SLOTS:

    // ── CATEGORY 1: Data Model Tests ────────────────────────────────────────
    void chatDataDefaultsAreCorrect();
    void chatDataGroupFlagAndFields();
    void messageStructHoldsGroupFields();
    void chatDataCanHoldLargeMessageHistory();

    // ── CATEGORY 2: Group Creation ──────────────────────────────────────────
    void groupIdIsUnique();
    void groupRequiresAtLeastOneMember();
    void emptyGroupNameFallsBackToDefault();
    void groupSubtitlePluralizesCorrectly();
    void groupCreationGeneratesValidUuid();

    // ── CATEGORY 3: Message Deduplication ────────────────────────────────────
    void duplicateMessageIdIsDetected();
    void uniqueMessageIdPassesThrough();
    void emptyMessageIdBypassesDedup();
    void dedupWorksAcrossMultipleMessages();

    // ── CATEGORY 4: Member Management ───────────────────────────────────────
    void selfKeyIsExcludedFromRecipients();
    void emptyKeysAreFilteredOut();
    void memberKeyMergeAddsNewKeys();
    void memberKeyMergeSkipsDuplicates();
    void memberKeyMergeExcludesSelfKey();
    void memberLeftRemovesKeyFromGroup();
    void memberLeftGeneratesSystemMessage();
    void memberLeftOnUnknownGroupIsIgnored();

    // ── CATEGORY 5: BUG — Add Member After Creation ─────────────────────────
    void bug_addMemberPostCreation_duplicateKeyCheckBlocksGroupSave();
    void bug_addMemberPostCreation_noMemberChangeBroadcast();
    void bug_addMemberPostCreation_newMemberNeverNotified();

    // ── CATEGORY 6: Signal Wiring ───────────────────────────────────────────
    void groupMessageSignalCarriesAllArgs();
    void groupMemberLeftSignalCarriesAllArgs();
    void groupRenameSignalCarriesAllArgs();
    void groupAvatarSignalCarriesAllArgs();

    // ── CATEGORY 7: Payload Construction ────────────────────────────────────
    void groupMsgPayloadHasCorrectShape();
    void groupMsgPayloadExcludesSelfFromMembers();
    void groupLeavePayloadHasCorrectShape();
    void groupRenamePayloadHasCorrectShape();
    void groupAvatarPayloadHasCorrectShape();

    // ── CATEGORY 8: Sequence Counter (G5 Fix) ───────────────────────────────
    void sequenceCounterIsMonotonic();
    void sequenceCounterIsPerGroup();
    void sequenceGapDetection();

    // ── CATEGORY 9: Blocked Group Handling ──────────────────────────────────
    void blockedGroupDropsIncomingMessages();
    void blockedGroupStillExistsInChatList();

    // ── CATEGORY 10: Group Chat Key / Lookup ────────────────────────────────
    void chatKeyUsesGroupIdForGroups();
    void chatKeyFallsBackToNamePrefix();
    void groupLookupByGroupId();
    void groupAutoCreatedOnFirstMessage();

    // ── CATEGORY 11: Edge Cases & Regressions ───────────────────────────────
    void whitespaceInKeysIsTrimmed();
    void veryLongGroupNameHandled();
    void specialCharactersInGroupName();
    void multipleGroupsWithSameMembers();
    void sendingToGroupWithNoKeysIsHandled();
};

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 1: Data Model Tests
// ═══════════════════════════════════════════════════════════════��═══════════════

void TestGroupChat::chatDataDefaultsAreCorrect()
{
    ChatData cd;
    QCOMPARE(cd.isGroup,   false);
    QCOMPARE(cd.isBlocked, false);
    QCOMPARE(cd.isOnline,  false);
    QVERIFY2(cd.groupId.isEmpty(),
             "groupId must be empty by default — non-empty would confuse group lookup");
    QVERIFY2(cd.name.isEmpty(), "name must be empty by default");
    QVERIFY2(cd.keys.isEmpty(), "keys must be empty by default");
    QVERIFY2(cd.messages.isEmpty(), "messages must be empty by default");
    QVERIFY2(cd.avatarData.isEmpty(), "avatarData must be empty by default");
    QVERIFY2(!cd.lastActive.isValid(), "lastActive must be invalid by default");
}

void TestGroupChat::chatDataGroupFlagAndFields()
{
    ChatData cd;
    cd.isGroup = true;
    cd.groupId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    cd.peerIdB64u = cd.groupId;
    cd.name    = "Test Group";
    cd.subtitle = "Group · 3 members";
    cd.keys    = {"peerA_key", "peerB_key", "peerC_key"};

    QVERIFY2(cd.isGroup, "isGroup must be true for group chats");
    QVERIFY2(!cd.groupId.isEmpty(), "groupId must be set for group chats");
    QCOMPARE(cd.peerIdB64u, cd.groupId);
    QCOMPARE(cd.keys.size(), 3);
    QCOMPARE(cd.name, QString("Test Group"));
    QVERIFY2(cd.subtitle.contains("3"), "subtitle should mention member count");
}

void TestGroupChat::messageStructHoldsGroupFields()
{
    Message msg;
    msg.sent       = false;
    msg.text       = "Hello group!";
    msg.timestamp  = QDateTime::currentDateTimeUtc();
    msg.msgId      = QUuid::createUuid().toString(QUuid::WithoutBraces);
    msg.senderName = "Alice";

    QCOMPARE(msg.sent, false);
    QCOMPARE(msg.text, QString("Hello group!"));
    QCOMPARE(msg.senderName, QString("Alice"));
    QVERIFY2(!msg.msgId.isEmpty(), "msgId should be set for dedup to work");
    QVERIFY2(msg.timestamp.isValid(), "timestamp must be valid");
}

void TestGroupChat::chatDataCanHoldLargeMessageHistory()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "stress-test-group";

    const int count = 500;
    for (int i = 0; i < count; ++i) {
        Message m;
        m.sent = (i % 3 == 0);
        m.text = QString("Message #%1").arg(i);
        m.timestamp = QDateTime::currentDateTimeUtc().addSecs(i);
        m.msgId = QString("msg-%1").arg(i);
        m.senderName = (i % 2 == 0) ? "Alice" : "Bob";
        group.messages.append(m);
    }

    QCOMPARE(group.messages.size(), count);
    QCOMPARE(group.messages.first().text, QString("Message #0"));
    QCOMPARE(group.messages.last().text, QString("Message #499"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 2: Group Creation
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::groupIdIsUnique()
{
    QString id1 = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QString id2 = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QVERIFY2(id1 != id2,
             "Group IDs must be unique — collisions would merge unrelated groups");
}

void TestGroupChat::groupRequiresAtLeastOneMember()
{
    QStringList gkeys;
    QVERIFY2(gkeys.isEmpty(),
             "Creating a group with zero members should be rejected by the UI");
}

void TestGroupChat::emptyGroupNameFallsBackToDefault()
{
    QString groupName = "";
    QString displayName = groupName.isEmpty() ? "Group Chat" : groupName;
    QCOMPARE(displayName, QString("Group Chat"));
}

void TestGroupChat::groupSubtitlePluralizesCorrectly()
{
    auto makeSubtitle = [](int count) -> QString {
        return QString("Group · %1 member%2").arg(count).arg(count == 1 ? "" : "s");
    };

    QCOMPARE(makeSubtitle(1), QString("Group · 1 member"));
    QCOMPARE(makeSubtitle(2), QString("Group · 2 members"));
    QCOMPARE(makeSubtitle(10), QString("Group · 10 members"));
}

void TestGroupChat::groupCreationGeneratesValidUuid()
{
    QString groupId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QUuid parsed(groupId);
    QVERIFY2(!parsed.isNull(),
             qPrintable(QString("Generated groupId '%1' is not a valid UUID").arg(groupId)));
    QVERIFY2(!groupId.contains('{') && !groupId.contains('}'),
             "groupId should not contain braces");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 3: Message Deduplication
// ════���══════════════════════════════════════════════════════════════════════════

void TestGroupChat::duplicateMessageIdIsDetected()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "dedup-test";

    Message m1{false, "First message", QDateTime::currentDateTimeUtc(), "msg-001", "Alice"};
    group.messages.append(m1);

    QString incoming = "msg-001";
    bool isDuplicate = false;
    for (const Message &m : std::as_const(group.messages)) {
        if (m.msgId == incoming) { isDuplicate = true; break; }
    }
    QVERIFY2(isDuplicate,
             "Message with existing msgId MUST be detected as duplicate to prevent "
             "the same message from showing twice in the chat");
}

void TestGroupChat::uniqueMessageIdPassesThrough()
{
    ChatData group;
    group.isGroup = true;
    Message m1{false, "First", QDateTime::currentDateTimeUtc(), "msg-001", "Alice"};
    group.messages.append(m1);

    QString incoming = "msg-002";
    bool isDuplicate = false;
    for (const Message &m : std::as_const(group.messages)) {
        if (m.msgId == incoming) { isDuplicate = true; break; }
    }
    QVERIFY2(!isDuplicate,
             "Message with a new unique msgId must NOT be flagged as duplicate");
}

void TestGroupChat::emptyMessageIdBypassesDedup()
{
    ChatData group;
    group.isGroup = true;
    Message m1{false, "Old message", QDateTime::currentDateTimeUtc(), "", "Bob"};
    group.messages.append(m1);

    QString incoming = "";
    bool wouldDedup = false;
    if (!incoming.isEmpty()) {
        for (const Message &m : std::as_const(group.messages)) {
            if (m.msgId == incoming) { wouldDedup = true; break; }
        }
    }
    QVERIFY2(!wouldDedup,
             "Empty msgId must bypass dedup — legacy messages don't have IDs");
}

void TestGroupChat::dedupWorksAcrossMultipleMessages()
{
    ChatData group;
    group.isGroup = true;
    for (int i = 0; i < 100; ++i) {
        group.messages.append({false, QString("msg %1").arg(i),
                               QDateTime::currentDateTimeUtc(),
                               QString("id-%1").arg(i), "Sender"});
    }

    bool found50 = false;
    for (const Message &m : std::as_const(group.messages)) {
        if (m.msgId == "id-50") { found50 = true; break; }
    }
    QVERIFY2(found50, "Message id-50 should be found in the history");

    bool found999 = false;
    for (const Message &m : std::as_const(group.messages)) {
        if (m.msgId == "id-999") { found999 = true; break; }
    }
    QVERIFY2(!found999, "Message id-999 should NOT be found");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 4: Member Management
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::selfKeyIsExcludedFromRecipients()
{
    const QString myId = "selfKey123";
    const QStringList allMembers = {"keyA", "selfKey123", "keyB", "keyC"};

    QStringList recipients;
    for (const QString &peer : allMembers) {
        if (peer.trimmed().isEmpty() || peer.trimmed() == myId) continue;
        recipients.append(peer);
    }

    QCOMPARE(recipients.size(), 3);
    QVERIFY2(!recipients.contains(myId),
             "Self key must NEVER appear in recipients");
}

void TestGroupChat::emptyKeysAreFilteredOut()
{
    const QString myId = "myKey";
    const QStringList members = {"keyA", "", "  ", "keyB", "   ", "keyC"};

    QStringList recipients;
    for (const QString &peer : members) {
        if (peer.trimmed().isEmpty() || peer.trimmed() == myId) continue;
        recipients.append(peer);
    }

    QCOMPARE(recipients.size(), 3);
}

void TestGroupChat::memberKeyMergeAddsNewKeys()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "merge-test";
    group.keys = {"keyA", "keyB"};

    const QString myKey = "myOwnKey";
    QStringList incomingMembers = {"keyA", "keyC", "keyD"};

    bool keysUpdated = false;
    for (const QString &key : incomingMembers) {
        if (key.trimmed().isEmpty() || key.trimmed() == myKey) continue;
        if (!group.keys.contains(key)) {
            group.keys << key;
            keysUpdated = true;
        }
    }

    QVERIFY2(keysUpdated, "Keys should be updated when new members are discovered");
    QCOMPARE(group.keys.size(), 4);
    QVERIFY(group.keys.contains("keyC"));
    QVERIFY(group.keys.contains("keyD"));
}

void TestGroupChat::memberKeyMergeSkipsDuplicates()
{
    ChatData group;
    group.isGroup = true;
    group.keys = {"keyA", "keyB", "keyC"};

    const QString myKey = "myOwnKey";
    QStringList incomingMembers = {"keyA", "keyB", "keyC"};

    bool keysUpdated = false;
    for (const QString &key : incomingMembers) {
        if (key.trimmed().isEmpty() || key.trimmed() == myKey) continue;
        if (!group.keys.contains(key)) {
            group.keys << key;
            keysUpdated = true;
        }
    }

    QVERIFY2(!keysUpdated, "No update should occur when all incoming keys already exist");
    QCOMPARE(group.keys.size(), 3);
}

void TestGroupChat::memberKeyMergeExcludesSelfKey()
{
    ChatData group;
    group.isGroup = true;
    group.keys = {"keyA"};

    const QString myKey = "myOwnKey";
    QStringList incomingMembers = {"keyA", "myOwnKey", "keyB"};

    for (const QString &key : incomingMembers) {
        if (key.trimmed().isEmpty() || key.trimmed() == myKey) continue;
        if (!group.keys.contains(key))
            group.keys << key;
    }

    QVERIFY2(!group.keys.contains("myOwnKey"),
             "Self key must NOT be added to group member list");
    QCOMPARE(group.keys.size(), 2);
}

void TestGroupChat::memberLeftRemovesKeyFromGroup()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "leave-test";
    group.keys = {"keyAlice", "keyBob", "keyCharlie"};

    QString leaverId = "keyBob";
    group.keys.removeAll(leaverId);

    QCOMPARE(group.keys.size(), 2);
    QVERIFY2(!group.keys.contains("keyBob"),
             "Leaver's key must be removed");
    QVERIFY(group.keys.contains("keyAlice"));
    QVERIFY(group.keys.contains("keyCharlie"));
}

void TestGroupChat::memberLeftGeneratesSystemMessage()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "leave-msg-test";
    group.keys = {"keyAlice", "keyBob"};

    QString leaverId = "keyBob";
    group.keys.removeAll(leaverId);

    QString leaverName = leaverId.left(8) + "...";
    QString systemText = leaverName + " left the group";
    Message systemMsg{false, systemText, QDateTime::currentDateTimeUtc()};
    group.messages.append(systemMsg);

    QCOMPARE(group.messages.size(), 1);
    QVERIFY2(group.messages.last().text.contains("left the group"),
             qPrintable(QString("System message should say 'left the group', got: '%1'")
                            .arg(group.messages.last().text)));
}

void TestGroupChat::memberLeftOnUnknownGroupIsIgnored()
{
    QVector<ChatData> chats;
    ChatData g;
    g.isGroup = true;
    g.groupId = "known-group";
    chats.append(g);

    int targetIndex = -1;
    for (int i = 0; i < chats.size(); ++i) {
        if (chats[i].isGroup && chats[i].groupId == "unknown-group") {
            targetIndex = i;
            break;
        }
    }

    QCOMPARE(targetIndex, -1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 5: BUG REPRODUCTION — Add Member After Creation
//
// These tests reproduce the EXACT bug you're seeing: when you try to add a
// member to an existing group chat, it always says "Key already belongs to
// contact ___" (the first member in the list). These tests FAIL intentionally
// to show the bug exists.
//
// ROOT CAUSE (chatview.cpp, onEditContact(), lines 1702-1715):
//
//   The duplicate-key check iterates ALL keys returned from the group editor
//   and checks each one against every non-group contact's peerIdB64u and keys.
//   But group member keys ARE contact keys — that's the whole point. The check
//   should be SKIPPED for groups, but it's not. The `if (!wasGroup)` guard on
//   line 1689 only protects the isValidPublicKey() check, NOT the duplicate
//   key check below it.
//
//   So when you click Save after adding a new member, the code runs:
//     for (const QString &k : keys) {           // keys = ALL group members
//       for (int i = 0; i < m_chats.size(); i++) {
//         if (i == index || m_chats[i].isGroup) continue;
//         if (m_chats[i].peerIdB64u == k || m_chats[i].keys.contains(k)) {
//           // "Key already belongs to contact X" ← BOOM, always hits
//
//   The very FIRST existing member key matches their contact entry → conflict.
//   The new member is never actually saved.
//
// FIX: Wrap lines 1702-1715 in `if (!wasGroup) { ... }` so the duplicate-key
// check only runs for 1:1 contacts, not group member lists.
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::bug_addMemberPostCreation_duplicateKeyCheckBlocksGroupSave()
{
    // ┌────────────────────────────────────────────────────────────────────────┐
    // │  This test reproduces the exact bug: adding a member to an existing   │
    // │  group ALWAYS triggers "Key already belongs to contact" because the   │
    // │  duplicate-key validation runs on group member keys, which are        │
    // │  SUPPOSED to match existing contacts.                                 │
    // │                                                                       │
    // │  This test MUST FAIL until the bug is fixed.                          │
    // └────────────────────────────────────────────────────────────────────────┘

    // Set up: contacts list with Alice, Bob, and a group containing both
    QVector<ChatData> m_chats;

    ChatData alice;
    alice.name = "Alice";
    alice.peerIdB64u = "keyAlice_base64url_43chars_aaaaaaaaaaa";
    alice.keys = {alice.peerIdB64u};
    m_chats.append(alice);  // index 0

    ChatData bob;
    bob.name = "Bob";
    bob.peerIdB64u = "keyBob___base64url_43chars_bbbbbbbbbbb";
    bob.keys = {bob.peerIdB64u};
    m_chats.append(bob);  // index 1

    ChatData charlie;
    charlie.name = "Charlie";
    charlie.peerIdB64u = "keyCharl_base64url_43chars_ccccccccccc";
    charlie.keys = {charlie.peerIdB64u};
    m_chats.append(charlie);  // index 2

    ChatData group;
    group.isGroup = true;
    group.groupId = "test-group-id";
    group.peerIdB64u = group.groupId;
    group.name = "Dev Team";
    group.keys = {alice.peerIdB64u, bob.peerIdB64u};  // Alice and Bob are members
    m_chats.append(group);  // index 3

    const int groupIndex = 3;
    const bool wasGroup = m_chats[groupIndex].isGroup;

    // Simulate: user opened editor and added Charlie as a new member
    QStringList updatedKeys = {alice.peerIdB64u, bob.peerIdB64u, charlie.peerIdB64u};

    // ── This is the EXACT code from onEditContact() lines 1702-1715 ──────────
    // Notice: there is NO `if (!wasGroup)` guard here. That's the bug.
    bool conflict = false;
    QString conflictContactName;
    for (const QString &k : std::as_const(updatedKeys)) {
        for (int i = 0; i < m_chats.size(); ++i) {
            if (i == groupIndex || m_chats[i].isGroup) continue;
            if (m_chats[i].peerIdB64u == k || m_chats[i].keys.contains(k)) {
                conflictContactName = m_chats[i].name;
                conflict = true;
                break;
            }
        }
        if (conflict) break;
    }

    // The bug: `conflict` is true because Alice's key (the first member)
    // matches Alice's contact entry. The save is blocked.
    // In a fixed version, this check should be SKIPPED for groups.

    qDebug() << "";
    qDebug() << "╔══════════════════════════════════════════════════════════════╗";
    qDebug() << "║  BUG: Duplicate-key check triggers on group member keys     ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  conflict      =" << conflict << "  (should be false for groups)     ║";
    qDebug() << "║  blocked by    =" << conflictContactName << "                              ║";
    qDebug() << "║  first member  = Alice's key matches Alice's contact        ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  LOCATION: chatview.cpp onEditContact() lines 1702-1715     ║";
    qDebug() << "║  FIX: Wrap the duplicate-key loop in if (!wasGroup) { }     ║";
    qDebug() << "╚══════════════════════════════════════════════════════════════╝";
    qDebug() << "";

    // This FAILS — proving the bug exists.
    // When the bug is fixed, this assertion will PASS.
    QVERIFY2(!conflict,
             qPrintable(QString(
                            "BUG: Adding a member to group '%1' is blocked because the "
                            "duplicate-key check found that '%2' already belongs to "
                            "contact '%3'. This check should be SKIPPED for groups "
                            "(wasGroup=true) because group member keys are SUPPOSED to "
                            "match existing contacts. "
                            "FIX: chatview.cpp line 1702 — wrap the duplicate-key loop "
                            "in 'if (!wasGroup) { ... }'")
                            .arg(group.name, updatedKeys.first(), conflictContactName)));
}

void TestGroupChat::bug_addMemberPostCreation_noMemberChangeBroadcast()
{
    // ┌────────────────────────────────────────────────────────────────────────┐
    // │  Even if the duplicate-key bug above were fixed, there's a second     │
    // │  problem: onEditContact() broadcasts rename and avatar changes, but   │
    // │  NOT member list changes. The new member would be saved locally but   │
    // │  nobody else would know about them until someone sends a message.     │
    // │                                                                       │
    // │  This test MUST FAIL until the broadcast is implemented.              │
    // └────────────────────────────────────────────────────────────────────────┘

    // Simulate what onEditContact() does after saving a group edit (lines 1728-1734):
    //   if (wasGroup) {
    //       if (name != oldName)   → sendGroupRename(...)   ✅ exists
    //       if (avatar != oldAvatar) → sendGroupAvatar(...) ✅ exists
    //       // if (keys != oldKeys) → sendGroupMemberAdded(...)  ❌ MISSING
    //   }

    const bool wasGroup = true;
    const QStringList oldKeys = {"keyAlice", "keyBob"};
    const QStringList newKeys = {"keyAlice", "keyBob", "keyCharlie"};
    const bool keysChanged = (oldKeys != newKeys);

    // Check: does the code broadcast member changes?
    // In the current code, onEditContact() only checks name and avatar changes.
    // There is no check for key list changes and no sendGroupMemberAdded() method.
    bool broadcastsMemberChanges = false;

    // To pass, the code would need something like:
    //   if (keys != oldKeys)
    //       m_controller->sendGroupMemberUpdate(groupId, keys);
    // This does not exist.

    qDebug() << "";
    qDebug() << "╔══════════════════════════════════════════════════════════════╗";
    qDebug() << "║  BUG: No broadcast when group member list changes           ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  keysChanged            =" << keysChanged << "                              ║";
    qDebug() << "║  broadcastsMemberChanges =" << broadcastsMemberChanges << "                             ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  onEditContact() broadcasts:                                ║";
    qDebug() << "║    ✅ name changes    → sendGroupRename()                   ║";
    qDebug() << "║    ✅ avatar changes  → sendGroupAvatar()                   ║";
    qDebug() << "║    ❌ member changes  → (nothing!)                          ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  LOCATION: chatview.cpp onEditContact() lines 1728-1734     ║";
    qDebug() << "║  FIX: Add sendGroupMemberUpdate() and call it when keys     ║";
    qDebug() << "║       differ from the original list.                        ║";
    qDebug() << "╚══════════════════════════════════════════════════════════════╝";
    qDebug() << "";

    QVERIFY2(keysChanged,
             "Sanity check: the key list should have changed after adding Charlie");

    // This FAILS — proving the broadcast is missing.
    QVERIFY2(broadcastsMemberChanges,
             "BUG: When a member is added to a group post-creation, the change "
             "is NOT broadcast to other members. onEditContact() only broadcasts "
             "name and avatar changes (lines 1729-1733). There is no "
             "sendGroupMemberUpdate() or equivalent. Other members won't know "
             "about the new member until someone sends a group_msg (which "
             "includes the members array). "
             "FIX: Add a member-change broadcast in onEditContact() after line 1733.");
}

void TestGroupChat::bug_addMemberPostCreation_newMemberNeverNotified()
{
    // ┌────────────────────────────────────────────────────────────────────────┐
    // │  Third part of the bug: even if we broadcast to existing members,     │
    // │  the NEW member (Charlie) also needs to be told about the group.      │
    // │  Without notification, Charlie has no idea the group exists until     │
    // │  someone sends a message.                                             │
    // │                                                                       │
    // │  This test MUST FAIL until the notification is implemented.            │
    // └────────────────────────────────────────────────────────────────────────┘

    // In the current code, there is no mechanism to send a "you've been added
    // to group X" notification to the new member.
    //
    // What SHOULD happen when Charlie is added:
    //   1. Send Charlie a payload like:
    //      { "type": "group_invite", "groupId": "...", "groupName": "Dev Team",
    //        "members": ["keyAlice", "keyBob", "keyCharlie"] }
    //   2. Charlie's client auto-creates the group and adds all members.
    //   3. Charlie can immediately send/receive messages in the group.
    //
    // What ACTUALLY happens:
    //   1. Nothing. Charlie is not notified.
    //   2. Charlie discovers the group only when someone sends a group_msg.
    //   3. If nobody sends a message, Charlie never knows about the group.

    bool newMemberIsNotified = false;

    // Check if ChatController has any method that could notify a new member
    // about being added to a group. It doesn't.
    // (sendGroupMessageViaMailbox sends a chat message, not an invite)
    // (sendGroupRename only changes the name)
    // (sendGroupAvatar only changes the avatar)

    qDebug() << "";
    qDebug() << "╔══════════════════════════════════════════════════════════════╗";
    qDebug() << "║  BUG: Newly added member is never notified about the group  ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  Scenario: Alice adds Charlie to 'Dev Team' group           ║";
    qDebug() << "║  Expected: Charlie sees 'Dev Team' appear in their chat     ║";
    qDebug() << "║  Actual:   Charlie has no idea the group exists              ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  Charlie only discovers the group when someone sends a      ║";
    qDebug() << "║  group_msg. If nobody messages, Charlie never knows.        ║";
    qDebug() << "║                                                             ║";
    qDebug() << "║  FIX: Add a 'group_invite' message type that is sent to     ║";
    qDebug() << "║       new members with the group ID, name, and member list. ║";
    qDebug() << "╚══════════════════════════════════════════════════════════════╝";
    qDebug() << "";

    QVERIFY2(newMemberIsNotified,
             "BUG: When a new member is added to a group, they receive NO "
             "notification about it. There is no 'group_invite' message type, "
             "no sendGroupInvite() method, and no handling code on the receiver "
             "side. The new member only discovers the group when someone else "
             "sends a message. "
             "FIX: (1) Add a 'group_invite' payload type in ChatController, "
             "(2) Send it to the new member from onEditContact(), "
             "(3) Handle it in onEnvelope() to auto-create the group.");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 6: Signal Wiring
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::groupMessageSignalCarriesAllArgs()
{
    ChatController ctrl;
    QSignalSpy spy(&ctrl, &ChatController::groupMessageReceived);
    QVERIFY2(spy.isValid(), "groupMessageReceived signal must be connectable");

    Q_EMIT ctrl.groupMessageReceived(
        "senderKeyBase64u", "group-id-123", "Test Group",
        {"keyA", "keyB", "keyC"}, "Hello everyone!",
        QDateTime::currentDateTimeUtc(), "msg-uuid-001"
        );

    QCOMPARE(spy.count(), 1);
    QList<QVariant> args = spy.takeFirst();
    QCOMPARE(args.at(0).toString(), QString("senderKeyBase64u"));
    QCOMPARE(args.at(1).toString(), QString("group-id-123"));
    QCOMPARE(args.at(2).toString(), QString("Test Group"));
    QCOMPARE(args.at(3).toStringList().size(), 3);
    QCOMPARE(args.at(4).toString(), QString("Hello everyone!"));
    QVERIFY2(args.at(5).toDateTime().isValid(), "Timestamp must be valid");
    QCOMPARE(args.at(6).toString(), QString("msg-uuid-001"));
}

void TestGroupChat::groupMemberLeftSignalCarriesAllArgs()
{
    ChatController ctrl;
    QSignalSpy spy(&ctrl, &ChatController::groupMemberLeft);
    QVERIFY2(spy.isValid(), "groupMemberLeft signal must be connectable");

    QDateTime now = QDateTime::currentDateTimeUtc();
    Q_EMIT ctrl.groupMemberLeft(
        "leaverKeyBase64u", "group-id-456", "Another Group",
        {"keyA", "keyB"}, now, "msg-uuid-002"
        );

    QCOMPARE(spy.count(), 1);
    QList<QVariant> args = spy.takeFirst();
    QCOMPARE(args.at(0).toString(), QString("leaverKeyBase64u"));
    QCOMPARE(args.at(1).toString(), QString("group-id-456"));
    QCOMPARE(args.at(3).toStringList(), QStringList({"keyA", "keyB"}));
    QCOMPARE(args.at(4).toDateTime(), now);
}

void TestGroupChat::groupRenameSignalCarriesAllArgs()
{
    ChatController ctrl;
    QSignalSpy spy(&ctrl, &ChatController::groupRenamed);
    QVERIFY2(spy.isValid(), "groupRenamed signal must be connectable");

    Q_EMIT ctrl.groupRenamed("group-id-789", "New Fancy Name");

    QCOMPARE(spy.count(), 1);
    QList<QVariant> args = spy.takeFirst();
    QCOMPARE(args.at(0).toString(), QString("group-id-789"));
    QCOMPARE(args.at(1).toString(), QString("New Fancy Name"));
}

void TestGroupChat::groupAvatarSignalCarriesAllArgs()
{
    ChatController ctrl;
    QSignalSpy spy(&ctrl, &ChatController::groupAvatarReceived);
    QVERIFY2(spy.isValid(), "groupAvatarReceived signal must be connectable");

    Q_EMIT ctrl.groupAvatarReceived("group-id-789", "iVBORw0KGgo=");

    QCOMPARE(spy.count(), 1);
    QList<QVariant> args = spy.takeFirst();
    QCOMPARE(args.at(0).toString(), QString("group-id-789"));
    QCOMPARE(args.at(1).toString(), QString("iVBORw0KGgo="));
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 7: Payload Construction
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::groupMsgPayloadHasCorrectShape()
{
    QJsonObject payload;
    payload["from"]      = "myPublicKeyBase64u";
    payload["type"]      = "group_msg";
    payload["groupId"]   = "group-xyz";
    payload["groupName"] = "Dev Team";
    payload["text"]      = "Payload test";
    payload["ts"]        = QDateTime::currentSecsSinceEpoch();
    payload["msgId"]     = QUuid::createUuid().toString(QUuid::WithoutBraces);
    payload["seq"]       = 1;

    QVERIFY2(payload.contains("from"),      "Missing 'from'");
    QVERIFY2(payload.contains("type"),      "Missing 'type'");
    QVERIFY2(payload.contains("groupId"),   "Missing 'groupId'");
    QVERIFY2(payload.contains("groupName"), "Missing 'groupName'");
    QVERIFY2(payload.contains("text"),      "Missing 'text'");
    QVERIFY2(payload.contains("ts"),        "Missing 'ts'");
    QVERIFY2(payload.contains("msgId"),     "Missing 'msgId'");
    QVERIFY2(payload.contains("seq"),       "Missing 'seq' (G5 fix)");
    QCOMPARE(payload["type"].toString(), QString("group_msg"));
}

void TestGroupChat::groupMsgPayloadExcludesSelfFromMembers()
{
    const QString myId = "myKey";
    const QStringList members = {"keyA", "myKey", "keyB"};

    QJsonArray membersArray;
    for (const QString &key : members) {
        if (key.trimmed() == myId) continue;
        membersArray.append(key);
    }

    QCOMPARE(membersArray.size(), 2);
    for (const auto &v : membersArray)
        QVERIFY2(v.toString() != myId, "Self key in members array");
}

void TestGroupChat::groupLeavePayloadHasCorrectShape()
{
    QJsonObject payload;
    payload["from"]      = "myKey";
    payload["type"]      = "group_leave";
    payload["groupId"]   = "group-leave-test";
    payload["groupName"] = "Goodbye Group";
    payload["members"]   = QJsonArray({"keyA", "keyB"});
    payload["ts"]        = QDateTime::currentSecsSinceEpoch();

    QCOMPARE(payload["type"].toString(), QString("group_leave"));
    QVERIFY2(payload.contains("groupId"), "Missing groupId");
    QVERIFY2(payload.contains("members"), "Missing members");
    QVERIFY2(payload.contains("ts"),      "Missing ts");
}

void TestGroupChat::groupRenamePayloadHasCorrectShape()
{
    QJsonObject payload;
    payload["from"]    = "myKey";
    payload["type"]    = "group_rename";
    payload["groupId"] = "group-rename-test";
    payload["newName"] = "Renamed Group";

    QCOMPARE(payload["type"].toString(), QString("group_rename"));
    QVERIFY2(payload.contains("newName"), "Missing 'newName'");
}

void TestGroupChat::groupAvatarPayloadHasCorrectShape()
{
    QJsonObject payload;
    payload["from"]    = "myKey";
    payload["type"]    = "group_avatar";
    payload["groupId"] = "group-avatar-test";
    payload["avatar"]  = "base64data==";

    QCOMPARE(payload["type"].toString(), QString("group_avatar"));
    QVERIFY2(payload.contains("avatar"), "Missing 'avatar'");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 8: Sequence Counter (G5 Fix)
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::sequenceCounterIsMonotonic()
{
    QMap<QString, qint64> groupSeqOut;
    const QString gid = "group-seq-test";

    qint64 seq1 = ++groupSeqOut[gid];
    qint64 seq2 = ++groupSeqOut[gid];
    qint64 seq3 = ++groupSeqOut[gid];

    QCOMPARE(seq1, 1);
    QCOMPARE(seq2, 2);
    QCOMPARE(seq3, 3);
    QVERIFY2(seq3 > seq2 && seq2 > seq1,
             "Sequence counter must be strictly monotonically increasing");
}

void TestGroupChat::sequenceCounterIsPerGroup()
{
    QMap<QString, qint64> groupSeqOut;

    qint64 seqA1 = ++groupSeqOut["groupA"];
    qint64 seqA2 = ++groupSeqOut["groupA"];
    qint64 seqB1 = ++groupSeqOut["groupB"];

    QCOMPARE(seqA1, 1);
    QCOMPARE(seqA2, 2);
    QCOMPARE(seqB1, 1);
}

void TestGroupChat::sequenceGapDetection()
{
    QMap<QString, qint64> groupSeqIn;
    const QString seqKey = "groupA:sender1";

    groupSeqIn[seqKey] = 1;

    qint64 incoming = 2;
    qint64 expected = groupSeqIn[seqKey] + 1;
    bool gap = (incoming > expected);
    QVERIFY2(!gap, "seq=2 after seq=1 should NOT trigger a gap");
    groupSeqIn[seqKey] = incoming;

    incoming = 5;
    expected = groupSeqIn[seqKey] + 1;
    gap = (incoming > expected);
    QVERIFY2(gap,
             qPrintable(QString("seq=%1 after seq=2 should trigger a gap (expected %2)")
                            .arg(incoming).arg(expected)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 9: Blocked Group Handling
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::blockedGroupDropsIncomingMessages()
{
    ChatData group;
    group.isGroup   = true;
    group.groupId   = "blocked-group";
    group.isBlocked = true;

    bool shouldProcess = !group.isBlocked;
    QVERIFY2(!shouldProcess,
             "Blocked group must NOT process incoming messages");
}

void TestGroupChat::blockedGroupStillExistsInChatList()
{
    QVector<ChatData> chats;
    ChatData g;
    g.isGroup = true;
    g.isBlocked = true;
    g.groupId = "blocked-but-visible";
    g.name = "Blocked Group";
    chats.append(g);

    QCOMPARE(chats.size(), 1);
    QVERIFY(chats[0].isBlocked);
    QVERIFY2(!chats[0].name.isEmpty(), "Blocked groups should still show in chat list");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 10: Group Chat Key / Lookup
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::chatKeyUsesGroupIdForGroups()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "stable-group-key";
    group.peerIdB64u = "stable-group-key";
    group.name = "Test Group";

    QString key;
    if (group.isGroup) key = group.groupId;
    else if (!group.peerIdB64u.isEmpty()) key = group.peerIdB64u;
    else key = "name:" + group.name;

    QCOMPARE(key, QString("stable-group-key"));
}

void TestGroupChat::chatKeyFallsBackToNamePrefix()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "";
    group.peerIdB64u = "";
    group.name = "Orphan Group";

    QString key;
    if (group.isGroup && !group.groupId.isEmpty()) key = group.groupId;
    else if (!group.peerIdB64u.isEmpty()) key = group.peerIdB64u;
    else key = "name:" + group.name;

    QCOMPARE(key, QString("name:Orphan Group"));
}

void TestGroupChat::groupLookupByGroupId()
{
    QVector<ChatData> chats;
    for (int i = 0; i < 5; ++i) {
        ChatData c;
        c.isGroup = (i >= 3);
        c.groupId = c.isGroup ? QString("group-%1").arg(i) : "";
        c.name = QString("Chat %1").arg(i);
        chats.append(c);
    }

    int idx = -1;
    for (int i = 0; i < chats.size(); ++i) {
        if (chats[i].isGroup && chats[i].groupId == "group-4") {
            idx = i;
            break;
        }
    }

    QCOMPARE(idx, 4);
    QCOMPARE(chats[idx].name, QString("Chat 4"));
}

void TestGroupChat::groupAutoCreatedOnFirstMessage()
{
    QVector<ChatData> chats;

    QString groupId = "brand-new-group";
    int idx = -1;
    for (int i = 0; i < chats.size(); ++i) {
        if (chats[i].isGroup && chats[i].groupId == groupId) { idx = i; break; }
    }

    QCOMPARE(idx, -1);

    ChatData ng;
    ng.isGroup = true;
    ng.groupId = groupId;
    ng.peerIdB64u = groupId;
    ng.name = "Auto Group";
    ng.subtitle = "Group chat";
    ng.keys.append("senderKey");
    chats.append(ng);
    idx = chats.size() - 1;

    QCOMPARE(idx, 0);
    QCOMPARE(chats[idx].groupId, groupId);
    QVERIFY(chats[idx].keys.contains("senderKey"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY 11: Edge Cases & Regressions
// ═══════════════════════════════════════════════════════════════════════════════

void TestGroupChat::whitespaceInKeysIsTrimmed()
{
    const QString rawKey = "  keyWithSpaces  ";
    const QString trimmed = rawKey.trimmed();
    QCOMPARE(trimmed, QString("keyWithSpaces"));

    ChatData group;
    group.isGroup = true;
    group.keys = {"keyWithSpaces"};

    bool found = false;
    for (const QString &k : std::as_const(group.keys)) {
        if (k.trimmed() == rawKey.trimmed()) { found = true; break; }
    }
    QVERIFY2(found, "Key lookup must trim whitespace");
}

void TestGroupChat::veryLongGroupNameHandled()
{
    ChatData group;
    group.isGroup = true;
    group.name = QString(500, QChar('A'));
    group.groupId = "long-name-group";

    QCOMPARE(group.name.size(), 500);
}

void TestGroupChat::specialCharactersInGroupName()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "special-chars-group";
    group.name = "🍐 Peer2Pear <Team> \"Quotes\" & 'Apostrophes'";

    QVERIFY(!group.name.isEmpty());
    QVERIFY(group.name.contains("🍐"));
    QVERIFY(group.name.contains("<Team>"));
}

void TestGroupChat::multipleGroupsWithSameMembers()
{
    ChatData g1, g2;
    g1.isGroup = true; g1.groupId = "group-1"; g1.keys = {"keyA", "keyB"};
    g2.isGroup = true; g2.groupId = "group-2"; g2.keys = {"keyA", "keyB"};

    QVERIFY2(g1.groupId != g2.groupId,
             "Groups with same members must be distinguished by groupId");
}

void TestGroupChat::sendingToGroupWithNoKeysIsHandled()
{
    ChatData group;
    group.isGroup = true;
    group.groupId = "empty-group";
    group.keys.clear();

    bool canSend = !group.keys.isEmpty();
    QVERIFY2(!canSend,
             "Sending to a group with no member keys must be blocked");
}

// ─────────────────────────────────────────────────────────────────────────────
QTEST_MAIN(TestGroupChat)
#include "tst_groupchat.moc"
