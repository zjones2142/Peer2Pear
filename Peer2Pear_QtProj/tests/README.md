# 🧪 Peer2Pear Group Chat Tests

Automated unit tests for the group chat functionality in **Peer2Pear**, a peer-to-peer encrypted chat application built with Qt 6 and C++.

## 📦 Framework

**[Qt Test (QTest)](https://doc.qt.io/qt-6/qttest-index.html)** — ships with every Qt installation.

| Consideration | QTest | Google Test |
|---|---|---|
| **Signal/slot testing** | ✅ `QSignalSpy` built-in | ❌ No Qt awareness |
| **Extra dependencies** | ✅ None — ships with Qt | ❌ Must add gtest |
| **Qt type support** | ✅ Native `QString`, `QDateTime` | ⚠️ Needs custom printers |

## 🏗️ Build & Run

```bash
cd build
cmake .. --preset default
cmake --build .
ctest --output-on-failure

# Or run directly for verbose output:
./tests/tst_groupchat -v2
```

## 🐛 Known Bug: "Add Member" Always Says "Key Already Exists"

### What You See

When you open a group chat's editor, click "Add Member", select a contact, and hit Save, you always get:

> **"Key already belongs to contact 'Alice'"**

(Where "Alice" is the first member in the group.)

### Root Cause

The bug is in `chatview.cpp`, function `onEditContact()`, **lines 1702-1715**.

After the group editor returns the updated key list (existing members + the new one), the code runs a duplicate-key check:

```cpp
// chatview.cpp lines 1702-1715 — THE BUG
bool conflict = false;
for (const QString &k : std::as_const(keys)) {          // keys = ALL group members
    for (int i = 0; i < m_chats.size(); ++i) {
        if (i == index || m_chats[i].isGroup) continue;  // skip self & other groups
        if (m_chats[i].peerIdB64u == k || m_chats[i].keys.contains(k)) {
            // "Key already belongs to contact X" ← ALWAYS HITS
            conflict = true; break;
        }
    }
    if (conflict) break;
}
if (conflict) return;  // ← Save is blocked, member is never added
```

**The problem:** This check loops through ALL keys in the group (Alice, Bob, and the new member Charlie). The very first key (`keyAlice`) matches Alice's contact entry → `conflict = true` → the entire save is aborted.

This check is designed for **1:1 contacts** to prevent two contacts from having the same public key. But for **groups**, the member keys are *supposed* to match existing contacts — that's the whole point of groups.

Notice that lines 1688-1700 have a `if (!wasGroup)` guard for the key-format validation, but **the duplicate-key check on lines 1702-1715 has NO such guard**. It runs for both contacts AND groups.

### The Fix

Wrap lines 1702-1715 in `if (!wasGroup)`:

```cpp
// chatview.cpp onEditContact() — FIXED VERSION
if (!wasGroup) {
    // Prevent duplicate keys: only for 1:1 contacts
    bool conflict = false;
    for (const QString &k : std::as_const(keys)) {
        for (int i = 0; i < m_chats.size(); ++i) {
            if (i == index || m_chats[i].isGroup) continue;
            if (m_chats[i].peerIdB64u == k || m_chats[i].keys.contains(k)) {
                QMessageBox::warning(...);
                conflict = true; break;
            }
        }
        if (conflict) break;
    }
    if (conflict) return;
}
```

### Additional Missing Feature

Even after fixing the duplicate-key bug, there are two more issues:

1. **No broadcast to existing members**: `onEditContact()` broadcasts name changes (`sendGroupRename`) and avatar changes (`sendGroupAvatar`), but there's no broadcast for member list changes. Other group members won't know about the new member until someone sends a `group_msg`.

2. **No notification to the new member**: The newly added member receives no notification that they've been added to the group. They only discover it when someone sends a message.

### Test Coverage

Three tests in Category 5 reproduce these bugs and **intentionally FAIL**:

| Test | What It Proves | Status |
|---|---|---|
| `bug_addMemberPostCreation_duplicateKeyCheckBlocksGroupSave` | The duplicate-key check falsely blocks group saves | ❌ FAIL (bug) |
| `bug_addMemberPostCreation_noMemberChangeBroadcast` | No broadcast when member list changes | ❌ FAIL (missing feature) |
| `bug_addMemberPostCreation_newMemberNeverNotified` | New member gets no notification | ❌ FAIL (missing feature) |

When the bugs are fixed, these tests will automatically **PASS**.

## 📋 All Test Categories

### Category 1: Data Model (4 tests) ✅

| Test | What It Verifies |
|---|---|
| `chatDataDefaultsAreCorrect` | Default `ChatData` has safe defaults |
| `chatDataGroupFlagAndFields` | Group chat carries `isGroup=true`, valid `groupId`, member `keys` |
| `messageStructHoldsGroupFields` | `Message.senderName` populated for group messages |
| `chatDataCanHoldLargeMessageHistory` | 500 messages appended without issue |

### Category 2: Group Creation (5 tests) ✅

| Test | What It Verifies |
|---|---|
| `groupIdIsUnique` | Two groups get different UUIDs |
| `groupRequiresAtLeastOneMember` | Empty member list rejected |
| `emptyGroupNameFallsBackToDefault` | Missing name → `"Group Chat"` |
| `groupSubtitlePluralizesCorrectly` | "1 member" vs "2 members" |
| `groupCreationGeneratesValidUuid` | Valid UUID without braces |

### Category 3: Message Deduplication (4 tests) ✅

| Test | What It Verifies |
|---|---|
| `duplicateMessageIdIsDetected` | Same `msgId` → dropped |
| `uniqueMessageIdPassesThrough` | New `msgId` → accepted |
| `emptyMessageIdBypassesDedup` | Legacy messages skip dedup |
| `dedupWorksAcrossMultipleMessages` | Dedup works with 100 messages |

### Category 4: Member Management (8 tests) ✅

| Test | What It Verifies |
|---|---|
| `selfKeyIsExcludedFromRecipients` | Own key filtered when sending |
| `emptyKeysAreFilteredOut
