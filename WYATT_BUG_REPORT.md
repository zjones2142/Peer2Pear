# Wyatt Branch — Bug Summary Report

Comparing the latest commit on `Wyatt` (commit `94577ad` — *"Start of File Sharing"*)
against the HEAD of `main` (commit `0ae82e8`).

---

## Summary Table

| # | Severity | File | Line(s) | Description | Fix |
|---|----------|------|---------|-------------|-----|
| 1 | 🔴 Critical | `chatview.h`, `chatview.cpp`, `CMakeLists.txt` | `chatview.h:18`, `CMakeLists.txt:32` | **`filetransfer.h` is missing** — included and listed in build but the file was never committed | Create `Peer2Pear_QtProj/filetransfer.h` with the `FileTransferRecord` struct, `FileTransferStatus` enum, `formatFileSize()`, and `fileIcon()` helper functions |
| 2 | 🟠 Moderate | `chatview.cpp` vs `ChatController.cpp` | `chatview.cpp:515-516`, `ChatController.cpp:23` | **Chunk-size mismatch** — sender uses `kChunkBytes = 240 KB`, but the local sent-file record calculates `totalChunks` using `kChunk = 256 KB`, producing a wrong chunk count | Change `chatview.cpp` line 515 to `constexpr qint64 kChunk = 240LL * 1024;` to match `ChatController.cpp` |
| 3 | 🟠 Moderate | `ChatController.cpp` | Lines 44–46 | **`unpack32()` unsigned-shift undefined behaviour** — `quint8(b[offset]) << 24` promotes `quint8` to `int`, then shifts into the sign bit when value ≥ 128 (C++ UB) | Cast to `quint32` before shifting: `(quint32(quint8(b[offset])) << 24) \| (quint32(quint8(b[offset+1])) << 16) \| ...` |
| 4 | 🟡 Minor | `ChatController.cpp` | Line 182 | **`stopPolling()` does not stop `m_rvzRefreshTimer`** — the 9-minute rendezvous refresh timer keeps firing after polling is halted | Add `m_rvzRefreshTimer.stop();` inside `stopPolling()` |
| 5 | 🟡 Minor | `ChatController.cpp` | Lines 71, 175 | **Inconsistent host in rendezvous `publish()` calls** — `startPolling()` publishes with `"3.141.14.234"` (hard-coded IP) while the refresh-timer lambda publishes with `"0.0.0.0"` (placeholder); the comment on line 173 says `"0.0.0.0"` is the correct placeholder | Change line 175 to `m_rvz.publish("0.0.0.0", 0, 10LL * 60 * 1000);` so both calls use the same placeholder |

---

## Detailed Findings

### Bug 1 — Missing `filetransfer.h` (Critical)

**What broke:** The commit adds a full file-sharing feature but forgot to commit the
header that defines its core types and helpers.

| Offending location | Detail |
|--------------------|--------|
| `Peer2Pear_QtProj/chatview.h` line 18 | `#include "filetransfer.h"` |
| `Peer2Pear_QtProj/CMakeLists.txt` line 32 | `filetransfer.h` listed in `PROJECT_SOURCES` |
| `Peer2Pear_QtProj/chatview.cpp` throughout | Uses `FileTransferRecord`, `FileTransferStatus`, `formatFileSize()`, `fileIcon()` |

**Symptoms:** The project will fail to compile entirely — the preprocessor cannot
find the included header and the linker will have unresolved symbols.

**Fix:** Create `Peer2Pear_QtProj/filetransfer.h` containing (at minimum):

```cpp
#pragma once
#include <QString>
#include <QDateTime>

enum class FileTransferStatus { Sending, Receiving, Complete, Failed };

struct FileTransferRecord {
    QString           transferId;
    QString           fileName;
    qint64            fileSize      = 0;
    QString           peerIdB64u;
    QString           peerName;
    QDateTime         timestamp;
    bool              sent          = false;
    FileTransferStatus status       = FileTransferStatus::Sending;
    int               chunksTotal   = 0;
    int               chunksComplete = 0;
    QString           savedPath;
};

inline QString formatFileSize(qint64 bytes) {
    if (bytes < 1024)        return QString("%1 B").arg(bytes);
    if (bytes < 1024*1024)   return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    return QString("%1 MB").arg(bytes / (1024.0*1024.0), 0, 'f', 1);
}

inline QString fileIcon(const QString &fileName) {
    const QString ext = fileName.section('.', -1).toLower();
    if (ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "gif" || ext == "webp")
        return "🖼️";
    if (ext == "pdf")  return "📄";
    if (ext == "mp4" || ext == "mov" || ext == "avi") return "🎬";
    if (ext == "mp3" || ext == "wav" || ext == "flac") return "🎵";
    if (ext == "zip" || ext == "tar" || ext == "gz")   return "🗜️";
    return "📎";
}
```

---

### Bug 2 — Chunk-size Mismatch (Moderate)

**What broke:** The sender (in `ChatController::sendFile`) splits the file into
**240 KB** chunks, but the local record created in `ChatView::onAttachFile` computes
`totalChunks` using **256 KB**, yielding a different number for any file > 256 KB.

| Location | Value |
|----------|-------|
| `ChatController.cpp` line 23 | `static constexpr qint64 kChunkBytes = 240LL * 1024;` |
| `chatview.cpp` line 515 | `constexpr qint64 kChunk = 256LL * 1024;` ← **wrong** |

**Example:** A 1 MB (1 024 KB) file:
- Sender (`ChatController`) splits it into **5 chunks** — `ceil(1024 / 240) = 5`
- Local record (`onAttachFile`) stores `totalChunks = 4` — `ceil(1024 / 256) = 4`

The off-by-one mismatch grows with file size. For a 2 MB file the sender produces
**9 chunks** while the local record stores **8**. Any file whose size is not an
exact multiple of 256 KB will show a discrepancy.

**Fix:** In `chatview.cpp` line 515, change:
```cpp
// Before (wrong)
constexpr qint64 kChunk = 256LL * 1024;

// After (correct)
constexpr qint64 kChunk = 240LL * 1024;
```
Or, better, expose `kChunkBytes` from `ChatController` (e.g., as a public constant or
method) so there is a single source of truth.

---

### Bug 3 — `unpack32()` Unsigned-Shift Undefined Behaviour (Moderate)

**What broke:** The new `unpack32()` helper, used to read the 4-byte big-endian
`metaLen` field from incoming file-chunk envelopes, promotes each `quint8` byte to a
signed `int` before shifting. When the high byte is ≥ 128, the left shift of 24
positions puts a 1 into the sign bit of a 32-bit `int` — undefined behaviour in C++11
and later.

| Location |
|----------|
| `ChatController.cpp` lines 44–46 |

```cpp
// Current (UB when b[offset] >= 0x80)
return (quint8(b[offset])   << 24)
    | (quint8(b[offset+1]) << 16)
    | (quint8(b[offset+2]) <<  8)
    |  quint8(b[offset+3]);
```

**Fix:** Cast each byte to `quint32` before shifting:
```cpp
return (quint32(quint8(b[offset  ])) << 24)
     | (quint32(quint8(b[offset+1])) << 16)
     | (quint32(quint8(b[offset+2])) <<  8)
     |  quint32(quint8(b[offset+3]));
```

In practice the metadata blob is always well under 2 GB so `metaLen` will never have
the high bit set, and most compilers produce the expected output anyway — but the UB
is real and should be fixed.

---

### Bug 4 — `stopPolling()` Leaks the Refresh Timer (Minor)

**What broke:** `ChatController::stopPolling()` (line 182) calls only
`m_pollTimer.stop()`. The `m_rvzRefreshTimer`, started at line 176 inside
`startPolling()`, is never stopped. After a caller halts polling, the app continues
sending rendezvous keep-alive requests every 9 minutes indefinitely.

| Location |
|----------|
| `ChatController.cpp` line 182 |

```cpp
// Current (incomplete)
void ChatController::stopPolling() { m_pollTimer.stop(); }

// Fix
void ChatController::stopPolling() {
    m_pollTimer.stop();
    m_rvzRefreshTimer.stop();
}
```

---

### Bug 5 — Inconsistent Host in Rendezvous `publish()` Calls (Minor)

**What broke:** When `startPolling()` is first called it publishes with the server's
real IP (`"3.141.14.234"`), but every subsequent refresh uses `"0.0.0.0"`. The
in-code comment on line 173 explicitly states `"0.0.0.0"` is the intended placeholder
and that the server records the caller's source IP. The initial call should use the
same placeholder.

| Location | Value |
|----------|-------|
| `ChatController.cpp` line 175 | `m_rvz.publish("3.141.14.234", ...)` ← inconsistent |
| `ChatController.cpp` line 71 | `m_rvz.publish("0.0.0.0", ...)` ← correct placeholder |

**Fix:** Change line 175 to:
```cpp
m_rvz.publish("0.0.0.0", 0, 10LL * 60 * 1000);
```

---

## Files Changed in the Wyatt Commit

| File | Change type |
|------|-------------|
| `Peer2Pear_QtProj/ChatController.cpp` | Modified — file-chunk send/receive, msgId dedup, fetchAll, P2P cleanup |
| `Peer2Pear_QtProj/ChatController.hpp` | Modified — new signals (`fileChunkReceived`), `sendFile()`, `msgId` on existing signals |
| `Peer2Pear_QtProj/MailboxClient.cpp` | Modified — `fetchAll()` added, single-fetch drain loop |
| `Peer2Pear_QtProj/MailboxClient.h` | Modified — `fetchAll()` declaration, `m_fetchInFlight` guard |
| `Peer2Pear_QtProj/chatview.cpp` | Modified — file tab UI, `onAttachFile`, `onFileChunkReceived`, `buildFileCard` |
| `Peer2Pear_QtProj/chatview.h` | Modified — `#include "filetransfer.h"`, new slots/members |
| `Peer2Pear_QtProj/databasemanager.cpp` | Modified — `msg_id` column added, `loadSetting` parameter rename |
| `Peer2Pear_QtProj/mainwindow.cpp` | Modified — `fileChunkReceived` signal wired, resize debounce, profile handle truncation |
| `Peer2Pear_QtProj/mainwindow.h` | Modified — `m_resizeDebounce` timer added |
| `Peer2Pear_QtProj/CMakeLists.txt` | Modified — `filetransfer.h` added to sources, macOS linker flags, deduplication |
| `Peer2Pear_QtProj/filetransfer.h` | **Missing** — referenced everywhere but never committed |
| `Peer2Pear_QtProj/chattypes.h` | Modified — `msgId` field added to `Message` struct |
