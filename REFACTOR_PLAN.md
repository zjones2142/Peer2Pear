# Core Qt-Strip Refactor Plan

**Goal:** remove the `Qt::Core` dependency from `core/` so the protocol library
can be linked into iOS (SwiftUI + C++), Android (Kotlin + JNI), and any other
host without requiring Qt at build time.

**Status:** in progress. Started 2026-04-18.

---

## Why

Qt for iOS is a ~500 MB dev install, ~15 MB of runtime bloat per app, and
complicates App Store distribution (LGPL static-linking gray area). Qt for
Android is worse. Neither aligns with the project vision of "open source
protocol, multiple clients, implementable in a weekend" (see PROTOCOL.md §1).

Qt stays on **desktop**, where it runs the UI. Qt leaves **core**, where it
only ever served as a container + string + file-I/O library.

## Out-of-scope (deliberately)

- `desktop/` keeps Qt forever — it's a Qt Widgets app, that's fine.
- No full C++ rewrite. We're doing mechanical type substitution, not
  redesigning algorithms.
- No Swift rewrite of core — see the project vision note that we have
  6000+ lines of battle-tested crypto; we port it, we don't re-derive it.

## Ground rules

1. **Desktop builds must stay green after every subsystem migration.**
   Boundary adapters convert Qt ↔ std at the desktop/core seam for any
   partially-migrated calls.
2. **No behavior changes.** Mechanical substitution only. Don't refactor
   algorithms while swapping types. That way any bug found later is clearly
   a translation error, not a logic change.
3. **Test after each subsystem.** Keep the test cadence short so we catch
   regressions near their introduction.
4. **Boundary conversions are OK temporarily.** When a migrated function
   is called from not-yet-migrated code, a few lines of `std::string(qs.toStdString())`
   are acceptable. They disappear when the caller migrates.

## Substitution table

| Qt type / facility | Replacement | Notes |
|---|---|---|
| `QString` | `std::string` | UTF-8 throughout. At the desktop boundary use `QString::fromStdString()` / `.toStdString()`. |
| `QByteArray` | `std::vector<uint8_t>` | Some call sites may prefer `std::string` (binary is fine in C++17+). Pick per file, stay consistent within. |
| `QStringList` | `std::vector<std::string>` | |
| `QMap<K,V>`, `QHash<K,V>` | `std::map` / `std::unordered_map` | |
| `QList<T>`, `QVector<T>` | `std::vector<T>` | |
| `QSet<T>` | `std::set<T>` / `std::unordered_set<T>` | |
| `QBitArray` | `std::vector<bool>` | (compact, ok performance for our sizes) |
| `QFile`, `QDir`, `QFileInfo` | `std::filesystem` (C++17) + `std::fstream` | |
| `QIODevice`, `QDataStream`, `QBuffer` | `std::ostringstream` / `std::istringstream` + hand-rolled binary helpers | |
| `QDateTime` | `std::chrono::system_clock::time_point` | Store Unix-seconds int64 for persistence. |
| `QTimer` | `std::function` callback + platform-provided timer via `ITimer` interface | New abstraction; desktop provides a `QTimer` wrapper. |
| `QUuid` | `randombytes_buf(16)` + 36-char string formatter | Trivial helper. |
| `QJsonDocument`, `QJsonObject`, `QJsonArray` | `nlohmann::json` (vcpkg dep, already added) | |
| `QDebug` / `qWarning` | `std::cerr` lines gated by `PEER2PEAR_DEBUG` | Or a tiny log macro. |
| `QObject` + signals/slots | **Plain class with `std::function` callbacks** | Desktop wraps core objects in QObject shims that emit Qt signals when core callbacks fire. See §"Signals/slots pattern" below. |
| `QSqlDatabase`, `QSqlQuery`, `QVariant` | **Direct SQLCipher C API** (`sqlite3_*`) | QtSql is the biggest single replacement — it's currently how SqlCipherDb talks to the DB. Direct libsqlcipher is ~200 lines of boilerplate but lives in one file. |
| `QRandomGenerator` | `randombytes_buf` (libsodium, CSPRNG) | We already prefer libsodium elsewhere; unify. |
| `QUrl` | `std::string` + small URL parser for the one or two fields we need | The core really only reads URL host/port/path. Not worth a full URL library. |
| `QCryptographicHash` | libsodium's `crypto_generichash` / libsodium directly | Already the primary crypto path. |

## Signals/slots pattern

Core currently has three `QObject` subclasses that emit Qt signals:
`ChatController`, `FileTransferManager`, `RelayClient`. Desktop `connect()`s
to those signals.

The replacement pattern is:

```cpp
// Core (no Qt):
class ChatController {
public:
    using TextMessageCallback = std::function<
        void(const std::string& fromPeerId,
             const std::string& text,
             int64_t             unixSecs,
             const std::string& msgId)>;

    void setOnTextMessage(TextMessageCallback cb) {
        m_onText = std::move(cb);
    }
    // ...
private:
    TextMessageCallback m_onText;
    void fireText(...) { if (m_onText) m_onText(...); }
};
```

Desktop wires this once, per-callback, wrapping in a lambda that emits a
Qt signal:

```cpp
// desktop/mainwindow.cpp
m_controller.setOnTextMessage([this](const std::string& from,
                                      const std::string& text,
                                      int64_t ts,
                                      const std::string& id) {
    emit m_qtShim->textMessageReceived(
        QString::fromStdString(from),
        QString::fromStdString(text),
        QDateTime::fromSecsSinceEpoch(ts),
        QString::fromStdString(id));
});
```

`m_qtShim` is a small `QObject` owned by `MainWindow` that carries the Qt
signals. `ChatView` connects to `m_qtShim`'s signals just like before. The
difference is one layer of glue; the signal contracts don't change.

## Phase plan

Seven phases, each ~2–4 hours. Each phase ends with a clean desktop
build + smoke test.

### Phase 0 — infrastructure (~1 hr)
- [x] Move UI types (`chattypes.h`, `filetransfer.h`) from `core/` to `desktop/`
- [x] Add `nlohmann-json` to `vcpkg.json`, wire to `core` target
- [x] Migrate `OnionWrap` as proof of pattern
- [x] Write this plan

### Phase 1 — crypto + envelope primitives (~2 hr)
Files, smallest to largest:
- [x] `SealedEnvelope.hpp/cpp` — migrated. `Bytes = std::vector<uint8_t>`
      API. CryptoEngine calls go through temp Qt bridge internally.
- [x] `NoiseState.hpp/cpp` — migrated. `QDataStream` replaced by
      `binary_io.hpp` (`BinaryWriter`/`BinaryReader`, byte-compatible wire
      format). CryptoEngine calls still go through temp Qt bridge
      internally.
- [x] `RatchetSession.hpp/cpp` — migrated. `QDataStream` → `binary_io.hpp`,
      `QMap<QPair<QByteArray,quint32>, QByteArray>` → `std::map<std::pair<Bytes,uint32_t>, Bytes>`.
      CryptoEngine calls via temp bridge. All SessionManager call sites
      wrap via `p2p::bridge::toBytes`/`toQByteArray`.
- [x] `CryptoEngine.hpp/cpp` — **migrated**. All APIs speak `Bytes` /
      `std::string` now. `QJsonDocument` → `nlohmann::json`. `QFile`/
      `QDir`/`QStandardPaths` → `std::filesystem` + `std::fstream`.
      Platform data-dir default wrapped in `#ifdef QT_CORE_LIB` so
      desktop still gets `QStandardPaths::AppDataLocation` behavior;
      iOS/Android must call `setDataDir()`. All 9 callers updated via
      `p2p::bridge` helpers (new `strBytes` + `secureZeroQ` helpers
      added). Internal bridges in `NoiseState`/`RatchetSession`/
      `SealedEnvelope` removed — they now speak Bytes natively end-to-end.
- Boundary adapters added in callers via `core/qt_bridge_temp.hpp`
  (`p2p::bridge::toBytes` / `toQByteArray`). Callers touched so far:
  `ChatController.cpp` (5 sites), `RelayClient.cpp` (1 site),
  `SessionManager.cpp` (many sites for NoiseState calls).

### Phase 2 — session layer (~2 hr)
- [x] `RatchetSession.hpp/cpp` — migrated in Phase 1c
- [x] `SessionManager.hpp/cpp` — migrated. `QString` → `std::string`,
      `QByteArray` → `Bytes`, `QMap` → `std::map`, all wire format via
      raw `read_u32_be` / `write_u32_be` helpers (no `qToBigEndian`).
      Callback signature changed: `SendResponseFn` now takes
      `(const std::string&, const Bytes&)`. ChatController's lambda
      and 5 other call sites updated with bridge adapters.
- [ ] `SessionStore.hpp/cpp` — deferred to Phase 6 (tightly coupled to
      SqlCipherDb which also migrates in Phase 6).
- [x] **C API fix:** `p2p_create`'s `data_dir` argument was stored but
      never applied. Now wired to `CryptoEngine::setDataDir()` via a new
      `ChatController::setDataDir()` forwarder — required for iOS/Android
      where no platform default exists.

### Phase 3 — interfaces ✅
- [x] `IWebSocket.hpp` — std::string URL/text, Bytes binary frames.
- [x] `IHttpClient.hpp` — std::string URL + error, Bytes body,
      `std::map<std::string,std::string>` headers.
- [x] Desktop `QtWebSocket`, `QtHttpClient` — adapt std ↔ Qt at the
      adapter boundary.
- [x] `CWebSocket`, `CHttpClient` in peer2pear_api.cpp — already used
      std::string keys internally; dropped the QString/QByteArray
      conversions and now speak std types natively to the C FFI.
- [x] `RelayClient.cpp` — still on Qt (Phase 4); bridges Qt ↔ std at
      every `m_ws.*` and `m_http.*` call site.
- [ ] `ios/…/WebSocketAdapter.swift`, `HttpAdapter.swift` — already use C types, no change

### Phase 4 — relay + file transfer (~3–4 hr)
- [x] `RelayClient.hpp/cpp` — data types migrated. `QByteArray` → `Bytes`,
      `QString` → `std::string`, `QUrl` → `std::string` in API (QUrl kept
      inside `.cpp` for path/scheme manipulation via local helpers
      `urlWithPath`, `baseOf`, `wsUrl`, `hostPort`).  `QJsonDocument` →
      `nlohmann::json`, `QMap/QVector/QSet` → `std::map/vector/set`,
      `QRandomGenerator` → `randombytes_uniform`.  Signals now carry std
      types.  ChatController bridges Qt signals via lambda adapters at
      each `connect()`.
- [x] `FileTransferManager.hpp/cpp` — migrated. `QFile` → `std::fstream`
      with seek-read/seek-write; `QBitArray` → `std::vector<bool>`
      (blob format byte-compatible with prior rows); `QDateTime` →
      `int64_t` Unix secs (signals emit seconds; ChatController converts
      to `QDateTime` at the bridge seam); `QJsonDocument` →
      `nlohmann::json`; `QUuid` → libsodium `randombytes_buf` +
      hex formatter; `QStandardPaths::DownloadLocation` wrapped in
      `#ifdef QT_CORE_LIB`. SqlCipherDb calls still bridge Qt types
      since SqlCipherDb itself migrates in Phase 6. ChatController bridges
      ~15 callsites: signals via lambda adapters, methods via inline
      `.toStdString()` / `p2p::bridge::toBytes` wrappers, a new
      `toStdFileKeys()` helper converts the file-keys map.
- [ ] **Pending:** convert `QObject` subclasses to plain classes with
      `std::function` callbacks (Phase 7 when we drop Qt::Core).
- [ ] **Pending:** add small `ITimer` interface (Phase 7).

### Phase 5 — ChatController (DEFERRED → rolled into Phase 7)
- [ ] `ChatController.hpp/cpp` — the central orchestrator. Last to
      migrate because every other core piece plumbs through it.

**Decision (2026-04-18):** a data-type-only Phase 5 (QString → std::string
in signals/methods) would churn ~45 UI call sites without itself unblocking
iOS — the header keeps `#include <QObject>` because ChatController is a
QObject subclass, so Qt::Core stays on the link line regardless.  The
actual iOS unlock is the QObject strip in Phase 7, which rewrites
ChatController's API wholesale (signals → `std::function` callbacks).
Doing Phase 5 as data-only now would pay twice: once to migrate
signals, again to convert them to callbacks.

Phase 7 will bundle ChatController's data-type migration + QObject strip
in one pass, touching `mainwindow.cpp`, `chatview.cpp`, `peer2pear_api.cpp`
once instead of twice.

### Phase 6 — SqlCipherDb + SessionStore ✅
- [x] `SqlCipherDb.hpp/cpp` — public API now speaks `std::string` / `Bytes`.
      Typed `bindValue` overloads replace the old `QVariant`-based polymorphic
      bind; typed `valueText`/`valueInt64`/`valueBlob`/… column accessors
      replace `QVariant value()`.
- [x] `SessionStore.hpp/cpp` — migrated (was deferred in Phase 2). Public
      API takes `std::string` peer IDs and `Bytes` blobs.  `SessionManager`
      lost all the Qt bridges it was wrapping around SessionStore calls.
- [x] Already drops `Qt::Sql` from the build since we never depended on it;
      the new wrapper just talks to the sqlite3 C API (which SQLCipher
      replaces transparently).
- [x] Desktop `DatabaseManager` uses the new interface — added thin
      `#ifdef QT_CORE_LIB` shims on SqlCipherQuery so Qt-typed values
      (`QString`, `QByteArray`) still bind without updating ~70 call sites
      individually.  Shims compile out of iOS builds.
      `value(col)` returns a `QValue` wrapper with QVariant-style
      `.toString()` / `.toByteArray()` / `.toInt()` methods so existing
      read paths didn't need touching.  `lastErrorQ()` returns a QString
      for `qWarning() <<` compatibility.

### Phase 7 — QObject strip + final cleanup

**7a (DONE):**
- [x] `ITimer` + `ITimerFactory` abstraction in `core/ITimer.hpp`
- [x] `QtTimer` + `QtTimerFactory` impls in `desktop/QtTimer.hpp`
- [x] `RelayClient` stripped of `QObject` + `Q_OBJECT` — now a plain class.
      Signals (connected/disconnected/status/envelopeReceived/presenceChanged)
      replaced with 5 `std::function` callback members.  `QTimer` members
      replaced with `std::unique_ptr<ITimer>` and `QTimer::singleShot` uses
      go through `ITimerFactory::singleShot`.
- [x] `FileTransferManager` stripped of `QObject` — 9 signals → 9
      `std::function` callback members.
- [x] `ChatController` updated to USE the new callback API (assigns to
      `m_relay.onStatus`, `m_fileMgr.onTransferCompleted`, … — 13 call
      sites migrated).  Still a QObject itself — stripped in 7b.
- [x] `peer2pear_api.cpp` owns a `QtApiTimerFactory` (inline Qt-based
      impl) that feeds into the ChatController constructor.  iOS swaps
      this for a platform-callback-driven factory in Phase 8.
- [x] `mainwindow.cpp` / `.h` owns a `QtTimerFactory` member passed into
      the ChatController constructor.

**7b (DONE):**
- [x] `ChatController` is no longer a `QObject`.  All 15 signals converted
      to `std::function` callback members (`onStatus`, `onMessageReceived`,
      `onGroupMessageReceived`, `onFileChunkReceived`, `onFileAcceptRequested`,
      `onFileTransferCanceled`, `onFileTransferDelivered`,
      `onFileTransferBlocked`, `onPeerMayNeedUpgrade`, `onAvatarReceived`,
      `onGroupRenamed`, `onGroupAvatarReceived`, `onGroupMemberLeft`,
      `onPresenceChanged`, `onRelayConnected`).  Callback signatures kept
      Qt-typed (QString/QDateTime) to minimize desktop-UI churn; a follow-up
      swaps them for std types so `Qt::Core` can actually drop from
      core/CMakeLists.txt.
- [x] `peer2pear_api.cpp` — `wire_signals()` now uses direct callback
      assignment instead of `QObject::connect`.  Same Qt-typed lambdas.
- [x] `mainwindow.cpp` — 12 signal `connect()` calls → direct
      `m_controller.onXxx = [...]` assignments.  3 SettingsPanel wires to
      non-slot methods now bounce through small lambdas.
- [x] `chatview.cpp` — `connect(&ChatController::relayConnected, …)` → direct
      `m_controller->onRelayConnected = [...]` assignment.
- [x] `QTimer m_maintenanceTimer` replaced with `std::unique_ptr<ITimer>`;
      the 30s interval self-rearms via `scheduleMaintenance()` recursion.
- [x] QuicConnection signals (still Qt-based, desktop only) bind their
      lambdas to `conn` as receiver so lifetime tracks the connection
      rather than a QObject-less ChatController.

**7c (partial — logging swept from simpler files):**
- [x] `core/log.hpp` — `P2P_LOG` / `P2P_WARN` / `P2P_CRITICAL` macros
      over `std::cerr`.  Qt-free.
- [x] Logging swept in: `RatchetSession.cpp` (10 sites),
      `SessionStore.cpp` (4), `SessionManager.cpp` (28),
      `CryptoEngine.cpp` (22), `FileTransferManager.cpp` (24),
      `RelayClient.cpp` (6), `SqlCipherDb.cpp` (7).  ~100 call sites.
      `peerPrefix`/`idPrefix` helpers return `std::string` now instead
      of `QString`.  Residual `QString` usage in these files is gated
      behind `#ifdef QT_CORE_LIB` (desktop-only `QStandardPaths` paths).

**Still PENDING — actual iOS unlock.  See "Phase 7c resumption guide" below for
a concrete plan a cold session can execute without re-deriving the strategy.**

- [ ] **Migrate ChatController.cpp internals.**  ~170 `QString`, 64
      `QByteArray`, 42 `QJson*`, 20 `QDateTime`, 14 `QStringList`,
      11 `QUuid`, 3 each of `QMap`/`QSet`, 62 `qDebug`/`qWarning`.
      `QJson*` → `nlohmann::json`, `QString` → `std::string`,
      `QDateTime` → `int64_t`, `QUuid` → libsodium + hex formatter,
      `QMap<QString,…>` → `std::map<std::string,…>`.
- [ ] **Migrate ChatController callback signatures** from Qt types to
      std types (QString → std::string, QDateTime → int64_t,
      QStringList → std::vector<std::string>, QByteArray → Bytes).
- [ ] **UI cascade:** `mainwindow.cpp` / `chatview.cpp` / `peer2pear_api.cpp`
      each re-wrap at the callback-assignment seam with
      `QString::fromStdString`/etc and `QDateTime::fromSecsSinceEpoch`.
- [ ] **Simplify peer2pear_api.cpp** now that ChatController speaks std.
      ~74 Qt-type call sites collapse to direct std forwarding.
- [ ] **RelayClient.cpp URL helpers:** the four `QUrl`-based helpers
      (`urlWithPath`, `baseOf`, `wsUrl`, `hostPort`) replace with a
      tiny std-only URL parser in `core/url_util.hpp`.
- [ ] **Drop `Qt::Core`** from `core/CMakeLists.txt`.
- [ ] **Full smoke test:** text, file transfer, offline delivery, resumption.

### Phase 8 — iOS build (~2 hr)
- [ ] `build-ios.sh` no longer needs Qt for iOS — drop the QT_IOS_PREFIX
      requirement
- [ ] Add `xcodegen` project.yml
- [ ] Smoke-test iOS simulator build with the now-Qt-free core

**Total estimate:** 13–17 hours. Conservatively ~20.

---

## Phase 7c resumption guide

Written 2026-04-18 after the qDebug sweep landed.  A cold session can execute
this top-to-bottom without re-deriving the strategy.  Build after each step;
none of them should break the build if followed in order.

### State of the tree at checkpoint

- All core/ files Qt-free **except** `ChatController.{hpp,cpp}`, the Qt-interop
  blocks in `SqlCipherDb.hpp` (guarded by `#ifdef QT_CORE_LIB`), and the
  Qt-conversion helpers in `qt_bridge_temp.hpp` (guarded the same way).
- `peer2pear_api.cpp` still carries Qt-typed lambdas because it wraps
  ChatController's Qt-typed callback signatures.
- Desktop UI (`mainwindow.cpp`, `chatview.cpp`) assigns Qt-typed lambdas to
  ChatController's callback members.

### Remaining Qt surface in ChatController (exact counts)

| Symbol | hpp | cpp | Notes |
|---|---:|---:|---|
| `QString` | 97 | 170 | Peer IDs, file names, transfer IDs, text bodies, group IDs — everywhere |
| `QByteArray` | 12 | 64 | Sealed envelopes, AEAD blobs, file hashes, fileKeys, avatar bytes |
| `QDateTime` | 5 | 20 | Message timestamps in signals/callbacks + `currentSecsSinceEpoch()` internal |
| `QStringList` | 14 | 14 | Group member lists, `m_selfKeys`, various |
| `QJsonObject` | 3 | 24 | Incoming/outgoing JSON control messages (file_accept, group_msg, etc.) |
| `QJsonDocument` | 0 | 12 | Serialize/parse JSON control messages |
| `QJsonArray` | 0 | 6 | Member key lists inside group messages |
| `QMap` | 15 | 3 | `m_fileKeys`, `m_peerKemPubs`, `m_pendingIncomingFiles`, `m_groupSeqOut`, … |
| `QSet` | 5 | 3 | `m_seenIds`, `m_kemPubAnnounced`, `m_groupBootstrapNeeded`, `m_groupMembers[gid]` values, `m_selfKeys` |
| `QUuid` | 0 | 11 | `QUuid::createUuid().toString(QUuid::WithoutBraces)` for msgIds + transferIds |
| `QUrl` | 2 | 1 | `setRelayUrl(const QUrl&)` + one internal use |
| `qDebug`/`qWarning` | 0 | 62 | Logging |

Total: ~650 Qt touches across the two files.

### Recommended sequence

The golden rule: **each step must leave the build green** so a mid-session
interruption is recoverable.

**Step 1 — qDebug sweep inside ChatController.cpp (~62 sites, 15 min). ✅ DONE.**
Pattern matches the other 7 files already done.  Python regex replacement
from the prior session:

```python
import re
path = "ChatController.cpp"
with open(path) as f: text = f.read()
text = text.replace('#include <QDebug>', '#include "log.hpp"', 1)
text = re.sub(
    r'#ifndef QT_NO_DEBUG_OUTPUT\n(\s+(?:qDebug|qWarning|qCritical)\(\) <<[^;]+;)\n#endif',
    r'\1', text, flags=re.MULTILINE)
def repl(m):
    kind, body, semi = m.group(1), m.group(2), m.group(3)
    body = re.sub(r'QString::fromStdString\(([^()]+)\)', r'\1', body)
    macro = {'qDebug':'P2P_LOG','qWarning':'P2P_WARN','qCritical':'P2P_CRITICAL'}[kind]
    return f'{macro}({body}){semi}'
text = re.sub(r'(qDebug|qWarning|qCritical)\(\)\s*<<\s*([^;]+?)(;)',
              repl, text, flags=re.DOTALL)
with open(path, 'w') as f: f.write(text)
```

Build green after — qDebug → P2P_LOG is safe because the message contents
(QString instances etc.) don't have ostream operators yet, which will be
caught by the compiler.  Fix those inline.  Most will be
`QString::fromStdString(x)` wrappers the regex already stripped.

Landed inline fixes across two categories:
1. `.left(n)` on std::string → `.substr(0, n)` (for `transferId`, `fromPeerId`,
   `pr.transferId`, `pr.peerId` which are already std::string)
2. QString inside a stream expression → `.toStdString()` (and the
   `someQString.left(8) + "..."` idiom split into two stream operands —
   `<< someQString.left(8).toStdString() << "..."`)

**Step 2 — JSON: `QJsonObject/Array/Document` → `nlohmann::json` (~45 min, careful). ✅ DONE.**
This is the highest-risk piece because it touches every incoming-message
code path.  Work bottom-up from the smallest emitters.

Core substitutions (cheat sheet):

| Qt | nlohmann::json |
|---|---|
| `QJsonObject o;` | `json o = json::object();` |
| `o["k"] = "v";` | same |
| `o["k"].toString()` | `o.value("k", std::string())` |
| `o["k"].toInt(-1)` | `o.value("k", -1)` |
| `o["k"].toVariant().toLongLong()` | `o.value("k", int64_t(0))` |
| `o["k"].toBool()` | `o.value("k", false)` |
| `o["k"].toArray()` | `o["k"]` (iterate) |
| `o.contains("k")` | same |
| `QJsonDocument(o).toJson(Compact)` | `o.dump()` (returns `std::string`) |
| `QJsonDocument::fromJson(ba).object()` | `json::parse(std::string(ba.begin(), ba.end()))` |
| `QJsonArray a;  a.append(x);` | `json a = json::array(); a.push_back(x);` |

Group message member list pattern:
```cpp
// old
QJsonArray arr;
for (const QString& k : memberKeys) arr.append(k);
obj["members"] = arr;

// new
json arr = json::array();
for (const std::string& k : memberKeys) arr.push_back(k);
obj["members"] = std::move(arr);
```

Parsing member list back out:
```cpp
// old
QStringList keys;
for (const QJsonValue& v : obj.value("members").toArray())
    keys << v.toString();

// new
std::vector<std::string> keys;
for (const auto& v : obj.value("members", json::array()))
    if (v.is_string()) keys.push_back(v.get<std::string>());
```

**Step 3 — QUuid → libsodium helper (~5 min). ✅ DONE.**  Created `core/uuid.hpp`
with header-only `p2p::makeUuid()` (RFC 4122 v4 via `randombytes_buf`) and
swapped all 10 `QUuid::createUuid().toString(...)` sites in ChatController.cpp.
FTM still has its anonymous-namespace copy (kept to minimize blast radius).

**Step 4 — internal QMap/QSet/QStringList → std (~30 min). ✅ DONE (build green).**
Converted these member declarations in ChatController.hpp:

- `m_seenIds`, `m_groupBootstrapNeeded`, `m_kemPubAnnounced` → `std::set<std::string>`
- `m_seenOrder`, `m_selfKeys` → `std::vector<std::string>`
- `m_p2pConnections` → `std::map<std::string, QuicConnection*>`
- `m_p2pCreatedSecs`, `m_handshakeFailCount`, `m_envelopeCount` → `std::map<std::string, int|int64_t>`
- `m_peerKemPubs`, `m_fileKeys` → `std::map<std::string, Bytes>`
- `m_groupMembers` → `std::map<std::string, std::set<std::string>>`
- `m_pendingIncomingFiles` → `std::map<std::string, PendingIncoming>`, and PendingIncoming struct fields migrated to std::string/Bytes/int64_t.
- `lookupPeerKemPub` return type QByteArray → Bytes.

Left as-is (exposed via public accessors — defer to Step 7):
- `m_groupSeqOut`, `m_groupSeqIn` stay `QMap<QString, qint64>`.

Cleanup bonus: removed the `toStdFileKeys` bridge helper — m_fileKeys now has the
exact shape FTM expects, so callers pass `m_fileKeys` directly.

Original plan notes (for reference):

- `QMap<QString, QByteArray> m_fileKeys` → `std::map<std::string, Bytes>`.
  Iteration is `for (const auto& [k,v] : m)` — different from `it.key()/it.value()`.
- `QMap<QString, QSet<QString>> m_groupMembers` →
  `std::map<std::string, std::set<std::string>>`.
- `QSet<QString>::contains(x)` → `s.count(x)` or `s.find(x) != s.end()`.
- `QStringList peerIds` → `std::vector<std::string> peerIds`; `.join('|')`
  has no std equivalent — write a tiny helper or inline a loop with a
  separator flag.
- `QVector<QString> m_seenOrder` → `std::vector<std::string>`.

**Step 5 — internal QByteArray → Bytes + QString → std::string (~60 min).**
Largest surface but mostly mechanical once the containers are fixed.  Be
careful with the AEAD / seal / unseal paths that still take `QByteArray` via
`qt_bridge_temp.hpp` — `toBytes`/`toQByteArray` calls should vanish once the
source types are already `Bytes`.

Known patterns:

- `peerIdB64u.toStdString()` → just `peerIdB64u` once it's already std::string.
- `QByteArray ct(data, len)` → `Bytes ct(data, data + len)`.
- `ba.left(n)` → `Bytes(ba.begin(), ba.begin() + n)`.
- `ba.mid(off, n)` → helper `slice(ba, off, n)` or inline.
- `qstring.split('|')` → std::stringstream with getline.

**Step 6 — QDateTime → int64_t (~15 min). ✅ DONE.**  `qint64` → `int64_t`,
`QDateTime::currentSecsSinceEpoch()` → `nowSecs()` helper using
`std::chrono::system_clock`, `tsFromSecs()` helper deleted.  Callbacks now
receive `int64_t tsSecs` directly; the Qt UI converts at the boundary via
`QDateTime::fromSecsSinceEpoch`.

**Step 5 / 7 / 8 / 9 / 10 / 11 — coordinated cascade ✅ DONE.**

Public surface (ChatController.hpp) migrated from Qt to std types:
- `QString` → `std::string`
- `QStringList` → `std::vector<std::string>`
- `QByteArray` → `Bytes`
- `QUrl` → `std::string`
- `QDateTime` → `int64_t` (unix-epoch seconds)
- `QMap<QString, qint64>` (seq counters) → `std::map<std::string, int64_t>`

ChatController.cpp internals fully converted: all 259 Qt-type uses gone.
Removed `qt_bridge_temp.hpp` for SealedEnvelope interop (already std-typed),
kept it only for QuicConnection's QByteArray-signal interop.  Replaced
`QFileInfo` with `std::filesystem`, `QString::trimmed()` with a local
`trimmed()` helper, `QByteArray::startsWith/mid` with `bytesStartsWith` and
direct iterator slicing on `Bytes`.

peer2pear_api.cpp callback adapters now speak std types directly — UTF8
roundtrips dropped, just `c_str()` at the FFI boundary.

UI cascade landed clean:
- `mainwindow.cpp` — boundary lambdas convert std → Qt with three local helpers
  (`toQ`, `toQL`, `toDT`).  All 17 callback wirings updated.
- `chatview.cpp` — added a top-of-file `qListToStd` helper; ~20 boundary
  conversions sprinkled at controller call sites (`.toStdString()` going in,
  `QString::fromStdString(...)` coming out).
- Group sequence counter persistence uses local `qMapToStd`/`stdToQ` helpers in
  mainwindow.cpp (DatabaseManager API unchanged).

Build (full clean rebuild, 25 ninja targets) — green.

**Step 12 — drop Qt::Core from core/CMakeLists.txt — ✅ DONE.**
`Qt::Core` is now conditional on a new CMake option `WITH_QT_CORE` (default
ON, so desktop is unaffected).  Two paths:

- **Desktop (`WITH_QT_CORE=ON`, default):** `core/` pulls Qt::Core in for
  ChatController's QuicConnection bridge and CryptoEngine/FTM's
  `QStandardPaths` convenience shims.  Existing builds unchanged.
- **Mobile (`WITH_QT_CORE=OFF`, `PEER2PEAR_P2P=OFF`):** `core/` links zero
  Qt libraries.  The `#ifdef QT_CORE_LIB` gates in CryptoEngine.cpp,
  FileTransferManager.cpp, qt_bridge_temp.hpp, and SqlCipherDb.hpp all
  compile out; the Qt-free `StdTimerFactory` handles internal timing.

Supporting changes to get here:
- New `core/bytes_util.hpp` with Qt-free `strBytes` (moved out of
  `qt_bridge_temp.hpp`).  Header-only, pure std, shared by core files.
- Swapped `QtApiTimer`/`QtApiTimerFactory` in `peer2pear_api.cpp` for
  `StdTimer`/`StdTimerFactory` using `std::thread` + `std::condition_variable`.
  Documented threading caveat (callbacks fire on worker thread; host is
  responsible for marshaling).
- Replaced `QUrl` helpers in `RelayClient.cpp` with a 30-line `parseUrl` +
  `buildUrl` pair.
- Swept 4× `qint64` → `int64_t` in `FileTransferManager.cpp`.
- Removed dead `toBytes`/`toQByteArray` `using` declarations from
  `SessionManager.cpp`.
- Gated `ChatController.cpp`'s `qt_bridge_temp.hpp` include on `QT_CORE_LIB`.

Verification:
- `build/` (desktop, WITH_QT_CORE=ON, PEER2PEAR_P2P=ON) — full clean rebuild, 25 targets green.
- `build-mobile/` (WITH_QT_CORE=OFF, PEER2PEAR_P2P=OFF) — full clean
  peer2pear-core rebuild, 15 translation units → `libpeer2pear-core.a`.
  `nm` confirms zero Qt symbols.

**Step 7 — ChatController.hpp public surface (~30 min).**
Once the .cpp is std-native, migrate the header:

1. Public methods: `sendText(const QString&, const QString&)` →
   `sendText(const std::string&, const std::string&)`.  Repeat for every
   method taking QString/QByteArray/QStringList.
2. Callback signatures: 15 `std::function<void(..., const QString& ...)>` →
   `std::function<void(..., const std::string& ...)>`.
3. Member variables: `QMap<QString, ...>` → `std::map<std::string, ...>`.
4. Signals → all removed already (Phase 7b), so this is just the function
   objects and member types.
5. Remove the `#include <QString>` / `<QByteArray>` / `<QDateTime>` etc.
   block at top — ChatController.hpp should no longer need Qt headers.

**Step 8 — UI cascade (~30 min).**
At the callback-assignment seam, wrap with converters.  There are 13 sites
in `mainwindow.cpp`, 1 in `chatview.cpp`, and 12 in `peer2pear_api.cpp`.
Example pattern — before:

```cpp
m_controller.onMessageReceived =
    [cv = m_chatView](const QString& from, const QString& text,
                      const QDateTime& ts, const QString& msgId) {
        cv->onIncomingMessage(from, text, ts, msgId);
    };
```

After (signatures now std, ChatView still Qt):

```cpp
m_controller.onMessageReceived =
    [cv = m_chatView](const std::string& from, const std::string& text,
                      int64_t tsSecs, const std::string& msgId) {
        cv->onIncomingMessage(
            QString::fromStdString(from),
            QString::fromStdString(text),
            QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime(),
            QString::fromStdString(msgId));
    };
```

Same template everywhere.  peer2pear_api.cpp's version becomes simpler
because the C FFI already wanted `const char*` — the `.toUtf8().constData()`
round-trips disappear.

**Step 9 — method signature cascade in mainwindow.cpp (~15 min).**
Calls like `m_controller.setRelayUrl(QUrl(url))` become
`m_controller.setRelayUrl(url.toStdString())`.  Same for `sendText`,
`sendFile`, `sendGroupFile`, `subscribePresence`, `checkPresence`,
`acceptFileTransfer`, `declineFileTransfer`, `cancelFileTransfer`,
`resetSession`, `setKnownGroupMembers`, `setGroupSeqCounters`,
`setSelfKeys`.

**Step 10 — `peer2pear_api.cpp` simplification (~20 min).**
Now that ChatController speaks std natively:

- `QString::fromUtf8(url).toStdString()` → just `url` (already `const char*`).
- The `CWebSocket`/`CHttpClient` internal Qt bridging is already done (Phase 3).
- Drop the `QtApiTimerFactory` fallback to `QtApiTimerFactory` — wait, that's
  the one piece of Qt this file legitimately needs on desktop.  Keep it
  under `#ifdef QT_CORE_LIB`; iOS provides an alternative via platform
  callbacks (deferred to Phase 8).

**Step 11 — `RelayClient.cpp` URL helpers (~20 min).**
The four `QUrl` helpers (`urlWithPath`, `baseOf`, `wsUrl`, `hostPort`) need
a pure-std replacement.  Write `core/url_util.hpp` with a tiny parser:
scheme split on `://`, host/port/path tokenize from there.  Only needs to
handle the URLs our relay actually serves (ws/wss/http/https), not the
full RFC 3986 surface.

**Step 12 — drop `Qt::Core` from `core/CMakeLists.txt` (~2 min).**
```diff
  target_link_libraries(peer2pear-core PUBLIC
-     Qt${QT_VERSION_MAJOR}::Core
      unofficial-sodium::sodium
      OQS::oqs
      nlohmann_json::nlohmann_json
      ${SQLCIPHER_TARGET}
  )
```

Also drop the "Qt::Core is on its way out" comment.

**Step 13 — full clean rebuild + smoke test (~10 min).**
```
cmake --build build --target clean
cmake --build build
```
Should complete without Qt::Core in the core/ link line.  Run the desktop
app against a dev relay:
- Text to self from a second client (round-trip).
- File transfer (small + > kLargeFileBytes).
- Kill + resume offline delivery path.
- Kill sender mid-stream to exercise file_cancel.
- Toggle Privacy Level 0/1/2 in settings — verify jitter + cover traffic.

### Total estimated effort

~3.5 hours of careful work.  The JSON step and the final cascade are the
highest-risk; everything else is bounded-mechanical.  Best done in one
sitting so context stays hot; worst case, stop at a step boundary where
the build is green.

## Running tally

| Phase | Status | Notes |
|---|---|---|
| 0 | ✅ | Infrastructure done |
| 1 | ✅ | OnionWrap + SealedEnvelope + NoiseState + RatchetSession + CryptoEngine migrated |
| 2 | ⏳ | SessionManager migrated. SessionStore deferred to Phase 6. |
| 3 | ✅ | IWebSocket + IHttpClient interfaces now speak std types |
| 4 | ✅ | RelayClient + FileTransferManager migrated |
| 5 | ⏸ | Deferred — bundled into Phase 7 (QObject strip) to avoid double churn |
| 6 | ✅ | SqlCipherDb + SessionStore migrated |
| 7a | ✅ | ITimer; RelayClient + FTM stripped of QObject; ChatController uses new callbacks |
| 7b | ✅ | ChatController stripped of QObject; 15 signals → callbacks; UI cascade done |
| 7c | ✅ | All 12 steps done.  log.hpp + qDebug sweep, JSON migration, QUuid → libsodium, internal QMap/QSet → std, ChatController public surface fully std-typed, peer2pear_api adapters + desktop UI cascade landed, and `Qt::Core` now conditional via `WITH_QT_CORE` option.  Mobile builds (`WITH_QT_CORE=OFF` + `PEER2PEAR_P2P=OFF`) produce a `libpeer2pear-core.a` with zero Qt symbols.  Desktop build unaffected. |
| 8 | ⏸ | iOS unblocks after Phase 7 |

## Migration progress (Qt-free core files)

1. `OnionWrap.{hpp,cpp}` ✅
2. `SealedEnvelope.{hpp,cpp}` ✅  (Bytes end-to-end — no internal Qt bridges)
3. `NoiseState.{hpp,cpp}` ✅  (Bytes end-to-end + binary_io.hpp wire format)
4. `RatchetSession.{hpp,cpp}` ✅  (Bytes end-to-end + std::map skipped keys)
5. `CryptoEngine.{hpp,cpp}` ✅  (Bytes + std::string + nlohmann::json + std::filesystem)
6. `SessionManager.{hpp,cpp}` ✅  (std::string peer IDs + std::map sessions/pendingCk)
7. `IWebSocket.hpp` ✅  (std::string URL + text, Bytes binary frames)
8. `IHttpClient.hpp` ✅  (std::string URL + error, Bytes body, std::map headers)
9. `RelayClient.{hpp,cpp}` ✅  (Bytes + std::string + nlohmann::json; QObject/QTimer retained for Phase 7)
10. `FileTransferManager.{hpp,cpp}` ✅  (Bytes + std::string + std::fstream + std::vector<bool>)
11. `SqlCipherDb.{hpp,cpp}` ✅  (typed bind/value overloads; no QVariant; Qt-interop shims behind #ifdef)
12. `SessionStore.{hpp,cpp}` ✅  (Bytes + std::string; tracks SqlCipherDb API)
13. `ITimer.hpp` ✅  (platform-abstract single-shot + restartable timers)
14. `RelayClient.{hpp,cpp}` ✅  **plain class now — no QObject/Q_OBJECT**; callbacks + ITimer
15. `FileTransferManager.{hpp,cpp}` ✅  **plain class now — no QObject/Q_OBJECT**; callbacks
16. `ChatController.{hpp,cpp}` ✅  **plain class now — no QObject/Q_OBJECT**; 15 signals → std::function callbacks. Signatures still Qt-typed pending Phase 7c.
17. `log.hpp` ✅  (P2P_LOG/P2P_WARN/P2P_CRITICAL macros, Qt-free)
18. `binary_io.hpp` ✅  (BinaryWriter/BinaryReader, QDataStream-compatible)

Files still on Qt (pending):
  `SessionStore` (Phase 6 w/ SqlCipherDb), `SqlCipherDb`, `RelayClient`,
  `FileTransferManager`, `ChatController`, `peer2pear_api`,
  `IWebSocket`, `IHttpClient`.

## Decision log

- **Why `std::vector<uint8_t>` over `std::string` for bytes?**
  C++17 allows embedded nulls in `std::string`, and libsodium accepts
  either via reinterpret_cast. But `std::vector<uint8_t>` makes intent
  unambiguous and avoids the "is this text or binary?" question when
  reading code. Accepting the slight extra verbosity.

- **Why `std::map` over `std::unordered_map` everywhere?**
  Default choice, ordered iteration is occasionally useful (e.g., session
  store), and our container sizes are small enough that hash overhead
  doesn't win. Specific hot paths can switch to `unordered_map` per file.

- **Why vendor nlohmann/json via vcpkg rather than drop-in single header?**
  Vcpkg already installs it automatically via the manifest. Drop-in
  would work too but duplicates what we already have infrastructure for.

- **Why keep signals/slots-like semantics via `std::function`?**
  ChatView and the C API both want "callback on event". `std::function`
  gives exactly that without a framework dep. Desktop re-wraps as Qt
  signals at the boundary so `QObject::connect` keeps working.

## Risks

- **Session/ratchet serialization format change.** `QDataStream` writes
  a specific byte layout (with a version marker + endianness). Swapping
  to hand-rolled binary risks changing the persisted session-blob format.
  Mitigation: we already clear stored ratchet sessions on format bumps
  (see `ratchet_v7_cleared`); bump to v8 and wipe once during migration.

- **QtSql replacement in SqlCipherDb is chunky.** Direct libsqlcipher
  means manually marshaling prepared-statement binds. Might find a
  thin C++ wrapper around sqlite3 to borrow. Mitigation: well-scoped
  file, can spend a whole session on it without blocking anything else.

- **Boundary adapters accumulate.** Every not-yet-migrated caller of
  a migrated function has a few lines of `.toStdString()` etc. These
  are visible, but they're clutter. Mitigation: track them; they all
  delete themselves in Phase 7.

## How to contribute / resume mid-refactor

- Pick the next unchecked item in the phase list.
- Migrate the file wholesale — both header and implementation.
- Update callers at the boundary (search: `grep -rn "OldClass::" desktop/ core/`).
- Run `cmake --build build` after. Green build = commit-worthy.
- Update the running tally in this file.
- If a callsite in `desktop/` needs a boundary adapter, add it inline
  — don't refactor the desktop side yet.

---

*Last updated: 2026-04-18 (start of refactor)*
