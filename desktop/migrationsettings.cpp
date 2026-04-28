#include "migrationsettings.h"
#include "AppDataStore.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>

#include <cstdint>

namespace MigrationSettings {

namespace {

// ── Wire helpers ─────────────────────────────────────────────────────────────

/// Build the per-value JSON wrapper bytes for the wire — `{"v":
/// <value>}` UTF-8.  Base64 of these bytes lands in the
/// userDefaults dict's value slot.
QByteArray wrapValue(const QJsonValue &v)
{
    QJsonObject o;
    o.insert("v", v);
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

/// Inverse of `wrapValue` — extract `v` from a per-key wire blob.
/// Returns Undefined on malformed input.
QJsonValue unwrapValue(const QByteArray &raw)
{
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        return QJsonValue::Undefined;
    }
    return doc.object().value("v");
}

/// Encode a single setting into the userDefaults wire dict —
/// JSON-wrap, base64-encode, store under the iOS key.
void putSetting(QJsonObject &out, const char *iosKey,
                 const QJsonValue &value)
{
    out.insert(QString::fromLatin1(iosKey),
                QString::fromLatin1(wrapValue(value).toBase64()));
}

/// Decode a single setting from the userDefaults wire dict.
/// Returns Undefined if the key is absent or malformed.
QJsonValue getSetting(const QJsonObject &in, const char *iosKey)
{
    const QString s = in.value(QString::fromLatin1(iosKey)).toString();
    if (s.isEmpty()) return QJsonValue::Undefined;
    return unwrapValue(QByteArray::fromBase64(s.toLatin1()));
}

// ── Local-storage adapters ───────────────────────────────────────────────────
// Read / write desktop's m_store.  iOS-side keys are canonical on
// the wire (p2p.* prefix); desktop's m_store uses unprefixed
// keys ("autoLockMinutes" etc.).  The translation lives in the
// build / apply tables below.

bool loadIntSetting(const AppDataStore &store, const std::string &key,
                     int defaultValue, int &out)
{
    const std::string raw = store.loadSetting(key, std::to_string(defaultValue));
    try { out = std::stoi(raw); return true; }
    catch (...) { return false; }
}

bool loadBoolSetting(const AppDataStore &store, const std::string &key,
                      bool &out)
{
    const std::string raw = store.loadSetting(key, "");
    if (raw == "true")  { out = true;  return true; }
    if (raw == "false") { out = false; return true; }
    return false;
}

}  // anonymous namespace

// ── Build (desktop is sender) ────────────────────────────────────────────────

QJsonObject buildSnapshotJson(const AppDataStore &store)
{
    QJsonObject out;

    // Strings
    {
        const std::string raw = store.loadSetting("relayUrl", "");
        if (!raw.empty()) {
            putSetting(out, "p2p.lastRelayUrl",
                        QString::fromStdString(raw));
        }
    }
    {
        const std::string raw = store.loadSetting("lockMode", "");
        if (!raw.empty()) {
            putSetting(out, "p2p.lockMode",
                        QString::fromStdString(raw));
        }
    }
    {
        const std::string raw = store.loadSetting("themePreference", "");
        if (!raw.empty()) {
            // iOS uses "system" / "light" / "dark"; desktop's
            // ThemeManager string aligns by convention.
            putSetting(out, "p2p.colorScheme",
                        QString::fromStdString(raw));
        }
    }
    {
        const std::string raw = store.loadSetting("notificationMode", "");
        if (!raw.empty()) {
            // iOS values: "hidden" / "sender" / "full" — match
            // desktop SettingsPanel::NotificationMode raw.
            putSetting(out, "p2p.notificationMode",
                        QString::fromStdString(raw));
        }
    }

    // Ints
    int v = 0;
    if (loadIntSetting(store, "autoLockMinutes", 5, v)) {
        putSetting(out, "p2p.autoLockMinutes", v);
    }
    if (loadIntSetting(store, "privacyLevel", 0, v)) {
        putSetting(out, "p2p.privacyLevel", v);
    }
    if (loadIntSetting(store, "fileAutoAcceptMaxMB", 100, v)) {
        // iOS calls this kFileAutoAcceptMBKey ("p2p.fileAutoAcceptMB").
        putSetting(out, "p2p.fileAutoAcceptMB", v);
    }
    if (loadIntSetting(store, "fileHardMaxMB", 100, v)) {
        putSetting(out, "p2p.fileHardMaxMB", v);
    }

    // Bools
    bool b = false;
    if (loadBoolSetting(store, "fileRequireP2P", b)) {
        putSetting(out, "p2p.fileRequireP2P", b);
    }
    if (loadBoolSetting(store, "fileRequireVerified", b)) {
        // iOS's `kFileVerifiedOnlyKey` = "p2p.fileVerifiedOnly".
        putSetting(out, "p2p.fileVerifiedOnly", b);
    }
    if (loadBoolSetting(store, "hardBlockOnKeyChange", b)) {
        putSetting(out, "p2p.hardBlockOnKeyChange", b);
    }
    if (loadBoolSetting(store, "parallelFanOutEnabled", b)) {
        putSetting(out, "p2p.parallelFanOut", b);
    }
    if (loadBoolSetting(store, "multiHopEnabled", b)) {
        putSetting(out, "p2p.multiHop", b);
    }

    // Backup relay URLs — array of strings.  Desktop persists as a
    // newline-joined string under `backupRelayUrls`; split for
    // wire emission to match iOS's [String] shape.
    {
        const std::string raw = store.loadSetting("backupRelayUrls", "");
        if (!raw.empty()) {
            QJsonArray arr;
            const QString joined = QString::fromStdString(raw);
            for (const QString &line : joined.split('\n', Qt::SkipEmptyParts)) {
                const QString trimmed = line.trimmed();
                if (!trimmed.isEmpty()) arr.append(trimmed);
            }
            if (!arr.isEmpty()) {
                putSetting(out, "p2p.backupRelayUrls", arr);
            }
        }
    }

    return out;
}

// ── Apply (desktop is receiver) ──────────────────────────────────────────────

void applySnapshot(const QJsonObject &userDefaults,
                    AppDataStore &store)
{
    auto saveString = [&](const char *iosKey, const std::string &storeKey) {
        const QJsonValue v = getSetting(userDefaults, iosKey);
        if (v.isString()) {
            store.saveSetting(storeKey, v.toString().toStdString());
        }
    };
    auto saveInt = [&](const char *iosKey, const std::string &storeKey) {
        const QJsonValue v = getSetting(userDefaults, iosKey);
        // iOS sends Int as JSON number (no quotes).  QJsonValue's
        // double accessor handles the integer-via-double round-trip
        // for values up to 2^53 — well past any plausible setting.
        if (v.isDouble()) {
            store.saveSetting(storeKey,
                std::to_string(static_cast<int64_t>(v.toDouble())));
        }
    };
    auto saveBool = [&](const char *iosKey, const std::string &storeKey) {
        const QJsonValue v = getSetting(userDefaults, iosKey);
        if (v.isBool()) {
            store.saveSetting(storeKey, v.toBool() ? "true" : "false");
        }
    };

    // Strings
    saveString("p2p.lastRelayUrl",     "relayUrl");
    saveString("p2p.lockMode",          "lockMode");
    saveString("p2p.colorScheme",       "themePreference");
    saveString("p2p.notificationMode",  "notificationMode");

    // Ints
    saveInt("p2p.autoLockMinutes",       "autoLockMinutes");
    saveInt("p2p.privacyLevel",          "privacyLevel");
    saveInt("p2p.fileAutoAcceptMB",      "fileAutoAcceptMaxMB");
    saveInt("p2p.fileHardMaxMB",         "fileHardMaxMB");

    // Bools
    saveBool("p2p.fileRequireP2P",       "fileRequireP2P");
    saveBool("p2p.fileVerifiedOnly",     "fileRequireVerified");
    saveBool("p2p.hardBlockOnKeyChange", "hardBlockOnKeyChange");
    saveBool("p2p.parallelFanOut",       "parallelFanOutEnabled");
    saveBool("p2p.multiHop",             "multiHopEnabled");

    // Backup relay URLs — JSON array of strings → newline-joined
    // string under desktop's `backupRelayUrls` storage convention.
    {
        const QJsonValue v = getSetting(userDefaults, "p2p.backupRelayUrls");
        if (v.isArray()) {
            QStringList lines;
            for (const QJsonValue &entry : v.toArray()) {
                const QString s = entry.toString().trimmed();
                if (!s.isEmpty()) lines.append(s);
            }
            if (!lines.isEmpty()) {
                store.saveSetting("backupRelayUrls",
                                   lines.join('\n').toStdString());
            }
        }
    }

    // iOS-only keys (NSLocalNetworkUsage / screen-capture toggles
    // / file-WiFi-only / parallel-fan-out-K / wipe-on-failed) are
    // intentionally not handled — they're either iOS-platform
    // primitives without desktop analogues, or features desktop
    // doesn't surface in its Settings panel yet.  Adding new
    // entries is a one-spot edit in the build + apply tables
    // above.
}

}  // namespace MigrationSettings
