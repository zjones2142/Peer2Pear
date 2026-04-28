#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QString>

class AppDataStore;

// Cross-platform settings migration — produces / consumes the
// `MigrationPayload.userDefaults` field.
//
// Wire shape: `{ <iosKey>: "<base64-of-{\"v\":<json-value>}>", ... }`
//
// iOS keys (`p2p.lastRelayUrl`, `p2p.autoLockMinutes`, etc.) are
// canonical on the wire — desktop translates iOS keys to/from
// its own `m_store` keys via the static map.  Each value is a
// JSON-wrapped {"v": <primitive>} object; the wrapper exists so
// QJsonDocument can parse top-level on every value (it doesn't
// support fragment-mode for bare primitives).  Bool / Int /
// String / [String] all round-trip cleanly across platforms.
//
// Allowlist + value-translation rules are codified in this file
// alongside the build/apply functions — adding a new migrated
// setting is a one-spot change.
namespace MigrationSettings {

/// Build the migrationPayload.userDefaults JSON object from the
/// device's local settings (m_store + the SettingsPanel cached
/// values).  Empty when nothing migrate-eligible is set; result
/// is JSON-shaped so it embeds directly as the `userDefaults`
/// field of the outer MigrationPayload struct.
QJsonObject buildSnapshotJson(const AppDataStore &store);

/// Apply a received userDefaults JSON object to local settings.
/// Filters by the same allowlist used during build; unknown
/// iOS-only keys are silently dropped.  Per-key failures are
/// non-fatal.
void applySnapshot(const QJsonObject &userDefaults,
                    AppDataStore &store);

}  // namespace MigrationSettings
