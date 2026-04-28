import Foundation

// UserDefaults snapshot for migration (Phase 4 backup-strategy
// step 2 / Tier 2 settings inventory).  Carries the durable user
// preferences that should travel to the new device — auto-lock
// minutes, privacy posture, file thresholds, screen-capture
// blocks, relay URLs, notification mode, etc.  Per-device
// counters (failed-unlock attempts) and runtime state stay
// behind by design.
//
// Wire format: `[String: Data]` keyed by UserDefaults key, each
// value is a JSON object of the form `{"v": <value>}` UTF-8
// bytes.  Cross-platform: desktop's QJsonDocument can parse a
// top-level JSON object on every value (it doesn't support
// fragment-mode parsing of bare primitives), so the wrapper
// keeps both platforms' parsers happy.  Native JSON types
// cover every UserDefaults value in our allowlist
// (Bool / Int / String / [String]).
//
// Defensive on apply: receiver only writes keys that match the
// curated allowlist below.  A malicious sender packing extra keys
// gets silently dropped.

enum MigrationSettings {

    /// UserDefaults keys that travel during migration.  Curated
    /// to match project_backup_strategy.md's settings inventory:
    /// durable user preferences yes; per-device counters no.
    ///
    /// Maintenance: when a new @AppStorage / UserDefaults key is
    /// added to Peer2PearClient (or a sibling like
    /// ScreenCapturePolicy), decide here whether it migrates.
    /// Defaults: anything user-configurable yes; anything device-
    /// or session-scoped no.
    static let migratedKeys: [String] = [
        // Relay configuration
        Peer2PearClient.kDefaultsRelayUrlKey,        // primary
        Peer2PearClient.kBackupRelayUrlsKey,         // user-added backups

        // Appearance + lock policy
        Peer2PearClient.kColorSchemeKey,
        Peer2PearClient.kAutoLockMinutesKey,
        Peer2PearClient.kWipeOnFailedAttemptsKey,
        Peer2PearClient.kLockModeKey,

        // File-transfer prefs
        Peer2PearClient.kFileAutoAcceptMBKey,
        Peer2PearClient.kFileHardMaxMBKey,
        Peer2PearClient.kFileRequireP2PKey,
        Peer2PearClient.kFileVerifiedOnlyKey,
        Peer2PearClient.kFileAutoAcceptWifiOnlyKey,

        // Privacy posture + transport dials
        Peer2PearClient.kPrivacyLevelKey,
        Peer2PearClient.kParallelFanOutKey,
        Peer2PearClient.kParallelFanOutKKey,
        Peer2PearClient.kMultiHopKey,

        // Trust + notification UX
        Peer2PearClient.kHardBlockOnKeyChangeKey,
        Peer2PearClient.kNotificationModeKey,

        // Screen-capture redaction toggles (defaults: login=on,
        // in-app=off — both worth migrating since the user may
        // have flipped them)
        ScreenCapturePolicy.blockOnLoginKey,
        ScreenCapturePolicy.blockInAppKey,

        // Intentionally NOT migrated:
        //   kFailedUnlockAttemptsKey — counter is reset to 0 on
        //                              every successful unlock
        //                              (resetFailedUnlockCounter
        //                              in OnboardingView's
        //                              success branch + start()'s
        //                              reset block).  At migration
        //                              time the source is by
        //                              definition unlocked, so
        //                              the value is always 0 —
        //                              same as the new device's
        //                              default.  No behavioural
        //                              difference; kept off the
        //                              allowlist for principle.
    ]

    /// Keys that have moved from UserDefaults to AppDataStore
    /// (project_ios_settings_storage.md).  `snapshot()` reads
    /// them via Peer2PearClient's @Published vars (the in-memory
    /// truth post-refactor); `apply()` writes them to
    /// UserDefaults transiently — `Peer2PearClient
    /// .loadAllSettingsFromDB` backfills to AppDataStore on
    /// the next `start()`, then clears UserDefaults.  Single
    /// list keeps snapshot + apply in lockstep with the
    /// settings refactor.
    private static let appDataStoreBackedKeys: Set<String> = [
        Peer2PearClient.kBackupRelayUrlsKey,
        Peer2PearClient.kAutoLockMinutesKey,
        Peer2PearClient.kLockModeKey,
        Peer2PearClient.kFileAutoAcceptMBKey,
        Peer2PearClient.kFileHardMaxMBKey,
        Peer2PearClient.kFileRequireP2PKey,
        Peer2PearClient.kFileVerifiedOnlyKey,
        Peer2PearClient.kFileAutoAcceptWifiOnlyKey,
        Peer2PearClient.kPrivacyLevelKey,
        Peer2PearClient.kParallelFanOutKey,
        Peer2PearClient.kParallelFanOutKKey,
        Peer2PearClient.kMultiHopKey,
        Peer2PearClient.kHardBlockOnKeyChangeKey,
        Peer2PearClient.kNotificationModeKey,
    ]

    /// Snapshot every allowlisted setting on the current device.
    /// Empty values are skipped — keeping the snapshot minimal
    /// so receivers default-init keys the user never touched on
    /// the source.  Reads from BOTH backings: AppDataStore for
    /// keys in `appDataStoreBackedKeys` (via the client's
    /// @Published vars), UserDefaults for the rest.
    static func snapshot(client: Peer2PearClient) -> [String: Data] {
        var out: [String: Data] = [:]
        let d = UserDefaults.standard
        for key in migratedKeys {
            let value: Any? =
                appDataStoreBackedKeys.contains(key)
                ? typedValue(forAppDataStoreKey: key, client: client)
                : d.object(forKey: key)
            guard let value else { continue }
            // Wrap in `{"v": <value>}` so the wire bytes are a
            // top-level JSON object — desktop's QJsonDocument
            // doesn't parse bare JSON fragments (true / 5 /
            // "abc") at the top level.  The wrapper is one
            // extra layer; round-trip cost is negligible.
            let wrapped: [String: Any] = ["v": value]
            do {
                let data = try JSONSerialization.data(
                    withJSONObject: wrapped,
                    options: [])
                out[key] = data
            } catch {
                // Skip the unencodable key — shouldn't happen
                // for the Bool / Int / String / [String] types
                // we ship; defensive against a future addition
                // that's not JSON-compatible.
                #if DEBUG
                print("[MigrationSettings] couldn't encode \(key): \(error)")
                #endif
            }
        }
        return out
    }

    /// Read an AppDataStore-backed setting via the client's
    /// @Published Swift-typed properties.  Returns nil if the
    /// value matches the hardcoded default (so we ship a
    /// minimal snapshot — receivers default-init untouched
    /// keys).  Skipping defaults is best-effort; an explicitly-
    /// set-to-default value DOES travel as the in-memory
    /// representation matches the default.
    private static func typedValue(forAppDataStoreKey key: String,
                                     client: Peer2PearClient) -> Any? {
        switch key {
        case Peer2PearClient.kBackupRelayUrlsKey:
            return client.backupRelayUrls.isEmpty ? nil : client.backupRelayUrls
        case Peer2PearClient.kAutoLockMinutesKey:
            return client.autoLockMinutes
        case Peer2PearClient.kLockModeKey:
            return client.lockMode.rawValue
        case Peer2PearClient.kFileAutoAcceptMBKey:
            return client.fileAutoAcceptMB
        case Peer2PearClient.kFileHardMaxMBKey:
            return client.fileHardMaxMB
        case Peer2PearClient.kFileRequireP2PKey:
            return client.fileRequireP2P
        case Peer2PearClient.kFileVerifiedOnlyKey:
            return client.fileRequireVerifiedContact
        case Peer2PearClient.kFileAutoAcceptWifiOnlyKey:
            return client.fileAutoAcceptWifiOnly
        case Peer2PearClient.kPrivacyLevelKey:
            return client.privacyLevel.rawValue
        case Peer2PearClient.kParallelFanOutKey:
            return client.parallelFanOutEnabled
        case Peer2PearClient.kParallelFanOutKKey:
            return client.parallelFanOutK
        case Peer2PearClient.kMultiHopKey:
            return client.multiHopEnabled
        case Peer2PearClient.kHardBlockOnKeyChangeKey:
            return client.hardBlockOnKeyChange
        case Peer2PearClient.kNotificationModeKey:
            return client.notificationContentMode.rawValue
        default:
            return nil
        }
    }

    /// Apply a snapshot to UserDefaults.  Filters by the
    /// allowlist on input — even if the wire payload contains
    /// extra keys (a malicious or buggy sender), only allowlisted
    /// ones get written.  Per-key apply failures are swallowed +
    /// logged in DEBUG; a single bad value doesn't stop the rest.
    ///
    /// All values land in UserDefaults regardless of whether
    /// they belong in AppDataStore long-term — `Peer2PearClient
    /// .loadAllSettingsFromDB` backfills the moved keys on the
    /// next `start()`, then clears them from UserDefaults.  The
    /// staged-via-UserDefaults pattern dodges a chicken-and-egg
    /// where apply runs before the C context (and thus
    /// AppDataStore) is open.
    static func apply(_ snapshot: [String: Data]) {
        let d = UserDefaults.standard
        let allowed = Set(migratedKeys)
        for (key, data) in snapshot {
            guard allowed.contains(key) else { continue }
            do {
                let obj = try JSONSerialization.jsonObject(
                    with: data, options: []) as? [String: Any]
                guard let value = obj?["v"] else { continue }
                d.set(value, forKey: key)
            } catch {
                #if DEBUG
                print("[MigrationSettings] couldn't apply \(key): \(error)")
                #endif
            }
        }
    }
}
