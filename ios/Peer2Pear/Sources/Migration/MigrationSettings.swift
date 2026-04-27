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
// value is a binary plist of the original UserDefaults value.
// Plist round-trips Bool / Int / String / [String] / Data without
// type loss — same encoding UserDefaults uses internally, so no
// info gets dropped on the way through migration.
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

    /// Snapshot every allowlisted UserDefaults key on the current
    /// device.  Empty values are skipped — keeping the snapshot
    /// minimal so receivers default-init keys the user never
    /// touched on the source.
    static func snapshot() -> [String: Data] {
        var out: [String: Data] = [:]
        let d = UserDefaults.standard
        for key in migratedKeys {
            guard let value = d.object(forKey: key) else { continue }
            do {
                let data = try PropertyListSerialization.data(
                    fromPropertyList: value,
                    format: .binary,
                    options: 0)
                out[key] = data
            } catch {
                // Skip the unencodable key — shouldn't happen for
                // anything UserDefaults stored, but defensive
                // against a future plist-incompatible value.
                #if DEBUG
                print("[MigrationSettings] couldn't encode \(key): \(error)")
                #endif
            }
        }
        return out
    }

    /// Apply a snapshot to UserDefaults.  Filters by the
    /// allowlist on input — even if the wire payload contains
    /// extra keys (a malicious or buggy sender), only allowlisted
    /// ones get written.  Per-key apply failures are swallowed +
    /// logged in DEBUG; a single bad value doesn't stop the rest.
    static func apply(_ snapshot: [String: Data]) {
        let d = UserDefaults.standard
        let allowed = Set(migratedKeys)
        for (key, data) in snapshot {
            guard allowed.contains(key) else { continue }
            do {
                let value = try PropertyListSerialization.propertyList(
                    from: data, options: [], format: nil)
                d.set(value, forKey: key)
            } catch {
                #if DEBUG
                print("[MigrationSettings] couldn't apply \(key): \(error)")
                #endif
            }
        }
    }
}
