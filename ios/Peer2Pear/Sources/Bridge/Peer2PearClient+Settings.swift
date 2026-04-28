import Foundation

// MARK: - Settings backed by AppDataStore (SQLCipher)
//
// iOS settings storage gap (project_ios_settings_storage.md):
// most user-configurable settings on iOS used to live in
// `UserDefaults` — plain plist on disk, NOT keyed off the user's
// Argon2id-derived passphrase.  This file consolidates the shift
// to `AppDataStore` (SQLCipher + per-field XChaCha20-Poly1305) for
// every setting that's only read POST-unlock.
//
// What stays in UserDefaults (and why):
//   * `p2p.lastRelayUrl` — `Peer2PearClient.start()` reads it
//     before the DB is open to know which relay to dial.
//   * `p2p.colorScheme` — initial app render runs before unlock;
//     reading from UserDefaults avoids a default-theme flash.
//   * `p2p.wipeOnFailedAttempts` — checked from
//     `recordFailedUnlock` BEFORE a successful unlock opens the
//     DB.  An attacker grinding the unlock screen would otherwise
//     disable this defense by virtue of the DB being closed.
//   * `p2p.blockScreenCaptureOnLogin` — the unlock screen's own
//     screen-capture redaction policy; pre-unlock by definition.
//   * `p2p.biometricUnlockEnabled` — the OnboardingView decides
//     whether to show "Unlock with Face ID" before the DB opens.
//   * `p2p.failedUnlockAttempts` — per-device counter; not
//     migrated; not sensitive.
//
// Each "moved" setting on `Peer2PearClient` follows the same
// pattern:
//   1. `@Published var foo: T = <hardcoded default>` — no
//      eager UserDefaults read at init.
//   2. `didSet { saveSettingIfReady(kFooKey, foo) }` — writes to
//      AppDataStore via the type-specific helper, gated on
//      `rawContext != nil && !loadingSettingsFromDB`.
//   3. Entry in `loadAllSettingsFromDB()` below — reads via
//      `dbLoadSetting` and assigns under the loadingFromDB
//      guard.
//
// The wire format Step 4c uses for migration is unchanged —
// `MigrationSettings.snapshot/apply` switches from
// `UserDefaults.standard` to `Peer2PearClient.dbLoadSetting` /
// `dbSaveSetting`, but the per-key string keys + JSON-wrapped
// values stay byte-identical to the desktop receiver's parser.

extension Peer2PearClient {

    // MARK: - Save helpers (type-aware wrappers around dbSaveSetting)

    /// Persist a string setting to `AppDataStore` if the C
    /// context is alive AND we're not currently inside the
    /// hydrate path.  `Peer2PearClient`'s settings @Published
    /// vars call this from their didSets.
    func saveSettingIfReady(_ key: String, _ value: String) {
        guard rawContext != nil           else { return }
        guard !loadingSettingsFromDB      else { return }
        _ = dbSaveSetting(key, value)
    }

    /// Int variant — stored as decimal-string.  std::to_string
    /// equivalent matches what desktop's m_store does, so wire-
    /// format round-trips between platforms via `MigrationSettings`.
    func saveSettingIfReady(_ key: String, _ value: Int) {
        saveSettingIfReady(key, String(value))
    }

    /// Bool variant — stored as `"true"` / `"false"` to match
    /// desktop's serialization convention.
    func saveSettingIfReady(_ key: String, _ value: Bool) {
        saveSettingIfReady(key, value ? "true" : "false")
    }

    /// String-array variant — stored as JSON-encoded text.
    /// Used for `backupRelayUrls`.  Desktop persists the same
    /// array as a newline-joined string (different convention
    /// per-platform; the wire format normalises to a JSON array
    /// at the migration boundary).
    func saveSettingIfReady(_ key: String, _ value: [String]) {
        guard let data = try? JSONEncoder().encode(value),
              let s = String(data: data, encoding: .utf8) else { return }
        saveSettingIfReady(key, s)
    }

    // MARK: - Load helpers (with one-shot UserDefaults backfill)
    //
    // Each helper checks AppDataStore first (the post-refactor
    // source-of-truth); if AppDataStore is empty for that key,
    // backfills from UserDefaults if a value is present there
    // (returning user with pre-refactor state, OR migration
    // receiver where MigrationSettings.apply wrote to
    // UserDefaults).  Backfill promotes the value to
    // AppDataStore + clears UserDefaults so the next read goes
    // straight to AppDataStore and UserDefaults stops carrying
    // the encrypted-elsewhere copy.

    /// Decode a string-array from the JSON-text stored by the
    /// `[String]` save helper above.  Backfills from
    /// UserDefaults's JSON-encoded-Data form (the pre-refactor
    /// shape used by `Peer2PearClient.kBackupRelayUrlsKey`).
    private func loadStringArray(_ key: String,
                                  default defaultValue: [String]) -> [String] {
        let raw = dbLoadSetting(key, default: "")
        if !raw.isEmpty,
           let data = raw.data(using: .utf8),
           let arr = try? JSONDecoder().decode([String].self, from: data) {
            return arr
        }
        // Backfill — UserDefaults stored this as Data containing
        // JSON-encoded [String].
        if let data = UserDefaults.standard.data(forKey: key),
           let arr = try? JSONDecoder().decode([String].self, from: data) {
            saveSettingIfReady(key, arr)
            UserDefaults.standard.removeObject(forKey: key)
            return arr
        }
        return defaultValue
    }

    private func loadInt(_ key: String, default defaultValue: Int) -> Int {
        let raw = dbLoadSetting(key, default: "")
        if let v = Int(raw), !raw.isEmpty {
            return v
        }
        if let v = UserDefaults.standard.object(forKey: key) as? Int {
            saveSettingIfReady(key, v)
            UserDefaults.standard.removeObject(forKey: key)
            return v
        }
        return defaultValue
    }

    private func loadBool(_ key: String, default defaultValue: Bool) -> Bool {
        let raw = dbLoadSetting(key, default: "")
        if raw == "true"  { return true  }
        if raw == "false" { return false }
        // Backfill — UserDefaults.bool returns false for missing
        // keys, so use object(forKey:) to detect absence vs.
        // explicit-false.
        if let v = UserDefaults.standard.object(forKey: key) as? Bool {
            saveSettingIfReady(key, v)
            UserDefaults.standard.removeObject(forKey: key)
            return v
        }
        return defaultValue
    }

    private func loadString(_ key: String, default defaultValue: String) -> String {
        let raw = dbLoadSetting(key, default: "")
        if !raw.isEmpty { return raw }
        if let v = UserDefaults.standard.string(forKey: key) {
            saveSettingIfReady(key, v)
            UserDefaults.standard.removeObject(forKey: key)
            return v
        }
        return defaultValue
    }

    // MARK: - Bulk hydrate (called from start() post-DB-open)

    /// Read every AppDataStore-backed setting and assign it to
    /// the matching @Published property.  The
    /// `loadingSettingsFromDB` flag bypasses each property's
    /// didSet write-back so the load path doesn't trigger a
    /// pointless save round-trip.
    ///
    /// Called from `Peer2PearClient.start()` AFTER the C context
    /// is alive + AFTER `loadStateFromDb()` rehydrates the chat
    /// mirrors, BEFORE the file/relay/controller config-apply
    /// calls (so they pick up migrated values rather than the
    /// hardcoded defaults).
    func loadAllSettingsFromDB() {
        guard rawContext != nil else { return }
        loadingSettingsFromDB = true
        defer { loadingSettingsFromDB = false }

        // ── Lock + auto-lock ────────────────────────────────
        autoLockMinutes = loadInt(Self.kAutoLockMinutesKey, default: 5)
        if let lm = LockMode(rawValue:
                loadString(Self.kLockModeKey,
                            default: LockMode.quickWithEviction.rawValue)) {
            lockMode = lm
        }

        // ── Notifications ───────────────────────────────────
        if let nm = NotificationContentMode(rawValue:
                loadString(Self.kNotificationModeKey,
                            default: NotificationContentMode.hidden.rawValue)) {
            notificationContentMode = nm
        }

        // ── File-transfer prefs ─────────────────────────────
        fileAutoAcceptMB        = loadInt (Self.kFileAutoAcceptMBKey,       default: 10)
        fileHardMaxMB           = loadInt (Self.kFileHardMaxMBKey,          default: 500)
        fileRequireP2P          = loadBool(Self.kFileRequireP2PKey,         default: false)
        fileRequireVerifiedContact
                                = loadBool(Self.kFileVerifiedOnlyKey,       default: false)
        fileAutoAcceptWifiOnly  = loadBool(Self.kFileAutoAcceptWifiOnlyKey, default: false)

        // ── Privacy posture ─────────────────────────────────
        // Load privacyLevel FIRST so its didSet's override of
        // parallelFanOutEnabled / multiHopEnabled fires before
        // we then apply the user's actual saved toggle values
        // — avoids a load-order clobber when the user has
        // explicitly set toggles inconsistent with the slider.
        if let pl = PrivacyLevel(rawValue:
                loadInt(Self.kPrivacyLevelKey, default: 0)) {
            privacyLevel = pl
        }
        parallelFanOutEnabled  = loadBool(Self.kParallelFanOutKey,  default: false)
        parallelFanOutK        = loadInt (Self.kParallelFanOutKKey, default: 2)
        multiHopEnabled        = loadBool(Self.kMultiHopKey,        default: false)
        hardBlockOnKeyChange   = loadBool(Self.kHardBlockOnKeyChangeKey,
                                            default: true)

        // ── Backup relays ───────────────────────────────────
        backupRelayUrls = loadStringArray(Self.kBackupRelayUrlsKey,
                                            default: [])

        // Screen-capture toggles intentionally stay UserDefaults-
        // backed: `blockScreenCaptureOnLogin` is read pre-unlock
        // (the OnboardingView's own redaction policy), and
        // `blockScreenCaptureInApp` lives behind @AppStorage in
        // SettingsView with no @Published mirror on the client —
        // a refactor to wire it through here would touch the view
        // layer without much privacy gain (the toggle is a Bool
        // saying "is privacy mode on", low forensic value).
    }
}
