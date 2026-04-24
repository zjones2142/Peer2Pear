import Foundation
import LocalAuthentication
import Security

// BiometricUnlock — stores the user's passphrase in the iOS Keychain
// under a biometry-gated access control, and retrieves it via Face ID
// or Touch ID on subsequent launches.
//
// Security posture:
//   • Item class: kSecClassGenericPassword
//   • Accessibility: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
//     — never syncs to iCloud, disappears if device passcode is removed.
//   • Access control: .biometryCurrentSet
//     — re-enrolling a fingerprint/face OR adding a new face/finger
//     invalidates the stored item.  Users have to re-enable Face ID
//     unlock after any biometry change, which is the same guarantee
//     Apple's own apps (e.g., Wallet) give.
//   • Service: com.peer2pear.passphrase (unique to this app bundle).
//
// On a Secure Enclave device (everything A7+, which is every iOS device
// we support), the key protecting the Keychain item is generated in and
// never leaves the SEP.  The passphrase bytes themselves live in the
// regular Keychain blob — gated on SEP-backed biometric auth.
//
// Why not store the derived key directly?  The core derives + zeros
// the SQLCipher key on every unlock via Argon2id — keeping that key
// warm in Swift would sidestep the workfactor the passphrase gate is
// supposed to impose.  Re-running Argon2 on each launch is the trade
// for "same CPU cost whether you typed it or Face ID gave us the
// passphrase."  ~1.3 s either way.
enum BiometricUnlock {

    // Keychain coordinates.  Keep in sync with anything that clears
    // user data (logout, etc.).
    private static let service = "com.peer2pear.passphrase"
    private static let account = "primary"

    // UserDefaults flag — the user explicitly opted in.  We don't rely
    // solely on Keychain presence because a logout/reset path should
    // clear both in one place.
    private static let kEnabledKey = "p2p.biometricUnlockEnabled"

    /// Is biometric authentication available on this device right now?
    /// Returns false when biometry isn't enrolled, hardware is absent,
    /// or the user has revoked permission for this app.
    static var isAvailable: Bool {
        let ctx = LAContext()
        var err: NSError?
        return ctx.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &err)
    }

    /// Human-readable biometry kind for UI copy ("Face ID" / "Touch ID" /
    /// "Biometrics" on older-SDK builds or Optic ID when it lands).
    static var biometryName: String {
        let ctx = LAContext()
        var err: NSError?
        _ = ctx.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &err)
        switch ctx.biometryType {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return "Biometrics"
        @unknown default: return "Biometrics"
        }
    }

    /// Has the user opted in, and is a passphrase actually stored?
    /// Checks both halves: UserDefaults flag AND Keychain item presence.
    /// Drift cases where they disagree:
    ///   • iOS restores UserDefaults from iCloud backup but the
    ///     Keychain item (.biometryCurrentSet, ThisDeviceOnly) does
    ///     NOT restore — flag would say true, item missing.
    ///   • User re-enrolls Face ID — Keychain entry invalidates,
    ///     flag stays true.
    /// We treat "either half missing" as not enabled and fix up the
    /// flag, so the Onboarding "Unlock with Face ID" button stops
    /// offering itself when it would just fail.
    static var isEnabled: Bool {
        let flag = UserDefaults.standard.bool(forKey: kEnabledKey)
        if !flag { return false }
        if hasKeychainItem { return true }
        // Flag-said-yes but item is gone — reconcile.
        UserDefaults.standard.set(false, forKey: kEnabledKey)
        return false
    }

    /// Probe for the stored passphrase entry without prompting biometry.
    /// `errSecInteractionNotAllowed` means "exists but auth required",
    /// which is the normal happy state for our biometry-protected item;
    /// `errSecSuccess` would only happen if access control had no
    /// interaction requirement.  Anything else (notably errSecItemNotFound)
    /// signals the item is gone.
    private static var hasKeychainItem: Bool {
        let query: [String: Any] = [
            kSecClass as String:                kSecClassGenericPassword,
            kSecAttrService as String:          service,
            kSecAttrAccount as String:          account,
            kSecUseAuthenticationUI as String:  kSecUseAuthenticationUIFail,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Enable biometric unlock by storing the passphrase.  Called from
    /// Settings after the user confirms their passphrase (we can't
    /// reuse the one from onboarding because it's already zeroed in
    /// the core by the time Settings opens).
    ///
    /// Overwrites any existing entry.  Throws on hardware failure or
    /// user-declined biometry prompt.
    static func enable(passphrase: String) throws {
        guard let data = passphrase.data(using: .utf8) else {
            throw NSError(domain: "BiometricUnlock", code: -1,
                          userInfo: [NSLocalizedDescriptionKey:
                                      "Passphrase encoding failed"])
        }

        // Wipe any stale entry first so SecItemAdd doesn't error on
        // duplicate — simpler than Add-then-Update branching, and the
        // net effect is identical (atomic from the caller's view).
        _ = remove()

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                &accessError) else {
            if let e = accessError?.takeRetainedValue() {
                throw e
            }
            throw NSError(domain: "BiometricUnlock", code: -2,
                          userInfo: [NSLocalizedDescriptionKey:
                                      "Access control creation failed"])
        }

        let attrs: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        service,
            kSecAttrAccount as String:        account,
            kSecValueData as String:          data,
            kSecAttrAccessControl as String:  access,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        UserDefaults.standard.set(true, forKey: kEnabledKey)
    }

    /// Retrieve the stored passphrase, prompting the user for Face ID
    /// / Touch ID.  The completion fires on the main queue.  On cancel
    /// or failure returns nil — the caller falls back to the typed
    /// passphrase path.
    static func retrieve(reason: String,
                          completion: @escaping (String?) -> Void) {
        guard isEnabled else {
            completion(nil)
            return
        }

        // LAContext.evaluatePolicy below already surfaces the system
        // biometry prompt with `reason` as subtitle.  The Keychain
        // access-control flag then gates item retrieval on that same
        // evaluation — we don't need a separate SecItemCopyMatching
        // authentication context because evaluatePolicy's success
        // unlocks the biometry-protected Keychain items for the
        // following matching call.
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                            localizedReason: reason) { success, _ in
            guard success else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            let query: [String: Any] = [
                kSecClass as String:             kSecClassGenericPassword,
                kSecAttrService as String:       service,
                kSecAttrAccount as String:       account,
                kSecReturnData as String:        true,
                kSecMatchLimit as String:        kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: ctx,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            DispatchQueue.main.async {
                guard status == errSecSuccess,
                      let data = item as? Data,
                      let pass = String(data: data, encoding: .utf8) else {
                    completion(nil)
                    return
                }
                completion(pass)
            }
        }
    }

    /// Disable biometric unlock — remove the Keychain entry AND the
    /// UserDefaults flag so neither can vouch for the other.  Called
    /// from Settings toggle-off and from any logout/reset path.
    @discardableResult
    static func remove() -> Bool {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrService as String:  service,
            kSecAttrAccount as String:  account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        UserDefaults.standard.set(false, forKey: kEnabledKey)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
