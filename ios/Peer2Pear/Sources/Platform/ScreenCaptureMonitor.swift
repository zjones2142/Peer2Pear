import SwiftUI
import UIKit

// Tracks whether the screen is currently being recorded or mirrored
// (AirPlay, QuickTime, AssistiveTouch screen-record, Sidecar, etc.).
//
// Purpose: gate sensitive input — the passphrase fields on
// OnboardingView — so screen-record-based capture can't sniff
// password length and timing.  Doesn't defeat external cameras or
// adversarial frame grabbers; that's out of scope.
//
// `isCaptured` is the live state.  Subscribers (SwiftUI views via
// @StateObject / @ObservedObject) re-render when it flips.  Backed
// by UIScreen.capturedDidChangeNotification + UIScreen.main.isCaptured
// — both stable since iOS 13.
final class ScreenCaptureMonitor: ObservableObject {
    @Published private(set) var isCaptured: Bool

    private var observer: NSObjectProtocol?

    init() {
        self.isCaptured = UIScreen.main.isCaptured
        self.observer = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            // Re-read from the source of truth instead of trusting
            // any payload on the notification — the notification
            // fires for both directions (capture started / stopped).
            self?.isCaptured = UIScreen.main.isCaptured
        }
    }

    deinit {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
    }
}

// User-configurable policy for what we do when capture is active.
//
// Two scopes:
//   - Login / Onboarding: default ON.  Passphrase entry is the
//     highest-leverage moment to leak — typing dots have visible
//     length + timing, and the field is on screen for a while.
//   - In-app (post-unlock): default OFF.  Plaintext messages,
//     contacts, files all become visible once unlocked, and the
//     user generally knows when they're recording.  Opt-in for
//     users who want the extra friction.
//
// iOS has no true "block" — the OS captures regardless of what
// the app does.  What we CAN do is detect capture (via
// ScreenCaptureMonitor) and replace sensitive UI with a redacted
// view, so the captured frames carry no plaintext.  Doesn't help
// against external cameras or jailbroken-device frame grabbers.
enum ScreenCapturePolicy {
    // Public so SwiftUI sites can pass them to @AppStorage and stay
    // in sync with non-SwiftUI readers below.  Keep these as the
    // single source of truth for the UserDefault key strings.
    static let blockOnLoginKey = "p2p.blockScreenCaptureOnLogin"
    static let blockOnLoginDefault = true

    static let blockInAppKey = "p2p.blockScreenCaptureInApp"
    static let blockInAppDefault = false

    // Convenience static accessors for non-SwiftUI call sites (none
    // today, kept for future use).  SwiftUI views should prefer
    // @AppStorage(ScreenCapturePolicy.blockOnLoginKey) for live
    // reactivity when the user toggles the setting.
    //
    // Default-true semantics: UserDefaults.bool returns false for
    // missing keys, so we have to detect absence explicitly to
    // avoid silently flipping new installs to "off".
    static var blockOnLogin: Bool {
        get {
            let d = UserDefaults.standard
            if d.object(forKey: blockOnLoginKey) == nil { return blockOnLoginDefault }
            return d.bool(forKey: blockOnLoginKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: blockOnLoginKey) }
    }

    static var blockInApp: Bool {
        get {
            let d = UserDefaults.standard
            if d.object(forKey: blockInAppKey) == nil { return blockInAppDefault }
            return d.bool(forKey: blockInAppKey)
        }
        set { UserDefaults.standard.set(newValue, forKey: blockInAppKey) }
    }
}
