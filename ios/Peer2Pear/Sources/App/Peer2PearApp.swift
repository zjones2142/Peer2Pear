import SwiftUI
import UIKit
import UserNotifications

@main
struct Peer2PearApp: App {
    @UIApplicationDelegateAdaptor(Peer2PearAppDelegate.self) private var appDelegate
    @StateObject private var client = Peer2PearClient()

    // Drives the app-switcher snapshot overlay below.  iOS captures
    // a screenshot of the active scene when the app backgrounds, and
    // that snapshot is cached in the multitasker until next launch
    // — a fingerprintable forensic surface separate from the app's
    // sandbox.  By installing a brand placeholder when scenePhase
    // leaves .active, we keep conversation content out of that
    // cached image.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            Group {
                if client.myPeerId.isEmpty {
                    OnboardingView(client: client)
                } else {
                    // In-app screen-capture redaction: when the user
                    // has enabled the in-app block in Settings, this
                    // overlay covers ChatListView (and pushed
                    // navigation views) with an opaque placeholder
                    // while the screen is being recorded / mirrored.
                    // Sheets (Settings, MyKey, etc.) are presented
                    // outside the overlay's bounds and therefore not
                    // covered — acceptable since those are
                    // user-initiated and momentary.  See
                    // ScreenCaptureMonitor.swift for threat-model
                    // notes.
                    ChatListView(client: client)
                        .overlay { InAppCaptureRedaction() }
                        // Quick-unlock overlay — covers ChatListView
                        // when the session is locked but the C
                        // context is still alive (lockMode .quick or
                        // .quickWithEviction).  Strict mode never
                        // hits this branch because lock() clears
                        // myPeerId, sending us to OnboardingView
                        // above instead.
                        .overlay {
                            if client.isUILocked {
                                LockOverlay(client: client)
                            }
                        }
                }
            }
            // App-switcher snapshot overlay.  Wraps the entire
            // root content (both locked + unlocked branches) so
            // the cached snapshot iOS takes during backgrounding
            // shows the brand placeholder instead of the active
            // conversation.  Stacked OUTSIDE InAppCaptureRedaction
            // so it covers OnboardingView too — the lock screen
            // doesn't show conversation content but applying the
            // placeholder uniformly avoids "different overlay
            // behaviour depending on auth state" weirdness.
            .overlay {
                if scenePhase != .active {
                    SnapshotOverlay()
                }
            }
            .p2pColorScheme(client.colorScheme)
            .onAppear {
                // Give the AppDelegate a handle to the client so APNs
                // tokens + silent pushes can flow through to the
                // protocol layer.  `appDelegate` is valid by the time
                // the root view appears.
                appDelegate.attachClient(client)
            }
            .onChange(of: client.myPeerId) { _, newValue in
                // Defer the notification prompt until the user has
                // completed onboarding (identity created + relay
                // configured).  Prompting during the welcome screen
                // would surface before users know why they'd want it.
                if !newValue.isEmpty {
                    requestNotificationPermissionIfNeeded()
                }
            }
        }
    }

    /// Ask for notification permission and, on grant, register for
    /// remote notifications so APNs can issue us a device token.
    /// No-op if the user has already answered the prompt once.
    private func requestNotificationPermissionIfNeeded() {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
                    if granted {
                        DispatchQueue.main.async {
                            UIApplication.shared.registerForRemoteNotifications()
                        }
                    }
                }
            case .authorized, .provisional, .ephemeral:
                DispatchQueue.main.async {
                    UIApplication.shared.registerForRemoteNotifications()
                }
            case .denied:
                break  // User said no — don't re-prompt.
            @unknown default:
                break
            }
        }
    }

}

// Shared modifier for applying the user's appearance preference.
// `.preferredColorScheme` scoped to the root view tree does NOT
// propagate into sheets / fullScreenCovers — iOS treats those as
// separate presentation contexts.  Apply this modifier on the body
// of every sheet-hosted top-level view (SettingsView, MyKeyView,
// AddContactSheet, NewGroupSheet, etc.) so a live toggle in Settings
// redraws them immediately instead of only after a relaunch.
extension View {
    func p2pColorScheme(_ pref: Peer2PearClient.ColorSchemePreference) -> some View {
        preferredColorScheme(schemeFor(pref))
    }
}

private func schemeFor(_ pref: Peer2PearClient.ColorSchemePreference) -> ColorScheme? {
    switch pref {
    case .dark:   return .dark
    case .light:  return .light
    case .system: return nil
    }
}

// App-switcher snapshot overlay.  iOS caches a screenshot of the
// active scene in the multitasker UI when the app backgrounds; that
// cache survives until the next foreground launch and lives outside
// the app's sandbox (read by forensic tools with device access).
// Without this overlay the snapshot captures whatever the user was
// looking at — usually a conversation thread.
//
// We install the overlay whenever scenePhase != .active.  The
// snapshot fires on the .active → .inactive transition; SwiftUI
// re-renders fast enough that the placeholder is in place before
// the snapshot is taken in practice on iOS 17+.  If timing-
// sensitive cases arise, the next-step fix is a UIWindow-level
// overlay installed from `applicationWillResignActive` in the
// AppDelegate — heavier-weight but guarantees the ordering.
private struct SnapshotOverlay: View {
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 16) {
                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 80))
                    .foregroundStyle(.green)
                Text("Peer2Pear")
                    .font(.title.bold())
            }
        }
    }
}

// LockOverlay — quick-unlock screen shown when the user has locked
// the app but the underlying session is still alive (lockMode
// .quick or .quickWithEviction).  The .strict mode never reaches
// here because lock() empties myPeerId, routing the WindowGroup
// back to OnboardingView (full Argon2 re-derive on unlock).
//
// In .quickWithEviction (the default), the C context, ratchet
// state, and DB key all stay in RAM so silent push notifications
// can still decrypt incoming messages while the UI is locked —
// only the @Published plaintext mirrors are wiped.  Quick-unlock
// verifies via the in-memory SHA-256 verifier (~1ms) and rehydrates
// the mirrors from the still-open SQLCipher store.
//
// In .quick, even the mirrors stay — the lock is a pure UI overlay
// and the unlock just toggles isUILocked back to false.
//
// Wrong passphrase surfaces inline.  No failed-attempt counter is
// applied here because the verifier compare doesn't burn Argon2
// cycles — wipe-on-failed-attempts is reserved for the OnboardingView
// path which actually unlocks the SQLCipher key.  An attacker who
// already has process memory access has the keys directly anyway.
private struct LockOverlay: View {
    @ObservedObject var client: Peer2PearClient
    @State private var passphrase: String  = ""
    @State private var error:      String? = nil
    @FocusState private var fieldFocused:  Bool

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 24) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.green)

                Text("Peer2Pear is locked")
                    .font(.title2.bold())

                Text("Enter your passphrase to unlock.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                SecureField("Passphrase", text: $passphrase)
                    .textContentType(.password)
                    .submitLabel(.go)
                    .focused($fieldFocused)
                    .padding(12)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(10)
                    .padding(.horizontal, 32)
                    .onSubmit(submit)

                if let error {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }

                Button(action: submit) {
                    Text("Unlock")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(passphrase.isEmpty
                                    ? Color.gray.opacity(0.4)
                                    : Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                }
                .padding(.horizontal, 32)
                .disabled(passphrase.isEmpty)
            }
        }
        .task {
            // Auto-focus so the user can start typing immediately.
            // Run via .task so SwiftUI cancels the work if the
            // overlay disappears before focus settles (e.g. user
            // unlocks via biometric / external trigger), instead
            // of firing into a torn-down @FocusState binding.
            fieldFocused = true
        }
    }

    private func submit() {
        guard !passphrase.isEmpty else { return }
        let success = client.quickUnlock(passphrase: passphrase)
        if success {
            // Wipe local @State as soon as the verifier accepts —
            // no reason to keep the passphrase around in SwiftUI
            // state once isUILocked has flipped.
            passphrase = ""
            error      = nil
        } else {
            error = "Wrong passphrase."
            passphrase = ""
        }
    }
}

// In-app screen-capture redaction.  Renders an opaque placeholder
// when (a) the screen is being recorded / mirrored AND (b) the user
// has opted into in-app blocking in Settings (off by default — the
// post-unlock threat model is weaker than the login screen).
//
// Lives at the WindowGroup level so it covers ChatListView and any
// pushed NavigationStack views (ConversationView, ArchivedChatsView,
// etc.).  Sheets and full-screen covers present in their own
// presentation context and aren't covered — accepted limitation.
private struct InAppCaptureRedaction: View {
    @StateObject private var monitor = ScreenCaptureMonitor()

    @AppStorage(ScreenCapturePolicy.blockInAppKey)
    private var blockInApp: Bool = ScreenCapturePolicy.blockInAppDefault

    var body: some View {
        if monitor.isCaptured && blockInApp {
            ZStack {
                Color(.systemBackground)
                VStack(spacing: 12) {
                    Image(systemName: "eye.slash.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.orange)
                    Text("Screen capture detected")
                        .font(.headline)
                    Text("Stop screen recording or mirroring to view the app.  You can disable this in Settings → Screen Capture.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            }
            .ignoresSafeArea()
        }
    }
}
