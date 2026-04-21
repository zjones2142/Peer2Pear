import SwiftUI
import UIKit
import UserNotifications

@main
struct Peer2PearApp: App {
    @UIApplicationDelegateAdaptor(Peer2PearAppDelegate.self) private var appDelegate
    @StateObject private var client = Peer2PearClient()

    var body: some Scene {
        WindowGroup {
            Group {
                if client.myPeerId.isEmpty {
                    OnboardingView(client: client)
                } else {
                    ChatListView(client: client)
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
