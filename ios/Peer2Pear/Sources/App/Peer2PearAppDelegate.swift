import UIKit
import UserNotifications

// AppDelegate bridge for SwiftUI — handles the three things SwiftUI's
// App protocol doesn't expose:
//
//   1. APNs device-token capture (UIApplication.didRegisterForRemoteNotifications)
//   2. Silent-push handling (application(_:didReceiveRemoteNotification:...))
//   3. Foreground-notification presentation policy (UNNotificationCenter delegate)
//
// The delegate forwards all three into a shared `Peer2PearClient`, which
// owns the actual protocol state.  The client is provided by the main
// App struct via `attachClient(_:)` so the AppDelegate never races the
// SwiftUI lifecycle — any event that arrives before the client is
// attached is buffered (see pendingDeviceToken).
final class Peer2PearAppDelegate: NSObject, UIApplicationDelegate,
                                     UNUserNotificationCenterDelegate {
    weak var client: Peer2PearClient?

    // If APNs delivers a token before the SwiftUI App has constructed
    // the client, stash it and forward once attached.  Rare, but
    // tracked so we don't lose a registration at first launch.
    private var pendingDeviceToken: Data?

    func attachClient(_ client: Peer2PearClient) {
        self.client = client
        if let token = pendingDeviceToken {
            pendingDeviceToken = nil
            forwardToken(token, to: client)
        }
    }

    // MARK: - App launch

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions:
                         [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Set ourselves as the notification-center delegate so we get
        // foreground-presentation callbacks.  Permission is requested
        // lazily when the user completes onboarding — we don't prompt
        // at first launch to keep the welcome screen clean.
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    // MARK: - APNs registration

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken
                         deviceToken: Data) {
        if let c = client {
            forwardToken(deviceToken, to: c)
        } else {
            pendingDeviceToken = deviceToken
        }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError
                         error: Error) {
        // Not fatal — the app still works on the foreground WebSocket
        // path.  Background delivery just won't be possible until the
        // next registration attempt succeeds.
        NSLog("[Peer2Pear] APNs registration failed: %@", error.localizedDescription)
    }

    // MARK: - Silent push (content-available)

    // Triggered by `aps: {content-available: 1}` payloads from the
    // relay.  We have up to ~30 seconds to fetch + process queued
    // envelopes before iOS freezes the app again.
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completion:
                         @escaping (UIBackgroundFetchResult) -> Void) {
        guard let client = client else {
            completion(.noData)
            return
        }
        client.handleBackgroundPush { hadNewData in
            completion(hadNewData ? .newData : .noData)
        }
    }

    // MARK: - Foreground notification policy

    // When a local notification fires while the app is foregrounded,
    // let it appear as a banner anyway — matches what users expect
    // from a messaging app.  Without this the OS suppresses it.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                  willPresent notification: UNNotification,
                                  withCompletionHandler completion:
                                      @escaping (UNNotificationPresentationOptions) -> Void) {
        completion([.banner, .sound, .badge])
    }

    // MARK: - Helpers

    private func forwardToken(_ token: Data, to client: Peer2PearClient) {
        // Encode as hex — matches the format servers conventionally
        // accept for APNs tokens.  Each byte is two hex chars.
        let hex = token.map { String(format: "%02x", $0) }.joined()
        client.setPushToken(hex, platform: "ios")
    }
}
