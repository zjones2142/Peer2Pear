import Foundation
import UIKit
import UserNotifications

// MARK: - Local notifications, push tokens, auto-lock, panic wipe
//
// Everything the app does with OS-level alerting and the "forget me"
// side of the session lifecycle.  Stored state (pendingPushToken,
// backgroundedAt, observers, @Published preferences) lives in the main
// file; the methods that operate on them live here.

extension Peer2PearClient {

    // MARK: - Push tokens

    /// Hand the APNs device token to the core, which forwards it to
    /// the relay over the authenticated WebSocket.  Safe to call
    /// before `start()` — the token is stashed and replayed once the
    /// core is live.  `token` is the hex-encoded bytes; empty
    /// unregisters the device.
    func setPushToken(_ token: String, platform: String) {
        pendingPushToken = (token, platform)
        forwardPushTokenIfConnected()
    }

    /// Invoked by the AppDelegate when a silent push arrives while the
    /// app is backgrounded.  iOS gives us ~30 s to fetch queued
    /// envelopes before freezing the app again.  Completion is called
    /// with `true` if we observed any new data during the wake.
    func handleBackgroundPush(completion: @escaping (Bool) -> Void) {
        guard let ctx = rawContext else {
            completion(false)
            return
        }
        let baseline = messages.count + groupMessages.count
        p2p_wake_for_push(ctx)

        // Poll for ~5 s: if a new message has landed by then, we
        // report newData.  Longer-running delivery after completion
        // still fires normal callbacks + local notifications — the
        // completion here just tells iOS whether the wake was useful
        // for background-refresh scheduling heuristics.
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            guard let self else { completion(false); return }
            let now = self.messages.count + self.groupMessages.count
            completion(now > baseline)
        }
    }

    func forwardPushTokenIfConnected() {
        guard let ctx = rawContext, let p = pendingPushToken else { return }
        p2p_set_push_token(ctx, p.token, p.platform)
        // Leave `pendingPushToken` set — RelayClient replays it on
        // every reconnect already, and re-sending on a warm WS is
        // idempotent at the relay level (upsert).
    }

    // MARK: - Local notification presentation

    /// Fire a local UNUserNotificationCenter banner for an inbound
    /// message, applying the user's content-privacy mode.  The OS
    /// decides whether to actually surface it — foreground banners
    /// go through Peer2PearAppDelegate's willPresent delegate method;
    /// backgrounded banners surface directly.
    ///
    /// The sender ID / message text passed here are always the
    /// decrypted, plaintext values; this function decides what
    /// fraction (if any) to hand to the OS notification store.
    /// Own-message check prevents double-notify when the sender
    /// receives their own fan-out on group sends.
    func fireLocalNotification(
        fromPeerId: String,
        senderDisplay: String,
        groupName: String?,
        messageText: String,
        threadId: String
    ) {
        if fromPeerId == myPeerId { return }

        let content = UNMutableNotificationContent()
        content.sound = .default
        content.threadIdentifier = threadId

        switch notificationContentMode {
        case .hidden:
            // Generic wake-up only — the OS notification DB learns
            // nothing about who or what.  User opens the app to see
            // the actual message, which lives only in our encrypted
            // SQLCipher AppDataStore.
            content.title = "Peer2Pear"
            content.body  = "New message"

        case .senderOnly:
            content.title = "Peer2Pear"
            if let group = groupName, !group.isEmpty {
                content.body = "New message in \(group)"
            } else {
                content.body = "New message from \(senderDisplay)"
            }

        case .full:
            if let group = groupName, !group.isEmpty {
                content.title = group
                content.subtitle = senderDisplay
            } else {
                content.title = senderDisplay
            }
            content.body = messageText.count > 140
                ? String(messageText.prefix(137)) + "…"
                : messageText
        }

        let req = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }

    // MARK: - Auto-lock on background→foreground

    /// Foreground hook: if the unlocked session has been backgrounded
    /// longer than `autoLockMinutes`, fire `lock()` so the user has to
    /// re-authenticate.  -1 = never, 0 = lock on every backgrounding,
    /// otherwise a minute threshold.  No-op when locked already.
    func maybeAutoLock() {
        guard let bgAt = backgroundedAt else { return }
        backgroundedAt = nil
        // Only relevant when we have a live unlocked session.
        guard rawContext != nil else { return }
        let mins = autoLockMinutes
        if mins < 0 { return }              // "Never"
        if mins == 0 { lock(); return }     // "Immediately"
        let elapsed = Date().timeIntervalSince(bgAt)
        if elapsed >= TimeInterval(mins) * 60 { lock() }
    }

    // MARK: - Panic wipe on repeated failed unlocks

    /// Bump the failed-attempt counter.  When the wipe-on-failure
    /// setting is on AND the counter crosses the threshold, nuke the
    /// entire app sandbox via `wipeAllData(documentDir:)`.  Returns
    /// true if a wipe fired so the caller (OnboardingView) can show
    /// the notice.
    @discardableResult
    func recordFailedUnlock(documentDir: String) -> Bool {
        let next = failedUnlockAttempts + 1
        UserDefaults.standard.set(next, forKey: Self.kFailedUnlockAttemptsKey)
        if wipeOnFailedAttempts, next >= Self.kFailedUnlockAttemptsThreshold {
            wipeAllData(documentDir: documentDir)
            return true
        }
        return false
    }

    /// Reset the failed-attempt counter — called after a successful
    /// unlock so a sequence like "wrong, wrong, right" doesn't keep
    /// the counter primed for a wipe on the next typo session.
    func resetFailedUnlockCounter() {
        UserDefaults.standard.set(0, forKey: Self.kFailedUnlockAttemptsKey)
    }
}
