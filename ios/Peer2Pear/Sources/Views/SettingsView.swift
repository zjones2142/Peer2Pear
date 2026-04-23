import SwiftUI

// SettingsView — per-device preferences that don't belong on the My Key
// screen.  Split out of MyKeyView so users can find settings under a
// gear icon (expected iOS affordance) rather than buried behind
// "profile" / "my key" which suggests identity-sharing.
//
// Sections (top to bottom):
//   • Appearance — three-way dark/light/system picker.
//   • Unlock with Face ID / Touch ID — biometric opt-in.
//   • Notification content — hidden / sender / full privacy mode.
//   • Relay server — advanced, self-host / federation switch.
//
// Every section persists to either UserDefaults or the Keychain; no
// save button required.  The full rationale for each choice lives in
// the section structs below.
struct SettingsView: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    AppearanceSection(client: client)
                    BiometricUnlockSection(client: client)
                    NotificationPrivacySection(client: client)
                    PrivacyLevelSection(client: client)
                    TrustSection(client: client)
                    FileTransferSection(client: client)
                    RelayServersSection(client: client)
                    LockSection(client: client, dismiss: dismiss)
                }
                .padding(.horizontal)
                .padding(.vertical)
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        // Sheet hosts don't inherit the root WindowGroup's preferred
        // color scheme; re-apply here so flipping the Appearance picker
        // below repaints this very sheet without waiting for a relaunch.
        .p2pColorScheme(client.colorScheme)
    }
}

// Three-way appearance picker.  Default is Dark to match the
// desktop app's hardcoded palette — users who prefer the OS
// default can pick System; Light is a deliberate override.
private struct AppearanceSection: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "moon.circle")
                    .foregroundStyle(.green)
                Text("Appearance")
                    .font(.headline)
            }

            Picker("Appearance", selection: Binding(
                get: { client.colorScheme },
                set: { client.colorScheme = $0 }
            )) {
                Text("Dark").tag(Peer2PearClient.ColorSchemePreference.dark)
                Text("Light").tag(Peer2PearClient.ColorSchemePreference.light)
                Text("System").tag(Peer2PearClient.ColorSchemePreference.system)
            }
            .pickerStyle(.segmented)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}

// Biometric-unlock opt-in.  When enabled, the user's passphrase is
// stored in the iOS Keychain under a `.biometryCurrentSet` access
// control — Face ID / Touch ID success releases the passphrase to
// Swift, which hands it to p2p_set_passphrase_v2 as if the user had
// typed it.  Re-enrolling biometry invalidates the entry (Apple's own
// guarantee via .biometryCurrentSet).
//
// The toggle is only shown when hardware actually supports it.  On
// enable, we reuse the passphrase from the current unlock session
// (`client.lastUnlockPassphrase`) so the user doesn't have to re-type —
// one less friction step for a setting that's purely additive
// convenience.  The passphrase is then zeroed from memory.
private struct BiometricUnlockSection: View {
    @ObservedObject var client: Peer2PearClient
    @State private var enabled: Bool = BiometricUnlock.isEnabled
    @State private var errorMessage: String = ""

    var body: some View {
        if BiometricUnlock.isAvailable {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: BiometricUnlock.biometryName
                          .contains("Face") ? "faceid" : "touchid")
                        .foregroundStyle(.green)
                    Text("Unlock with \(BiometricUnlock.biometryName)")
                        .font(.headline)
                }

                Toggle(isOn: $enabled) {
                    Text(enabled
                         ? "Enabled"
                         : "Use \(BiometricUnlock.biometryName) instead of typing your passphrase on launch.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .tint(.green)
                .onChange(of: enabled) { _, newValue in
                    if newValue {
                        guard let pass = client.consumeUnlockPassphrase() else {
                            errorMessage = "Please re-launch the app and unlock, then enable Face ID right after."
                            enabled = false
                            return
                        }
                        do {
                            try BiometricUnlock.enable(passphrase: pass)
                            errorMessage = ""
                        } catch {
                            errorMessage = error.localizedDescription
                            enabled = false
                        }
                    } else {
                        BiometricUnlock.remove()
                        errorMessage = ""
                    }
                }

                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                Text("Passphrase stays on this device, sealed to your biometry. Re-enrolling \(BiometricUnlock.biometryName) disables this automatically.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(12)
            .background(Color(.secondarySystemBackground))
            .cornerRadius(10)
        }
    }
}

// Notification-content privacy picker.  Default is "hidden" — the OS
// only sees a generic "New message" banner.  Users who value richer
// banners over the residual forensic leak can opt up.
//
// Background: iOS writes every delivered notification payload into a
// system-level store (backboardd / NotificationCenter DB).  That
// store is NOT inside the app's sandbox; it survives app deletion
// and is readable by forensic tools that have device access.  Even
// if the app scrubs its own on-disk state, notification text that
// once hit the banner can be recovered.  Hiding the content at the
// UNMutableNotificationContent level keeps plaintext out of that
// store entirely.
private struct NotificationPrivacySection: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "bell.badge")
                    .foregroundStyle(.green)
                Text("Notification content")
                    .font(.headline)
            }

            Picker("Content", selection: Binding(
                get: { client.notificationContentMode },
                set: { client.notificationContentMode = $0 }
            )) {
                Text("Hidden").tag(Peer2PearClient.NotificationContentMode.hidden)
                Text("Sender").tag(Peer2PearClient.NotificationContentMode.senderOnly)
                Text("Full").tag(Peer2PearClient.NotificationContentMode.full)
            }
            .pickerStyle(.segmented)

            Text(explanation(for: client.notificationContentMode))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private func explanation(for mode: Peer2PearClient.NotificationContentMode)
        -> String {
        switch mode {
        case .hidden:
            return "Banners show only \"New message\".  Message contents stay inside the encrypted app sandbox — the OS notification history sees nothing."
        case .senderOnly:
            return "Banners name the sender (or group).  The OS stores that identifier; message text stays private."
        case .full:
            return "Banners include the message text.  Convenient, but the OS retains the plaintext in its notification history, which forensic tools can read even after the message is deleted."
        }
    }
}

// Relay servers — advanced setting for users self-hosting a relay or
// switching federation.  Off the Onboarding screen because the vast
// majority of users will stay on the default, and asking about it
// up front is a cognitive-load tax for a decision that doesn't matter
// to them.  Primary URL applies on next app launch; changing the live
// WebSocket mid-session would need a reconnect orchestration we haven't
// built.  Backup relays populate the send pool used by Privacy=Maximum
// multi-hop forwarding — the core gates multi-hop on
// `m_sendRelays.size() >= 2`, so a single backup silently falls back
// to Enhanced-tier behavior; the footer copy makes that honest.
private struct RelayServersSection: View {
    @ObservedObject var client: Peer2PearClient
    @State private var url: String = Peer2PearClient.storedRelayUrl
    @State private var saved = false
    @State private var showAddSheet = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "server.rack")
                    .foregroundStyle(.green)
                Text("Relay Servers")
                    .font(.headline)
            }

            // ── Primary relay ───────────────────────────────────────
            Text("Primary")
                .font(.caption.bold())
                .foregroundStyle(.secondary)

            TextField("Relay URL", text: $url)
                .textFieldStyle(.roundedBorder)
                .autocapitalization(.none)
                .keyboardType(.URL)
                .onSubmit { save() }

            HStack {
                Button(saved ? "Saved" : "Save") { save() }
                    .buttonStyle(.bordered)
                    .disabled(url == Peer2PearClient.storedRelayUrl)
                Spacer()
                if url != Peer2PearClient.kDefaultRelayUrl {
                    Button("Reset to default") {
                        url = Peer2PearClient.kDefaultRelayUrl
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
            }

            Divider()

            // ── Backup relays ───────────────────────────────────────
            HStack {
                Text("Backup Relays")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    showAddSheet = true
                } label: {
                    Label("Add Relay", systemImage: "plus")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }

            if client.backupRelayUrls.isEmpty {
                Text("No backup relays configured.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(client.backupRelayUrls, id: \.self) { entry in
                    HStack(spacing: 8) {
                        Text(entry)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button(role: .destructive) {
                            client.removeBackupRelay(entry)
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }

            Text("Relays forward encrypted envelopes between peers; they never see message content.  Additional relays enable multi-hop forwarding when Privacy is set to Maximum.  Without backup relays, Maximum behaves like Enhanced.  Takes effect on next launch.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
        .sheet(isPresented: $showAddSheet) {
            AddBackupRelaySheet(client: client, isPresented: $showAddSheet)
        }
    }

    private func save() {
        UserDefaults.standard.set(url, forKey: Peer2PearClient.kDefaultsRelayUrlKey)
        saved = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { saved = false }
    }
}

// Modal for entering a new backup relay URL.  Validation happens in
// Peer2PearClient.addBackupRelay (trim + https/wss prefix + URL parse +
// dedupe); on failure we surface a single error line rather than branch
// the message per cause — the user only needs to know the URL didn't
// stick, and the example placeholder tells them the expected shape.
private struct AddBackupRelaySheet: View {
    @ObservedObject var client: Peer2PearClient
    @Binding var isPresented: Bool
    @State private var url: String = ""
    @State private var errorMessage: String = ""

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 14) {
                Text("Add a relay URL to use for multi-hop forwarding.  Must start with https:// or wss://.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                TextField("https://relay.example.com", text: $url)
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .keyboardType(.URL)
                    .textContentType(.URL)
                    .autocorrectionDisabled(true)

                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Add Backup Relay")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { isPresented = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        if client.addBackupRelay(url) {
                            isPresented = false
                        } else {
                            errorMessage = "Invalid or duplicate URL.  Must start with https:// or wss://."
                        }
                    }
                    .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}

// Privacy posture against the relay/network — mirrors desktop's
// three-tier picker (Standard / Enhanced / Maximum).  Each level
// strictly subsumes the one below; the descriptive text below the
// picker swaps to match the chosen tier so the user can see exactly
// what they're opting into without leaving Settings.
private struct PrivacyLevelSection: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "eye.slash.fill")
                    .foregroundStyle(.green)
                Text("Privacy")
                    .font(.headline)
            }

            Picker("Privacy", selection: Binding(
                get: { client.privacyLevel },
                set: { client.privacyLevel = $0 }
            )) {
                Text("Standard").tag(Peer2PearClient.PrivacyLevel.standard)
                Text("Enhanced").tag(Peer2PearClient.PrivacyLevel.enhanced)
                Text("Maximum").tag(Peer2PearClient.PrivacyLevel.maximum)
            }
            .pickerStyle(.segmented)

            // Per-level explainer.  Cumulative wording mirrors the
            // protocol's actual stacking: each tier adds defenses on
            // top of every lower tier, never replaces them.
            switch client.privacyLevel {
            case .standard:
                privacyDescription(
                    title: "Standard — baseline privacy.",
                    bullets: [
                        "Envelope size padding (hides message size from the relay)",
                        "Sealed sender (hides your identity from the relay)",
                        "End-to-end encryption (no operator can read content)",
                    ],
                    footer: "Recommended for most users.")
            case .enhanced:
                privacyDescription(
                    title: "Enhanced — adds traffic shaping.",
                    bullets: [
                        "Everything in Standard",
                        "Send jitter (randomized delays so timing patterns don't leak)",
                        "Cover traffic (decoy envelopes blend real activity into noise)",
                        "Multi-relay rotation (no single relay sees the full picture)",
                    ],
                    footer: "Higher latency, slightly more battery.")
            case .maximum:
                privacyDescription(
                    title: "Maximum — full anonymity posture.",
                    bullets: [
                        "Everything in Enhanced",
                        "Multi-hop forwarding (envelopes route through several relays)",
                        "High-frequency cover traffic (continuous decoys)",
                    ],
                    footer: "Slowest delivery + highest battery cost.  For high-risk users.")
                if client.backupRelayUrls.isEmpty {
                    Text("Add backup relays under Settings → Relay Servers to enable multi-hop.")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .padding(.top, 2)
                }
            }
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    @ViewBuilder
    private func privacyDescription(title: String,
                                     bullets: [String],
                                     footer: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption.bold())
            ForEach(bullets, id: \.self) { b in
                Text("• " + b)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Text(footer)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.top, 2)
        }
    }
}

// Trust & Verification — mirrors desktop's "Block contacts whose
// safety number changed" toggle.  The mismatch warning (orange triangle
// in ChatRow) still fires either way; this control just decides whether
// the core hard-blocks send/receive on top of the visual warning.
private struct TrustSection: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Text("Trust")
                    .font(.headline)
            }

            Toggle(isOn: Binding(
                get: { client.hardBlockOnKeyChange },
                set: { client.hardBlockOnKeyChange = $0 }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Block contacts whose safety number changed")
                        .font(.subheadline)
                    Text("Refuses to send to (or accept from) a previously-verified contact whose safety number no longer matches.  Default off — a mismatch shows a banner and you decide whether to continue.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(.green)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}

// Mirrors desktop's File Transfers section: two MB thresholds + the
// require-direct-connection toggle, plus two iOS-specific additions:
//   * Verified contacts only — silently declines files from peers whose
//     safety number hasn't been confirmed.
//   * Auto-accept on Wi-Fi only — overrides the auto-accept threshold
//     to 0 whenever the device is on cellular, so users never get
//     surprise data charges from a forgotten 100 MB threshold.
//
// All settings persist via UserDefaults and are re-applied on every
// unlock from Peer2PearClient.start(); didSet hooks push live changes
// to the core without a reconnect.
private struct FileTransferSection: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "externaldrive.badge.checkmark")
                    .foregroundStyle(.green)
                Text("File Transfers")
                    .font(.headline)
            }

            // ── Auto-accept threshold ───────────────────────────────
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Auto-accept files up to")
                        .font(.subheadline)
                    Spacer()
                    Stepper("\(client.fileAutoAcceptMB) MB",
                            value: Binding(
                                get: { client.fileAutoAcceptMB },
                                set: { client.fileAutoAcceptMB = max(0, $0) }),
                            in: 0...4096, step: 5)
                        .labelsHidden()
                    Text("\(client.fileAutoAcceptMB) MB")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 60, alignment: .trailing)
                }
                Text("Files at or below this size download without asking.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Divider()

            // ── Hard cap ────────────────────────────────────────────
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Never accept files larger than")
                        .font(.subheadline)
                    Spacer()
                    Stepper("\(client.fileHardMaxMB) MB",
                            value: Binding(
                                get: { client.fileHardMaxMB },
                                set: { client.fileHardMaxMB = max(1, $0) }),
                            in: 1...8192, step: 25)
                        .labelsHidden()
                    Text("\(client.fileHardMaxMB) MB")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 60, alignment: .trailing)
                }
                Text("Files above this size are declined automatically, no notification.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Divider()

            // ── Wi-Fi-only auto-accept ──────────────────────────────
            Toggle(isOn: Binding(
                get: { client.fileAutoAcceptWifiOnly },
                set: { client.fileAutoAcceptWifiOnly = $0 }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auto-accept on Wi-Fi only")
                        .font(.subheadline)
                    Text("Pauses auto-accept on cellular so large files don't surprise your data plan — you'll still see a prompt for each file.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(.green)
            if client.fileAutoAcceptWifiOnly && !client.onWifi {
                Label("On cellular — auto-accept paused.", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }

            Divider()

            // ── Direct-connection requirement ───────────────────────
            Toggle(isOn: Binding(
                get: { client.fileRequireP2P },
                set: { client.fileRequireP2P = $0 }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Require direct connection")
                        .font(.subheadline)
                    Text("Only accept files when a direct P2P connection is available.  Relayed files are refused.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(.green)

            Divider()

            // ── Verified-contacts gate ──────────────────────────────
            Toggle(isOn: Binding(
                get: { client.fileRequireVerifiedContact },
                set: { client.fileRequireVerifiedContact = $0 }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Only from verified contacts")
                        .font(.subheadline)
                    Text("Files from peers whose safety number you haven't confirmed are silently declined.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(.green)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}

// App Lock — bundle of session-security controls.
//
//   * Auto-Lock picker: minutes of background time before the app
//     auto-locks on next foreground.  0 = lock immediately on every
//     backgrounding (banking-app posture); -1 = never (rely on the
//     manual button only).
//   * Erase After 12 Failed Attempts: panic-wipe toggle.  Mirrors the
//     iOS native passcode "Erase Data" — after 12 consecutive failed
//     unlocks the entire app sandbox is removed.  Off by default.
//   * Lock Now: immediate manual lock, no confirmation (footer copy
//     already explains the consequence, and the action is non-
//     destructive — data lives on in the encrypted DB).
//
// Face ID toggle stays in its own BiometricUnlockSection above —
// that already has the hardware-availability + Keychain-enrolment
// state machine, no need to duplicate it here.
private struct LockSection: View {
    @ObservedObject var client: Peer2PearClient
    let dismiss: DismissAction

    /// Auto-lock options.  Encoded as the int we persist in
    /// UserDefaults — keep these in sync with `maybeAutoLock` in
    /// Peer2PearClient.
    private static let autoLockChoices: [(label: String, minutes: Int)] = [
        ("Immediately",    0),
        ("After 1 minute", 1),
        ("After 5 minutes", 5),
        ("After 15 minutes", 15),
        ("After 1 hour",   60),
        ("Never",          -1),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "lock.fill")
                    .foregroundStyle(.red)
                Text("App Lock")
                    .font(.headline)
            }

            // ── Auto-lock delay ─────────────────────────────────────
            VStack(alignment: .leading, spacing: 4) {
                Text("Auto-Lock")
                    .font(.subheadline)
                Picker("Auto-Lock", selection: Binding(
                    get: { client.autoLockMinutes },
                    set: { client.autoLockMinutes = $0 }
                )) {
                    ForEach(Self.autoLockChoices, id: \.minutes) { c in
                        Text(c.label).tag(c.minutes)
                    }
                }
                .pickerStyle(.menu)
                Text("Locks the app after this much time in the background.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Divider()

            // ── Wipe-on-failure ─────────────────────────────────────
            Toggle(isOn: Binding(
                get: { client.wipeOnFailedAttempts },
                set: { client.wipeOnFailedAttempts = $0 }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Erase After 12 Failed Attempts")
                        .font(.subheadline)
                    Text("Permanently deletes identity, contacts, messages, and saved files from this device.  No recovery.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(.red)
            if client.wipeOnFailedAttempts && client.failedUnlockAttempts > 0 {
                Text("\(client.failedUnlockAttempts) of \(Peer2PearClient.kFailedUnlockAttemptsThreshold) failed attempts so far.")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }

            Divider()

            // ── Manual lock ─────────────────────────────────────────
            Button(role: .destructive) {
                // Dismiss the sheet first so the parent's
                // `if myPeerId.isEmpty` swap to OnboardingView
                // happens against a fully-unwound presentation stack.
                dismiss()
                DispatchQueue.main.async { client.lock() }
            } label: {
                Label("Lock Now", systemImage: "lock.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)

            Text("Clears the unlocked session from memory.  Re-entering requires your passphrase \(BiometricUnlock.isEnabled ? "or \(BiometricUnlock.biometryName) " : "")— message history stays safely on disk in the encrypted database.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}
