import SwiftUI

// Matches P2P_MIN_PASSPHRASE_BYTES in peer2pear.h — the core rejects
// anything shorter at p2p_set_passphrase_v2 time with rc = -1.  Mirror
// the check in Swift so the user gets an inline hint instead of a
// silent no-op on the submit button.
private let kMinPassphraseLength = 8

struct OnboardingView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var passphrase = ""
    @State private var starting = false
    // Tracks whether we've already offered biometric unlock on appear.
    // Without this, a user who cancels Face ID would get re-prompted
    // every time a @State change re-evaluates the view body.
    @State private var biometricAutoAttempted = false

    // Computed once at view construction.  If the user creates an
    // identity, then later re-enters Onboarding after a crash, the
    // view is rebuilt — so we re-query the filesystem at that point.
    private let returning: Bool = Peer2PearClient.identityExists(
        documentDir: Peer2PearClient.documentsPath)

    // Biometric opt-in is only meaningful when (a) hardware supports
    // it, (b) the user enabled it in Settings, and (c) we have an
    // existing identity to unlock.  Computed once per view build so
    // the Face ID button appears consistently.
    private var biometricAvailable: Bool {
        returning && BiometricUnlock.isEnabled && BiometricUnlock.isAvailable
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()

                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.green)

                Text("Peer2Pear")
                    .font(.largeTitle.bold())

                Text(returning
                     ? "Welcome back.\nEnter your passphrase to unlock."
                     : "Private messaging.\nNo phone number. No servers you don't control.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                VStack(spacing: 16) {
                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(.roundedBorder)
                        .submitLabel(returning ? .go : .continue)
                        // Return inside the focused SecureField submits
                        // the form — the .keyboardShortcut on the button
                        // alone doesn't fire when the field is capturing
                        // the Return event first.
                        .onSubmit {
                            if passphraseAccepted && !starting { submit() }
                        }

                    // Inline guidance — caught by the same check as the
                    // button's .disabled binding, so what the user sees
                    // matches why the button can't be tapped.
                    Text(passphraseHint)
                        .font(.caption)
                        .foregroundStyle(passphraseAccepted
                                         ? Color.secondary
                                         : Color.orange)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 32)

                // Surface any status message from the core.  If
                // passphrase passes the local gate but Argon2 still
                // fails (e.g., identity file corrupt), the user sees
                // the reason instead of another silent no-op.
                if !client.statusMessage.isEmpty {
                    Text(client.statusMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                Button(action: submit) {
                    if starting {
                        HStack(spacing: 8) {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .tint(.white)
                            Text("Unlocking…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(returning ? "Unlock" : "Get Started")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .padding(.horizontal, 32)
                .disabled(!passphraseAccepted || starting)
                // Hardware-keyboard Return (and Enter from the software
                // "Go" key iOS promotes on submit-style fields) submits
                // the form — matches what users expect after typing the
                // passphrase and not wanting to reach for the button.
                .keyboardShortcut(.defaultAction)

                // Secondary biometric unlock button — only offered
                // when the user previously opted in (Settings).
                if biometricAvailable {
                    Button {
                        tryBiometric(auto: false)
                    } label: {
                        Label("Unlock with \(BiometricUnlock.biometryName)",
                              systemImage: BiometricUnlock.biometryName
                                .contains("Face") ? "faceid" : "touchid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.green)
                    .padding(.horizontal, 32)
                    .disabled(starting)
                }

                Spacer()
            }
            .padding()
            .onAppear {
                // One-shot biometric prompt on first appearance.  If
                // the user dismisses Face ID, we don't re-nag — they
                // can tap the explicit button or type their
                // passphrase.  Without the guard, every re-render
                // (e.g., keyboard showing) would pop the sheet again.
                if biometricAvailable && !biometricAutoAttempted {
                    biometricAutoAttempted = true
                    tryBiometric(auto: true)
                }
            }
        }
    }

    private func submit() {
        starting = true
        // Stash a copy of what the user typed for potential use by
        // the Settings biometric-enable flow.  Only kept if the
        // unlock succeeds; zeroed otherwise (see below).
        let typed = passphrase
        // Argon2id runs for ~1.3 s on typical hardware; kick it off
        // on a background queue so the button's spinner actually
        // renders.  The @Published myPeerId mutation inside start()
        // marshals back to main before Peer2PearApp's conditional
        // switches to ChatListView.
        DispatchQueue.global(qos: .userInitiated).async {
            client.start(dataDir: Peer2PearClient.documentsPath,
                          passphrase: typed,
                          relayUrl: Peer2PearClient.storedRelayUrl)
            DispatchQueue.main.async {
                // Expose the just-used passphrase to Settings so
                // "Enable Face ID" doesn't need to re-prompt.  Only
                // stored on successful unlock; if start() failed,
                // myPeerId is still empty and we don't cache it.
                if !client.myPeerId.isEmpty {
                    client.lastUnlockPassphrase = typed
                }
                starting = false
            }
        }
    }

    private func tryBiometric(auto: Bool) {
        let reason = "Unlock Peer2Pear"
        BiometricUnlock.retrieve(reason: reason) { pass in
            guard let pass, !pass.isEmpty else { return }
            starting = true
            DispatchQueue.global(qos: .userInitiated).async {
                client.start(dataDir: Peer2PearClient.documentsPath,
                              passphrase: pass,
                              relayUrl: Peer2PearClient.storedRelayUrl)
                DispatchQueue.main.async {
                    if !client.myPeerId.isEmpty {
                        client.lastUnlockPassphrase = pass
                    }
                    starting = false
                }
            }
        }
        // Suppress unused-parameter warning without changing the
        // signature; `auto` is there for future telemetry (distinguishing
        // on-appear from explicit button-tap unlocks if we ever want
        // to count cancel rates).
        _ = auto
    }

    private var passphraseAccepted: Bool {
        passphrase.count >= kMinPassphraseLength
    }

    private var passphraseHint: String {
        if passphrase.isEmpty {
            return returning
                ? "Your passphrase unlocks this device's identity key."
                : "Passphrase protects your identity key on this device."
        }
        if passphrase.count < kMinPassphraseLength {
            return "At least \(kMinPassphraseLength) characters " +
                   "(\(passphrase.count)/\(kMinPassphraseLength))."
        }
        return "Looks good."
    }
}
