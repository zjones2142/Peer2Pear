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
    // Suppresses re-prompting biometry on every view re-evaluation
    // after the user dismisses the first auto-prompt.
    @State private var biometricAutoAttempted = false

    // Mutable so we can re-evaluate after a panic-wipe (12 failed
    // attempts) flips the on-disk state from "identity present" back
    // to "no identity" without rebuilding the view.
    @State private var returning: Bool = Peer2PearClient.identityExists(
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
                        tryBiometric()
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
                // One-shot biometric prompt on first appearance.  Guard
                // against re-nagging on every body re-render.
                if biometricAvailable && !biometricAutoAttempted {
                    biometricAutoAttempted = true
                    tryBiometric()
                }
            }
            .alert("All Data Erased",
                   isPresented: $client.dataWipedNotice) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("Too many failed unlock attempts.  Identity, contacts, messages, and saved files have been permanently removed from this device.")
            }
        }
    }

    private func submit() {
        unlock(with: passphrase)
    }

    private func tryBiometric() {
        BiometricUnlock.retrieve(reason: "Unlock Peer2Pear") { pass in
            guard let pass, !pass.isEmpty else { return }
            unlock(with: pass)
        }
    }

    // Argon2id runs for ~1.3 s on typical hardware; kick it off on a
    // background queue so the button's spinner actually renders.  The
    // @Published myPeerId mutation inside start() marshals back to
    // main before Peer2PearApp's conditional switches to ChatListView.
    private func unlock(with pass: String) {
        starting = true
        DispatchQueue.global(qos: .userInitiated).async {
            client.start(dataDir: Peer2PearClient.documentsPath,
                          passphrase: pass,
                          relayUrl: Peer2PearClient.storedRelayUrl)
            DispatchQueue.main.async {
                // Cache the passphrase only on a successful unlock so
                // the Settings → "Enable Face ID" toggle can install it
                // without re-prompting.  consumeUnlockPassphrase()
                // wipes it after first read.
                if !client.myPeerId.isEmpty {
                    client.setLastUnlockPassphrase(pass)
                    client.resetFailedUnlockCounter()
                } else if returning {
                    // Only count failures against EXISTING identities —
                    // a fresh install's first "Get Started" attempt with
                    // a too-short passphrase shouldn't count toward wipe.
                    let wiped = client.recordFailedUnlock(
                        documentDir: Peer2PearClient.documentsPath)
                    if wiped {
                        // Sandbox is empty now; rebuild the view's
                        // returning flag so the UI flips to the
                        // "Get Started" branch instead of "Unlock".
                        returning = false
                        passphrase = ""
                    }
                }
                starting = false
            }
        }
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
