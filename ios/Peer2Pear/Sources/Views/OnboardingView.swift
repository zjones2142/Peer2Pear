import SwiftUI

// Matches P2P_MIN_PASSPHRASE_BYTES in peer2pear.h — the core rejects
// anything shorter at p2p_set_passphrase_v2 time with rc = -1.  Mirror
// the check in Swift so the user gets an inline hint instead of a
// silent no-op on the submit button.
private let kMinPassphraseLength = 8

struct OnboardingView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var passphrase = ""
    // Confirmation field for first-launch only — empty on the
    // returning/Unlock branch.  Required to match `passphrase`
    // before "Get Started" enables, so a typo doesn't seal an
    // unrecoverable identity behind a string the user can't
    // reproduce.
    @State private var confirmPassphrase = ""
    @State private var starting = false
    // Suppresses re-prompting biometry on every view re-evaluation
    // after the user dismisses the first auto-prompt.
    @State private var biometricAutoAttempted = false
    @State private var showForgotPassword = false
    @State private var forgotConfirmText = ""

    // Phase 4 backup-strategy step 2: device-to-device migration
    // entry point.  Only renders on the !returning branch (fresh
    // install) — the receiving device never has an existing
    // identity to compete with.
    @State private var showTransferReceive = false

    // Tracks whether the screen is being recorded / mirrored so we
    // can blank out the passphrase fields — see ScreenCaptureMonitor
    // for the mechanics + threat model.
    @StateObject private var captureMonitor = ScreenCaptureMonitor()

    // User toggle from Settings — defaults true.  When false, we
    // don't react to capture (user accepts the risk).  @AppStorage
    // keeps it in sync with SettingsView and the in-app overlay.
    @AppStorage(ScreenCapturePolicy.blockOnLoginKey)
    private var blockOnLogin: Bool = ScreenCapturePolicy.blockOnLoginDefault

    // First-launch only: flips true when the user hits Return on
    // the primary passphrase field (or taps the Continue button)
    // to reveal the confirm field + warning toast.  Resets back
    // to false if the user clears or shrinks the primary
    // passphrase below the length gate (see .onChange below) so
    // a stale confirm value can't quietly come back into view.
    @State private var confirmPromptShown = false

    // Drives keyboard focus after the step1→step2 transition so
    // the user lands in the confirm field automatically.
    @FocusState private var focusedField: Field?

    private enum Field { case passphrase, confirm }

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
                    if captureBlocksLogin {
                        // Screen recording / mirroring detected and the
                        // user hasn't disabled the block in Settings:
                        // hide the passphrase input.  Stops a length-
                        // and-timing trace from leaking to whoever's
                        // recording.  Doesn't help against an
                        // external camera or shoulder-surfing — that's
                        // a separate threat.
                        VStack(spacing: 10) {
                            Image(systemName: "eye.slash.fill")
                                .font(.system(size: 36))
                                .foregroundStyle(.orange)
                            Text("Screen capture detected")
                                .font(.headline)
                            Text("Stop screen recording or mirroring before entering your passphrase.  You can disable this block in Settings after unlocking.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(Color.orange.opacity(0.12))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .strokeBorder(Color.orange.opacity(0.5),
                                              lineWidth: 1)
                        )
                    } else {
                        SecureField("Passphrase", text: $passphrase)
                            .textFieldStyle(.roundedBorder)
                            .submitLabel(returning ? .go : .continue)
                            .focused($focusedField, equals: .passphrase)
                            // Return on the primary field plays a
                            // different role per branch.  Unlock:
                            // submit.  First-launch: advance from
                            // step 1 to step 2 (reveal confirm +
                            // warning) — matches the requested flow
                            // of "enter password, then another box
                            // comes up".
                            .onSubmit {
                                if returning {
                                    if passphraseAccepted && !starting { submit() }
                                } else if passphrase.count >= kMinPassphraseLength {
                                    advanceToConfirmStep()
                                }
                            }

                        // First-launch step 2: confirm field appears
                        // only after the user explicitly advances
                        // from step 1 (Return key or Continue
                        // button), not just on length being met.
                        if !returning && confirmPromptShown {
                            SecureField("Confirm passphrase",
                                        text: $confirmPassphrase)
                                .textFieldStyle(.roundedBorder)
                                .submitLabel(.go)
                                .focused($focusedField, equals: .confirm)
                                .onSubmit {
                                    if passphraseAccepted && !starting { submit() }
                                }
                        }

                        // Inline guidance.  Stays neutral on the
                        // confirm step — we deliberately don't
                        // surface "passphrases don't match" in real
                        // time, which would let an observer infer
                        // the moment a guess turns correct.  The
                        // disabled state on the primary button is
                        // the only mid-typing signal.
                        Text(passphraseHint)
                            .font(.caption)
                            .foregroundStyle(passphraseHintColor)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        // First-launch warning, paired with the
                        // confirm field.  Wrapped in an orange-
                        // tinted card so it reads as a callout,
                        // not just orange caption text floating
                        // beside the input.
                        if !returning && confirmPromptShown {
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                Text("Save this passphrase somewhere safe. If you forget it, your data is permanently unrecoverable — there's no recovery email or reset link.")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                    .frame(maxWidth: .infinity,
                                           alignment: .leading)
                            }
                            .padding(12)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color.orange.opacity(0.12))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .strokeBorder(Color.orange.opacity(0.5),
                                                  lineWidth: 1)
                            )
                        }
                    }
                }
                .padding(.horizontal, 32)
                .onChange(of: passphrase) { _, new in
                    // Revoke step 2 when the user clears or shrinks
                    // the primary passphrase below the length gate.
                    // Without this, a stale confirm value from an
                    // earlier attempt would silently come back into
                    // view when the user re-grows the primary.
                    if new.count < kMinPassphraseLength {
                        if confirmPromptShown { confirmPromptShown = false }
                        if !confirmPassphrase.isEmpty { confirmPassphrase = "" }
                    }
                }

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

                Button(action: primaryButtonAction) {
                    if starting {
                        HStack(spacing: 8) {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .tint(.white)
                            Text("Unlocking…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text(primaryButtonLabel)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .padding(.horizontal, 32)
                // Capture-block disable matches the field-hiding
                // above: when the screen is being recorded there's
                // no visible field to type into, so the button has
                // nothing meaningful to submit.  Biometric stays
                // available (system Face ID prompt doesn't render
                // the passphrase to the screen).
                .disabled(!primaryButtonEnabled
                          || starting
                          || captureBlocksLogin)
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

                // Forgot password — recovery path for users who
                // didn't enable wipe-on-failed-attempts (off by
                // default).  Without this they'd be permanently
                // locked out, since Settings → Factory Reset is only
                // reachable post-unlock.  Discreet placement +
                // type-RESET confirmation keeps it out of the way
                // for users who DO know their passphrase.  Only
                // surfaced on the "Unlock" branch — fresh installs
                // have nothing to forget.
                if returning {
                    Button {
                        showForgotPassword = true
                    } label: {
                        Text("Forgot Password?")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.bottom, 12)
                }

                // Migration entry — only on fresh installs.  Sits
                // below the primary "Get Started" button as a
                // secondary affordance: most users create a new
                // identity, but those replacing a device need a
                // first-class path that doesn't bury "Transfer"
                // under Settings (Settings is post-unlock and the
                // user has no identity yet on this device).
                if !returning {
                    Button {
                        showTransferReceive = true
                    } label: {
                        Text("Transfer from another device")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.bottom, 12)
                }
            }
            .padding()
            .sheet(isPresented: $showTransferReceive) {
                TransferReceiveView(client: client)
            }
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
            // Forgot-password recovery: type-RESET-to-confirm wipe.
            // Only path back into the app for users who didn't enable
            // wipe-on-failed-attempts.  Same destructive primitive as
            // Settings → Factory Reset; surfaceFailedAttemptsAlert=false
            // so the user doesn't see the auto-wipe alert message
            // (they did this on purpose).
            .alert("Reset Identity",
                   isPresented: $showForgotPassword) {
                TextField("Type RESET to confirm", text: $forgotConfirmText)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                Button("Cancel", role: .cancel) {
                    forgotConfirmText = ""
                }
                Button("Reset", role: .destructive) {
                    if forgotConfirmText == "RESET" {
                        client.wipeAllData(
                            documentDir: Peer2PearClient.documentsPath,
                            surfaceFailedAttemptsAlert: false)
                        // Flip to the "Get Started" branch so the next
                        // render shows the create-passphrase flow.
                        returning = false
                    }
                    forgotConfirmText = ""
                }
            } message: {
                Text("There's no way to recover a forgotten passphrase — your data is encrypted with it.  The only path forward is to erase everything on this device and start over.\n\nType RESET to confirm.")
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
                    // Cache the verifier so the lock overlay can
                    // re-unlock without re-deriving Argon2id (~1s) —
                    // matters in .quick / .quickWithEviction modes
                    // where the rawContext is staying alive across
                    // the lock.  No-op for .strict (the verifier
                    // gets wiped on lock anyway).
                    client.recordVerifier(passphrase: pass)
                    client.resetFailedUnlockCounter()
                    // Drop our @State copies as soon as the session
                    // is live — no reason to keep the passphrase in
                    // SwiftUI state while the view tears down.  The
                    // cached copy on `client` is one-shot: the first
                    // reader (Settings biometric toggle) wipes it
                    // via consumeUnlockPassphrase().
                    passphrase = ""
                    confirmPassphrase = ""
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
                        // Clear both fields so the create-passphrase
                        // step starts from a blank slate.
                        returning = false
                        passphrase = ""
                        confirmPassphrase = ""
                    } else {
                        // Failed-but-not-wiped: clear the typed
                        // passphrase so the wrong-but-typed string
                        // doesn't linger in @State across the next
                        // attempt.  Bounds in-memory dwell time and
                        // mirrors iOS Settings → Passcode behaviour
                        // (which also force-retypes after each miss).
                        // Trade-off: user can't fix a single typo
                        // without retyping the whole thing — that's
                        // intentional, the security win is bigger.
                        passphrase = ""
                    }
                }
                starting = false
            }
        }
    }

    private var passphraseAccepted: Bool {
        guard passphrase.count >= kMinPassphraseLength else { return false }
        // First-launch: also require the confirmation to match
        // exactly, so a single typo doesn't seal an unrecoverable
        // identity behind a passphrase the user can't reproduce.
        if !returning && confirmPassphrase != passphrase {
            return false
        }
        return true
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
        if !returning && !confirmPromptShown {
            return "Press return to continue."
        }
        if !returning && confirmPromptShown {
            // Stay generic regardless of match state.  The live
            // flip from "doesn't match" to "looks good" is the
            // exact tell we don't want to surface — it lets an
            // observer pinpoint when a guess turned correct.
            // Mismatch is enforced at submit time via the button's
            // disabled binding (still reactive, but a button shape
            // is a much weaker signal than text changing).
            return "Re-enter to confirm."
        }
        return "Looks good."
    }

    // Hint color: orange ONLY when the user has typed something
    // but is below the length gate (a clear "you're not done
    // typing" cue).  Stays secondary for instructional and
    // success states, including step 2, so the color itself
    // doesn't leak match-state info.
    private var passphraseHintColor: Color {
        if !passphrase.isEmpty && passphrase.count < kMinPassphraseLength {
            return .orange
        }
        return .secondary
    }

    // Primary button title is branch- and step-aware.  Step 1
    // says "Continue" because tapping it advances to the confirm
    // step (same effect as Return); step 2 says "Get Started"
    // because tapping commits the new identity.
    private var primaryButtonLabel: String {
        if returning { return "Unlock" }
        return confirmPromptShown ? "Get Started" : "Continue"
    }

    // Step 1 button: enabled once length is met (taps advance to
    // step 2).  Step 2 button: enabled only when confirm matches
    // (taps commit).  Returning branch: enabled once length is
    // met.  Capture-block disable lives on the .disabled()
    // modifier itself so it's visible at the call site.
    private var primaryButtonEnabled: Bool {
        guard passphrase.count >= kMinPassphraseLength else { return false }
        if returning { return true }
        if !confirmPromptShown { return true }
        return confirmPassphrase == passphrase
    }

    // Combined gate for "should we hide passphrase entry right now?"
    // — captures both the live capture state and the user's
    // Settings toggle.  Used by the field-hiding branch above and
    // the primary-button .disabled() modifier so the two stay in
    // sync.
    private var captureBlocksLogin: Bool {
        captureMonitor.isCaptured && blockOnLogin
    }

    // Step 1 → step 2 advance, used by both the Continue button
    // tap and the primary field's Return key.  Defers the focus
    // shift one runloop so SwiftUI has time to materialize the
    // confirm field before we focus it (otherwise focus targets
    // a view that doesn't exist yet and is silently dropped).
    private func advanceToConfirmStep() {
        confirmPromptShown = true
        DispatchQueue.main.async {
            focusedField = .confirm
        }
    }

    private func primaryButtonAction() {
        if !returning && !confirmPromptShown {
            advanceToConfirmStep()
            return
        }
        submit()
    }
}
