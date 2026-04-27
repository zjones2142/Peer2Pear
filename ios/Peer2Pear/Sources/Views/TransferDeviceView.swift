import SwiftUI
import CoreImage.CIFilterBuiltins

// MARK: - Transfer-device migration UI
//
// Two entry points + two roles.  The receiving device (new
// install) shows a QR + paste-string and waits.  The sending
// device (unlocked source) scans the QR or pastes the string,
// confirms, and ships the encrypted blob.
//
//   * TransferReceiveView — fresh install, OnboardingView's
//     "Transfer from another device" footer button.  Owns a
//     MigrationReceiveSession that generates keypairs +
//     advertises on MultipeerConnectivity.
//
//   * TransferSendView — unlocked source, Settings →
//     "Transfer to new device".  Either scans the QR or
//     accepts a manually-pasted handshake string (same
//     base64url-of-JSON format either way), then runs a
//     MigrationSendSession that ships the encrypted blob.
//
// B.4 scope (this file): the UI shells on top of B.3's
// transport.  Receiver acknowledges the decrypted blob but
// doesn't yet apply it (that's B.5 — write identity files +
// kick start()).  Sender ships a placeholder payload (B.6 will
// populate it with the real identity + DB snapshot).
//
// See project_backup_strategy.md for the full design.

// MARK: - Receive (new device)

struct TransferReceiveView: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss

    /// Session is created in `.task` so `MigrationReceiveSession.make()`
    /// — which calls into the C-side keypair generation and can
    /// fail if libsodium / liboqs aren't available — has a clear
    /// error path + we don't construct it on every view rebuild.
    @State private var session: MigrationReceiveSession?
    @State private var initError: String?

    /// "Copy" button feedback — flips to "Copied!" briefly so the
    /// user knows the clipboard write succeeded.
    @State private var copied = false

    // MARK: Apply path (B.5)
    //
    // After `session.phase` reaches `.applying` the session has
    // delivered the decrypted MigrationPayload via
    // `session.receivedPayload`.  The view then prompts for the
    // SAME passphrase the source used (it doesn't travel — that's
    // the one piece of state the user must type) and runs the
    // file-write + `client.start(...)` chain.
    //
    // On success the app auto-switches to ChatListView via
    // Peer2PearApp's `if client.myPeerId.isEmpty` branch and the
    // sheet dismisses naturally.  On failure (wrong passphrase,
    // empty payload, file write error), surface a retry-able
    // error inline.

    enum ApplyStage: Equatable {
        case awaitingPassphrase
        case running
        case failed(String)
    }
    @State private var applyStage: ApplyStage = .awaitingPassphrase
    @State private var applyPassphrase: String = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                if let session {
                    body(for: session)
                } else if let initError {
                    errorState(initError)
                } else {
                    ProgressView("Preparing transfer…")
                        .frame(maxHeight: .infinity)
                }
            }
            .padding()
            .navigationTitle("Transfer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        session?.cancel()
                        dismiss()
                    }
                }
            }
            .task {
                // Initialize once.  Repeated re-entries (e.g.,
                // sheet dismissed + re-presented) get a fresh
                // session each time — fresh keypairs are required
                // for security anyway.
                if session == nil && initError == nil {
                    if let s = MigrationReceiveSession.make() {
                        s.start()
                        self.session = s
                    } else {
                        self.initError =
                            "Couldn't prepare migration keys.  Restart the app and try again."
                    }
                }
            }
        }
    }

    // MARK: Inner state-driven body

    @ViewBuilder
    private func body(for session: MigrationReceiveSession) -> some View {
        // Watch session.phase so the view re-renders on each
        // transition.  ObservedObject would also work but
        // @StateObject manages lifetime which we don't want for
        // this — the session is owned by the @State above.
        let phaseObserver = PhaseObserver(session: session)
        switch phaseObserver.observedPhase {
        case .idle, .advertising:
            advertisingState(session)
        case .paired:
            statusState(systemImage: "iphone.and.arrow.forward",
                        title: "Connected to your old device",
                        body: "Receiving your account…")
        case .applying:
            applyState(session)
        case .success:
            statusState(systemImage: "checkmark.circle.fill",
                        title: "Transfer complete",
                        body: "Tap Done to continue.")
        case .error(let msg):
            errorState(msg)
        }
    }

    @ViewBuilder
    private func advertisingState(_ session: MigrationReceiveSession) -> some View {
        let encoded = session.handshake.encodeForQR()

        ScrollView {
            VStack(spacing: 16) {
                Text("On your old device, open Peer2Pear → Settings → Transfer to new device.  Then scan this QR code.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 16)

                if let qr = makeQRImage(from: encoded) {
                    Image(uiImage: qr)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 240, height: 240)
                        .padding(8)
                        .background(Color.white)
                        .cornerRadius(8)
                } else {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(.secondarySystemBackground))
                        .frame(width: 240, height: 240)
                        .overlay(Text("QR generation failed")
                                    .font(.caption)
                                    .foregroundStyle(.secondary))
                }

                // Manual-paste fallback — same encoded string,
                // selectable + with a one-tap Copy button.  Used
                // when the camera path fails (one device has no
                // back camera, accessibility, etc.).
                VStack(alignment: .leading, spacing: 8) {
                    Text("Or paste this code on your old device:")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                    Text(encoded)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(6)
                    Button {
                        UIPasteboard.general.string = encoded
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                            copied = false
                        }
                    } label: {
                        Label(copied ? "Copied!" : "Copy code",
                              systemImage: copied ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.green)
                    .animation(.easeInOut(duration: 0.15), value: copied)
                }
                .padding(.horizontal, 16)

                Text("Both devices need to be on the same Wi-Fi or close enough for Bluetooth.  After scanning / pasting, you'll enter the same passphrase on this device.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.top, 4)

                // Files-don't-transfer note, mirrored from the
                // sender's "What transfers" section so a user
                // who only sees the receiver flow still gets
                // the heads-up.
                Text("Note: saved files (attachments) don't transfer — move those with AirDrop or your usual device-transfer flow.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.top, 6)
            }
            .padding(.vertical)
        }
    }

    // MARK: Apply state (B.5)
    //
    // Receiver session has decrypted the migration blob; surface
    // a passphrase prompt + drive the on-disk apply.  Watching
    // session.receivedPayload via the @ObservedObject phase
    // observer is what gets us re-rendered when the data arrives.

    @ViewBuilder
    private func applyState(_ session: MigrationReceiveSession) -> some View {
        switch applyStage {
        case .awaitingPassphrase:
            applyPassphrasePrompt(session)
        case .running:
            VStack(spacing: 16) {
                Spacer()
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(1.5)
                Text("Applying your account…")
                    .font(.headline)
                Text("Argon2id key derivation typically takes ~1–2 seconds.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Spacer()
            }
        case .failed(let msg):
            VStack(spacing: 16) {
                Spacer()
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.orange)
                Text("Couldn't apply migration")
                    .font(.title3.bold())
                Text(msg)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Spacer()
                Button("Try Again") {
                    applyStage = .awaitingPassphrase
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .padding(.horizontal, 32)
                Button("Cancel transfer") {
                    session.cancel()
                    dismiss()
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .padding(.horizontal, 32)
                .padding(.bottom, 16)
            }
        }
    }

    @ViewBuilder
    private func applyPassphrasePrompt(_ session: MigrationReceiveSession) -> some View {
        VStack(spacing: 20) {
            Spacer().frame(height: 16)

            Image(systemName: "key.fill")
                .font(.system(size: 56))
                .foregroundStyle(.green)

            Text("Almost done")
                .font(.title2.bold())

            Text("Enter the SAME passphrase you use on your old device.  Your account is encrypted with it; without that passphrase the transfer can't be applied here.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            SecureField("Passphrase", text: $applyPassphrase)
                .textFieldStyle(.roundedBorder)
                .submitLabel(.go)
                .onSubmit {
                    if !applyPassphrase.isEmpty { startApply(session) }
                }
                .padding(.horizontal, 24)

            Button {
                startApply(session)
            } label: {
                Text("Finish transfer")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .padding(.horizontal, 24)
            .disabled(applyPassphrase.isEmpty)

            Text("If the passphrase doesn't match, you'll get a chance to retry — no data is overwritten until decryption succeeds.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Spacer()
        }
    }

    /// Kick the apply pipeline — JSON-decode the payload, write
    /// identity.json + db_salt.bin, call client.start() with the
    /// user-typed passphrase.  Argon2id runs ~1.3s on typical
    /// hardware; off-main thread so the spinner renders.
    private func startApply(_ session: MigrationReceiveSession) {
        guard let payloadData = session.receivedPayload else {
            applyStage = .failed("No migration data to apply.")
            return
        }
        let pass = applyPassphrase
        applyStage = .running

        DispatchQueue.global(qos: .userInitiated).async {
            // 1. Decode the wire JSON → MigrationPayload struct.
            let payload: MigrationPayload
            do {
                payload = try JSONDecoder().decode(
                    MigrationPayload.self, from: payloadData)
            } catch {
                DispatchQueue.main.async {
                    applyStage = .failed(
                        "Migration data is malformed: \(error.localizedDescription)")
                }
                return
            }

            // 2. Version + content sanity checks.  The B.4
            //    placeholder ships empty bytes; we surface a
            //    clear error rather than silently writing 0-byte
            //    files to disk.
            guard payload.version == MigrationPayload.currentVersion else {
                DispatchQueue.main.async {
                    applyStage = .failed(
                        "Migration data uses an incompatible format.  Update both devices to the same Peer2Pear release and try again.")
                }
                return
            }
            guard !payload.identityFile.isEmpty,
                  !payload.saltFile.isEmpty else {
                DispatchQueue.main.async {
                    applyStage = .failed(
                        "The other device sent an empty payload.  This is likely a development build (B.6 — sender's blob builder — hasn't landed yet) or a known bug; please report it.")
                }
                return
            }

            // 3. Write the identity files.  The directory layout
            //    (`<dataDir>/keys/identity.json`, `<dataDir>/keys/db_salt.bin`)
            //    must match what CryptoEngine::identityPath()
            //    returns — that's where the unlock path looks.
            let dataDir = Peer2PearClient.documentsPath
            let keysDir = dataDir + "/keys"
            let fm = FileManager.default
            do {
                try fm.createDirectory(atPath: keysDir,
                                        withIntermediateDirectories: true)
                try payload.identityFile.write(
                    to: URL(fileURLWithPath: keysDir + "/identity.json"))
                try payload.saltFile.write(
                    to: URL(fileURLWithPath: keysDir + "/db_salt.bin"))
            } catch {
                DispatchQueue.main.async {
                    applyStage = .failed(
                        "Couldn't write identity files: \(error.localizedDescription)")
                }
                return
            }

            // 4. Apply UserDefaults BEFORE start() — `start()`
            //    reads settings like the relay URL +
            //    autoLockMinutes immediately, so they need to be
            //    in place first.  Empty `userDefaults: [:]` is a
            //    silent no-op (sender had only-defaults settings).
            //    Allowlist filtering is enforced inside apply().
            if !payload.userDefaults.isEmpty {
                MigrationSettings.apply(payload.userDefaults)
            }

            // 5. Drive client.start() — this runs Argon2id over
            //    the typed passphrase using the migrated salt,
            //    derives the SQLCipher key, opens the DB.  Wrong
            //    passphrase = start() returns with myPeerId
            //    still empty.  applyDataProtection runs INSIDE
            //    start() post-unlock so .complete + iCloud-
            //    excluded land on the freshly-written files.
            //    Uses Peer2PearClient.storedRelayUrl which now
            //    reads the just-migrated relay URL setting.
            client.start(dataDir:    dataDir,
                          passphrase:  pass,
                          relayUrl:    Peer2PearClient.storedRelayUrl)

            // After identity-unlock succeeds, apply the SQLCipher
            // snapshot (contacts / conversations / messages /
            // members / blocked_keys) on the same background
            // thread — bulk DB inserts can take a moment for
            // long histories, no point bouncing back to main
            // mid-apply.  Run BEFORE marshalling success back to
            // main so the @Published mirrors are populated by
            // the time the WindowGroup swaps to ChatListView.
            var snapshotApplyError: String?
            if !client.myPeerId.isEmpty,
               !payload.appDataSnapshot.isEmpty {
                do {
                    let snap = try JSONDecoder().decode(
                        MigrationAppDataSnapshot.self,
                        from: payload.appDataSnapshot)
                    try client.applyAppDataSnapshot(snap)
                } catch {
                    snapshotApplyError = error.localizedDescription
                }
            }

            DispatchQueue.main.async {
                if !client.myPeerId.isEmpty {
                    if let err = snapshotApplyError {
                        // Identity made it but app data didn't —
                        // partial migration.  Surface so the user
                        // knows their messages/contacts may be
                        // incomplete; they can still use the app.
                        applyStage = .failed(
                            "Your identity transferred, but some of your data didn't apply: \(err).  Tap Try Again or close to continue without it.")
                    } else {
                        // Full success — Peer2PearApp's
                        // WindowGroup will re-render to
                        // ChatListView (myPeerId is non-empty),
                        // which dismisses this sheet naturally.
                        // No explicit dismiss() so the user
                        // briefly sees the success state if the
                        // WindowGroup transition lags.
                        applyStage = .running   // stays on spinner briefly
                    }
                } else {
                    // Wrong passphrase OR identity.json corrupt
                    // OR salt mismatch — same surface ("identity
                    // unlock failed") as the OnboardingView
                    // unlock branch.  Wipe the files we just
                    // wrote so retrying with a different
                    // passphrase doesn't accumulate stale state
                    // on disk.
                    let identityPath = keysDir + "/identity.json"
                    let saltPath     = keysDir + "/db_salt.bin"
                    try? fm.removeItem(atPath: identityPath)
                    try? fm.removeItem(atPath: saltPath)
                    applyPassphrase = ""
                    applyStage = .failed(
                        "Couldn't unlock with that passphrase.  Make sure you're entering the same passphrase you use on your old device.")
                }
            }
        }
    }

    @ViewBuilder
    private func statusState(systemImage: String,
                              title: String,
                              body: String) -> some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: systemImage)
                .font(.system(size: 64))
                .foregroundStyle(.green)
            Text(title)
                .font(.title3.bold())
            Text(body)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .padding(.horizontal, 32)
        }
    }

    @ViewBuilder
    private func errorState(_ message: String) -> some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.orange)
            Text("Transfer didn't complete")
                .font(.title3.bold())
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Close") {
                session?.cancel()
                dismiss()
            }
            .buttonStyle(.bordered)
            .tint(.red)
            .padding(.horizontal, 32)
        }
    }
}

// MARK: - Send (old device, unlocked)

struct TransferSendView: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss

    enum InputMode: String, CaseIterable, Identifiable {
        case scan = "Scan QR"
        case paste = "Paste code"
        var id: String { rawValue }
    }

    @State private var inputMode: InputMode = .scan
    @State private var pasteText: String = ""
    @State private var pasteError: String?
    @State private var showScanner: Bool = false
    @State private var scanError: String?
    @State private var session: MigrationSendSession?

    // Post-success state — tracks the optional follow-up actions
    // the user picks AFTER the transfer itself completes:
    //   * Sentinel notification: did the user tap "Notify my
    //     contacts"?  Single-fire to prevent double-spamming if
    //     the button rebuilds.
    //   * Erase-this-device confirmation: gated behind type-ERASE
    //     to match the Factory Reset confirmation pattern, since
    //     the action is irreversible.
    @State private var sentinelStatus: SentinelStatus = .notSent
    @State private var showEraseConfirm: Bool = false
    @State private var eraseConfirmText: String = ""

    enum SentinelStatus: Equatable {
        case notSent
        case sent(contacts: Int, groups: Int)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if let session {
                    sendingBody(for: session)
                } else {
                    pickerBody
                }
            }
            .navigationTitle("Transfer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        session?.cancel()
                        dismiss()
                    }
                }
            }
            .fullScreenCover(isPresented: $showScanner) {
                QRScannerView(
                    onScan: { raw in
                        showScanner = false
                        attemptStart(with: raw)
                    },
                    onCancel: { showScanner = false }
                )
            }
        }
        .p2pColorScheme(client.colorScheme)
    }

    // MARK: Picker (initial state — choose Scan vs Paste)

    @ViewBuilder
    private var pickerBody: some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: "iphone.and.arrow.forward")
                    .font(.system(size: 56))
                    .foregroundStyle(.green)
                    .padding(.top, 12)

                Text("Transfer to new device")
                    .font(.title2.bold())

                Text("On your new iPhone, install Peer2Pear and tap \"Transfer from another device\".  Then either scan the QR code OR paste the code shown there.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)

                Picker("Input", selection: $inputMode) {
                    ForEach(InputMode.allCases) { m in
                        Text(m.rawValue).tag(m)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 32)

                Group {
                    switch inputMode {
                    case .scan:  scanModeBody
                    case .paste: pasteModeBody
                    }
                }
                .padding(.horizontal, 24)

                // What-transfers preview.  Honest scope: the
                // app's worth of state, not raw saved-file
                // bytes.  Files-don't-transfer is named
                // explicitly so users can plan ahead (use
                // AirDrop / Quick Transfer for bulk file moves).
                VStack(alignment: .leading, spacing: 4) {
                    Text("What transfers:")
                        .font(.caption.bold())
                    Text("• Identity keys + same peer ID")
                    Text("• Contacts (with verification status)")
                    Text("• Conversations + full message history")
                    Text("• Groups + member rosters")
                    Text("• Blocked keys")
                    Text("• Settings + relay configuration")

                    Text("What does NOT transfer:")
                        .font(.caption.bold())
                        .padding(.top, 6)
                    Text("• Saved files (downloaded attachments).  Move those with AirDrop, iCloud Drive, or your normal device-transfer flow — Peer2Pear isn't a file-sync layer.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 32)
                .padding(.top, 8)

                Text("Encrypted transfer over MultipeerConnectivity — the blob never touches Apple's servers or any third party.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .padding(.bottom, 16)
            }
        }
    }

    @ViewBuilder
    private var scanModeBody: some View {
        VStack(spacing: 12) {
            Button {
                scanError = nil
                showScanner = true
            } label: {
                Label("Open scanner", systemImage: "qrcode.viewfinder")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)

            if let scanError {
                Text(scanError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private var pasteModeBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Paste the code from your new device:")
                .font(.caption.bold())
                .foregroundStyle(.secondary)

            TextEditor(text: $pasteText)
                .frame(minHeight: 80, maxHeight: 120)
                .font(.system(.caption, design: .monospaced))
                .padding(8)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(.separator), lineWidth: 0.5)
                )
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

            HStack {
                Button {
                    if let s = UIPasteboard.general.string {
                        pasteText = s
                    }
                } label: {
                    Label("Paste", systemImage: "doc.on.clipboard")
                        .font(.caption)
                }
                .buttonStyle(.bordered)

                Spacer()

                Button("Continue") {
                    attemptStart(with: pasteText)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(pasteText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            if let pasteError {
                Text(pasteError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    // MARK: Sending state — once a session is live

    @ViewBuilder
    private func sendingBody(for session: MigrationSendSession) -> some View {
        // Phase observer triggers re-render on each transition.
        let phaseObserver = SendPhaseObserver(session: session)
        switch phaseObserver.observedPhase {
        case .idle, .browsing:
            statusBody(systemImage: "wave.3.right",
                        title: "Looking for your new device…",
                        body: "Both devices need to be on the same Wi-Fi or close enough for Bluetooth.")
        case .connecting:
            statusBody(systemImage: "arrow.left.arrow.right",
                        title: "Connecting…",
                        body: "Establishing encrypted channel.")
        case .verifying:
            statusBody(systemImage: "lock.shield.fill",
                        title: "Verifying…",
                        body: "Checking the new device's keys match the QR / pasted handshake.")
        case .sending:
            statusBody(systemImage: "arrow.up.circle.fill",
                        title: "Sending your account…",
                        body: "Encrypted transfer in progress.")
        case .success:
            successBody()
        case .error(let msg):
            errorBody(msg)
        }
    }

    /// Post-success action surface — sentinel notification +
    /// keep-or-erase choice.  Replaces the generic statusBody
    /// for `.success` because there are real follow-up actions
    /// to surface, not just a "transfer complete" announcement.
    @ViewBuilder
    private func successBody() -> some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.green)
                    .padding(.top, 24)

                Text("Transfer complete")
                    .font(.title2.bold())

                Text("Your new device has your account.  Two optional follow-ups below.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)

                // ── Notify contacts ──────────────────────────────
                VStack(alignment: .leading, spacing: 8) {
                    Text("NOTIFY CONTACTS")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)

                    Text("Send each of your contacts + groups a one-line \"I switched devices\" message from THIS device — so when they next see a safety-number-changed alert from your new device, it has context.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    switch sentinelStatus {
                    case .notSent:
                        Button {
                            let counts = client.sendMigrationSentinel()
                            sentinelStatus = .sent(
                                contacts: counts.contacts,
                                groups:   counts.groups)
                        } label: {
                            Label("Tell my contacts I moved",
                                  systemImage: "megaphone.fill")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.bordered)
                        .tint(.green)
                    case .sent(let c, let g):
                        Label {
                            Text("Sent — \(c) contact\(c == 1 ? "" : "s")"
                                  + (g > 0 ? " + \(g) group\(g == 1 ? "" : "s")" : ""))
                                .font(.caption.weight(.medium))
                        } icon: {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                        }
                        .padding(.vertical, 6)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(10)
                .padding(.horizontal, 16)

                // ── This device ──────────────────────────────────
                VStack(alignment: .leading, spacing: 8) {
                    Text("THIS DEVICE")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)

                    Text("Your account now lives on the new device too.  Keep both, or erase this one.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Button {
                        dismiss()
                    } label: {
                        Text("Keep this device")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)

                    Button(role: .destructive) {
                        showEraseConfirm = true
                    } label: {
                        Text("Erase this device")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(10)
                .padding(.horizontal, 16)

                Spacer().frame(height: 16)
            }
        }
        // type-ERASE confirmation — same pattern as Factory Reset
        // (Settings → FactoryResetSection).  Keeps a fat-finger
        // tap from nuking the device.
        .alert("Erase this device?",
               isPresented: $showEraseConfirm) {
            TextField("Type ERASE to confirm", text: $eraseConfirmText)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
            Button("Cancel", role: .cancel) {
                eraseConfirmText = ""
            }
            Button("Erase", role: .destructive) {
                if eraseConfirmText == "ERASE" {
                    // surfaceFailedAttemptsAlert: false — this
                    // is a deliberate post-migration wipe, not
                    // the auto-wipe-after-12-fails path.  User
                    // doesn't need that alert.
                    client.wipeAllData(
                        documentDir: Peer2PearClient.documentsPath,
                        surfaceFailedAttemptsAlert: false)
                    // wipeAllData clears myPeerId → Peer2PearApp
                    // re-renders to OnboardingView.  Dismiss the
                    // sheet so the user sees that fresh state.
                    dismiss()
                }
                eraseConfirmText = ""
            }
        } message: {
            Text("This erases your identity, contacts, messages, and settings from THIS device.  Cannot be undone — your new device keeps the migrated copy.\n\nType ERASE to confirm.")
        }
    }

    @ViewBuilder
    private func statusBody(systemImage: String,
                             title: String,
                             body: String) -> some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: systemImage)
                .font(.system(size: 64))
                .foregroundStyle(.green)
            Text(title)
                .font(.title3.bold())
            Text(body)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .padding(.horizontal, 32)
                .padding(.bottom, 16)
        }
    }

    @ViewBuilder
    private func errorBody(_ message: String) -> some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.orange)
            Text("Transfer didn't complete")
                .font(.title3.bold())
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            // Append a "version-mismatch?" hint when the error
            // string suggests it.  Heuristic but unambiguous —
            // version-mismatch errors all carry the literal word
            // "version" since the underlying enum value is
            // versionMismatch.
            if message.lowercased().contains("version") {
                Text("Make sure both devices are running the same Peer2Pear release.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            Spacer()

            // Try Again clears the failed session + bounces
            // back to the input picker so the user can re-
            // scan / re-paste.  Useful for transient MPC drops
            // where the QR is still valid; for hard failures
            // (version mismatch) the user retries with a fresh
            // QR from the receiver.
            Button("Try Again") {
                session?.cancel()
                session = nil
                pasteText = ""
                pasteError = nil
                scanError = nil
                sentinelStatus = .notSent
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .padding(.horizontal, 32)

            Button("Close") {
                session?.cancel()
                dismiss()
            }
            .buttonStyle(.bordered)
            .tint(.red)
            .padding(.horizontal, 32)
            .padding(.bottom, 16)
        }
    }

    // MARK: Start path — shared between scan + paste

    /// Validate the handshake string + spin up a send session.
    /// `raw` is whatever the user provided — QR scanner output or
    /// pasted text.  Both routes go through `MigrationHandshake.decode`
    /// and yield the same struct, so this function is one
    /// implementation for both input modes.
    private func attemptStart(with raw: String) {
        guard let handshake = MigrationHandshake.decode(raw) else {
            surfaceInputError(
                "That doesn't look like a Peer2Pear handshake.  Make sure you're scanning / pasting the code from your new device's transfer screen.")
            return
        }

        // B.6 — build the real payload by reading the source
        // device's identity files off disk.  identity.json is
        // already encrypted-at-rest under the user's passphrase
        // (CryptoEngine handles that), so we ship those exact
        // ciphertext bytes; the AEAD migration envelope is a
        // SECOND layer on top.  Receiver writes them verbatim,
        // types the same passphrase, the existing unlock path
        // decrypts — passphrase never travels.
        //
        // Layout matches CryptoEngine::identityPath():
        //   <dataDir>/keys/identity.json
        //   <dataDir>/keys/db_salt.bin
        //
        // Future Phase B chunks expand this to include a
        // SQLCipher snapshot + UserDefaults subset + file
        // metadata.  Identity-only first to validate the
        // end-to-end pipeline.
        let dataDir = Peer2PearClient.documentsPath
        let keysDir = dataDir + "/keys"
        let identityPath = keysDir + "/identity.json"
        let saltPath     = keysDir + "/db_salt.bin"

        let identityData: Data
        let saltData:     Data
        do {
            identityData = try Data(contentsOf: URL(fileURLWithPath: identityPath))
            saltData     = try Data(contentsOf: URL(fileURLWithPath: saltPath))
        } catch {
            surfaceInputError(
                "Couldn't read this device's identity files: \(error.localizedDescription).  This shouldn't happen — try locking + unlocking the app and retrying the transfer.")
            return
        }
        guard !identityData.isEmpty, !saltData.isEmpty else {
            surfaceInputError(
                "This device's identity files are empty.  Complete onboarding first, then start the transfer.")
            return
        }

        // Build the SQLCipher snapshot — Tier 1 content
        // (contacts, conversations, members, messages, blocked
        // keys).  Wraps the existing dbLoad* helpers so we don't
        // need new C API for the export path.  Empty store
        // (e.g., user just created identity, no chats yet)
        // produces an empty-but-valid snapshot.
        let snapshot = client.buildAppDataSnapshot()
        let snapshotBytes: Data
        do {
            snapshotBytes = try JSONEncoder().encode(snapshot)
        } catch {
            surfaceInputError(
                "Couldn't build app-data snapshot: \(error.localizedDescription)")
            return
        }

        // Settings snapshot — allowlisted UserDefaults keys
        // (auto-lock, privacy level, file thresholds, screen-
        // capture blocks, relay URLs, notification mode, etc.).
        // Curated in MigrationSettings.migratedKeys; per-device
        // counters like failedUnlockAttempts intentionally don't
        // travel.
        let settings = MigrationSettings.snapshot()

        let payload = MigrationPayload(
            version:         MigrationPayload.currentVersion,
            identityFile:    identityData,
            saltFile:        saltData,
            appDataSnapshot: snapshotBytes,
            userDefaults:    settings)
        guard let payloadBytes = try? JSONEncoder().encode(payload) else {
            surfaceInputError("Couldn't build migration payload.")
            return
        }

        let s = MigrationSendSession(handshake: handshake,
                                       payload:  payloadBytes)
        s.start()
        self.session = s
    }

    /// Route an error message to whichever input mode the user
    /// is currently looking at — so a paste failure shows under
    /// the paste field, a scan failure shows under the scan
    /// button.  Centralized so the picker logic doesn't repeat
    /// in three places.
    private func surfaceInputError(_ msg: String) {
        switch inputMode {
        case .scan:  scanError  = msg
        case .paste: pasteError = msg
        }
    }
}

// MARK: - QR code generation

/// Render a string into a QR-code image suitable for SwiftUI's
/// `Image(uiImage:)`.  Returns nil if Core Image fails (rare —
/// usually an OOM or a malformed message exceeding QR capacity).
private func makeQRImage(from string: String) -> UIImage? {
    let context = CIContext()
    let filter  = CIFilter.qrCodeGenerator()
    filter.message = Data(string.utf8)
    // Error-correction level "M" (15%) — balances QR density vs
    // resilience to camera shake / partial occlusion.  "L" packs
    // more data but scans worse in practice; "H" is overkill.
    filter.correctionLevel = "M"
    guard let output = filter.outputImage else { return nil }
    // CIQRCodeGenerator emits a tiny image; scale up so the QR
    // modules render as crisp pixels at SwiftUI display size.
    let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
    guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else {
        return nil
    }
    return UIImage(cgImage: cgImage)
}

// MARK: - Phase observers
//
// SwiftUI's @StateObject manages lifetime; we want to OBSERVE an
// existing object's @Published phase without taking ownership.
// @ObservedObject works inside a struct property, but we want to
// react inline in `body` based on current phase — these tiny
// wrapper structs let us pull the latest @Published value into
// the calling view's redraw cycle without re-architecting the
// session ownership.

private struct PhaseObserver {
    @ObservedObject var session: MigrationReceiveSession
    var observedPhase: MigrationReceiveSession.Phase { session.phase }
}

private struct SendPhaseObserver {
    @ObservedObject var session: MigrationSendSession
    var observedPhase: MigrationSendSession.Phase { session.phase }
}
