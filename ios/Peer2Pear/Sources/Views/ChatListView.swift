import SwiftUI
import UniformTypeIdentifiers

struct ChatListView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var showAddContact = false
    @State private var showNewGroup = false
    @State private var showMyKey = false
    @State private var showSettings = false
    @State private var showContacts = false
    @State private var showConnectivityInfo = false
    @State private var newContactId = ""

    /// 1:1 conversations keyed by the OTHER peer's ID (not always the
    /// `from` — for outgoing messages `from == myPeerId` and we key off
    /// `to` instead).  Used to render the last-message preview per chat.
    private var conversations: [String: [P2PMessage]] {
        Dictionary(grouping: client.messages) { msg in
            msg.from == client.myPeerId ? (msg.to ?? "") : msg.from
        }
    }

    private var directPeerIds: [String] {
        client.chatPeerIds.subtracting([""]).sorted()
    }

    /// Groups sorted most-recently-active first.
    private var groupsSorted: [P2PGroup] {
        client.groups.values.sorted { $0.lastActivity > $1.lastActivity }
    }

    private var isEmpty: Bool {
        directPeerIds.isEmpty && groupsSorted.isEmpty
    }

    var body: some View {
        NavigationStack {
            List {
                if !groupsSorted.isEmpty {
                    Section("Groups") {
                        ForEach(groupsSorted) { group in
                            NavigationLink {
                                GroupConversationView(client: client, groupId: group.id)
                            } label: {
                                GroupRow(client: client, group: group)
                            }
                        }
                    }
                }
                if !directPeerIds.isEmpty {
                    Section("Direct Messages") {
                        ForEach(directPeerIds, id: \.self) { peerId in
                            NavigationLink {
                                ConversationView(client: client, peerId: peerId)
                            } label: {
                                ChatRow(client: client, peerId: peerId,
                                        preview: conversations[peerId]?.last?.text)
                            }
                            .swipeActions(edge: .leading, allowsFullSwipe: false) {
                                NavigationLink {
                                    ContactDetailView(client: client, peerId: peerId)
                                } label: {
                                    Label("Info", systemImage: "info.circle")
                                }
                                .tint(.blue)
                            }
                            // Trailing swipe: wipe the chat transcript.
                            // Leaves `knownPeerContacts` alone — useful for
                            // dismissing a stranger's chat without adding
                            // them as a contact just to remove them.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    client.deleteChat(peerId: peerId)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                // Leading slot: full contacts list (separate from the
                // chats-with-history section below).  Lets the user
                // edit / remove peers even before any messages flow.
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showContacts = true
                    } label: {
                        Image(systemName: "person.2")
                    }
                    .accessibilityLabel("Contacts")
                }
                // Trailing cluster, left-to-right:
                //   wifi (status, was top-leading)
                //   gear (settings)
                //   person (my key)
                //   + (add menu)
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showConnectivityInfo = true
                    } label: {
                        Image(systemName: client.isConnected
                              ? "wifi" : "wifi.slash")
                            .foregroundStyle(client.isConnected ? .green : .red)
                    }
                    .accessibilityLabel(client.isConnected
                                        ? "Connected"
                                        : "Offline")
                    .popover(isPresented: $showConnectivityInfo,
                             arrowEdge: .top) {
                        ConnectivityPopover(client: client)
                            .presentationCompactAdaptation(.popover)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showMyKey = true
                    } label: {
                        Image(systemName: "person.crop.circle")
                    }
                    .accessibilityLabel("My key")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            showAddContact = true
                        } label: {
                            Label("New Chat", systemImage: "bubble.left")
                        }
                        Button {
                            showNewGroup = true
                        } label: {
                            Label("New Group", systemImage: "person.3")
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showAddContact) {
                AddContactSheet(client: client, newContactId: $newContactId)
            }
            .sheet(isPresented: $showNewGroup) {
                NewGroupSheet(client: client)
            }
            .sheet(isPresented: $showMyKey) {
                MyKeyView(client: client)
            }
            .sheet(isPresented: $showSettings) {
                SettingsView(client: client)
            }
            .sheet(isPresented: $showContacts) {
                ContactsListView(client: client)
            }
            .overlay {
                if isEmpty {
                    ContentUnavailableView(
                        "No conversations yet",
                        systemImage: "bubble.left.and.bubble.right",
                        description: Text("Tap + to start a new chat or group")
                    )
                }
            }
        }
    }
}

// MARK: - Group list row
// Group icon + name + last message preview.  The preview pulls the most
// recent groupMessages entry, falling back to "No messages yet" before
// anything lands.

struct GroupRow: View {
    @ObservedObject var client: Peer2PearClient
    let group: P2PGroup

    private var preview: String? {
        client.groupMessages.last(where: { $0.groupId == group.id })?.text
    }

    var body: some View {
        HStack {
            GroupAvatarThumbnail(
                avatarB64: client.groupAvatars[group.id],
                fallbackInitials: String(group.name.prefix(2)).uppercased(),
                size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.name)
                    .font(.headline)
                if let preview, !preview.isEmpty {
                    Text(preview)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else {
                    Text("\(group.memberIds.count) member\(group.memberIds.count == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - Chat list row
// Shows avatar initials, verification badge, and the last message preview.
// A persistent keyChanges[peerId] entry flips the row into warning mode —
// same signal the desktop's chatview.cpp surfaces.

struct ChatRow: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    let preview: String?

    var body: some View {
        HStack {
            Circle()
                .fill(.green)
                .frame(width: 40, height: 40)
                .overlay {
                    Text(String(peerId.prefix(2)).uppercased())
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(client.displayName(for: peerId))
                        .font(.headline)
                    TrustBadge(trust: client.peerTrust(for: peerId))
                    if client.isBlocked(peerId: peerId) {
                        Image(systemName: "nosign")
                            .foregroundStyle(.red)
                            .accessibilityLabel("Blocked")
                    }
                }
                if let preview, !preview.isEmpty {
                    Text(preview)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            // Red warning dot if there's an outstanding key change for this peer.
            if client.keyChanges[peerId] != nil {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Safety number changed")
            }
        }
    }
}

// MARK: - New group creation sheet
// Source of truth for "known contacts": peers we've exchanged 1:1
// messages with.  In a full build we'd have a dedicated address book;
// for now, the DM log is what we have to pick from.

struct NewGroupSheet: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss
    @State private var groupName = ""
    @State private var selectedPeers: Set<String> = []

    /// Anyone you might want in a group — explicit contacts plus
    /// active chat partners.  Wider than ChatListView's Direct
    /// Messages section because picking-into-a-group is a contact-
    /// list operation, not a chat-list operation.
    private var knownPeers: [String] {
        client.chatPeerIds
            .union(client.contactPeerIds)
            .subtracting([""])
            .sorted()
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Group Name") {
                    TextField("e.g. Weekend Plans", text: $groupName)
                }
                Section {
                    if knownPeers.isEmpty {
                        Text("No contacts yet.  Start a 1:1 chat first, then " +
                             "come back to create a group.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(knownPeers, id: \.self) { peerId in
                            Button {
                                if selectedPeers.contains(peerId) {
                                    selectedPeers.remove(peerId)
                                } else {
                                    selectedPeers.insert(peerId)
                                }
                            } label: {
                                HStack {
                                    Image(systemName: selectedPeers.contains(peerId)
                                           ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(selectedPeers.contains(peerId)
                                                         ? .green : .secondary)
                                    Text(client.displayName(for: peerId))
                                        .font(.body)
                                    Spacer()
                                    TrustBadge(trust: client.peerTrust(for: peerId))
                                }
                            }
                            .foregroundStyle(.primary)
                        }
                    }
                } header: {
                    Text("Members")
                } footer: {
                    Text("Members will see the group appear on their device the first time you send a message.")
                }
            }
            .navigationTitle("New Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        _ = client.createGroup(name: groupName.trimmingCharacters(in: .whitespaces),
                                               memberPeerIds: Array(selectedPeers))
                        dismiss()
                    }
                    .disabled(groupName.trimmingCharacters(in: .whitespaces).isEmpty
                              || selectedPeers.isEmpty)
                }
            }
        }
        .p2pColorScheme(client.colorScheme)
    }
}

// MARK: - Add-contact sheet
// Paste OR scan paths land in the same `newContactId` binding so the
// caller doesn't care which one the user took.  Sheet (vs alert) so we
// can host the QR scanner as a full-screen presentation inside it.

struct AddContactSheet: View {
    @ObservedObject var client: Peer2PearClient
    @Binding var newContactId: String
    @Environment(\.dismiss) private var dismiss
    @State private var showScanner = false
    @State private var scanError: String?

    private var trimmed: String {
        newContactId.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var isValid: Bool {
        // Delegates to the shared C API so iOS and desktop never drift
        // on what counts as a well-formed peer ID.
        Peer2PearClient.isValidPeerId(trimmed)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Paste peer's 43-char key", text: $newContactId, axis: .vertical)
                        .font(.system(.footnote, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .lineLimit(2...4)
                } header: {
                    Text("Peer ID")
                } footer: {
                    Text("Either paste the base64url key here or scan their QR code.")
                }

                Section {
                    Button {
                        scanError = nil
                        showScanner = true
                    } label: {
                        Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                    }
                    if let scanError {
                        Text(scanError)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("New Chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        newContactId = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Chat") {
                        // addContact lands the peer in knownPeerContacts
                        // so they surface in the chat list before any
                        // message round-trip happens.
                        client.addContact(peerId: trimmed)
                        newContactId = ""
                        dismiss()
                    }
                    .disabled(!isValid)
                }
            }
            .fullScreenCover(isPresented: $showScanner) {
                QRScannerView(
                    onScan: { raw in
                        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        if Peer2PearClient.isValidPeerId(trimmed) {
                            newContactId = trimmed
                            showScanner = false
                        } else {
                            scanError = "That QR code isn't a Peer2Pear key (\(trimmed.count) chars, need 43)."
                            showScanner = false
                        }
                    },
                    onCancel: { showScanner = false }
                )
            }
        }
        .p2pColorScheme(client.colorScheme)
    }
}

// MARK: - Trust badge
// Mirrors desktop chatview.cpp: green check when verified, orange bang
// when mismatch, nothing when unverified (default state for new peers).

struct TrustBadge: View {
    let trust: P2PPeerTrust
    var body: some View {
        switch trust {
        case .verified:
            Image(systemName: "checkmark.seal.fill")
                .foregroundStyle(.green)
                .accessibilityLabel("Verified contact")
        case .mismatch:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel("Safety number mismatch")
        case .unverified:
            EmptyView()
        }
    }
}

// MARK: - Contact detail + safety-number view
// Identity fingerprint surface — this is where a user compares the
// 60-digit number with the peer out-of-band and taps "Verify".  Hitting
// Verify calls markVerified which also clears any outstanding
// keyChanges[peerId] entry (see Peer2PearClient.markVerified).

struct ContactDetailView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    @Environment(\.dismiss) private var dismiss
    @State private var confirmUnverify = false
    @State private var confirmRemove = false
    @State private var confirmBlock = false
    @State private var confirmReset = false
    @State private var nicknameDraft = ""

    private var trust: P2PPeerTrust { client.peerTrust(for: peerId) }
    private var keyChanged: Bool   { client.keyChanges[peerId] != nil }
    private var isBlocked: Bool    { client.isBlocked(peerId: peerId) }

    var body: some View {
        Form {
            // ── Header — avatar + peer ID + status ─────────────────────
            Section {
                HStack(spacing: 16) {
                    Circle()
                        .fill(.green)
                        .frame(width: 56, height: 56)
                        .overlay {
                            Text(String(peerId.prefix(2)).uppercased())
                                .font(.title3.bold())
                                .foregroundStyle(.white)
                        }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(client.displayName(for: peerId))
                            .font(.headline)
                        Text(peerId.prefix(16) + "…")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        HStack(spacing: 4) {
                            TrustBadge(trust: trust)
                            Text(trustLabel)
                                .font(.caption)
                                .foregroundStyle(trustColor)
                        }
                        if client.peerPresence[peerId] == true {
                            Text("Online")
                                .font(.caption)
                                .foregroundStyle(.green)
                        }
                    }
                    Spacer()
                }
                .padding(.vertical, 4)
            }

            // ── Send Message — entry point from the contact card.
            // Chats are now message-history-only (no longer auto-include
            // address-book contacts), so without this link an explicit
            // contact with no prior chat would be unreachable from the
            // contacts list.
            Section {
                NavigationLink {
                    ConversationView(client: client, peerId: peerId)
                } label: {
                    Label("Send Message", systemImage: "bubble.left")
                }
            }

            // ── Nickname (user-editable) ───────────────────────────────
            Section {
                TextField("Add a nickname", text: $nicknameDraft)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .onSubmit {
                        client.setNickname(peerId: peerId, nickname: nicknameDraft)
                    }
            } header: {
                Text("Nickname")
            } footer: {
                Text("Only visible on this device. The peer can't see what you've named them.")
            }

            // ── Key-change warning, if any ─────────────────────────────
            if keyChanged {
                Section {
                    Label("""
                        This peer's identity key changed.  Compare the \
                        safety number below with them over a trusted channel \
                        before you tap Verify.
                        """,
                        systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            }

            // ── Safety number (60-digit sort-invariant BLAKE2b) ────────
            Section("Safety Number") {
                Text(formattedSafetyNumber)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("Compare this 60-digit number with your contact out " +
                     "of band (video call, in person).  If both sides see " +
                     "the same number, the connection hasn't been tampered with.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // ── Actions ────────────────────────────────────────────────
            Section {
                switch trust {
                case .verified:
                    Button("Mark as Unverified", role: .destructive) {
                        confirmUnverify = true
                    }
                case .unverified, .mismatch:
                    Button(trust == .mismatch ? "Confirm New Number" : "Mark as Verified") {
                        _ = client.markVerified(peerId: peerId)
                    }
                    .tint(.green)
                }
            }

            // ── Session + block management ─────────────────────────────
            // Reset Session wipes the ratchet so the next outbound
            // handshake is fresh (recovery path for desync / device
            // swap).  Block is a client-side filter — inbound DMs and
            // file requests from blocked peers are dropped silently.
            Section {
                Button("Reset Session") {
                    confirmReset = true
                }
                .tint(.orange)
                Button(isBlocked ? "Unblock Contact" : "Block Contact",
                       role: isBlocked ? .none : .destructive) {
                    confirmBlock = true
                }
            } footer: {
                if isBlocked {
                    Text("Blocked — messages and files from this peer are discarded.")
                        .foregroundStyle(.red)
                }
            }

            // ── Destructive: Remove Contact ────────────────────────────
            // Narrow removal: drops the address-book entry and clears
            // the nickname but leaves message history alone so the
            // chat thread can keep flowing under the peer's key.  Use
            // the trailing-swipe Delete on ChatListView to wipe the
            // transcript separately.
            Section {
                Button("Remove Contact", role: .destructive) {
                    confirmRemove = true
                }
            }
        }
        .navigationTitle("Contact Info")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            nicknameDraft = client.contactNicknames[peerId] ?? ""
        }
        .confirmationDialog("Unverify this contact?",
                            isPresented: $confirmUnverify,
                            titleVisibility: .visible) {
            Button("Unverify", role: .destructive) {
                client.unverify(peerId: peerId)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Messages will still flow, but the verification check will be cleared.")
        }
        .confirmationDialog("Remove this contact?",
                            isPresented: $confirmRemove,
                            titleVisibility: .visible) {
            Button("Remove", role: .destructive) {
                client.removeContact(peerId: peerId)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They'll leave your contacts list. Message history stays — if they write again, the chat continues under the same key.")
        }
        .confirmationDialog(isBlocked ? "Unblock this contact?" : "Block this contact?",
                            isPresented: $confirmBlock,
                            titleVisibility: .visible) {
            Button(isBlocked ? "Unblock" : "Block",
                   role: isBlocked ? .none : .destructive) {
                client.setBlocked(peerId: peerId, blocked: !isBlocked)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(isBlocked
                 ? "They'll be able to send you messages and files again."
                 : "Their messages and file requests will be silently dropped on arrival. You can unblock later from this screen.")
        }
        .confirmationDialog("Reset the encrypted session?",
                            isPresented: $confirmReset,
                            titleVisibility: .visible) {
            Button("Reset Session", role: .destructive) {
                client.resetSession(peerId: peerId)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The next message either of you sends will start a fresh handshake. Use this if the peer reports undecryptable messages or after a device swap.")
        }
    }

    private var trustLabel: String {
        switch trust {
        case .verified:   return "Verified"
        case .mismatch:   return "Safety number changed"
        case .unverified: return "Unverified"
        }
    }
    private var trustColor: Color {
        switch trust {
        case .verified:   return .green
        case .mismatch:   return .orange
        case .unverified: return .secondary
        }
    }

    /// Format the 60-digit run as "XXXXX XXXXX XXXXX ..." in 4 rows of 3,
    /// matching the desktop chatview layout.  If the core returned empty
    /// (peer has no stored bundle yet), show a placeholder.
    private var formattedSafetyNumber: String {
        let raw = client.safetyNumber(for: peerId)
        guard !raw.isEmpty else {
            return "No safety number yet — send a message to establish a session."
        }
        let digits = raw.filter(\.isNumber)
        guard digits.count == 60 else { return raw }
        var groups: [String] = []
        var i = digits.startIndex
        for _ in 0..<12 {
            let j = digits.index(i, offsetBy: 5)
            groups.append(String(digits[i..<j]))
            i = j
        }
        let rows = stride(from: 0, to: groups.count, by: 3).map {
            groups[$0..<min($0+3, groups.count)].joined(separator: " ")
        }
        return rows.joined(separator: "\n")
    }
}

// MARK: - Contacts list (address book)
//
// Surfaced from ChatListView's leading toolbar button.  Backed by
// `client.contactPeerIds` — only peers the user EXPLICITLY added
// (via New Chat / QR scan / Import).  Strangers who messaged us
// without being added show up in Chats but NOT here, keeping the
// address book as a curated roster.
//
// Tap a row → ContactDetailView (safety number + verify/unverify +
// destructive Remove).  Swipe-to-delete = full removal (wipes the
// address-book entry AND 1:1 message history).

struct ContactsListView: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss
    @State private var showExport = false
    @State private var showImport = false
    @State private var importAlert: ImportAlert?

    // Contacts = address book, distinct from Chats (which unions
    // contacts with any peer who's messaged us).  See `chatPeerIds`
    // vs `contactPeerIds` in Peer2PearClient.
    private var peerIds: [String] {
        client.contactPeerIds.subtracting([""]).sorted()
    }

    var body: some View {
        NavigationStack {
            Group {
                if peerIds.isEmpty {
                    ContentUnavailableView(
                        "No contacts yet",
                        systemImage: "person.2",
                        description: Text("Use the + button on the chats screen to add a contact.")
                    )
                } else {
                    List {
                        ForEach(peerIds, id: \.self) { peerId in
                            NavigationLink {
                                ContactDetailView(client: client, peerId: peerId)
                            } label: {
                                ChatRow(client: client, peerId: peerId,
                                        preview: client.peerTrust(for: peerId) == .verified
                                            ? "Verified"
                                            : nil)
                            }
                        }
                        // Swipe-to-delete is a shortcut for the
                        // ContactDetail Remove button — no
                        // confirmation dialog here since iOS already
                        // surfaces a tap-to-confirm "Delete" pill.
                        .onDelete { offsets in
                            for idx in offsets {
                                client.removeContact(peerId: peerIds[idx])
                            }
                        }
                    }
                }
            }
            .navigationTitle("Contacts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Button {
                            showExport = true
                        } label: {
                            Label("Export…", systemImage: "square.and.arrow.up")
                        }
                        .disabled(peerIds.isEmpty)
                        Button {
                            showImport = true
                        } label: {
                            Label("Import…", systemImage: "square.and.arrow.down")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .accessibilityLabel("Contact actions")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .fileExporter(
                isPresented: $showExport,
                document: ContactsExportDoc(data: client.exportContactsJSON()),
                contentType: .json,
                defaultFilename: "peer2pear_contacts"
            ) { _ in }
            .fileImporter(
                isPresented: $showImport,
                allowedContentTypes: [.json]
            ) { result in
                switch result {
                case .success(let url):
                    // iOS file picker hands us a security-scoped URL;
                    // must start accessing before reading the file or
                    // the read fails with EACCES.
                    let started = url.startAccessingSecurityScopedResource()
                    defer { if started { url.stopAccessingSecurityScopedResource() } }
                    guard let data = try? Data(contentsOf: url) else {
                        importAlert = .failure("Couldn't read the selected file.")
                        return
                    }
                    let count = client.importContacts(from: data)
                    importAlert = count > 0
                        ? .success("Imported \(count) contact\(count == 1 ? "" : "s").")
                        : .failure("No valid contacts found in that file.")
                case .failure(let err):
                    importAlert = .failure(err.localizedDescription)
                }
            }
            .alert(item: $importAlert) { alert in
                Alert(title: Text(alert.title),
                      message: Text(alert.message),
                      dismissButton: .default(Text("OK")))
            }
        }
        .p2pColorScheme(client.colorScheme)
    }
}

// Sheet-shaped alert payload for the import flow.  Two cases (ok /
// error) let us drive a single .alert binding with the right copy.
private struct ImportAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String

    static func success(_ msg: String) -> ImportAlert {
        .init(title: "Import Complete", message: msg)
    }
    static func failure(_ msg: String) -> ImportAlert {
        .init(title: "Import Failed", message: msg)
    }
}

// FileDocument wrapper for the .json export.  Doesn't bother with
// read support — imports go through .fileImporter instead, which
// takes a URL rather than deserializing into a FileDocument.
struct ContactsExportDoc: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    static var writableContentTypes: [UTType] { [.json] }

    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        self.data = configuration.file.regularFileContents ?? Data()
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

// MARK: - Connectivity popover
// Tap target for the wifi icon in the top toolbar.  Shows the live
// connection state + which relay the client is pointed at, so the
// user can tell at a glance whether they are on the default relay
// or a self-hosted one without drilling into Settings → Relay server.

struct ConnectivityPopover: View {
    @ObservedObject var client: Peer2PearClient

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: client.isConnected
                      ? "wifi" : "wifi.slash")
                    .foregroundStyle(client.isConnected ? .green : .red)
                Text(client.isConnected ? "Connected" : "Offline")
                    .font(.headline)
            }
            Divider()
            Text("Relay")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(Peer2PearClient.storedRelayUrl)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
        }
        .padding(14)
        .frame(minWidth: 240, maxWidth: 300, alignment: .leading)
    }
}
