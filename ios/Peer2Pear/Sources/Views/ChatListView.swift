import SwiftUI
import UniformTypeIdentifiers
import UIKit

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
        // Order chats by most recent activity (iMessage-style).
        // `conversations` is already grouped by peer; take the last
        // message's timestamp and sort descending.  Peers with no
        // messages in the dict (shouldn't happen given chatPeerIds is
        // message-derived) fall to the bottom in insertion order.
        // Archived peers are filtered out — they live in
        // `archivedDirectPeerIds` after the user toggles
        // "Hide from Chat List" in `ConversationDetailView`.
        client.chatPeerIds
            .subtracting([""])
            .subtracting(client.archivedDirectPeerIds)
            .sorted { a, b in
                let lastA = conversations[a]?.last?.timestamp ?? .distantPast
                let lastB = conversations[b]?.last?.timestamp ?? .distantPast
                return lastA > lastB
            }
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
                            // Trailing swipe: wipe the group transcript.
                            // Leaves the group's roster / avatar intact on
                            // the sending side; the user can still rejoin
                            // if someone re-messages them.  "Leave Group"
                            // (separate action) handles the network-side
                            // departure signal.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    client.deleteChat(peerId: group.id)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
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
                                // Phase 3d: leading swipe opens the
                                // thread editor (per-chat mute / archive
                                // / delete).  Person editing lives one
                                // drill-in deeper via "View Contact".
                                NavigationLink {
                                    ConversationDetailView(client: client, peerId: peerId)
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
            .overlay(alignment: .bottom) {
                // Transient toast for core status events — group-send
                // failures, relay give-up, etc.  Styled close to the
                // desktop toast; auto-dismisses on a timer.
                if let msg = client.toastMessage, !msg.isEmpty {
                    Text(msg)
                        .font(.footnote)
                        .foregroundStyle(.primary)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .background(.thickMaterial, in: Capsule())
                        .overlay(Capsule().stroke(.quaternary, lineWidth: 1))
                        .padding(.bottom, 24)
                        .padding(.horizontal, 20)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .task(id: msg) {
                            try? await Task.sleep(for: .seconds(3))
                            if client.toastMessage == msg {
                                client.toastMessage = nil
                            }
                        }
                }
            }
            .animation(.easeInOut(duration: 0.25), value: client.toastMessage)
            .navigationTitle("Chats")
            .toolbar {
                // Leading cluster (left-to-right): identity-shaped
                // affordances, grouped together so the user can see
                // "who am I" + "who do I know" in one glance.
                //   person.crop.circle (my key)
                //   person.2 (contacts list)
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showMyKey = true
                    } label: {
                        Image(systemName: "person.crop.circle")
                    }
                    .accessibilityLabel("My key")
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showContacts = true
                    } label: {
                        Image(systemName: "person.2")
                    }
                    .accessibilityLabel("Contacts")
                }
                // Trailing cluster, left-to-right: connection +
                // configuration + creation actions.
                //   wifi (status)
                //   gear (settings)
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
                AddContactSheet(client: client,
                                newContactId: $newContactId,
                                onOpenChat: { peerId in
                                    // Sheet has already dismissed itself
                                    // on Chat — defer a tick so the main
                                    // stack push doesn't collide with the
                                    // sheet slide animation.
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                                        client.pendingDirectChatPeerId = peerId
                                    }
                                })
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
                ContactsListView(client: client, onOpenChat: { peerId in
                    // Dismiss the contacts sheet, then ask the main
                    // stack to push the peer's chat.  The small delay
                    // gives the sheet dismissal time to settle so the
                    // nav animation isn't stomped on by the slide.
                    showContacts = false
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                        client.pendingDirectChatPeerId = peerId
                    }
                })
            }
            // Any view in the app can drop a peerId into
            // `client.pendingDirectChatPeerId` to request a direct-chat
            // push on the main stack.  We clear the binding when the
            // destination is consumed so the same peer can be routed
            // to again later.
            .navigationDestination(item: Binding(
                get: { client.pendingDirectChatPeerId },
                set: { client.pendingDirectChatPeerId = $0 }
            )) { peerId in
                ConversationView(client: client, peerId: peerId)
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
            Spacer()
            if client.unreadChatIds.contains(group.id) {
                Circle()
                    .fill(.blue)
                    .frame(width: 10, height: 10)
                    .accessibilityLabel("Unread messages")
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
            // Blue "unread" dot — iMessage-style.  Cleared when the
            // user opens the thread (ConversationView.onAppear).
            if client.unreadChatIds.contains(peerId) {
                Circle()
                    .fill(.blue)
                    .frame(width: 10, height: 10)
                    .accessibilityLabel("Unread messages")
            }
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
    /// Invoked when the user taps Chat.  The parent dismisses this
    /// sheet and pushes ConversationView on its own navigation stack,
    /// matching the ContactsListView flow — otherwise the conversation
    /// would render trapped inside the sheet.
    var onOpenChat: ((String) -> Void)? = nil
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
                        // Jump straight into a conversation — no
                        // address-book entry is created.  If the user
                        // wants the peer in their contacts, they can
                        // set a nickname from the chat's info view.
                        let target = trimmed
                        newContactId = ""
                        dismiss()
                        onOpenChat?(target)
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

// MARK: - Contact detail (person-only editor)
//
// Phase 3d: this view edits a single row in the `contacts` table —
// strictly person-level state.  Anything thread-shaped (per-chat
// mute, archive, delete-history) lives in `ConversationDetailView`
// (1:1) or `GroupDetailView` (groups) — those navigate INTO this view
// when the user wants to inspect a specific peer.
//
// Reachable from:
//   • ContactsListView — tapping a row in the address book
//   • ConversationDetailView — "View Contact" drill-in for a 1:1 thread
//   • GroupDetailView — tapping a member row in a group's roster
//
// Identity-fingerprint surface lives here too — verify / unverify and
// the 60-digit safety number stay person-scoped because they identify
// the underlying key, not any particular thread.

struct ContactDetailView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String

    /// Provided when this view is reached from inside a sheet (e.g.
    /// ContactsListView).  Calling it lets the parent dismiss the
    /// sheet and push ConversationView on the main navigation stack
    /// instead of trapping the user inside the sheet's own stack.
    /// When nil, "Send Message" falls back to a local NavigationLink
    /// push — correct for non-sheet call sites.
    var onOpenChat: ((String) -> Void)? = nil

    @Environment(\.dismiss) private var dismiss
    // Verification dialogs (Unverify) live inside SafetyNumberView,
    // which owns its own @State for that confirm.
    @State private var confirmRemove = false
    @State private var confirmBlock = false
    @State private var confirmReset = false
    @State private var nicknameDraft = ""
    @State private var showComposeSheet = false

    private var trust: P2PPeerTrust { client.peerTrust(for: peerId) }
    private var keyChanged: Bool   { client.keyChanges[peerId] != nil }
    private var isBlocked: Bool    { client.isBlocked(peerId: peerId) }

    /// True when any 1:1 message with this peer lives in the local
    /// transcript — either side of the echo counts.  Drives whether
    /// "Send Message" jumps straight to the existing thread or opens
    /// a compose sheet to start a fresh one.
    private var hasChat: Bool {
        client.messages.contains { $0.from == peerId || $0.to == peerId }
    }

    /// True when this peer is in the address book.  When false, most
    /// person-level fields are read-only and the destructive Remove /
    /// Block actions are hidden — the user has to "Add Contact" first
    /// (a separate compose-an-entry flow) before editing nickname /
    /// person-mute / block on a stranger.
    private var inAddressBook: Bool {
        client.knownPeerContacts.contains(peerId)
    }

    var body: some View {
        Form {
            headerSection
            sendMessageSection
            if inAddressBook {
                contactFieldsSections
            } else {
                addContactSection
            }
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
            SafetyNumberView(client: client, peerId: peerId)
            sessionAndBlockSection
            if inAddressBook {
                Section {
                    Button("Remove from Address Book", role: .destructive) {
                        confirmRemove = true
                    }
                } footer: {
                    Text("Removes the contact entry only. Message history with this person is not affected.")
                }
            }
        }
        .navigationTitle("Contact Info")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            nicknameDraft = client.contactNicknames[peerId] ?? ""
        }
        .confirmationDialog("Remove from Address Book?",
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
        .sheet(isPresented: $showComposeSheet) {
            ComposeFirstMessageSheet(
                peerName: client.displayName(for: peerId),
                onSend: { text in
                    client.sendText(to: peerId, text: text)
                    showComposeSheet = false
                    // Let the compose sheet finish dismissing, then
                    // route to the freshly-created conversation in the
                    // main stack (callback is only nil from non-sheet
                    // call sites, which don't need compose anyway).
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                        onOpenChat?(peerId)
                    }
                })
        }
    }

    // MARK: - Sections (split for type-checker speed + readability)

    /// Header — circular avatar + display name + status.  Renders
    /// the peer-published avatar when one is on hand, otherwise falls
    /// back to a colored disc with two-letter initials.  Avatar is
    /// view-only on iOS today (set by the peer, not the user).
    @ViewBuilder private var headerSection: some View {
        Section {
            HStack(spacing: 16) {
                ContactAvatarThumbnail(
                    avatarB64: client.peerAvatars[peerId]?.avatarB64,
                    fallbackInitials: String(peerId.prefix(2)).uppercased(),
                    size: 56)
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
    }

    /// "Send Message" — entry point from the contact card.  Chats are
    /// message-history-only (no longer auto-include address-book
    /// contacts), so without this link an explicit contact with no
    /// prior chat would be unreachable from the contacts list.  Two
    /// shapes:
    ///   • In the contacts-sheet context (onOpenChat != nil):
    ///     existing chat → dismiss-and-push via the callback;
    ///     no chat → open a compose sheet to author the first
    ///     message, then dismiss-and-push.
    ///   • Otherwise (opened from the chat list's own stack):
    ///     a plain NavigationLink is correct — we're already in
    ///     the main stack.
    @ViewBuilder private var sendMessageSection: some View {
        // Only renders when the caller passed `onOpenChat` — i.e. the
        // user reached this view from a context where opening the chat
        // is meaningful (ContactsListView in a sheet, or a group
        // member-row tap where the user wants to DM).  When reached
        // via "View Contact" from inside a 1:1 conversation editor we
        // skip the button entirely — they're already in that chat.
        if let onOpenChat {
            Section {
                Button {
                    if hasChat {
                        onOpenChat(peerId)
                    } else {
                        showComposeSheet = true
                    }
                } label: {
                    Label("Send Message", systemImage: "bubble.left")
                }
            }
        }
    }

    /// Editable fields — only shown for peers that are in the address
    /// book.  Strangers see the read-only header + "Add Contact"
    /// affordance instead.
    @ViewBuilder private var contactFieldsSections: some View {
        // Name (user-editable, local-only).  Stored in the
        // contacts.name column; same field the rest of the app
        // reads via `displayName(for:)`.
        Section {
            TextField("Add a name", text: $nicknameDraft)
                .textInputAutocapitalization(.words)
                .autocorrectionDisabled()
                .submitLabel(.done)
                .onSubmit {
                    client.setNickname(peerId: peerId, nickname: nicknameDraft)
                }
        } header: {
            Text("Name")
        } footer: {
            Text("Only visible on this device. The peer can't see what you've named them.")
        }

        // Person-level mute — silences notifications from this peer
        // across every chat (1:1 and groups they're in).  Per-thread
        // mute lives in ConversationDetailView / GroupDetailView.
        Section {
            Toggle(isOn: Binding(
                get: { client.isMuted(peerId: peerId) },
                set: { client.setMuted(peerId: peerId, muted: $0) }
            )) {
                Label("Mute Contact", systemImage: "bell.slash")
            }
        } footer: {
            Text("Silences notifications for this person everywhere — direct chats and any groups they're in. Use Hide Alerts on a chat to silence one thread only.")
        }
    }

    /// Strangers (peers with no contacts row) get a single Add-Contact
    /// affordance instead of the full editor.  Tapping it calls
    /// `addContact(peerId:)`, which upserts a contacts row with empty
    /// name + default flags so the view re-renders with the editable
    /// fields exposed.  No nickname is required — the user can fill
    /// it in afterwards if they want.
    @ViewBuilder private var addContactSection: some View {
        Section {
            Button {
                client.addContact(peerId: peerId)
            } label: {
                Label("Add to Address Book", systemImage: "person.badge.plus")
            }
        } footer: {
            Text("Add this person to your contacts to set a nickname, mute, or block them.")
        }
    }

    /// Reset Session wipes the ratchet so the next outbound handshake
    /// is fresh (recovery path for desync / device swap).  Block is a
    /// client-side filter on the peer's identity key — inbound DMs and
    /// file requests from a blocked key are dropped silently regardless
    /// of address-book status (a key compromise doesn't depend on
    /// having a nickname on file).  Same shape as Safety Numbers:
    /// security primitives key on the identity, not on curation state.
    @ViewBuilder private var sessionAndBlockSection: some View {
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

}

// MARK: - Safety number (shared)
//
// Phase 3f: the safety-number display + verify/unverify action lifted
// out of ContactDetailView so ConversationDetailView can show the same
// UI for stranger peers (those not yet in the address book).  Same
// reasoning as `verified_peers` being a separate table from `contacts`:
// verification is keyed on the peer's identity key, NOT on whether
// they're in your address book.  A user may verify-then-add or
// add-then-verify; both work.
//
// Renders TWO sections (so it composes inside a Form): the safety
// number itself and the verify/unverify action button.  The unverify
// confirmation dialog is also owned here so callers don't have to
// thread the @State through.

struct SafetyNumberView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String

    @State private var confirmUnverify = false

    private var trust: P2PPeerTrust { client.peerTrust(for: peerId) }

    var body: some View {
        Group {
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
    }

    /// Format the 60-digit run as "XXXXX XXXXX XXXXX ..." in 4 rows of 3.
    /// Empty payload (no session yet) gets a placeholder.
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

// MARK: - Conversation detail (1:1 thread editor)
//
// Phase 3d: this view edits a single 1:1 row in the `conversations`
// table.  It is THREAD-SCOPED, not person-scoped — tweaks here only
// affect this chat.  Person-level state (nickname, block, person-mute,
// safety number) lives in `ContactDetailView`, which the user reaches
// via the "View Contact" / "Add Contact" drill-in below.
//
// Opened from the toolbar (i) button on `ConversationView`.
//
// Mute writes to `conversations.muted` via `setConversationMuted`.
// Archive writes to `conversations.in_chat_list` via
// `dbSetConversationInChatList`; the in-memory mirror is
// `archivedDirectPeerIds`, which `ChatListView` subtracts from the
// chat list — the thread reappears the moment the user toggles it
// back off.
//
// "Delete Chat" calls `client.deleteChat(peerId:)` which cascades
// through the messages + file_transfers tables but preserves the
// contact row.

struct ConversationDetailView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String

    @Environment(\.dismiss) private var dismiss
    @State private var confirmDelete = false
    @State private var confirmResetSession = false
    @State private var confirmBlock = false

    private var inAddressBook: Bool {
        client.knownPeerContacts.contains(peerId)
    }

    /// Resolved conversation_id for this 1:1, if any.  Strangers we
    /// haven't messaged yet won't have a row — archive then becomes
    /// a no-op (nothing to hide), so we disable the toggle.
    private var conversationId: String? {
        client.directConversationIdByPeer[peerId]
    }

    /// Shared peer card layout — used either as a static header (when
    /// the peer isn't a contact) or wrapped in a NavigationLink (when
    /// they are, so SwiftUI adds the chevron and full-row tap target).
    @ViewBuilder private var peerHeader: some View {
        HStack(spacing: 16) {
            ContactAvatarThumbnail(
                avatarB64: client.peerAvatars[peerId]?.avatarB64,
                fallbackInitials: String(peerId.prefix(2)).uppercased(),
                size: 56)
            VStack(alignment: .leading, spacing: 4) {
                // Name + trust badge inline so the user can see at a
                // glance whether the safety number's been verified
                // without having to drill in.  Matches the same badge
                // ConversationView's toolbar shows.
                HStack(spacing: 6) {
                    Text(client.displayName(for: peerId))
                        .font(.headline)
                        .foregroundStyle(.primary)
                    TrustBadge(trust: client.peerTrust(for: peerId))
                }
                Text(peerId.prefix(16) + "…")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    var body: some View {
        Form {
            // ── Header — display name + key prefix ─────────────────────
            // When the peer's in the address book, the whole card is a
            // tappable NavigationLink into ContactDetailView (SwiftUI
            // adds the chevron automatically).  When they're not, the
            // card is read-only and an "Add Contact" row appears below.
            Section {
                if inAddressBook {
                    NavigationLink {
                        ContactDetailView(client: client, peerId: peerId)
                    } label: {
                        peerHeader
                    }
                } else {
                    peerHeader
                }
            }

            // ── Add Contact + per-peer security (stranger only) ────────
            // Upserts a contact row right here — once it exists,
            // `inAddressBook` flips and the header re-renders as a
            // tappable link to ContactDetailView.  We keep this
            // in-place rather than hopping to AddContactSheet so the
            // user doesn't lose their place.
            //
            // Reset Session and the safety-number / verification UI
            // also live in this stranger-only branch.  Once the peer
            // is added, all per-peer security state moves to
            // ContactDetailView (reached via the header card chevron)
            // — same principle as `verified_peers` being a separate
            // table from `contacts`: the UI follows the data layering.
            if !inAddressBook {
                // Add to Address Book stays first — it's the gate for
                // moving everything else onto ContactDetailView.
                Section {
                    Button {
                        client.addContact(peerId: peerId)
                    } label: {
                        Label("Add Contact", systemImage: "person.badge.plus")
                    }
                } footer: {
                    Text("Add this peer to your address book to set a name or persist verification across sessions.")
                }

                // Per-peer security primitives surface here for strangers
                // in the same order as ContactDetailView shows them when
                // the peer IS added: Safety Number first (verification
                // is the foundation), Reset Session + Block after.
                SafetyNumberView(client: client, peerId: peerId)

                Section {
                    Button("Reset Session") {
                        confirmResetSession = true
                    }
                    .tint(.orange)
                    Button(client.isBlocked(peerId: peerId)
                            ? "Unblock Contact" : "Block Contact",
                           role: client.isBlocked(peerId: peerId)
                                  ? .none : .destructive) {
                        confirmBlock = true
                    }
                } footer: {
                    Text("Blocked keys remain visible in your contacts list under Blocked even if you delete the chat.")
                }
            }

            // ── Hide alerts (per-thread) ───────────────────────────────
            // Distinct from ContactDetailView's "Mute this person":
            // this writes conversations.muted, which only silences
            // THIS chat.  Person-level mute reaches across threads.
            Section {
                Toggle(isOn: Binding(
                    get: { client.isMuted(peerId: peerId) },
                    set: { client.setConversationMuted(peerId: peerId, muted: $0) }
                )) {
                    Label("Hide Alerts", systemImage: "bell.slash")
                }
            } footer: {
                Text("Messages still arrive and appear in the chat. Only the notification banner is silenced.")
            }

            // ── Archive (hide from chat list) ──────────────────────────
            // `inChatList = false` removes the row from ChatListView
            // without deleting messages; flipping it back un-hides
            // immediately.  In-memory mirror is `archivedDirectPeerIds`
            // so the toggle reflects state across navigations.
            Section {
                Toggle(isOn: Binding(
                    get: { client.archivedDirectPeerIds.contains(peerId) },
                    set: { hide in
                        guard let convId = conversationId else { return }
                        _ = client.dbSetConversationInChatList(id: convId, inList: !hide)
                        if hide { client.archivedDirectPeerIds.insert(peerId) }
                        else    { client.archivedDirectPeerIds.remove(peerId) }
                    }
                )) {
                    Label("Hide from Chat List", systemImage: "eye.slash")
                }
                .disabled(conversationId == nil)
            } footer: {
                Text("Hides this thread from the main chat list without deleting messages. Toggle off to bring it back.")
            }

            // ── Destructive: wipe transcript ──────────────────────────
            // Delete Chat removes the local message history; address-
            // book entry stays intact.  Reset Session is per-peer and
            // lives on ContactDetailView for added contacts (or in the
            // unadded-stranger section above) so security actions stay
            // grouped with verification UI.
            Section {
                Button("Delete Chat", role: .destructive) {
                    confirmDelete = true
                }
            }
        }
        .navigationTitle("Chat Info")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Reset session?",
               isPresented: $confirmResetSession) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                client.resetSession(peerId: peerId)
            }
        } message: {
            Text("Wipes the encrypted session with this peer. Next message triggers a fresh handshake — the safety number will change, so you'll need to re-verify if it was confirmed.")
        }
        .alert(client.isBlocked(peerId: peerId)
               ? "Unblock this key?" : "Block this key?",
               isPresented: $confirmBlock) {
            Button("Cancel", role: .cancel) {}
            Button(client.isBlocked(peerId: peerId) ? "Unblock" : "Block",
                   role: client.isBlocked(peerId: peerId) ? .none : .destructive) {
                client.setBlocked(peerId: peerId,
                                  blocked: !client.isBlocked(peerId: peerId))
            }
        } message: {
            Text(client.isBlocked(peerId: peerId)
                 ? "Messages and files from this key will be accepted again."
                 : "Messages and files from this key will be silently dropped. The key stays in your contacts list under Blocked so you can unblock it later.")
        }
        .alert("Delete this chat?",
               isPresented: $confirmDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                client.deleteChat(peerId: peerId)
                dismiss()
            }
        } message: {
            Text("This will permanently delete the message history with this person. Their address-book entry will not be affected.")
        }
    }
}

// MARK: - Contact avatar thumbnail
// Decodes a peer-published avatar (base64 PNG/JPEG) to UIImage; falls
// back to a colored disc with the peer-id initials when no avatar has
// arrived yet.  Mirrors GroupAvatarThumbnail (in ConversationView.swift)
// but for 1:1 contacts.

struct ContactAvatarThumbnail: View {
    let avatarB64: String?
    let fallbackInitials: String
    let size: CGFloat

    private var image: UIImage? {
        guard let avatarB64,
              !avatarB64.isEmpty,
              let data = Data(base64Encoded: avatarB64),
              let img = UIImage(data: data) else { return nil }
        return img
    }

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                Circle()
                    .fill(.green)
                    .overlay {
                        Text(fallbackInitials)
                            .font(.system(size: size * 0.35, weight: .bold))
                            .foregroundStyle(.white)
                    }
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
    }
}

// MARK: - Compose first message
//
// Presented over ContactDetailView when the user taps Send Message on
// a contact they've never chatted with.  After Send, the parent
// dismisses the contacts sheet and pushes ConversationView on the main
// navigation stack so the user lands on their new chat instead of
// being stuck inside the modal.

private struct ComposeFirstMessageSheet: View {
    let peerName: String
    let onSend: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text: String = ""

    private var trimmed: String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Type your message…", text: $text, axis: .vertical)
                        .lineLimit(3...8)
                } header: {
                    Text("First message to \(peerName)")
                } footer: {
                    Text("This starts the conversation. After sending, you'll jump into the chat.")
                }
            }
            .navigationTitle("New Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        guard !trimmed.isEmpty else { return }
                        onSend(trimmed)
                    }
                    .disabled(trimmed.isEmpty)
                }
            }
        }
        .presentationDetents([.medium])
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
    /// Fired when the user picks "Send Message" on a contact with an
    /// existing chat (or after composing the first message of a new
    /// one).  ChatListView dismisses the contacts sheet and routes to
    /// the appropriate ConversationView on its own navigation stack.
    var onOpenChat: ((String) -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var showExport = false
    @State private var showImport = false
    @State private var importAlert: ImportAlert?

    // Contacts = address book, distinct from Chats (which unions
    // contacts with any peer who's messaged us).  See `chatPeerIds`
    // vs `contactPeerIds` in Peer2PearClient.  Blocked peers are
    // pulled OUT into their own section so the main list reads as
    // "people I want to talk to" not "everyone the data layer knows
    // about".
    private var unblockedPeerIds: [String] {
        client.contactPeerIds.subtracting([""])
            .filter { !client.blockedPeerIds.contains($0) }
            .sorted()
    }

    /// Blocked keys.  Surfaced here (not just inside ContactDetailView)
    /// so the user has a recovery path after blocking a stranger and
    /// then deleting the chat — without this, the blocked key would
    /// be invisible despite still filtering inbound messages.
    private var blockedPeerIds: [String] {
        client.blockedPeerIds.subtracting([""]).sorted()
    }

    var body: some View {
        NavigationStack {
            Group {
                if unblockedPeerIds.isEmpty && blockedPeerIds.isEmpty {
                    ContentUnavailableView(
                        "No contacts yet",
                        systemImage: "person.2",
                        description: Text("Use the + button on the chats screen to add a contact.")
                    )
                } else {
                    List {
                        if !unblockedPeerIds.isEmpty {
                            Section {
                                ForEach(unblockedPeerIds, id: \.self) { peerId in
                                    NavigationLink {
                                        ContactDetailView(client: client,
                                                           peerId: peerId,
                                                           onOpenChat: onOpenChat)
                                    } label: {
                                        ChatRow(client: client, peerId: peerId,
                                                preview: client.peerTrust(for: peerId) == .verified
                                                    ? "Verified"
                                                    : nil)
                                    }
                                }
                                // Swipe-to-delete is a shortcut for the
                                // ContactDetail Remove button — iOS
                                // surfaces its own tap-to-confirm pill.
                                .onDelete { offsets in
                                    for idx in offsets {
                                        client.removeContact(peerId: unblockedPeerIds[idx])
                                    }
                                }
                            }
                        }
                        if !blockedPeerIds.isEmpty {
                            Section {
                                ForEach(blockedPeerIds, id: \.self) { peerId in
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(client.displayName(for: peerId))
                                                .font(.body)
                                            Text(peerId.prefix(16) + "…")
                                                .font(.caption2)
                                                .foregroundStyle(.secondary)
                                                .textSelection(.enabled)
                                        }
                                        Spacer()
                                        Button("Unblock") {
                                            client.setBlocked(peerId: peerId,
                                                              blocked: false)
                                        }
                                        .buttonStyle(.bordered)
                                        .tint(.blue)
                                    }
                                }
                            } header: {
                                Text("Blocked")
                            } footer: {
                                Text("Messages and files from these keys are silently dropped. Tap Unblock to start accepting them again.")
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
                        .disabled(unblockedPeerIds.isEmpty)
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
