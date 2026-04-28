import SwiftUI
import UniformTypeIdentifiers
import PhotosUI
import UIKit

struct ConversationView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    @State private var messageText = ""
    @State private var showFilePicker = false
    @State private var activeFileRequest: P2PFileRequest?

    private var peerMessages: [P2PMessage] {
        // Both directions: inbound (from == peerId) + outbound echoes
        // (from == myPeerId && to == peerId).  Without the echo side
        // the sender's own bubbles would never render — tapping Send
        // would just clear the text field with no visible feedback.
        client.messages.filter { msg in
            msg.from == peerId
                || (msg.from == client.myPeerId && msg.to == peerId)
        }
    }

    /// Transfers with this peer — inbound or outbound, in-flight or
    /// terminal.  The unified `transfers` dict is keyed by transferId;
    /// counterparty filter is uniform across directions.
    private var activeTransfers: [P2PTransferRecord] {
        client.transfers.values
            .filter { $0.peerId == peerId }
            .sorted(by: { $0.timestamp > $1.timestamp })
    }

    private var pendingRequestsForPeer: [P2PFileRequest] {
        client.pendingFileRequests.filter { $0.from == peerId }
    }

    var body: some View {
        VStack(spacing: 0) {
            if let change = client.keyChanges[peerId] {
                KeyChangeBanner(client: client, peerId: peerId, change: change)
            }
            messagesScroll
            if !activeTransfers.isEmpty {
                Divider()
                transfersStrip
            }
            Divider()
            inputBar
        }
        .navigationTitle(client.displayName(for: peerId))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbarContent }
        .fileImporter(isPresented: $showFilePicker,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: false) { result in
            handleFilePick(result: result)
        }
        .onChange(of: pendingRequestsForPeer.count) {
            activeFileRequest = pendingRequestsForPeer.first
        }
        .onAppear {
            activeFileRequest = pendingRequestsForPeer.first
            client.enterChat(id: peerId)
            // Tier 1 PQ — kick an async bundle fetch so the
            // peer's ML-KEM-768 pub is in our DB by the time the
            // user types + sends msg1.  ChatController dedupes
            // when already-cached / in-flight.  Falls back to the
            // existing in-band kem_pub_announce path if the
            // fetch hasn't returned by send time.
            client.requestIdentityBundleFetch(peerId)
        }
        .onDisappear {
            client.exitChat(id: peerId)
        }
        .sheet(item: $activeFileRequest) { req in
            FileRequestSheet(client: client, request: req) {
                activeFileRequest = pendingRequestsForPeer
                    .first(where: { $0.id != req.id })
            }
        }
    }

    // MARK: - Body fragments (split to keep the type-checker happy)

    @ViewBuilder private var messagesScroll: some View {
        ChatMessagesScroll(messages: peerMessages) { msg in
            MessageBubble(client: client,
                           message: msg,
                           isMine: msg.from == client.myPeerId)
                .contextMenu {
                    Button {
                        UIPasteboard.general.string = msg.text
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    Button(role: .destructive) {
                        client.deleteMessage(chatKey: peerId, msgId: msg.id)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
        }
    }

    @ViewBuilder private var transfersStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(activeTransfers) { t in
                    FileTransferRow(client: client, transfer: t)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
        .background(.thinMaterial)
    }

    @ViewBuilder private var inputBar: some View {
        ChatInputBar(text: $messageText) {
            showFilePicker = true
        } onSend: {
            guard !messageText.isEmpty else { return }
            client.sendText(to: peerId, text: messageText)
            messageText = ""
        }
    }

    @ToolbarContentBuilder private var toolbarContent: some ToolbarContent {
        // Trust marker lives beside the display name; the trailing
        // slot is the always-visible info button so the user can get
        // to thread settings regardless of verification state.
        // Phase 3d: this opens the THREAD editor (1:1 conversation row),
        // not the person editor — the conv editor drills into
        // `ContactDetailView` via "View Contact" when the user wants
        // to manage the person.
        ToolbarItem(placement: .principal) {
            HStack(spacing: 6) {
                Text(client.displayName(for: peerId))
                    .font(.headline)
                TrustBadge(trust: client.peerTrust(for: peerId))
            }
        }
        ToolbarItem(placement: .topBarTrailing) {
            NavigationLink {
                ConversationDetailView(client: client, peerId: peerId)
            } label: {
                Image(systemName: "info.circle")
                    .foregroundStyle(.blue)
            }
        }
    }

    // Dispatch the selected file into the core.  The file stays at its
    // original path — core streams chunks from there.
    private func handleFilePick(result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        // iOS hands us a security-scoped URL for user-picked files; start
        // accessing before reading the path and stop afterwards.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        _ = client.sendFile(to: peerId,
                            fileName: url.lastPathComponent,
                            filePath: url.path)
    }
}

// MARK: - Group conversation
// Mirrors ConversationView for 1:1 chats: scroll-of-messages + input bar.
// Group-specific affordances: show sender name above each bubble (so
// members can tell messages apart), toolbar button to see the roster.
//
// Outbound messages use `client.sendGroupText` which fans out to every
// member in the group's roster.  Inbound messages land in
// `client.groupMessages` via the on_group_message callback — we filter
// to this groupId and render.

struct GroupConversationView: View {
    @ObservedObject var client: Peer2PearClient
    let groupId: String
    @State private var messageText = ""
    @State private var showInfo = false
    @State private var showFilePicker = false
    @State private var dismissedLostEventId: UUID?

    private var group: P2PGroup? { client.groups[groupId] }

    private var groupMessages: [P2PGroupMessage] {
        client.groupMessages.filter { $0.groupId == groupId }
    }

    /// pv=2: any blocked senders for this group → banner state.
    /// We dedupe by senderPeerId; multiple stalls on the same sender
    /// just update the range in place via the @Published map.
    private var blockedSenders: [(sender: String, range: Peer2PearClient.BlockedRange)] {
        guard let map = client.groupBlockedStreams[groupId] else { return [] }
        return map.map { (sender: $0.key, range: $0.value) }
                  .sorted { $0.sender < $1.sender }
    }

    /// pv=2: oldest unhandled lost-messages event for this group, if any.
    private var pendingLostEvent: Peer2PearClient.LostMessagesEvent? {
        client.groupLostMessages
            .first { $0.groupId == groupId && $0.id != dismissedLostEventId }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Per-sender blocked banner.  Surfaces the gap range so
            // power users can see "waiting for messages 47–52 from X."
            // ChatController already fired a gap_request to the
            // sender; this is purely informational.
            if !blockedSenders.isEmpty {
                blockedBanner
            }
            messagesScroll
            Divider()
            inputBar
        }
        .alert(
            "Some messages were lost",
            isPresented: Binding(
                get: { pendingLostEvent != nil },
                set: { if !$0 { dismissedLostEventId = pendingLostEvent?.id } }
            ),
            presenting: pendingLostEvent
        ) { _ in
            Button("OK", role: .cancel) {
                if let ev = pendingLostEvent {
                    dismissedLostEventId = ev.id
                    client.groupLostMessages.removeAll { $0.id == ev.id }
                }
            }
        } message: { ev in
            Text("\(ev.count) message\(ev.count == 1 ? "" : "s") from this group could not be delivered. They were sent before the encrypted session was reset and can no longer be recovered.")
        }
        .navigationTitle(group?.name ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { client.enterChat(id: groupId) }
        .onDisappear { client.exitChat(id: groupId) }
        .toolbar {
            // Phase 3d: (i) opens the GROUP editor (rename / avatar /
            // mute / archive / member list / delete).  Member rows in
            // the editor drill into ContactDetailView for per-person
            // editing, mirroring the 1:1 toolbar's convention.
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showInfo = true
                } label: {
                    Image(systemName: "info.circle")
                        .foregroundStyle(.blue)
                }
                .disabled(group == nil)
            }
        }
        .sheet(isPresented: $showInfo) {
            if let group {
                GroupDetailView(client: client, group: group,
                                onOpenChat: { peerId in
                                    // Close the editor, then hand the
                                    // request off to ChatListView's
                                    // navigationDestination.  Small
                                    // delay so the sheet finishes
                                    // sliding before the push starts.
                                    showInfo = false
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                                        client.pendingDirectChatPeerId = peerId
                                    }
                                })
            }
        }
        .fileImporter(isPresented: $showFilePicker,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: false) { result in
            handleFilePick(result: result)
        }
    }

    /// Banner surfaced at the top of the conversation while ANY
    /// sender's stream is blocked at a gap.  ChatController has
    /// already fired gap_request(s); the banner is purely
    /// informational ("waiting for X's missing messages...").  Once
    /// each gap fills, the v2 dispatcher delivers the drained
    /// messages and the on_group_message handler clears the entry —
    /// the banner shrinks / disappears automatically.
    @ViewBuilder private var blockedBanner: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(blockedSenders, id: \.sender) { entry in
                HStack(spacing: 8) {
                    Image(systemName: "hourglass")
                        .foregroundStyle(.orange)
                    let label = entry.range.from == entry.range.to
                        ? "Waiting for message \(entry.range.from)"
                        : "Waiting for messages \(entry.range.from)–\(entry.range.to)"
                    Text("\(label) from \(senderShortName(entry.sender))…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 6)
        .padding(.horizontal, 12)
        .background(Color(.systemBackground).opacity(0.95))
        .overlay(
            Rectangle()
                .frame(height: 0.5)
                .foregroundStyle(Color(.separator)),
            alignment: .bottom
        )
    }

    /// Best display name for a peer ID.  Delegates to the single
    /// source-of-truth helper on Peer2PearClient (nickname → peer-
    /// published display name → key prefix).
    private func senderShortName(_ peerId: String) -> String {
        client.displayName(for: peerId)
    }

    @ViewBuilder private var messagesScroll: some View {
        ChatMessagesScroll(messages: groupMessages) { msg in
            GroupMessageBubble(client: client,
                                message: msg,
                               isMine: msg.from == client.myPeerId)
                .contextMenu {
                    Button {
                        UIPasteboard.general.string = msg.text
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    Button(role: .destructive) {
                        client.deleteMessage(chatKey: groupId, msgId: msg.id)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
        }
    }

    @ViewBuilder private var inputBar: some View {
        ChatInputBar(text: $messageText, enabled: group != nil) {
            showFilePicker = true
        } onSend: {
            send()
        }
    }

    private func handleFilePick(result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first,
              let group else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        _ = client.sendGroupFile(groupId: group.id,
                                 groupName: group.name,
                                 memberPeerIds: group.memberIds,
                                 fileName: url.lastPathComponent,
                                 filePath: url.path)
    }

    private func send() {
        guard let group, !messageText.isEmpty else { return }
        // Mint the msgId BEFORE the C call so the protocol envelope
        // and the local echo bubble share the id — that's what lets
        // on_send_failed mark the right group bubble after retry-
        // exhaustion.  Same pattern as the 1:1 sendText path.
        let msgId = UUID().uuidString
        client.sendGroupText(groupId: group.id,
                             groupName: group.name,
                             memberPeerIds: group.memberIds,
                             text: messageText,
                             msgId: msgId)
        // Local echo — the core doesn't loop-back our own group sends
        // through on_group_message, so we append ourselves to keep the
        // transcript in-sync with what recipients see.
        let echo = P2PGroupMessage(
            id: msgId,
            from: client.myPeerId,
            groupId: group.id,
            groupName: group.name,
            members: group.memberIds,
            text: messageText,
            timestamp: Date()
        )
        client.groupMessages.append(echo)
        // Bump lastActivity so the group floats to the top of the list.
        var g = group
        g.lastActivity = Date()
        client.groups[group.id] = g
        // Persist: bump the group's conversation row + insert the
        // echo message.  v3: groups live in conversations(kind=group),
        // and conv_id == group_id by design.  senderId == "" is the
        // outbound convention; senderName stays empty since the
        // sender (us) doesn't ship a self-declared name.
        client.dbSaveConversation(Peer2PearClient.DBConversation(
            id:              g.id,
            kind:            .group,
            groupName:       g.name,
            groupAvatarB64:  client.groupAvatars[g.id] ?? "",
            muted:           client.isMuted(peerId: g.id),
            lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
            inChatList:      true))
        client.dbSaveMessage(conversationId: g.id, message: Peer2PearClient.DBMessage(
            sent:          true,
            text:          echo.text,
            timestampSecs: Int64(echo.timestamp.timeIntervalSince1970),
            msgId:         echo.id,
            senderId:      "",
            senderName:    ""))
        messageText = ""
    }
}

// Group message bubble — adds a sender-label row above the bubble so
// members can attribute messages.  Own messages skip the label.

struct GroupMessageBubble: View {
    @ObservedObject var client: Peer2PearClient
    let message: P2PGroupMessage
    let isMine: Bool

    @State private var showFailedActions = false

    /// Outbound only — same semantics as MessageBubble's check.
    /// All N fan-out envelopes share the bubble's msgId, so the
    /// FIRST envelope's retry-exhaustion is what flips this true.
    private var sendFailed: Bool {
        isMine && client.failedMessageIds.contains(message.id)
    }

    var body: some View {
        HStack(alignment: .bottom, spacing: 6) {
            if isMine { Spacer() }

            if sendFailed {
                Button {
                    showFailedActions = true
                } label: {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.body)
                        .foregroundStyle(.red)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Group message failed to send")
            }

            VStack(alignment: isMine ? .trailing : .leading, spacing: 2) {
                if !isMine {
                    Text(message.from.prefix(8) + "...")
                        .font(.caption2.bold())
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 4)
                }
                Text(message.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(isMine ? Color.green : Color(.systemGray5))
                    .foregroundStyle(isMine ? .white : .primary)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .opacity(sendFailed ? 0.65 : 1.0)

                if sendFailed {
                    Text("Not delivered")
                        .font(.caption2)
                        .foregroundStyle(.red)
                } else {
                    Text(message.timestamp, style: .time)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if !isMine { Spacer() }
        }
        .confirmationDialog(
            "Group message not delivered",
            isPresented: $showFailedActions,
            titleVisibility: .visible
        ) {
            Button("Try Again") {
                client.retryFailedGroupMessage(
                    messageId:     message.id,
                    groupId:       message.groupId,
                    groupName:     message.groupName,
                    memberPeerIds: message.members,
                    text:          message.text)
            }
            Button("Delete", role: .destructive) {
                client.deleteMessage(chatKey: message.groupId, msgId: message.id)
                client.failedMessageIds.remove(message.id)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Couldn't reach the relay after retrying for ~30 seconds.  At least one recipient didn't get this message.")
        }
    }
}

// MARK: - Group detail (group thread editor)
//
// Phase 3d: the group equivalent of `ConversationDetailView`.  Mutates
// the `conversations` row for a group (kind = .group) plus the
// `conversation_members` roster.  Sheet-shaped because the editor's
// own NavigationStack hosts member drill-ins to `ContactDetailView`
// without colliding with the chat-list nav stack underneath.
//
// Group fields:
//   • name (broadcast via renameGroup)
//   • avatar (broadcast via sendGroupAvatar)
//   • thread mute (conversations.muted via setMuted — for groups,
//     setMuted already routes to the conv row)
//   • archive (conversations.in_chat_list)
//   • member roster (add via AddGroupMemberSheet, remove inline)
//
// Destructive actions:
//   • Leave Group — broadcast network-side leave; preserves local
//     history.  Surfaced as a button so the user can step away from
//     the conversation without nuking it.
//   • Delete Group — full local cascade via deleteChat; mirrors the
//     trailing-swipe Delete on ChatListView with an explicit prompt.

struct GroupDetailView: View {
    @ObservedObject var client: Peer2PearClient
    let group: P2PGroup
    /// Relayed to ContactDetailView when the user opens a member's
    /// card.  Tapping Send Message inside that card invokes this; the
    /// parent (GroupConversationView) dismisses the sheet and routes
    /// through `client.pendingDirectChatPeerId`.
    var onOpenChat: ((String) -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var showRename = false
    @State private var newName = ""
    @State private var confirmLeave = false
    @State private var confirmDelete = false
    @State private var confirmResetSessions = false
    @State private var avatarSelection: PhotosPickerItem?
    @State private var showAddMember = false
    @State private var isEditing = false

    /// Non-self members — self is always rendered separately at the top
    /// and can never be the target of "remove member".  Filtering here
    /// keeps the swipe-actions + ForEach indexing simple.
    private var otherMembers: [String] {
        group.memberIds.filter { $0 != client.myPeerId }
    }

    var body: some View {
        NavigationStack {
            List {
                avatarSection
                membersSection
                threadActionsSection
                destructiveSection
            }
            .navigationTitle(group.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(isEditing ? "Done" : "Edit") {
                        isEditing.toggle()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .alert("Rename Group", isPresented: $showRename) {
                TextField("Group name", text: $newName)
                    .autocapitalization(.words)
                Button("Cancel", role: .cancel) {}
                Button("Rename") {
                    let trimmed = newName.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty else { return }
                    _ = client.renameGroup(groupId: group.id,
                                           newName: trimmed,
                                           memberPeerIds: group.memberIds)
                }
            } message: {
                Text("Other members will see the new name.")
            }
            .alert("Reset sessions with all members?",
                   isPresented: $confirmResetSessions) {
                Button("Cancel", role: .cancel) {}
                Button("Reset", role: .destructive) {
                    let me = client.myPeerId
                    for member in group.memberIds where member != me {
                        client.resetSession(peerId: member)
                    }
                }
            } message: {
                Text("Wipes the encrypted session with every member of this group. Each member's safety number will change — re-verify any you'd confirmed previously.")
            }
            .alert("Leave this group?",
                   isPresented: $confirmLeave) {
                Button("Cancel", role: .cancel) {}
                Button("Leave", role: .destructive) {
                    _ = client.leaveGroup(groupId: group.id,
                                          groupName: group.name,
                                          memberPeerIds: group.memberIds)
                    dismiss()
                }
            } message: {
                Text("Other members will see you left. Your local transcript stays on this device — use Delete Group to wipe it.")
            }
            .alert("Delete this group?",
                   isPresented: $confirmDelete) {
                Button("Cancel", role: .cancel) {}
                Button("Delete", role: .destructive) {
                    client.deleteChat(peerId: group.id)
                    dismiss()
                }
            } message: {
                Text("This will permanently delete the group and its message history on this device. Other members are not notified.")
            }
            .sheet(isPresented: $showAddMember) {
                AddGroupMemberSheet(client: client, group: group)
            }
            .onChange(of: avatarSelection) {
                Task { await handleAvatarPicked(avatarSelection) }
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder private var avatarSection: some View {
        Section {
            HStack {
                Spacer()
                VStack(spacing: 8) {
                    GroupAvatarThumbnail(
                        avatarB64: client.groupAvatars[group.id],
                        fallbackInitials: String(group.name.prefix(2)).uppercased(),
                        size: 72)
                    PhotosPicker(selection: $avatarSelection,
                                 matching: .images) {
                        Text("Change Group Photo")
                            .font(.caption)
                    }
                    Button {
                        newName = group.name
                        showRename = true
                    } label: {
                        Label("Rename Group", systemImage: "pencil")
                            .font(.caption)
                    }
                }
                Spacer()
            }
            .listRowBackground(Color.clear)
        }
    }

    @ViewBuilder private var membersSection: some View {
        Section {
            // Self pinned at the top so users always recognise themselves.
            HStack {
                Image(systemName: "person.fill").foregroundStyle(.secondary)
                Text("You")
                Spacer()
            }
            ForEach(otherMembers, id: \.self) { peerId in
                // Tap a member to open their contact info.  Inside the
                // detail view, "Send Message" calls `onOpenChat`, which
                // the parent uses to dismiss this sheet and hand the
                // push off to the root ChatListView stack.  The detail
                // view auto-handles strangers via its inAddressBook
                // gate (Add-to-Address-Book affordance instead of
                // editable fields).
                NavigationLink {
                    ContactDetailView(client: client, peerId: peerId,
                                       onOpenChat: onOpenChat)
                } label: {
                    HStack {
                        Image(systemName: "person").foregroundStyle(.secondary)
                        Text(client.displayName(for: peerId))
                        Spacer()
                        if client.peerPresence[peerId] == true {
                            Circle().fill(.green).frame(width: 8, height: 8)
                        }
                        TrustBadge(trust: client.peerTrust(for: peerId))
                    }
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                    if isEditing {
                        Button(role: .destructive) {
                            removeMember(peerId)
                        } label: {
                            Label("Remove", systemImage: "person.badge.minus")
                        }
                    }
                }
            }
            if isEditing {
                Button {
                    showAddMember = true
                } label: {
                    Label("Add Member", systemImage: "person.badge.plus")
                        .foregroundStyle(.blue)
                }
            }
        } header: {
            Text("Members (\(group.memberIds.count))")
        } footer: {
            if isEditing {
                Text("Swipe a member to remove them.  Changes are broadcast immediately to the rest of the group.")
                    .font(.caption)
            }
        }
    }

    /// Per-thread toggles — mute + archive.  For groups, `setMuted`
    /// already routes to the conv row (peerId == groupId == convId).
    /// Archive writes `conversations.in_chat_list = 0` and removes
    /// the @Published `groups` entry so the row drops out of the
    /// chat list immediately.  The DB row stays so the load-time
    /// filter (which honours `inChatList`) keeps the group hidden
    /// across relaunches — no `dbDeleteConversation` here, that's
    /// the Delete Group path.
    @ViewBuilder private var threadActionsSection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { client.isMuted(peerId: group.id) },
                set: { client.setMuted(peerId: group.id, muted: $0) }
            )) {
                Label("Hide Alerts", systemImage: "bell.slash")
            }
            Toggle(isOn: Binding(
                get: { false },  // Active groups always render here.
                set: { hide in
                    guard hide else { return }
                    _ = client.dbSetConversationInChatList(id: group.id, inList: false)
                    // Drop the @Published group so ChatListView re-renders
                    // without it.  The conv row remains on disk for the
                    // un-archive path (next inbound message).
                    client.groups.removeValue(forKey: group.id)
                    dismiss()
                }
            )) {
                Label("Hide from Chat List", systemImage: "eye.slash")
            }
        } header: {
            Text("This Chat")
        } footer: {
            Text("Hide Alerts silences notifications for this group only. Hide from Chat List removes it from the main list without losing the message history.")
        }
    }

    /// Three actions, in order of severity:
    ///   • Reset Sessions — wipes the pairwise DR ratchet with every
    ///     member.  Causally-Linked Pairwise has no group session; we
    ///     iterate per-member.  Each member's safety number changes,
    ///     so re-verify any you'd previously confirmed.
    ///   • Leave — network-visible departure (other members see the
    ///     leave marker).  Local history is preserved.
    ///   • Delete — full local cascade.  Wipes messages + member
    ///     roster + group avatar on this device.  Other members are
    ///     NOT notified — use Leave first if you want them to know
    ///     you left.
    @ViewBuilder private var destructiveSection: some View {
        Section {
            Button {
                confirmResetSessions = true
            } label: {
                Label("Reset Sessions", systemImage: "arrow.clockwise.shield")
            }
            .tint(.orange)
            Button(role: .destructive) {
                confirmLeave = true
            } label: {
                Label("Leave Group", systemImage: "rectangle.portrait.and.arrow.right")
            }
            Button(role: .destructive) {
                confirmDelete = true
            } label: {
                Label("Delete Group", systemImage: "trash")
            }
        } footer: {
            Text("Leave Group tells other members you left but keeps your local history. Delete Group removes everything from this device permanently.")
        }
    }

    // MARK: - Handlers

    private func removeMember(_ peerId: String) {
        let newRoster = group.memberIds.filter { $0 != peerId }
        _ = client.updateGroupMembers(groupId: group.id,
                                       groupName: group.name,
                                       memberPeerIds: newRoster)
    }

    /// Downscale to 256×256, JPEG-encode, base64.  Keeps group avatars
    /// under ~20 KB so they fit comfortably in a single sealed envelope
    /// and don't dominate the relay's recipient-rate-limit budget.
    private func handleAvatarPicked(_ item: PhotosPickerItem?) async {
        guard let item else { return }
        guard let data = try? await item.loadTransferable(type: Data.self),
              let image = UIImage(data: data) else { return }
        let resized = image.peer2pearResized(to: CGSize(width: 256, height: 256))
        guard let jpeg = resized.jpegData(compressionQuality: 0.8) else { return }
        let b64 = jpeg.base64EncodedString()
        _ = client.sendGroupAvatar(groupId: group.id,
                                    avatarB64: b64,
                                    memberPeerIds: group.memberIds)
        // Clear selection so picking the same photo twice in a row works.
        avatarSelection = nil
    }
}

// MARK: - Group avatar thumbnail
// Decodes base64 → UIImage and shows it in a circle.  Falls back to
// initials when there's no avatar yet.

struct GroupAvatarThumbnail: View {
    let avatarB64: String?
    let fallbackInitials: String
    let size: CGFloat

    private var image: UIImage? {
        guard let avatarB64,
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
                    .fill(.indigo)
                    .overlay {
                        Text(fallbackInitials)
                            .font(.system(size: size * 0.4, weight: .bold))
                            .foregroundStyle(.white)
                    }
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
    }
}

// MARK: - Add member sheet
// Reuses the known-peers list from NewGroupSheet — anyone we've DM'd
// is a valid candidate.  Excludes existing members + self.

struct AddGroupMemberSheet: View {
    @ObservedObject var client: Peer2PearClient
    let group: P2PGroup
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []

    private var candidates: [String] {
        let existing = Set(group.memberIds)
        let known = Set(client.messages.map(\.from))
            .union(Set(client.peerPresence.keys))
        return known
            .subtracting(existing)
            .filter { $0 != client.myPeerId }
            .sorted()
    }

    var body: some View {
        NavigationStack {
            Form {
                if candidates.isEmpty {
                    Text("No other contacts to add.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(candidates, id: \.self) { peerId in
                        Button {
                            if selected.contains(peerId) {
                                selected.remove(peerId)
                            } else {
                                selected.insert(peerId)
                            }
                        } label: {
                            HStack {
                                Image(systemName: selected.contains(peerId)
                                      ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(peerId)
                                                     ? .green : .secondary)
                                Text(peerId.prefix(12) + "...")
                                Spacer()
                                TrustBadge(trust: client.peerTrust(for: peerId))
                            }
                        }
                        .foregroundStyle(.primary)
                    }
                }
            }
            .navigationTitle("Add Members")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        let newRoster = group.memberIds + Array(selected)
                        _ = client.updateGroupMembers(groupId: group.id,
                                                       groupName: group.name,
                                                       memberPeerIds: newRoster)
                        dismiss()
                    }
                    .disabled(selected.isEmpty)
                }
            }
        }
    }
}

// MARK: - UIImage resize helper (iOS-only)

private extension UIImage {
    /// Aspect-fill resize to `target` using UIGraphicsImageRenderer.  Used
    /// by the avatar picker to normalise images before base64-encoding.
    func peer2pearResized(to target: CGSize) -> UIImage {
        let ratio = max(target.width / size.width, target.height / size.height)
        let scaled = CGSize(width: size.width * ratio, height: size.height * ratio)
        let origin = CGPoint(x: (target.width - scaled.width) / 2,
                             y: (target.height - scaled.height) / 2)
        let renderer = UIGraphicsImageRenderer(size: target)
        return renderer.image { _ in
            draw(in: CGRect(origin: origin, size: scaled))
        }
    }
}

// MARK: - Message bubble (unchanged)

struct MessageBubble: View {
    @ObservedObject var client: Peer2PearClient
    let message: P2PMessage
    let isMine: Bool

    @State private var showFailedActions = false

    /// True for outbound messages whose send exhausted the relay
    /// retry loop.  Reads off the @Published set on the client so
    /// the view re-renders the moment on_send_failed fires.
    private var sendFailed: Bool {
        isMine && client.failedMessageIds.contains(message.id)
    }

    var body: some View {
        HStack(alignment: .bottom, spacing: 6) {
            if isMine { Spacer() }

            // Red exclamation appears to the LEFT of the bubble
            // (mirror of iMessage) so it's visually grouped with
            // the bubble it annotates.  Tap target is the icon
            // itself; the bubble text stays selectable so users
            // can copy a failed message before retrying.
            if sendFailed {
                Button {
                    showFailedActions = true
                } label: {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.body)
                        .foregroundStyle(.red)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Message failed to send")
            }

            VStack(alignment: isMine ? .trailing : .leading, spacing: 4) {
                Text(message.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(isMine ? Color.green : Color(.systemGray5))
                    .foregroundStyle(isMine ? .white : .primary)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    // Slight visual desaturation on failed bubbles
                    // so it reads as "this didn't go through" even
                    // before the user notices the icon.
                    .opacity(sendFailed ? 0.65 : 1.0)

                if sendFailed {
                    Text("Not delivered")
                        .font(.caption2)
                        .foregroundStyle(.red)
                } else {
                    Text(message.timestamp, style: .time)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if !isMine { Spacer() }
        }
        .confirmationDialog(
            "Message not delivered",
            isPresented: $showFailedActions,
            titleVisibility: .visible
        ) {
            // Retry only renders when we have a peerId — outbound
            // P2PMessage carries `to`, which `sendText` populates.
            if let peerId = message.to {
                Button("Try Again") {
                    client.retryFailedMessage(
                        messageId: message.id,
                        peerId:    peerId,
                        text:      message.text)
                }
            }
            Button("Delete", role: .destructive) {
                if let peerId = message.to {
                    client.deleteMessage(chatKey: peerId, msgId: message.id)
                }
                client.failedMessageIds.remove(message.id)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Couldn't reach the relay after retrying for ~30 seconds.")
        }
    }
}

// MARK: - Key-change banner
// Peers can tap Verify (which opens contact details) or Dismiss (which
// hides the banner without trusting).  Hard-block mode is a separate
// setting — the banner respects it by showing the same "messages refused"
// state the desktop does.

struct KeyChangeBanner: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    let change: P2PKeyChange
    @State private var dismissed = false

    var body: some View {
        if !dismissed {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Safety number changed")
                        .font(.subheadline.bold())
                    Text("Verify out of band before trusting new messages.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                NavigationLink {
                    ContactDetailView(client: client, peerId: peerId)
                } label: {
                    Text("Verify")
                        .font(.caption.bold())
                }
                Button {
                    dismissed = true
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(Color.orange.opacity(0.15))
        }
    }
}

// MARK: - Shared chat components
// Generic over message type + bubble view so ConversationView (1:1)
// and GroupConversationView (group) share the same scroll + auto-
// scroll behavior without duplicating the ScrollViewReader dance.

struct ChatMessagesScroll<Message: Identifiable, Bubble: View>: View {
    let messages: [Message]
    @ViewBuilder let bubble: (Message) -> Bubble

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(messages) { msg in
                        bubble(msg).id(msg.id)
                    }
                }
                .padding()
            }
            // iOS 17+ — sets the initial scroll position to the
            // bottom on first render.  Without this, the user
            // opens a thread that already has history loaded and
            // lands at the TOP (default), having to scroll down
            // to see the most recent message — the standard
            // "messaging app" affordance is to start at the
            // bottom like iMessage / Signal / Telegram.
            .defaultScrollAnchor(.bottom)
            .onChange(of: messages.count) {
                if let last = messages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
            // Belt-and-suspenders for the rare case where the
            // ScrollView's default-anchor doesn't take (typically
                // when navigating in mid-frame and SwiftUI hasn't
            // composed the LazyVStack rows yet).  Fires once on
            // appear, deferred to the next runloop so the rows
            // exist before we jump to them.
            .onAppear {
                if let last = messages.last {
                    DispatchQueue.main.async {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }
}

// Paperclip + text field + send button.  Shared between 1:1 and group
// views.  `enabled` gates both buttons at once — GroupConversationView
// passes `enabled: group != nil` so there's no interactive input while
// the group roster hasn't loaded.
struct ChatInputBar: View {
    @Binding var text: String
    var enabled: Bool = true
    let onAttach: () -> Void
    let onSend: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Button {
                onAttach()
            } label: {
                Image(systemName: "paperclip")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
            .disabled(!enabled)

            TextField("Message", text: $text)
                .textFieldStyle(.roundedBorder)

            Button {
                onSend()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.green)
            }
            .disabled(!enabled || text.isEmpty)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}

// MARK: - File transfer row
// Shows filename + progress (% when streaming, status text when terminal).
// Reads everything from a single P2PTransferRecord — no cross-dict
// lookups.

struct FileTransferRow: View {
    @ObservedObject var client: Peer2PearClient
    let transfer: P2PTransferRecord
    @State private var confirmRemove = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Image(systemName: iconName)
                    .foregroundStyle(tint)
                Text(transfer.fileName)
                    .font(.caption.bold())
                    .lineLimit(1)
                    .frame(maxWidth: 160, alignment: .leading)
                if !transfer.isTerminal {
                    Button(role: .destructive) {
                        client.cancelTransfer(transferId: transfer.id)
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.caption)
                    }
                }
            }
            subtitle
        }
        .padding(8)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        // Long-press → "Remove from List" on terminal rows.  Hides the
        // chat-strip card and drops the file_transfers row but never
        // touches the file on disk — same semantics as desktop's
        // chatview "Delete" button.  In-flight transfers offer the
        // inline xmark.circle cancel button instead, so this menu is
        // strictly for cleaning up history.
        .contextMenu {
            if transfer.isTerminal {
                Button(role: .destructive) {
                    confirmRemove = true
                } label: {
                    Label("Remove from List", systemImage: "trash")
                }
            }
        }
        // Confirm before removing — the user's mental model is "delete",
        // so reassure them their saved file stays in the iOS Files app.
        .confirmationDialog("Remove from List?",
                            isPresented: $confirmRemove,
                            titleVisibility: .visible) {
            Button("Remove", role: .destructive) {
                client.removeTransferRecord(transferId: transfer.id)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This file will remain in Files — only the entry in this chat is removed.")
        }
    }

    @ViewBuilder private var subtitle: some View {
        switch transfer.status {
        case .completed:
            if let saved = transfer.savedPath {
                Text("Saved → " + (saved as NSString).lastPathComponent)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        case .delivered:
            Text("Sent · Delivered")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        case .canceled:
            Text("Canceled")
                .font(.caption2)
                .foregroundStyle(.secondary)
        case .blocked(let byReceiver):
            Text(byReceiver ? "Blocked by recipient (P2P required)"
                            : "Blocked: P2P unavailable")
                .font(.caption2)
                .foregroundStyle(.red)
        case .inFlight:
            if transfer.direction == .outbound
               && transfer.chunksTotal > 0
               && transfer.chunksDone >= transfer.chunksTotal {
                // Last chunk dispatched, awaiting receiver's file_ack.
                Text("Sent · Awaiting confirmation")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            } else {
                ProgressView(value: fraction)
                    .progressViewStyle(.linear)
                    .tint(tint)
                    .frame(width: 160)
            }
        }
    }

    private var fraction: Double {
        guard transfer.chunksTotal > 0 else { return 0 }
        return Double(transfer.chunksDone) / Double(transfer.chunksTotal)
    }

    private var iconName: String {
        switch transfer.status {
        case .completed, .delivered: return "checkmark.circle.fill"
        case .blocked:               return "nosign"
        case .canceled:              return "xmark.circle"
        case .inFlight:
            return transfer.direction == .inbound ? "arrow.down.circle"
                                                  : "arrow.up.circle"
        }
    }

    private var tint: Color {
        switch transfer.status {
        case .completed, .delivered: return .green
        case .blocked:               return .red
        case .canceled:              return .secondary
        case .inFlight:              return .blue
        }
    }
}

// MARK: - File-request consent sheet
// Surfaces Phase-2 prompts — a sender initiated a transfer, we must
// explicitly accept before the core releases the AEAD key and asks
// the sender to stream chunks.  Accept/Decline both dismiss the
// sheet via the `done` closure so the parent can surface the next one.

struct FileRequestSheet: View {
    @ObservedObject var client: Peer2PearClient
    let request: P2PFileRequest
    let done: () -> Void
    @State private var requireP2P = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(request.fileName)
                            .font(.headline)
                        Text("\(humanSize) from \(request.from.prefix(12))...")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
                Section {
                    Toggle("Require direct (P2P) transport", isOn: $requireP2P)
                } footer: {
                    Text("If enabled, the file will only arrive over a direct " +
                         "peer connection.  If P2P fails, the transfer is " +
                         "blocked rather than falling back to the relay.")
                }
            }
            .navigationTitle("Incoming File")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Decline", role: .destructive) {
                        client.respondToFileRequest(transferId: request.id,
                                                    accept: false)
                        done()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Accept") {
                        client.respondToFileRequest(transferId: request.id,
                                                    accept: true,
                                                    requireP2P: requireP2P)
                        done()
                    }
                }
            }
        }
    }

    private var humanSize: String {
        ByteCountFormatter.string(fromByteCount: request.fileSize, countStyle: .file)
    }
}
