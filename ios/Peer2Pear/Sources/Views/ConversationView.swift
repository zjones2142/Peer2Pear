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
        .navigationTitle(peerId.prefix(8) + "...")
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
            MessageBubble(message: msg, isMine: msg.from == client.myPeerId)
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
        ToolbarItem(placement: .topBarTrailing) {
            NavigationLink {
                ContactDetailView(client: client, peerId: peerId)
            } label: {
                let trust = client.peerTrust(for: peerId)
                if trust == .unverified {
                    Image(systemName: "info.circle")
                        .foregroundStyle(.blue)
                } else {
                    TrustBadge(trust: trust)
                }
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
    @State private var showRoster = false
    @State private var showFilePicker = false

    private var group: P2PGroup? { client.groups[groupId] }

    private var groupMessages: [P2PGroupMessage] {
        client.groupMessages.filter { $0.groupId == groupId }
    }

    var body: some View {
        VStack(spacing: 0) {
            messagesScroll
            Divider()
            inputBar
        }
        .navigationTitle(group?.name ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showRoster = true
                } label: {
                    Image(systemName: "person.3")
                }
                .disabled(group == nil)
            }
        }
        .sheet(isPresented: $showRoster) {
            if let group {
                GroupRosterSheet(client: client, group: group)
            }
        }
        .fileImporter(isPresented: $showFilePicker,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: false) { result in
            handleFilePick(result: result)
        }
    }

    @ViewBuilder private var messagesScroll: some View {
        ChatMessagesScroll(messages: groupMessages) { msg in
            GroupMessageBubble(message: msg,
                               isMine: msg.from == client.myPeerId)
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
        client.sendGroupText(groupId: group.id,
                             groupName: group.name,
                             memberPeerIds: group.memberIds,
                             text: messageText)
        // Local echo — the core doesn't loop-back our own group sends
        // through on_group_message, so we append ourselves to keep the
        // transcript in-sync with what recipients see.
        let echo = P2PGroupMessage(
            id: UUID().uuidString,
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
        messageText = ""
    }
}

// Group message bubble — adds a sender-label row above the bubble so
// members can attribute messages.  Own messages skip the label.

struct GroupMessageBubble: View {
    let message: P2PGroupMessage
    let isMine: Bool

    var body: some View {
        HStack {
            if isMine { Spacer() }
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

                Text(message.timestamp, style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if !isMine { Spacer() }
        }
    }
}

// Group roster sheet — shows the full member list with trust badges +
// online status dots.  No mutations from here today (no C API for
// adding/removing members yet); it's purely a view.

struct GroupRosterSheet: View {
    @ObservedObject var client: Peer2PearClient
    let group: P2PGroup
    @Environment(\.dismiss) private var dismiss
    @State private var showRename = false
    @State private var newName = ""
    @State private var confirmLeave = false
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
                actionsSection
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
            .confirmationDialog("Leave this group?",
                                isPresented: $confirmLeave,
                                titleVisibility: .visible) {
                Button("Leave", role: .destructive) {
                    _ = client.leaveGroup(groupId: group.id,
                                          groupName: group.name,
                                          memberPeerIds: group.memberIds)
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Other members will see you left.  Your local messages will be cleared.")
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
                HStack {
                    Image(systemName: "person").foregroundStyle(.secondary)
                    Text(peerId.prefix(12) + "...")
                    Spacer()
                    if client.peerPresence[peerId] == true {
                        Circle().fill(.green).frame(width: 8, height: 8)
                    }
                    TrustBadge(trust: client.peerTrust(for: peerId))
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

    @ViewBuilder private var actionsSection: some View {
        Section {
            Button {
                newName = group.name
                showRename = true
            } label: {
                Label("Rename Group", systemImage: "pencil")
            }
            Button(role: .destructive) {
                confirmLeave = true
            } label: {
                Label("Leave Group", systemImage: "rectangle.portrait.and.arrow.right")
            }
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
    let message: P2PMessage
    let isMine: Bool

    var body: some View {
        HStack {
            if isMine { Spacer() }
            VStack(alignment: isMine ? .trailing : .leading, spacing: 4) {
                Text(message.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(isMine ? Color.green : Color(.systemGray5))
                    .foregroundStyle(isMine ? .white : .primary)
                    .clipShape(RoundedRectangle(cornerRadius: 16))

                Text(message.timestamp, style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if !isMine { Spacer() }
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
            .onChange(of: messages.count) {
                if let last = messages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
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
