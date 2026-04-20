import SwiftUI
import UniformTypeIdentifiers

struct ConversationView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    @State private var messageText = ""
    @State private var showFilePicker = false
    @State private var activeFileRequest: P2PFileRequest?

    private var peerMessages: [P2PMessage] {
        client.messages.filter { $0.from == peerId }
    }

    /// Transfers with this peer — inbound or outbound.  Both halves land
    /// in `client.fileProgress` keyed by transferId; the counterparty is
    /// `peerId` regardless of direction, so filtering is uniform.
    private var activeTransfers: [P2PFileProgress] {
        client.fileProgress.values
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
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(peerMessages) { msg in
                        MessageBubble(message: msg,
                                      isMine: msg.from == client.myPeerId)
                            .id(msg.id)
                    }
                }
                .padding()
            }
            .onChange(of: peerMessages.count) {
                if let last = peerMessages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }

    @ViewBuilder private var transfersStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(activeTransfers) { t in
                    FileTransferRow(client: client, progress: t)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
        .background(.thinMaterial)
    }

    @ViewBuilder private var inputBar: some View {
        HStack(spacing: 12) {
            Button {
                showFilePicker = true
            } label: {
                Image(systemName: "paperclip")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            TextField("Message", text: $messageText)
                .textFieldStyle(.roundedBorder)

            Button {
                guard !messageText.isEmpty else { return }
                client.sendText(to: peerId, text: messageText)
                messageText = ""
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.green)
            }
            .disabled(messageText.isEmpty)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
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
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(groupMessages) { msg in
                        GroupMessageBubble(message: msg,
                                           isMine: msg.from == client.myPeerId)
                            .id(msg.id)
                    }
                }
                .padding()
            }
            .onChange(of: groupMessages.count) {
                if let last = groupMessages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }

    @ViewBuilder private var inputBar: some View {
        HStack(spacing: 12) {
            Button {
                showFilePicker = true
            } label: {
                Image(systemName: "paperclip")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
            .disabled(group == nil)

            TextField("Message", text: $messageText)
                .textFieldStyle(.roundedBorder)

            Button {
                send()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.green)
            }
            .disabled(messageText.isEmpty || group == nil)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
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

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(group.memberIds, id: \.self) { peerId in
                        HStack {
                            Image(systemName: peerId == client.myPeerId
                                   ? "person.fill" : "person")
                                .foregroundStyle(.secondary)
                            Text(peerId == client.myPeerId
                                 ? "You"
                                 : String(peerId.prefix(12)) + "...")
                            Spacer()
                            if peerId != client.myPeerId {
                                if client.peerPresence[peerId] == true {
                                    Circle().fill(.green).frame(width: 8, height: 8)
                                }
                                TrustBadge(trust: client.peerTrust(for: peerId))
                            }
                        }
                    }
                } header: {
                    Text("Members (\(group.memberIds.count))")
                }

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
            .navigationTitle(group.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
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
// Surfaces the audit M5/M6 mitigation: peers can tap Verify (which opens
// contact details) or Dismiss (which hides the banner without trusting).
// Hard-block mode is a separate setting — the banner respects it by
// showing the same "messages refused" state the desktop does.

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

// MARK: - File transfer row
// Shows filename + progress (% when streaming, saved-path when done) for
// a single in-flight transfer.  Tap to cancel.  Blocked + canceled
// states come from the corresponding @Published dicts so we don't miss
// anything after fileProgress stops updating.

struct FileTransferRow: View {
    @ObservedObject var client: Peer2PearClient
    let progress: P2PFileProgress

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Image(systemName: iconName)
                    .foregroundStyle(tint)
                Text(progress.fileName)
                    .font(.caption.bold())
                    .lineLimit(1)
                    .frame(maxWidth: 160, alignment: .leading)
                if progress.savedPath == nil && !isTerminal {
                    Button(role: .destructive) {
                        client.cancelTransfer(transferId: progress.id)
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.caption)
                    }
                }
            }
            if let saved = progress.savedPath {
                Text("Saved → " + (saved as NSString).lastPathComponent)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            } else if isComplete {
                // Outbound finished — note delivery confirmation lives in
                // client.deliveredTransferIds (arrives when the receiver acks).
                Text(client.deliveredTransferIds.contains(progress.id)
                     ? "Sent · Delivered"
                     : "Sent · Awaiting confirmation")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            } else if let blocked = client.blockedTransfers[progress.id] {
                Text(blocked ? "Blocked by recipient (P2P required)"
                             : "Blocked: P2P unavailable")
                    .font(.caption2)
                    .foregroundStyle(.red)
            } else if client.canceledTransfers[progress.id] != nil {
                Text("Canceled")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                ProgressView(value: fraction)
                    .progressViewStyle(.linear)
                    .tint(tint)
                    .frame(width: 160)
            }
        }
        .padding(8)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var fraction: Double {
        guard progress.chunksTotal > 0 else { return 0 }
        return Double(progress.chunksDone) / Double(progress.chunksTotal)
    }
    /// Outbound transfers complete when the last chunk dispatches
    /// (chunksDone == chunksTotal) — sender delivery confirmation arrives
    /// separately via onFileTransferDelivered / deliveredTransferIds.
    private var isComplete: Bool {
        if progress.direction == .inbound { return progress.savedPath != nil }
        return progress.chunksDone >= progress.chunksTotal && progress.chunksTotal > 0
    }
    private var isTerminal: Bool {
        isComplete
        || client.blockedTransfers[progress.id] != nil
        || client.canceledTransfers[progress.id] != nil
    }
    private var iconName: String {
        if isComplete { return "checkmark.circle.fill" }
        if client.blockedTransfers[progress.id] != nil { return "nosign" }
        if client.canceledTransfers[progress.id] != nil { return "xmark.circle" }
        return progress.direction == .inbound ? "arrow.down.circle" : "arrow.up.circle"
    }
    private var tint: Color {
        if isComplete { return .green }
        if client.blockedTransfers[progress.id] != nil { return .red }
        if client.canceledTransfers[progress.id] != nil { return .secondary }
        return .blue
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
        let bytes = request.fileSize
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes)/1024) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(bytes)/1024/1024) }
        return String(format: "%.1f GB", Double(bytes)/1024/1024/1024)
    }
}
