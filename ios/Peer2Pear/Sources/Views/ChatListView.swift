import SwiftUI

struct ChatListView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var showAddContact = false
    @State private var showNewGroup = false
    @State private var newContactId = ""

    /// 1:1 conversations keyed by the other peer's ID.
    private var conversations: [String: [P2PMessage]] {
        Dictionary(grouping: client.messages, by: \.from)
    }

    /// Groups sorted most-recently-active first.
    private var groupsSorted: [P2PGroup] {
        client.groups.values.sorted { $0.lastActivity > $1.lastActivity }
    }

    private var isEmpty: Bool {
        conversations.isEmpty && groupsSorted.isEmpty
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
                if !conversations.isEmpty {
                    Section("Direct Messages") {
                        ForEach(conversations.keys.sorted(), id: \.self) { peerId in
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
                        }
                    }
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Text(client.isConnected ? "Connected" : "Offline")
                        .font(.caption)
                        .foregroundStyle(client.isConnected ? .green : .red)
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
            .alert("New Chat", isPresented: $showAddContact) {
                TextField("Peer ID", text: $newContactId)
                    .autocapitalization(.none)
                Button("Cancel", role: .cancel) { newContactId = "" }
                Button("Chat") {
                    if !newContactId.isEmpty {
                        // Navigate to conversation with this peer
                        newContactId = ""
                    }
                }
            } message: {
                Text("Enter the peer's public key or scan their QR code")
            }
            .sheet(isPresented: $showNewGroup) {
                NewGroupSheet(client: client)
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
            Circle()
                .fill(.indigo)
                .frame(width: 40, height: 40)
                .overlay {
                    Image(systemName: "person.3.fill")
                        .foregroundStyle(.white)
                        .font(.subheadline)
                }
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
                    Text(peerId.prefix(8) + "...")
                        .font(.headline)
                    TrustBadge(trust: client.peerTrust(for: peerId))
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

    /// Peer IDs we've seen in 1:1 messages — potential group members.
    private var knownPeers: [String] {
        let ids = Set(client.messages.map(\.from))
            .union(Set(client.peerPresence.keys))
        return ids.filter { $0 != client.myPeerId }.sorted()
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
                                    Text(peerId.prefix(12) + "...")
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

    private var trust: P2PPeerTrust { client.peerTrust(for: peerId) }
    private var keyChanged: Bool   { client.keyChanges[peerId] != nil }

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
                        Text(peerId.prefix(16) + "...")
                            .font(.headline)
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
        }
        .navigationTitle("Contact Info")
        .navigationBarTitleDisplayMode(.inline)
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
