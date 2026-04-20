import SwiftUI

struct ChatListView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var showAddContact = false
    @State private var newContactId = ""

    /// Group messages by sender into "conversations"
    private var conversations: [String: [P2PMessage]] {
        Dictionary(grouping: client.messages, by: \.from)
    }

    var body: some View {
        NavigationStack {
            List {
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
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Text(client.isConnected ? "Connected" : "Offline")
                        .font(.caption)
                        .foregroundStyle(client.isConnected ? .green : .red)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAddContact = true
                    } label: {
                        Image(systemName: "plus.message")
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
            .overlay {
                if conversations.isEmpty {
                    ContentUnavailableView(
                        "No conversations yet",
                        systemImage: "bubble.left.and.bubble.right",
                        description: Text("Tap + to start a new chat")
                    )
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
