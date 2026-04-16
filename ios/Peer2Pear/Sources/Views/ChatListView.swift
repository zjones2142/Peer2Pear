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
                        HStack {
                            Circle()
                                .fill(.green)
                                .frame(width: 40, height: 40)
                                .overlay {
                                    Text(String(peerId.prefix(2)).uppercased())
                                        .font(.caption.bold())
                                        .foregroundStyle(.white)
                                }

                            VStack(alignment: .leading) {
                                Text(peerId.prefix(8) + "...")
                                    .font(.headline)
                                if let last = conversations[peerId]?.last {
                                    Text(last.text)
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
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
