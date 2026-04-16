import SwiftUI

struct ConversationView: View {
    @ObservedObject var client: Peer2PearClient
    let peerId: String
    @State private var messageText = ""

    private var peerMessages: [P2PMessage] {
        client.messages.filter { $0.from == peerId }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Messages
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(peerMessages) { msg in
                            MessageBubble(message: msg, isMine: msg.from == client.myPeerId)
                                .id(msg.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: peerMessages.count) { _ in
                    if let last = peerMessages.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }

            Divider()

            // Input bar
            HStack(spacing: 12) {
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
        .navigationTitle(peerId.prefix(8) + "...")
        .navigationBarTitleDisplayMode(.inline)
    }
}

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
