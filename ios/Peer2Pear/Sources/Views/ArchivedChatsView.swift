import SwiftUI

// ArchivedChatsView — recovery surface for chats the user has hidden
// via the editors' "Hide from Chat List" toggles.  Once a thread is
// archived, the editor that toggled it (ConversationDetailView for 1:1,
// GroupDetailView for groups) is no longer reachable from the main
// chat list, so without this view a hidden thread can only come back
// by way of a fresh inbound message.  Settings entry-point keeps the
// surface low-traffic: discoverable when the user goes looking, out of
// the way otherwise.
//
// Single combined list of both kinds (direct + group) — the kind icon
// is enough to disambiguate, and splitting into two sections would
// double the chrome for an empty list in the common case.  Sorted
// most-recently-active first, same as ChatListView, so the thread the
// user is most likely to be hunting for sits at the top.
//
// State source: re-reads `dbLoadAllConversations` on appear and after
// every action.  The conversations table is the source of truth — the
// in-memory `archivedDirectPeerIds` mirror is correct for direct rows
// but doesn't carry group rows (which live in the table but not in
// `groups` once archived).  Reloading from the DB sidesteps any drift.
//
// Restore path: flips `in_chat_list = 1` via dbSetConversationInChatList,
// then calls `loadStateFromDb()` so the chat list's @Published surfaces
// (groups, archivedDirectPeerIds, directConversationIdByPeer) repopulate
// in one pass.  Updating archivedDirectPeerIds inline first keeps the
// row from blinking back in this view while the async reload settles.
//
// Delete path: routes through `deleteChat(peerId:)` which already
// cascades messages + members + group_* state via dbDeleteConversation.
// Same destructive guard the chat list itself uses.
struct ArchivedChatsView: View {
    @ObservedObject var client: Peer2PearClient

    /// Snapshot of archived rows for this navigation push.  Reloaded
    /// from the DB on appear and after each action — keeps the list
    /// in sync without binding to a @Published surface that doesn't
    /// hold archived groups.
    @State private var rows: [Peer2PearClient.DBConversation] = []

    var body: some View {
        Group {
            if rows.isEmpty {
                ContentUnavailableView(
                    "No archived chats",
                    systemImage: "archivebox",
                    description: Text("Threads you hide from the chat list show up here so you can bring them back.")
                )
            } else {
                List {
                    ForEach(rows, id: \.id) { conv in
                        archivedRow(for: conv)
                            .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                Button {
                                    restore(conv)
                                } label: {
                                    Label("Restore", systemImage: "tray.and.arrow.up")
                                }
                                .tint(.green)
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    delete(conv)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                    }
                }
            }
        }
        .navigationTitle("Archived Chats")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { reload() }
    }

    // MARK: - Row rendering

    /// Direct rows mirror `ChatRow` (peer-keyed avatar + nickname);
    /// group rows mirror `GroupRow` (group avatar + member count).
    /// Both are read-only here — taps are intercepted by the swipe
    /// actions, no NavigationLink so the row doesn't push into a
    /// conversation that isn't on the chat list.
    @ViewBuilder
    private func archivedRow(for conv: Peer2PearClient.DBConversation) -> some View {
        switch conv.kind {
        case .direct:
            HStack {
                ContactAvatarThumbnail(
                    avatarB64: client.peerAvatars[conv.directPeerId]?.avatarB64,
                    fallbackInitials: String(conv.directPeerId.prefix(2)).uppercased(),
                    size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(client.displayName(for: conv.directPeerId))
                        .font(.headline)
                    Text("Direct message")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "archivebox")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        case .group:
            HStack {
                GroupAvatarThumbnail(
                    avatarB64: conv.groupAvatarB64.isEmpty ? nil : conv.groupAvatarB64,
                    fallbackInitials: String(conv.groupName.prefix(2)).uppercased(),
                    size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(conv.groupName.isEmpty ? "Group" : conv.groupName)
                        .font(.headline)
                    Text("Group")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "archivebox")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        }
    }

    // MARK: - Actions

    /// Re-read the conversations table and keep only archived rows.
    /// Cheap enough to run on every action — the table is small and
    /// the C bridge streams synchronously.
    private func reload() {
        var collected: [Peer2PearClient.DBConversation] = []
        client.dbLoadAllConversations { conv in
            if !conv.inChatList {
                collected.append(conv)
            }
        }
        // Most-recently-active first so the thread the user is most
        // likely hunting for is at the top — same ordering rule as
        // ChatListView.
        collected.sort { $0.lastActiveSecs > $1.lastActiveSecs }
        rows = collected
    }

    /// Flip `in_chat_list = 1`, update the in-memory mirror so the
    /// row vanishes from this view immediately, then reload the
    /// client's @Published surfaces so the restored thread surfaces
    /// in `ChatListView` on the next render.
    private func restore(_ conv: Peer2PearClient.DBConversation) {
        _ = client.dbSetConversationInChatList(id: conv.id, inList: true)
        if conv.kind == .direct, !conv.directPeerId.isEmpty {
            client.archivedDirectPeerIds.remove(conv.directPeerId)
        }
        client.loadStateFromDb()
        reload()
    }

    /// Cascading delete.  `deleteChat(peerId:)` takes a peerId for
    /// direct chats and a groupId for groups — both happen to be the
    /// right key here (direct uses `directPeerId`, group uses `id`
    /// which equals the group_id).  Reload after so the row drops
    /// out of this list.
    private func delete(_ conv: Peer2PearClient.DBConversation) {
        let key = conv.kind == .direct ? conv.directPeerId : conv.id
        client.deleteChat(peerId: key)
        // deleteChat dispatches its work async to the main queue; defer
        // the reload one tick so the cascade lands first.  Without this
        // the row briefly reappears before vanishing on the next pass.
        DispatchQueue.main.async { reload() }
    }
}
