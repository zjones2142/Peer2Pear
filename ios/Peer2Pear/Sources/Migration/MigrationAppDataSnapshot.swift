import Foundation

// SQLCipher app-data snapshot for migration (Phase 4 backup-strategy
// step 2 / Tier 1).  Carries everything the user thinks of as
// "their account" except the identity keys (which travel separately
// in MigrationPayload.identityFile/saltFile):
//
//   - contacts (with verification fingerprints)
//   - conversations (DM threads + groups)
//   - conversation members (group rosters)
//   - messages (full chat history)
//   - blocked keys
//
// What's NOT here (per project_backup_strategy.md):
//   - Ratchet / session / replay-cache state — STRIPPED.  Receiver
//     rebuilds on first send to each peer; honest "safety number
//     changed" alerts are the right signal of a device move.
//   - File-transfer records — separate Tier 2 chunk later (small
//     metadata, but interacts with Saved Files toggle).
//   - Saved files (decrypted attachments) — separate Tier 2
//     toggle, optional + bulk.
//   - UserDefaults / @AppStorage settings — separate Tier 2 chunk
//     covering autoLockMinutes, privacyLevel, file thresholds,
//     screen-capture blocks, relay URLs, etc.
//
// Wire format: JSON-encoded MigrationAppDataSnapshot, embedded as
// Data in MigrationPayload.appDataSnapshot.  JSON keeps it human-
// debuggable + cross-platform-friendly (desktop migration's Qt
// parser is a one-liner with QJsonDocument when it lands).
//
// Size note: typical user with ~50 contacts + ~5000 messages
// compresses to ~1–2 MB.  MultipeerConnectivity reliable-data
// messages handle that comfortably.

/// Group-roster entry — keyed by conversation ID, lists member
/// peer IDs.  Only populated for `kind == .group` rows; direct
/// conversations don't have member rosters (the other party IS
/// the membership).
struct MigrationGroupMembers: Codable {
    let conversationId: String
    let peerIds: [String]
}

/// One row from the messages table — pairs a DBMessage with its
/// conversation_id (which the DBMessage struct itself doesn't
/// carry; the storage layer keys by conversation, not by message).
struct MigrationMessageRow: Codable {
    let conversationId: String
    let message: Peer2PearClient.DBMessage
}

struct MigrationAppDataSnapshot: Codable {
    /// Schema version — bumped when adding required fields.
    /// Optional fields (forward-compat) don't bump.
    let version: Int

    let contacts:             [Peer2PearClient.DBContact]
    let conversations:        [Peer2PearClient.DBConversation]
    let conversationMembers:  [MigrationGroupMembers]
    let messages:             [MigrationMessageRow]
    let blockedKeys:          [String]
}

extension MigrationAppDataSnapshot {
    static let currentVersion = 1
}

// MARK: - Build (sender side)

extension Peer2PearClient {

    /// Build a snapshot of the on-disk app data for migration.
    /// Reads everything from the SQLCipher store via the existing
    /// dbLoad* helpers — no new C API surface, no direct SQL.
    /// Caller wraps this in MigrationPayload + ships via
    /// MigrationCryptoBridge.seal.
    func buildAppDataSnapshot() -> MigrationAppDataSnapshot {
        var contacts: [DBContact] = []
        dbLoadAllContacts { contacts.append($0) }

        var conversations: [DBConversation] = []
        dbLoadAllConversations { conversations.append($0) }

        // Members are only relevant for group conversations;
        // direct rows have an implicit 2-party membership and
        // don't need a roster row.
        var members: [MigrationGroupMembers] = []
        for conv in conversations where conv.kind == .group {
            var peerIds: [String] = []
            dbLoadConversationMembers(conversationId: conv.id) { peerIds.append($0) }
            members.append(MigrationGroupMembers(
                conversationId: conv.id,
                peerIds:        peerIds))
        }

        // Walk every conversation's messages.  Each is keyed by
        // conv id at storage time; we re-attach that here so the
        // receiver knows where to insert each row.
        var messages: [MigrationMessageRow] = []
        for conv in conversations {
            dbLoadMessages(conversationId: conv.id) { msg in
                messages.append(MigrationMessageRow(
                    conversationId: conv.id,
                    message:        msg))
            }
        }

        var blocked: [String] = []
        dbLoadAllBlockedKeys { blocked.append($0) }

        return MigrationAppDataSnapshot(
            version:             MigrationAppDataSnapshot.currentVersion,
            contacts:            contacts,
            conversations:       conversations,
            conversationMembers: members,
            messages:            messages,
            blockedKeys:         blocked)
    }
}

// MARK: - Apply (receiver side)

extension Peer2PearClient {

    enum AppDataSnapshotApplyError: Error, LocalizedError {
        case versionMismatch
        case writeFailed(String)

        var errorDescription: String? {
            switch self {
            case .versionMismatch:
                return "Snapshot uses a format this version doesn't recognize.  Update both devices to the same Peer2Pear release."
            case .writeFailed(let reason):
                return "Failed to write migrated data: \(reason)"
            }
        }
    }

    /// Apply a snapshot to the local SQLCipher store.  Caller has
    /// already ensured `start()` succeeded — i.e., identity files
    /// are written, DB key is derived, AppDataStore is open.
    /// Returns nothing on success; throws AppDataSnapshotApplyError
    /// on a hard failure (most individual row-write failures are
    /// swallowed + continue, since partial migration is better
    /// than none — see comment below).
    ///
    /// After applying, calls `loadStateFromDb()` to rehydrate
    /// every @Published mirror so SwiftUI sees the migrated state
    /// in one redraw.
    func applyAppDataSnapshot(_ snapshot: MigrationAppDataSnapshot) throws {
        guard snapshot.version == MigrationAppDataSnapshot.currentVersion else {
            throw AppDataSnapshotApplyError.versionMismatch
        }

        // 1. Conversations FIRST — messages have a foreign-key
        //    dependency on conversation_id.  Group rosters depend
        //    on the conversation row existing too.
        var firstWriteFailure: String?
        for conv in snapshot.conversations {
            if !dbSaveConversation(conv) && firstWriteFailure == nil {
                firstWriteFailure = "conversations table"
            }
        }

        // 2. Conversation members (group rosters).  Inserted
        //    after the conversation rows since the C-side
        //    setConversationMembers replaces the membership
        //    atomically and needs the conversation to exist.
        for m in snapshot.conversationMembers {
            if !dbSetConversationMembers(
                    conversationId: m.conversationId,
                    peerIds:        m.peerIds)
                && firstWriteFailure == nil {
                firstWriteFailure = "conversation_members table"
            }
        }

        // 3. Contacts — independent of conversations, but
        //    typically inserted after so the chat-list rendering
        //    sees a consistent set on first @Published refresh.
        for c in snapshot.contacts {
            if !dbSaveContact(c) && firstWriteFailure == nil {
                firstWriteFailure = "contacts table"
            }
        }

        // 4. Blocked keys — independent of contacts post-Phase 3h.
        //    A blocked stranger has no contacts row but still
        //    needs to round-trip into the blocked_keys table.
        for peerId in snapshot.blockedKeys {
            if !dbAddBlockedKey(peerId: peerId) && firstWriteFailure == nil {
                firstWriteFailure = "blocked_keys table"
            }
        }

        // 5. Messages last — bulkiest.  We don't error out on
        //    individual row-write failures (partial history is
        //    much better than none for the user); we record the
        //    first failure for the post-apply throw decision.
        for mr in snapshot.messages {
            if !dbSaveMessage(conversationId: mr.conversationId,
                                message:        mr.message)
                && firstWriteFailure == nil {
                firstWriteFailure = "messages table"
            }
        }

        // 6. Refresh the @Published mirrors so SwiftUI redraws
        //    chat list + threads with the migrated state without
        //    waiting for the next external trigger.
        loadStateFromDb()

        // Throw only if EVERYTHING failed — partial success is
        // fine, the user will see most of their state and can
        // always factory-reset + retry the migration if it's
        // visibly broken.  Individual failures land in the
        // C-side log via the dbSave* logging.
        if let stage = firstWriteFailure,
           snapshot.contacts.isEmpty == false &&
           snapshot.messages.isEmpty == false {
            // Heuristic: if the FIRST failure was on a
            // non-empty source table, surface it.  Empty source
            // = nothing to migrate, so empty-target post-apply
            // isn't a failure.
            // TODO: tighten this — currently throws only when
            // BOTH contacts AND messages were non-empty + any
            // write failed.  Good enough for v1.
            throw AppDataSnapshotApplyError.writeFailed(stage)
        }
    }
}
