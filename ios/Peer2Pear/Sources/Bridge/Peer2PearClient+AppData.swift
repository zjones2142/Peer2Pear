import Foundation

// MARK: - AppDataStore Swift wrappers
//
// Thin layer over the p2p_app_* C API.  v3 schema split: contacts hold
// only address-book rows (1:1 people), conversations own chat threads
// (direct + group), conversation_members hold group rosters, and
// messages re-key off conversation_id (not peer_id) — the same shape
// the C++ AppDataStore uses on disk.
//
// All loaders use C-friendly heap-boxed callback contexts: Swift
// closures can't be cast to C function pointers when they capture, so
// each loader allocates a heap-backed callback context, threads it
// through the C call, and copies rows out before returning.

extension Peer2PearClient {

    /// Wire-format mirror of AppDataStore::Contact (v3 slim shape).
    /// Address-book row only — groups are NOT contacts in v3.  Strangers
    /// who message us produce a `conversations` row, never a contact.
    /// Block state lives in `blocked_keys` (Phase 3h), reachable via
    /// `dbAddBlockedKey` / `dbIsBlockedKey` / `dbLoadAllBlockedKeys` —
    /// never on this row.
    struct DBContact: Codable {
        let peerId: String
        var name: String = ""
        var subtitle: String = ""
        var avatarB64: String = ""
        /// Person-level mute (cross-conversation).  OR'd with the
        /// matching conversation's `muted` at notification time.
        var muted: Bool = false
        var lastActiveSecs: Int64 = 0
    }

    /// Conversation kind discriminator.  Maps to the `"direct"` /
    /// `"group"` strings the C boundary expects.
    enum DBConversationKind: String, Codable {
        case direct
        case group

        /// String the C API uses on the wire (matches AppDataStore::ConversationKind).
        var wireValue: String {
            switch self {
            case .direct: return "direct"
            case .group:  return "group"
            }
        }

        /// Decode the C-side kind string.  Empty / unrecognised falls
        /// back to `.direct` — defensive for future-proofing if the
        /// core ever ships a new kind we don't know about yet.
        static func from(_ wire: String) -> DBConversationKind {
            wire == "group" ? .group : .direct
        }
    }

    /// Wire-format mirror of AppDataStore::Conversation.  One row per
    /// chat thread — direct (1:1) or group.  For direct chats the
    /// `id` is a UUID minted by the core (NOT the peer's pubkey);
    /// `directPeerId` carries the peer's pubkey.  For groups, `id`
    /// equals the group_id and `directPeerId` is empty.
    struct DBConversation: Codable {
        let id: String
        var kind: DBConversationKind = .direct
        var directPeerId: String = ""
        var groupName: String = ""
        var groupAvatarB64: String = ""
        /// Conversation-level mute.  OR'd with the contact-level mute
        /// at notification time.
        var muted: Bool = false
        var lastActiveSecs: Int64 = 0
        /// Hide a thread from the chat list without deleting messages.
        var inChatList: Bool = true
    }

    /// Mirror of AppDataStore::Message (v3 shape — adds senderId).
    struct DBMessage: Codable {
        let sent: Bool
        let text: String
        let timestampSecs: Int64
        let msgId: String
        /// Originator peer_id for inbound messages; "" for outbound.
        /// Distinct from senderName (the self-declared display name a
        /// group sender embeds in the envelope) — senderId is the
        /// cryptographic pubkey we use to look up sender display info.
        let senderId: String
        /// Self-declared display name carried in group inbound messages.
        /// Empty for 1:1 inbound and for outbound.
        let senderName: String
        /// Outbound-only persistence of the per-bubble fail flag.
        /// Default false — flips true on the relay-retry-exhaustion
        /// path so the red-! indicator survives a relaunch.  Inbound
        /// rows always carry this as false.
        var sendFailed: Bool = false
    }

    /// Mirror of AppDataStore::FileRecord.  Used to persist the
    /// `transfers` dict so file rows survive lock/unlock.
    struct DBFileRecord: Codable {
        let transferId: String
        let chatKey: String           // 1:1 peerId or groupId
        let fileName: String
        let fileSize: Int64
        let peerId: String
        let peerName: String
        let timestampSecs: Int64
        let sent: Bool
        /// Encoded P2PTransferStatus — see encodeStatus() / decodeStatus().
        let status: Int
        let chunksTotal: Int
        let chunksComplete: Int
        let savedPath: String         // "" for outbound (sender already has the file)
    }

    // MARK: - Save (contacts)

    @discardableResult
    func dbSaveContact(_ c: DBContact) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_contact(
            ctx, c.peerId, c.name, c.subtitle, c.avatarB64,
            c.muted ? 1 : 0,
            c.lastActiveSecs) == 0
    }

    @discardableResult
    func dbDeleteContact(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_contact(ctx, peerId) == 0
    }

    @discardableResult
    func dbSetContactMuted(peerId: String, muted: Bool) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_set_contact_muted(ctx, peerId, muted ? 1 : 0) == 0
    }

    @discardableResult
    func dbSaveContactAvatar(peerId: String, avatarB64: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_contact_avatar(ctx, peerId, avatarB64) == 0
    }

    // MARK: - Blocked keys (Phase 3h)
    //
    // Block is its own table — independent of contacts.  Adding /
    // removing a blocked key never touches the address book.

    @discardableResult
    func dbAddBlockedKey(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_add_blocked_key(ctx, peerId) == 0
    }

    @discardableResult
    func dbRemoveBlockedKey(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_remove_blocked_key(ctx, peerId) == 0
    }

    func dbIsBlockedKey(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_is_blocked_key(ctx, peerId) == 1
    }

    /// Stream every blocked key.  Used by `loadStateFromDb` to populate
    /// the `blockedPeerIds` @Published set on launch / unlock.
    /// Reuses `MemberCallbackBox` since the shape is identical
    /// (single-string per row); `blocked_at` is dropped at the bridge
    /// boundary because the @Published set doesn't need it.
    func dbLoadAllBlockedKeys(_ each: @escaping (String) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(MemberCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_blocked_keys(ctx, { peerIdC, _ /*blockedAt*/, ud in
            guard let ud, let peerIdC else { return }
            let unbox = Unmanaged<MemberCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            unbox.handler(String(cString: peerIdC))
        }, box.toOpaque())
    }

    // MARK: - Save (conversations)

    @discardableResult
    func dbSaveConversation(_ c: DBConversation) -> Bool {
        guard let ctx = rawContext else { return false }
        // Group rows use `id` == group_id; direct rows pass directPeerId
        // through so the partial-UNIQUE index can dedupe on it.
        let directPeer: String? = c.kind == .direct
            ? (c.directPeerId.isEmpty ? nil : c.directPeerId) : nil
        let groupName:  String? = c.kind == .group  ? c.groupName       : nil
        let groupAvB64: String? = c.kind == .group  ? c.groupAvatarB64  : nil
        return p2p_app_save_conversation(
            ctx, c.id, c.kind.wireValue,
            directPeer, groupName, groupAvB64,
            c.muted ? 1 : 0,
            c.lastActiveSecs,
            c.inChatList ? 1 : 0) == 0
    }

    /// Mint (or fetch) the conversation id for a 1:1 with `peerId`.
    /// Returns nil only on `rawContext == nil` or DB error.  Idempotent
    /// — concurrent callers with the same peer converge on the same
    /// UUID via the partial UNIQUE index on direct_peer_id.
    func dbFindOrCreateDirectConversation(peerId: String) -> String? {
        guard let ctx = rawContext else { return nil }
        // 64 bytes is plenty for any UUID-shaped value the core mints
        // (current format is 36-byte UUID + NUL).
        var buf = [CChar](repeating: 0, count: 64)
        let rc = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
            p2p_app_find_or_create_direct_conversation(ctx, peerId, ptr.baseAddress, 64)
        }
        guard rc == 0 else { return nil }
        return String(cString: buf)
    }

    @discardableResult
    func dbDeleteConversation(id: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_conversation(ctx, id) == 0
    }

    @discardableResult
    func dbSetConversationMuted(id: String, muted: Bool) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_set_conversation_muted(ctx, id, muted ? 1 : 0) == 0
    }

    @discardableResult
    func dbSetConversationInChatList(id: String, inList: Bool) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_set_conversation_in_chat_list(ctx, id, inList ? 1 : 0) == 0
    }

    /// Replace the entire member roster of a conversation atomically.
    /// `peerIds` is empty / nil for 1:1 chats — caller passes the group
    /// roster only.
    @discardableResult
    func dbSetConversationMembers(conversationId: String, peerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        return withCStringArray(peerIds) { ptr in
            p2p_app_set_conversation_members(ctx, conversationId, ptr) == 0
        }
    }

    // MARK: - Save (messages)

    /// Save a single message into a conversation.  The conversation row
    /// MUST already exist — for inbound-from-stranger callers should
    /// `dbFindOrCreateDirectConversation(peerId:)` first.
    @discardableResult
    func dbSaveMessage(conversationId: String, message: DBMessage) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_message(
            ctx, conversationId,
            message.sent ? 1 : 0,
            message.text,
            message.timestampSecs,
            message.msgId,
            message.senderId,
            message.senderName,
            message.sendFailed ? 1 : 0) == 0
    }

    @discardableResult
    func dbDeleteMessages(conversationId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_messages(ctx, conversationId) == 0
    }

    @discardableResult
    func dbDeleteMessage(conversationId: String, msgId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_message(ctx, conversationId, msgId) == 0
    }

    /// Flip the persisted send_failed flag on a single message —
    /// used by the on_send_failed callback (mark) and by retry /
    /// delete paths (clear).  Mirrors the in-memory mutation on
    /// `failedMessageIds`.
    @discardableResult
    func dbSetMessageSendFailed(conversationId: String,
                                 msgId: String,
                                 failed: Bool) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_set_message_send_failed(
            ctx, conversationId, msgId, failed ? 1 : 0) == 0
    }

    // MARK: - Save (settings + file records)

    @discardableResult
    func dbSaveSetting(_ key: String, _ value: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_setting(ctx, key, value) == 0
    }

    func dbLoadSetting(_ key: String, default defaultValue: String = "") -> String {
        guard let ctx = rawContext,
              let cstr = p2p_app_load_setting(ctx, key, defaultValue) else {
            return defaultValue
        }
        return String(cString: cstr)
    }

    @discardableResult
    func dbSaveFileRecord(_ r: DBFileRecord) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_file_record(
            ctx, r.transferId, r.chatKey, r.fileName, r.fileSize,
            r.peerId, r.peerName, r.timestampSecs,
            r.sent ? 1 : 0,
            Int32(r.status),
            Int32(r.chunksTotal), Int32(r.chunksComplete),
            r.savedPath) == 0
    }

    @discardableResult
    func dbDeleteFileRecord(transferId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_file_record(ctx, transferId) == 0
    }

    @discardableResult
    func dbDeleteFileRecordsForChat(chatKey: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_file_records_for_chat(ctx, chatKey) == 0
    }

    /// Encode a P2PTransferStatus into a single int for the file_transfers
    /// row.  Symmetric with decodeStatus() on load — keep them in sync.
    /// Values are deliberately non-zero for terminal states so a default-0
    /// row reads as inFlight.
    static func encodeStatus(_ s: P2PTransferStatus) -> Int {
        switch s {
        case .inFlight:                       return 0
        case .completed:                      return 1
        case .delivered:                      return 2
        case .canceled(let byReceiver):       return byReceiver ? 4 : 3
        case .blocked(let byReceiver):        return byReceiver ? 6 : 5
        }
    }

    static func decodeStatus(_ i: Int) -> P2PTransferStatus {
        switch i {
        case 1: return .completed
        case 2: return .delivered
        case 3: return .canceled(byReceiver: false)
        case 4: return .canceled(byReceiver: true)
        case 5: return .blocked(byReceiver: false)
        case 6: return .blocked(byReceiver: true)
        default: return .inFlight
        }
    }

    // MARK: - Load (callback bridges)

    /// Load every contact row.  Synchronous — callback fires per row,
    /// then this returns when the C iterator drains.  Caller buffers
    /// rows into an array if it needs them after the call ends.
    /// `each` is marked @escaping because the heap-box pattern hands
    /// it through Unmanaged for the C trampoline to recover; the
    /// closure doesn't actually outlive this call frame in practice.
    func dbLoadAllContacts(_ each: @escaping (DBContact) -> Void) {
        guard let ctx = rawContext else { return }
        // Heap-box the closure so the C trampoline can recover it via
        // bridging.  Lifetimes: the box lives until p2p_app_load_contacts
        // returns; we deallocate after.
        let box = Unmanaged.passRetained(ContactCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_contacts(ctx, { peerIdC, nameC, subtitleC,
                                       avatarC, muted, lastActive, ud in
            guard let ud,
                  let peerIdC, let nameC, let subtitleC, let avatarC else { return }
            let unbox = Unmanaged<ContactCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            unbox.handler(DBContact(
                peerId:        String(cString: peerIdC),
                name:          String(cString: nameC),
                subtitle:      String(cString: subtitleC),
                avatarB64:     String(cString: avatarC),
                muted:         muted != 0,
                lastActiveSecs: lastActive))
        }, box.toOpaque())
    }

    /// Load every conversation row (direct + group) in last_active DESC
    /// order.  Mirrors dbLoadAllContacts but for the chat-thread side
    /// of the v3 split.
    func dbLoadAllConversations(_ each: @escaping (DBConversation) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(ConversationCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_conversations(ctx, {
            idC, kindC, directPeerC, groupNameC, groupAvC,
            muted, lastActive, inChatList, ud in
            guard let ud, let idC, let kindC else { return }
            let unbox = Unmanaged<ConversationCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            // The pure-string fields can be NULL on the C side when
            // they're irrelevant for this kind (e.g. group_name on a
            // direct row); coerce to empty so the Swift struct stays
            // non-optional.
            let direct = directPeerC.flatMap { String(cString: $0) } ?? ""
            let gname  = groupNameC.flatMap  { String(cString: $0) } ?? ""
            let gav    = groupAvC.flatMap    { String(cString: $0) } ?? ""
            unbox.handler(DBConversation(
                id:              String(cString: idC),
                kind:            DBConversationKind.from(String(cString: kindC)),
                directPeerId:    direct,
                groupName:       gname,
                groupAvatarB64:  gav,
                muted:           muted != 0,
                lastActiveSecs:  lastActive,
                inChatList:      inChatList != 0))
        }, box.toOpaque())
    }

    /// Stream the peer_ids of every member of a conversation.  Used at
    /// startup to populate group rosters from the v3
    /// conversation_members table.
    func dbLoadConversationMembers(conversationId: String,
                                    _ each: @escaping (String) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(MemberCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_conversation_members(ctx, conversationId,
            { peerIdC, ud in
                guard let ud, let peerIdC else { return }
                let unbox = Unmanaged<MemberCallbackBox>.fromOpaque(ud).takeUnretainedValue()
                unbox.handler(String(cString: peerIdC))
            }, box.toOpaque())
    }

    /// Load every message for `conversationId` in chronological order.
    func dbLoadMessages(conversationId: String,
                        _ each: @escaping (DBMessage) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(MessageCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_messages(ctx, conversationId,
            { sent, textC, ts, msgIdC, senderIdC, senderNameC, sendFailed, ud in
            guard let ud, let textC, let msgIdC,
                  let senderIdC, let senderNameC else { return }
            let unbox = Unmanaged<MessageCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            unbox.handler(DBMessage(
                sent:          sent != 0,
                text:          String(cString: textC),
                timestampSecs: ts,
                msgId:         String(cString: msgIdC),
                senderId:      String(cString: senderIdC),
                senderName:    String(cString: senderNameC),
                sendFailed:    sendFailed != 0))
        }, box.toOpaque())
    }

    /// Stream file-transfer rows for `chatKey` (peerId or groupId).
    func dbLoadFileRecords(chatKey: String,
                            _ each: @escaping (DBFileRecord) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(FileRecordCallbackBox(handler: each))
        defer { box.release() }
        // Capture chatKey so we can stamp it onto each row — the C
        // callback only carries the per-row fields, not the query
        // predicate that produced them.
        let ck = chatKey
        p2p_app_load_file_records(ctx, chatKey,
            { tidC, fnC, fs, pidC, pnC, ts, sent, status, ct, cc, spC, ud in
                guard let ud, let tidC, let fnC, let pidC, let pnC, let spC else { return }
                let unbox = Unmanaged<FileRecordCallbackBox>.fromOpaque(ud).takeUnretainedValue()
                unbox.handler(DBFileRecord(
                    transferId:     String(cString: tidC),
                    chatKey:        "",       // overwritten below
                    fileName:       String(cString: fnC),
                    fileSize:       fs,
                    peerId:         String(cString: pidC),
                    peerName:       String(cString: pnC),
                    timestampSecs:  ts,
                    sent:           sent != 0,
                    status:         Int(status),
                    chunksTotal:    Int(ct),
                    chunksComplete: Int(cc),
                    savedPath:      String(cString: spC)))
            }, box.toOpaque())
        // The closure copies tids out via String(cString:), so handing
        // the chatKey back through a side channel works — but cleaner
        // to just have callers use the chatKey they already passed in.
        _ = ck
    }
}

// Heap-allocated callback boxes — one per loader so C trampolines can
// recover the Swift closure via Unmanaged round-trip.  Plain reference
// types (not structs) so Unmanaged can hand out a stable opaque pointer.
private final class ContactCallbackBox {
    let handler: (Peer2PearClient.DBContact) -> Void
    init(handler: @escaping (Peer2PearClient.DBContact) -> Void) { self.handler = handler }
}

private final class ConversationCallbackBox {
    let handler: (Peer2PearClient.DBConversation) -> Void
    init(handler: @escaping (Peer2PearClient.DBConversation) -> Void) { self.handler = handler }
}

private final class MessageCallbackBox {
    let handler: (Peer2PearClient.DBMessage) -> Void
    init(handler: @escaping (Peer2PearClient.DBMessage) -> Void) { self.handler = handler }
}

private final class MemberCallbackBox {
    let handler: (String) -> Void
    init(handler: @escaping (String) -> Void) { self.handler = handler }
}

private final class FileRecordCallbackBox {
    let handler: (Peer2PearClient.DBFileRecord) -> Void
    init(handler: @escaping (Peer2PearClient.DBFileRecord) -> Void) { self.handler = handler }
}

// MARK: - Startup load

extension Peer2PearClient {

    /// Populate the @Published surfaces from the SQLCipher DB.  Called
    /// from `start()` after the core has bound the AppDataStore.
    ///
    /// v3 split: contacts and conversations live in different tables.
    /// We load them separately:
    ///   - contacts → `contactNicknames` / `knownPeerContacts` / etc.
    ///   - conversations(kind=group) → `groups` dict (keyed by group_id)
    ///   - conversations(kind=direct) → `directConversationIdByPeer`
    ///     (peer → conv-id mapping; `messages` stays peer-keyed for the
    ///     view layer's sake)
    func loadStateFromDb() {
        // Phase 1: drain contacts (address book only).
        var loadedContacts: [DBContact] = []
        dbLoadAllContacts { loadedContacts.append($0) }

        var newContacts:    Set<String>      = []
        var newNicknames:   [String: String] = [:]
        var newBlocked:     Set<String>      = []
        var newMuted:       Set<String>      = []

        for c in loadedContacts {
            // v3: contacts are address-book entries by definition —
            // no in_address_book toggle, just presence in the table.
            newContacts.insert(c.peerId)
            if !c.name.isEmpty { newNicknames[c.peerId] = c.name }
            if c.muted         { newMuted.insert(c.peerId)      }
            // c.isBlocked is dead state since Phase 3h — block lives in
            // its own table now, hydrated below.  Field stays in
            // DBContact for legacy ABI but is ignored at this layer.
        }

        // Phase 3h: blocked keys are independent of contacts.  A
        // blocked stranger has no contacts row but still needs to
        // round-trip into blockedPeerIds so inbound messages from them
        // are filtered.  Curated contacts who happen to be blocked
        // appear in BOTH sets — runtime checks just consult the
        // blocked set.
        dbLoadAllBlockedKeys { peerId in
            newBlocked.insert(peerId)
        }

        // Phase 2: drain conversations.  Groups populate `groups` /
        // `groupAvatars`; direct conversations build the peer → conv-id
        // index used by saveMessage / loadMessages call sites.
        var loadedConversations: [DBConversation] = []
        dbLoadAllConversations { loadedConversations.append($0) }

        var newGroups:                  [String: P2PGroup] = [:]
        var newGroupAvatars:            [String: String]   = [:]
        var newDirectConvIdByPeer:      [String: String]   = [:]
        var newConvMutedIds:            Set<String>        = []
        var newArchivedDirectPeerIds:   Set<String>        = []

        for conv in loadedConversations {
            switch conv.kind {
            case .group:
                // Skip conversations the user dropped from the chat
                // list — they reappear automatically when a fresh
                // inbound group_msg flips inChatList back to true via
                // the core's ensureGroupConversation path.
                guard conv.inChatList else { continue }
                var members: [String] = []
                dbLoadConversationMembers(conversationId: conv.id) { pid in
                    members.append(pid)
                }
                let g = P2PGroup(
                    id:           conv.id,
                    name:         conv.groupName,
                    memberIds:    members,
                    lastActivity: Date(timeIntervalSince1970: TimeInterval(conv.lastActiveSecs)))
                newGroups[conv.id] = g
                if !conv.groupAvatarB64.isEmpty {
                    newGroupAvatars[conv.id] = conv.groupAvatarB64
                }
                if conv.muted { newConvMutedIds.insert(conv.id) }
            case .direct:
                guard !conv.directPeerId.isEmpty else { continue }
                // Direct rows: keep the conv-id mapping populated even
                // for archived chats so resume-on-message works.  The
                // archive set is consulted by the chat list filter.
                newDirectConvIdByPeer[conv.directPeerId] = conv.id
                if conv.muted        { newConvMutedIds.insert(conv.directPeerId) }
                if !conv.inChatList  { newArchivedDirectPeerIds.insert(conv.directPeerId) }
            }
        }

        // Phase 3: drain messages + file records per conversation.
        // For groups we read messages keyed by conv.id (== group_id);
        // for direct chats we read by conv.id but emit P2PMessages
        // keyed by the OTHER party's peerId so views stay peer-keyed.
        var newMessages:      [P2PMessage]              = []
        var newGroupMessages: [P2PGroupMessage]         = []
        var newTransfers:     [String: P2PTransferRecord] = [:]
        // Rehydrates @Published failedMessageIds: any outbound row
        // with send_failed=1 from the DB feeds in here so the
        // red-! indicator survives a relaunch instead of vanishing
        // when the in-memory set was cleared on lock.
        var newFailedIds:     Set<String> = []

        let myId = myPeerId
        for conv in loadedConversations {
            // file_transfers is still keyed by chatKey (peerId for
            // direct, groupId for group) — independent of the
            // conversations table.
            let fileChatKey = conv.kind == .group
                ? conv.id
                : conv.directPeerId
            if !fileChatKey.isEmpty {
                dbLoadFileRecords(chatKey: fileChatKey) { dbf in
                    let direction: P2PTransferDirection = dbf.sent ? .outbound : .inbound
                    newTransfers[dbf.transferId] = P2PTransferRecord(
                        id:           dbf.transferId,
                        peerId:       dbf.peerId.isEmpty ? fileChatKey : dbf.peerId,
                        fileName:     dbf.fileName,
                        fileSize:     dbf.fileSize,
                        direction:    direction,
                        chunksDone:   dbf.chunksComplete,
                        chunksTotal:  dbf.chunksTotal,
                        savedPath:    dbf.savedPath.isEmpty ? nil : dbf.savedPath,
                        status:       Self.decodeStatus(dbf.status),
                        timestamp:    Date(timeIntervalSince1970: TimeInterval(dbf.timestampSecs)))
                }
            }

            switch conv.kind {
            case .group:
                let g = newGroups[conv.id]
                let groupName = g?.name ?? conv.groupName
                let memberIds = g?.memberIds ?? []
                dbLoadMessages(conversationId: conv.id) { dbm in
                    // senderId carries the originator's peer_id for
                    // inbound; outbound has senderId == "" and we
                    // stamp `from = myId` so the bubble renders on
                    // the right side.
                    let from = dbm.sent
                        ? myId
                        : (dbm.senderId.isEmpty ? myId : dbm.senderId)
                    let id = dbm.msgId.isEmpty ? UUID().uuidString : dbm.msgId
                    newGroupMessages.append(P2PGroupMessage(
                        id:        id,
                        from:      from,
                        groupId:   conv.id,
                        groupName: groupName,
                        members:   memberIds,
                        text:      dbm.text,
                        timestamp: Date(timeIntervalSince1970: TimeInterval(dbm.timestampSecs))))
                    if dbm.sent && dbm.sendFailed {
                        newFailedIds.insert(id)
                    }
                }
            case .direct:
                guard !conv.directPeerId.isEmpty else { continue }
                let other = conv.directPeerId
                dbLoadMessages(conversationId: conv.id) { dbm in
                    let id = dbm.msgId.isEmpty ? UUID().uuidString : dbm.msgId
                    newMessages.append(P2PMessage(
                        id:        id,
                        from:      dbm.sent ? myId : other,
                        text:      dbm.text,
                        timestamp: Date(timeIntervalSince1970: TimeInterval(dbm.timestampSecs)),
                        to:        dbm.sent ? other : nil))
                    if dbm.sent && dbm.sendFailed {
                        newFailedIds.insert(id)
                    }
                }
            }
        }

        // Person-mute (contacts.muted) and conversation-mute
        // (conversations.muted) feed the same `mutedPeerIds` set —
        // the view layer's isMuted() check treats them as equivalent
        // for SwiftUI purposes.  The C++ side keeps them split for
        // the notification layer; iOS unifies for in-memory queries.
        newMuted.formUnion(newConvMutedIds)

        // Push to @Published on the main queue so SwiftUI rerenders
        // exactly once per startup, not once per row.
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts          = newContacts
            self.mutedPeerIds               = newMuted
            self.contactNicknames           = newNicknames
            self.blockedPeerIds             = newBlocked
            self.groups                     = newGroups
            self.groupAvatars               = newGroupAvatars
            self.directConversationIdByPeer = newDirectConvIdByPeer
            self.archivedDirectPeerIds      = newArchivedDirectPeerIds
            self.messages                   = newMessages
            self.groupMessages              = newGroupMessages
            self.failedMessageIds           = newFailedIds
            self.transfers                  = newTransfers

            // Replay group rosters to the core so inbound control
            // messages from existing members pass authorization.
            // Same shape as the old store.load() code path.
            for g in newGroups.values {
                self.setKnownGroupMembers(groupId: g.id, memberPeerIds: g.memberIds)
            }
        }
    }
}
