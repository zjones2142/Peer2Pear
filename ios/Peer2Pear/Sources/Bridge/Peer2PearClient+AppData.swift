import Foundation

// MARK: - AppDataStore Swift wrappers
//
// Thin layer over the p2p_app_* C API.  Uses C-friendly buffers for
// callback dispatch — Swift closures can't be cast to C function
// pointers when they capture, so each loader allocates a heap-backed
// callback context, threads it through the C call, and copies rows out.
//
// All methods marshal Swift Strings via `cString(using: .utf8)` (which
// returns optional CChar arrays the C API can read) — Swift's automatic
// String → UnsafePointer<CChar> bridging only lasts the duration of the
// expression, which is wrong for the heap-context pattern.

extension Peer2PearClient {

    /// Wire-format mirror of AppDataStore::Contact.  Used both as the
    /// row decode shape and the encode shape for save calls.
    struct DBContact {
        let peerId: String
        var name: String = ""
        var subtitle: String = ""
        var keys: [String] = []
        var isBlocked: Bool = false
        var isGroup: Bool = false
        var groupId: String = ""
        var avatarB64: String = ""
        var lastActiveSecs: Int64 = 0
        /// iOS chats-vs-contacts split.  Stranger-message stub rows
        /// have this false; explicit add-contact / import sets it true.
        var inAddressBook: Bool = true
    }

    /// Mirror of AppDataStore::Message.
    struct DBMessage {
        let sent: Bool
        let text: String
        let timestampSecs: Int64
        let msgId: String
        /// Sender peer ID for group messages; empty for 1:1.  See
        /// AppDataStore.hpp for the cross-platform semantic.
        let senderName: String
    }

    /// Mirror of AppDataStore::FileRecord.  Used to persist the
    /// `transfers` dict so file rows survive lock/unlock.
    struct DBFileRecord {
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

    // MARK: - Save

    @discardableResult
    func dbSaveContact(_ c: DBContact) -> Bool {
        guard let ctx = rawContext else { return false }
        // Build a NULL-terminated [UnsafePointer<CChar>?] for the keys.
        let keyDups = c.keys.map { strdup($0) }
        defer { keyDups.forEach { free($0) } }
        var keyPtrs: [UnsafePointer<CChar>?] = keyDups.map { $0.map { UnsafePointer($0) } }
        keyPtrs.append(nil)
        return keyPtrs.withUnsafeMutableBufferPointer { buf -> Bool in
            p2p_app_save_contact(
                ctx, c.peerId, c.name, c.subtitle, buf.baseAddress,
                c.isBlocked ? 1 : 0,
                c.isGroup   ? 1 : 0,
                c.groupId, c.avatarB64,
                c.lastActiveSecs,
                c.inAddressBook ? 1 : 0) == 0
        }
    }

    @discardableResult
    func dbDeleteContact(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_contact(ctx, peerId) == 0
    }

    @discardableResult
    func dbSaveContactAvatar(peerId: String, avatarB64: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_contact_avatar(ctx, peerId, avatarB64) == 0
    }

    @discardableResult
    func dbSaveMessage(peerId: String, message: DBMessage) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_save_message(
            ctx, peerId,
            message.sent ? 1 : 0,
            message.text,
            message.timestampSecs,
            message.msgId,
            message.senderName) == 0
    }

    @discardableResult
    func dbDeleteMessages(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        return p2p_app_delete_messages(ctx, peerId) == 0
    }

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
        p2p_app_load_contacts(ctx, { peerIdC, nameC, subtitleC, keysC,
                                       isBlocked, isGroup, groupIdC,
                                       avatarC, lastActive, inAB, ud in
            guard let ud,
                  let peerIdC, let nameC, let subtitleC,
                  let groupIdC, let avatarC else { return }
            let unbox = Unmanaged<ContactCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            var keys: [String] = []
            if let keysC {
                var i = 0
                while let k = keysC[i] { keys.append(String(cString: k)); i += 1 }
            }
            unbox.handler(DBContact(
                peerId:        String(cString: peerIdC),
                name:          String(cString: nameC),
                subtitle:      String(cString: subtitleC),
                keys:          keys,
                isBlocked:     isBlocked != 0,
                isGroup:       isGroup   != 0,
                groupId:       String(cString: groupIdC),
                avatarB64:     String(cString: avatarC),
                lastActiveSecs: lastActive,
                inAddressBook: inAB != 0))
        }, box.toOpaque())
    }

    /// Load every message for `peerId` in chronological order.
    func dbLoadMessages(peerId: String, _ each: @escaping (DBMessage) -> Void) {
        guard let ctx = rawContext else { return }
        let box = Unmanaged.passRetained(MessageCallbackBox(handler: each))
        defer { box.release() }
        p2p_app_load_messages(ctx, peerId, { sent, textC, ts, msgIdC, senderC, ud in
            guard let ud, let textC, let msgIdC, let senderC else { return }
            let unbox = Unmanaged<MessageCallbackBox>.fromOpaque(ud).takeUnretainedValue()
            unbox.handler(DBMessage(
                sent:          sent != 0,
                text:          String(cString: textC),
                timestampSecs: ts,
                msgId:         String(cString: msgIdC),
                senderName:    String(cString: senderC)))
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

private final class MessageCallbackBox {
    let handler: (Peer2PearClient.DBMessage) -> Void
    init(handler: @escaping (Peer2PearClient.DBMessage) -> Void) { self.handler = handler }
}

private final class FileRecordCallbackBox {
    let handler: (Peer2PearClient.DBFileRecord) -> Void
    init(handler: @escaping (Peer2PearClient.DBFileRecord) -> Void) { self.handler = handler }
}

// MARK: - Startup load

extension Peer2PearClient {

    /// Populate the @Published surfaces from the SQLCipher DB.  Called
    /// from `start()` after the core has bound the AppDataStore.
    func loadStateFromDb() {
        var loadedContacts:    [DBContact] = []
        dbLoadAllContacts { loadedContacts.append($0) }

        var newContacts:       Set<String>          = []
        var newNicknames:      [String: String]     = [:]
        var newBlocked:        Set<String>          = []
        var newGroups:         [String: P2PGroup]   = [:]
        var newGroupAvatars:   [String: String]     = [:]

        for c in loadedContacts {
            if c.isGroup {
                let g = P2PGroup(
                    id:           c.peerId,
                    name:         c.name,
                    memberIds:    c.keys,
                    lastActivity: Date(timeIntervalSince1970: TimeInterval(c.lastActiveSecs)))
                newGroups[c.peerId] = g
                if !c.avatarB64.isEmpty { newGroupAvatars[c.peerId] = c.avatarB64 }
            } else {
                if c.inAddressBook { newContacts.insert(c.peerId) }
                if !c.name.isEmpty { newNicknames[c.peerId] = c.name }
                if c.isBlocked     { newBlocked.insert(c.peerId) }
            }
        }

        // Walk every contact once to drain its messages + file records.
        // Transfers are dict-keyed by transferId; persistTransfer keeps
        // the file_transfers row in sync as the user later sends/receives.
        var newMessages:      [P2PMessage]      = []
        var newGroupMessages: [P2PGroupMessage] = []
        var newTransfers:     [String: P2PTransferRecord] = [:]

        let myId = myPeerId
        for c in loadedContacts {
            dbLoadFileRecords(chatKey: c.peerId) { dbf in
                let direction: P2PTransferDirection = dbf.sent ? .outbound : .inbound
                newTransfers[dbf.transferId] = P2PTransferRecord(
                    id:           dbf.transferId,
                    peerId:       dbf.peerId.isEmpty ? c.peerId : dbf.peerId,
                    fileName:     dbf.fileName,
                    fileSize:     dbf.fileSize,
                    direction:    direction,
                    chunksDone:   dbf.chunksComplete,
                    chunksTotal:  dbf.chunksTotal,
                    savedPath:    dbf.savedPath.isEmpty ? nil : dbf.savedPath,
                    status:       Self.decodeStatus(dbf.status),
                    timestamp:    Date(timeIntervalSince1970: TimeInterval(dbf.timestampSecs)))
            }
            if c.isGroup {
                let groupName = c.name
                let memberIds = c.keys
                dbLoadMessages(peerId: c.peerId) { dbm in
                    let from = dbm.senderName.isEmpty ? myId : dbm.senderName
                    newGroupMessages.append(P2PGroupMessage(
                        id:        dbm.msgId.isEmpty ? UUID().uuidString : dbm.msgId,
                        from:      from,
                        groupId:   c.peerId,
                        groupName: groupName,
                        members:   memberIds,
                        text:      dbm.text,
                        timestamp: Date(timeIntervalSince1970: TimeInterval(dbm.timestampSecs))))
                }
            } else {
                dbLoadMessages(peerId: c.peerId) { dbm in
                    newMessages.append(P2PMessage(
                        id:        dbm.msgId.isEmpty ? UUID().uuidString : dbm.msgId,
                        from:      dbm.sent ? myId : c.peerId,
                        text:      dbm.text,
                        timestamp: Date(timeIntervalSince1970: TimeInterval(dbm.timestampSecs)),
                        to:        dbm.sent ? c.peerId : nil))
                }
            }
        }

        // Push to @Published on the main queue so SwiftUI rerenders
        // exactly once per startup, not once per row.
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts = newContacts
            self.contactNicknames  = newNicknames
            self.blockedPeerIds    = newBlocked
            self.groups            = newGroups
            self.groupAvatars      = newGroupAvatars
            self.messages          = newMessages
            self.groupMessages     = newGroupMessages
            self.transfers         = newTransfers

            // Replay group rosters to the core so inbound control
            // messages from existing members pass authorization.
            // Same shape as the old store.load() code path.
            for g in newGroups.values {
                self.setKnownGroupMembers(groupId: g.id, memberPeerIds: g.memberIds)
            }
        }
    }
}

