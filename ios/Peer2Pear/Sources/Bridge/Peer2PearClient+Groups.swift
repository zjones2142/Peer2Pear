import Foundation

// MARK: - Group chat mutations
//
// All the group CRUD/messaging entry points that SwiftUI views call.
// Moved out of Peer2PearClient.swift to keep that file focused on
// lifecycle, contacts, and core client state.  No stored properties
// here — every method reads/writes `self.groups`, `self.groupMessages`,
// and `self.groupAvatars` on the main actor.

extension Peer2PearClient {

    /// Create a new group locally.  `memberPeerIds` is the roster you
    /// want to invite (self is NOT included — the core filters self
    /// out when fanning out sends).  The returned `groupId` is a fresh
    /// UUID the app keeps and passes to every subsequent sendGroupText.
    ///
    /// There's no network round-trip here — groups exist only in the
    /// client.  Members learn about the group the first time they
    /// receive a message tagged with this groupId.
    ///
    /// Also seeds the core's in-memory roster for this group so
    /// subsequent control messages (rename / avatar / leave) from
    /// other members pass the authorization check.
    @discardableResult
    func createGroup(name: String, memberPeerIds: [String]) -> String {
        let gid = UUID().uuidString.lowercased()
        let group = P2PGroup(id: gid, name: name,
                             memberIds: memberPeerIds,
                             lastActivity: Date())
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.groups[gid] = group
            // v3: group state lives in the conversations table (kind
            // = group), with the roster denormalized into
            // conversation_members.  conv id == group_id by design,
            // so existing call sites that pass a group_id keep working.
            self.dbSaveConversation(DBConversation(
                id:              gid,
                kind:            .group,
                groupName:       name,
                groupAvatarB64:  "",
                muted:           false,
                lastActiveSecs:  Int64(group.lastActivity.timeIntervalSince1970),
                inChatList:      true))
            self.dbSetConversationMembers(conversationId: gid,
                                           peerIds: memberPeerIds)
        }
        // Seed the core's roster with self + members so we'll accept
        // inbound rename/avatar/leave from any of them.
        if let ctx = rawContext {
            var roster = memberPeerIds
            if !roster.contains(myPeerId) {
                roster.append(myPeerId)
            }
            withCStringArray(roster) { ptr in
                p2p_set_known_group_members(ctx, gid, ptr)
            }
        }
        return gid
    }

    /// Seed the core's roster for a group that was either (a) loaded
    /// from local persistence on startup or (b) learned about via an
    /// inbound message.  Call on every known group after start() so
    /// the authorization check admits control messages from other members.
    func setKnownGroupMembers(groupId: String, memberPeerIds: [String]) {
        guard let ctx = rawContext else { return }
        withCStringArray(memberPeerIds) { ptr in
            p2p_set_known_group_members(ctx, groupId, ptr)
        }
    }

    /// Send a text message to every member of a group.  `memberPeerIds`
    /// must include the recipients (self is filtered out internally).
    /// `msgId` is optional but recommended — passing the same UUID
    /// the local echo bubble carries lets `on_send_failed` correlate
    /// retry-exhaustion back to that specific bubble (red-! indicator,
    /// retry / delete affordance).  Empty falls back to v1 (core mints
    /// internally, no per-bubble feedback).
    func sendGroupText(groupId: String,
                       groupName: String,
                       memberPeerIds: [String],
                       text: String,
                       msgId: String = "") {
        guard let ctx = rawContext else { return }
        withCStringArray(memberPeerIds) { ptr in
            _ = p2p_send_group_text_v2(ctx, groupId, groupName, ptr, text, msgId)
        }
    }

    /// Retry a previously-failed group send.  Drops the old echo
    /// bubble (memory + DB) + clears its failure marker, then
    /// re-sends with a fresh msgId.  Mirrors retryFailedMessage's
    /// 1:1 semantics — old bubble is replaced by the new attempt
    /// at the bottom of the thread.
    func retryFailedGroupMessage(messageId: String,
                                   groupId: String,
                                   groupName: String,
                                   memberPeerIds: [String],
                                   text: String) {
        if failedMessageIds.contains(messageId) {
            failedMessageIds.remove(messageId)
        }
        // deleteMessage(chatKey:msgId:) accepts either a peerId or
        // a groupId; for groups the chatKey IS the conversation_id.
        deleteMessage(chatKey: groupId, msgId: messageId)
        // Fresh send — generates a new bubble + new msgId via the
        // normal sendGroupText path.  The caller (ConversationView)
        // mints the UUID; this helper uses the standard send path
        // through the existing send() callsite.
        let newId = UUID().uuidString
        let echo = P2PGroupMessage(
            id: newId,
            from: myPeerId,
            groupId: groupId,
            groupName: groupName,
            members: memberPeerIds,
            text: text,
            timestamp: Date())
        groupMessages.append(echo)
        dbSaveMessage(conversationId: groupId, message: DBMessage(
            sent:          true,
            text:          text,
            timestampSecs: Int64(echo.timestamp.timeIntervalSince1970),
            msgId:         newId,
            senderId:      "",
            senderName:    ""))
        sendGroupText(groupId: groupId, groupName: groupName,
                       memberPeerIds: memberPeerIds, text: text,
                       msgId: newId)
    }

    /// Send a file to every member of a group.  Mirrors `sendFile` for
    /// 1:1 — chunks stream after each recipient's file_accept.
    @discardableResult
    func sendGroupFile(groupId: String,
                       groupName: String,
                       memberPeerIds: [String],
                       fileName: String,
                       filePath: String) -> String? {
        guard let ctx = rawContext else { return nil }
        return withCStringArray(memberPeerIds) { ptr -> String? in
            guard let c = p2p_send_group_file(ctx, groupId, groupName,
                                              ptr, fileName, filePath) else {
                return nil
            }
            return String(cString: c)
        }
    }

    /// Rename a group — broadcasts a `group_rename` control message.
    @discardableResult
    func renameGroup(groupId: String, newName: String,
                     memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_rename_group(ctx, groupId, newName, ptr)
        }
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                guard let self, var g = self.groups[groupId] else { return }
                g.name = newName
                g.lastActivity = Date()
                self.groups[groupId] = g
                self.dbSaveConversation(DBConversation(
                    id:              groupId,
                    kind:            .group,
                    groupName:       newName,
                    groupAvatarB64:  self.groupAvatars[groupId] ?? "",
                    muted:           self.isMuted(peerId: groupId),
                    lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
                    inChatList:      true))
            }
        }
        return rc == 0
    }

    /// Leave a group — broadcasts a `group_leave` notification.
    /// iMessage-parity: local transcript + group entry stay.  Members
    /// get the leave marker; the user keeps their history and can wipe
    /// it separately via swipe-to-delete → `deleteChat(peerId:)`.
    @discardableResult
    func leaveGroup(groupId: String, groupName: String,
                    memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_leave_group(ctx, groupId, groupName, ptr)
        }
        return rc == 0
    }

    /// Publish a new group avatar.  v3: group avatars live on the
    /// conversation row, not on a contact (groups aren't contacts).
    @discardableResult
    func sendGroupAvatar(groupId: String, avatarB64: String,
                         memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_send_group_avatar(ctx, groupId, avatarB64, ptr)
        }
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.groupAvatars[groupId] = avatarB64
                let g = self.groups[groupId]
                self.dbSaveConversation(DBConversation(
                    id:              groupId,
                    kind:            .group,
                    groupName:       g?.name ?? "",
                    groupAvatarB64:  avatarB64,
                    muted:           self.isMuted(peerId: groupId),
                    lastActiveSecs:  Int64((g?.lastActivity ?? Date()).timeIntervalSince1970),
                    inChatList:      true))
            }
        }
        return rc == 0
    }

    /// Broadcast an updated member list — new members learn about the
    /// group, dropped members see a left-marker.
    @discardableResult
    func updateGroupMembers(groupId: String, groupName: String,
                            memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_update_group_members(ctx, groupId, groupName, ptr)
        }
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                guard let self, var g = self.groups[groupId] else { return }
                g.memberIds = memberPeerIds
                g.lastActivity = Date()
                self.groups[groupId] = g
                self.dbSaveConversation(DBConversation(
                    id:              groupId,
                    kind:            .group,
                    groupName:       g.name,
                    groupAvatarB64:  self.groupAvatars[groupId] ?? "",
                    muted:           self.isMuted(peerId: groupId),
                    lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
                    inChatList:      true))
                self.dbSetConversationMembers(conversationId: groupId,
                                               peerIds: memberPeerIds)
            }
        }
        return rc == 0
    }

    // MARK: - Shared C-array marshaling

    /// Marshal `[String]` into the `const char**` (NULL-terminated) shape
    /// the C API expects.  All five group-mutation wrappers above share
    /// the same prologue — consolidate here to keep them readable.  Also
    /// used by `checkPresence` / `subscribePresence` in the main file.
    func withCStringArray<R>(_ strings: [String],
                              _ body: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> R) -> R {
        let cStrings = strings.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        var cArray: [UnsafePointer<CChar>?] =
            cStrings.map { $0.map { UnsafePointer($0) } }
        cArray.append(nil)
        return cArray.withUnsafeMutableBufferPointer { buf in
            body(buf.baseAddress)
        }
    }
}
