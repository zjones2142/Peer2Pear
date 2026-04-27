import Foundation

// MARK: - C FFI callback wiring
//
// `setupCallbacks()` attaches all 15 `p2p_set_on_*` closures to the
// core context.  Each one marshals C types → Swift, dispatches to the
// main actor, and mutates a sliver of @Published state.  The body was
// the largest single chunk of Peer2PearClient.swift — lifted here
// verbatim.  Helpers it needs (`from`, `stringsFromCArray`,
// `upsertTransfer`, `markTransferStatus`, `fireLocalNotification`) live
// in their natural-owner files and are reachable here via `internal`
// module access.

extension Peer2PearClient {

    internal func setupCallbacks() {
        guard let ctx = rawContext else { return }
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        // ── Connection / status ─────────────────────────────────────────
        p2p_set_on_connected(ctx, { ud in
            guard let client = Peer2PearClient.from(ud) else { return }
            DispatchQueue.main.async { client.isConnected = true }
        }, selfPtr)

        p2p_set_on_status(ctx, { msg, ud in
            guard let client = Peer2PearClient.from(ud), let msg else { return }
            let str = String(cString: msg)
            DispatchQueue.main.async {
                client.statusMessage = str
                // Also surface as a transient toast on the chat list so
                // group-send failures / relay retries don't stay
                // invisible.  OnboardingView keeps its own read of
                // statusMessage for the unlock banner.
                if !str.isEmpty { client.toastMessage = str }
            }
        }, selfPtr)

        // ── Incoming 1:1 text ──────────────────────────────────────────
        p2p_set_on_message(ctx, { from, text, ts, msgId, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let text, let msgId else { return }
            let msg = P2PMessage(
                id: String(cString: msgId),
                from: String(cString: from),
                text: String(cString: text),
                timestamp: Date(timeIntervalSince1970: TimeInterval(ts))
            )
            DispatchQueue.main.async {
                // Drop messages from blocked peers.  Mirrors desktop
                // chatview `if (chat.isBlocked) return`.  Silent — no
                // notification, no list entry.
                if client.isBlocked(peerId: msg.from) { return }
                client.messages.append(msg)
                // Blue-dot marker in ChatListView.  Cleared when the
                // user opens the thread (ConversationView.onAppear).
                // Skip the insert when the user is actively viewing
                // this thread — they're already watching the message
                // land, so re-flagging it as unread the moment they
                // back out is a regression they (rightly) noticed.
                if client.activeChatId != msg.from {
                    client.unreadChatIds.insert(msg.from)
                }
                // Resolve / mint the conversation_id INSIDE the async
                // block.  Calling ensureDirectConversationId
                // synchronously BEFORE the dispatch re-enters
                // p2p_app_find_or_create_direct_conversation while
                // the C++ side still holds the WS-receive ctrlMu —
                // same non-recursive std::mutex, same thread →
                // deadlock.  See peer2pear_api.cpp ~line 1605: the
                // p2p_app_load_contacts case documents the same
                // invariant ("Do NOT hold ctrlMu across the
                // callback...").  By the time this async block fires
                // the C++ side has returned and the lock is free.
                // v3 contract: stranger's first inbound message
                // creates a CONVERSATION, not a contact (address
                // book stays user-curated).
                let convId = client.ensureDirectConversationId(for: msg.from)
                // Persist into the v3 messages table keyed by
                // conversation_id.  senderId carries the originator's
                // peer_id — needed on a later restart to route the
                // row back to the right bubble side.
                if let convId {
                    client.dbSaveMessage(conversationId: convId, message: DBMessage(
                        sent:          false,
                        text:          msg.text,
                        timestampSecs: Int64(msg.timestamp.timeIntervalSince1970),
                        msgId:         msg.id,
                        senderId:      msg.from,
                        senderName:    ""))
                }
                // threadId = sender so iOS groups banners per-conversation.
                // The content-privacy mode decides how much actually
                // enters the OS notification store.  Skip entirely if
                // the user has muted this chat.
                if !client.isMuted(peerId: msg.from) {
                    client.fireLocalNotification(
                        fromPeerId: msg.from,
                        senderDisplay: String(msg.from.prefix(8)) + "…",
                        groupName: nil,
                        messageText: msg.text,
                        threadId: "dm:" + msg.from)
                }
            }
        }, selfPtr)

        // ── Incoming group text ────────────────────────────────────────
        p2p_set_on_group_message(ctx, {
            from, gid, gname, memberIds, text, ts, msgId, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let gid, let gname, let text, let msgId else { return }
            let members = Peer2PearClient.stringsFromCArray(memberIds)
            let gm = P2PGroupMessage(
                id: String(cString: msgId),
                from: String(cString: from),
                groupId: String(cString: gid),
                groupName: String(cString: gname),
                members: members,
                text: String(cString: text),
                timestamp: Date(timeIntervalSince1970: TimeInterval(ts))
            )
            DispatchQueue.main.async {
                client.groupMessages.append(gm)
                // Any in-order delivery clears the blocked-stream
                // banner for this (group, sender) pair.  If the gap
                // is only partially filled, the v2 dispatcher will
                // re-fire onGroupStreamBlocked with the new range.
                if gm.from != client.myPeerId {
                    client.groupBlockedStreams[gm.groupId]?.removeValue(forKey: gm.from)
                    if client.groupBlockedStreams[gm.groupId]?.isEmpty == true {
                        client.groupBlockedStreams.removeValue(forKey: gm.groupId)
                    }
                }
                // Skip the unread marker when (a) it's our own echo
                // — the sender sees their message immediately and
                // doesn't need a "new" indicator (same behaviour as
                // the notification-suppression guard below), or
                // (b) the user is currently viewing this group's
                // thread — re-flagging a chat the user is reading
                // produces a stale dot the moment they back out.
                if gm.from != client.myPeerId
                    && client.activeChatId != gm.groupId {
                    client.unreadChatIds.insert(gm.groupId)
                }
                // Upsert group roster.  Non-creator members learn about
                // a group by receiving a message tagged with its ID.
                // If the creator renames the group later, we also pick
                // that up here (last-write-wins on name + members).
                // Always add the SENDER to the roster (sendGroupText
                // strips self from the declared members so members ==
                // recipients) — otherwise subsequent control messages
                // from the sender would fail the authorization check.
                var roster = gm.members
                if !roster.contains(client.myPeerId) {
                    roster.append(client.myPeerId)
                }
                if !roster.contains(gm.from) {
                    roster.append(gm.from)
                }
                var g = client.groups[gm.groupId]
                    ?? P2PGroup(id: gm.groupId, name: gm.groupName,
                                 memberIds: roster, lastActivity: gm.timestamp)
                g.name = gm.groupName.isEmpty ? g.name : gm.groupName
                g.memberIds = roster
                g.lastActivity = max(g.lastActivity, gm.timestamp)
                client.groups[gm.groupId] = g
                // Seed core's roster too so inbound control messages
                // from this group's members are admitted.
                client.setKnownGroupMembers(groupId: gm.groupId,
                                             memberPeerIds: roster)
                // Persist: upsert the group's conversation metadata +
                // insert the message.  The conversation row itself is
                // guaranteed to exist (the C++ side calls
                // ensureGroupConversation + setConversationMembers
                // before dispatching this callback), so saveMessage's
                // FK requirement is met.  senderId carries the
                // originator's peer_id — needed on a later restart.
                client.dbSaveConversation(DBConversation(
                    id:              gm.groupId,
                    kind:            .group,
                    groupName:       g.name,
                    groupAvatarB64:  client.groupAvatars[gm.groupId] ?? "",
                    muted:           client.isMuted(peerId: gm.groupId),
                    lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
                    inChatList:      true))
                client.dbSaveMessage(conversationId: gm.groupId, message: DBMessage(
                    sent:          gm.from == client.myPeerId,
                    text:          gm.text,
                    timestampSecs: Int64(gm.timestamp.timeIntervalSince1970),
                    msgId:         gm.id,
                    senderId:      gm.from,
                    senderName:    gm.from))

                // Suppress the banner if the user muted this group.
                if !client.isMuted(peerId: gm.groupId) {
                    client.fireLocalNotification(
                        fromPeerId: gm.from,
                        senderDisplay: String(gm.from.prefix(8)) + "…",
                        groupName: gm.groupName.isEmpty ? "Group" : gm.groupName,
                        messageText: gm.text,
                        threadId: "group:" + gm.groupId)
                }
            }
        }, selfPtr)

        // ── Group member left ──────────────────────────────────────────
        // member_ids is the NEW roster as the sender saw it — replace
        // our stored roster verbatim.  Removing self means we were
        // removed; we leave our local state alone and let the user decide.
        p2p_set_on_group_member_left(ctx, {
            from, gid, gname, memberIds, _, _, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let gid, let gname else { return }
            let gidStr    = String(cString: gid)
            let fromStr   = String(cString: from)
            let gnameStr  = String(cString: gname)
            let members   = Peer2PearClient.stringsFromCArray(memberIds)
            DispatchQueue.main.async {
                // Drop the departing peer from our stored roster.
                if var g = client.groups[gidStr] {
                    g.memberIds = members.filter { $0 != client.myPeerId }
                    if !gnameStr.isEmpty { g.name = gnameStr }
                    g.lastActivity = Date()
                    client.groups[gidStr] = g
                } else {
                    // Unknown group — create a shell so the UI has something
                    // to render if the user reconnects mid-departure.
                    client.groups[gidStr] = P2PGroup(
                        id: gidStr, name: gnameStr, memberIds: members,
                        lastActivity: Date())
                }
                // Surface a transcript marker so the user sees what happened.
                let marker = P2PGroupMessage(
                    id: UUID().uuidString,
                    from: fromStr, groupId: gidStr, groupName: gnameStr,
                    members: members,
                    text: fromStr == client.myPeerId
                        ? "You left the group"
                        : "\(fromStr.prefix(8))… left the group",
                    timestamp: Date())
                client.groupMessages.append(marker)
                // Persist roster change + marker.  Members are kept
                // in sync by the C++ side (GroupProtocol calls
                // setConversationMembers when the roster changes), so
                // we only need to upsert the conversation metadata
                // and append the marker message.
                if let g = client.groups[gidStr] {
                    client.dbSaveConversation(DBConversation(
                        id:              gidStr,
                        kind:            .group,
                        groupName:       g.name,
                        groupAvatarB64:  client.groupAvatars[gidStr] ?? "",
                        muted:           client.isMuted(peerId: gidStr),
                        lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
                        inChatList:      true))
                }
                client.dbSaveMessage(conversationId: gidStr, message: DBMessage(
                    sent:          fromStr == client.myPeerId,
                    text:          marker.text,
                    timestampSecs: Int64(marker.timestamp.timeIntervalSince1970),
                    msgId:         marker.id,
                    senderId:      fromStr == client.myPeerId ? "" : fromStr,
                    senderName:    fromStr))
            }
        }, selfPtr)

        // ── Group renamed ──────────────────────────────────────────────
        p2p_set_on_group_renamed(ctx, { gid, newName, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let newName else { return }
            let gidStr = String(cString: gid)
            let nameStr = String(cString: newName)
            DispatchQueue.main.async {
                guard var g = client.groups[gidStr] else { return }
                g.name = nameStr
                g.lastActivity = Date()
                client.groups[gidStr] = g
                client.dbSaveConversation(DBConversation(
                    id:              gidStr,
                    kind:            .group,
                    groupName:       nameStr,
                    groupAvatarB64:  client.groupAvatars[gidStr] ?? "",
                    muted:           client.isMuted(peerId: gidStr),
                    lastActiveSecs:  Int64(g.lastActivity.timeIntervalSince1970),
                    inChatList:      true))
            }
        }, selfPtr)

        // ── Group avatar updated ───────────────────────────────────────
        // v3: group avatars live on the conversation row, not on a
        // contact (groups aren't contacts).  Re-upsert the whole
        // conversation row so the field-encrypted avatar lands in
        // place; group name + last_active come from in-memory state.
        p2p_set_on_group_avatar(ctx, { gid, avatarB64, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let avatarB64 else { return }
            let gidStr = String(cString: gid)
            let avatarStr = String(cString: avatarB64)
            DispatchQueue.main.async {
                if client.groupAvatars[gidStr] != avatarStr {
                    client.groupAvatars[gidStr] = avatarStr
                    let g = client.groups[gidStr]
                    client.dbSaveConversation(DBConversation(
                        id:              gidStr,
                        kind:            .group,
                        groupName:       g?.name ?? "",
                        groupAvatarB64:  avatarStr,
                        muted:           client.isMuted(peerId: gidStr),
                        lastActiveSecs:  Int64((g?.lastActivity ?? Date()).timeIntervalSince1970),
                        inChatList:      true))
                }
            }
        }, selfPtr)

        // ── pv=2 stream blocked: gap detected, gap_request fired ───────
        p2p_set_on_group_stream_blocked(ctx, { gid, sender, fromCtr, toCtr, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let sender else { return }
            let gidStr = String(cString: gid)
            let senderStr = String(cString: sender)
            DispatchQueue.main.async {
                client.groupBlockedStreams[gidStr, default: [:]][senderStr] =
                    Peer2PearClient.BlockedRange(from: fromCtr, to: toCtr)
            }
        }, selfPtr)

        // ── pv=2 messages lost on session reset ────────────────────────
        p2p_set_on_group_messages_lost(ctx, { gid, sender, count, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let sender else { return }
            let gidStr = String(cString: gid)
            let senderStr = String(cString: sender)
            DispatchQueue.main.async {
                client.groupLostMessages.append(
                    Peer2PearClient.LostMessagesEvent(
                        groupId: gidStr,
                        senderPeerId: senderStr,
                        count: count))
                // Once a session reset surfaces lost messages, the
                // gap that was blocking us is now closed (the buffer
                // was drained for the OLD session).  Clear the
                // banner state for this (group, sender) pair.
                client.groupBlockedStreams[gidStr]?.removeValue(forKey: senderStr)
            }
        }, selfPtr)

        // ── Presence push ──────────────────────────────────────────────
        // No-op guard: `peerPresence[pid] = isUp` always triggers
        // objectWillChange, even when the value is unchanged.  Relay
        // pushes are unconditional on subscribe/reconnect, so without
        // the guard every reconnect rebuilds every view that reads
        // peerPresence.
        p2p_set_on_presence(ctx, { peerId, online, ud in
            guard let client = Peer2PearClient.from(ud), let peerId else { return }
            let pid = String(cString: peerId)
            let isUp = online != 0
            DispatchQueue.main.async {
                if client.peerPresence[pid] != isUp {
                    client.peerPresence[pid] = isUp
                }
            }
        }, selfPtr)

        // ── Avatar from a peer ─────────────────────────────────────────
        p2p_set_on_avatar(ctx, { peerId, name, avatarB64, ud in
            guard let client = Peer2PearClient.from(ud),
                  let peerId, let name, let avatarB64 else { return }
            let av = P2PAvatar(
                from: String(cString: peerId),
                displayName: String(cString: name),
                avatarB64: String(cString: avatarB64)
            )
            DispatchQueue.main.async {
                // Skip the write when the base64 payload is unchanged —
                // avatars are re-pushed on every connect, so without
                // this guard every reconnect re-renders every view
                // reading peerAvatars.
                if client.peerAvatars[av.from]?.avatarB64 != av.avatarB64 {
                    client.peerAvatars[av.from] = av
                }
            }
        }, selfPtr)

        // ── File transfer: inbound progress + completion ──────────────
        // Sets status = .completed once the core hands us a savedPath
        // (receiver reassembled + hash-verified the file).
        p2p_set_on_file_progress(ctx, {
            from, tid, fileName, fileSize,
            chunksReceived, chunksTotal, savedPath, ts, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let tid, let fileName else { return }
            let idStr   = String(cString: tid)
            let fromStr = String(cString: from)
            let nameStr = String(cString: fileName)
            let saved   = savedPath.flatMap { String(cString: $0) }
            let when    = Date(timeIntervalSince1970: TimeInterval(ts))
            DispatchQueue.main.async {
                client.upsertTransfer(
                    id: idStr, peerId: fromStr, fileName: nameStr,
                    fileSize: fileSize,
                    direction: .inbound,
                    chunksDone: Int(chunksReceived),
                    chunksTotal: Int(chunksTotal),
                    savedPath: saved,
                    // Inbound reaches .completed only once the file has
                    // been written to disk AND hash-verified — core
                    // signals that by populating savedPath.
                    status: (saved != nil && !saved!.isEmpty) ? .completed : .inFlight,
                    timestamp: when)
            }
        }, selfPtr)

        // ── File transfer: outbound (sender-side) progress ────────────
        // Fires after every outbound chunk dispatches.  savedPath stays
        // nil here — the sender already has the source file at the path
        // they passed to p2p_send_file.  The .delivered status arrives
        // later via on_file_delivered once the receiver acks.
        p2p_set_on_file_sent_progress(ctx, {
            to, tid, fileName, fileSize,
            chunksSent, chunksTotal, ts, ud in
            guard let client = Peer2PearClient.from(ud),
                  let to, let tid, let fileName else { return }
            let idStr   = String(cString: tid)
            let toStr   = String(cString: to)
            let nameStr = String(cString: fileName)
            let when    = Date(timeIntervalSince1970: TimeInterval(ts))
            DispatchQueue.main.async {
                client.upsertTransfer(
                    id: idStr, peerId: toStr, fileName: nameStr,
                    fileSize: fileSize,
                    direction: .outbound,
                    chunksDone: Int(chunksSent),
                    chunksTotal: Int(chunksTotal),
                    savedPath: nil,
                    status: .inFlight,
                    timestamp: when)
            }
        }, selfPtr)

        // ── File transfer: user-consent prompt ─────────────────────────
        p2p_set_on_file_request(ctx, { from, tid, fileName, fileSize, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let tid, let fileName else { return }
            let req = P2PFileRequest(
                id: String(cString: tid),
                from: String(cString: from),
                fileName: String(cString: fileName),
                fileSize: fileSize
            )
            DispatchQueue.main.async {
                // Silently decline files from blocked peers — the core
                // still expects a response, so we explicitly reject
                // rather than let the sender sit in "awaiting consent".
                if client.isBlocked(peerId: req.from) {
                    client.respondToFileRequest(transferId: req.id, accept: false)
                    return
                }
                // Verified-contacts gate: when on, files from peers
                // whose safety number hasn't been confirmed are
                // declined without prompting.  iOS-side policy — the
                // core has already accepted the envelope; we just
                // refuse before the user is bothered.
                if client.fileRequireVerifiedContact
                   && client.peerTrust(for: req.from) != .verified {
                    client.respondToFileRequest(transferId: req.id, accept: false)
                    return
                }
                // Avoid duplicates if the relay re-delivers the envelope.
                if !client.pendingFileRequests.contains(where: { $0.id == req.id }) {
                    client.pendingFileRequests.append(req)
                }
            }
        }, selfPtr)

        // ── File transfer: cancellation ────────────────────────────────
        // Flip status → .canceled and drop the pending-request entry if
        // we never accepted.  We KEEP the transfer in the `transfers`
        // dict (with terminal status) so the UI can show "Canceled" on
        // the card instead of silently removing it.
        p2p_set_on_file_canceled(ctx, { tid, byReceiver, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            let byRcv = byReceiver != 0
            DispatchQueue.main.async {
                client.pendingFileRequests.removeAll { $0.id == id }
                client.markTransferStatus(id: id, status: .canceled(byReceiver: byRcv))
            }
        }, selfPtr)

        // ── File transfer: sender-side delivery confirmation ───────────
        p2p_set_on_file_delivered(ctx, { tid, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            DispatchQueue.main.async {
                client.markTransferStatus(id: id, status: .delivered)
            }
        }, selfPtr)

        // ── File transfer: blocked by transport policy ─────────────────
        p2p_set_on_file_blocked(ctx, { tid, byReceiver, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            let byRcv = byReceiver != 0
            DispatchQueue.main.async {
                client.markTransferStatus(id: id, status: .blocked(byReceiver: byRcv))
            }
        }, selfPtr)

        // ── Per-bubble send failure (post retry-exhaustion) ────────────
        // Fires once the relay-client's retry loop runs out
        // (~30–60s after the first attempt).  We mark the matching
        // P2PMessage so MessageBubble renders the red icon + the
        // bubble's tap action offers retry / delete.  Also persist
        // the flag so the indicator survives a relaunch — the
        // C++-side stamps the row's send_failed column to 1, mirror
        // it into our @Published set for the live view.
        p2p_set_on_send_failed(ctx, { msgId, ud in
            guard let client = Peer2PearClient.from(ud), let msgId else { return }
            let id = String(cString: msgId)
            DispatchQueue.main.async {
                client.failedMessageIds.insert(id)
                // Persistence: find the conversation that holds this
                // message and stamp the column.  Outbound messages
                // carry `to` (DM) or live in groupMessages by groupId.
                // Search both — whichever matches is the one to
                // persist against.  Cheap enough: searches walk the
                // in-memory mirrors, not the DB.
                if let dm = client.messages.first(where: { $0.id == id }),
                   let to = dm.to,
                   let convId = client.directConversationIdByPeer[to] {
                    client.dbSetMessageSendFailed(
                        conversationId: convId,
                        msgId:          id,
                        failed:         true)
                } else if let gm = client.groupMessages.first(where: { $0.id == id }) {
                    // Group conversation_id is the groupId itself
                    // (groups skip the directConversationIdByPeer
                    // indirection — the conv id IS the group id by
                    // convention).
                    client.dbSetMessageSendFailed(
                        conversationId: gm.groupId,
                        msgId:          id,
                        failed:         true)
                }
            }
        }, selfPtr)

        // ── Safety numbers: peer's stored fingerprint no longer matches ─
        p2p_set_on_peer_key_changed(ctx, {
            peerId, oldFp, oldLen, newFp, newLen, ud in
            guard let client = Peer2PearClient.from(ud), let peerId else { return }
            let pid = String(cString: peerId)
            let oldData = (oldFp != nil && oldLen > 0)
                ? Data(bytes: oldFp!, count: Int(oldLen)) : Data()
            let newData = (newFp != nil && newLen > 0)
                ? Data(bytes: newFp!, count: Int(newLen)) : Data()
            let change = P2PKeyChange(
                id: pid, oldFingerprint: oldData, newFingerprint: newData)
            DispatchQueue.main.async { client.keyChanges[pid] = change }
        }, selfPtr)
    }

    // MARK: - Shared helpers used by the callback bridge

    /// Turn the opaque user-data pointer that every C callback receives
    /// back into the `Peer2PearClient` that owns it.  Used by every
    /// `p2p_set_on_*` handler and by the platform adapter wiring in
    /// `start()` — same semantics either way.  `takeUnretainedValue` is
    /// safe because the core never outlives the client (p2p_destroy
    /// clears the callbacks before the pointer goes away).
    internal static func from(_ ptr: UnsafeMutableRawPointer?) -> Peer2PearClient? {
        guard let ptr else { return nil }
        return Unmanaged<Peer2PearClient>.fromOpaque(ptr).takeUnretainedValue()
    }

    /// Read a NULL-terminated C string array into a Swift `[String]`.
    /// Used by every callback that receives a member list from the C API.
    internal static func stringsFromCArray(
        _ ptr: UnsafePointer<UnsafePointer<CChar>?>?
    ) -> [String] {
        guard let ptr else { return [] }
        var out: [String] = []
        var i = 0
        while let p = ptr[i] {
            out.append(String(cString: p))
            i += 1
        }
        return out
    }
}
