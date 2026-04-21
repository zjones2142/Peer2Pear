import Foundation
import Combine

// MARK: - Persistent UI-state snapshot
// Groups, group avatars, and message history live here across app
// launches.  The core's own SQLCipher DB covers identity + ratchet
// sessions separately; this snapshot is just the iOS-side @Published
// surface so the user doesn't see an empty chat list on every restart.
//
// Storage: JSON file at <docs>/peer2pear-ui-state.json.  Written with
// .completeFileProtection so iOS encrypts it at rest while the device
// is locked (matches the at-rest posture of identity.json + the
// SQLCipher DB).
//
// Not persisted (intentional): peerPresence (transient), keyChanges
// (session-scoped warnings), pendingFileRequests (re-arrive on
// reconnect), transfers (FileTransferManager owns ground truth and
// re-emits progress on resume), statusMessage / isConnected /
// myPeerId (derived).
final class Peer2PearStore {
    private let url: URL

    struct Snapshot: Codable {
        var groups:        [String: P2PGroup]
        var groupAvatars:  [String: String]
        var groupMessages: [P2PGroupMessage]
        var messages:      [P2PMessage]
    }

    init(documentDir: String) {
        url = URL(fileURLWithPath: documentDir)
            .appendingPathComponent("peer2pear-ui-state.json")
    }

    func load() -> Snapshot? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(Snapshot.self, from: data)
    }

    func save(_ snap: Snapshot) {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        guard let data = try? enc.encode(snap) else { return }
        // Atomic write so a crash mid-save doesn't truncate the file.
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }
}

// MARK: - Event data models

/// Message received from a peer.
struct P2PMessage: Identifiable, Codable {
    let id: String       // msgId
    let from: String     // peer ID (base64url)
    let text: String
    let timestamp: Date
}

/// Group message — carries groupId + member list alongside the text.
struct P2PGroupMessage: Identifiable, Codable {
    let id: String       // msgId
    let from: String
    let groupId: String
    let groupName: String
    let members: [String]
    let text: String
    let timestamp: Date
}

/// Client-side group state.  The core doesn't track groups itself (the
/// relay is memberless) — each client maintains its own group roster
/// derived from inbound messages + locally-created groups.  `memberIds`
/// includes the peers you send to; your own peerId is NOT in the list
/// (self-filtering is handled in the core when fanning out).
struct P2PGroup: Identifiable, Codable {
    let id: String         // groupId — a UUID chosen by the creator
    var name: String
    var memberIds: [String]
    var lastActivity: Date
}

/// Avatar received from a peer.
struct P2PAvatar {
    let from: String
    let displayName: String
    let avatarB64: String
}

/// Incoming file transfer awaiting user consent (Phase 2).
/// App UI surfaces a prompt and calls `respondToFileRequest`.
struct P2PFileRequest: Identifiable {
    let id: String       // transferId
    let from: String
    let fileName: String
    let fileSize: Int64
}

/// Direction of a file transfer — inbound means WE'RE receiving, outbound
/// means WE'RE sending.  Lets a single `transfers` dict carry both
/// halves and lets views filter by counterparty without care for which
/// direction the bytes are flowing.
enum P2PTransferDirection {
    case inbound
    case outbound
}

/// Lifecycle state of a transfer.  Replaces the pre-unification trio of
/// `deliveredTransferIds` / `canceledTransfers` / `blockedTransfers`
/// that each views had to cross-reference to figure out status.
enum P2PTransferStatus: Equatable {
    /// Chunks are still being dispatched / received.
    case inFlight
    /// Inbound: receiver reassembled the file and wrote savedPath.
    case completed
    /// Outbound: receiver sent the file_ack confirming delivery.
    case delivered
    /// Transfer was canceled.  `byReceiver == true` means the recipient
    /// canceled; false means we (sender or otherwise) canceled.
    case canceled(byReceiver: Bool)
    /// Transfer was blocked by transport policy (P2P required, P2P
    /// unavailable).  `byReceiver == true` when the receiver's policy
    /// is what blocked it.
    case blocked(byReceiver: Bool)
}

/// Single source of truth for per-transfer state.  Mutates in place as
/// chunk-progress / ack / cancel / block events arrive.  `savedPath`
/// is non-nil only for .inbound transfers that reached .completed
/// (sender never has a savedPath — the file already lives at its
/// original path on their disk).
struct P2PTransferRecord: Identifiable {
    let id: String             // transferId
    let peerId: String         // the OTHER party (sender if inbound, recipient if outbound)
    let fileName: String
    let fileSize: Int64
    let direction: P2PTransferDirection
    var chunksDone: Int
    var chunksTotal: Int
    var savedPath: String?
    var status: P2PTransferStatus
    var timestamp: Date

    /// True for .completed / .delivered / .canceled / .blocked —
    /// i.e. the transfer is no longer in-flight and won't change further.
    var isTerminal: Bool {
        switch status {
        case .inFlight: return false
        default:        return true
        }
    }
}

/// Trust state for a peer — mirrors `P2P_PEER_*` in peer2pear.h.
enum P2PPeerTrust: Int {
    case unverified = 0
    case verified   = 1
    case mismatch   = 2
}

/// A safety-number mismatch event — fires once per session per peer.
struct P2PKeyChange: Identifiable {
    let id: String                  // peerId (doubles as identifier)
    let oldFingerprint: Data
    let newFingerprint: Data
}

/// High-level Swift wrapper around the peer2pear C API.
/// Owns the p2p_context and bridges C callbacks → Combine publishers.
final class Peer2PearClient: ObservableObject {
    // MARK: - Published state (drives SwiftUI)

    @Published var isConnected = false
    @Published var myPeerId: String = ""
    @Published var statusMessage: String = ""

    /// Last-write-wins 1:1 message log.  Views may further partition by peer.
    @Published var messages: [P2PMessage] = []

    /// Group message log.  Views partition by `groupId`.
    @Published var groupMessages: [P2PGroupMessage] = []

    /// Known groups keyed by groupId.  Populated from two sources:
    /// (1) `createGroup` when the local user creates one, and
    /// (2) `on_group_message` upserts when a peer adds us to a group
    /// or sends a message whose member roster we didn't know.
    @Published var groups: [String: P2PGroup] = [:]

    /// groupId → base64 avatar payload.  Set by on_group_avatar or
    /// locally after a successful sendGroupAvatar.
    @Published var groupAvatars: [String: String] = [:]

    /// peerId → online.  Updated by `on_presence` pushes.
    @Published var peerPresence: [String: Bool] = [:]

    /// peerId → most-recent avatar payload.
    @Published var peerAvatars: [String: P2PAvatar] = [:]

    /// Transfers waiting on user consent (see `respondToFileRequest`).
    @Published var pendingFileRequests: [P2PFileRequest] = []

    /// All known file transfers (in-flight and terminal), keyed by
    /// transferId.  Unified from what was previously four parallel
    /// dicts (progress / delivered / canceled / blocked) — see
    /// `P2PTransferRecord` + `P2PTransferStatus`.
    @Published var transfers: [String: P2PTransferRecord] = [:]

    /// Safety-number mismatches surfaced since this session started.
    /// Views use this to render a warning banner; clear entries after
    /// the user re-verifies via `markPeerVerified`.
    @Published var keyChanges: [String: P2PKeyChange] = [:]

    // MARK: - Internal

    /// Raw C context pointer — accessed by platform adapters
    private(set) var rawContext: OpaquePointer?

    private var ws: WebSocketAdapter!
    private var http: HttpAdapter!

    // Persistent UI-state — bound after `start()` once we know the
    // data dir.  See Peer2PearStore for what gets persisted vs. not.
    private var store: Peer2PearStore?
    private var saveCancellable: AnyCancellable?

    // MARK: - Lifecycle

    init() {
        ws = WebSocketAdapter(client: self)
        http = HttpAdapter(client: self)
    }

    /// Initialize the protocol engine with a data directory and passphrase.
    func start(dataDir: String, passphrase: String, relayUrl: String) {
        guard rawContext == nil else { return }

        // Build the platform callbacks struct
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        var platform = p2p_platform()
        platform.platform_ctx = selfPtr

        // WebSocket callbacks
        platform.ws_open = { urlCStr, ctx in
            guard let client = Peer2PearClient.from(ctx), let urlCStr,
                  let url = URL(string: String(cString: urlCStr)) else { return }
            client.ws.open(url: url)
        }
        platform.ws_close = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return }
            client.ws.close()
        }
        platform.ws_send_text = { msgCStr, ctx in
            guard let client = Peer2PearClient.from(ctx), let msgCStr else { return }
            client.ws.sendText(String(cString: msgCStr))
        }
        platform.ws_is_connected = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return 0 }
            return client.ws.isConnected ? 1 : 0
        }
        platform.ws_is_idle = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return 1 }
            return client.ws.isIdle ? 1 : 0
        }

        // HTTP callback
        platform.http_post = { urlCStr, body, bodyLen, hKeys, hVals, hCount, ctx in
            guard let client = Peer2PearClient.from(ctx), let urlCStr,
                  let url = URL(string: String(cString: urlCStr)) else { return -1 }
            let data = body != nil ? Data(bytes: body!, count: Int(bodyLen)) : Data()
            var headers: [(String, String)] = []
            for i in 0..<Int(hCount) {
                if let k = hKeys?[i], let v = hVals?[i] {
                    headers.append((String(cString: k), String(cString: v)))
                }
            }
            return client.http.post(url: url, body: data, headers: headers)
        }

        // Create core context
        rawContext = p2p_create(dataDir, platform)
        guard rawContext != nil else {
            statusMessage = "Failed to create Peer2Pear context"
            return
        }

        // Set event callbacks
        setupCallbacks()

        // Initialize identity (unified Argon2id path).
        let rc = p2p_set_passphrase_v2(rawContext, passphrase)
        if rc != 0 {
            statusMessage = "Identity unlock failed (wrong passphrase?)"
            p2p_destroy(rawContext)
            rawContext = nil
            return
        }
        myPeerId = String(cString: p2p_my_id(rawContext))

        // Restore persisted UI state.  Do this BEFORE connectToRelay so
        // setKnownGroupMembers replays the H2 roster gate before any
        // inbound control messages arrive on the new socket.
        store = Peer2PearStore(documentDir: dataDir)
        if let snap = store?.load() {
            groups        = snap.groups
            groupAvatars  = snap.groupAvatars
            groupMessages = snap.groupMessages
            messages      = snap.messages
            // Replay every known group's roster to the core so inbound
            // group_rename / group_avatar / group_leave / group_member_update
            // from existing members are admitted.  Without this, all
            // control messages drop after restart until a fresh group_msg
            // bootstraps the roster.
            for group in snap.groups.values {
                setKnownGroupMembers(groupId: group.id,
                                      memberPeerIds: group.memberIds)
            }
        }

        // Auto-save on any persisted-state change, debounced so a burst
        // of message arrivals coalesces into one write.
        saveCancellable = objectWillChange
            .debounce(for: .milliseconds(500), scheduler: DispatchQueue.main)
            .sink { [weak self] _ in self?.persistSnapshot() }

        p2p_set_relay_url(rawContext, relayUrl)
        p2p_connect(rawContext)
    }

    private func persistSnapshot() {
        guard let store else { return }
        store.save(.init(
            groups:        groups,
            groupAvatars:  groupAvatars,
            groupMessages: groupMessages,
            messages:      messages))
    }

    func stop() {
        if let ctx = rawContext {
            p2p_destroy(ctx)
            rawContext = nil
        }
        isConnected = false
    }

    deinit { stop() }

    // MARK: - Messaging actions

    func sendText(to peerId: String, text: String) {
        guard let ctx = rawContext else { return }
        p2p_send_text(ctx, peerId, text)
    }

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
            self?.groups[gid] = group
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
    func sendGroupText(groupId: String,
                       groupName: String,
                       memberPeerIds: [String],
                       text: String) {
        guard let ctx = rawContext else { return }
        withCStringArray(memberPeerIds) { ptr in
            _ = p2p_send_group_text(ctx, groupId, groupName, ptr, text)
        }
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
                if var g = self?.groups[groupId] {
                    g.name = newName
                    g.lastActivity = Date()
                    self?.groups[groupId] = g
                }
            }
        }
        return rc == 0
    }

    /// Leave a group — broadcasts a `group_leave` notification and drops
    /// the group from our local state.  Peers will remove us from their
    /// rosters via their on_group_member_left callback.
    @discardableResult
    func leaveGroup(groupId: String, groupName: String,
                    memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_leave_group(ctx, groupId, groupName, ptr)
        }
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                self?.groups.removeValue(forKey: groupId)
                self?.groupMessages.removeAll { $0.groupId == groupId }
                self?.groupAvatars.removeValue(forKey: groupId)
            }
        }
        return rc == 0
    }

    /// Publish a new group avatar.
    @discardableResult
    func sendGroupAvatar(groupId: String, avatarB64: String,
                         memberPeerIds: [String]) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = withCStringArray(memberPeerIds) { ptr -> Int32 in
            p2p_send_group_avatar(ctx, groupId, avatarB64, ptr)
        }
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                self?.groupAvatars[groupId] = avatarB64
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
                if var g = self?.groups[groupId] {
                    g.memberIds = memberPeerIds
                    g.lastActivity = Date()
                    self?.groups[groupId] = g
                }
            }
        }
        return rc == 0
    }

    // Helper: marshal [String] into the `const char**` (NULL-terminated)
    // shape the C API expects.  All five group-mutation wrappers above
    // share the same prologue — consolidate here to keep them readable.
    private func withCStringArray<R>(_ strings: [String],
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

    /// Read a NULL-terminated C string array into a Swift `[String]`.
    /// Used by every callback that receives a member list from the C API.
    fileprivate static func stringsFromCArray(
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

    // MARK: - Transfer state mutators (called from callbacks on the main queue)

    /// Upsert an in-progress transfer record.  Preserves existing
    /// terminal status (.completed / .delivered / .canceled / .blocked)
    /// — a late-arriving chunk event shouldn't flip a completed
    /// transfer back to .inFlight.
    fileprivate func upsertTransfer(id: String, peerId: String,
                                     fileName: String, fileSize: Int64,
                                     direction: P2PTransferDirection,
                                     chunksDone: Int, chunksTotal: Int,
                                     savedPath: String?,
                                     status: P2PTransferStatus,
                                     timestamp: Date) {
        if var existing = transfers[id] {
            existing.chunksDone  = max(existing.chunksDone, chunksDone)
            existing.chunksTotal = chunksTotal > 0 ? chunksTotal : existing.chunksTotal
            if let savedPath { existing.savedPath = savedPath }
            if !existing.isTerminal {
                existing.status = status
            }
            existing.timestamp = max(existing.timestamp, timestamp)
            transfers[id] = existing
        } else {
            transfers[id] = P2PTransferRecord(
                id: id, peerId: peerId, fileName: fileName, fileSize: fileSize,
                direction: direction,
                chunksDone: chunksDone, chunksTotal: chunksTotal,
                savedPath: savedPath, status: status, timestamp: timestamp)
        }
    }

    /// Flip the status on an existing record (delivered / canceled /
    /// blocked events).  No-op if the transferId is unknown — not
    /// every cancel / block necessarily has a prior progress event on
    /// record (e.g. the transfer was blocked before the first chunk).
    fileprivate func markTransferStatus(id: String, status: P2PTransferStatus) {
        guard var existing = transfers[id] else { return }
        existing.status = status
        existing.timestamp = Date()
        transfers[id] = existing
    }

    // MARK: - File transfer actions

    /// Start a file send.  Returns the transferId on success, nil otherwise.
    /// The receiver will get an `on_file_request` callback and must accept
    /// via `respondToFileRequest` before chunks flow.
    @discardableResult
    func sendFile(to peerId: String, fileName: String, filePath: String) -> String? {
        guard let ctx = rawContext else { return nil }
        guard let c = p2p_send_file(ctx, peerId, fileName, filePath) else { return nil }
        return String(cString: c)
    }

    /// Reply to an on_file_request prompt.  Accept=true installs the key
    /// and tells the sender to start streaming chunks; accept=false
    /// declines (zeroes the stashed key, no further state).
    func respondToFileRequest(transferId: String,
                              accept: Bool,
                              requireP2P: Bool = false) {
        guard let ctx = rawContext else { return }
        p2p_respond_file_request(ctx, transferId, accept ? 1 : 0, requireP2P ? 1 : 0)
        // Remove from pending list regardless of the choice.
        DispatchQueue.main.async { [weak self] in
            self?.pendingFileRequests.removeAll { $0.id == transferId }
        }
    }

    /// Cancel an in-flight transfer (inbound or outbound).
    func cancelTransfer(transferId: String) {
        guard let ctx = rawContext else { return }
        p2p_cancel_transfer(ctx, transferId)
    }

    /// Global consent thresholds (match core defaults — 100 MB / 100 MB).
    func setFileAutoAcceptMB(_ mb: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_file_auto_accept_mb(ctx, Int32(mb))
    }
    func setFileHardMaxMB(_ mb: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_file_hard_max_mb(ctx, Int32(mb))
    }
    func setFileRequireP2P(_ on: Bool) {
        guard let ctx = rawContext else { return }
        p2p_set_file_require_p2p(ctx, on ? 1 : 0)
    }

    // MARK: - Presence

    func checkPresence(for peerIds: [String]) {
        guard let ctx = rawContext else { return }
        withCStringArray(peerIds) { ptr in
            p2p_check_presence(ctx, ptr, Int32(peerIds.count))
        }
    }
    func subscribePresence(for peerIds: [String]) {
        guard let ctx = rawContext else { return }
        withCStringArray(peerIds) { ptr in
            p2p_subscribe_presence(ctx, ptr, Int32(peerIds.count))
        }
    }

    // MARK: - Privacy + relay config

    func setPrivacyLevel(_ level: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_privacy_level(ctx, Int32(level))
    }

    // MARK: - Safety numbers (key verification)

    /// Returns the 60-digit safety-number display string, or empty on error.
    func safetyNumber(for peerId: String) -> String {
        guard let ctx = rawContext else { return "" }
        return String(cString: p2p_safety_number(ctx, peerId))
    }

    func peerTrust(for peerId: String) -> P2PPeerTrust {
        guard let ctx = rawContext else { return .unverified }
        return P2PPeerTrust(rawValue: Int(p2p_peer_trust(ctx, peerId))) ?? .unverified
    }

    /// Persist "user compared the safety numbers and confirmed".  Also
    /// clears any outstanding `keyChanges` entry for this peer.
    @discardableResult
    func markVerified(peerId: String) -> Bool {
        guard let ctx = rawContext else { return false }
        let rc = p2p_mark_peer_verified(ctx, peerId)
        if rc == 0 {
            DispatchQueue.main.async { [weak self] in
                self?.keyChanges.removeValue(forKey: peerId)
            }
        }
        return rc == 0
    }

    func unverify(peerId: String) {
        guard let ctx = rawContext else { return }
        p2p_unverify_peer(ctx, peerId)
        DispatchQueue.main.async { [weak self] in
            self?.keyChanges.removeValue(forKey: peerId)
        }
    }

    /// Toggle: when enabled, messages to/from Mismatch peers are refused.
    func setHardBlockOnKeyChange(_ on: Bool) {
        guard let ctx = rawContext else { return }
        p2p_set_hard_block_on_key_change(ctx, on ? 1 : 0)
    }

    // MARK: - Callback wiring

    private func setupCallbacks() {
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
            DispatchQueue.main.async { client.statusMessage = str }
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
            DispatchQueue.main.async { client.messages.append(msg) }
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
            }
        }, selfPtr)

        // ── Group renamed ──────────────────────────────────────────────
        p2p_set_on_group_renamed(ctx, { gid, newName, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let newName else { return }
            let gidStr = String(cString: gid)
            let nameStr = String(cString: newName)
            DispatchQueue.main.async {
                if var g = client.groups[gidStr] {
                    g.name = nameStr
                    g.lastActivity = Date()
                    client.groups[gidStr] = g
                }
            }
        }, selfPtr)

        // ── Group avatar updated ───────────────────────────────────────
        p2p_set_on_group_avatar(ctx, { gid, avatarB64, ud in
            guard let client = Peer2PearClient.from(ud),
                  let gid, let avatarB64 else { return }
            let gidStr = String(cString: gid)
            let avatarStr = String(cString: avatarB64)
            DispatchQueue.main.async {
                if client.groupAvatars[gidStr] != avatarStr {
                    client.groupAvatars[gidStr] = avatarStr
                }
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

        // ── File transfer: user-consent prompt (Phase 2) ───────────────
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

    // MARK: - Helpers

    private static func from(_ ptr: UnsafeMutableRawPointer?) -> Peer2PearClient? {
        guard let ptr else { return nil }
        return Unmanaged<Peer2PearClient>.fromOpaque(ptr).takeUnretainedValue()
    }
}
