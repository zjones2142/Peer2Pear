import Foundation
import Combine

// MARK: - Event data models

/// Message received from a peer.
struct P2PMessage: Identifiable {
    let id: String       // msgId
    let from: String     // peer ID (base64url)
    let text: String
    let timestamp: Date
}

/// Group message — carries groupId + member list alongside the text.
struct P2PGroupMessage: Identifiable {
    let id: String       // msgId
    let from: String
    let groupId: String
    let groupName: String
    let members: [String]
    let text: String
    let timestamp: Date
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

/// Progress event from an in-flight transfer.  `savedPath` is non-nil
/// only when `chunksReceived == chunksTotal` (transfer complete).
struct P2PFileProgress: Identifiable {
    let id: String       // transferId
    let from: String
    let fileName: String
    let fileSize: Int64
    let chunksReceived: Int
    let chunksTotal: Int
    let savedPath: String?
    let timestamp: Date
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

    /// peerId → online.  Updated by `on_presence` pushes.
    @Published var peerPresence: [String: Bool] = [:]

    /// peerId → most-recent avatar payload.
    @Published var peerAvatars: [String: P2PAvatar] = [:]

    /// Transfers waiting on user consent (see `respondToFileRequest`).
    @Published var pendingFileRequests: [P2PFileRequest] = []

    /// Transfer progress / completion events, keyed by transferId.
    @Published var fileProgress: [String: P2PFileProgress] = [:]

    /// Transfers the sender confirmed landed intact.
    @Published var deliveredTransferIds: Set<String> = []

    /// Transfers that got canceled — maps transferId → `byReceiver` flag.
    @Published var canceledTransfers: [String: Bool] = [:]

    /// Transport policy blocked these transfers (P2P required, P2P failed).
    @Published var blockedTransfers: [String: Bool] = [:]

    /// Safety-number mismatches surfaced since this session started.
    /// Views use this to render a warning banner; clear entries after
    /// the user re-verifies via `markPeerVerified`.
    @Published var keyChanges: [String: P2PKeyChange] = [:]

    // MARK: - Internal

    /// Raw C context pointer — accessed by platform adapters
    private(set) var rawContext: OpaquePointer?

    private var ws: WebSocketAdapter!
    private var http: HttpAdapter!

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

        // Initialize identity (v5 unified Argon2id path — H4 fix).
        let rc = p2p_set_passphrase_v2(rawContext, passphrase)
        if rc != 0 {
            statusMessage = "Identity unlock failed (wrong passphrase?)"
            p2p_destroy(rawContext)
            rawContext = nil
            return
        }
        myPeerId = String(cString: p2p_my_id(rawContext))
        p2p_set_relay_url(rawContext, relayUrl)
        p2p_connect(rawContext)
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

    /// Send a text message to every member of a group.  `memberPeerIds`
    /// must include the recipients (self is filtered out internally).
    func sendGroupText(groupId: String,
                       groupName: String,
                       memberPeerIds: [String],
                       text: String) {
        guard let ctx = rawContext else { return }
        // Build a NULL-terminated C array of member IDs.
        let cStrings = memberPeerIds.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        var cArray: [UnsafePointer<CChar>?] =
            cStrings.map { $0.map { UnsafePointer($0) } }
        cArray.append(nil)
        cArray.withUnsafeMutableBufferPointer { buf in
            _ = p2p_send_group_text(ctx, groupId, groupName, buf.baseAddress, text)
        }
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
        let cStrings = peerIds.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        var cArray: [UnsafePointer<CChar>?] =
            cStrings.map { $0.map { UnsafePointer($0) } }
        cArray.withUnsafeMutableBufferPointer { buf in
            p2p_check_presence(ctx, buf.baseAddress, Int32(peerIds.count))
        }
    }
    func subscribePresence(for peerIds: [String]) {
        guard let ctx = rawContext else { return }
        let cStrings = peerIds.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        var cArray: [UnsafePointer<CChar>?] =
            cStrings.map { $0.map { UnsafePointer($0) } }
        cArray.withUnsafeMutableBufferPointer { buf in
            p2p_subscribe_presence(ctx, buf.baseAddress, Int32(peerIds.count))
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
            // memberIds is a NULL-terminated array of C strings.
            var members: [String] = []
            if let memberIds {
                var i = 0
                while let p = memberIds[i] {
                    members.append(String(cString: p))
                    i += 1
                }
            }
            let gm = P2PGroupMessage(
                id: String(cString: msgId),
                from: String(cString: from),
                groupId: String(cString: gid),
                groupName: String(cString: gname),
                members: members,
                text: String(cString: text),
                timestamp: Date(timeIntervalSince1970: TimeInterval(ts))
            )
            DispatchQueue.main.async { client.groupMessages.append(gm) }
        }, selfPtr)

        // ── Presence push ──────────────────────────────────────────────
        p2p_set_on_presence(ctx, { peerId, online, ud in
            guard let client = Peer2PearClient.from(ud), let peerId else { return }
            let pid = String(cString: peerId)
            let isUp = online != 0
            DispatchQueue.main.async { client.peerPresence[pid] = isUp }
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
            DispatchQueue.main.async { client.peerAvatars[av.from] = av }
        }, selfPtr)

        // ── File transfer: progress + completion ───────────────────────
        p2p_set_on_file_progress(ctx, {
            from, tid, fileName, fileSize,
            chunksReceived, chunksTotal, savedPath, ts, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let tid, let fileName else { return }
            let progress = P2PFileProgress(
                id: String(cString: tid),
                from: String(cString: from),
                fileName: String(cString: fileName),
                fileSize: fileSize,
                chunksReceived: Int(chunksReceived),
                chunksTotal: Int(chunksTotal),
                savedPath: savedPath.flatMap { String(cString: $0) },
                timestamp: Date(timeIntervalSince1970: TimeInterval(ts))
            )
            DispatchQueue.main.async { client.fileProgress[progress.id] = progress }
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
        p2p_set_on_file_canceled(ctx, { tid, byReceiver, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            DispatchQueue.main.async {
                client.canceledTransfers[id] = (byReceiver != 0)
                client.pendingFileRequests.removeAll { $0.id == id }
                client.fileProgress.removeValue(forKey: id)
            }
        }, selfPtr)

        // ── File transfer: sender-side delivery confirmation ───────────
        p2p_set_on_file_delivered(ctx, { tid, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            DispatchQueue.main.async { client.deliveredTransferIds.insert(id) }
        }, selfPtr)

        // ── File transfer: blocked by transport policy ─────────────────
        p2p_set_on_file_blocked(ctx, { tid, byReceiver, ud in
            guard let client = Peer2PearClient.from(ud), let tid else { return }
            let id = String(cString: tid)
            DispatchQueue.main.async {
                client.blockedTransfers[id] = (byReceiver != 0)
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
