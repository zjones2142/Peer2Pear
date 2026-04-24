import Foundation
import Combine
import Network
import UIKit
import UserNotifications

// MARK: - Event data models

/// Message received from a peer.
struct P2PMessage: Identifiable, Codable {
    let id: String       // msgId
    let from: String     // peer ID (base64url)
    let text: String
    let timestamp: Date
    // Set only for locally-originated (outgoing) messages so the UI
    // knows which conversation the echo belongs to.  Nil for inbound
    // — the sender is the conversation key in that case.  Optional so
    // older on-disk snapshots that predate this field load cleanly.
    var to: String?
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

/// Incoming file transfer awaiting user consent.
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
    // MARK: - Relay URL (shared by Onboarding + Settings)

    // UserDefaults survives app launches and passcode unlock but is
    // wiped on uninstall (iOS sandbox).  Cross-reinstall persistence
    // would need iCloud Keychain, which we deliberately avoid to keep
    // the relay URL from leaving the device.
    static let kDefaultsRelayUrlKey = "p2p.lastRelayUrl"
    static let kDefaultRelayUrl     = "https://peer2pear.com"

    /// Last-entered (or default) relay URL.  Reads UserDefaults each
    /// time so a Settings-screen change is visible without needing a
    /// notification to propagate.
    static var storedRelayUrl: String {
        UserDefaults.standard.string(forKey: kDefaultsRelayUrlKey)
            ?? kDefaultRelayUrl
    }

    // MARK: - Backup relays (send pool for multi-hop)

    // Stored as a JSON-encoded [String] in UserDefaults.  Multi-hop
    // forwarding in RelayClient gates on `m_sendRelays.size() >= 2`,
    // so a user on Privacy=Maximum with fewer than two backup relays
    // silently falls back to Enhanced-tier behavior.  The SettingsView
    // explainer reflects that honestly.
    static let kBackupRelayUrlsKey = "p2p.backupRelayUrls"

    @Published var backupRelayUrls: [String] = {
        guard let data = UserDefaults.standard
                .data(forKey: Peer2PearClient.kBackupRelayUrlsKey),
              let arr = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        return arr
    }() {
        didSet {
            if let data = try? JSONEncoder().encode(backupRelayUrls) {
                UserDefaults.standard.set(data, forKey: Self.kBackupRelayUrlsKey)
            }
        }
    }

    /// Validate + append a backup relay URL.  Returns false when the URL
    /// is empty, malformed, uses a non-TLS scheme, or duplicates one
    /// already in the list.  On success, also pushes the new relay to
    /// the live send pool so multi-hop can pick it up without waiting
    /// for a relaunch — the core deduplicates, so the next start() call
    /// replaying the persisted list is a no-op.
    @discardableResult
    func addBackupRelay(_ url: String) -> Bool {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let lowered = trimmed.lowercased()
        guard lowered.hasPrefix("https://") || lowered.hasPrefix("wss://")
        else { return false }
        guard URL(string: trimmed) != nil else { return false }
        guard !backupRelayUrls.contains(trimmed) else { return false }
        backupRelayUrls.append(trimmed)
        addSendRelay(url: trimmed)
        return true
    }

    /// Remove a backup relay from the persisted list.  The live send
    /// pool is not mutated — the core has no remove-send-relay entry
    /// point, so the deletion takes effect on the next start().
    func removeBackupRelay(_ url: String) {
        backupRelayUrls.removeAll { $0 == url }
    }

    /// True when a passphrase-unlockable identity already lives on disk.
    /// Drives the Onboarding "Unlock" vs. "Create" branching — mirrors
    /// what `p2p_set_passphrase_v2` in the core checks (the salt file is
    /// created on first run and persists for the life of the install).
    /// 43-char base64url peer-ID validator — delegates to the shared C API
    /// (`p2p_is_valid_peer_id`) so iOS, desktop, and any future clients all
    /// accept/reject the same strings.  Nil or empty returns false.
    static func isValidPeerId(_ key: String?) -> Bool {
        guard let k = key else { return false }
        return p2p_is_valid_peer_id(k) == 1
    }

    static func identityExists(documentDir: String) -> Bool {
        let salt = URL(fileURLWithPath: documentDir)
            .appendingPathComponent("keys/db_salt.bin")
        return FileManager.default.fileExists(atPath: salt.path)
    }

    static var documentsPath: String {
        FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0].path
    }

    // MARK: - Appearance preference

    /// Three-way color scheme preference.  `.system` follows the OS
    /// dark/light toggle; `.dark` / `.light` pin regardless.  Default
    /// is `.dark` because the desktop app is dark-only and we want
    /// per-user identity posture to feel consistent across platforms.
    enum ColorSchemePreference: String, CaseIterable, Identifiable {
        case dark   = "dark"
        case light  = "light"
        case system = "system"
        var id: String { rawValue }
    }

    private static let kColorSchemeKey = "p2p.colorScheme"

    @Published var colorScheme: ColorSchemePreference = {
        let raw = UserDefaults.standard.string(forKey: kColorSchemeKey)
               ?? ColorSchemePreference.dark.rawValue
        return ColorSchemePreference(rawValue: raw) ?? .dark
    }() {
        didSet {
            UserDefaults.standard.set(colorScheme.rawValue,
                                       forKey: Self.kColorSchemeKey)
        }
    }

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

    /// Peers the user added via "New Chat" before any messages flowed.
    /// ChatListView unions this with the message-derived peer set so a
    /// freshly-added contact shows up immediately.  Persisted as
    /// in_address_book=1 contact rows in the AppDataStore so restarts
    /// don't lose contacts that haven't yet exchanged a message.
    @Published var knownPeerContacts: Set<String> = []

    /// Register a peer as a known contact.  Safe to call on an already-
    /// known peer (idempotent), and skips self (the core filters self
    /// out everywhere else, keep the invariant here too).  Upserts the
    /// matching contacts row with in_address_book=1 so a future restart
    /// reloads the peer as an explicit contact.
    func addContact(peerId: String) {
        let trimmed = peerId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != myPeerId else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts.insert(trimmed)
            self.dbSaveContact(DBContact(
                peerId:        trimmed,
                name:          self.contactNicknames[trimmed] ?? "",
                keys:          [trimmed],
                isBlocked:     self.blockedPeerIds.contains(trimmed),
                inAddressBook: true))
        }
    }

    /// Remove a peer from the address book and clear their nickname.
    /// Leaves message history intact — the key pair still identifies
    /// the peer, so if they message again the chat row stays attached
    /// to the same cryptographic identity.  Use `deleteChat(peerId:)`
    /// to wipe the transcript separately.  In the DB the row stays
    /// (so messages.peer_id FK is satisfied) but in_address_book flips
    /// to 0 and name resets to empty.
    func removeContact(peerId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts.remove(peerId)
            self.contactNicknames.removeValue(forKey: peerId)
            self.dbSaveContact(DBContact(
                peerId:        peerId,
                name:          "",
                keys:          [peerId],
                isBlocked:     self.blockedPeerIds.contains(peerId),
                inAddressBook: false))
        }
    }

    /// Wipe 1:1 message history with a peer without touching the
    /// contacts roster.  Used by the ChatListView trailing swipe so
    /// the user can dismiss a chat row (e.g. from a stranger who
    /// messaged first) without also deleting the contact.  Also wipes
    /// the file_transfers rows for this chat so the strip cards
    /// disappear — the actual files at savedPath stay on disk.
    func deleteChat(peerId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.messages.removeAll { $0.from == peerId || $0.to == peerId }
            // In-memory transfer cards for this peer also go away.
            // (We don't touch the on-disk files at savedPath — only
            // the bookkeeping row + UI card.)
            let toRemove = self.transfers.filter { $0.value.peerId == peerId }.keys
            for tid in toRemove {
                self.transfers.removeValue(forKey: tid)
            }
            self.dbDeleteMessages(peerId: peerId)
            self.dbDeleteFileRecordsForChat(chatKey: peerId)
        }
    }

    /// Peers the user has blocked.  Inbound 1:1 messages and file
    /// requests from these peers are dropped on arrival; outbound
    /// sends are refused by `sendText` / `sendFile`.  Purely a
    /// client-side filter (the relay still delivers the envelope —
    /// we just never surface it).  Mirrors the desktop's
    /// `ChatData.isBlocked` bit.
    @Published var blockedPeerIds: Set<String> = []

    /// Toggle block state for a peer.  `blocked == true` adds to the
    /// set; `blocked == false` removes.  Persisted via the snapshot
    /// so blocks survive relaunch.
    func setBlocked(peerId: String, blocked: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if blocked { self.blockedPeerIds.insert(peerId) }
            else       { self.blockedPeerIds.remove(peerId) }
            self.dbSaveContact(DBContact(
                peerId:        peerId,
                name:          self.contactNicknames[peerId] ?? "",
                keys:          [peerId],
                isBlocked:     blocked,
                inAddressBook: self.knownPeerContacts.contains(peerId)))
        }
    }

    func isBlocked(peerId: String) -> Bool {
        blockedPeerIds.contains(peerId)
    }

    /// Tear down the Double Ratchet session with this peer so the next
    /// outbound message performs a fresh X3DH-style handshake.  Useful
    /// after a device swap or when the peer reports decryption errors.
    /// Does not touch trust state, message history, or safety numbers.
    func resetSession(peerId: String) {
        guard let ctx = rawContext else { return }
        p2p_reset_session(ctx, peerId)
    }

    /// User-chosen friendly names for contacts, keyed by peer ID.
    /// Editable in ContactDetailView + via the swipe-rename in
    /// ContactsListView.  Falls back through `displayName(for:)` to
    /// the peer's published `peerAvatars` name and then to the key
    /// prefix when no nickname is set.
    @Published var contactNicknames: [String: String] = [:]

    /// Set or clear the user's nickname for a peer.  Empty / whitespace
    /// strings clear the entry so future renders fall back to the
    /// peer-published display name (or, if none, the key prefix).
    func setNickname(peerId: String, nickname: String) {
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if trimmed.isEmpty {
                self.contactNicknames.removeValue(forKey: peerId)
            } else {
                self.contactNicknames[peerId] = trimmed
                // Setting a nickname is a strong "this person is now
                // in my address book" signal — promote stranger-stub
                // rows so the peer also surfaces in ContactsListView,
                // not just the chat thread they came from.
                self.knownPeerContacts.insert(peerId)
            }
            self.dbSaveContact(DBContact(
                peerId:        peerId,
                name:          trimmed,
                keys:          [peerId],
                isBlocked:     self.blockedPeerIds.contains(peerId),
                inAddressBook: !trimmed.isEmpty
                                || self.knownPeerContacts.contains(peerId)))
        }
    }

    // MARK: - Contacts export / import
    //
    // Serializer lives in the shared C core (`p2p_export_contacts_json` /
    // `p2p_import_contacts_json`) so desktop + iOS cannot drift on the
    // v1 wire format: `{ "version": 1, "contacts": [{name, keys[]}] }`.

    func exportContactsJSON() -> Data {
        guard let ctx = rawContext else { return Data() }
        var outPtr: UnsafeMutablePointer<CChar>? = nil
        guard p2p_export_contacts_json(ctx, &outPtr) == 0, let c = outPtr else {
            return Data()
        }
        defer { free(c) }
        return Data(String(cString: c).utf8)
    }

    /// Merge contacts from an exported JSON blob into our local state.
    /// Core handles the AppDataStore write + duplicate skip; we refresh
    /// the @Published contacts set so SwiftUI views pick up the changes.
    @discardableResult
    func importContacts(from data: Data) -> Int {
        guard let ctx = rawContext else { return 0 }
        let count: Int = data.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            // Force NUL-termination — nlohmann::json::parse accepts any
            // length-delimited input, but the C API takes `const char*`.
            var buf = Array(UnsafeBufferPointer(start: base.assumingMemoryBound(to: CChar.self),
                                                count: data.count))
            buf.append(0)
            return Int(p2p_import_contacts_json(ctx, buf))
        }
        if count > 0 {
            // Refresh the in-memory address book from disk so the newly
            // inserted rows surface in ContactsListView immediately.
            loadStateFromDb()
        }
        return max(count, 0)
    }

    /// Best-available display name for a peer ID.  Priority:
    ///   1. user-chosen nickname (contactNicknames),
    ///   2. peer-published display name (peerAvatars),
    ///   3. truncated key prefix `"abcdefgh…"`.
    /// Single source of truth used by every chat row, conversation
    /// header, and contact detail view so a rename in one place
    /// propagates everywhere.
    func displayName(for peerId: String) -> String {
        if let nick = contactNicknames[peerId],
           !nick.isEmpty { return nick }
        if let pub = peerAvatars[peerId]?.displayName,
           !pub.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return pub
        }
        return String(peerId.prefix(8)) + "…"
    }

    /// Active 1:1 conversations — peers with at least one message in
    /// either direction.  Address-book entries with no message history
    /// do NOT appear here (they live only in ContactsListView until the
    /// user actually starts a chat from the "Send Message" link in
    /// ContactDetailView).  Decoupling chats from contacts is what lets
    /// `deleteChat` remove a row without also removing the contact —
    /// the chat list listens to message presence, the contact list
    /// listens to in_address_book.
    var chatPeerIds: Set<String> {
        var ids = Set<String>()
        for m in messages {
            ids.insert(m.from)
            if let to = m.to { ids.insert(to) }
        }
        ids.remove(myPeerId)
        return ids
    }

    /// Address-book peers: only those the user explicitly added via
    /// New Chat paste / QR scan / Import.  Narrower than
    /// `chatPeerIds` — drives ContactsListView so strangers who
    /// messaged us don't auto-populate the roster.
    var contactPeerIds: Set<String> {
        var ids = knownPeerContacts
        ids.remove(myPeerId)
        return ids
    }

    // Plaintext passphrase from the most recent unlock, held only so
    // the Settings → "Enable Face ID" toggle can install it into the
    // Keychain without re-prompting.  Wiped on app background and on
    // first read via `consumeUnlockPassphrase()` — whichever comes
    // first.  Not @Published: we don't want the value flowing through
    // SwiftUI re-renders or driving persistSnapshot.
    private var lastUnlockPassphrase: String = ""

    func setLastUnlockPassphrase(_ pass: String) {
        lastUnlockPassphrase = pass
    }

    /// One-time read.  Returns the cached passphrase and clears it.
    /// Returns nil if nothing's cached (e.g. user came back to Settings
    /// after backgrounding the app, or already enabled Face ID once).
    func consumeUnlockPassphrase() -> String? {
        let pass = lastUnlockPassphrase
        lastUnlockPassphrase = ""
        return pass.isEmpty ? nil : pass
    }

    // MARK: - Internal

    /// Raw C context pointer — accessed by platform adapters
    private(set) var rawContext: OpaquePointer?

    private var ws: WebSocketAdapter!
    private var http: HttpAdapter!

    // MARK: - Lifecycle

    init() {
        ws = WebSocketAdapter(client: self)
        http = HttpAdapter(client: self)
        // Wipe any cached unlock passphrase as soon as the app
        // backgrounds — UIKit posts this synchronously before the
        // process can be jetsam'd or memory-imaged.  Also stamp the
        // background time so the foreground observer can decide
        // whether to auto-lock.  Kept tokens here so the observers
        // don't outlive `self`.
        backgroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            _ = self?.consumeUnlockPassphrase()
            self?.backgroundedAt = Date()
        }
        foregroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.maybeAutoLock()
        }
    }

    deinit {
        if let backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
        }
        if let foregroundObserver {
            NotificationCenter.default.removeObserver(foregroundObserver)
        }
        stop()
    }

    private var backgroundObserver: NSObjectProtocol?
    private var foregroundObserver: NSObjectProtocol?

    /// Wall-clock instant the app most recently entered background.
    /// Cleared once the auto-lock decision is made on foreground.
    /// Read/written by `maybeAutoLock` in +Notifications.
    var backgroundedAt: Date?


    /// Panic wipe: nuke every file in the app's documents directory
    /// (identity, SQLCipher DB, salt, message snapshot if any) and
    /// remove the biometric passphrase from the Keychain.  Mirrors
    /// what `simctl uninstall + install` does, without an actual
    /// reinstall.  After this returns the app is in the "fresh
    /// install" state and OnboardingView's next render will show the
    /// "Get Started" branch instead of "Unlock".
    func wipeAllData(documentDir: String) {
        stop()
        BiometricUnlock.remove()
        UserDefaults.standard.set(0, forKey: Self.kFailedUnlockAttemptsKey)
        let fm = FileManager.default
        if let contents = try? fm.contentsOfDirectory(atPath: documentDir) {
            for item in contents {
                try? fm.removeItem(atPath: documentDir + "/" + item)
            }
        }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.myPeerId        = ""
            self.statusMessage   = ""
            self.dataWipedNotice = true
        }
    }

    /// Initialize the protocol engine with a data directory and passphrase.
    func start(dataDir: String, passphrase: String, relayUrl: String) {
        guard rawContext == nil else { return }
        // Wipe any stale error from a prior failed unlock so the new
        // attempt starts clean.  Without this, a successful retry
        // shows the previous "Identity unlock failed" string until
        // the next on_status callback overwrites it.
        statusMessage = ""

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

        // Hydrate the @Published surface from the SQLCipher AppDataStore.
        // Done BEFORE p2p_connect so setKnownGroupMembers replays the
        // roster authorization gate before any inbound control
        // messages arrive on the new socket.
        loadStateFromDb()

        // Re-apply file-policy preferences each unlock so a setting the
        // user changed in a prior session takes effect now.  Network
        // monitor decides the effective auto-accept value (0 on
        // cellular when wifi-only is on).
        startNetworkMonitor()
        setFileHardMaxMB(fileHardMaxMB)
        setFileRequireP2P(fileRequireP2P)
        setHardBlockOnKeyChange(hardBlockOnKeyChange)
        setPrivacyLevel(privacyLevel.rawValue)
        applyEffectiveAutoAcceptThreshold()

        p2p_set_relay_url(rawContext, relayUrl)
        // Replay the persisted backup-relay list into the core's send
        // pool so Privacy=Maximum's multi-hop path (gated on
        // m_sendRelays.size() >= 2) has forwarders to choose from.
        // Order is stable (primary via set_relay_url, then backups in
        // insertion order) so the pool composition matches across
        // relaunches — keeps forwarder selection consistent.
        for backup in backupRelayUrls {
            addSendRelay(url: backup)
        }
        p2p_connect(rawContext)

        // If APNs registered before start() completed, the AppDelegate
        // will have stashed the token in `pendingPushToken`.  Forward
        // it now so the relay sees us as reachable via push from the
        // very first connection.
        forwardPushTokenIfConnected()
    }

    func stop() {
        if let ctx = rawContext {
            p2p_destroy(ctx)
            rawContext = nil
        }
        isConnected = false
    }

    /// Tear down the unlocked session and bounce back to OnboardingView.
    /// Drops the rawContext (which evicts the dbKey + ratchet state from
    /// memory), wipes the cached passphrase, and clears the @Published
    /// surface so SwiftUI swaps to the unlock screen via the
    /// `client.myPeerId.isEmpty` state-machine guard at the app root.
    /// On the next unlock, `loadStateFromDb()` repopulates from the
    /// SQLCipher AppDataStore so contacts/messages/etc. survive the lock.
    func lock() {
        _ = consumeUnlockPassphrase()  // belt-and-braces — also wiped on background
        stop()
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.myPeerId          = ""
            self.statusMessage     = ""
            self.messages          = []
            self.groupMessages     = []
            self.groups            = [:]
            self.groupAvatars      = [:]
            self.knownPeerContacts = []
            self.contactNicknames  = [:]
            self.blockedPeerIds    = []
            self.peerPresence      = [:]
            self.peerAvatars       = [:]
            self.pendingFileRequests = []
            self.transfers         = [:]
            self.keyChanges        = [:]
        }
    }

    /// Stashed APNs token waiting to be forwarded once `rawContext` is live.
    /// Accessed by +Notifications' push-token methods.
    var pendingPushToken: (token: String, platform: String)?

    /// How much content to reveal in the OS notification banner.
    /// Default is `.hidden` because iOS persists notification
    /// payloads in a system-level store (`backboardd` / NotificationCenter
    /// DB) that forensic tools can extract even after the app "forgets"
    /// a message.  Once plaintext enters that store, our SQLCipher-
    /// at-rest posture is defeated.  Users who value UX over this
    /// residual leak can opt up to `.senderOnly` or `.full`.
    enum NotificationContentMode: String {
        case hidden     = "hidden"      // "New message"
        case senderOnly = "sender"      // "New message from <fingerprint>"
        case full       = "full"        // "Alice: hello"
    }

    // MARK: - Auto-lock + wipe-on-failure preferences

    /// Minutes of background time before the app auto-locks on
    /// foreground.  0 = lock immediately on every background, -1 = never,
    /// otherwise a positive minute count.  Default 5 minutes.
    static let kAutoLockMinutesKey = "p2p.autoLockMinutes"
    static let kDefaultAutoLockMinutes = 5

    @Published var autoLockMinutes: Int = {
        let v = UserDefaults.standard.object(forKey: Peer2PearClient.kAutoLockMinutesKey) as? Int
        return v ?? Peer2PearClient.kDefaultAutoLockMinutes
    }() {
        didSet { UserDefaults.standard.set(autoLockMinutes,
                                            forKey: Peer2PearClient.kAutoLockMinutesKey) }
    }

    /// When enabled, 12 consecutive failed unlock attempts wipe every
    /// byte in the app sandbox (identity files, SQLCipher DB, Keychain
    /// passphrase if any) — panic-wipe mirrors the iOS native passcode
    /// "Erase Data" option.  Off by default: destructive setting that
    /// users must opt into knowingly.
    static let kWipeOnFailedAttemptsKey = "p2p.wipeOnFailedAttempts"
    static let kFailedUnlockAttemptsKey = "p2p.failedUnlockAttempts"
    /// After N consecutive failures, wipe.  Matches iOS native default.
    static let kFailedUnlockAttemptsThreshold = 12

    @Published var wipeOnFailedAttempts: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kWipeOnFailedAttemptsKey) {
        didSet { UserDefaults.standard.set(wipeOnFailedAttempts,
                                            forKey: Peer2PearClient.kWipeOnFailedAttemptsKey) }
    }

    /// Flipped to true by `wipeAllData` so the onboarding view can show
    /// a one-shot "Data Erased" notice.  Consumer should reset after read.
    @Published var dataWipedNotice: Bool = false

    // MARK: - File-transfer policy preferences
    //
    // Core ships defaults of 100 MB auto-accept / 100 MB hard cap.  We
    // mirror that here, persist user changes to UserDefaults, and re-
    // apply on every start() so the policy survives lock + relaunch.
    // The verified-contacts gate is iOS-side because it's a UX policy
    // (silently decline) rather than a protocol invariant.

    static let kFileAutoAcceptMBKey   = "p2p.file.autoAcceptMB"
    static let kFileHardMaxMBKey      = "p2p.file.hardMaxMB"
    static let kFileRequireP2PKey     = "p2p.file.requireP2P"
    static let kFileVerifiedOnlyKey   = "p2p.file.verifiedOnly"

    static let kDefaultFileAutoAcceptMB = 100
    static let kDefaultFileHardMaxMB    = 100

    @Published var fileAutoAcceptMB: Int = {
        let v = UserDefaults.standard.object(forKey: Peer2PearClient.kFileAutoAcceptMBKey) as? Int
        return v ?? Peer2PearClient.kDefaultFileAutoAcceptMB
    }() {
        didSet {
            UserDefaults.standard.set(fileAutoAcceptMB, forKey: Self.kFileAutoAcceptMBKey)
            setFileAutoAcceptMB(fileAutoAcceptMB)
        }
    }

    @Published var fileHardMaxMB: Int = {
        let v = UserDefaults.standard.object(forKey: Peer2PearClient.kFileHardMaxMBKey) as? Int
        return v ?? Peer2PearClient.kDefaultFileHardMaxMB
    }() {
        didSet {
            UserDefaults.standard.set(fileHardMaxMB, forKey: Self.kFileHardMaxMBKey)
            setFileHardMaxMB(fileHardMaxMB)
        }
    }

    @Published var fileRequireP2P: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kFileRequireP2PKey) {
        didSet {
            UserDefaults.standard.set(fileRequireP2P, forKey: Self.kFileRequireP2PKey)
            setFileRequireP2P(fileRequireP2P)
        }
    }

    /// Silently decline file requests from peers whose safety number
    /// hasn't been confirmed.  Pure iOS-side filter (the core still
    /// receives the envelope; we just send back a decline before the
    /// user is even prompted).
    @Published var fileRequireVerifiedContact: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kFileVerifiedOnlyKey) {
        didSet {
            UserDefaults.standard.set(fileRequireVerifiedContact,
                                       forKey: Self.kFileVerifiedOnlyKey)
        }
    }

    /// Three-tier privacy posture for the relay protocol.  Mirrors the
    /// desktop "Privacy" picker — every level subsumes the previous.
    /// Stored as the int the C API expects (0/1/2).
    enum PrivacyLevel: Int, CaseIterable, Identifiable {
        case standard = 0   // envelope padding + sealed sender + E2EE
        case enhanced = 1   // + send jitter + cover traffic + multi-relay rotation
        case maximum  = 2   // + multi-hop forwarding + high-frequency cover traffic
        var id: Int { rawValue }
    }

    static let kPrivacyLevelKey = "p2p.privacyLevel"

    @Published var privacyLevel: PrivacyLevel = {
        let raw = UserDefaults.standard.object(forKey: Peer2PearClient.kPrivacyLevelKey) as? Int
        return PrivacyLevel(rawValue: raw ?? 0) ?? .standard
    }() {
        didSet {
            UserDefaults.standard.set(privacyLevel.rawValue,
                                       forKey: Self.kPrivacyLevelKey)
            setPrivacyLevel(privacyLevel.rawValue)
        }
    }

    /// Hard-block messages and files to/from a contact whose safety
    /// number no longer matches what we previously verified.  Off by
    /// default — a mismatch surfaces a banner in ChatRow and the user
    /// chooses whether to continue.  When on, the core enforces the
    /// block at seal/unseal time so the UI never has to render the
    /// warning state, mirroring desktop's policy of the same name.
    static let kHardBlockOnKeyChangeKey = "p2p.hardBlockOnKeyChange"
    @Published var hardBlockOnKeyChange: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kHardBlockOnKeyChangeKey) {
        didSet {
            UserDefaults.standard.set(hardBlockOnKeyChange,
                                       forKey: Self.kHardBlockOnKeyChangeKey)
            setHardBlockOnKeyChange(hardBlockOnKeyChange)
        }
    }

    /// Cellular-data hygiene: when on, the auto-accept threshold is
    /// silently overridden to 0 whenever the device is NOT on Wi-Fi
    /// (LTE / 5G / hotspot tethering).  The user gets an explicit
    /// prompt for every file on cellular and saves both bytes and
    /// battery.  Default ON because surprise data charges are worse
    /// than an extra tap.  Doesn't affect the hard cap or any other
    /// policy — only auto-accept.
    static let kFileAutoAcceptWifiOnlyKey = "p2p.file.autoAcceptWifiOnly"
    @Published var fileAutoAcceptWifiOnly: Bool = {
        let v = UserDefaults.standard.object(forKey: Peer2PearClient.kFileAutoAcceptWifiOnlyKey) as? Bool
        return v ?? true
    }() {
        didSet {
            UserDefaults.standard.set(fileAutoAcceptWifiOnly,
                                       forKey: Self.kFileAutoAcceptWifiOnlyKey)
            applyEffectiveAutoAcceptThreshold()
        }
    }

    /// True whenever the most-recent NWPathMonitor update saw Wi-Fi
    /// (or a wired connection on iPad with USB-C ethernet).  False on
    /// cellular / hotspot / unknown.  Drives both
    /// `applyEffectiveAutoAcceptThreshold` and a small UI label that
    /// surfaces "Cellular — auto-accept paused" when relevant.
    @Published var onWifi: Bool = true

    /// Owned by +FileTransfer's `startNetworkMonitor`; held here since
    /// extensions can't hold stored state.
    var pathMonitor: NWPathMonitor?


    /// Current consecutive-failure counter.  Exposed so the settings UI
    /// can surface "X of 12 attempts used" to give users a heads-up.
    var failedUnlockAttempts: Int {
        UserDefaults.standard.integer(forKey: Self.kFailedUnlockAttemptsKey)
    }

    private static let kNotificationModeKey = "p2p.notificationContentMode"

    @Published var notificationContentMode: NotificationContentMode = {
        let raw = UserDefaults.standard.string(forKey: kNotificationModeKey)
               ?? NotificationContentMode.hidden.rawValue
        return NotificationContentMode(rawValue: raw) ?? .hidden
    }() {
        didSet {
            UserDefaults.standard.set(notificationContentMode.rawValue,
                                       forKey: Self.kNotificationModeKey)
        }
    }

    // MARK: - Messaging actions

    func sendText(to peerId: String, text: String) {
        guard let ctx = rawContext else { return }
        // Refuse to send to a blocked peer — mirrors desktop's
        // isBlocked guard.  Silent no-op so the UI doesn't accidentally
        // reach someone the user chose to ignore.
        if isBlocked(peerId: peerId) { return }
        // Local echo: the core doesn't fire on_message for our own
        // outbound sends, so the sender's ConversationView would stay
        // empty even after a successful send.  Append to `messages`
        // with from == myPeerId so MessageBubble renders it on the
        // right side.  Mirrors the group send path which already echoes
        // via `client.groupMessages.append(...)` in ConversationView.
        let echo = P2PMessage(
            id: UUID().uuidString,
            from: myPeerId,
            text: text,
            timestamp: Date(),
            to: peerId)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.messages.append(echo)
            // saveMessage internally INSERT-OR-IGNOREs a contacts stub
            // row to satisfy the FK, so callers don't have to worry
            // about ordering vs. addContact.
            self.dbSaveMessage(peerId: peerId, message: DBMessage(
                sent:          true,
                text:          echo.text,
                timestampSecs: Int64(echo.timestamp.timeIntervalSince1970),
                msgId:         echo.id,
                senderName:    ""))
        }
        p2p_send_text(ctx, peerId, text)
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

    /// Append a relay URL to the core's send pool for multi-hop
    /// forwarding.  Safe to call before start() — becomes a no-op when
    /// rawContext is nil, and the persisted list is replayed on every
    /// start() anyway.  Deduplication happens in the core.
    func addSendRelay(url: String) {
        guard let ctx = rawContext else { return }
        p2p_add_send_relay(ctx, url)
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

}
