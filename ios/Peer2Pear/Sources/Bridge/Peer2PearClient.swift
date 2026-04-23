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

    /// True when a passphrase-unlockable identity already lives on disk.
    /// Drives the Onboarding "Unlock" vs. "Create" branching — mirrors
    /// what `p2p_set_passphrase_v2` in the core checks (the salt file is
    /// created on first run and persists for the life of the install).
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
    // Wire format matches the desktop's `peer2pear_contacts.json`
    // schema (see desktop/mainwindow.cpp onExportContacts + onImportContacts)
    // so an exported file from either platform imports cleanly into the
    // other.  Version 1 is: `{ "version": 1, "contacts": [{name, keys[]}] }`.

    struct ContactsExport: Codable {
        let version: Int
        let contacts: [Entry]
        struct Entry: Codable {
            let name: String
            let keys: [String]
        }
    }

    /// Build a desktop-compatible JSON blob of the address book.  Only
    /// explicit contacts are exported — strangers we've merely exchanged
    /// messages with stay out, matching the ContactsListView roster.
    /// Each entry uses `displayName(for:)` so nicknames survive the
    /// round-trip; when no nickname is set, falls back to the peer's
    /// published display name or the key prefix.
    func exportContactsJSON() -> Data {
        let entries = contactPeerIds.sorted().map { peerId in
            ContactsExport.Entry(
                name: displayName(for: peerId),
                keys: [peerId])
        }
        let payload = ContactsExport(version: 1, contacts: entries)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        return (try? enc.encode(payload)) ?? Data()
    }

    /// Merge contacts from an exported JSON blob into our local state.
    /// Returns the count successfully imported (skipping malformed
    /// entries, self, and entries whose first key isn't a 43-char
    /// base64url peer ID).  Existing nicknames are overwritten by the
    /// incoming name — treating the import as authoritative matches
    /// the desktop's "imported name stored as-is" behavior.
    @discardableResult
    func importContacts(from data: Data) -> Int {
        guard let payload = try? JSONDecoder()
            .decode(ContactsExport.self, from: data) else { return 0 }
        var imported = 0
        for entry in payload.contacts {
            guard let key = entry.keys.first else { continue }
            let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.count == 43, trimmed != myPeerId else { continue }
            addContact(peerId: trimmed)
            let name = entry.name.trimmingCharacters(in: .whitespacesAndNewlines)
            if !name.isEmpty {
                setNickname(peerId: trimmed, nickname: name)
            }
            imported += 1
        }
        return imported
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
    private var backgroundedAt: Date?

    /// Foreground hook: if the unlocked session has been backgrounded
    /// longer than `autoLockMinutes`, fire `lock()` so the user has to
    /// re-authenticate.  -1 = never, 0 = lock on every backgrounding,
    /// otherwise a minute threshold.  No-op when locked already.
    private func maybeAutoLock() {
        guard let bgAt = backgroundedAt else { return }
        backgroundedAt = nil
        // Only relevant when we have a live unlocked session.
        guard rawContext != nil else { return }
        let mins = autoLockMinutes
        if mins < 0 { return }              // "Never"
        if mins == 0 { lock(); return }     // "Immediately"
        let elapsed = Date().timeIntervalSince(bgAt)
        if elapsed >= TimeInterval(mins) * 60 { lock() }
    }

    // MARK: - Failed unlock counter + panic wipe

    /// Bump the failed-attempt counter.  When the wipe-on-failure
    /// setting is on AND the counter crosses the threshold, nuke the
    /// entire app sandbox via `wipeAllData(documentDir:)`.  Returns
    /// true if a wipe fired so the caller (OnboardingView) can show
    /// the notice.
    @discardableResult
    func recordFailedUnlock(documentDir: String) -> Bool {
        let next = failedUnlockAttempts + 1
        UserDefaults.standard.set(next, forKey: Self.kFailedUnlockAttemptsKey)
        if wipeOnFailedAttempts, next >= Self.kFailedUnlockAttemptsThreshold {
            wipeAllData(documentDir: documentDir)
            return true
        }
        return false
    }

    /// Reset the failed-attempt counter — called after a successful
    /// unlock so a sequence like "wrong, wrong, right" doesn't keep
    /// the counter primed for a wipe on the next typo session.
    func resetFailedUnlockCounter() {
        UserDefaults.standard.set(0, forKey: Self.kFailedUnlockAttemptsKey)
    }

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
        // H2 roster gate before any inbound control messages arrive on
        // the new socket.
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

    // MARK: - Push notifications

    /// Hand the APNs device token to the core, which forwards it to
    /// the relay over the authenticated WebSocket.  Safe to call
    /// before `start()` — the token is stashed and replayed once the
    /// core is live.  `token` is the hex-encoded bytes; empty
    /// unregisters the device.
    func setPushToken(_ token: String, platform: String) {
        pendingPushToken = (token, platform)
        forwardPushTokenIfConnected()
    }

    /// Invoked by the AppDelegate when a silent push arrives while the
    /// app is backgrounded.  iOS gives us ~30 s to fetch queued
    /// envelopes before freezing the app again.  Completion is called
    /// with `true` if we observed any new data during the wake.
    func handleBackgroundPush(completion: @escaping (Bool) -> Void) {
        guard let ctx = rawContext else {
            completion(false)
            return
        }
        let baseline = messages.count + groupMessages.count
        p2p_wake_for_push(ctx)

        // Poll for ~5 s: if a new message has landed by then, we
        // report newData.  Longer-running delivery after completion
        // still fires normal callbacks + local notifications — the
        // completion here just tells iOS whether the wake was useful
        // for background-refresh scheduling heuristics.
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            guard let self else { completion(false); return }
            let now = self.messages.count + self.groupMessages.count
            completion(now > baseline)
        }
    }

    private var pendingPushToken: (token: String, platform: String)?

    private func forwardPushTokenIfConnected() {
        guard let ctx = rawContext, let p = pendingPushToken else { return }
        p2p_set_push_token(ctx, p.token, p.platform)
        // Leave `pendingPushToken` set — RelayClient replays it on
        // every reconnect already, and re-sending on a warm WS is
        // idempotent at the relay level (upsert).
    }

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

    private var pathMonitor: NWPathMonitor?

    /// Compute and push the effective auto-accept MB to the core based
    /// on the user's setting + current network type.  Called on every
    /// network change AND every time the user flips the toggle / changes
    /// the threshold, so the core's rule is always current.
    private func applyEffectiveAutoAcceptThreshold() {
        let effective: Int = (fileAutoAcceptWifiOnly && !onWifi)
            ? 0
            : fileAutoAcceptMB
        setFileAutoAcceptMB(effective)
    }

    private func startNetworkMonitor() {
        guard pathMonitor == nil else { return }
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            // usesInterfaceType(.wifi) is true for both 802.11 and a
            // wired ethernet adapter.  Treat both as "not cellular".
            let onWifi = path.usesInterfaceType(.wifi)
                      || path.usesInterfaceType(.wiredEthernet)
            DispatchQueue.main.async {
                guard let self else { return }
                if self.onWifi != onWifi {
                    self.onWifi = onWifi
                    self.applyEffectiveAutoAcceptThreshold()
                }
            }
        }
        m.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = m
    }

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

    /// Fire a local UNUserNotificationCenter banner for an inbound
    /// message, applying the user's content-privacy mode.  The OS
    /// decides whether to actually surface it — foreground banners
    /// go through Peer2PearAppDelegate's willPresent delegate method;
    /// backgrounded banners surface directly.
    ///
    /// The sender ID / message text passed here are always the
    /// decrypted, plaintext values; this function decides what
    /// fraction (if any) to hand to the OS notification store.
    /// Own-message check prevents double-notify when the sender
    /// receives their own fan-out on group sends.
    fileprivate func fireLocalNotification(
        fromPeerId: String,
        senderDisplay: String,   // e.g., first-8-chars fingerprint, or "Alice"
        groupName: String?,      // non-nil for group messages
        messageText: String,
        threadId: String
    ) {
        if fromPeerId == myPeerId { return }

        let content = UNMutableNotificationContent()
        content.sound = .default
        content.threadIdentifier = threadId

        switch notificationContentMode {
        case .hidden:
            // Generic wake-up only — the OS notification DB learns
            // nothing about who or what.  User opens the app to see
            // the actual message, which lives only in our encrypted
            // SQLCipher AppDataStore.
            content.title = "Peer2Pear"
            content.body  = "New message"

        case .senderOnly:
            content.title = "Peer2Pear"
            if let group = groupName, !group.isEmpty {
                content.body = "New message in \(group)"
            } else {
                content.body = "New message from \(senderDisplay)"
            }

        case .full:
            if let group = groupName, !group.isEmpty {
                content.title = group
                content.subtitle = senderDisplay
            } else {
                content.title = senderDisplay
            }
            content.body = messageText.count > 140
                ? String(messageText.prefix(137)) + "…"
                : messageText
        }

        let req = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
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
            self.dbSaveContact(DBContact(
                peerId:        gid,
                name:          name,
                keys:          memberPeerIds,
                isGroup:       true,
                groupId:       gid,
                lastActiveSecs: Int64(group.lastActivity.timeIntervalSince1970)))
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
                guard let self, var g = self.groups[groupId] else { return }
                g.name = newName
                g.lastActivity = Date()
                self.groups[groupId] = g
                self.dbSaveContact(DBContact(
                    peerId:        groupId,
                    name:          newName,
                    keys:          g.memberIds,
                    isGroup:       true,
                    groupId:       groupId,
                    avatarB64:     self.groupAvatars[groupId] ?? "",
                    lastActiveSecs: Int64(g.lastActivity.timeIntervalSince1970)))
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
                guard let self else { return }
                self.groups.removeValue(forKey: groupId)
                self.groupMessages.removeAll { $0.groupId == groupId }
                self.groupAvatars.removeValue(forKey: groupId)
                // CASCADE wipes the group's messages via the FK.
                self.dbDeleteContact(peerId: groupId)
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
                guard let self else { return }
                self.groupAvatars[groupId] = avatarB64
                self.dbSaveContactAvatar(peerId: groupId, avatarB64: avatarB64)
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
                self.dbSaveContact(DBContact(
                    peerId:        groupId,
                    name:          g.name,
                    keys:          memberPeerIds,
                    isGroup:       true,
                    groupId:       groupId,
                    avatarB64:     self.groupAvatars[groupId] ?? "",
                    lastActiveSecs: Int64(g.lastActivity.timeIntervalSince1970)))
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
        if let r = transfers[id] { persistTransfer(r) }
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
        persistTransfer(existing)
    }

    /// Mirror a P2PTransferRecord into the file_transfers table so the
    /// row survives lock/unlock + relaunch.  Cheap UPSERT — every status
    /// change calls this; SQLite handles it in <1 ms.  The chat key is
    /// the counter-party's peer ID for 1:1 (groups TBD when iOS sends
    /// group files).
    private func persistTransfer(_ r: P2PTransferRecord) {
        dbSaveFileRecord(DBFileRecord(
            transferId:     r.id,
            chatKey:        r.peerId,
            fileName:       r.fileName,
            fileSize:       r.fileSize,
            peerId:         r.peerId,
            peerName:       contactNicknames[r.peerId] ?? "",
            timestampSecs:  Int64(r.timestamp.timeIntervalSince1970),
            sent:           r.direction == .outbound,
            status:         Self.encodeStatus(r.status),
            chunksTotal:    r.chunksTotal,
            chunksComplete: r.chunksDone,
            savedPath:      r.savedPath ?? ""))
    }

    // MARK: - File transfer actions

    /// Start a file send.  Returns the transferId on success, nil otherwise.
    /// The receiver will get an `on_file_request` callback and must accept
    /// via `respondToFileRequest` before chunks flow.
    @discardableResult
    func sendFile(to peerId: String, fileName: String, filePath: String) -> String? {
        guard let ctx = rawContext else { return nil }
        if isBlocked(peerId: peerId) { return nil }
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

    /// Drop a terminal transfer record from the chat strip and the
    /// SQLCipher file_transfers table.  Mirrors desktop's "Remove this
    /// file from your file list" action — the saved file (if any) stays
    /// on disk untouched; only the bookkeeping row goes away.  No-op
    /// for in-flight transfers (use `cancelTransfer` for those).
    func removeTransferRecord(transferId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.transfers.removeValue(forKey: transferId)
            self.dbDeleteFileRecord(transferId: transferId)
        }
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
            DispatchQueue.main.async {
                // Drop messages from blocked peers.  Mirrors desktop
                // chatview `if (chat.isBlocked) return`.  Silent — no
                // notification, no list entry.
                if client.isBlocked(peerId: msg.from) { return }
                client.messages.append(msg)
                // Persist: saveMessage internally INSERT-OR-IGNOREs a
                // stub contacts row for the FK, leaving the sender
                // out of the address book (in_address_book=0) until
                // the user explicitly adds them via "+ New Chat".
                client.dbSaveMessage(peerId: msg.from, message: DBMessage(
                    sent:          false,
                    text:          msg.text,
                    timestampSecs: Int64(msg.timestamp.timeIntervalSince1970),
                    msgId:         msg.id,
                    senderName:    ""))
                // threadId = sender so iOS groups banners per-conversation.
                // The content-privacy mode decides how much actually
                // enters the OS notification store.
                client.fireLocalNotification(
                    fromPeerId: msg.from,
                    senderDisplay: String(msg.from.prefix(8)) + "…",
                    groupName: nil,
                    messageText: msg.text,
                    threadId: "dm:" + msg.from)
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
                // Persist: upsert the group's contact row + insert the
                // message.  senderName carries the sender's peer ID so
                // a later restart can reconstruct who sent what.
                client.dbSaveContact(DBContact(
                    peerId:        gm.groupId,
                    name:          g.name,
                    keys:          roster,
                    isGroup:       true,
                    groupId:       gm.groupId,
                    avatarB64:     client.groupAvatars[gm.groupId] ?? "",
                    lastActiveSecs: Int64(g.lastActivity.timeIntervalSince1970)))
                client.dbSaveMessage(peerId: gm.groupId, message: DBMessage(
                    sent:          gm.from == client.myPeerId,
                    text:          gm.text,
                    timestampSecs: Int64(gm.timestamp.timeIntervalSince1970),
                    msgId:         gm.id,
                    senderName:    gm.from))

                client.fireLocalNotification(
                    fromPeerId: gm.from,
                    senderDisplay: String(gm.from.prefix(8)) + "…",
                    groupName: gm.groupName.isEmpty ? "Group" : gm.groupName,
                    messageText: gm.text,
                    threadId: "group:" + gm.groupId)
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
                // Persist roster change + marker.
                if let g = client.groups[gidStr] {
                    client.dbSaveContact(DBContact(
                        peerId:        gidStr,
                        name:          g.name,
                        keys:          g.memberIds,
                        isGroup:       true,
                        groupId:       gidStr,
                        avatarB64:     client.groupAvatars[gidStr] ?? "",
                        lastActiveSecs: Int64(g.lastActivity.timeIntervalSince1970)))
                }
                client.dbSaveMessage(peerId: gidStr, message: DBMessage(
                    sent:          fromStr == client.myPeerId,
                    text:          marker.text,
                    timestampSecs: Int64(marker.timestamp.timeIntervalSince1970),
                    msgId:         marker.id,
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
                client.dbSaveContact(DBContact(
                    peerId:        gidStr,
                    name:          nameStr,
                    keys:          g.memberIds,
                    isGroup:       true,
                    groupId:       gidStr,
                    avatarB64:     client.groupAvatars[gidStr] ?? "",
                    lastActiveSecs: Int64(g.lastActivity.timeIntervalSince1970)))
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
                    client.dbSaveContactAvatar(peerId: gidStr, avatarB64: avatarStr)
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
