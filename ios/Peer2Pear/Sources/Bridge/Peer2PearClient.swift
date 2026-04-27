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

    /// Walk `dir` and apply two on-disk privacy attributes to every
    /// file:
    ///
    /// 1. **`NSFileProtectionComplete`** — iOS drops the per-file
    ///    storage key whenever the device locks.  Default for app-
    ///    sandbox files is `.completeUntilFirstUserAuthentication`
    ///    (key stays resident across lock cycles after the first
    ///    post-boot unlock).
    ///
    /// 2. **`isExcludedFromBackup = true`** — keep the SQLCipher DB,
    ///    identity keys, salt, and saved files out of iCloud Backup.
    ///    The bytes are encrypted (SQLCipher + Argon2id over the
    ///    user passphrase), but iCloud Backup persists ciphertext on
    ///    Apple's servers indefinitely — a long-tail subpoena /
    ///    server-compromise / brute-force surface that an
    ///    on-device-only privacy app shouldn't carry.  Migration to
    ///    a new device is intentionally NOT served by iCloud here;
    ///    a deliberate export/import flow is tracked in
    ///    project_backup_strategy.md as future work.
    ///
    /// Called after every successful unlock.  Both operations are
    /// idempotent — re-applying on a file that already has them is
    /// a cheap no-op.  Failures on individual files are swallowed
    /// (debug-logged) so a single permission glitch doesn't break
    /// the whole unlock flow.
    ///
    /// Doesn't recurse into subdirectories today — we don't have
    /// any.  Add a `subpathsOfDirectory` walk here if that changes.
    fileprivate func applyDataProtection(toDirectory dir: String) {
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(atPath: dir) else {
            return
        }
        for item in contents {
            let path = dir + "/" + item

            // Pass 1: NSFileProtectionComplete via FileManager
            // attributes.
            do {
                try fm.setAttributes(
                    [.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: path)
            } catch {
                #if DEBUG
                print("[Peer2Pear] couldn't set .complete protection on \(item): \(error)")
                #endif
            }

            // Pass 2: exclude from iCloud Backup.  Uses URL resource
            // values, not FileManager attributes — the key lives on
            // the URL's resource-properties surface, not the
            // POSIX-style file metadata.  setResourceValues mutates
            // the URL value (it's `inout` semantically even though
            // not declared so), which is why `url` is `var`.
            var url = URL(fileURLWithPath: path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            do {
                try url.setResourceValues(values)
            } catch {
                #if DEBUG
                print("[Peer2Pear] couldn't exclude \(item) from iCloud Backup: \(error)")
                #endif
            }
        }
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

    static let kColorSchemeKey = "p2p.colorScheme"

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

    /// Transient status for the chat-list toast (group-send failures,
    /// relay retry / give-up, session errors).  Set by the core's
    /// on_status callback; the view clears it after displaying for a
    /// few seconds.  Kept separate from `statusMessage`, which
    /// OnboardingView uses for the persistent unlock banner.
    @Published var toastMessage: String?

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

    /// pv=2 (Causally-Linked Pairwise) UX state.

    /// One sender's missing range inside a group.  Surfaced as
    /// "waiting for messages from X..." banner in ConversationView.
    /// Cleared once the gap fills (next in-order group_message
    /// arrival from this sender) or on session reset.
    struct BlockedRange: Equatable {
        var from: Int64
        var to:   Int64
    }
    /// groupId → senderPeerId → BlockedRange.  Per-(group, sender)
    /// because the same group may have multiple senders blocked
    /// independently (one peer's stream stalled while another's flows).
    @Published var groupBlockedStreams: [String: [String: BlockedRange]] = [:]

    /// One "K messages lost during reconnection" event.  Appended on
    /// session reset; the UI surfaces a one-shot alert and removes
    /// (or marks-seen) the entry after dismissal.
    struct LostMessagesEvent: Equatable, Identifiable {
        let id = UUID()
        let groupId:      String
        let senderPeerId: String
        let count:        Int64
    }
    @Published var groupLostMessages: [LostMessagesEvent] = []

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

    /// Peers the user explicitly added to the address book — drives
    /// ContactsListView and is unioned with message-derived peers in
    /// ChatListView.  Backed 1:1 by the v3 contacts table now: every
    /// row in `contacts` is by definition a curated address-book
    /// entry (no more in_address_book toggle).
    @Published var knownPeerContacts: Set<String> = []

    /// peer_id → conversation_id mapping for 1:1 chats.  Populated at
    /// startup from the conversations table and lazily extended via
    /// `ensureDirectConversationId(for:)` when a stranger first
    /// messages us or we send to a peer for the first time.  The view
    /// layer keeps `messages` peer-keyed; this dict is the indirection
    /// that lets the bridge re-key those reads/writes onto
    /// `messages.conversation_id` under the hood.
    @Published var directConversationIdByPeer: [String: String] = [:]

    /// Look up (or mint + cache) the conversation_id for a 1:1 chat
    /// with `peerId`.  Returns nil only when `rawContext` is nil —
    /// concurrent callers converge on the same id via the partial
    /// UNIQUE index in the conversations table.
    @discardableResult
    func ensureDirectConversationId(for peerId: String) -> String? {
        if let cached = directConversationIdByPeer[peerId] { return cached }
        guard let convId = dbFindOrCreateDirectConversation(peerId: peerId) else {
            return nil
        }
        DispatchQueue.main.async { [weak self] in
            self?.directConversationIdByPeer[peerId] = convId
        }
        return convId
    }

    /// Register a peer as a known contact.  Safe to call on an already-
    /// known peer (idempotent), and skips self (the core filters self
    /// out everywhere else, keep the invariant here too).  Upserts a
    /// row in the v3 contacts table.
    func addContact(peerId: String) {
        let trimmed = peerId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != myPeerId else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts.insert(trimmed)
            self.dbSaveContact(DBContact(
                peerId: trimmed,
                name:   self.contactNicknames[trimmed] ?? "",
                muted:  self.mutedPeerIds.contains(trimmed)))
        }
    }

    /// Remove a peer from the address book.  v3 contract: this drops
    /// the `contacts` row only; conversations and messages with this
    /// peer are NOT touched (chat history is the user's data, separate
    /// from address-book curation).  Use `deleteChat(peerId:)` to wipe
    /// the transcript separately.
    func removeContact(peerId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.knownPeerContacts.remove(peerId)
            self.contactNicknames.removeValue(forKey: peerId)
            self.dbDeleteContact(peerId: peerId)
        }
    }

    /// Delete a single 1:1 or group message by msgId.  Wipes the row
    /// from the in-memory @Published arrays and from the SQLCipher
    /// store; the chat itself is untouched.  Used by the long-press
    /// "Delete Message" action on message bubbles.
    ///
    /// `chatKey` is the peer ID for 1:1s and the group ID for group
    /// messages — under v3 we resolve it to a conversation_id before
    /// the DB write (groups: chatKey == conv_id; direct: lookup via
    /// directConversationIdByPeer).
    func deleteMessage(chatKey: String, msgId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.messages.removeAll { $0.id == msgId }
            self.groupMessages.removeAll { $0.id == msgId }
            // Group: chatKey IS the conversation_id (group_id == conv_id
            // in v3 by design).  Direct: walk the peer→conv index.
            let convId: String? = self.groups[chatKey] != nil
                ? chatKey
                : self.directConversationIdByPeer[chatKey]
            if let convId {
                self.dbDeleteMessage(conversationId: convId, msgId: msgId)
            }
        }
    }

    /// Wipe local message history for a chat without touching the
    /// contacts roster.  Works for both 1:1 peers and groups — pass
    /// the peerIdB64u for a direct chat or the groupId for a group.
    /// Also wipes the file_transfers rows for this chat so the strip
    /// cards disappear; the actual files at savedPath stay on disk.
    ///
    /// The contact row in the AppDataStore is untouched — nickname,
    /// avatar, and (for groups) member roster all survive.  If the
    /// peer or group messages again, the chat re-materializes with
    /// its prior identity intact.  Use `removeContact` / `leaveGroup`
    /// separately to drop the address-book / membership side.
    ///
    /// v3: this calls `dbDeleteConversation` which CASCADEs through
    /// messages + members + group_* state — we don't have to wipe
    /// each table individually.
    func deleteChat(peerId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }

            // 1:1 bucket.
            self.messages.removeAll { $0.from == peerId || $0.to == peerId }

            // Group bucket (the `peerId` arg doubles as a groupId for
            // group-chat call sites).  Safe to run both branches: the
            // keys don't overlap — groupIds are UUIDs, peer IDs are
            // 43-char base64url.  v3 stores groups in `conversations`
            // (kind='group'), and dropping the conversation cascades
            // into messages/members/group_* automatically.
            let wasGroup = self.groups[peerId] != nil
            self.groupMessages.removeAll { $0.groupId == peerId }
            self.groups.removeValue(forKey: peerId)
            self.groupAvatars.removeValue(forKey: peerId)

            // In-memory transfer cards for this chat also go away.
            // (We don't touch the on-disk files at savedPath — only
            // the bookkeeping row + UI card.)
            let toRemove = self.transfers.filter { $0.value.peerId == peerId }.keys
            for tid in toRemove {
                self.transfers.removeValue(forKey: tid)
            }

            // Resolve the conversation id and cascade-delete it.
            // Group: chatKey == group_id == conv_id (v3 invariant).
            // Direct: lookup via the peer→conv index.  No cached row
            // means there's nothing to delete on disk — the @Published
            // wipe above is the whole effect.
            let convId: String? = wasGroup
                ? peerId
                : self.directConversationIdByPeer[peerId]
            if let convId {
                self.dbDeleteConversation(id: convId)
            }
            // file_transfers is keyed by chatKey (peerId or groupId),
            // independent of the conversations cascade — explicit wipe.
            self.dbDeleteFileRecordsForChat(chatKey: peerId)

            // Drop the peer→conv mapping so the next message restarts
            // with a fresh row (the user explicitly cleared this chat).
            if !wasGroup {
                self.directConversationIdByPeer.removeValue(forKey: peerId)
            }
        }
    }

    /// Peers the user has blocked.  Inbound 1:1 messages and file
    /// requests from these peers are dropped on arrival; outbound
    /// sends are refused by `sendText` / `sendFile`.  Purely a
    /// client-side filter (the relay still delivers the envelope —
    /// we just never surface it).  Mirrors the desktop's
    /// `ChatData.isBlocked` bit.
    @Published var blockedPeerIds: Set<String> = []

    /// "Hide Alerts" membership set — peers and groups whose inbound
    /// messages should not fire a local notification.  Persisted as
    /// the `muted` column on the contacts table; loaded on unlock.
    @Published var mutedPeerIds: Set<String> = []

    /// Direct conversations the user archived from `ConversationDetailView`'s
    /// "Hide from Chat List" toggle.  Mirrors `conversations.in_chat_list = 0`
    /// for direct rows — populated on load from the DB and updated by
    /// the toggle's write path.  Read-side: views can filter
    /// `chatPeerIds` against this set when archive should hide rows.
    @Published var archivedDirectPeerIds: Set<String> = []

    /// Set by any view that wants the root `ChatListView` nav stack to
    /// open a specific 1:1 chat — e.g. "Send Message" on a contact
    /// detail reached from the contacts sheet or a group member row.
    /// ChatListView observes this via `.navigationDestination(item:)`
    /// and pushes a `ConversationView` when it goes non-nil.  The
    /// destination handler zeroes it out so the same peer can be
    /// routed to again later.
    @Published var pendingDirectChatPeerId: String?

    /// Chats with at least one unread inbound message.  Keyed by the
    /// same id a ConversationView is loaded with (peer ID for 1:1,
    /// group ID for groups).  Session-only for now — cleared on
    /// `lock()` and re-populated by inbound callbacks.  The chat list
    /// renders a blue dot for any peer/group in this set.
    @Published var unreadChatIds: Set<String> = []

    /// Messages whose send exhausted the relay's retry loop
    /// (~30–60s of attempts on the 1→2→4→8→16s backoff schedule).
    /// Keyed by P2PMessage.id — same UUID we hand to
    /// p2p_send_text_v2, which the C++ retry-give-up path hands
    /// back via the on_send_failed C callback.
    ///
    /// Session-only — cleared on `lock()` (the message itself is
    /// still in the DB, just without the failure marker after a
    /// relaunch).  Persistence would need a `messages.send_failed`
    /// column; tracked as future work in
    /// project_ios_notification_polish.md alongside the other
    /// per-message UX items.
    @Published var failedMessageIds: Set<String> = []

    /// Mark the chat (1:1 or group) as read.  Used when the user
    /// deletes / leaves a thread — the more common
    /// "user-is-viewing" case goes through `enterChat(id:)` below
    /// so the active id is tracked alongside the marker clear.
    func markChatRead(chatKey: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if self.unreadChatIds.contains(chatKey) {
                self.unreadChatIds.remove(chatKey)
            }
        }
    }

    /// The chat the user is currently viewing (peer ID for 1:1,
    /// group ID for groups), or nil when they're on the chat list
    /// / a settings sheet / anywhere not chat-specific.  Inbound
    /// messages addressed to this id skip the unread-marker insert
    /// in the message callbacks — the user is already watching the
    /// message land.  Set/cleared by ConversationView's onAppear /
    /// onDisappear.
    @Published var activeChatId: String? = nil

    /// User opened a chat thread.  Clears any existing unread dot
    /// AND tracks the active id so subsequent inbound messages
    /// don't re-flag the thread while it's on screen.  Replaces
    /// the bare `markChatRead` call at the onAppear callsites.
    func enterChat(id: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.activeChatId = id
            if self.unreadChatIds.contains(id) {
                self.unreadChatIds.remove(id)
            }
        }
    }

    /// User backed out of a chat thread.  Only clears
    /// `activeChatId` if it still matches the leaving id — guards
    /// against the iOS quirk where a sibling view's onAppear can
    /// fire before the leaving view's onDisappear under certain
    /// pop / present orderings, which would otherwise null out the
    /// freshly-set active id.
    func exitChat(id: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.activeChatId == id else { return }
            self.activeChatId = nil
        }
    }

    /// True when `peerId` (either a 1:1 peer or a group) has alerts
    /// silenced.  Reads the in-memory set so SwiftUI views re-render
    /// reactively.
    func isMuted(peerId: String) -> Bool {
        mutedPeerIds.contains(peerId)
    }

    /// Flip the mute flag for a chat (1:1 peerId or groupId).  Writes
    /// the single-column DB update immediately so the state survives
    /// lock/unlock and relaunch.  Safe to call on the main thread.
    ///
    /// v3 split: groups live in conversations and use the per-thread
    /// mute column; 1:1s flip the contact-level mute (cross-conversation,
    /// silences the same person in groups too).
    func setMuted(peerId: String, muted: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if muted { self.mutedPeerIds.insert(peerId) }
            else     { self.mutedPeerIds.remove(peerId) }
            if self.groups[peerId] != nil {
                // Groups: per-conversation mute (peerId == group_id == conv_id).
                self.dbSetConversationMuted(id: peerId, muted: muted)
            } else {
                // Direct: person-level mute on the contact row.
                self.dbSetContactMuted(peerId: peerId, muted: muted)
            }
        }
    }

    /// Per-thread mute for a 1:1 conversation.  Distinct from
    /// `setMuted(peerId:)`, which writes the contact-row (person-level)
    /// flag.  Used by `ConversationDetailView` so the user can silence
    /// notifications for a single thread without touching the
    /// address-book entry.  Resolves the conversation_id via
    /// `directConversationIdByPeer` and writes `conversations.muted`.
    /// `mutedPeerIds` aggregates both flags so the in-memory check
    /// (`isMuted`) stays a single set lookup.
    func setConversationMuted(peerId: String, muted: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if muted { self.mutedPeerIds.insert(peerId) }
            else     { self.mutedPeerIds.remove(peerId) }
            if let convId = self.directConversationIdByPeer[peerId] {
                self.dbSetConversationMuted(id: convId, muted: muted)
            }
        }
    }

    /// Toggle block state for a peer.  `blocked == true` adds to the
    /// set; `blocked == false` removes.  Persisted as a contact-row
    /// flag so blocks survive relaunch.  Block is a person-level
    /// concept (always touches the contacts table, never a
    /// conversation row).
    func setBlocked(peerId: String, blocked: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            // Block lives in its own `blocked_keys` table (Phase 3h),
            // separate from `contacts`.  We do NOT touch the address
            // book here — a stranger stays a stranger after block, a
            // curated contact keeps their nickname / avatar.  The
            // @Published set is the runtime mirror; persistence and
            // launch hydration go through the new dedicated bridges.
            if blocked {
                self.blockedPeerIds.insert(peerId)
                self.dbAddBlockedKey(peerId: peerId)
            } else {
                self.blockedPeerIds.remove(peerId)
                self.dbRemoveBlockedKey(peerId: peerId)
            }
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
    ///
    /// v3: setting a nickname promotes the peer into the address book
    /// (an explicit "this is a person I know" signal).  Clearing the
    /// nickname leaves them in the address book — call `removeContact`
    /// to drop the row entirely.
    func setNickname(peerId: String, nickname: String) {
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if trimmed.isEmpty {
                self.contactNicknames.removeValue(forKey: peerId)
            } else {
                self.contactNicknames[peerId] = trimmed
                // Setting a nickname is a strong "this person is now
                // in my address book" signal — promote stranger
                // conversations into the contacts table so the peer
                // also surfaces in ContactsListView, not just the
                // thread they came from.
                self.knownPeerContacts.insert(peerId)
            }
            self.dbSaveContact(DBContact(
                peerId: peerId,
                name:   trimmed,
                muted:  self.mutedPeerIds.contains(peerId)))
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

    // v2 multi-WS pool.  Each connection (primary + each
    // addSubscribeRelay) is its own WebSocketAdapter; the pool maps
    // C-side conn_handle pointers to Swift adapters.
    private var wsPool: WebSocketPool!
    private var http: HttpAdapter!

    // MARK: - Lifecycle

    init() {
        wsPool = WebSocketPool(client: self)
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
        // Device-lock-while-foregrounded coverage.  iOS does NOT
        // fire didEnterBackground when the user locks the device
        // with our app on screen — the app stays foregrounded but
        // inactive.  Without this hook the autoLockMinutes timer
        // would never start, plaintext lingers in memory.  Pairs
        // with the .complete file-protection class we set in
        // privacy-hardening #4: that class is what makes iOS post
        // these notifications at lock/unlock boundaries.
        protectedDataWillUnavailObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            // Mirror didEnterBackground's effect.  Only stamp if
            // not already set — if the app was ALREADY in
            // background (timer already running), keep the older
            // timestamp so we don't reset the elapsed clock on
            // every device re-lock.
            if self.backgroundedAt == nil {
                _ = self.consumeUnlockPassphrase()
                self.backgroundedAt = Date()
            }
            // "Immediately" (autoLockMinutes == 0) wants the lock
            // to fire BEFORE the device unlocks, so the user
            // never sees the unlocked app peek through after a
            // device unlock.  Other thresholds (5, 15, 60, etc.)
            // wait for the unlock-and-foreground path to evaluate
            // elapsed time.
            if self.autoLockMinutes == 0 {
                self.maybeAutoLock()
            }
        }
        protectedDataDidAvailObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            // Device unlock.  If the app was foregrounded the
            // whole time, willEnterForeground will NOT fire
            // (the app didn't enter background) — so we evaluate
            // auto-lock here.  If the app WAS backgrounded,
            // willEnterForeground also fires; maybeAutoLock is
            // idempotent past the first call (clears
            // backgroundedAt to nil, second call early-returns).
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
        if let protectedDataWillUnavailObserver {
            NotificationCenter.default.removeObserver(protectedDataWillUnavailObserver)
        }
        if let protectedDataDidAvailObserver {
            NotificationCenter.default.removeObserver(protectedDataDidAvailObserver)
        }
        stop()
    }

    private var backgroundObserver: NSObjectProtocol?
    private var foregroundObserver: NSObjectProtocol?
    private var protectedDataWillUnavailObserver: NSObjectProtocol?
    private var protectedDataDidAvailObserver: NSObjectProtocol?

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
    ///
    /// `surfaceFailedAttemptsAlert` controls whether the
    /// `dataWipedNotice` flag is set, which fires the "Too many
    /// failed unlock attempts" alert in OnboardingView.  Default
    /// `true` matches the auto-wipe path (12-strike) where the user
    /// genuinely needs to be told why their data is gone.  Pass
    /// `false` from explicit factory-reset flows (Settings →
    /// Erase Identity & All Data) — the user just tapped the button,
    /// they don't need an alert telling them what they did.
    func wipeAllData(documentDir: String,
                      surfaceFailedAttemptsAlert: Bool = true) {
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
            if surfaceFailedAttemptsAlert {
                self.dataWipedNotice = true
            }
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

        // v2 multi-connection WebSocket callbacks.  Each connection
        // (primary + each addSubscribeRelay-spawned slave) is its own
        // WebSocketAdapter; the pool maps conn_handle pointers to
        // adapters.  When wired, the C++ core uses MultiCWebSocketFactory
        // and addSubscribeRelay() works end-to-end.
        platform.ws_alloc_connection = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return nil }
            return UnsafeMutableRawPointer(client.wsPool.allocate())
        }
        platform.ws_free_connection = { handle, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle else { return }
            client.wsPool.free(handle)
        }
        // v2 per-connection callbacks: each receives the conn_handle
        // (returned from ws_alloc_connection) plus platform_ctx (the
        // Peer2PearClient).  We look up the adapter via the pool —
        // safe against late callbacks that arrive after free()
        // because find() returns nil for unknown handles.
        platform.ws_open_v2 = { handle, urlCStr, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle, let urlCStr,
                  let url = URL(string: String(cString: urlCStr)) else { return }
            client.wsPool.find(handle)?.open(url: url)
        }
        platform.ws_close_v2 = { handle, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle else { return }
            client.wsPool.find(handle)?.close()
        }
        platform.ws_send_text_v2 = { handle, msgCStr, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle, let msgCStr else { return }
            client.wsPool.find(handle)?.sendText(String(cString: msgCStr))
        }
        platform.ws_is_connected_v2 = { handle, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle else { return 0 }
            return (client.wsPool.find(handle)?.isConnected ?? false) ? 1 : 0
        }
        platform.ws_is_idle_v2 = { handle, ctx in
            guard let client = Peer2PearClient.from(ctx),
                  let handle = handle else { return 1 }
            return (client.wsPool.find(handle)?.isIdle ?? true) ? 1 : 0
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

        // Privacy hardening: elevate every file in the data
        // directory to NSFileProtectionComplete.  iOS' default for
        // app sandbox files is
        // `NSFileProtectionCompleteUntilFirstUserAuthentication` —
        // the storage class key stays resident across lock cycles
        // after the first post-boot unlock, so a forensic image of
        // a still-warm device can read the on-disk ciphertext.
        // `.complete` drops the key on every device-lock event,
        // closing that gap.
        //
        // Trade-off: silent-push handlers can't read the DB while
        // the device is locked → notifications for messages
        // received during a locked session don't surface in
        // real-time, they materialize on next unlock.  The DB is
        // already encrypted with SQLCipher + Argon2id over the
        // user's passphrase — this is a defense-in-depth layer
        // that costs some push-UX freshness in exchange for
        // forensic-resistance on stolen devices.  See
        // project_ios_privacy_hardening.md #4 for the full
        // rationale.
        applyDataProtection(toDirectory: dataDir)

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
        // Apply the slider preset first, then re-push the explicit
        // transport toggles so a user who has overridden parallel
        // fan-out / multi-hop independently of the slider keeps that
        // override across relaunches.
        setPrivacyLevel(privacyLevel.rawValue)
        setParallelFanOut(parallelFanOutEnabled)
        setParallelFanOutK(parallelFanOutK)
        setMultiHopEnabled(multiHopEnabled)
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
            // Also subscribe to the backup so the recipient mailbox is
            // replicated end-to-end: sender posts to all relays via
            // parallel fan-out, receiver listens on all of them via
            // multi-WS subscribe, dedup catches duplicates.
            addSubscribeRelay(url: backup)
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
        // Drop every WebSocket the pool was holding — the C core is
        // gone, so its ws_free_connection callbacks have already
        // fired for each (in p2p_destroy).  reset() is defensive in
        // case any straggler escaped that path.
        wsPool.reset()
        isConnected = false
    }

    /// Tear down the unlocked session and bounce back to OnboardingView.
    /// Drops the rawContext (which evicts the dbKey + ratchet state from
    /// memory), wipes the cached passphrase, and clears the @Published
    /// surface so SwiftUI swaps to the unlock screen via the
    /// `client.myPeerId.isEmpty` state-machine guard at the app root.
    /// On the next unlock, `loadStateFromDb()` repopulates from the
    /// SQLCipher AppDataStore so contacts/messages/etc. survive the lock.
    ///
    /// Privacy invariant (project_ios_privacy_hardening.md #5):
    /// EVERY @Published mirror that holds plaintext-derived data
    /// (message bodies, peer IDs, contact names, file paths,
    /// presence, key fingerprints, conversation gap state) MUST be
    /// reset here.  When this list drifts vs. the @Published
    /// declarations above, plaintext stays resident across an
    /// auto-lock — undoing the memory-bounding the lock is
    /// supposed to provide.  Settings-shaped @Published fields
    /// (autoLockMinutes, fileHardMaxMB, privacyLevel, colorScheme,
    /// backupRelayUrls, etc.) are intentionally NOT cleared —
    /// they're durable preferences, not session state.
    func lock() {
        _ = consumeUnlockPassphrase()  // belt-and-braces — also wiped on background
        stop()
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.myPeerId          = ""
            self.statusMessage     = ""
            // Toast string can carry "Couldn't deliver message to
            // <prefix>…" — short-lived but still session content.
            self.toastMessage      = nil
            self.messages          = []
            self.groupMessages     = []
            self.groups            = [:]
            self.groupAvatars      = [:]
            // Group v2 chain-state surface — counter ranges and
            // per-(group,sender) pairings.  Not plaintext message
            // bodies, but it does trace the user's group activity.
            self.groupBlockedStreams        = [:]
            self.groupLostMessages          = []
            self.knownPeerContacts          = []
            self.contactNicknames           = [:]
            self.blockedPeerIds             = []
            self.mutedPeerIds               = []
            self.archivedDirectPeerIds      = []
            // Pending nav target carries a peer ID — clear so a
            // post-unlock re-render doesn't auto-navigate into a
            // thread the user didn't reopen this session.
            self.pendingDirectChatPeerId    = nil
            self.unreadChatIds              = []
            self.failedMessageIds           = []
            self.activeChatId               = nil
            self.peerPresence               = [:]
            self.peerAvatars                = [:]
            self.pendingFileRequests        = []
            self.transfers                  = [:]
            self.keyChanges                 = [:]
            self.directConversationIdByPeer = [:]
            // Auto-wipe alert flag.  If a wipe DOES fire, it sets
            // this true after lock() teardown — the OnboardingView
            // alert shows on the next render, not the current one.
            self.dataWipedNotice            = false
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

    /// Three-tier privacy posture preset.  Maps onto the four
    /// orthogonal transport dials (jitter, cover traffic, parallel
    /// fan-out, multi-hop) in the C core's setPrivacyLevel().  Users
    /// who want fine-grained control can also flip the parallelFanOut /
    /// multiHopEnabled toggles directly — they're independent dials
    /// that target different threats:
    ///   parallel fan-out  = redundancy (one relay down ≠ delivery loss)
    ///   multi-hop onion   = anonymity (no relay sees both sender + recipient)
    enum PrivacyLevel: Int, CaseIterable, Identifiable {
        case standard = 0   // envelope padding + sealed sender + E2EE
        case enhanced = 1   // + jitter + cover traffic + parallel fan-out (all relays)
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
            // Sync the independent toggle state so the slider and the
            // advanced toggles stay coherent.  Each assignment fires
            // its own didSet which re-pushes to the core — harmless,
            // since setPrivacyLevel already configured the same values
            // in the same call.
            switch privacyLevel {
            case .standard:
                parallelFanOutEnabled = false
                multiHopEnabled       = false
            case .enhanced:
                parallelFanOutEnabled = true
                multiHopEnabled       = false
            case .maximum:
                parallelFanOutEnabled = true
                multiHopEnabled       = true
            }
        }
    }

    // MARK: - Independent transport dials
    //
    // These are settable orthogonally to privacyLevel — flipping
    // either toggle here applies on top of (and overrides) whatever
    // the preset configured.  Persisted in UserDefaults so the user's
    // explicit choice survives relaunches even if they later move the
    // privacy slider.

    static let kParallelFanOutKey  = "p2p.parallelFanOutEnabled"
    static let kParallelFanOutKKey = "p2p.parallelFanOutK"
    static let kMultiHopKey        = "p2p.multiHopEnabled"

    /// Send each outbound message envelope to multiple configured
    /// relays simultaneously.  File chunks are exempt (handled in
    /// core).  Improves reliability — does not improve anonymity.
    @Published var parallelFanOutEnabled: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kParallelFanOutKey) {
        didSet {
            UserDefaults.standard.set(parallelFanOutEnabled,
                                       forKey: Self.kParallelFanOutKey)
            setParallelFanOut(parallelFanOutEnabled)
        }
    }

    /// 0 = all configured send relays.  K > 0 picks K random relays
    /// per send.  Ignored when parallelFanOutEnabled is false.
    @Published var parallelFanOutK: Int = {
        let raw = UserDefaults.standard.object(
            forKey: Peer2PearClient.kParallelFanOutKKey) as? Int
        return raw ?? 0
    }() {
        didSet {
            UserDefaults.standard.set(parallelFanOutK,
                                       forKey: Self.kParallelFanOutKKey)
            setParallelFanOutK(parallelFanOutK)
        }
    }

    /// Onion-route each envelope through a chain of relays.  No
    /// single relay sees both sender and recipient.  Improves
    /// anonymity — does not improve reliability.  Adds latency
    /// per hop.  Wins over parallel fan-out in the dispatch path.
    @Published var multiHopEnabled: Bool =
        UserDefaults.standard.bool(forKey: Peer2PearClient.kMultiHopKey) {
        didSet {
            UserDefaults.standard.set(multiHopEnabled,
                                       forKey: Self.kMultiHopKey)
            setMultiHopEnabled(multiHopEnabled)
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

    // MARK: - Migration sentinel
    //
    // Post-migration courtesy: tell every contact + group "I moved
    // devices" using the OLD device's still-aligned ratchets.
    // Buys us "user got pre-warned" — when the new device next
    // sends to each peer, the safety-number-changed alarm fires
    // anyway (we strip ratchet state on migrate by design), but
    // recipients have context for it.
    //
    // Sender-side ONLY (this is the user's own outgoing message
    // from the device they're leaving).  Opt-in: TransferSendView
    // exposes a "Tell my contacts I moved" button on the post-
    // success screen; this isn't auto-fired, since "I moved"
    // isn't always the user's mental model (re-setup, testing,
    // etc.).
    //
    // Returns the total count of envelopes scheduled — UI surfaces
    // it as "Sent to N contacts and M groups."  Each send is async
    // at the protocol layer; failures (no session, etc.) are
    // surfaced via the existing onStatus / failed-message path,
    // not here.

    /// Sentinel text — kept short + tone-neutral.  Recipients
    /// see it as a normal message in their thread; pairs well
    /// with the "safety number changed" UI that fires on the
    /// next ratchet rebuild.
    static let kMigrationSentinelDmText =
        "📱 I just switched devices.  My safety number with you will change — feel free to verify out of band if you want to confirm it's me."

    static let kMigrationSentinelGroupText =
        "📱 I just switched devices.  My safety number in this group will change — verify next time we chat."

    /// Send the migration-sentinel message to every known
    /// contact (1:1 DM) and every group the user is in.  Caller
    /// gets back the count actually scheduled so UI can show
    /// honest feedback.  Idempotent at the protocol layer (each
    /// send mints a new msgId), so calling twice is wasteful but
    /// not broken — UI gates against repeat taps via @State.
    @discardableResult
    func sendMigrationSentinel() -> (contacts: Int, groups: Int) {
        var contactCount = 0
        for peerId in knownPeerContacts {
            // Skip blocked contacts — sending "I moved" to
            // someone you've blocked is a footgun.
            if isBlocked(peerId: peerId) { continue }
            sendText(to: peerId, text: Self.kMigrationSentinelDmText)
            contactCount += 1
        }

        var groupCount = 0
        for (gid, group) in groups {
            sendGroupText(groupId: gid,
                           groupName: group.name,
                           memberPeerIds: group.memberIds,
                           text: Self.kMigrationSentinelGroupText)
            groupCount += 1
        }

        return (contactCount, groupCount)
    }

    static let kNotificationModeKey = "p2p.notificationContentMode"

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
        //
        // The id we mint here is also what we hand to
        // p2p_send_text_v2 so the protocol envelope shares the
        // bubble's id — that's the round-trip the on_send_failed
        // callback needs to mark THIS bubble specifically when its
        // retry loop exhausts.
        let echo = P2PMessage(
            id: UUID().uuidString,
            from: myPeerId,
            text: text,
            timestamp: Date(),
            to: peerId)
        // Resolve / mint the conversation_id eagerly so the dispatch
        // below has a concrete id to write against.  Calls into the
        // C API but doesn't touch any UI state — safe outside the
        // main-queue async block.
        let convId = ensureDirectConversationId(for: peerId)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.messages.append(echo)
            // The conversation row is guaranteed to exist after
            // ensureDirectConversationId — saveMessage requires it.
            // Outbound: senderId == "" by convention (caller is self).
            if let convId {
                self.dbSaveMessage(conversationId: convId, message: DBMessage(
                    sent:          true,
                    text:          echo.text,
                    timestampSecs: Int64(echo.timestamp.timeIntervalSince1970),
                    msgId:         echo.id,
                    senderId:      "",
                    senderName:    ""))
            }
        }
        p2p_send_text_v2(ctx, peerId, text, echo.id)
    }

    /// Retry a previously-failed send.  Removes the old failed
    /// bubble (memory + DB) and re-sends with a fresh msgId — the
    /// new bubble appears at the bottom of the thread in
    /// "sending" state.  Cleaner UX than leaving the old failed
    /// bubble in place and silently appending a duplicate; matches
    /// iMessage's "tap to retry" behaviour where the failed
    /// bubble is replaced by the new attempt.
    func retryFailedMessage(messageId: String, peerId: String, text: String) {
        // Drop the failure marker first so the icon disappears
        // even if the retry's bubble lands a frame later.
        if failedMessageIds.contains(messageId) {
            failedMessageIds.remove(messageId)
        }
        // Remove the old bubble from memory + DB.  The
        // conversation row stays (other messages still belong to
        // it); we just delete this one message by id.
        deleteMessage(chatKey: peerId, msgId: messageId)
        // Fresh send — generates a new bubble + new msgId via the
        // normal sendText path.
        sendText(to: peerId, text: text)
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

    func setParallelFanOut(_ enabled: Bool) {
        guard let ctx = rawContext else { return }
        p2p_set_parallel_fan_out(ctx, enabled ? 1 : 0)
    }

    func setParallelFanOutK(_ k: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_parallel_fan_out_k(ctx, Int32(k))
    }

    func setMultiHopEnabled(_ enabled: Bool) {
        guard let ctx = rawContext else { return }
        p2p_set_multi_hop_enabled(ctx, enabled ? 1 : 0)
    }

    /// Append a relay URL to the core's send pool for multi-hop
    /// forwarding.  Safe to call before start() — becomes a no-op when
    /// rawContext is nil, and the persisted list is replayed on every
    /// start() anyway.  Deduplication happens in the core.
    func addSendRelay(url: String) {
        guard let ctx = rawContext else { return }
        p2p_add_send_relay(ctx, url)
    }

    /// Add an additional relay URL to the receive-side subscribe pool.
    /// Spawns a parallel WebSocket connection so the recipient mailbox
    /// is replicated across multiple relays.  Pairs with parallel
    /// send fan-out for end-to-end redundancy.
    ///
    /// Requires the platform layer to expose the multi-connection FFI
    /// (ws_alloc_connection et al).  The core silently skips with a
    /// warning when the platform is single-connection only.
    func addSubscribeRelay(url: String) {
        guard let ctx = rawContext else { return }
        p2p_add_subscribe_relay(ctx, url)
    }

    /// Drop every extra subscribe relay; the primary stays connected.
    func clearSubscribeRelays() {
        guard let ctx = rawContext else { return }
        p2p_clear_subscribe_relays(ctx)
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
