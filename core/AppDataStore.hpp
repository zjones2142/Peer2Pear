#pragma once

#include "types.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "SqlCipherDb.hpp"

/*
 * AppDataStore — persistent app-data layer on the core's SQLCipher DB.
 *
 * Owns the contacts / messages / settings / group_seq_counters /
 * file_transfers tables.  Sits side-by-side with SessionStore on the
 * same `peer2pear.db` so there's one passphrase, one backup file, one
 * encryption story across desktop and mobile.
 *
 * Page-level encryption comes from SQLCipher (key supplied to
 * SqlCipherDb::open).  Per-field XChaCha20-Poly1305 layered on top via
 * setEncryptionKey() — defense-in-depth so a memory dump that leaks
 * the page key alone still doesn't reveal message bodies.
 *
 * Stored encrypted: messages.text, messages.sender_name, contacts.name,
 * contacts.subtitle, contacts.keys, contacts.avatar, file_transfers.file_name,
 * file_transfers.peer_name, file_transfers.saved_path.
 *
 * Stored plaintext: peer_id (PK lookup), timestamps, counters,
 * settings.value (callers encrypt sensitive settings themselves).
 *
 * Thread-safety: not internally synchronised.  Callers must serialise
 * access — typical pattern is "call from the controller thread".
 *
 * Mirrors the desktop DatabaseManager API (1:1 method names) so the
 * desktop facade can delegate field-by-field without behavioural drift.
 */
class AppDataStore {
public:

    AppDataStore() = default;
    ~AppDataStore();

    AppDataStore(const AppDataStore&) = delete;
    AppDataStore& operator=(const AppDataStore&) = delete;

    /// Bind to an opened SqlCipherDb and create app-data tables if missing.
    /// Safe to call repeatedly — CREATE TABLE IF NOT EXISTS + ALTER TABLE
    /// guards make it idempotent.
    bool bind(SqlCipherDb& db);

    /// Set the per-field encryption key (32 bytes for XChaCha20-Poly1305).
    /// `legacyKeys` are tried in order when the primary key fails to
    /// decrypt an "ENC:" field — supports multi-generation key rotation.
    /// Empty key disables per-field encryption (plaintext storage).
    void setEncryptionKey(const Bytes& key32,
                          const std::vector<Bytes>& legacyKeys = {});

    // ── Contacts ──────────────────────────────────────────────────────────
    //
    // Address book rows.  User-curated only — first inbound message
    // from a stranger creates a CONVERSATION (see below), never a
    // contact.  No is_group / group_id / keys list — those concerns
    // moved to `conversations` and `conversation_members`.
    //
    // `muted` is the person-level mute, OR'd with the matching
    // conversation's `muted` flag at notification time.  Muting Alice
    // here silences her messages everywhere (1:1 and groups).

    struct Contact {
        std::string  peerIdB64u;     // PK; Ed25519 base64url public key
        std::string  name;
        std::string  subtitle;
        std::string  avatarB64;
        bool         muted          = false;
        int64_t      lastActiveSecs = 0;   // 0 = never
        // Block state lives in `blocked_keys` (Phase 3h), keyed by
        // peer_id but independent of contact-row existence.  Use
        // isBlockedKey()/addBlockedKey()/removeBlockedKey() — never
        // store block on the address-book row.
    };

    bool saveContact(const Contact& c);

    /// Remove the address-book entry only.  Conversations and messages
    /// involving this peer are NOT touched — chat history is the
    /// user's data, separate from address-book curation.  To wipe a
    /// chat thread use `deleteConversation`.
    bool deleteContact(const std::string& peerIdB64u);

    /// Flip the mute flag on a single contact row without rewriting
    /// the rest of the record.  Cheap per-field UPDATE so the UI
    /// toggle doesn't have to round-trip the whole Contact struct.
    bool setContactMuted(const std::string& peerIdB64u, bool muted);

    /// Stream every contact via callback in last_active DESC order.
    /// Streaming (not batching) keeps memory flat for large rosters and
    /// matches the C-API consumer pattern (one callback per row).
    void loadAllContacts(const std::function<void(const Contact&)>& cb) const;

    /// Load a single contact by peer ID.  Returns true and populates
    /// `out` when the row exists; false otherwise (leaves `out`
    /// untouched).  A peer with no contact row is just "not in your
    /// address book yet" — they may still appear in conversations.
    bool loadContact(const std::string& peerIdB64u, Contact& out) const;

    /// Serialize the address book to the v1 wire format used by
    /// desktop's "Export Contacts" + iOS's share sheet.  Blocked rows
    /// are omitted.  Format:
    ///   { "version": 1, "contacts": [ { "name": "...", "keys": [...] } ] }
    std::string exportContactsJson() const;

    /// Merge contacts from a v1 JSON blob.  Existing rows (keyed by
    /// peerIdB64u) are never overwritten.  Returns the number of rows
    /// inserted, or -1 on parse error.
    int importContactsJson(const std::string& json);

    bool  saveContactAvatar(const std::string& peerIdB64u, const std::string& avatarB64);
    bool  saveContactKemPub(const std::string& peerIdB64u, const Bytes& kemPub);
    Bytes loadContactKemPub(const std::string& peerIdB64u) const;

    // ── Conversations ─────────────────────────────────────────────────────
    //
    // Chat threads.  One row per direct (1:1) or group conversation.
    // `id` is always a fresh UUID — for a 1:1 chat it does NOT equal
    // the peer's peer_id; lookup goes through `directPeerId` which is
    // partial-UNIQUE-indexed.  Groups have NULL directPeerId; their
    // members live in `conversation_members`.
    //
    // `groupName` and `groupAvatar` are field-encrypted at rest with
    // AAD = "conversations|<column>|<id>".

    enum class ConversationKind { Direct, Group };

    struct Conversation {
        std::string       id;             // PK; UUID
        ConversationKind  kind           = ConversationKind::Direct;
        std::string       directPeerId;   // 1:1: peer_id; group: empty
        std::string       groupName;      // group: encrypted name
        std::string       groupAvatarB64; // group: encrypted avatar
        bool              muted          = false;
        int64_t           lastActiveSecs = 0;
        bool              inChatList     = true;
    };

    /// Create or replace a conversation row by id.  Members must be
    /// added separately via `addConversationMember` — saveConversation
    /// only writes the conversations row.
    bool saveConversation(const Conversation& c);

    /// Lookup by id.  False if missing.
    bool loadConversation(const std::string& id, Conversation& out) const;

    /// Stream every conversation in last_active DESC order.
    void loadAllConversations(
        const std::function<void(const Conversation&)>& cb) const;

    /// Find an existing direct conversation for `peerIdB64u`, or mint
    /// a new one + add the peer as the sole member.  Idempotent —
    /// concurrent callers converge on the same row via the partial
    /// UNIQUE index on direct_peer_id.  Returns the conversation id
    /// (empty on DB error).
    std::string findOrCreateDirectConversation(const std::string& peerIdB64u);

    /// Ensure a group conversation row exists with the given id (which
    /// equals the group_id used by every group_* table's FK).  Used
    /// by call sites that touch group_chain_state / group_send_state /
    /// group_replay_cache / group_msg_buffer / group_bundle_map —
    /// these all FK to conversations(id) ON DELETE CASCADE in v3, so
    /// the parent must exist before any child INSERT.  Idempotent;
    /// no-op when a row with that id already exists.
    bool ensureGroupConversation(const std::string& groupId);

    /// Cascade-deletes messages, members, group_* state for this
    /// conversation via the FK ON DELETE CASCADE constraints.
    bool deleteConversation(const std::string& id);

    /// Per-conversation mute (independent of contact-level mute).
    bool setConversationMuted(const std::string& id, bool muted);

    /// Hide / un-hide a conversation from the chat list without
    /// deleting messages.  Useful for "archive" / "leave but don't
    /// delete" UX.
    bool setConversationInChatList(const std::string& id, bool inList);

    /// Bump last_active for a conversation.  Called on every send and
    /// receive; sorting/ordering in the chat list reads this column.
    void touchConversation(const std::string& id, int64_t whenSecs);

    // ── Conversation members ──────────────────────────────────────────────

    /// Add a peer to a conversation (no-op if already a member).
    /// Returns false on DB error or invalid foreign key.
    bool addConversationMember(const std::string& conversationId,
                                 const std::string& peerIdB64u);

    /// Remove a peer from a conversation.  Returns false if no row
    /// matched (idempotent caller can ignore).
    bool removeConversationMember(const std::string& conversationId,
                                    const std::string& peerIdB64u);

    /// Replace the entire membership of a conversation atomically —
    /// callers handing us a fresh roster snapshot don't need to diff.
    bool setConversationMembers(const std::string& conversationId,
                                  const std::vector<std::string>& peerIds);

    /// Stream the peer_ids of every member of a conversation.
    void loadConversationMembers(
        const std::string& conversationId,
        const std::function<void(const std::string&)>& cb) const;

    // ── Blocked keys ──────────────────────────────────────────────────────
    //
    // Phase 3h: block is its own thing, separate from `contacts`.
    // Inbound messages from a peer in this table are silently dropped
    // (the runtime check is in the platform bridge — core just owns
    // the persistence).
    //
    // Independent of address-book curation: a user can simultaneously
    // have a contact entry AND have them blocked, OR be blocked
    // without ever being added to the address book.  Both states are
    // valid and orthogonal.

    /// Add `peerIdB64u` to the blocked list.  Idempotent (re-blocking
    /// is a no-op).  Returns false on DB error or empty input.
    bool addBlockedKey(const std::string& peerIdB64u, int64_t whenSecs);

    /// Remove `peerIdB64u` from the blocked list.  Returns true when
    /// a row was removed, false when the key wasn't blocked.
    bool removeBlockedKey(const std::string& peerIdB64u);

    /// Single-key membership check.  Hot-path-friendly (PK lookup).
    bool isBlockedKey(const std::string& peerIdB64u) const;

    /// Stream every blocked key in insertion order (blocked_at ASC).
    /// Used by the iOS bridge to populate its `blockedPeerIds` set on
    /// launch and by the desktop's "Blocked" picker.
    void loadAllBlockedKeys(
        const std::function<void(const std::string& peerIdB64u,
                                  int64_t blockedAt)>& cb) const;

    // ── Messages ──────────────────────────────────────────────────────────
    //
    // Keyed by `conversationId` (UUID into `conversations.id`), not by
    // peer.  For direct chats the conversation tells us who the other
    // party is; for groups the per-message `senderId` identifies which
    // member sent it.  Outbound messages set senderId = "" (caller is
    // self by definition).

    struct Message {
        bool         sent;
        std::string  text;
        int64_t      timestampSecs;
        std::string  msgId;
        std::string  senderId;       // empty on outbound; peer_id on inbound
        std::string  senderName;     // self-declared name (group inbound only)
    };

    /// Insert a message and bump conversations.last_active in one
    /// transaction.  The conversation row MUST already exist — callers
    /// that handle inbound-from-stranger should call
    /// `findOrCreateDirectConversation` first.
    bool saveMessage(const std::string& conversationId, const Message& m);

    /// Stream every message for `conversationId` in chronological order.
    void loadMessages(const std::string& conversationId,
                      const std::function<void(const Message&)>& cb) const;

    /// Wipe every message for `conversationId`.  Doesn't touch the
    /// conversation row itself — caller decides whether the thread
    /// stays in the chat list.
    bool deleteMessages(const std::string& conversationId);

    /// Delete a single message by (conversationId, msgId).  Used by the
    /// long-press / right-click "Delete Message" UX on both platforms.
    /// Returns true when a row was deleted, false when nothing matched.
    bool deleteMessage(const std::string& conversationId, const std::string& msgId);

    // ── Settings ──────────────────────────────────────────────────────────

    bool        saveSetting(const std::string& key, const std::string& value);
    std::string loadSetting(const std::string& key,
                            const std::string& defaultValue = "") const;

    // ── Group sequence counters (replay protection across restart) ────────

    void saveGroupSeqOut(const std::map<std::string, int64_t>& counters);
    void saveGroupSeqIn (const std::map<std::string, int64_t>& counters);
    std::map<std::string, int64_t> loadGroupSeqOut() const;
    std::map<std::string, int64_t> loadGroupSeqIn () const;

    // ── File transfer records ─────────────────────────────────────────────

    struct FileRecord {
        std::string  transferId;
        std::string  chatKey;        // peer_id or group_id
        std::string  fileName;
        int64_t      fileSize;
        std::string  peerIdB64u;     // counter-party
        std::string  peerName;
        int64_t      timestampSecs;
        bool         sent;
        int          status;
        int          chunksTotal;
        int          chunksComplete;
        std::string  savedPath;
    };

    bool saveFileRecord(const std::string& chatKey, const FileRecord& r);
    bool deleteFileRecord(const std::string& transferId);
    /// Wipe every file_transfers row for a chat key.  Used by
    /// "delete chat" flows so the strip cards disappear alongside the
    /// message bubbles — does NOT touch the actual files at savedPath.
    bool deleteFileRecordsForChat(const std::string& chatKey);
    void loadFileRecords(const std::string& chatKey,
                         const std::function<void(const FileRecord&)>& cb) const;

    // ── Group replay cache (Phase 1, sender side) ────────────────────────
    //
    // After a successful group-message send, the sealed envelope is
    // cached for `kReplayCacheMaxAgeSecs` so a recipient that later
    // reports a gap (gap_request) gets byte-identical replay rather
    // than a fresh DR step (which would advance the chain past their
    // expected counter).  Aligned with the relay mailbox TTL (7d) so
    // replay coverage matches the primary delivery window.
    static constexpr int64_t kReplayCacheMaxAgeSecs = 7LL * 24 * 60 * 60;

    /// Cache a sealed envelope under (recipient, group, session, counter).
    /// `sentAt` is the unix-epoch-secs the cache row was written; on a
    /// later purgeReplayCacheOlderThan, rows older than the cutoff are
    /// dropped.  Returns false on DB error or duplicate primary key.
    bool addReplayCacheEntry(const std::string& peerIdB64u,
                              const std::string& groupId,
                              const Bytes& sessionId,
                              int64_t counter,
                              const Bytes& sealedEnvelope,
                              int64_t sentAt);

    /// Look up a single cached envelope.  Returns empty Bytes on miss.
    Bytes loadReplayCacheEntry(const std::string& peerIdB64u,
                                const std::string& groupId,
                                const Bytes& sessionId,
                                int64_t counter) const;

    /// Stream every cached envelope in [fromCounter, toCounter] for a
    /// (recipient, group, session) tuple, in counter-ascending order.
    /// Used by the gap_request fulfillment path.
    void loadReplayCacheRange(
        const std::string& peerIdB64u,
        const std::string& groupId,
        const Bytes& sessionId,
        int64_t fromCounter, int64_t toCounter,
        const std::function<void(int64_t counter, const Bytes&)>& cb) const;

    /// Drop a single cached envelope (e.g., on positive ack).
    bool dropReplayCacheEntry(const std::string& peerIdB64u,
                               const std::string& groupId,
                               const Bytes& sessionId,
                               int64_t counter);

    /// Sweep rows whose `sent_at` is strictly less than `cutoffSecs`.
    /// Returns the number of rows deleted.  Wired to a periodic timer
    /// that runs `purgeReplayCacheOlderThan(now - kReplayCacheMaxAgeSecs)`.
    int  purgeReplayCacheOlderThan(int64_t cutoffSecs);

    // ── Group chain state (Phase 1, receiver side) ───────────────────────

    /// Per-(group, sender) state machine.  One row per pair; on session
    /// reset the row is updated in place + the buffer for the old
    /// session_id is drained as a "K lost messages" UI event.
    struct ChainState {
        Bytes    sessionId;          // 8 bytes; empty on first row
        int64_t  expectedNext   = 1; // next counter we expect to deliver
        Bytes    lastHash;           // 16 bytes prev_hash, may be empty
        int64_t  blockedSince   = 0; // unix-secs when stream blocked, 0 = active
        int64_t  gapFrom        = 0; // missing range, [from, to] inclusive
        int64_t  gapTo          = 0;
        int64_t  lastRetryAt    = 0;
        int      retryCount     = 0;
    };

    bool loadChainState(const std::string& groupId,
                         const std::string& senderPeerId,
                         ChainState& out) const;

    /// Upsert the chain state row for (groupId, senderPeerId).
    bool saveChainState(const std::string& groupId,
                         const std::string& senderPeerId,
                         const ChainState& state);

    /// Drop the chain-state row (e.g., when leaving the group or the
    /// sender is removed from the roster).
    bool dropChainState(const std::string& groupId,
                         const std::string& senderPeerId);

    // ── Group message buffer (Phase 1, blocked-stream hold) ─────────────

    struct BufferedMessage {
        int64_t      counter;
        Bytes        prevHash;        // 16B; what THIS message claimed as prev
        Bytes        sealedEnvHash;   // 16B; hash of the sealed envelope —
                                       // becomes lastHash when row drains, so
                                       // the chain continues into the next
                                       // delivered message
        std::string  msgId;
        std::string  body;
        std::string  senderName;
        int64_t      receivedAt;
    };

    /// Add a DR-decrypted-but-not-delivered group_msg to the buffer.
    /// `sessionId` matches the chain_state row's session_id; on session
    /// reset, dropBufferForSession sweeps everything tagged with the
    /// old id.  Body + senderName are field-encrypted at rest the same
    /// way `messages.text` is.  `sealedEnvHash` is the 16B hash of the
    /// sealed envelope — receiver-side it's used to continue the
    /// prev_hash chain when the buffered row eventually drains.
    bool addBufferEntry(const std::string& groupId,
                         const std::string& senderPeerId,
                         const Bytes& sessionId,
                         int64_t counter,
                         const Bytes& prevHash,
                         const Bytes& sealedEnvHash,
                         const std::string& msgId,
                         const std::string& body,
                         const std::string& senderName,
                         int64_t receivedAt);

    /// Stream buffered messages in [fromCounter, toCounter] in counter
    /// order — used to drain into `messages` once the gap fills.
    void loadBufferRange(
        const std::string& groupId,
        const std::string& senderPeerId,
        const Bytes& sessionId,
        int64_t fromCounter, int64_t toCounter,
        const std::function<void(const BufferedMessage&)>& cb) const;

    /// Drop buffered rows in [fromCounter, toCounter].  Returns the
    /// number of rows removed.  Called after successful drain into
    /// the delivered messages table.
    int  dropBufferRange(const std::string& groupId,
                          const std::string& senderPeerId,
                          const Bytes& sessionId,
                          int64_t fromCounter, int64_t toCounter);

    /// Drop every buffered row for an old session_id — used on session
    /// reset to seal off the "K lost messages" cohort before resuming
    /// at the new session's counter=1.  Returns the count for the UI.
    int  dropBufferForSession(const std::string& groupId,
                                const std::string& senderPeerId,
                                const Bytes& sessionId);

    // ── Group send state (Phase 1, sender side) ──────────────────────────
    //
    // Per (recipient, group, session_id) the sender tracks the
    // monotonic counter to use on the next outbound and the
    // 16-byte hash of the most recently sealed envelope (the next
    // message's prev_hash).  Read+update happens once per send;
    // independent of group_replay_cache so the chain advances past
    // the cache's 7-day purge horizon.

    struct SendState {
        int64_t nextCounter = 1;  // counter for the NEXT outbound (1-based)
        Bytes   lastHash;         // 16 bytes; empty for the first send
    };

    /// Load the per-(peer, group, session) send state.  Missing row
    /// returns a default-constructed SendState (nextCounter = 1,
    /// empty lastHash) — the first message of a fresh session.
    /// Always returns true; the bool is reserved for future "DB
    /// failed" signalling without changing the call site.
    bool loadSendState(const std::string& peerIdB64u,
                        const std::string& groupId,
                        const Bytes& sessionId,
                        SendState& out) const;

    /// Upsert the send state.  Called immediately after a successful
    /// seal+cache to pin the new counter/lastHash before the relay
    /// dispatch fires (so a crash between cache and relay doesn't
    /// reuse the counter on retry).
    bool saveSendState(const std::string& peerIdB64u,
                        const std::string& groupId,
                        const Bytes& sessionId,
                        const SendState& state);

    /// Drop the send state for a (peer, group, session) tuple.  Used
    /// when the recipient is removed from the group or the user
    /// leaves the group.
    bool dropSendState(const std::string& peerIdB64u,
                        const std::string& groupId,
                        const Bytes& sessionId);

    // ── Group bundle map (Phase 2, Invisible Groups) ─────────────────────
    //
    // Local groupId ↔ on-the-wire bundle_id (16-byte random) mapping.
    // The bundle_id replaces groupId in transit so the relay sees only
    // an opaque, unlinkable identifier per group.  Members learn each
    // other's bundle_id via inner-payload distribution; receivers drop
    // messages whose bundle_id has no local mapping.
    //
    // Stable per group for Phase 2.0; Phase 2.1 adds rotation.

    /// Look up the bundle_id for a known local group.  Empty Bytes on
    /// miss — caller decides whether to mint one (sender path) or drop
    /// the inbound message (receiver path).
    Bytes bundleIdForGroup(const std::string& groupId) const;

    /// Return the existing bundle_id for `groupId` or generate +
    /// persist a fresh 16-byte UUID-shaped value if none exists.
    /// Idempotent — concurrent callers converge on the same id via
    /// the UNIQUE INDEX on bundle_id.
    Bytes ensureBundleIdForGroup(const std::string& groupId);

    /// Reverse lookup: bundle_id → local groupId.  Empty string on
    /// miss; callers MUST drop the message rather than guessing.
    std::string groupIdForBundle(const Bytes& bundleId) const;

    /// Explicit insert used when a peer's group_member_update tells us
    /// the bundle_id for a group we already know about (e.g., we
    /// joined via invite that predates Phase 2).  Returns false on DB
    /// error or UNIQUE-constraint violation.
    bool addBundleMapping(const std::string& groupId,
                           const Bytes& bundleId,
                           int64_t createdAt);

    /// Drop the mapping when the user leaves / deletes the group.
    bool dropBundleMapping(const std::string& groupId);

private:
    void createTables();
    /// Bump contacts.last_active.  No-op when there's no contact row
    /// (Phase 3 dropped the auto-stub-from-stranger behaviour).
    void touchContact(const std::string& peerIdB64u, int64_t whenSecs);

    // Arch-review #1b: every per-field encrypt MUST supply an AAD
    // that binds the row's logical identity (table, column, row key)
    // so an attacker with SQLCipher write access cannot cross-swap
    // blobs between rows / columns / tables.  Callers use the
    // `fieldAad(...)` helper to build the string consistently.
    std::string encryptField(const std::string& plaintext,
                              const std::string& aad = {}) const;
    std::string decryptField(const std::string& stored,
                              const std::string& aad = {}) const;

    SqlCipherDb*       m_db = nullptr;
    Bytes              m_encKey;       // 32-byte primary key; empty = plaintext
    std::vector<Bytes> m_legacyKeys;   // tried in order on decrypt failure
};
