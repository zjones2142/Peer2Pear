#pragma once

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
 * Stored plaintext: peer_id (PK lookup), is_blocked, is_group, timestamps,
 * counters, settings.value (callers encrypt sensitive settings themselves).
 *
 * Thread-safety: not internally synchronised.  Callers must serialise
 * access — typical pattern is "call from the controller thread".
 *
 * Mirrors the desktop DatabaseManager API (1:1 method names) so the
 * desktop facade can delegate field-by-field without behavioural drift.
 */
class AppDataStore {
public:
    using Bytes = std::vector<uint8_t>;

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

    struct Contact {
        std::string  peerIdB64u;     // PK; for groups this is the groupId
        std::string  name;
        std::string  subtitle;
        std::vector<std::string> keys;
        bool         isBlocked      = false;
        bool         isGroup        = false;
        std::string  groupId;
        std::string  avatarB64;
        int64_t      lastActiveSecs = 0;   // 0 = never
        // iOS chats-vs-contacts split: a stranger's first inbound message
        // auto-creates a contact row so messages.peer_id satisfies its FK,
        // but they only appear in the address-book UI once the user
        // explicitly adds them (taps + New Chat / imports).  Desktop
        // leaves this true — every contact desktop saves IS in the
        // address book by construction.
        bool         inAddressBook  = true;
    };

    bool saveContact(const Contact& c);
    bool deleteContact(const std::string& peerIdB64u);

    /// Stream every contact via callback in last_active DESC order.
    /// Streaming (not batching) keeps memory flat for large rosters and
    /// matches the C-API consumer pattern (one callback per row).
    void loadAllContacts(const std::function<void(const Contact&)>& cb) const;

    bool  saveContactAvatar(const std::string& peerIdB64u, const std::string& avatarB64);
    bool  saveContactKemPub(const std::string& peerIdB64u, const Bytes& kemPub);
    Bytes loadContactKemPub(const std::string& peerIdB64u) const;

    // ── Messages ──────────────────────────────────────────────────────────

    struct Message {
        bool         sent;
        std::string  text;
        int64_t      timestampSecs;
        std::string  msgId;
        std::string  senderName;     // populated for inbound group messages
    };

    /// Insert a message and bump contacts.last_active in one transaction.
    bool saveMessage(const std::string& peerIdB64u, const Message& m);

    /// Stream every message for `peerIdB64u` in chronological order.
    void loadMessages(const std::string& peerIdB64u,
                      const std::function<void(const Message&)>& cb) const;

    /// Wipe every message for `peerIdB64u`.  Doesn't touch the contacts
    /// row — caller decides whether the contact stays in the address book.
    bool deleteMessages(const std::string& peerIdB64u);

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

private:
    void createTables();
    void updateLastActive(const std::string& peerIdB64u);

    std::string encryptField(const std::string& plaintext) const;
    std::string decryptField(const std::string& stored) const;

    SqlCipherDb*       m_db = nullptr;
    Bytes              m_encKey;       // 32-byte primary key; empty = plaintext
    std::vector<Bytes> m_legacyKeys;   // tried in order on decrypt failure
};
