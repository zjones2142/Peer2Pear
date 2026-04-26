#include "AppDataStore.hpp"
#include "shared.hpp"
#include "uuid.hpp"  // p2p::makeUuid for findOrCreateDirectConversation

#include <sodium.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <unordered_set>

// Per-field encryption format: "ENC:" + base64(nonce || ciphertext || tag).
// Anything without the prefix is treated as a legacy plaintext value and
// returned as-is — handles the upgrade path from the desktop's pre-encrypted
// rows.  Mirrors desktop/databasemanager.cpp's kEncPrefix exactly so values
// written by either code path round-trip cleanly.
namespace {
// Per-field ciphertext prefixes.
//   ENC:   — legacy format, no AAD.  Rows written by older builds
//            decrypt through this path.
//   ENC2:  — current format, AAD binds `<table>|<column>|<row-key>`
//            so an attacker with SQLCipher write access cannot swap
//            a blob from e.g. contacts.name into contacts.subtitle
//            without tripping AEAD verification.
constexpr const char* kEncPrefix     = "ENC:";
constexpr size_t      kEncPrefixLen  = 4;
constexpr const char* kEnc2Prefix    = "ENC2:";
constexpr size_t      kEnc2PrefixLen = 5;

// Base64 (no padding, standard alphabet) — small inline helpers so we
// don't pull in a dependency.  libsodium's sodium_bin2base64 is here
// already; use it.
std::string base64Encode(const uint8_t* data, size_t len)
{
    if (len == 0) return {};
    const size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), outLen, data, len, sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

bool base64Decode(const std::string& in, std::vector<uint8_t>& out)
{
    out.assign(in.size(), 0);
    size_t actualLen = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          in.data(), in.size(),
                          nullptr, &actualLen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        out.clear();
        return false;
    }
    out.resize(actualLen);
    return true;
}

// RAII transaction.  Rolls back on destruction unless commit() was called.
// Wraps multi-step writes (saveMessage's INSERT + UPDATE) so a crash
// mid-pair doesn't leave a message without its corresponding last_active
// bump — and so the two queries are one disk-fsync instead of two.
class Tx {
public:
    explicit Tx(sqlite3* db) : m_db(db) {
        if (m_db) sqlite3_exec(m_db, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr);
    }
    ~Tx() {
        if (m_db && !m_committed)
            sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
    bool commit() {
        if (!m_db) return false;
        m_committed = sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK;
        return m_committed;
    }
private:
    sqlite3* m_db = nullptr;
    bool     m_committed = false;
};
} // namespace

AppDataStore::~AppDataStore()
{
    // Zero key material on destruction so a memory dump after shutdown
    // doesn't leak the per-field key.  Mirrors desktop DBM.
    if (!m_encKey.empty())
        sodium_memzero(m_encKey.data(), m_encKey.size());
    for (auto& k : m_legacyKeys) {
        if (!k.empty()) sodium_memzero(k.data(), k.size());
    }
}

bool AppDataStore::bind(SqlCipherDb& db)
{
    if (!db.isOpen()) return false;
    m_db = &db;
    // Enable FK cascade — the desktop DBM declares ON DELETE CASCADE on
    // messages.peer_id but never enables foreign_keys, so the cascade
    // silently no-ops on desktop today.  Bug fix carried into the port.
    sqlite3_exec(m_db->handle(), "PRAGMA foreign_keys = ON;",
                 nullptr, nullptr, nullptr);
    createTables();
    return true;
}

void AppDataStore::setEncryptionKey(const Bytes& key32,
                                    const std::vector<Bytes>& legacyKeys)
{
    if (key32.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        m_encKey = key32;
    m_legacyKeys.clear();
    for (const auto& k : legacyKeys) {
        if (k.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
            m_legacyKeys.push_back(k);
    }
}

// ── Per-field encryption ────────────────────────────────────────────────────

// Build the per-row AAD string for encryptField / decryptField.  Layout
// is `<table>|<column>|<row-key>` — the pipe-delimited form mirrors
// SessionStore::sessionAad / handshakeAad so the two AAD conventions
// look the same at a glance.  Kept internal (no AAD reuse across the
// codebase) because the exact wording is not a wire contract.
static std::string fieldAad(const std::string& table,
                              const std::string& column,
                              const std::string& rowKey) {
    return table + "|" + column + "|" + rowKey;
}

std::string AppDataStore::encryptField(const std::string& plaintext,
                                         const std::string& aad) const
{
    if (m_encKey.empty()) return plaintext;

    const size_t nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const size_t tagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16

    Bytes buf(nonceLen + plaintext.size() + tagLen, 0);
    randombytes_buf(buf.data(), nonceLen);

    unsigned long long ctLen = 0;
    const unsigned char* aadPtr = aad.empty()
        ? nullptr
        : reinterpret_cast<const unsigned char*>(aad.data());
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        buf.data() + nonceLen, &ctLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        aadPtr, aad.size(),
        nullptr,
        buf.data(),
        m_encKey.data());

    buf.resize(nonceLen + ctLen);
    // Always emit the v2 prefix.  Legacy rows written under the v1
    // (no-AAD) path continue to decrypt via decryptField's fallback
    // branch; new writes are AAD-bound.
    return std::string(kEnc2Prefix) + base64Encode(buf.data(), buf.size());
}

std::string AppDataStore::decryptField(const std::string& stored,
                                         const std::string& aad) const
{
    const bool isV2 = stored.compare(0, kEnc2PrefixLen, kEnc2Prefix) == 0;
    const bool isV1 = !isV2 &&
        stored.compare(0, kEncPrefixLen, kEncPrefix) == 0;

    // Legacy plaintext row — no prefix, return verbatim.
    if (!isV1 && !isV2) return stored;

    if (m_encKey.empty() && m_legacyKeys.empty())
        return {}; // no key — never expose ciphertext

    Bytes blob;
    const size_t prefixLen = isV2 ? kEnc2PrefixLen : kEncPrefixLen;
    if (!base64Decode(stored.substr(prefixLen), blob)) return {};

    const size_t nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (blob.size() < nonceLen + tagLen) return {};

    Bytes pt(blob.size() - nonceLen - tagLen, 0);
    unsigned long long ptLen = 0;

    // v2 rows MUST verify under the caller-supplied AAD.  v1 (legacy)
    // rows have no AAD — try with empty AAD only, never cross-use
    // the v2 AAD value.  Cross-version fallback is deliberately
    // NOT supported: that would let an attacker strip the v2 prefix
    // to bypass the AAD binding.
    const std::string aadForRow = isV2 ? aad : std::string{};
    const unsigned char* aadPtr = aadForRow.empty()
        ? nullptr
        : reinterpret_cast<const unsigned char*>(aadForRow.data());

    auto tryKey = [&](const Bytes& key) -> bool {
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &ptLen,
            nullptr,
            blob.data() + nonceLen, blob.size() - nonceLen,
            aadPtr, aadForRow.size(),
            blob.data(),
            key.data()) == 0;
    };

    if (!m_encKey.empty() && tryKey(m_encKey))
        return std::string(reinterpret_cast<const char*>(pt.data()), ptLen);
    for (const auto& k : m_legacyKeys) {
        if (tryKey(k))
            return std::string(reinterpret_cast<const char*>(pt.data()), ptLen);
    }
    return {}; // all keys failed — never expose ciphertext
}

// ── Schema ──────────────────────────────────────────────────────────────────

void AppDataStore::createTables()
{
    SqlCipherQuery q(*m_db);

    // Settings table comes first — we read schema_version from it.
    q.exec(
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL DEFAULT ''"
        ");"
    );

    // ── Schema v3 hard-break gate ────────────────────────────────────────
    //
    // v3 splits contacts (people) from conversations (chat threads) and
    // retargets messages.peer_id → conversations.id.  See the audit /
    // commit message for the full design rationale.  No automatic data
    // migration is provided — pre-v3 DBs have their (now-incompatible)
    // tables dropped and the user starts fresh.  The user explicitly
    // chose this path; if you're reading this with chat history you
    // care about, restore from backup before upgrading.
    bool isV3 = false;
    {
        SqlCipherQuery v(m_db->handle());
        v.prepare("SELECT value FROM settings WHERE key='schema_version';");
        if (v.exec() && v.next()) isV3 = (v.valueText(0) == "3");
    }
    if (!isV3) {
        // Drop every v2-shaped table we're about to recreate in
        // incompatible shape.  Order matters — child tables (with FKs
        // pointing into the dropped parents) come first so we don't
        // hit FK errors mid-drop.  PRAGMA foreign_keys = OFF for the
        // duration so the cascades-on-drop don't fire.
        q.exec("PRAGMA foreign_keys = OFF;");
        q.exec("DROP TABLE IF EXISTS messages;");
        q.exec("DROP TABLE IF EXISTS conversation_members;");
        q.exec("DROP TABLE IF EXISTS conversations;");
        q.exec("DROP TABLE IF EXISTS contacts;");
        q.exec("DROP TABLE IF EXISTS group_replay_cache;");
        q.exec("DROP TABLE IF EXISTS group_chain_state;");
        q.exec("DROP TABLE IF EXISTS group_msg_buffer;");
        q.exec("DROP TABLE IF EXISTS group_send_state;");
        q.exec("DROP TABLE IF EXISTS group_bundle_map;");
        // blocked_keys (Phase 3h) is additive on top of v3 — leave it
        // alone here so a v2→v3 upgrade path doesn't lose block state
        // a user has already curated.  CREATE IF NOT EXISTS below is
        // the only thing that touches it.
        // Preserved across v2→v3: file_transfers (separate refactor),
        // group_seq_counters (legacy SenderChain — dies with that path).
    }
    // FK enforcement on for the rebuild.  SQLite defaults this off
    // per-connection; setting it here keeps the cascade semantics
    // we declare on the v3 tables actually fire.
    q.exec("PRAGMA foreign_keys = ON;");

    // ── contacts ────────────────────────────────────────────────────────
    // Address book.  User-curated only — first message from a stranger
    // creates a conversation row but NOT a contact.  No is_group, no
    // group_id, no embedded keys list: groups live in `conversations`
    // and group rosters in `conversation_members`.
    //
    // `muted` here is the person-level mute (across all conversations
    // they appear in); the per-conversation mute lives on `conversations`.
    // Notification logic ORs the two.
    q.exec(
        "CREATE TABLE IF NOT EXISTS contacts ("
        "  peer_id      TEXT PRIMARY KEY NOT NULL,"
        "  name         TEXT NOT NULL DEFAULT '',"
        "  subtitle     TEXT NOT NULL DEFAULT '',"
        "  avatar       TEXT NOT NULL DEFAULT '',"
        "  kem_pub      BLOB,"
        "  muted        INTEGER NOT NULL DEFAULT 0,"
        "  last_active  INTEGER NOT NULL DEFAULT 0"
        ");"
    );
    // Phase 3h purge: legacy v3 DBs still carry an `is_blocked` column
    // that nothing reads or writes anymore (block moved to the
    // dedicated `blocked_keys` table).  Drop it idempotently — fresh
    // DBs created without the column have nothing to remove and the
    // exec quietly returns false.
    q.exec("ALTER TABLE contacts DROP COLUMN is_blocked;");

    // ── conversations ───────────────────────────────────────────────────
    // Chat threads.  One row per direct (1:1) or group conversation.
    // `id` is always a fresh UUID minted at creation time — distinct
    // from peer_id even for 1:1, so deleting a contact doesn't drop
    // their chat thread (and vice versa).
    //
    // `direct_peer_id` is the denormalised lookup key for 1:1 chats —
    // partial UNIQUE index below enforces "at most one direct
    // conversation per peer" without paying for a join through
    // conversation_members on every send/receive.
    q.exec(
        "CREATE TABLE IF NOT EXISTS conversations ("
        "  id              TEXT PRIMARY KEY NOT NULL,"
        "  kind            TEXT NOT NULL CHECK (kind IN ('direct','group')),"
        "  direct_peer_id  TEXT,"
        "  group_name      TEXT NOT NULL DEFAULT '',"
        "  group_avatar    TEXT NOT NULL DEFAULT '',"
        "  muted           INTEGER NOT NULL DEFAULT 0,"
        "  last_active     INTEGER NOT NULL DEFAULT 0,"
        "  in_chat_list    INTEGER NOT NULL DEFAULT 1"
        ");"
    );
    q.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_direct_peer"
           " ON conversations(direct_peer_id) WHERE direct_peer_id IS NOT NULL;");

    // ── conversation_members ────────────────────────────────────────────
    // Membership of a conversation, excluding self.  Direct conversations
    // have exactly one row (the peer); groups have one row per other
    // member.  Intentionally NO FK to contacts — a peer can be in a
    // conversation without being in our address book (e.g. a group
    // member we've never explicitly added).
    q.exec(
        "CREATE TABLE IF NOT EXISTS conversation_members ("
        "  conversation_id  TEXT NOT NULL,"
        "  peer_id          TEXT NOT NULL,"
        "  PRIMARY KEY (conversation_id, peer_id),"
        "  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );

    // ── messages ────────────────────────────────────────────────────────
    // FK retargeted from contacts(peer_id) to conversations(id).
    // sender_id explicitly identifies who sent the message — for direct
    // chats the conversation tells us who the other party is; for
    // groups we need to know which member sent it.  Outbound: sender_id
    // is empty (caller is self).  Inbound: sender_id is the peer_id of
    // the originator.
    q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id               INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  conversation_id  TEXT NOT NULL,"
        "  sent             INTEGER NOT NULL,"
        "  text             TEXT NOT NULL DEFAULT '',"
        "  timestamp        INTEGER NOT NULL,"
        "  msg_id           TEXT NOT NULL DEFAULT '',"
        "  sender_id        TEXT NOT NULL DEFAULT '',"
        "  sender_name      TEXT NOT NULL DEFAULT '',"
        "  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );
    q.exec("CREATE INDEX IF NOT EXISTS idx_messages_conv_ts"
           " ON messages(conversation_id, timestamp);");

    // group_seq_counters: legacy SenderChain v1 counters.  Untouched
    // by Phase 3 — dies with the SenderChain deletion (deferred).
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_seq_counters ("
        "  seq_key    TEXT NOT NULL,"
        "  direction  INTEGER NOT NULL,"
        "  counter    INTEGER NOT NULL,"
        "  PRIMARY KEY(seq_key, direction)"
        ");"
    );

    q.exec(
        "CREATE TABLE IF NOT EXISTS file_transfers ("
        "  transfer_id      TEXT PRIMARY KEY,"
        "  chat_key         TEXT NOT NULL,"
        "  file_name        TEXT NOT NULL DEFAULT '',"
        "  file_size        INTEGER NOT NULL,"
        "  peer_id          TEXT NOT NULL DEFAULT '',"
        "  peer_name        TEXT NOT NULL DEFAULT '',"
        "  timestamp        INTEGER NOT NULL,"
        "  sent             INTEGER NOT NULL,"
        "  status           INTEGER NOT NULL,"
        "  chunks_total     INTEGER NOT NULL,"
        "  chunks_complete  INTEGER NOT NULL,"
        "  saved_path       TEXT NOT NULL DEFAULT ''"
        ");"
    );
    q.exec("CREATE INDEX IF NOT EXISTS idx_file_transfers_chat_ts"
           " ON file_transfers(chat_key, timestamp);");

    // ── Phase 1: Causally-Linked Pairwise group messaging schema ──────
    //
    // group_replay_cache: sender's already-sent sealed envelopes,
    // retained for kReplayCacheMaxAgeSecs (7 days) so a recipient that
    // detects a gap can ask via gap_request and we replay byte-identical
    // (no re-encryption, no key reuse).  See PROTOCOL.md §X (TBD) for
    // the wire-format contract; the table just stores the sealed bytes.
    //
    // peer_id is the recipient (the per-recipient envelope of a group
    // fan-out).  PRIMARY KEY allows efficient replay-range queries
    // bound by (peer_id, group_id, session_id) and a counter range.
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_replay_cache ("
        "  peer_id          TEXT NOT NULL,"
        "  group_id         TEXT NOT NULL,"
        "  session_id       BLOB NOT NULL,"
        "  counter          INTEGER NOT NULL,"
        "  sealed_envelope  BLOB NOT NULL,"
        "  sent_at          INTEGER NOT NULL,"
        "  PRIMARY KEY (peer_id, group_id, session_id, counter),"
        "  FOREIGN KEY (group_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );
    // Index used by the periodic TTL purge — scans rows where
    // sent_at < (now - 7d) without touching the rest of the table.
    q.exec("CREATE INDEX IF NOT EXISTS idx_group_replay_cache_sent_at"
           " ON group_replay_cache(sent_at);");

    // group_chain_state: receiver's per-(group, sender) state machine
    // for the Causally-Linked Pairwise protocol.  One row per (group,
    // sender) — only the CURRENT session_id is tracked; on session
    // reset the row is updated in place and any in-flight buffer for
    // the old session is drained as "K messages lost during reconnect".
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_chain_state ("
        "  group_id          TEXT NOT NULL,"
        "  sender_peer_id    TEXT NOT NULL,"
        "  session_id        BLOB NOT NULL,"
        "  expected_next     INTEGER NOT NULL DEFAULT 1,"
        "  last_hash         BLOB,"
        "  blocked_since     INTEGER NOT NULL DEFAULT 0,"
        "  gap_from          INTEGER NOT NULL DEFAULT 0,"
        "  gap_to            INTEGER NOT NULL DEFAULT 0,"
        "  last_retry_at     INTEGER NOT NULL DEFAULT 0,"
        "  retry_count       INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (group_id, sender_peer_id),"
        "  FOREIGN KEY (group_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );

    // group_msg_buffer: receiver's hold table for out-of-order
    // group_msgs that arrived while the stream was blocked at a gap.
    // Body + sender_name are encrypted at field level via encryptField
    // (same XChaCha20-Poly1305-with-AAD pattern as messages.text), so
    // the buffer is no weaker at rest than the delivered messages
    // table.  Drained into `messages` once the gap fills.
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_msg_buffer ("
        "  group_id          TEXT NOT NULL,"
        "  sender_peer_id    TEXT NOT NULL,"
        "  session_id        BLOB NOT NULL,"
        "  counter           INTEGER NOT NULL,"
        "  prev_hash         BLOB,"
        "  sealed_env_hash   BLOB,"     // 16B hash of the sealed envelope —
                                          // becomes lastHash when this row drains
        "  msg_id            TEXT NOT NULL DEFAULT '',"
        "  body              TEXT NOT NULL DEFAULT '',"
        "  sender_name       TEXT NOT NULL DEFAULT '',"
        "  received_at       INTEGER NOT NULL,"
        "  PRIMARY KEY (group_id, sender_peer_id, session_id, counter),"
        "  FOREIGN KEY (group_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );

    // group_send_state: sender's per-(recipient, group, session)
    // monotonic counter + last sealed-envelope hash.  Updated
    // atomically with every successful enqueue so the next send
    // continues the chain even after a process restart.
    //
    // Independent of group_replay_cache so the chain can advance past
    // the cache TTL — purging old replay rows must not reset the
    // counter (counter monotonicity is what guards against replay).
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_send_state ("
        "  peer_id      TEXT NOT NULL,"
        "  group_id     TEXT NOT NULL,"
        "  session_id   BLOB NOT NULL,"
        "  next_counter INTEGER NOT NULL DEFAULT 1,"
        "  last_hash    BLOB,"
        "  PRIMARY KEY (peer_id, group_id, session_id),"
        "  FOREIGN KEY (group_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );

    // ── Phase 2: Invisible Groups (bundle_id ↔ group_id) ─────────────
    //
    // group_bundle_map: local-only mapping between the persistent
    // group identifier (group_id, used in app state + chain_state) and
    // an opaque on-wire bundle identifier (bundle_id, 16B random,
    // generated at group creation).  The bundle_id replaces group_id
    // on the wire so an attacker who later compromises a peer's DR
    // session can't correlate their messages across other groups
    // by reading the inner payload's group identifier — the bundle is
    // per-group-instance and never reused.
    //
    // Mapping is bidirectional: PK(group_id) for sender lookup,
    // UNIQUE(bundle_id) for receiver lookup.  Stable for the life of
    // the group; rotation on member change is a Phase 2.1 follow-up.
    q.exec(
        "CREATE TABLE IF NOT EXISTS group_bundle_map ("
        "  group_id   TEXT PRIMARY KEY NOT NULL,"
        "  bundle_id  BLOB NOT NULL UNIQUE,"
        "  created_at INTEGER NOT NULL,"
        "  FOREIGN KEY (group_id) REFERENCES conversations(id) ON DELETE CASCADE"
        ");"
    );
    q.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_bundle_map_bundle"
           " ON group_bundle_map(bundle_id);");

    // ── blocked_keys ────────────────────────────────────────────────────
    //
    // Phase 3h: block is its own thing, separate from the address book.
    // Inbound messages from a peer in this table are silently dropped
    // regardless of whether a `contacts` row exists for that peer.
    // This is the proper architectural fix for the prior coupling
    // (block previously wrote contacts.is_blocked, which forced an
    // auto-stub contact row and polluted the address book).
    //
    // Additive — doesn't disturb existing v3 tables, no version bump
    // required.  contacts.is_blocked column still exists for now but
    // is no longer written or read; cleanup is a follow-up.
    q.exec(
        "CREATE TABLE IF NOT EXISTS blocked_keys ("
        "  peer_id    TEXT PRIMARY KEY NOT NULL,"
        "  blocked_at INTEGER NOT NULL"
        ");"
    );

    // Stamp the schema version.  Future migrations gate on this — see
    // the v3 hard-break block at the top of this function for how the
    // current release handles upgrades from pre-v3 DBs.
    {
        SqlCipherQuery v(*m_db);
        v.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('schema_version','3');");
        v.exec();
    }
}

void AppDataStore::touchContact(const std::string& peerIdB64u, int64_t whenSecs)
{
    if (peerIdB64u.empty() || !m_db) return;
    // No-op when there's no contact row — strangers messaging us
    // don't get auto-added to the address book (Phase 3 design).
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET last_active=:ts WHERE peer_id=:peer_id;");
    q.bindValue(":ts", whenSecs);
    q.bindValue(":peer_id", peerIdB64u);
    q.exec();
}

void AppDataStore::touchConversation(const std::string& id, int64_t whenSecs)
{
    if (id.empty() || !m_db) return;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE conversations SET last_active=:ts WHERE id=:id;");
    q.bindValue(":ts", whenSecs);
    q.bindValue(":id", id);
    q.exec();
}

// ── Contacts ────────────────────────────────────────────────────────────────

bool AppDataStore::saveContact(const Contact& c)
{
    if (!m_db || c.peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT INTO contacts"
        " (peer_id,name,subtitle,avatar,muted,last_active)"
        " VALUES (:peer_id,:name,:subtitle,:avatar,:muted,:last_active)"
        " ON CONFLICT(peer_id) DO UPDATE SET"
        "   name=excluded.name,"
        "   subtitle=excluded.subtitle,"
        "   avatar=excluded.avatar,"
        "   muted=excluded.muted;"
    );
    q.bindValue(":peer_id",     c.peerIdB64u);
    q.bindValue(":name",        encryptField(c.name,
                                  fieldAad("contacts", "name", c.peerIdB64u)));
    q.bindValue(":subtitle",    encryptField(c.subtitle,
                                  fieldAad("contacts", "subtitle", c.peerIdB64u)));
    q.bindValue(":avatar",      encryptField(c.avatarB64,
                                  fieldAad("contacts", "avatar", c.peerIdB64u)));
    q.bindValue(":muted",       c.muted ? 1 : 0);
    q.bindValue(":last_active", c.lastActiveSecs);
    return q.exec();
}

bool AppDataStore::deleteContact(const std::string& peerIdB64u)
{
    if (!m_db || peerIdB64u.empty()) return false;
    // Address-book removal only.  Conversations, messages, and
    // group_* state involving this peer are intentionally NOT touched
    // — chat history is separate from address-book curation.  Use
    // deleteConversation to wipe a thread.
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM contacts WHERE peer_id=:peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    return q.exec();
}

void AppDataStore::loadAllContacts(const std::function<void(const Contact&)>& cb) const
{
    if (!m_db || !cb) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT peer_id,name,subtitle,avatar,muted,last_active"
        " FROM contacts ORDER BY last_active DESC, rowid ASC;"
    );
    if (!q.exec()) return;
    while (q.next()) {
        Contact c;
        c.peerIdB64u     = q.valueText(0);
        c.name           = decryptField(q.valueText(1),
                                          fieldAad("contacts", "name",     c.peerIdB64u));
        c.subtitle       = decryptField(q.valueText(2),
                                          fieldAad("contacts", "subtitle", c.peerIdB64u));
        c.avatarB64      = decryptField(q.valueText(3),
                                          fieldAad("contacts", "avatar",   c.peerIdB64u));
        c.muted          = q.valueInt(4) == 1;
        c.lastActiveSecs = q.valueInt64(5);
        cb(c);
    }
}

bool AppDataStore::loadContact(const std::string& peerIdB64u, Contact& out) const
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT peer_id,name,subtitle,avatar,muted,last_active"
        " FROM contacts WHERE peer_id=:pid LIMIT 1;"
    );
    q.bindValue(":pid", peerIdB64u);
    if (!q.exec() || !q.next()) return false;
    out.peerIdB64u     = q.valueText(0);
    out.name           = decryptField(q.valueText(1),
                                        fieldAad("contacts", "name",     out.peerIdB64u));
    out.subtitle       = decryptField(q.valueText(2),
                                        fieldAad("contacts", "subtitle", out.peerIdB64u));
    out.avatarB64      = decryptField(q.valueText(3),
                                        fieldAad("contacts", "avatar",   out.peerIdB64u));
    out.muted          = q.valueInt(4) == 1;
    out.lastActiveSecs = q.valueInt64(5);
    return true;
}

bool AppDataStore::setContactMuted(const std::string& peerIdB64u, bool muted)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET muted=:muted WHERE peer_id=:pid;");
    q.bindValue(":muted", muted ? 1 : 0);
    q.bindValue(":pid",   peerIdB64u);
    return q.exec() && q.numRowsAffected() > 0;
}

std::string AppDataStore::exportContactsJson() const
{
    // Wire format kept compatible with v1 ("name" + "keys" array per
    // entry) for cross-version sharing.  Contacts are now strictly 1:1
    // peers — `keys` will always be a one-element array containing
    // the peer's public key.  Blocked rows are omitted.
    nlohmann::json arr = nlohmann::json::array();
    loadAllContacts([&](const Contact& c) {
        // v3 export: blocked-state lives in `blocked_keys` (Phase 3h),
        // a separate concept from address-book curation.  Exporting
        // contacts intentionally does NOT include block state — that's
        // a per-device security action, not a portable address-book
        // attribute.  Recipients of an exported list shouldn't inherit
        // blocks from the sender.
        nlohmann::json obj;
        obj["name"] = c.name;
        obj["keys"] = nlohmann::json::array({ c.peerIdB64u });
        arr.push_back(std::move(obj));
    });
    nlohmann::json root;
    root["version"]  = 1;
    root["contacts"] = std::move(arr);
    return root.dump(2);
}

int AppDataStore::importContactsJson(const std::string& json)
{
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(json);
    } catch (const std::exception&) {
        return -1;
    }
    if (!doc.is_object() || !doc.contains("contacts") || !doc["contacts"].is_array()) {
        return -1;
    }

    // Snapshot existing peer_ids once so the import never overwrites.
    std::unordered_set<std::string> existing;
    loadAllContacts([&](const Contact& c) {
        if (!c.peerIdB64u.empty()) existing.insert(c.peerIdB64u);
    });

    int imported = 0;
    for (const auto& entry : doc["contacts"]) {
        if (!entry.is_object()) continue;
        Contact c;
        if (entry.contains("name") && entry["name"].is_string()) {
            c.name = p2p::trimmed(entry["name"].get<std::string>());
        }
        // v1 wire format used a `keys` array; first key is the peer's
        // public key.  Group-shaped exports (multi-key) from older
        // versions are silently dropped — no equivalent in v3.
        if (entry.contains("keys") && entry["keys"].is_array()
            && !entry["keys"].empty()
            && entry["keys"].front().is_string()) {
            c.peerIdB64u = entry["keys"].front().get<std::string>();
        }
        if (c.peerIdB64u.empty()) continue;
        if (existing.count(c.peerIdB64u)) continue;

        c.subtitle = "Secure chat";
        if (saveContact(c)) {
            existing.insert(c.peerIdB64u);
            ++imported;
        }
    }
    return imported;
}

bool AppDataStore::saveContactAvatar(const std::string& peerIdB64u,
                                     const std::string& avatarB64)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET avatar=:av WHERE peer_id=:pid;");
    q.bindValue(":av",  encryptField(avatarB64,
                           fieldAad("contacts", "avatar", peerIdB64u)));
    q.bindValue(":pid", peerIdB64u);
    return q.exec();
}

bool AppDataStore::saveContactKemPub(const std::string& peerIdB64u, const Bytes& kemPub)
{
    if (!m_db || peerIdB64u.empty() || kemPub.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:pid;");
    q.bindValue(":kp",  kemPub);
    q.bindValue(":pid", peerIdB64u);
    return q.exec();
}

Bytes AppDataStore::loadContactKemPub(const std::string& peerIdB64u) const
{
    if (!m_db || peerIdB64u.empty()) return {};
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:pid;");
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

// ── Conversations ───────────────────────────────────────────────────────────

namespace {
constexpr const char* kKindDirect = "direct";
constexpr const char* kKindGroup  = "group";

const char* kindToString(AppDataStore::ConversationKind k)
{
    return k == AppDataStore::ConversationKind::Group ? kKindGroup : kKindDirect;
}

AppDataStore::ConversationKind kindFromString(const std::string& s)
{
    return s == kKindGroup ? AppDataStore::ConversationKind::Group
                           : AppDataStore::ConversationKind::Direct;
}
}  // namespace

bool AppDataStore::saveConversation(const Conversation& c)
{
    if (!m_db || c.id.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT INTO conversations"
        " (id,kind,direct_peer_id,group_name,group_avatar,muted,"
        "  last_active,in_chat_list)"
        " VALUES (:id,:kind,:direct_peer,:gname,:gavatar,:muted,"
        "         :last_active,:in_list)"
        " ON CONFLICT(id) DO UPDATE SET"
        "   kind=excluded.kind,"
        "   direct_peer_id=excluded.direct_peer_id,"
        "   group_name=excluded.group_name,"
        "   group_avatar=excluded.group_avatar,"
        "   muted=excluded.muted,"
        "   in_chat_list=excluded.in_chat_list;"
    );
    q.bindValue(":id",    c.id);
    q.bindValue(":kind",  std::string(kindToString(c.kind)));
    // direct_peer_id is NULL for groups so the partial UNIQUE index
    // doesn't reject multiple groups.  SqlCipherQuery's bindValue
    // takes a string — empty string maps to NULL for TEXT columns
    // when we explicitly bind NULL, which we do here for groups.
    if (c.kind == ConversationKind::Direct && !c.directPeerId.empty()) {
        q.bindValue(":direct_peer", c.directPeerId);
    } else {
        q.bindValue(":direct_peer", nullptr);
    }
    q.bindValue(":gname",       encryptField(c.groupName,
                                  fieldAad("conversations", "group_name",   c.id)));
    q.bindValue(":gavatar",     encryptField(c.groupAvatarB64,
                                  fieldAad("conversations", "group_avatar", c.id)));
    q.bindValue(":muted",       c.muted ? 1 : 0);
    q.bindValue(":last_active", c.lastActiveSecs);
    q.bindValue(":in_list",     c.inChatList ? 1 : 0);
    return q.exec();
}

bool AppDataStore::loadConversation(const std::string& id, Conversation& out) const
{
    if (!m_db || id.empty()) return false;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT id,kind,direct_peer_id,group_name,group_avatar,muted,"
        "       last_active,in_chat_list"
        " FROM conversations WHERE id=:id LIMIT 1;"
    );
    q.bindValue(":id", id);
    if (!q.exec() || !q.next()) return false;
    out.id              = q.valueText(0);
    out.kind            = kindFromString(q.valueText(1));
    out.directPeerId    = q.valueText(2);
    out.groupName       = decryptField(q.valueText(3),
                                          fieldAad("conversations", "group_name",   out.id));
    out.groupAvatarB64  = decryptField(q.valueText(4),
                                          fieldAad("conversations", "group_avatar", out.id));
    out.muted           = q.valueInt(5) == 1;
    out.lastActiveSecs  = q.valueInt64(6);
    out.inChatList      = q.valueInt(7) == 1;
    return true;
}

void AppDataStore::loadAllConversations(
    const std::function<void(const Conversation&)>& cb) const
{
    if (!m_db || !cb) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT id,kind,direct_peer_id,group_name,group_avatar,muted,"
        "       last_active,in_chat_list"
        " FROM conversations ORDER BY last_active DESC, rowid ASC;"
    );
    if (!q.exec()) return;
    while (q.next()) {
        Conversation c;
        c.id              = q.valueText(0);
        c.kind            = kindFromString(q.valueText(1));
        c.directPeerId    = q.valueText(2);
        c.groupName       = decryptField(q.valueText(3),
                                          fieldAad("conversations", "group_name",   c.id));
        c.groupAvatarB64  = decryptField(q.valueText(4),
                                          fieldAad("conversations", "group_avatar", c.id));
        c.muted           = q.valueInt(5) == 1;
        c.lastActiveSecs  = q.valueInt64(6);
        c.inChatList      = q.valueInt(7) == 1;
        cb(c);
    }
}

bool AppDataStore::ensureGroupConversation(const std::string& groupId)
{
    if (!m_db || groupId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR IGNORE INTO conversations (id,kind,last_active,in_chat_list)"
        " VALUES (:id,'group',:ts,1);"
    );
    q.bindValue(":id", groupId);
    q.bindValue(":ts", static_cast<int64_t>(time(nullptr)));
    return q.exec();
}

std::string AppDataStore::findOrCreateDirectConversation(const std::string& peerIdB64u)
{
    if (!m_db || peerIdB64u.empty()) return {};

    {
        SqlCipherQuery q(m_db->handle());
        q.prepare(
            "SELECT id FROM conversations"
            " WHERE direct_peer_id=:pid LIMIT 1;"
        );
        q.bindValue(":pid", peerIdB64u);
        if (q.exec() && q.next()) return q.valueText(0);
    }

    // Mint a fresh UUID via the project's existing helper.  The
    // partial UNIQUE index on direct_peer_id makes the INSERT race-safe
    // — concurrent callers that lose the race re-read the winner's row.
    const std::string id = p2p::makeUuid();
    SqlCipherQuery ins(*m_db);
    ins.prepare(
        "INSERT INTO conversations (id,kind,direct_peer_id,last_active,in_chat_list)"
        " VALUES (:id,'direct',:pid,:ts,1);"
    );
    ins.bindValue(":id", id);
    ins.bindValue(":pid", peerIdB64u);
    ins.bindValue(":ts", static_cast<int64_t>(time(nullptr)));
    if (!ins.exec()) {
        // Lost the race — re-read the winning row.
        SqlCipherQuery q(m_db->handle());
        q.prepare("SELECT id FROM conversations WHERE direct_peer_id=:pid LIMIT 1;");
        q.bindValue(":pid", peerIdB64u);
        if (q.exec() && q.next()) return q.valueText(0);
        return {};
    }

    // Direct conversation has exactly one member (the peer).
    addConversationMember(id, peerIdB64u);
    return id;
}

bool AppDataStore::deleteConversation(const std::string& id)
{
    if (!m_db || id.empty()) return false;
    // FK ON DELETE CASCADE on messages, conversation_members, and the
    // group_* tables sweeps everything tied to this conversation.
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM conversations WHERE id=:id;");
    q.bindValue(":id", id);
    return q.exec();
}

bool AppDataStore::setConversationMuted(const std::string& id, bool muted)
{
    if (!m_db || id.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE conversations SET muted=:m WHERE id=:id;");
    q.bindValue(":m",  muted ? 1 : 0);
    q.bindValue(":id", id);
    return q.exec() && q.numRowsAffected() > 0;
}

bool AppDataStore::setConversationInChatList(const std::string& id, bool inList)
{
    if (!m_db || id.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE conversations SET in_chat_list=:v WHERE id=:id;");
    q.bindValue(":v",  inList ? 1 : 0);
    q.bindValue(":id", id);
    return q.exec() && q.numRowsAffected() > 0;
}

// ── Conversation members ─────────────────────────────────────────────────────

bool AppDataStore::addConversationMember(const std::string& conversationId,
                                            const std::string& peerIdB64u)
{
    if (!m_db || conversationId.empty() || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR IGNORE INTO conversation_members (conversation_id,peer_id)"
        " VALUES (:cid,:pid);"
    );
    q.bindValue(":cid", conversationId);
    q.bindValue(":pid", peerIdB64u);
    return q.exec();
}

bool AppDataStore::removeConversationMember(const std::string& conversationId,
                                               const std::string& peerIdB64u)
{
    if (!m_db || conversationId.empty() || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM conversation_members"
        " WHERE conversation_id=:cid AND peer_id=:pid;"
    );
    q.bindValue(":cid", conversationId);
    q.bindValue(":pid", peerIdB64u);
    return q.exec() && q.numRowsAffected() > 0;
}

bool AppDataStore::setConversationMembers(const std::string& conversationId,
                                             const std::vector<std::string>& peerIds)
{
    if (!m_db || conversationId.empty()) return false;

    Tx tx(m_db->handle());

    {
        SqlCipherQuery del(*m_db);
        del.prepare("DELETE FROM conversation_members WHERE conversation_id=:cid;");
        del.bindValue(":cid", conversationId);
        if (!del.exec()) return false;
    }
    for (const std::string& pid : peerIds) {
        if (pid.empty()) continue;
        SqlCipherQuery ins(*m_db);
        ins.prepare(
            "INSERT OR IGNORE INTO conversation_members (conversation_id,peer_id)"
            " VALUES (:cid,:pid);"
        );
        ins.bindValue(":cid", conversationId);
        ins.bindValue(":pid", pid);
        if (!ins.exec()) return false;
    }
    return tx.commit();
}

void AppDataStore::loadConversationMembers(
    const std::string& conversationId,
    const std::function<void(const std::string&)>& cb) const
{
    if (!m_db || !cb || conversationId.empty()) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT peer_id FROM conversation_members"
        " WHERE conversation_id=:cid ORDER BY peer_id ASC;"
    );
    q.bindValue(":cid", conversationId);
    if (!q.exec()) return;
    while (q.next()) cb(q.valueText(0));
}

// ── Blocked keys ────────────────────────────────────────────────────────────

bool AppDataStore::addBlockedKey(const std::string& peerIdB64u, int64_t whenSecs)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    // INSERT OR REPLACE so re-blocking refreshes the timestamp without
    // erroring on the PK collision.  Idempotent from the caller's view.
    q.prepare(
        "INSERT OR REPLACE INTO blocked_keys (peer_id, blocked_at)"
        " VALUES (:peer, :ts);"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":ts",   whenSecs);
    return q.exec();
}

bool AppDataStore::removeBlockedKey(const std::string& peerIdB64u)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM blocked_keys WHERE peer_id=:peer;");
    q.bindValue(":peer", peerIdB64u);
    return q.exec() && q.numRowsAffected() > 0;
}

bool AppDataStore::isBlockedKey(const std::string& peerIdB64u) const
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT 1 FROM blocked_keys WHERE peer_id=:peer LIMIT 1;");
    q.bindValue(":peer", peerIdB64u);
    return q.exec() && q.next();
}

void AppDataStore::loadAllBlockedKeys(
    const std::function<void(const std::string&, int64_t)>& cb) const
{
    if (!m_db || !cb) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT peer_id, blocked_at FROM blocked_keys"
        " ORDER BY blocked_at ASC;"
    );
    if (!q.exec()) return;
    while (q.next()) cb(q.valueText(0), q.valueInt64(1));
}

// ── Messages ────────────────────────────────────────────────────────────────

bool AppDataStore::saveMessage(const std::string& conversationId, const Message& m)
{
    if (!m_db || conversationId.empty()) return false;

    // Single transaction so the message INSERT and conversation
    // last_active bump are atomic + share one fsync.  The conversation
    // row MUST exist — callers that handle inbound-from-stranger
    // should call findOrCreateDirectConversation first.
    Tx tx(m_db->handle());

    {
        SqlCipherQuery q(*m_db);
        q.prepare(
            "INSERT INTO messages"
            " (conversation_id,sent,text,timestamp,msg_id,sender_id,sender_name)"
            " VALUES (:cid,:sent,:text,:ts,:msg_id,:sender_id,:sender_name);"
        );
        q.bindValue(":cid",         conversationId);
        q.bindValue(":sent",        m.sent ? 1 : 0);
        // Messages bind (conversation_id, msg_id) into the AAD so a
        // blob from convA@msg1 cannot be swapped into convB@msg1 or
        // convA@msg2.
        const std::string rowKey = conversationId + "|" + m.msgId;
        q.bindValue(":text",        encryptField(m.text,
                                      fieldAad("messages", "text", rowKey)));
        q.bindValue(":ts",          m.timestampSecs);
        q.bindValue(":msg_id",      m.msgId);
        q.bindValue(":sender_id",   m.senderId);
        q.bindValue(":sender_name", encryptField(m.senderName,
                                      fieldAad("messages", "sender_name", rowKey)));
        if (!q.exec()) return false;
    }
    touchConversation(conversationId, m.timestampSecs > 0
                                          ? m.timestampSecs
                                          : static_cast<int64_t>(time(nullptr)));
    // Bump the sender's contact last_active too, when the message is
    // inbound and we have an address-book row for them.  Outbound
    // messages don't touch any contact (sender is self).
    if (!m.sent && !m.senderId.empty()) {
        touchContact(m.senderId, m.timestampSecs > 0
                                     ? m.timestampSecs
                                     : static_cast<int64_t>(time(nullptr)));
    }
    // Auto-unhide on inbound: if the user previously archived this
    // conversation (in_chat_list=0), pop it back into the chat list
    // when the other party speaks up.  Matches the "hide until they
    // message me again" mental model.  Outbound stays sticky — sending
    // to a hidden chat doesn't auto-unhide (the user already has the
    // chat in front of them; if they want it back in the list they
    // can flip the toggle themselves).
    if (!m.sent) {
        SqlCipherQuery unhide(*m_db);
        unhide.prepare(
            "UPDATE conversations SET in_chat_list=1"
            " WHERE id=:id AND in_chat_list=0;"
        );
        unhide.bindValue(":id", conversationId);
        unhide.exec();
    }
    return tx.commit();
}

void AppDataStore::loadMessages(const std::string& conversationId,
                                const std::function<void(const Message&)>& cb) const
{
    if (!m_db || !cb || conversationId.empty()) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT sent,text,timestamp,msg_id,sender_id,sender_name FROM messages"
        " WHERE conversation_id=:cid ORDER BY timestamp ASC, id ASC;"
    );
    q.bindValue(":cid", conversationId);
    if (!q.exec()) return;
    while (q.next()) {
        Message m;
        m.sent          = q.valueInt(0) == 1;
        m.timestampSecs = q.valueInt64(2);
        m.msgId         = q.valueText(3);
        m.senderId      = q.valueText(4);
        const std::string rowKey = conversationId + "|" + m.msgId;
        m.text          = decryptField(q.valueText(1),
                                          fieldAad("messages", "text",        rowKey));
        m.senderName    = decryptField(q.valueText(5),
                                          fieldAad("messages", "sender_name", rowKey));
        cb(m);
    }
}

bool AppDataStore::deleteMessages(const std::string& conversationId)
{
    if (!m_db || conversationId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM messages WHERE conversation_id=:cid;");
    q.bindValue(":cid", conversationId);
    return q.exec();
}

bool AppDataStore::deleteMessage(const std::string& conversationId,
                                 const std::string& msgId)
{
    if (!m_db || conversationId.empty() || msgId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM messages WHERE conversation_id=:cid AND msg_id=:msg_id;");
    q.bindValue(":cid",    conversationId);
    q.bindValue(":msg_id", msgId);
    // exec() returns true for SQLITE_DONE even when zero rows matched;
    // honor the docstring's "returns false when nothing matched".
    return q.exec() && q.numRowsAffected() > 0;
}

// ── Settings ────────────────────────────────────────────────────────────────

bool AppDataStore::saveSetting(const std::string& key, const std::string& value)
{
    if (!m_db || key.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(:k,:v);");
    q.bindValue(":k", key);
    // Encrypt every value at the storage layer so a page-key compromise
    // can't harvest relay URLs / TURN creds / display name / similar.
    // AAD binds the setting key so one setting's blob cannot be swapped
    // into another.
    q.bindValue(":v", encryptField(value,
                        fieldAad("settings", "value", key)));
    return q.exec();
}

std::string AppDataStore::loadSetting(const std::string& key,
                                      const std::string& defaultValue) const
{
    if (!m_db || key.empty()) return defaultValue;
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT value FROM settings WHERE key=:k;");
    q.bindValue(":k", key);
    if (q.exec() && q.next()) {
        // decryptField handles both the new encrypted form AND the
        // legacy plaintext rows — it returns the input unchanged if
        // the ciphertext prefix is missing.  See encryptField impl.
        return decryptField(q.valueText(0),
                             fieldAad("settings", "value", key));
    }
    return defaultValue;
}

// ── Group sequence counters ────────────────────────────────────────────────

namespace {
void saveSeqMap(SqlCipherDb& db, int direction,
                const std::map<std::string, int64_t>& counters)
{
    // UPSERT per entry instead of DELETE-all + reinsert.  Desktop's
    // DBM nuked every row of the direction on every save which is
    // O(n) writes for every counter bump — pathological once a user
    // is in dozens of groups.  Per-entry UPSERT is O(changed).
    Tx tx(db.handle());
    for (const auto& [k, v] : counters) {
        SqlCipherQuery q(db);
        q.prepare(
            "INSERT INTO group_seq_counters(seq_key,direction,counter)"
            " VALUES(:k,:d,:c)"
            " ON CONFLICT(seq_key,direction) DO UPDATE SET counter=excluded.counter;"
        );
        q.bindValue(":k", k);
        q.bindValue(":d", direction);
        q.bindValue(":c", v);
        q.exec();
    }
    tx.commit();
}

std::map<std::string, int64_t> loadSeqMap(sqlite3* db, int direction)
{
    std::map<std::string, int64_t> out;
    SqlCipherQuery q(db);
    q.prepare("SELECT seq_key,counter FROM group_seq_counters WHERE direction=:d;");
    q.bindValue(":d", direction);
    if (!q.exec()) return out;
    while (q.next()) out[q.valueText(0)] = q.valueInt64(1);
    return out;
}
} // namespace

void AppDataStore::saveGroupSeqOut(const std::map<std::string, int64_t>& c)
{ if (m_db) saveSeqMap(*m_db, 0, c); }
void AppDataStore::saveGroupSeqIn(const std::map<std::string, int64_t>& c)
{ if (m_db) saveSeqMap(*m_db, 1, c); }
std::map<std::string, int64_t> AppDataStore::loadGroupSeqOut() const
{ return m_db ? loadSeqMap(m_db->handle(), 0) : std::map<std::string, int64_t>{}; }
std::map<std::string, int64_t> AppDataStore::loadGroupSeqIn() const
{ return m_db ? loadSeqMap(m_db->handle(), 1) : std::map<std::string, int64_t>{}; }

// ── File transfer records ──────────────────────────────────────────────────

bool AppDataStore::saveFileRecord(const std::string& chatKey, const FileRecord& r)
{
    if (!m_db || chatKey.empty() || r.transferId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR REPLACE INTO file_transfers"
        " (transfer_id,chat_key,file_name,file_size,peer_id,peer_name,"
        "  timestamp,sent,status,chunks_total,chunks_complete,saved_path)"
        " VALUES (:tid,:ck,:fn,:fs,:pid,:pn,:ts,:sent,:status,:ct,:cc,:sp);"
    );
    q.bindValue(":tid",    r.transferId);
    q.bindValue(":ck",     chatKey);
    q.bindValue(":fn",     encryptField(r.fileName,
                             fieldAad("file_transfers", "file_name",  r.transferId)));
    q.bindValue(":fs",     r.fileSize);
    q.bindValue(":pid",    r.peerIdB64u);
    q.bindValue(":pn",     encryptField(r.peerName,
                             fieldAad("file_transfers", "peer_name",  r.transferId)));
    q.bindValue(":ts",     r.timestampSecs);
    q.bindValue(":sent",   r.sent ? 1 : 0);
    q.bindValue(":status", r.status);
    q.bindValue(":ct",     r.chunksTotal);
    q.bindValue(":cc",     r.chunksComplete);
    q.bindValue(":sp",     encryptField(r.savedPath,
                             fieldAad("file_transfers", "saved_path", r.transferId)));
    return q.exec();
}

bool AppDataStore::deleteFileRecord(const std::string& transferId)
{
    if (!m_db || transferId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM file_transfers WHERE transfer_id=:tid;");
    q.bindValue(":tid", transferId);
    return q.exec();
}

bool AppDataStore::deleteFileRecordsForChat(const std::string& chatKey)
{
    if (!m_db || chatKey.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM file_transfers WHERE chat_key=:ck;");
    q.bindValue(":ck", chatKey);
    return q.exec();
}

void AppDataStore::loadFileRecords(const std::string& chatKey,
                                   const std::function<void(const FileRecord&)>& cb) const
{
    if (!m_db || !cb || chatKey.empty()) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT transfer_id,file_name,file_size,peer_id,peer_name,"
        "       timestamp,sent,status,chunks_total,chunks_complete,saved_path"
        " FROM file_transfers WHERE chat_key=:ck ORDER BY timestamp ASC;"
    );
    q.bindValue(":ck", chatKey);
    if (!q.exec()) return;
    while (q.next()) {
        FileRecord r;
        r.transferId      = q.valueText(0);
        r.fileName        = decryptField(q.valueText(1),
                              fieldAad("file_transfers", "file_name",  r.transferId));
        r.fileSize        = q.valueInt64(2);
        r.peerIdB64u      = q.valueText(3);
        r.peerName        = decryptField(q.valueText(4),
                              fieldAad("file_transfers", "peer_name",  r.transferId));
        r.timestampSecs   = q.valueInt64(5);
        r.sent            = q.valueInt(6) == 1;
        r.status          = q.valueInt(7);
        r.chunksTotal     = q.valueInt(8);
        r.chunksComplete  = q.valueInt(9);
        r.savedPath       = decryptField(q.valueText(10),
                              fieldAad("file_transfers", "saved_path", r.transferId));
        r.chatKey         = chatKey;
        cb(r);
    }
}

// ── Group replay cache ──────────────────────────────────────────────────────

bool AppDataStore::addReplayCacheEntry(const std::string& peerIdB64u,
                                         const std::string& groupId,
                                         const Bytes& sessionId,
                                         int64_t counter,
                                         const Bytes& sealedEnvelope,
                                         int64_t sentAt)
{
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty() || sealedEnvelope.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR REPLACE INTO group_replay_cache "
        "(peer_id, group_id, session_id, counter, sealed_envelope, sent_at) "
        "VALUES (:peer, :gid, :sid, :ctr, :env, :ts);"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    q.bindValue(":ctr",  counter);
    q.bindValue(":env",  sealedEnvelope);
    q.bindValue(":ts",   sentAt);
    return q.exec();
}

Bytes AppDataStore::loadReplayCacheEntry(const std::string& peerIdB64u,
                                           const std::string& groupId,
                                           const Bytes& sessionId,
                                           int64_t counter) const
{
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty()) return {};

    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT sealed_envelope FROM group_replay_cache "
        "WHERE peer_id=:peer AND group_id=:gid "
        "AND session_id=:sid AND counter=:ctr;"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    q.bindValue(":ctr",  counter);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

void AppDataStore::loadReplayCacheRange(
    const std::string& peerIdB64u,
    const std::string& groupId,
    const Bytes& sessionId,
    int64_t fromCounter, int64_t toCounter,
    const std::function<void(int64_t, const Bytes&)>& cb) const
{
    if (!m_db || !cb || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty() || toCounter < fromCounter) return;

    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT counter, sealed_envelope FROM group_replay_cache "
        "WHERE peer_id=:peer AND group_id=:gid AND session_id=:sid "
        "AND counter BETWEEN :lo AND :hi "
        "ORDER BY counter ASC;"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    q.bindValue(":lo",   fromCounter);
    q.bindValue(":hi",   toCounter);
    if (!q.exec()) return;
    while (q.next()) {
        cb(q.valueInt64(0), q.valueBlob(1));
    }
}

bool AppDataStore::dropReplayCacheEntry(const std::string& peerIdB64u,
                                          const std::string& groupId,
                                          const Bytes& sessionId,
                                          int64_t counter)
{
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM group_replay_cache "
        "WHERE peer_id=:peer AND group_id=:gid "
        "AND session_id=:sid AND counter=:ctr;"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    q.bindValue(":ctr",  counter);
    return q.exec();
}

int AppDataStore::purgeReplayCacheOlderThan(int64_t cutoffSecs)
{
    if (!m_db) return 0;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM group_replay_cache WHERE sent_at < :cutoff;");
    q.bindValue(":cutoff", cutoffSecs);
    if (!q.exec()) return 0;
    return q.numRowsAffected();
}

// ── Group chain state ───────────────────────────────────────────────────────

bool AppDataStore::loadChainState(const std::string& groupId,
                                    const std::string& senderPeerId,
                                    ChainState& out) const
{
    if (!m_db || groupId.empty() || senderPeerId.empty()) return false;

    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT session_id, expected_next, last_hash, blocked_since, "
        "       gap_from, gap_to, last_retry_at, retry_count "
        "FROM group_chain_state "
        "WHERE group_id=:gid AND sender_peer_id=:sender;"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    if (!q.exec() || !q.next()) return false;

    out.sessionId    = q.valueBlob(0);
    out.expectedNext = q.valueInt64(1);
    out.lastHash     = q.valueBlob(2);
    out.blockedSince = q.valueInt64(3);
    out.gapFrom      = q.valueInt64(4);
    out.gapTo        = q.valueInt64(5);
    out.lastRetryAt  = q.valueInt64(6);
    out.retryCount   = q.valueInt(7);
    return true;
}

bool AppDataStore::saveChainState(const std::string& groupId,
                                    const std::string& senderPeerId,
                                    const ChainState& s)
{
    if (!m_db || groupId.empty() || senderPeerId.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR REPLACE INTO group_chain_state "
        "(group_id, sender_peer_id, session_id, expected_next, last_hash, "
        " blocked_since, gap_from, gap_to, last_retry_at, retry_count) "
        "VALUES (:gid, :sender, :sid, :next, :hash, "
        "        :blocked, :gfrom, :gto, :lretry, :rcount);"
    );
    q.bindValue(":gid",     groupId);
    q.bindValue(":sender",  senderPeerId);
    q.bindValue(":sid",     s.sessionId);
    q.bindValue(":next",    s.expectedNext);
    q.bindValue(":hash",    s.lastHash);
    q.bindValue(":blocked", s.blockedSince);
    q.bindValue(":gfrom",   s.gapFrom);
    q.bindValue(":gto",     s.gapTo);
    q.bindValue(":lretry",  s.lastRetryAt);
    q.bindValue(":rcount",  static_cast<int64_t>(s.retryCount));
    return q.exec();
}

bool AppDataStore::dropChainState(const std::string& groupId,
                                    const std::string& senderPeerId)
{
    if (!m_db || groupId.empty() || senderPeerId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM group_chain_state "
        "WHERE group_id=:gid AND sender_peer_id=:sender;"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    return q.exec();
}

// ── Group message buffer ────────────────────────────────────────────────────

namespace {

// AAD scope for group_msg_buffer field encryption.  Mirrors the
// `messages.text` convention but adds session_id (hex) to the row
// key — the buffer can hold rows from multiple sessions briefly
// (during a session-reset transition) and the AAD must distinguish.
// Uses hex (not base64url) so we don't depend on CryptoEngine here.
std::string bufferRowKey(const std::string& groupId,
                          const std::string& senderPeerId,
                          const Bytes& sessionId,
                          int64_t counter) {
    std::string sidHex;
    sidHex.reserve(sessionId.size() * 2);
    static constexpr char kHex[] = "0123456789abcdef";
    for (uint8_t b : sessionId) {
        sidHex.push_back(kHex[b >> 4]);
        sidHex.push_back(kHex[b & 0xF]);
    }
    return groupId + "|" + senderPeerId + "|" + sidHex
         + "|" + std::to_string(counter);
}

}  // namespace

bool AppDataStore::addBufferEntry(const std::string& groupId,
                                    const std::string& senderPeerId,
                                    const Bytes& sessionId,
                                    int64_t counter,
                                    const Bytes& prevHash,
                                    const Bytes& sealedEnvHash,
                                    const std::string& msgId,
                                    const std::string& body,
                                    const std::string& senderName,
                                    int64_t receivedAt)
{
    if (!m_db || groupId.empty() || senderPeerId.empty()
        || sessionId.empty()) return false;

    const std::string rowKey = bufferRowKey(groupId, senderPeerId,
                                              sessionId, counter);

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR REPLACE INTO group_msg_buffer "
        "(group_id, sender_peer_id, session_id, counter, prev_hash, "
        " sealed_env_hash, msg_id, body, sender_name, received_at) "
        "VALUES (:gid, :sender, :sid, :ctr, :hash, "
        "        :envh, :mid, :body, :sname, :ts);"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    q.bindValue(":sid",    sessionId);
    q.bindValue(":ctr",    counter);
    q.bindValue(":hash",   prevHash);
    q.bindValue(":envh",   sealedEnvHash);
    q.bindValue(":mid",    msgId);
    q.bindValue(":body",   encryptField(body,
                              fieldAad("group_msg_buffer", "body", rowKey)));
    q.bindValue(":sname",  encryptField(senderName,
                              fieldAad("group_msg_buffer", "sender_name", rowKey)));
    q.bindValue(":ts",     receivedAt);
    return q.exec();
}

void AppDataStore::loadBufferRange(
    const std::string& groupId,
    const std::string& senderPeerId,
    const Bytes& sessionId,
    int64_t fromCounter, int64_t toCounter,
    const std::function<void(const BufferedMessage&)>& cb) const
{
    if (!m_db || !cb || groupId.empty() || senderPeerId.empty()
        || sessionId.empty() || toCounter < fromCounter) return;

    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT counter, prev_hash, sealed_env_hash, msg_id, "
        "       body, sender_name, received_at "
        "FROM group_msg_buffer "
        "WHERE group_id=:gid AND sender_peer_id=:sender "
        "AND session_id=:sid "
        "AND counter BETWEEN :lo AND :hi "
        "ORDER BY counter ASC;"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    q.bindValue(":sid",    sessionId);
    q.bindValue(":lo",     fromCounter);
    q.bindValue(":hi",     toCounter);
    if (!q.exec()) return;

    while (q.next()) {
        BufferedMessage m;
        m.counter         = q.valueInt64(0);
        m.prevHash        = q.valueBlob(1);
        m.sealedEnvHash   = q.valueBlob(2);
        m.msgId           = q.valueText(3);
        const std::string rowKey = bufferRowKey(groupId, senderPeerId,
                                                  sessionId, m.counter);
        m.body         = decryptField(q.valueText(4),
                            fieldAad("group_msg_buffer", "body", rowKey));
        m.senderName   = decryptField(q.valueText(5),
                            fieldAad("group_msg_buffer", "sender_name", rowKey));
        m.receivedAt   = q.valueInt64(6);
        cb(m);
    }
}

int AppDataStore::dropBufferRange(const std::string& groupId,
                                    const std::string& senderPeerId,
                                    const Bytes& sessionId,
                                    int64_t fromCounter, int64_t toCounter)
{
    if (!m_db || groupId.empty() || senderPeerId.empty()
        || sessionId.empty() || toCounter < fromCounter) return 0;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM group_msg_buffer "
        "WHERE group_id=:gid AND sender_peer_id=:sender "
        "AND session_id=:sid "
        "AND counter BETWEEN :lo AND :hi;"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    q.bindValue(":sid",    sessionId);
    q.bindValue(":lo",     fromCounter);
    q.bindValue(":hi",     toCounter);
    if (!q.exec()) return 0;
    return q.numRowsAffected();
}

int AppDataStore::dropBufferForSession(const std::string& groupId,
                                         const std::string& senderPeerId,
                                         const Bytes& sessionId)
{
    if (!m_db || groupId.empty() || senderPeerId.empty()
        || sessionId.empty()) return 0;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM group_msg_buffer "
        "WHERE group_id=:gid AND sender_peer_id=:sender "
        "AND session_id=:sid;"
    );
    q.bindValue(":gid",    groupId);
    q.bindValue(":sender", senderPeerId);
    q.bindValue(":sid",    sessionId);
    if (!q.exec()) return 0;
    return q.numRowsAffected();
}

// ── Group send state ────────────────────────────────────────────────────────

bool AppDataStore::loadSendState(const std::string& peerIdB64u,
                                   const std::string& groupId,
                                   const Bytes& sessionId,
                                   SendState& out) const
{
    out = SendState{};  // default for missing row
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty()) return true;

    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT next_counter, last_hash FROM group_send_state "
        "WHERE peer_id=:peer AND group_id=:gid AND session_id=:sid;"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    if (q.exec() && q.next()) {
        out.nextCounter = q.valueInt64(0);
        out.lastHash    = q.valueBlob(1);
    }
    return true;
}

bool AppDataStore::saveSendState(const std::string& peerIdB64u,
                                   const std::string& groupId,
                                   const Bytes& sessionId,
                                   const SendState& s)
{
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR REPLACE INTO group_send_state "
        "(peer_id, group_id, session_id, next_counter, last_hash) "
        "VALUES (:peer, :gid, :sid, :next, :hash);"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    q.bindValue(":next", s.nextCounter);
    q.bindValue(":hash", s.lastHash);
    return q.exec();
}

bool AppDataStore::dropSendState(const std::string& peerIdB64u,
                                   const std::string& groupId,
                                   const Bytes& sessionId)
{
    if (!m_db || peerIdB64u.empty() || groupId.empty()
        || sessionId.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "DELETE FROM group_send_state "
        "WHERE peer_id=:peer AND group_id=:gid AND session_id=:sid;"
    );
    q.bindValue(":peer", peerIdB64u);
    q.bindValue(":gid",  groupId);
    q.bindValue(":sid",  sessionId);
    return q.exec();
}

// ── Group bundle map (Phase 2, Invisible Groups) ────────────────────────────

Bytes AppDataStore::bundleIdForGroup(const std::string& groupId) const
{
    if (!m_db || groupId.empty()) return {};
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT bundle_id FROM group_bundle_map WHERE group_id=:gid;");
    q.bindValue(":gid", groupId);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

Bytes AppDataStore::ensureBundleIdForGroup(const std::string& groupId)
{
    if (!m_db || groupId.empty()) return {};

    if (Bytes existing = bundleIdForGroup(groupId); !existing.empty())
        return existing;

    // Mint a fresh 16-byte bundle_id.  16 bytes is the same width as a
    // UUID — large enough to make collisions astronomical, small enough
    // not to bloat the per-message inner payload.
    Bytes bundleId(16);
    randombytes_buf(bundleId.data(), bundleId.size());

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT INTO group_bundle_map (group_id, bundle_id, created_at) "
        "VALUES (:gid, :bid, :ts);"
    );
    q.bindValue(":gid", groupId);
    q.bindValue(":bid", bundleId);
    q.bindValue(":ts",  static_cast<int64_t>(time(nullptr)));
    if (!q.exec()) {
        // UNIQUE-violation race: another caller raced ahead.  Re-read
        // the row so both callers converge on the same id.
        return bundleIdForGroup(groupId);
    }
    return bundleId;
}

std::string AppDataStore::groupIdForBundle(const Bytes& bundleId) const
{
    if (!m_db || bundleId.empty()) return {};
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT group_id FROM group_bundle_map WHERE bundle_id=:bid;");
    q.bindValue(":bid", bundleId);
    if (q.exec() && q.next()) return q.valueText(0);
    return {};
}

bool AppDataStore::addBundleMapping(const std::string& groupId,
                                       const Bytes& bundleId,
                                       int64_t createdAt)
{
    if (!m_db || groupId.empty() || bundleId.empty()) return false;

    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT OR IGNORE INTO group_bundle_map "
        "(group_id, bundle_id, created_at) VALUES (:gid, :bid, :ts);"
    );
    q.bindValue(":gid", groupId);
    q.bindValue(":bid", bundleId);
    q.bindValue(":ts",  createdAt);
    return q.exec();
}

bool AppDataStore::dropBundleMapping(const std::string& groupId)
{
    if (!m_db || groupId.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM group_bundle_map WHERE group_id=:gid;");
    q.bindValue(":gid", groupId);
    return q.exec();
}
