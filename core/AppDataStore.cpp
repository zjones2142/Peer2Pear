#include "AppDataStore.hpp"

#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <cstring>

// Per-field encryption format: "ENC:" + base64(nonce || ciphertext || tag).
// Anything without the prefix is treated as a legacy plaintext value and
// returned as-is — handles the upgrade path from the desktop's pre-encrypted
// rows.  Mirrors desktop/databasemanager.cpp's kEncPrefix exactly so values
// written by either code path round-trip cleanly.
namespace {
constexpr const char* kEncPrefix    = "ENC:";
constexpr size_t      kEncPrefixLen = 4;

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

// Join/split the contacts.keys list using '|' — same encoding as desktop.
std::string joinKeys(const std::vector<std::string>& keys)
{
    std::string out;
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i) out += '|';
        out += keys[i];
    }
    return out;
}

std::vector<std::string> splitKeys(const std::string& s)
{
    std::vector<std::string> out;
    if (s.empty()) return out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '|') {
            if (i > start) out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
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

std::string AppDataStore::encryptField(const std::string& plaintext) const
{
    if (m_encKey.empty()) return plaintext;

    const size_t nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
    const size_t tagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;    // 16

    Bytes buf(nonceLen + plaintext.size() + tagLen, 0);
    randombytes_buf(buf.data(), nonceLen);

    unsigned long long ctLen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        buf.data() + nonceLen, &ctLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        nullptr, 0,
        nullptr,
        buf.data(),
        m_encKey.data());

    buf.resize(nonceLen + ctLen);
    return std::string(kEncPrefix) + base64Encode(buf.data(), buf.size());
}

std::string AppDataStore::decryptField(const std::string& stored) const
{
    // Legacy plaintext row — no prefix, return verbatim.
    if (stored.compare(0, kEncPrefixLen, kEncPrefix) != 0)
        return stored;

    if (m_encKey.empty() && m_legacyKeys.empty())
        return {}; // no key — never expose ciphertext

    Bytes blob;
    if (!base64Decode(stored.substr(kEncPrefixLen), blob)) return {};

    const size_t nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t tagLen   = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (blob.size() < nonceLen + tagLen) return {};

    Bytes pt(blob.size() - nonceLen - tagLen, 0);
    unsigned long long ptLen = 0;

    auto tryKey = [&](const Bytes& key) -> bool {
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &ptLen,
            nullptr,
            blob.data() + nonceLen, blob.size() - nonceLen,
            nullptr, 0,
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

    // contacts: peer_id is the canonical lookup key — for groups this is
    // the groupId, NOT a "name:Foo" sentinel like desktop's DBM uses.
    // The fallback there made unnamed groups un-keyable and rotted on
    // rename; new code requires a real ID.
    q.exec(
        "CREATE TABLE IF NOT EXISTS contacts ("
        "  peer_id          TEXT PRIMARY KEY NOT NULL,"
        "  name             TEXT NOT NULL DEFAULT '',"
        "  subtitle         TEXT NOT NULL DEFAULT '',"
        "  keys             TEXT NOT NULL DEFAULT '',"
        "  is_blocked       INTEGER NOT NULL DEFAULT 0,"
        "  is_group         INTEGER NOT NULL DEFAULT 0,"
        "  group_id         TEXT NOT NULL DEFAULT '',"
        "  avatar           TEXT NOT NULL DEFAULT '',"
        "  last_active      INTEGER NOT NULL DEFAULT 0,"
        "  in_address_book  INTEGER NOT NULL DEFAULT 1,"
        "  kem_pub          BLOB"
        ");"
    );
    // Idempotent additive migrations for a desktop DBM-created table
    // that pre-dates new columns.  SQLite errors with "duplicate column"
    // if the column exists; we swallow that — q.exec just returns false.
    q.exec("ALTER TABLE contacts ADD COLUMN is_blocked       INTEGER NOT NULL DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN is_group         INTEGER NOT NULL DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN group_id         TEXT    NOT NULL DEFAULT '';");
    q.exec("ALTER TABLE contacts ADD COLUMN avatar           TEXT    NOT NULL DEFAULT '';");
    q.exec("ALTER TABLE contacts ADD COLUMN last_active      INTEGER NOT NULL DEFAULT 0;");
    q.exec("ALTER TABLE contacts ADD COLUMN in_address_book  INTEGER NOT NULL DEFAULT 1;");
    q.exec("ALTER TABLE contacts ADD COLUMN kem_pub          BLOB;");

    // messages: FK to contacts so deleteContact cascades.  Index on
    // (peer_id, timestamp) so loadMessages doesn't full-scan once
    // history grows past a few thousand rows.
    q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  peer_id      TEXT NOT NULL,"
        "  sent         INTEGER NOT NULL,"
        "  text         TEXT NOT NULL DEFAULT '',"
        "  timestamp    INTEGER NOT NULL,"
        "  msg_id       TEXT NOT NULL DEFAULT '',"
        "  sender_name  TEXT NOT NULL DEFAULT '',"
        "  FOREIGN KEY(peer_id) REFERENCES contacts(peer_id) ON DELETE CASCADE"
        ");"
    );
    q.exec("ALTER TABLE messages ADD COLUMN msg_id      TEXT NOT NULL DEFAULT '';");
    q.exec("ALTER TABLE messages ADD COLUMN sender_name TEXT NOT NULL DEFAULT '';");
    q.exec("CREATE INDEX IF NOT EXISTS idx_messages_peer_ts"
           " ON messages(peer_id, timestamp);");

    q.exec(
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL DEFAULT ''"
        ");"
    );

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
}

void AppDataStore::updateLastActive(const std::string& peerIdB64u)
{
    if (peerIdB64u.empty() || !m_db) return;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET last_active=:ts WHERE peer_id=:peer_id;");
    q.bindValue(":ts", static_cast<int64_t>(time(nullptr)));
    q.bindValue(":peer_id", peerIdB64u);
    q.exec();
}

// ── Contacts ────────────────────────────────────────────────────────────────

bool AppDataStore::saveContact(const Contact& c)
{
    if (!m_db || c.peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare(
        "INSERT INTO contacts"
        " (peer_id,name,subtitle,keys,is_blocked,is_group,group_id,avatar,"
        "  last_active,in_address_book)"
        " VALUES (:peer_id,:name,:subtitle,:keys,:is_blocked,:is_group,"
        "         :group_id,:avatar,:last_active,:in_ab)"
        " ON CONFLICT(peer_id) DO UPDATE SET"
        "   name=excluded.name,"
        "   subtitle=excluded.subtitle,"
        "   keys=excluded.keys,"
        "   is_blocked=excluded.is_blocked,"
        "   is_group=excluded.is_group,"
        "   group_id=excluded.group_id,"
        "   avatar=excluded.avatar,"
        "   in_address_book=excluded.in_address_book;"
    );
    q.bindValue(":peer_id",     c.peerIdB64u);
    q.bindValue(":name",        encryptField(c.name));
    q.bindValue(":subtitle",    encryptField(c.subtitle));
    q.bindValue(":keys",        encryptField(joinKeys(c.keys)));
    q.bindValue(":is_blocked",  c.isBlocked ? 1 : 0);
    q.bindValue(":is_group",    c.isGroup   ? 1 : 0);
    // Audit #3 L1: encrypt group_id alongside name/keys/avatar.  All
    // other PII-shaped contact fields are field-encrypted; leaving
    // group_id plaintext meant a SQLCipher-page-key compromise still
    // leaked group membership topology.
    q.bindValue(":group_id",    encryptField(c.groupId));
    q.bindValue(":avatar",      encryptField(c.avatarB64));
    q.bindValue(":last_active", c.lastActiveSecs);
    q.bindValue(":in_ab",       c.inAddressBook ? 1 : 0);
    return q.exec();
}

bool AppDataStore::deleteContact(const std::string& peerIdB64u)
{
    if (!m_db || peerIdB64u.empty()) return false;
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
        "SELECT peer_id,name,subtitle,keys,is_blocked,is_group,"
        "       group_id,avatar,last_active,in_address_book"
        " FROM contacts ORDER BY last_active DESC, rowid ASC;"
    );
    if (!q.exec()) return;
    while (q.next()) {
        Contact c;
        c.peerIdB64u     = q.valueText(0);
        c.name           = decryptField(q.valueText(1));
        c.subtitle       = decryptField(q.valueText(2));
        c.keys           = splitKeys(decryptField(q.valueText(3)));
        c.isBlocked      = q.valueInt(4) == 1;
        c.isGroup        = q.valueInt(5) == 1;
        c.groupId        = decryptField(q.valueText(6));
        c.avatarB64      = decryptField(q.valueText(7));
        c.lastActiveSecs = q.valueInt64(8);
        c.inAddressBook  = q.valueInt(9) == 1;
        cb(c);
    }
}

bool AppDataStore::saveContactAvatar(const std::string& peerIdB64u,
                                     const std::string& avatarB64)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("UPDATE contacts SET avatar=:av WHERE peer_id=:pid;");
    q.bindValue(":av",  encryptField(avatarB64));
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

AppDataStore::Bytes AppDataStore::loadContactKemPub(const std::string& peerIdB64u) const
{
    if (!m_db || peerIdB64u.empty()) return {};
    SqlCipherQuery q(m_db->handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:pid;");
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

// ── Messages ────────────────────────────────────────────────────────────────

bool AppDataStore::saveMessage(const std::string& peerIdB64u, const Message& m)
{
    if (!m_db || peerIdB64u.empty()) return false;

    // Single transaction so the contact-stub INSERT, message INSERT,
    // and last_active UPDATE are atomic.  Desktop DBM ran INSERT +
    // last_active as two separate fsyncs which both doubled the write
    // latency and left a window where a crash mid-pair would store the
    // message without the activity bump.
    Tx tx(m_db->handle());

    // FK guarantee: the messages.peer_id FK requires a contacts row to
    // exist before the INSERT can land.  iOS callers append to their
    // in-memory message array before they have a chance to create the
    // contact row (e.g. inbound from a stranger we've never added),
    // so silently ensure a minimal stub row here.  INSERT OR IGNORE
    // means an existing row (with its is_group / in_address_book /
    // name / etc. intact) is left alone — only true strangers get a
    // fresh stub with in_address_book=0.
    {
        SqlCipherQuery ensure(*m_db);
        ensure.prepare(
            "INSERT OR IGNORE INTO contacts (peer_id, in_address_book)"
            " VALUES (:peer_id, 0);"
        );
        ensure.bindValue(":peer_id", peerIdB64u);
        ensure.exec();
    }

    {
        SqlCipherQuery q(*m_db);
        q.prepare(
            "INSERT INTO messages (peer_id,sent,text,timestamp,msg_id,sender_name)"
            " VALUES (:peer_id,:sent,:text,:ts,:msg_id,:sender_name);"
        );
        q.bindValue(":peer_id",     peerIdB64u);
        q.bindValue(":sent",        m.sent ? 1 : 0);
        q.bindValue(":text",        encryptField(m.text));
        q.bindValue(":ts",          m.timestampSecs);
        q.bindValue(":msg_id",      m.msgId);
        q.bindValue(":sender_name", encryptField(m.senderName));
        if (!q.exec()) return false;
    }
    updateLastActive(peerIdB64u);
    return tx.commit();
}

void AppDataStore::loadMessages(const std::string& peerIdB64u,
                                const std::function<void(const Message&)>& cb) const
{
    if (!m_db || !cb || peerIdB64u.empty()) return;
    SqlCipherQuery q(m_db->handle());
    q.prepare(
        "SELECT sent,text,timestamp,msg_id,sender_name FROM messages"
        " WHERE peer_id=:peer_id ORDER BY timestamp ASC, id ASC;"
    );
    q.bindValue(":peer_id", peerIdB64u);
    if (!q.exec()) return;
    while (q.next()) {
        Message m;
        m.sent          = q.valueInt(0) == 1;
        m.text          = decryptField(q.valueText(1));
        m.timestampSecs = q.valueInt64(2);
        m.msgId         = q.valueText(3);
        m.senderName    = decryptField(q.valueText(4));
        cb(m);
    }
}

bool AppDataStore::deleteMessages(const std::string& peerIdB64u)
{
    if (!m_db || peerIdB64u.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("DELETE FROM messages WHERE peer_id=:peer_id;");
    q.bindValue(":peer_id", peerIdB64u);
    return q.exec();
}

// ── Settings ────────────────────────────────────────────────────────────────

bool AppDataStore::saveSetting(const std::string& key, const std::string& value)
{
    if (!m_db || key.empty()) return false;
    SqlCipherQuery q(*m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(:k,:v);");
    q.bindValue(":k", key);
    // Audit #3 M5: encrypt every value at the storage layer so a
    // page-key compromise can't harvest relay URLs / TURN creds /
    // display name / similar.  The old comment "callers encrypt
    // sensitive settings themselves" was a paper policy with zero
    // enforcement — now the field is always wrapped.
    q.bindValue(":v", encryptField(value));
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
        return decryptField(q.valueText(0));
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
    q.bindValue(":fn",     encryptField(r.fileName));
    q.bindValue(":fs",     r.fileSize);
    q.bindValue(":pid",    r.peerIdB64u);
    q.bindValue(":pn",     encryptField(r.peerName));
    q.bindValue(":ts",     r.timestampSecs);
    q.bindValue(":sent",   r.sent ? 1 : 0);
    q.bindValue(":status", r.status);
    q.bindValue(":ct",     r.chunksTotal);
    q.bindValue(":cc",     r.chunksComplete);
    q.bindValue(":sp",     encryptField(r.savedPath));
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
        r.fileName        = decryptField(q.valueText(1));
        r.fileSize        = q.valueInt64(2);
        r.peerIdB64u      = q.valueText(3);
        r.peerName        = decryptField(q.valueText(4));
        r.timestampSecs   = q.valueInt64(5);
        r.sent            = q.valueInt(6) == 1;
        r.status          = q.valueInt(7);
        r.chunksTotal     = q.valueInt(8);
        r.chunksComplete  = q.valueInt(9);
        r.savedPath       = decryptField(q.valueText(10));
        r.chatKey         = chatKey;
        cb(r);
    }
}
