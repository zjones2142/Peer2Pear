#include "SessionStore.hpp"
#include <sodium.h>
#include <chrono>
#include <cstring>

#include "log.hpp"

namespace {

inline int64_t nowSecs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // anonymous namespace

SessionStore::SessionStore(SqlCipherDb& db, Bytes storeKey)
    : m_db(db)
    , m_storeKey(std::move(storeKey))
{
    createTables();
    pruneStaleHandshakes();   // G2 fix: clean up on startup
}

SessionStore::~SessionStore() {
    if (!m_storeKey.empty())
        sodium_memzero(m_storeKey.data(), m_storeKey.size());
}

void SessionStore::createTables() {
    SqlCipherQuery q(m_db);

    q.exec(
        "CREATE TABLE IF NOT EXISTS ratchet_sessions ("
        "  peer_id    TEXT PRIMARY KEY,"
        "  state_blob BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL"
        ");"
    );

    // B4 fix: skipped_message_keys table removed — RatchetSession manages
    // skipped keys in its own serialized blob (in-memory map).
    q.exec("DROP TABLE IF EXISTS skipped_message_keys;");

    q.exec(
        "CREATE TABLE IF NOT EXISTS pending_handshakes ("
        "  peer_id        TEXT PRIMARY KEY,"
        "  role           INTEGER NOT NULL,"
        "  handshake_blob BLOB NOT NULL,"
        "  created_at     INTEGER NOT NULL"
        ");"
    );
}

// ---------------------------
// Blob encryption helpers
// ---------------------------

SessionStore::Bytes SessionStore::encryptBlob(const Bytes& plaintext) const {
    if (m_storeKey.size() != 32) return {};  // no valid key — refuse to store plaintext

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    Bytes out(sizeof(nonce) + plaintext.size() +
              crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + sizeof(nonce), &clen,
        plaintext.data(),
        static_cast<unsigned long long>(plaintext.size()),
        nullptr, 0, nullptr, nonce,
        m_storeKey.data());
    std::memcpy(out.data(), nonce, sizeof(nonce));
    out.resize(sizeof(nonce) + clen);
    return out;
}

SessionStore::Bytes SessionStore::decryptBlob(const Bytes& ciphertext) const {
    const size_t kMinSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                            crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (m_storeKey.size() != 32) return {};     // no valid key — fail safe
    if (ciphertext.size() < kMinSize) return {}; // too short — treat as invalid

    const unsigned char* nonce = ciphertext.data();
    const size_t ctLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    Bytes pt(ctLen - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen,
            nullptr,
            ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            static_cast<unsigned long long>(ctLen),
            nullptr, 0, nonce,
            m_storeKey.data()) != 0) {
        return {}; // authentication failed — invalid or old plaintext blob
    }
    pt.resize(plen);
    return pt;
}

// ---------------------------
// Ratchet sessions
// ---------------------------

void SessionStore::saveSession(const std::string& peerId, const Bytes& stateBlob) {
    const int64_t now = nowSecs();
    SqlCipherQuery q(m_db);
    q.prepare(
        "INSERT INTO ratchet_sessions (peer_id, state_blob, created_at, updated_at)"
        " VALUES (:pid, :blob, :now, :now)"
        " ON CONFLICT(peer_id) DO UPDATE SET state_blob=excluded.state_blob, updated_at=excluded.updated_at;"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":blob", encryptBlob(stateBlob));
    q.bindValue(":now", now);
    if (!q.exec())
        P2P_WARN("SessionStore::saveSession: " << q.lastError());
}

SessionStore::Bytes SessionStore::loadSession(const std::string& peerId) const {
    SqlCipherQuery q(m_db.handle());
    q.prepare("SELECT state_blob FROM ratchet_sessions WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) return decryptBlob(q.valueBlob(0));
    return {};
}

void SessionStore::deleteSession(const std::string& peerId) {
    SqlCipherQuery q(m_db);
    q.prepare("DELETE FROM ratchet_sessions WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
    deletePendingHandshake(peerId);
}

// ---------------------------
// Clear all
// ---------------------------

void SessionStore::clearAll() {
    SqlCipherQuery q(m_db);
    q.exec("DELETE FROM ratchet_sessions;");
    q.exec("DELETE FROM pending_handshakes;");
    P2P_LOG("[SessionStore] Cleared all sessions, skipped keys, and pending handshakes");
}

// ---------------------------
// Pending handshakes
// ---------------------------

void SessionStore::savePendingHandshake(const std::string& peerId, int role,
                                        const Bytes& handshakeBlob) {
    const int64_t now = nowSecs();
    SqlCipherQuery q(m_db);
    q.prepare(
        "INSERT INTO pending_handshakes (peer_id, role, handshake_blob, created_at)"
        " VALUES (:pid, :role, :blob, :now)"
        " ON CONFLICT(peer_id) DO UPDATE SET role=excluded.role,"
        "   handshake_blob=excluded.handshake_blob, created_at=excluded.created_at;"
    );
    q.bindValue(":pid", peerId);
    q.bindValue(":role", role);
    q.bindValue(":blob", encryptBlob(handshakeBlob));
    q.bindValue(":now", now);
    if (!q.exec())
        P2P_WARN("SessionStore::savePendingHandshake: " << q.lastError());
}

SessionStore::Bytes SessionStore::loadPendingHandshake(const std::string& peerId,
                                                       int& roleOut) const {
    SqlCipherQuery q(m_db.handle());
    q.prepare("SELECT role, handshake_blob FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    if (q.exec() && q.next()) {
        roleOut = q.valueInt(0);
        return decryptBlob(q.valueBlob(1));
    }
    return {};
}

void SessionStore::deletePendingHandshake(const std::string& peerId) {
    SqlCipherQuery q(m_db);
    q.prepare("DELETE FROM pending_handshakes WHERE peer_id=:pid;");
    q.bindValue(":pid", peerId);
    q.exec();
}

std::vector<std::string> SessionStore::pruneStaleHandshakes(int maxAgeSecs) {
    const int64_t cutoff = nowSecs() - maxAgeSecs;
    std::vector<std::string> pruned;

    // SEC9: collect peer IDs before deleting so we can report them.
    {
        SqlCipherQuery sel(m_db.handle());
        sel.prepare("SELECT peer_id FROM pending_handshakes WHERE created_at < :cutoff;");
        sel.bindValue(":cutoff", cutoff);
        if (sel.exec()) {
            while (sel.next())
                pruned.push_back(sel.valueText(0));
        }
    }

    if (!pruned.empty()) {
        SqlCipherQuery q(m_db);
        q.prepare("DELETE FROM pending_handshakes WHERE created_at < :cutoff;");
        q.bindValue(":cutoff", cutoff);
        q.exec();
        P2P_LOG("[SessionStore] Pruned " << int(pruned.size()) << " stale pending handshakes");
    }
    return pruned;
}
