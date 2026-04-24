#include "SqlCipherDb.hpp"
#include <sqlite3.h>
#include <sodium.h>
#include <cstring>

// Debug logging — see log.hpp.
#include "log.hpp"

// ─── SqlCipherDb ─────────────────────────────────────────────────────────────

SqlCipherDb::~SqlCipherDb() { close(); }

bool SqlCipherDb::open(const std::string& path, const Bytes& key)
{
    close();
    m_path = path;

    int rc = sqlite3_open_v2(path.c_str(), &m_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                             SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_PRIVATECACHE,
                             nullptr);
    if (rc != SQLITE_OK) {
        m_lastError = m_db ? sqlite3_errmsg(m_db) : "sqlite3_open_v2 failed";
        P2P_WARN("SqlCipherDb::open failed");
        sqlite3_close_v2(m_db);
        m_db = nullptr;
        return false;
    }

    // ── Apply encryption key ─────────────────────────────────────────────
    if (!key.empty()) {
#ifdef SQLITE_HAS_CODEC
        // Preferred: native sqlite3_key (available when linked against SQLCipher)
        rc = sqlite3_key(m_db, key.data(), static_cast<int>(key.size()));
        if (rc != SQLITE_OK) {
            m_lastError = sqlite3_errmsg(m_db);
            P2P_WARN("sqlite3_key failed: " << m_lastError);
            close();
            return false;
        }
#else
        // Fallback: PRAGMA key with hex-encoded raw key.
        // Build the hex key ourselves so we can zero it right after use.
        std::string hexKey;
        hexKey.resize(key.size() * 2);
        static const char kHex[] = "0123456789abcdef";
        for (size_t i = 0; i < key.size(); ++i) {
            hexKey[i * 2]     = kHex[(key[i] >> 4) & 0xF];
            hexKey[i * 2 + 1] = kHex[key[i] & 0xF];
        }
        std::string pragma = "PRAGMA key = \"x'" + hexKey + "'\";";
        char* err = nullptr;
        rc = sqlite3_exec(m_db, pragma.c_str(), nullptr, nullptr, &err);
        // Zero key material from local strings immediately.
        sodium_memzero(hexKey.data(), hexKey.size());
        sodium_memzero(pragma.data(), pragma.size());
        if (rc != SQLITE_OK) {
            m_lastError = err ? err : "PRAGMA key failed";
            sqlite3_free(err);
            P2P_WARN("SqlCipherDb: PRAGMA key failed");
            close();
            return false;
        }
#endif
        // Verify key by reading sqlite_master.
        char* verifyErr = nullptr;
        rc = sqlite3_exec(m_db, "SELECT count(*) FROM sqlite_master;",
                          nullptr, nullptr, &verifyErr);
        if (rc != SQLITE_OK) {
            m_lastError = verifyErr ? verifyErr : "Key verification failed";
            sqlite3_free(verifyErr);
            P2P_WARN("SqlCipherDb: wrong key or unencrypted database");
            close();
            return false;
        }
    }

    // ── Verify SQLCipher ────────────────────────────────────────────────
    // No unencrypted databases allowed — refuse to run on plain sqlite3.
    m_isSqlCipher = false;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, "PRAGMA cipher_version;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* ver = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (ver && std::strlen(ver) > 0) {
                m_isSqlCipher = true;
                P2P_LOG("SqlCipherDb: SQLCipher version " << ver);
            }
        }
        sqlite3_finalize(stmt);
    }

    if (!m_isSqlCipher) {
        m_lastError =
            "SQLCipher is required but the linked sqlite library is plain sqlite3. "
            "Install SQLCipher and rebuild.";
        P2P_CRITICAL("SqlCipherDb: SQLCipher required but not available");
        close();
        return false;
    }

    // ── Standard pragmas ─────────────────────────────────────────────────
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA cipher_memory_security=ON;", nullptr, nullptr, nullptr);

    P2P_LOG("SqlCipherDb: opened " << path << " (encrypted)");
    return true;
}

void SqlCipherDb::close()
{
    if (m_db) {
        sqlite3_close_v2(m_db);
        m_db = nullptr;
    }
}

// ─── SqlCipherQuery ──────────────────────────────────────────────────────────

SqlCipherQuery::SqlCipherQuery(SqlCipherDb& db)
    : m_db(db.handle()) {}

SqlCipherQuery::SqlCipherQuery(sqlite3* db)
    : m_db(db) {}

SqlCipherQuery::~SqlCipherQuery() { finalize(); }

void SqlCipherQuery::finalize()
{
    if (m_stmt) {
        sqlite3_finalize(m_stmt);
        m_stmt = nullptr;
    }
    m_binds.clear();
    m_stepped = false;
}

bool SqlCipherQuery::prepare(const std::string& sql)
{
    finalize();
    int rc = sqlite3_prepare_v2(m_db, sql.data(), static_cast<int>(sql.size()),
                                 &m_stmt, nullptr);
    if (rc != SQLITE_OK) {
        m_lastError = sqlite3_errmsg(m_db);
        return false;
    }
    return true;
}

void SqlCipherQuery::bindValue(const std::string& key, std::nullptr_t) {
    m_binds.push_back({key, BindKind::Null, 0, 0.0, {}, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, int v) {
    m_binds.push_back({key, BindKind::Int, int64_t(v), 0.0, {}, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, int64_t v) {
    m_binds.push_back({key, BindKind::Int64, v, 0.0, {}, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, double v) {
    m_binds.push_back({key, BindKind::Double, 0, v, {}, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, bool v) {
    m_binds.push_back({key, BindKind::Bool, v ? 1 : 0, 0.0, {}, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, const std::string& v) {
    m_binds.push_back({key, BindKind::Text, 0, 0.0, v, {}});
}
void SqlCipherQuery::bindValue(const std::string& key, const char* v) {
    m_binds.push_back({key, BindKind::Text, 0, 0.0, v ? std::string(v) : std::string(), {}});
}
void SqlCipherQuery::bindValue(const std::string& key, const Bytes& v) {
    m_binds.push_back({key, BindKind::Blob, 0, 0.0, {}, v});
}

static void applyBinds(sqlite3_stmt* stmt,
                        const std::vector<SqlCipherQuery::Bind>& binds)
{
    for (const auto& b : binds) {
        int idx = sqlite3_bind_parameter_index(stmt, b.key.c_str());
        if (idx == 0) continue;  // unknown placeholder

        using K = SqlCipherQuery::BindKind;
        switch (b.kind) {
        case K::Null:
            sqlite3_bind_null(stmt, idx);
            break;
        case K::Int:
        case K::Bool:
            sqlite3_bind_int(stmt, idx, static_cast<int>(b.ival));
            break;
        case K::Int64:
            sqlite3_bind_int64(stmt, idx, b.ival);
            break;
        case K::Double:
            sqlite3_bind_double(stmt, idx, b.dval);
            break;
        case K::Text:
            sqlite3_bind_text(stmt, idx, b.sval.data(),
                              static_cast<int>(b.sval.size()), SQLITE_TRANSIENT);
            break;
        case K::Blob:
            sqlite3_bind_blob(stmt, idx,
                              b.bval.empty() ? "" : reinterpret_cast<const char*>(b.bval.data()),
                              static_cast<int>(b.bval.size()), SQLITE_TRANSIENT);
            break;
        }
    }
}

bool SqlCipherQuery::exec(const std::string& sql)
{
    finalize();
    char* err = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        m_lastError = err ? err : sqlite3_errmsg(m_db);
        sqlite3_free(err);
        return false;
    }
    m_changes = sqlite3_changes(m_db);
    return true;
}

bool SqlCipherQuery::exec()
{
    if (!m_stmt) {
        m_lastError = "No prepared statement";
        return false;
    }

    sqlite3_reset(m_stmt);
    sqlite3_clear_bindings(m_stmt);
    applyBinds(m_stmt, m_binds);

    m_stepRc = sqlite3_step(m_stmt);
    m_stepped = true;
    m_changes = sqlite3_changes(m_db);

    if (m_stepRc != SQLITE_ROW && m_stepRc != SQLITE_DONE) {
        m_lastError = sqlite3_errmsg(m_db);
        return false;
    }
    return true;
}

bool SqlCipherQuery::next()
{
    if (!m_stmt) return false;

    if (m_stepped) {
        m_stepped = false;
        return m_stepRc == SQLITE_ROW;
    }

    int rc = sqlite3_step(m_stmt);
    return rc == SQLITE_ROW;
}

// ─── Column accessors ────────────────────────────────────────────────────────

std::string SqlCipherQuery::valueText(int column) const
{
    if (!m_stmt) return {};
    const char* txt = reinterpret_cast<const char*>(
        sqlite3_column_text(m_stmt, column));
    const int sz = sqlite3_column_bytes(m_stmt, column);
    return txt ? std::string(txt, size_t(sz)) : std::string();
}

int64_t SqlCipherQuery::valueInt64(int column) const
{
    return m_stmt ? sqlite3_column_int64(m_stmt, column) : 0;
}

int SqlCipherQuery::valueInt(int column) const
{
    return m_stmt ? sqlite3_column_int(m_stmt, column) : 0;
}

double SqlCipherQuery::valueDouble(int column) const
{
    return m_stmt ? sqlite3_column_double(m_stmt, column) : 0.0;
}

Bytes SqlCipherQuery::valueBlob(int column) const
{
    if (!m_stmt) return {};
    const void* data = sqlite3_column_blob(m_stmt, column);
    const int sz = sqlite3_column_bytes(m_stmt, column);
    if (!data || sz <= 0) return {};
    const uint8_t* p = static_cast<const uint8_t*>(data);
    return Bytes(p, p + sz);
}

bool SqlCipherQuery::valueBool(int column) const
{
    return m_stmt ? sqlite3_column_int(m_stmt, column) != 0 : false;
}

bool SqlCipherQuery::isNull(int column) const
{
    return m_stmt ? (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) : true;
}

int SqlCipherQuery::numRowsAffected() const
{
    return m_changes;
}
