#pragma once

#include "types.hpp"

#include <cstdint>
#include <string>
#include <vector>

#ifdef QT_CORE_LIB
#include <QByteArray>
#include <QString>
#endif

struct sqlite3;
struct sqlite3_stmt;

/*
 * SqlCipherDb — thin C++ wrapper around the sqlite3 / SQLCipher C API.
 *
 * Replaces QSqlDatabase so the app has zero dependency on Qt::Sql.
 * When linked against SQLCipher (instead of plain sqlite3), the database
 * is transparently AES-256-encrypted at the page level.
 *
 * Types: std::string (UTF-8) for paths/SQL/text, std::vector<uint8_t>
 * (Bytes) for keys and blob columns.
 */
class SqlCipherDb {
public:

    SqlCipherDb() = default;
    ~SqlCipherDb();

    SqlCipherDb(const SqlCipherDb&) = delete;
    SqlCipherDb& operator=(const SqlCipherDb&) = delete;

    /// Open (or create) a database file.
    /// If @p key is non-empty it is applied via sqlite3_key / PRAGMA key.
    bool open(const std::string& path, const Bytes& key = {});
    void close();
    bool isOpen() const { return m_db != nullptr; }

    sqlite3* handle() const { return m_db; }

    /// True when the linked sqlite library is actually SQLCipher.
    bool isSqlCipher() const { return m_isSqlCipher; }

    std::string lastError()    const { return m_lastError; }
    std::string databaseName() const { return m_path; }

#ifdef QT_CORE_LIB
    // ── Qt interop (desktop convenience) ────────────────────────────────
    // These disappear from iOS builds.  Desktop callers that already speak
    // QString/QByteArray avoid a migration cascade.
    bool open(const QString& path, const QByteArray& key = {}) {
        const std::string p = path.toStdString();
        Bytes k(reinterpret_cast<const uint8_t*>(key.constData()),
                reinterpret_cast<const uint8_t*>(key.constData()) + key.size());
        return open(p, k);
    }
    QString lastErrorQ()    const { return QString::fromStdString(m_lastError); }
    QString databaseNameQ() const { return QString::fromStdString(m_path); }
#endif

private:
    sqlite3*    m_db = nullptr;
    std::string m_path;
    std::string m_lastError;
    bool        m_isSqlCipher = false;
};

/*
 * SqlCipherQuery — thin wrapper around sqlite3_stmt.
 *
 * API mirrors the subset of QSqlQuery used in the project:
 *   prepare → bindValue → exec → next → value*()
 *
 * bindValue is overloaded per SQLite storage class so callers don't need
 * a variant type.  value*() is split into typed accessors (valueText,
 * valueInt64, valueBlob, …) — SQLite's dynamic typing is too permissive
 * to hide behind a single return type without losing information.
 */
class SqlCipherQuery {
public:

    /// Construct from a SqlCipherDb (convenience).
    explicit SqlCipherQuery(SqlCipherDb& db);
    /// Construct from a raw sqlite3 handle.
    explicit SqlCipherQuery(sqlite3* db);
    ~SqlCipherQuery();

    SqlCipherQuery(const SqlCipherQuery&) = delete;
    SqlCipherQuery& operator=(const SqlCipherQuery&) = delete;

    bool prepare(const std::string& sql);

    // Typed binders — one per SQLite storage class + null.
    // Placeholder keys follow sqlite3's named-parameter syntax, e.g. ":pid".
    void bindValue(const std::string& key, std::nullptr_t);
    void bindValue(const std::string& key, int v);
    void bindValue(const std::string& key, int64_t v);
    void bindValue(const std::string& key, double v);
    void bindValue(const std::string& key, bool v);
    void bindValue(const std::string& key, const std::string& v);
    void bindValue(const std::string& key, const char* v);   // literals
    void bindValue(const std::string& key, const Bytes& v);  // BLOB

    bool exec(const std::string& sql);   // one-shot exec (no prepare)
    bool exec();                          // execute a prepared statement

    bool next();

    // Typed column accessors.  Callers pick based on the column's SQL type.
    // Auto-coerce follows sqlite3's documented conversions (e.g. valueText
    // on an integer column stringifies).
    std::string valueText(int column) const;
    int64_t     valueInt64(int column) const;
    int         valueInt(int column) const;
    double      valueDouble(int column) const;
    Bytes       valueBlob(int column) const;
    bool        valueBool(int column) const;
    bool        isNull(int column) const;

    int         numRowsAffected() const;
    std::string lastError() const { return m_lastError; }

#ifdef QT_CORE_LIB
    // ── Qt interop (desktop convenience) ────────────────────────────────
    // Value overloads only — the key stays std::string so prepare/exec
    // don't become ambiguous with string literals.  These disappear from
    // iOS builds.
    void bindValue(const std::string& key, const QString& v) {
        bindValue(key, v.toStdString());
    }
    void bindValue(const std::string& key, const QByteArray& v) {
        Bytes b(reinterpret_cast<const uint8_t*>(v.constData()),
                reinterpret_cast<const uint8_t*>(v.constData()) + v.size());
        bindValue(key, b);
    }

    struct QValue {
        const SqlCipherQuery* q;
        int col;
        QString    toString()    const { return QString::fromStdString(q->valueText(col)); }
        QByteArray toByteArray() const {
            const Bytes b = q->valueBlob(col);
            return QByteArray(reinterpret_cast<const char*>(b.data()),
                              static_cast<int>(b.size()));
        }
        int       toInt()      const { return q->valueInt(col); }
        qlonglong toLongLong() const { return q->valueInt64(col); }
        double    toDouble()   const { return q->valueDouble(col); }
        bool      toBool()     const { return q->valueBool(col); }
        bool      isNull()     const { return q->isNull(col); }
    };
    QValue value(int column) const { return QValue{this, column}; }

    QString lastErrorQ() const { return QString::fromStdString(m_lastError); }
#endif

    // Public so the anonymous-namespace applyBinds() helper in the .cpp can
    // see it.  Callers should treat these as implementation details.
    enum class BindKind { Null, Int, Int64, Double, Bool, Text, Blob };
    struct Bind {
        std::string key;
        BindKind    kind = BindKind::Null;
        int64_t     ival = 0;
        double      dval = 0.0;
        std::string sval;
        Bytes       bval;
    };

private:
    void finalize();

    sqlite3*      m_db   = nullptr;
    sqlite3_stmt* m_stmt = nullptr;
    std::string   m_lastError;

    std::vector<Bind> m_binds;

    bool m_stepped = false;  // true after first sqlite3_step in exec()
    int  m_stepRc  = 0;      // result of the first step
    int  m_changes = 0;      // sqlite3_changes after exec
};
