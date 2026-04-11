#include "SqlCipherDb.hpp"
#include <sqlite3.h>
#include <QDebug>
#include <QByteArray>
#include <sodium.h>
#include <cstring>

// ─── SqlCipherDb ─────────────────────────────────────────────────────────────

SqlCipherDb::~SqlCipherDb() { close(); }

bool SqlCipherDb::open(const QString& path, const QByteArray& key)
{
    close();
    m_path = path;

    const QByteArray pathUtf8 = path.toUtf8();
    int rc = sqlite3_open_v2(pathUtf8.constData(), &m_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                             SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_PRIVATECACHE,
                             nullptr);
    if (rc != SQLITE_OK) {
        m_lastError = QString::fromUtf8(sqlite3_errmsg(m_db));
        qWarning() << "SqlCipherDb::open failed";
        sqlite3_close_v2(m_db);
        m_db = nullptr;
        return false;
    }

    // ── Apply encryption key ─────────────────────────────────────────────
    if (!key.isEmpty()) {
#ifdef SQLITE_HAS_CODEC
        // Preferred: native sqlite3_key (available when linked against SQLCipher)
        rc = sqlite3_key(m_db, key.constData(), key.size());
        if (rc != SQLITE_OK) {
            m_lastError = QString::fromUtf8(sqlite3_errmsg(m_db));
            qWarning() << "sqlite3_key failed:" << m_lastError;
            close();
            return false;
        }
#else
        // Fallback: PRAGMA key with hex-encoded raw key
        QString hexKey = QString::fromLatin1(key.toHex());
        QString pragma = QStringLiteral("PRAGMA key = \"x'%1'\";").arg(hexKey);
        char* err = nullptr;
        rc = sqlite3_exec(m_db, pragma.toUtf8().constData(), nullptr, nullptr, &err);
        // Zero key material from local strings immediately
        sodium_memzero(hexKey.data(), static_cast<size_t>(hexKey.size()) * sizeof(QChar));
        sodium_memzero(pragma.data(), static_cast<size_t>(pragma.size()) * sizeof(QChar));
        if (rc != SQLITE_OK) {
            m_lastError = err ? QString::fromUtf8(err) : QStringLiteral("PRAGMA key failed");
            sqlite3_free(err);
            qWarning() << "SqlCipherDb: PRAGMA key failed";
            close();
            return false;
        }
#endif
        // Verify key by reading sqlite_master
        char* verifyErr = nullptr;
        rc = sqlite3_exec(m_db, "SELECT count(*) FROM sqlite_master;",
                          nullptr, nullptr, &verifyErr);
        if (rc != SQLITE_OK) {
            m_lastError = verifyErr ? QString::fromUtf8(verifyErr)
                                    : QStringLiteral("Key verification failed");
            sqlite3_free(verifyErr);
            qWarning() << "SqlCipherDb: wrong key or unencrypted database";
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
                qDebug() << "SqlCipherDb: SQLCipher version" << ver;
            }
        }
        sqlite3_finalize(stmt);
    }

    if (!m_isSqlCipher) {
        m_lastError = QStringLiteral(
            "SQLCipher is required but the linked sqlite library is plain sqlite3. "
            "Install SQLCipher and rebuild.");
        qCritical() << "SqlCipherDb: SQLCipher required but not available";
        close();
        return false;
    }

    // ── Standard pragmas ─────────────────────────────────────────────────
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA cipher_memory_security=ON;", nullptr, nullptr, nullptr);

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "SqlCipherDb: opened" << path << "(encrypted)";
#endif
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

bool SqlCipherQuery::prepare(const QString& sql)
{
    finalize();
    const QByteArray utf8 = sql.toUtf8();
    int rc = sqlite3_prepare_v2(m_db, utf8.constData(), utf8.size(), &m_stmt, nullptr);
    if (rc != SQLITE_OK) {
        m_lastError = QString::fromUtf8(sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

void SqlCipherQuery::bindValue(const QString& placeholder, const QVariant& val)
{
    m_binds.append({placeholder, val});
}

static void applyBinds(sqlite3_stmt* stmt,
                        const QVector<QPair<QString, QVariant>>& binds)
{
    for (const auto& [name, val] : binds) {
        int idx = sqlite3_bind_parameter_index(stmt, name.toUtf8().constData());
        if (idx == 0) continue;  // unknown placeholder

        if (val.isNull()) {
            sqlite3_bind_null(stmt, idx);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        } else if (val.typeId() == QMetaType::Int) {
#else
        } else if (val.type() == QVariant::Int) {
#endif
            sqlite3_bind_int(stmt, idx, val.toInt());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        } else if (val.typeId() == QMetaType::LongLong ||
                   val.typeId() == QMetaType::UInt ||
                   val.typeId() == QMetaType::ULongLong) {
#else
        } else if (val.type() == QVariant::LongLong ||
                   val.type() == QVariant::UInt ||
                   val.type() == QVariant::ULongLong) {
#endif
            sqlite3_bind_int64(stmt, idx, val.toLongLong());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        } else if (val.typeId() == QMetaType::Double) {
#else
        } else if (val.type() == QVariant::Double) {
#endif
            sqlite3_bind_double(stmt, idx, val.toDouble());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        } else if (val.typeId() == QMetaType::QByteArray) {
#else
        } else if (val.type() == QVariant::ByteArray) {
#endif
            const QByteArray ba = val.toByteArray();
            sqlite3_bind_blob(stmt, idx, ba.constData(), ba.size(), SQLITE_TRANSIENT);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        } else if (val.typeId() == QMetaType::Bool) {
#else
        } else if (val.type() == QVariant::Bool) {
#endif
            sqlite3_bind_int(stmt, idx, val.toBool() ? 1 : 0);
        } else {
            // Default: bind as text
            const QByteArray utf8 = val.toString().toUtf8();
            sqlite3_bind_text(stmt, idx, utf8.constData(), utf8.size(), SQLITE_TRANSIENT);
        }
    }
}

bool SqlCipherQuery::exec(const QString& sql)
{
    finalize();
    char* err = nullptr;
    int rc = sqlite3_exec(m_db, sql.toUtf8().constData(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        m_lastError = err ? QString::fromUtf8(err) : QString::fromUtf8(sqlite3_errmsg(m_db));
        sqlite3_free(err);
        return false;
    }
    m_changes = sqlite3_changes(m_db);
    return true;
}

bool SqlCipherQuery::exec()
{
    if (!m_stmt) {
        m_lastError = QStringLiteral("No prepared statement");
        return false;
    }

    sqlite3_reset(m_stmt);
    sqlite3_clear_bindings(m_stmt);
    applyBinds(m_stmt, m_binds);

    m_stepRc = sqlite3_step(m_stmt);
    m_stepped = true;
    m_changes = sqlite3_changes(m_db);

    if (m_stepRc != SQLITE_ROW && m_stepRc != SQLITE_DONE) {
        m_lastError = QString::fromUtf8(sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool SqlCipherQuery::next()
{
    if (!m_stmt) return false;

    if (m_stepped) {
        // First call after exec() — use the saved step result
        m_stepped = false;
        return m_stepRc == SQLITE_ROW;
    }

    int rc = sqlite3_step(m_stmt);
    return rc == SQLITE_ROW;
}

QVariant SqlCipherQuery::value(int column) const
{
    if (!m_stmt) return {};

    int type = sqlite3_column_type(m_stmt, column);
    switch (type) {
    case SQLITE_INTEGER:
        return QVariant(static_cast<qlonglong>(sqlite3_column_int64(m_stmt, column)));
    case SQLITE_FLOAT:
        return QVariant(sqlite3_column_double(m_stmt, column));
    case SQLITE_BLOB: {
        const void* data = sqlite3_column_blob(m_stmt, column);
        int sz = sqlite3_column_bytes(m_stmt, column);
        return QVariant(QByteArray(static_cast<const char*>(data), sz));
    }
    case SQLITE_NULL:
        return QVariant();
    case SQLITE_TEXT:
    default: {
        const char* txt = reinterpret_cast<const char*>(sqlite3_column_text(m_stmt, column));
        int sz = sqlite3_column_bytes(m_stmt, column);
        return QVariant(QString::fromUtf8(txt, sz));
    }
    }
}

int SqlCipherQuery::numRowsAffected() const
{
    return m_changes;
}
