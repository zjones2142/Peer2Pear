#pragma once

#include <QString>
#include <QVariant>
#include <QVector>

struct sqlite3;
struct sqlite3_stmt;

/*
 * SqlCipherDb — thin C++ wrapper around the sqlite3 / SQLCipher C API.
 *
 * Replaces QSqlDatabase so the app has zero dependency on Qt::Sql.
 * When linked against SQLCipher (instead of plain sqlite3), the database
 * is transparently AES-256-encrypted at the page level.
 */
class SqlCipherDb {
public:
    SqlCipherDb() = default;
    ~SqlCipherDb();

    SqlCipherDb(const SqlCipherDb&) = delete;
    SqlCipherDb& operator=(const SqlCipherDb&) = delete;

    /// Open (or create) a database file.
    /// If @p key is non-empty it is applied via sqlite3_key / PRAGMA key.
    bool open(const QString& path, const QByteArray& key = {});
    void close();
    bool isOpen() const { return m_db != nullptr; }

    sqlite3* handle() const { return m_db; }

    /// True when the linked sqlite library is actually SQLCipher.
    bool isSqlCipher() const { return m_isSqlCipher; }

    QString lastError() const { return m_lastError; }
    QString databaseName() const { return m_path; }

private:
    sqlite3* m_db = nullptr;
    QString  m_path;
    QString  m_lastError;
    bool     m_isSqlCipher = false;
};

/*
 * SqlCipherQuery — thin wrapper around sqlite3_stmt.
 *
 * API mirrors the subset of QSqlQuery used in the project:
 *   prepare → bindValue → exec → next → value
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

    bool prepare(const QString& sql);
    void bindValue(const QString& placeholder, const QVariant& val);
    bool exec(const QString& sql);   // one-shot exec (no prepare)
    bool exec();                      // execute a prepared statement

    bool next();
    QVariant value(int column) const;

    int numRowsAffected() const;
    QString lastError() const { return m_lastError; }

private:
    void finalize();

    sqlite3*      m_db   = nullptr;
    sqlite3_stmt* m_stmt = nullptr;
    QString       m_lastError;

    // Bind map: placeholder name -> value (applied at exec time)
    QVector<QPair<QString, QVariant>> m_binds;

    bool m_stepped   = false;  // true after first sqlite3_step in exec()
    int  m_stepRc    = 0;      // result of the first step
    int  m_changes   = 0;      // sqlite3_changes after exec
};
