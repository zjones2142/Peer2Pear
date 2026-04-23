#pragma once

// Tiny inline helpers for the Qt UI ↔ std::-typed AppDataStore boundary.
// Used at render sites only — chatview/mainwindow now hold
// AppDataStore::Contact / Message / FileRecord directly (std::string +
// int64_t epoch seconds), and convert to QString / QDateTime here when
// pushing into QLabel / QListWidgetItem / QDateTime formatters.
//
// Not a facade — these are pure type marshalers, no DB knowledge.  The
// previous AppDataStoreQt.hpp facade (and the older DatabaseManager
// class) were retired in favor of having desktop call AppDataStore
// methods directly with their native std types.

#include <QString>
#include <QDateTime>
#include <QStringList>
#include <QTimeZone>

#include <cstdint>
#include <string>
#include <vector>

namespace qtbridge {

inline QString qstr(const std::string& s) {
    return QString::fromStdString(s);
}

inline std::string stdstr(const QString& s) {
    return s.toStdString();
}

inline QDateTime qdate(int64_t epochSecs) {
    if (epochSecs <= 0) return QDateTime();
    return QDateTime::fromSecsSinceEpoch(epochSecs, QTimeZone::utc()).toLocalTime();
}

inline int64_t epochSecs(const QDateTime& dt) {
    return dt.isValid() ? dt.toUTC().toSecsSinceEpoch() : 0;
}

inline QStringList qstrList(const std::vector<std::string>& v) {
    QStringList out;
    out.reserve(static_cast<int>(v.size()));
    for (const auto& s : v) out << QString::fromStdString(s);
    return out;
}

inline std::vector<std::string> stdstrList(const QStringList& l) {
    std::vector<std::string> out;
    out.reserve(l.size());
    for (const QString& s : l) out.push_back(s.toStdString());
    return out;
}

}  // namespace qtbridge
