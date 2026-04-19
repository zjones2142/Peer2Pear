#pragma once
//
// Temporary Qt ↔ std bridge helpers used during the Qt-strip refactor
// (see REFACTOR_PLAN.md).
//
// Once every caller has migrated off QByteArray, this header gets deleted.
// Having the helpers in one place makes grepping "who still needs bridging"
// easy:  any file that #includes "qt_bridge_temp.hpp" is on the todo list.
//
// Rules:
//   - Do not use this header in mobile / iOS builds (Qt may not be present).
//   - Do not put anything here that isn't a pure type conversion; logic
//     lives in the class that owns the behavior.
//

#ifdef QT_CORE_LIB

#include <QByteArray>
#include <QString>
#include <sodium.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace p2p::bridge {

using Bytes = std::vector<uint8_t>;

inline Bytes toBytes(const QByteArray& q) {
    return Bytes(reinterpret_cast<const uint8_t*>(q.constData()),
                 reinterpret_cast<const uint8_t*>(q.constData()) + q.size());
}

inline QByteArray toQByteArray(const Bytes& b) {
    return QByteArray(reinterpret_cast<const char*>(b.data()),
                      static_cast<int>(b.size()));
}

// Wipe-in-place helpers that accept Qt types.  CryptoEngine::secureZero
// only takes Bytes/std::string now; these are the Qt-caller equivalents.
inline void secureZeroQ(QByteArray& buf) {
    if (!buf.isEmpty()) sodium_memzero(buf.data(), static_cast<size_t>(buf.size()));
    buf.clear();
}
inline void secureZeroQ(QString& str) {
    if (!str.isEmpty()) sodium_memzero(str.data(), static_cast<size_t>(str.size()) * sizeof(QChar));
    str.clear();
}

}  // namespace p2p::bridge

#endif  // QT_CORE_LIB
