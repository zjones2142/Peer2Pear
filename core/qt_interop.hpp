#pragma once
//
// Qt ↔ std interop helpers — permanent boundary layer between Qt-typed
// callers (desktop UI, QuicConnection signals) and the std-typed core API.
// The desktop UI is intentionally Qt-native and the core API is
// intentionally std-native, so a translation layer is the right long-term
// shape.
//
// Scope:
//   - `toBytes(QByteArray)` / `toQByteArray(Bytes)` — pure type conversions,
//     used at the QuicConnection ↔ ChatController boundary (desktop only,
//     gated by PEER2PEAR_P2P) and in desktop's password-unlock flow.
//   - `secureZeroQ(QByteArray&)` / `secureZeroQ(QString&)` — wipe Qt-typed
//     sensitive memory.  CryptoEngine::secureZero only takes Bytes/std.
//
// Rules:
//   - Header-only.  No logic — anything that does work belongs in the class
//     that owns the behavior.
//   - The whole file is gated on `QT_CORE_LIB`.  Mobile builds (which set
//     `WITH_QT_CORE=OFF`) compile it out to nothing; their callers don't
//     have QByteArray/QString to convert in the first place.
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
// only takes Bytes/std::string; these are the Qt-caller equivalents.
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
