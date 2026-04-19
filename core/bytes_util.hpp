#pragma once
//
// Pure-std byte utilities.  No Qt, no sodium — safe for every host.
// The Qt-dependent boundary helpers (QByteArray ↔ Bytes, secureZeroQ) live
// in qt_interop.hpp and are gated on `#ifdef QT_CORE_LIB`.
//

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace p2p::bridge {

using Bytes = std::vector<uint8_t>;

// Tag a C string literal as a Bytes buffer — handy for ad-hoc domain strings
// passed into HKDF / keyed-hash calls (e.g. `strBytes("prekey-salt")`).
inline Bytes strBytes(const char* s) {
    const size_t n = std::strlen(s);
    return Bytes(reinterpret_cast<const uint8_t*>(s),
                 reinterpret_cast<const uint8_t*>(s) + n);
}

inline Bytes strBytes(const std::string& s) {
    return Bytes(reinterpret_cast<const uint8_t*>(s.data()),
                 reinterpret_cast<const uint8_t*>(s.data()) + s.size());
}

}  // namespace p2p::bridge
