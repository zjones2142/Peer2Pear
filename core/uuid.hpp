#pragma once

// RFC 4122 v4 UUID generator using libsodium's randombytes_buf.
// Returns a 36-char "8-4-4-4-12" hex+hyphen string with the version (4)
// and variant (10xx) bits set per the spec.  Header-only so callers don't
// have to pull in another translation unit.

#include <cstdint>
#include <cstdio>
#include <string>
#include <sodium.h>

namespace p2p {

inline std::string makeUuid() {
    uint8_t bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    // RFC 4122 v4 bits (high nibble of byte 6 = 4; high bits of byte 8 = 10)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2],  bytes[3],
        bytes[4], bytes[5], bytes[6],  bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

}  // namespace p2p
