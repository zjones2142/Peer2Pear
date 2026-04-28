#pragma once

#include "types.hpp"
//
// Small binary serialization helpers used by session/ratchet persistence.
//
// Replaces QDataStream for core/ files being migrated off Qt.  Writes
// big-endian integers and length-prefixed byte blobs.  Wire format is
// byte-compatible with QDataStream Qt_5_15 for QByteArray, so existing
// serialized NoiseState / RatchetSession blobs deserialize unchanged.
//
// Intentionally minimal — we write sessions, we read sessions, nothing
// else.  If this grows past ~200 lines, it's turned into a library; for
// now it stays a header-only helper.

#include <cstdint>
#include <cstring>
#include <vector>

namespace p2p {


// ── BinaryWriter ────────────────────────────────────────────────────────────

class BinaryWriter {
public:
    BinaryWriter() = default;

    void u8(uint8_t v)   { m_buf.push_back(v); }
    void boolean(bool v) { m_buf.push_back(v ? 1 : 0); }

    void u16(uint16_t v) {
        m_buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        m_buf.push_back(static_cast<uint8_t>( v       & 0xFF));
    }
    void u32(uint32_t v) {
        m_buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        m_buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        m_buf.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
        m_buf.push_back(static_cast<uint8_t>( v        & 0xFF));
    }
    void u64(uint64_t v) {
        for (int s = 56; s >= 0; s -= 8)
            m_buf.push_back(static_cast<uint8_t>((v >> s) & 0xFF));
    }

    // Length-prefixed byte blob — byte-compatible with QDataStream's
    // QByteArray write (quint32 BE length + raw bytes).
    void bytes(const Bytes& b) {
        u32(static_cast<uint32_t>(b.size()));
        m_buf.insert(m_buf.end(), b.begin(), b.end());
    }
    void bytes(const uint8_t* data, size_t n) {
        u32(static_cast<uint32_t>(n));
        m_buf.insert(m_buf.end(), data, data + n);
    }

    // Raw append (no length prefix) — for fixed-size fields the reader
    // knows the size of up front.
    void raw(const uint8_t* data, size_t n) {
        m_buf.insert(m_buf.end(), data, data + n);
    }

    const Bytes& buffer() const { return m_buf; }
    Bytes        take() { return std::move(m_buf); }

private:
    Bytes m_buf;
};

// ── BinaryReader ────────────────────────────────────────────────────────────
//
// Bounds-checked: each read returns a default-constructed value (or `false`
// / empty bytes) on short reads, AND sets an error flag.  Callers check
// `ok()` at the end rather than after every field, which keeps the
// deserializer loops readable.

class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t n)
        : m_data(data), m_size(n), m_pos(0), m_ok(true) {}
    explicit BinaryReader(const Bytes& b)
        : BinaryReader(b.data(), b.size()) {}

    bool   ok()       const { return m_ok; }
    size_t remaining() const { return m_size - m_pos; }

    uint8_t u8() {
        if (!check(1)) return 0;
        return m_data[m_pos++];
    }
    bool boolean() {
        if (!check(1)) return false;
        return m_data[m_pos++] != 0;
    }
    uint16_t u16() {
        if (!check(2)) return 0;
        const uint16_t v =
            (static_cast<uint16_t>(m_data[m_pos]) << 8) |
             static_cast<uint16_t>(m_data[m_pos + 1]);
        m_pos += 2;
        return v;
    }
    uint32_t u32() {
        if (!check(4)) return 0;
        const uint32_t v =
            (static_cast<uint32_t>(m_data[m_pos    ]) << 24) |
            (static_cast<uint32_t>(m_data[m_pos + 1]) << 16) |
            (static_cast<uint32_t>(m_data[m_pos + 2]) <<  8) |
             static_cast<uint32_t>(m_data[m_pos + 3]);
        m_pos += 4;
        return v;
    }
    uint64_t u64() {
        if (!check(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | static_cast<uint64_t>(m_data[m_pos + i]);
        }
        m_pos += 8;
        return v;
    }

    // Length-prefixed blob — mirrors BinaryWriter::bytes.
    // QDataStream writes a null QByteArray as 0xFFFFFFFF; we treat that
    // as "empty" for safety (we never write null bytes in our format).
    Bytes bytes() {
        const uint32_t len = u32();
        if (!m_ok) return {};
        if (len == 0xFFFFFFFFu) return {};  // null marker → empty
        if (!check(len)) return {};
        Bytes out(m_data + m_pos, m_data + m_pos + len);
        m_pos += len;
        return out;
    }

    // Raw read of known size (no length prefix).
    Bytes raw(size_t n) {
        if (!check(n)) return {};
        Bytes out(m_data + m_pos, m_data + m_pos + n);
        m_pos += n;
        return out;
    }

private:
    bool check(size_t n) {
        if (m_pos + n > m_size) {
            m_ok = false;
            return false;
        }
        return true;
    }

    const uint8_t* m_data;
    size_t         m_size;
    size_t         m_pos;
    bool           m_ok;
};

}  // namespace p2p
