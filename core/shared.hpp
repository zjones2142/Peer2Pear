#pragma once

// Tiny shared utility helpers for core/*.cpp.
//
// Previously nowSecs() was duplicated in anonymous namespaces across
// ChatController.cpp, FileProtocol.cpp, GroupProtocol.cpp, and
// SessionSealer.cpp; trimmed() was in FileProtocol + GroupProtocol +
// (inlined) RelayClient; peerPrefix()'s `substr(0,8)` log-truncation
// idiom appeared in ~90 places with no shared helper.  Each copy
// was nominally identical but drifted over time in tiny ways
// (different newline handling for trimmed(), varying argument types
// for peerPrefix).  Consolidating here keeps the bodies honest and
// lets the compiler catch future drift.
//
// Header-only by design: these are a few lines each and inlining
// them avoids pulling in shared_library headers.  All functions are
// `inline` so they obey ODR across translation units.
//
// Types: std::string for UTF-8 text, int64_t for Unix seconds.
// Byte buffers stay as each caller's existing `Bytes` alias (usually
// std::vector<uint8_t>).  We don't consolidate that alias here
// because the class-scoped `Foo::Bytes` idiom is load-bearing for
// C API + FFI ergonomics elsewhere.

#include <chrono>
#include <cstdint>
#include <string>

namespace p2p {

// Current Unix time in seconds.  Wall-clock, not monotonic — callers
// use it for message timestamps + TTL comparisons where wall-clock
// semantics are what the user expects.
inline int64_t nowSecs() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// Strip ASCII whitespace (space, tab, CR, LF) from both ends.  Used
// on member-ID lists that may arrive with trailing newlines from
// textarea copy-paste.  Returns an empty string if `s` is entirely
// whitespace.  UTF-8 safe because we only touch ASCII whitespace
// bytes — a codepoint like U+00A0 (non-breaking space) is left alone.
inline std::string trimmed(const std::string& s) {
    auto lb = s.find_first_not_of(" \t\r\n");
    if (lb == std::string::npos) return {};
    auto rb = s.find_last_not_of(" \t\r\n");
    return s.substr(lb, rb - lb + 1);
}

// Return the first 8 chars of a base64url peer ID, for log messages.
// Peer IDs are 43 chars; the 8-char prefix is enough to identify a
// peer in a sea of log lines while keeping lines readable and not
// leaking more than necessary.  Guards against short / empty inputs.
inline std::string peerPrefix(const std::string& peerId) {
    return peerId.size() >= 8 ? peerId.substr(0, 8) : peerId;
}

}  // namespace p2p
