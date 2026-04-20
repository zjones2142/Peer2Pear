#pragma once
//
// Shared helpers for the core/tests suite.  Previously every test file
// carried its own copy of `makeTempDir` / `makeTempPath`; consolidating
// here removes six near-identical implementations.

#include <sodium.h>

#include <cstdio>
#include <filesystem>
#include <string>

namespace p2p_test {

// Build a unique tmp path: "<tmpDir>/<tag>-<16 hex chars><suffix>".
// Does NOT create the path — callers that want a directory call
// makeTempDir() below.  Pass an empty suffix for bare tags.
inline std::string makeTempPath(const char* tag, const char* suffix) {
    (void)sodium_init();
    uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char buf[96];
    std::snprintf(buf, sizeof(buf),
                  "%s-%02x%02x%02x%02x%02x%02x%02x%02x%s",
                  tag, rnd[0], rnd[1], rnd[2], rnd[3],
                  rnd[4], rnd[5], rnd[6], rnd[7],
                  suffix ? suffix : "");
    namespace fs = std::filesystem;
    const fs::path p = fs::temp_directory_path() / buf;
    fs::remove_all(p);
    return p.string();
}

// Build AND create a fresh directory under <tmp>.  Used by tests that
// need a data_dir to write identity.json / db into.
inline std::string makeTempDir(const char* tag) {
    const std::string path = makeTempPath(tag, "");
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace p2p_test
