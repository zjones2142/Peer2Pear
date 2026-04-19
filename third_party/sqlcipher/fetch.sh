#!/usr/bin/env bash
#
# Download SQLCipher source and generate the amalgamation (sqlite3.c +
# sqlite3.h), then copy the result next to this script.  Run once per
# SQLCipher version bump and commit the result.
#
# The amalgamation is a single ~250 000-line C file containing all of
# SQLCipher (which is SQLite + AES-CBC encryption patches).  It's the
# upstream-supported way to embed SQLCipher without autotools on the
# consumer's build machine.
#
# Usage:
#   ./fetch.sh [version]       # defaults to SQLCIPHER_VERSION below
#
# Prerequisites:
#   - tclsh (ships on macOS; apt install tcl on Linux)
#   - autoconf + automake (brew install autoconf automake)

set -euo pipefail

SQLCIPHER_VERSION="${1:-4.6.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORKDIR="$(mktemp -d -t sqlcipher-fetch)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==============================================================="
echo "Fetching SQLCipher ${SQLCIPHER_VERSION} amalgamation"
echo "Work directory: ${WORKDIR}"
echo "Output:         ${SCRIPT_DIR}/{sqlite3.c, sqlite3.h, LICENSE}"
echo "==============================================================="
echo

# ── Download source ─────────────────────────────────────────────────────────
cd "${WORKDIR}"
curl -fL -o "sqlcipher-${SQLCIPHER_VERSION}.tar.gz" \
    "https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v${SQLCIPHER_VERSION}.tar.gz"
tar xzf "sqlcipher-${SQLCIPHER_VERSION}.tar.gz"
cd "sqlcipher-${SQLCIPHER_VERSION}"

# ── Configure (host build — produces the amalgamation, not the final lib) ──
# --disable-tcl      don't build the TCL extension
# --disable-shared   we don't need the shared lib from this step either
# CFLAGS=-DSQLITE_HAS_CODEC  turns on encryption
#
# The "sqlite3.c" target drives the TCL amalgamation generator.  We'll
# compile it fresh for each platform (desktop, iOS, Android, etc.) from
# the CMake target defined in third_party/sqlcipher/CMakeLists.txt, so the
# flags passed here don't end up in the shipping binary — only the
# generated .c file does.
# SQLCipher's configure script runs a libcrypto sniff test to confirm the
# selected crypto backend links — even though the sqlite3.c target itself
# doesn't actually link anything.  Point it at the host's Homebrew OpenSSL
# just to satisfy the check.  The generated amalgamation is crypto-backend-
# neutral: the shipping binary links whichever OpenSSL is provided by the
# consuming platform (vcpkg's on iOS, the system one on desktop, etc.).
OPENSSL_PREFIX=""
if [ -d /opt/homebrew/opt/openssl@3 ]; then
    OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3
elif command -v brew >/dev/null 2>&1 && brew --prefix openssl@3 >/dev/null 2>&1; then
    OPENSSL_PREFIX=$(brew --prefix openssl@3)
elif [ -d /usr/local/opt/openssl@3 ]; then
    OPENSSL_PREFIX=/usr/local/opt/openssl@3
fi

if [ -z "${OPENSSL_PREFIX}" ]; then
    echo "Error: couldn't find a host OpenSSL install."
    echo "  macOS: brew install openssl@3"
    echo "  Linux: apt install libssl-dev"
    exit 1
fi

./configure \
    --disable-tcl \
    --disable-shared \
    --enable-static \
    CFLAGS="-DSQLITE_HAS_CODEC -DSQLCIPHER_CRYPTO_OPENSSL -I${OPENSSL_PREFIX}/include" \
    LDFLAGS="-L${OPENSSL_PREFIX}/lib"

make sqlite3.c

# ── Copy results ───────────────────────────────────────────────────────────
cp sqlite3.c    "${SCRIPT_DIR}/sqlite3.c"
cp sqlite3.h    "${SCRIPT_DIR}/sqlite3.h"
cp LICENSE.md   "${SCRIPT_DIR}/LICENSE"
# SQLCIPHER_VERSION.txt rather than VERSION because the C++20 standard
# library's `<version>` header resolves via case-insensitive filesystem
# lookup on macOS, and a plain `VERSION` in our include path would shadow it.
echo "${SQLCIPHER_VERSION}" > "${SCRIPT_DIR}/SQLCIPHER_VERSION.txt"

SIZE=$(wc -c < "${SCRIPT_DIR}/sqlite3.c")
LINES=$(wc -l < "${SCRIPT_DIR}/sqlite3.c")

echo
echo "  [ok] sqlite3.c    ($(printf "%'d" "${SIZE}") bytes, $(printf "%'d" "${LINES}") lines)"
echo "  [ok] sqlite3.h"
echo "  [ok] LICENSE"
echo "  [ok] VERSION      (${SQLCIPHER_VERSION})"
echo
echo "Commit these alongside this script.  Consumers don't need tclsh or"
echo "autoconf — they just compile sqlite3.c against OpenSSL."
