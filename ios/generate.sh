#!/usr/bin/env bash
#
# Generate ios/Peer2Pear.xcodeproj from project.yml via xcodegen.
#
# The .xcodeproj is NOT checked in — everyone regenerates from project.yml.
# That means there's no .pbxproj merge conflict when two people change
# the project config; whoever rebases just re-runs this script.
#
# Usage:
#   ./ios/generate.sh          # from the repo root, or
#   cd ios && ./generate.sh
#
# Prereq: static libraries built via `./build-ios.sh --both` from the repo
# root.  Without those, the project generates but Xcode's link step will
# fail with "library not found for -lpeer2pear-core".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ── xcodegen dependency ──────────────────────────────────────────────────────

if ! command -v xcodegen >/dev/null 2>&1; then
    echo "xcodegen not found.  Attempting 'brew install xcodegen'..."
    if ! command -v brew >/dev/null 2>&1; then
        echo "Error: Homebrew not found either.  Install xcodegen manually:"
        echo "    brew install xcodegen"
        echo "    # or from https://github.com/yonaskolb/XcodeGen"
        exit 1
    fi
    brew install xcodegen
fi

echo "xcodegen: $(xcodegen --version 2>&1 | head -1)"

# ── Warn if the iOS static libs haven't been built yet ─────────────────────

missing=()
for lib in \
    ../build-ios-sim/core/libpeer2pear-core.a \
    ../build-ios-sim/third_party/sqlcipher/libsqlcipher.a \
    ../build-ios-device/core/libpeer2pear-core.a
do
    [ -f "$lib" ] || missing+=("$lib")
done

if [ ${#missing[@]} -gt 0 ]; then
    echo
    echo "  Warning: the following static libraries don't exist yet:"
    for lib in "${missing[@]}"; do echo "    $lib"; done
    echo
    echo "  Run './build-ios.sh --both' from the repo root first if you want"
    echo "  the project to actually link.  Proceeding with project generation"
    echo "  anyway — the .xcodeproj itself doesn't need the libs to exist."
    echo
fi

# ── Generate ────────────────────────────────────────────────────────────────

xcodegen generate --spec project.yml

echo
echo "  [ok] Generated: ${SCRIPT_DIR}/Peer2Pear.xcodeproj"
echo
echo "  Next:"
echo "    open Peer2Pear.xcodeproj"
echo "    # or build from the command line:"
echo "    xcodebuild -project Peer2Pear.xcodeproj -scheme Peer2Pear \\"
echo "               -sdk iphonesimulator -arch arm64"
