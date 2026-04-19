#!/usr/bin/env bash
#
# Cross-compile the Peer2Pear core library for iOS.
#
# Output: build-ios-<platform>/core/libpeer2pear-core.a
#
# Usage:
#   ./build-ios.sh                      # device (arm64)
#   ./build-ios.sh --simulator          # arm64 simulator (Apple Silicon Mac)
#   ./build-ios.sh --both               # both device and simulator
#
# Prerequisites:
#   - Xcode Command Line Tools (xcode-select --install)
#   - CMake 3.16+
#   - vcpkg bootstrapped (run ./setup.sh first if needed)
#
# Build configuration:
#   BUILD_DESKTOP=OFF  → skip Qt::Widgets and the desktop/ subdirectory
#   WITH_QT_CORE=OFF   → libpeer2pear-core.a has zero Qt symbols
#   PEER2PEAR_P2P=OFF  → skip msquic / libnice / glib (don't build for iOS)
#
# iOS is a relay-only client for now.  P2P on mobile is a separate effort
# (libnice + GLib ports to iOS).  The core itself is Qt-free either way.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Parse args ───────────────────────────────────────────────────────────────

TARGETS=("device")

while [ $# -gt 0 ]; do
    case "$1" in
        --simulator)  TARGETS=("simulator") ;;
        --both)       TARGETS=("device" "simulator") ;;
        -h|--help)
            echo "Usage: $0 [--simulator | --both]"
            exit 0
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
    esac
    shift
done

# ── Validate vcpkg ───────────────────────────────────────────────────────────

if [ ! -x vcpkg/vcpkg ]; then
    echo "Error: vcpkg not found or not bootstrapped."
    echo "Run ./setup.sh first."
    exit 1
fi

# ── Per-platform build ───────────────────────────────────────────────────────

build_for() {
    local target="$1"
    local platform triplet build_dir

    case "$target" in
        device)
            platform="OS64"
            triplet="arm64-ios"
            build_dir="build-ios-device"
            ;;
        simulator)
            platform="SIMULATOR64"
            triplet="arm64-ios-simulator"
            build_dir="build-ios-sim"
            ;;
        *)
            echo "Unknown target: $target" >&2
            return 1
            ;;
    esac

    echo
    echo "==============================================================="
    echo "Building peer2pear-core for iOS ($target, $triplet)"
    echo "Output dir: $build_dir/"
    echo "==============================================================="
    echo

    # vcpkg manifest mode pulls libsodium, liboqs, sqlcipher, nlohmann-json
    # for the iOS triplet.  BUILD_DESKTOP=OFF propagates WITH_QT_CORE=OFF to
    # core/ so no Qt is required at any layer.

    cmake -S . -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$SCRIPT_DIR/vcpkg/scripts/buildsystems/vcpkg.cmake" \
        -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/ios.toolchain.cmake" \
        -DVCPKG_MANIFEST_MODE=ON \
        -DVCPKG_TARGET_TRIPLET="$triplet" \
        -DPLATFORM="$platform" \
        -DBUILD_DESKTOP=OFF \
        -DPEER2PEAR_P2P=OFF

    # Only build the core static library on iOS.
    cmake --build "$build_dir" --target peer2pear-core

    echo
    echo "  [ok] $build_dir/core/libpeer2pear-core.a"
    ls -la "$build_dir/core/libpeer2pear-core.a"
}

for t in "${TARGETS[@]}"; do
    build_for "$t"
done

echo
echo "iOS build complete."
echo
echo "Next: open ios/Peer2Pear.xcodeproj in Xcode (once created), or use the"
echo "shipped sources in ios/Peer2Pear/Sources/ to wire up an iOS app that"
echo "links against build-ios-<target>/core/libpeer2pear-core.a."
