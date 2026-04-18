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
# Prerequisites (see ios/README.md for details):
#   - Xcode Command Line Tools
#   - CMake 3.16+
#   - vcpkg bootstrapped (run ./setup.sh first if needed)
#   - Qt for iOS installed, with QT_IOS_PREFIX exported or passed via --qt-ios
#
# The build uses PEER2PEAR_P2P=OFF because msquic / libnice / glib do not
# cross-compile cleanly for iOS.  iOS is a relay-only client by design.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Parse args ───────────────────────────────────────────────────────────────

TARGETS=("device")
QT_IOS_PREFIX="${QT_IOS_PREFIX:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --simulator)  TARGETS=("simulator") ;;
        --both)       TARGETS=("device" "simulator") ;;
        --qt-ios)     QT_IOS_PREFIX="$2"; shift ;;
        -h|--help)
            echo "Usage: $0 [--simulator | --both] [--qt-ios <path>]"
            exit 0
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
    esac
    shift
done

# ── Validate Qt for iOS ──────────────────────────────────────────────────────

if [ -z "$QT_IOS_PREFIX" ]; then
    echo "Error: QT_IOS_PREFIX not set and --qt-ios flag not provided."
    echo
    echo "The core library links against Qt::Core.  On iOS we need Qt's iOS"
    echo "target libraries, which aren't installed by 'brew install qt'."
    echo
    echo "Install Qt for iOS:"
    echo "  pip install aqtinstall"
    echo "  aqt install-qt mac ios 6.5.3 -O \$HOME/Qt"
    echo
    echo "Then re-run with one of:"
    echo "  QT_IOS_PREFIX=\$HOME/Qt/6.5.3/ios ./build-ios.sh"
    echo "  ./build-ios.sh --qt-ios \$HOME/Qt/6.5.3/ios"
    exit 1
fi

if [ ! -f "$QT_IOS_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" ]; then
    echo "Error: $QT_IOS_PREFIX doesn't look like a Qt for iOS install."
    echo "Expected to find: $QT_IOS_PREFIX/lib/cmake/Qt6/Qt6Config.cmake"
    exit 1
fi

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

    # vcpkg manifest mode -- pulls libsodium, liboqs, sqlcipher for iOS.
    # PEER2PEAR_P2P=OFF so msquic/libnice/glib are skipped.

    cmake -S . -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/ios.toolchain.cmake" \
        -DPLATFORM="$platform" \
        -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/ios.toolchain.cmake" \
        -DVCPKG_MANIFEST_MODE=ON \
        -DVCPKG_TARGET_TRIPLET="$triplet" \
        -DCMAKE_PREFIX_PATH="$QT_IOS_PREFIX" \
        -DPEER2PEAR_P2P=OFF \
        -DBUILD_DESKTOP=OFF

    # Only build the core static library on iOS — skip desktop/.
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
echo "Next: open ios/Peer2Pear.xcodeproj in Xcode, or run 'xcodegen generate'"
echo "in ios/ to create the Xcode project from project.yml."
