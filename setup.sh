#!/usr/bin/env bash
#
# Peer2Pear setup — macOS and Linux.
#
# Installs system dependencies (Ninja, pkg-config, SQLCipher, Qt 6), clones
# and bootstraps vcpkg, and leaves the repo ready for Qt Creator or a manual
# `cmake --build` invocation.
#
# Idempotent: re-running after a successful setup is a no-op.
#
# KEEP THIS IN SYNC WITH vcpkg.json, CMakeLists.txt, and winsetup.bat.
# If new dependencies are added to the build, add the install step here too.

set -euo pipefail

echo "Peer2Pear setup (macOS / Linux)"
echo

# ── Detect OS ────────────────────────────────────────────────────────────────

OS="$(uname -s)"
case "$OS" in
    Darwin)
        PLATFORM="macos"
        ;;
    Linux)
        PLATFORM="linux"
        if [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
            LINUX_FLAVOR="debian"
        else
            LINUX_FLAVOR="other"
        fi
        ;;
    *)
        echo "Error: unsupported OS '$OS'. This script supports macOS and Linux."
        echo "On Windows, run winsetup.bat instead."
        exit 1
        ;;
esac

echo "Detected platform: $PLATFORM"
echo

# ── Required tools ───────────────────────────────────────────────────────────

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command '$1' not found in PATH."
        echo "       $2"
        exit 1
    fi
}

require_cmd git   "Install git from your package manager or https://git-scm.com"
require_cmd cmake "Install CMake >= 3.16 from your package manager or https://cmake.org"

# ── System dependencies ──────────────────────────────────────────────────────
#
# These can't be provided by vcpkg cleanly:
#   - ninja:      build tool; vcpkg can't bootstrap itself to build ninja to
#                 build vcpkg (chicken/egg).  Use system package.
#   - pkg-config: used by CMakeLists.txt to locate libnice + glib when the
#                 PEER2PEAR_P2P feature is on.
#
# SQLCipher is NOT a system dep anymore — the repo vendors the SQLCipher
# amalgamation in third_party/sqlcipher/ (sqlite3.c + sqlite3.h, committed).
# core/ compiles it against the OpenSSL that vcpkg pulls in transitively via
# liboqs.  Same build on desktop and mobile, no per-platform install step.
#
# qrcodegen (Project Nayuki, MIT) is also vendored in third_party/qrcodegen/
# for the desktop Edit Profile QR preview.  Single static library, no deps.
# iOS uses CIFilter.qrCodeGenerator natively and doesn't link it.

install_macos_deps() {
    if ! command -v brew >/dev/null 2>&1; then
        echo "Error: Homebrew is required on macOS."
        echo "       Install it from https://brew.sh and re-run this script."
        exit 1
    fi

    # `qt` currently maps to Qt 6 on Homebrew.  CMake's find_package(Qt6)
    # picks up the brew prefix via the default CMAKE_SYSTEM_PREFIX_PATH.
    local pkgs=(ninja pkg-config qt)
    for p in "${pkgs[@]}"; do
        if brew list --versions "$p" >/dev/null 2>&1; then
            echo "  [ok] $p (already installed)"
        else
            echo "  [..] installing $p via brew..."
            brew install "$p"
        fi
    done
}

install_debian_deps() {
    # Qt 6 Core/Widgets/Network come from qt6-base-dev; WebSockets is its
    # own package.  build-essential ensures gcc/g++/make are present so
    # vcpkg can build libsodium/liboqs/msquic from source.
    # On Ubuntu 22.04 the WebSockets package is libqt6websockets6-dev; on
    # 24.04+ it's qt6-websockets-dev.  Try the modern name first, fall
    # back to the legacy one if unavailable.
    local base_pkgs=(
        build-essential
        ninja-build
        pkg-config
        qt6-base-dev
    )
    local pkgs=("${base_pkgs[@]}")

    # Pick whichever WebSockets package apt knows about.
    if apt-cache show qt6-websockets-dev >/dev/null 2>&1; then
        pkgs+=(qt6-websockets-dev)
    elif apt-cache show libqt6websockets6-dev >/dev/null 2>&1; then
        pkgs+=(libqt6websockets6-dev)
    else
        echo "Warning: neither qt6-websockets-dev nor libqt6websockets6-dev"
        echo "         was found in your apt sources.  Qt WebSockets is"
        echo "         required.  Install it manually and re-run."
    fi

    local missing=()
    for p in "${pkgs[@]}"; do
        if dpkg -s "$p" >/dev/null 2>&1; then
            echo "  [ok] $p (already installed)"
        else
            missing+=("$p")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "  [..] installing: ${missing[*]}"
        sudo apt-get update
        sudo apt-get install -y "${missing[@]}"
    fi
}

echo "Checking system dependencies..."
if [ "$PLATFORM" = "macos" ]; then
    install_macos_deps
elif [ "${LINUX_FLAVOR:-}" = "debian" ]; then
    install_debian_deps
else
    echo "Warning: your Linux distribution isn't auto-detected."
    echo "Install these packages manually, then re-run:"
    echo "    build tools:     gcc, g++, make"
    echo "    build-system:    ninja, pkg-config, cmake"
    echo "    qt6:             qtbase (Widgets, Network), qtwebsockets"
    echo
    echo "SQLCipher is NOT a system dep — the repo vendors the amalgamation."
    echo
    echo "On Fedora/RHEL:"
    echo "    sudo dnf install gcc gcc-c++ make ninja-build pkgconf-pkg-config \\"
    echo "                     cmake qt6-qtbase-devel qt6-qtwebsockets-devel"
    echo "On Arch:"
    echo "    sudo pacman -S base-devel ninja pkgconf cmake qt6-base qt6-websockets"
    exit 1
fi
echo

# ── vcpkg (manifest mode via vcpkg.json) ─────────────────────────────────────
#
# vcpkg.json declares libsodium, liboqs, openssl, nlohmann-json, and
# (feature "p2p") msquic, libnice, glib.  The toolchain file (set in
# CMakeLists.txt) triggers auto-install on first CMake configure — no
# manual `vcpkg install` needed.

if [ ! -d vcpkg ]; then
    echo "Cloning vcpkg..."
    git clone https://github.com/microsoft/vcpkg.git
else
    echo "  [ok] vcpkg directory already exists"
fi

if [ ! -x vcpkg/vcpkg ]; then
    echo "Bootstrapping vcpkg..."
    ./vcpkg/bootstrap-vcpkg.sh -disableMetrics
else
    echo "  [ok] vcpkg already bootstrapped"
fi
echo

# ── Done ─────────────────────────────────────────────────────────────────────

echo "Setup complete."
echo
echo "Next steps:"
echo "  - Open CMakeLists.txt in Qt Creator, OR"
echo "  - Build from the command line:"
echo "        cmake -B build -S . -G Ninja"
echo "        cmake --build build"
echo
echo "The first CMake configure will take several minutes — vcpkg builds"
echo "libsodium, liboqs, nlohmann-json, and (if PEER2PEAR_P2P=ON) msquic,"
echo "libnice, and glib from source."
