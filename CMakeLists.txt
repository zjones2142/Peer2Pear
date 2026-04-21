cmake_minimum_required(VERSION 3.16)

# ── Build options ─────────────────────────────────────────────────────────────
# Declared BEFORE the toolchain file / project() so they can drive vcpkg
# feature selection.  Order matters: vcpkg reads VCPKG_MANIFEST_FEATURES
# during toolchain load, which happens inside project().
option(PEER2PEAR_P2P
    "Enable direct peer-to-peer transport (QUIC over ICE). Adds msquic + libnice + glib dependencies; on Windows this requires MSVC."
    ON)

# BUILD_DESKTOP=ON pulls in Qt::Widgets/Network/WebSockets and the desktop/
# subdirectory.  Turn it OFF for iOS / Android / headless builds — the
# mobile apps link libpeer2pear-core.a directly via the C API and bring
# their own platform adapters.  When OFF, core/ gets WITH_QT_CORE=OFF too.
option(BUILD_DESKTOP
    "Build the Qt Widgets desktop app (desktop/).  Turn OFF for iOS/Android cross-compiles."
    ON)

# Unit + integration tests for core/.  Default ON when building the desktop
# (CI + dev machines get coverage); OFF when cross-compiling for mobile (iOS
# doesn't benefit from linking a test binary into its app bundle).
option(BUILD_TESTS
    "Build core/tests/ (GoogleTest).  Default ON for desktop, OFF for iOS/Android."
    ${BUILD_DESKTOP})

# Forward the options into vcpkg's manifest feature selection so the extra
# deps only get pulled in when actually needed.  FORCE ensures a flip from
# ON to OFF invalidates the previous cached value.
set(_vcpkg_features "")
if(PEER2PEAR_P2P)
    list(APPEND _vcpkg_features "p2p")
endif()
if(BUILD_TESTS)
    list(APPEND _vcpkg_features "tests")
endif()
set(VCPKG_MANIFEST_FEATURES "${_vcpkg_features}" CACHE STRING "vcpkg manifest features" FORCE)

# Force the vcpkg toolchain — must come BEFORE project()
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(Peer2Pear VERSION 0.2 LANGUAGES C CXX)
# C is enabled because third_party/sqlcipher compiles sqlite3.c (the vendored
# SQLCipher amalgamation).  Everything else is still C++.

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Qt ────────────────────────────────────────────────────────────────────────
# Only needed when building the desktop app.  iOS / Android cross-compiles set
# BUILD_DESKTOP=OFF and skip this entirely — libpeer2pear-core.a itself is
# Qt-free when WITH_QT_CORE=OFF (driven by BUILD_DESKTOP below).
if(BUILD_DESKTOP)
    find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network WebSockets)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network WebSockets)

    # Fix Qt's malformed framework flags on macOS desktop builds.
    if(APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
        set(CMAKE_EXE_LINKER_FLAGS
            "${CMAKE_EXE_LINKER_FLAGS} -framework CoreFoundation -framework AppKit -framework Carbon")
    endif()
else()
    # Propagate to core/: no Qt::Core linkage, so qt_interop.hpp compiles to nothing.
    set(WITH_QT_CORE OFF CACHE BOOL "Link core/ against Qt::Core" FORCE)
endif()

# ── vcpkg Dependencies ────────────────────────────────────────────────────────
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(liboqs CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)

# P2P-only deps: msquic needs MSVC on Windows; libnice + GLib aren't needed
# for the relay-only build path.  Gated so the default build can succeed
# on a plain MinGW / non-MSVC toolchain when PEER2PEAR_P2P=OFF.
if(PEER2PEAR_P2P)
    find_package(msquic CONFIG REQUIRED)
    pkg_check_modules(NICE REQUIRED IMPORTED_TARGET nice)
    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gobject-2.0 gio-2.0)
    if(APPLE)
        set_property(TARGET PkgConfig::NICE PROPERTY INTERFACE_LINK_OPTIONS "")
        set_property(TARGET PkgConfig::GLIB PROPERTY INTERFACE_LINK_OPTIONS "")
    endif()
endif()

# ── SQLCipher (vendored amalgamation) ────────────────────────────────────────
# Built from the vendored amalgamation in third_party/sqlcipher/ — same
# static library on every platform (desktop / iOS / Android).  Regenerate
# the amalgamation with third_party/sqlcipher/fetch.sh on SQLCipher bumps.
# Reads the OpenSSL that comes in transitively via liboqs from vcpkg.
add_subdirectory(third_party/sqlcipher)
set(SQLCIPHER_TARGET sqlcipher)
message(STATUS "SQLCipher: vendored amalgamation "
    "(third_party/sqlcipher/VERSION: see file)")

# ── Subdirectories ────────────────────────────────────────────────────────────
add_subdirectory(core)      # libpeer2pear-core (static library)
if(BUILD_DESKTOP)
    # qrcodegen — Nayuki's MIT-licensed C++ QR encoder, used only by the
    # desktop Edit Profile dialog.  iOS uses CIFilter.qrCodeGenerator, so
    # we don't pay the static-lib cost on mobile builds.
    add_subdirectory(third_party/qrcodegen)
    add_subdirectory(desktop)   # Peer2Pear desktop executable
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
# One GoogleTest binary per module under core/tests/.  Invoke the suite via
# `cmake --build build --target test` or `ctest` from the build dir.
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(core/tests)
endif()
