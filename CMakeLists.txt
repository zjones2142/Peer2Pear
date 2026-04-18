cmake_minimum_required(VERSION 3.16)

# ── Build options ─────────────────────────────────────────────────────────────
# Declared BEFORE the toolchain file / project() so they can drive vcpkg
# feature selection.  Order matters: vcpkg reads VCPKG_MANIFEST_FEATURES
# during toolchain load, which happens inside project().
option(PEER2PEAR_P2P
    "Enable direct peer-to-peer transport (QUIC over ICE). Adds msquic + libnice + glib dependencies; on Windows this requires MSVC."
    ON)

# Forward the option into vcpkg's manifest feature selection so the extra
# P2P deps only get pulled in when actually needed.  FORCE ensures a flip
# from ON to OFF invalidates the previous cached value.
if(PEER2PEAR_P2P)
    set(VCPKG_MANIFEST_FEATURES "p2p" CACHE STRING "vcpkg manifest features" FORCE)
else()
    set(VCPKG_MANIFEST_FEATURES "" CACHE STRING "vcpkg manifest features" FORCE)
endif()

# Force the vcpkg toolchain — must come BEFORE project()
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(Peer2Pear VERSION 0.2 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Qt ────────────────────────────────────────────────────────────────────────
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network WebSockets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network WebSockets)

# Fix Qt's malformed framework flags on macOS
if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -framework CoreFoundation -framework AppKit -framework Carbon")
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

# ── SQLCipher ─────────────────────────────────────────────────────────────────
if(APPLE)
    execute_process(
        COMMAND brew --prefix sqlcipher
        OUTPUT_VARIABLE _SQLCIPHER_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(_SQLCIPHER_PREFIX)
        set(ENV{PKG_CONFIG_PATH}
            "$ENV{PKG_CONFIG_PATH}:${_SQLCIPHER_PREFIX}/lib/pkgconfig")
    endif()
endif()
pkg_check_modules(SQLCIPHER REQUIRED IMPORTED_TARGET sqlcipher)
message(STATUS "SQLCipher found: ${SQLCIPHER_VERSION}")
set(SQLCIPHER_TARGET PkgConfig::SQLCIPHER)

# ── Subdirectories ────────────────────────────────────────────────────────────
add_subdirectory(core)      # libpeer2pear-core (static library)
add_subdirectory(desktop)   # Peer2Pear desktop executable
