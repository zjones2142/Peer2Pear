# Peer2Pear iOS CMake toolchain.
#
# Minimalist toolchain for cross-compiling the peer2pear-core static library
# to iOS.  Supports two platforms:
#
#   -DPLATFORM=OS64        → iPhone / iPad device, arm64
#   -DPLATFORM=SIMULATOR64 → iOS Simulator, arm64 (Apple Silicon Macs)
#
# Intel-Mac simulator (x86_64) is out of scope — the reference client team
# builds and runs on Apple Silicon only.
#
# Usage:
#   cmake -B build-ios-device \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
#         -DPLATFORM=OS64 \
#         -DPEER2PEAR_P2P=OFF \          # msquic/libnice don't build for iOS
#         -DVCPKG_TARGET_TRIPLET=arm64-ios \
#         -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake \
#         ...
#   cmake --build build-ios-device --target peer2pear-core
#
# Intentionally NOT using leetal/ios-cmake or similar third-party toolchains
# — kept here so the project has no external "magic" toolchain dep.

cmake_minimum_required(VERSION 3.16)

# ── Sanity: this toolchain only runs on macOS ────────────────────────────────
if(NOT APPLE)
    message(FATAL_ERROR "ios.toolchain.cmake can only be used on macOS.")
endif()

# ── Platform selection ───────────────────────────────────────────────────────
# Default: device build.  Override with -DPLATFORM=SIMULATOR64.
if(NOT DEFINED PLATFORM)
    set(PLATFORM "OS64")
endif()

if(PLATFORM STREQUAL "OS64")
    set(IOS_SDK "iphoneos")
    set(IOS_ARCH "arm64")
    set(IOS_DEPLOYMENT_TARGET "15.0")
elseif(PLATFORM STREQUAL "SIMULATOR64")
    set(IOS_SDK "iphonesimulator")
    set(IOS_ARCH "arm64")
    set(IOS_DEPLOYMENT_TARGET "15.0")
else()
    message(FATAL_ERROR
        "Unknown PLATFORM='${PLATFORM}'.  Valid values: OS64, SIMULATOR64.")
endif()

# ── CMake system identity ────────────────────────────────────────────────────
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_SYSROOT ${IOS_SDK})
set(CMAKE_OSX_ARCHITECTURES ${IOS_ARCH})
set(CMAKE_OSX_DEPLOYMENT_TARGET ${IOS_DEPLOYMENT_TARGET})

# ── SDK path ─────────────────────────────────────────────────────────────────
execute_process(
    COMMAND xcrun --sdk ${IOS_SDK} --show-sdk-path
    OUTPUT_VARIABLE IOS_SDK_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)

if(NOT IOS_SDK_PATH)
    message(FATAL_ERROR
        "Unable to locate ${IOS_SDK} SDK via xcrun.  "
        "Is Xcode Command Line Tools installed? (xcode-select --install)")
endif()

# ── Compilers ────────────────────────────────────────────────────────────────
execute_process(
    COMMAND xcrun --sdk ${IOS_SDK} --find clang
    OUTPUT_VARIABLE CMAKE_C_COMPILER
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND xcrun --sdk ${IOS_SDK} --find clang++
    OUTPUT_VARIABLE CMAKE_CXX_COMPILER
    OUTPUT_STRIP_TRAILING_WHITESPACE)

# ── Build type defaults ──────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Bitcode was deprecated in Xcode 14 — don't emit, Apple ignores it anyway.
set(CMAKE_XCODE_ATTRIBUTE_ENABLE_BITCODE NO)

# ── Test/try_compile behavior ────────────────────────────────────────────────
# try_compile() on iOS defaults to building a full app bundle which we don't
# want for feature-detection checks.  Use STATIC_LIBRARY to keep them simple.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ── Message so the user knows they're in an iOS build ───────────────────────
message(STATUS "iOS toolchain loaded")
message(STATUS "  Platform:           ${PLATFORM}")
message(STATUS "  SDK:                ${IOS_SDK}")
message(STATUS "  SDK path:           ${IOS_SDK_PATH}")
message(STATUS "  Architecture:       ${IOS_ARCH}")
message(STATUS "  Deployment target:  iOS ${IOS_DEPLOYMENT_TARGET}")
