# ── SQLCipher amalgamation ──────────────────────────────────────────────────
#
# Builds the vendored SQLCipher amalgamation (sqlite3.c + sqlite3.h)
# as a static library.  Zero external build-time dependencies beyond
# OpenSSL — the amalgamation is a single giant .c file committed to the
# repo, regenerated via fetch.sh when SQLCipher is bumped.
#
# Same build on every platform we care about:
#   - macOS arm64 / x86_64 desktop
#   - iOS arm64 simulator / device
#   - Android (once the toolchain lands)
#   - Linux / Windows

add_library(sqlcipher STATIC sqlite3.c sqlite3.h)

# sqlcipher is pure C — skip Qt's AUTOMOC/AUTOUIC/AUTORCC which are enabled
# globally for the Qt desktop target.  Without these, CMake ends up emitting
# an empty `libsqlcipher.a` (the C source gets shadowed by the autogen rule).
set_target_properties(sqlcipher PROPERTIES
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)

# Encryption on: SQLCIPHER_CRYPTO_OPENSSL picks the OpenSSL backend for the
# page-level AES-CBC.  SQLITE_HAS_CODEC is the hook that enables the codec
# layer at all.  SQLITE_TEMP_STORE=2 = always use memory for temp tables
# (saves unencrypted disk writes when the OS swaps temp files).
target_compile_definitions(sqlcipher PUBLIC
    SQLITE_HAS_CODEC
    SQLCIPHER_CRYPTO_OPENSSL
    SQLITE_TEMP_STORE=2
    SQLITE_THREADSAFE=1
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_JSON1
    HAVE_USLEEP=1
    # SQLCipher 4.14.0+ requires these to be set at compile time so its init
    # hooks run during sqlite3_initialize() and don't silently no-op.
    SQLITE_EXTRA_INIT=sqlcipher_extra_init
    SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
)

# The amalgamation has known unused-function / strict-aliasing warnings
# that we can't fix without forking — silence them so our own -Wall builds
# stay readable.
target_compile_options(sqlcipher PRIVATE
    $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:
        -Wno-unused-function
        -Wno-unused-variable
        -Wno-unused-parameter
        -Wno-unused-but-set-variable
        -Wno-deprecated-declarations
    >
)

# Consumers #include "sqlite3.h" — expose it via a public include dir.
target_include_directories(sqlcipher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# OpenSSL backend.  vcpkg provides libcrypto for every platform we build
# for (it's a transitive dep of liboqs); find_package(OpenSSL) finds the
# vcpkg-installed one ahead of any system copy because the toolchain file
# prepends vcpkg_installed to CMAKE_PREFIX_PATH.
find_package(OpenSSL REQUIRED)
target_link_libraries(sqlcipher PUBLIC OpenSSL::Crypto)

# On Unix, sqlite links against libdl (dlopen) + libm + libpthread.  Apple
# platforms provide these as part of libSystem; Linux needs them explicit.
if(UNIX AND NOT APPLE)
    target_link_libraries(sqlcipher PUBLIC ${CMAKE_DL_LIBS} m pthread)
endif()
