cmake_minimum_required(VERSION 3.16)
project(Peer2Pear_Tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# ── Find Qt packages ──────────────────────────────────────────────────────────
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Test Sql Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Test Sql Network)

# ── Shared source paths ──────────────────────────────────────────────────────
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# ── Use our stub <sodium.h> instead of real libsodium ─────────────────────────
# The stub header lives in tests/ and is included via -I before the system paths.
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/stubs)

# ── 1. tst_contacts — contact creation / editing / deletion / import-export ──
add_executable(tst_contacts
    tst_contacts.cpp
    ${SRC}/databasemanager.cpp
    ${SRC}/databasemanager.h
    ${SRC}/chattypes.h
    ${SRC}/filetransfer.h
)
target_include_directories(tst_contacts PRIVATE ${SRC})
target_link_libraries(tst_contacts PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Sql
    Qt${QT_VERSION_MAJOR}::Network
)

# ── 2. tst_keys — CryptoEngine key generation / AEAD / signing ───────────────
add_executable(tst_keys
    tst_keys.cpp
    ${SRC}/CryptoEngine.cpp
    ${SRC}/CryptoEngine.hpp
)
target_include_directories(tst_keys PRIVATE ${SRC})
target_link_libraries(tst_keys PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Sql
    Qt${QT_VERSION_MAJOR}::Network
)
