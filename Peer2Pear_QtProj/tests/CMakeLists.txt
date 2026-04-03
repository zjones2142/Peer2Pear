cmake_minimum_required(VERSION 3.16)
project(Peer2Pear_Tests LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# ── Qt packages (only Widgets, Sql, Test — no vcpkg needed) ──────────────────
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Sql Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Sql Test)

enable_testing()

# ── Contact test suite ────────────────────────────────────────────────────────
# Builds DatabaseManager.cpp directly.  Encryption is never exercised in tests
# (m_encKey is left empty), so we link lightweight sodium stubs instead of the
# real libsodium library.
add_executable(tst_contacts
    tst_contacts.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../databasemanager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_stubs/sodium_stub.c
)

# Stub sodium.h takes precedence over any system header
target_include_directories(tst_contacts PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sodium_stubs
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(tst_contacts PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Sql
    Qt${QT_VERSION_MAJOR}::Test
)

add_test(NAME tst_contacts COMMAND tst_contacts)

