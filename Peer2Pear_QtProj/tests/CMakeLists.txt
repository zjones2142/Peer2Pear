cmake_minimum_required(VERSION 3.16)

# When building tests standalone (not as a subdirectory of the main project),
# we locate sodium ourselves via PkgConfig. The main project uses vcpkg's
# unofficial-sodium target, so we handle both cases.
if(NOT TARGET unofficial-sodium::sodium)
    project(Peer2Pear_Tests LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_AUTOMOC ON)

    find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Test Sql Core)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test Sql Core)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(SODIUM_TARGET PkgConfig::SODIUM)
else()
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test Sql)
    set(SODIUM_TARGET unofficial-sodium::sodium)
endif()

# ── DatabaseManager unit tests ───────────────────────────────────────────────
add_executable(tst_databasemanager
    tst_databasemanager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../databasemanager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../databasemanager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../chattypes.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../filetransfer.h
)

target_include_directories(tst_databasemanager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(tst_databasemanager PRIVATE
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Sql
    Qt${QT_VERSION_MAJOR}::Core
    ${SODIUM_TARGET}
)

enable_testing()
add_test(NAME tst_databasemanager COMMAND tst_databasemanager)
