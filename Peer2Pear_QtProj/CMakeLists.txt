cmake_minimum_required(VERSION 3.16)

# Force the vcpkg toolchain using CMake's native forward-slash paths
# This must come BEFORE the project() command.
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project(Peer2Pear_QtProj VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Build speed: MSVC parallel compilation ---
if(MSVC)
    add_compile_options(/MP)
endif()

# --- Build speed: Unity (jumbo) builds ---
# Combines source files into fewer translation units for faster compilation.
set(CMAKE_UNITY_BUILD ON CACHE BOOL "Enable unity (jumbo) builds")

# --- 1. Find Qt Packages ---
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network Sql)

# Fix Qt's malformed framework flags on macOS
if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -framework CoreFoundation -framework AppKit -framework Carbon")
endif()

if(WIN32)
    set(app_icon_resource "windows_icon.rc")
else()
    set(app_icon_resource "")
endif()

# --- 2. Find vcpkg Dependencies ---
# libsodium uses an unofficial wrapper name in vcpkg
find_package(unofficial-sodium CONFIG REQUIRED)

if(WIN32)
    # On Windows, pkg-config is not reliably available. Use vcpkg's CMake
    # config files and manual library discovery instead.
    find_package(unofficial-glib CONFIG REQUIRED)

    # libnice does not ship a CMake config in vcpkg; find it manually.
    find_library(NICE_LIBRARY NAMES nice)
    find_path(NICE_INCLUDE_DIR nice/agent.h)
    if(NOT NICE_LIBRARY OR NOT NICE_INCLUDE_DIR)
        message(FATAL_ERROR
            "Could not find libnice. Make sure vcpkg dependencies are installed:\n"
            "  .\\vcpkg\\vcpkg install --triplet x64-windows")
    endif()

    add_library(libnice_imported INTERFACE IMPORTED)
    set_target_properties(libnice_imported PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${NICE_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${NICE_LIBRARY}"
    )

    set(NICE_TARGET libnice_imported)
    set(GLIB_TARGETS unofficial::glib::glib unofficial::glib::gobject unofficial::glib::gio)
else()
    # On macOS/Linux, pkg-config works reliably
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NICE REQUIRED IMPORTED_TARGET nice)
    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gobject-2.0 gio-2.0)

    if(APPLE)
        set_property(TARGET PkgConfig::NICE PROPERTY INTERFACE_LINK_OPTIONS "")
        set_property(TARGET PkgConfig::GLIB PROPERTY INTERFACE_LINK_OPTIONS "")
    endif()

    set(NICE_TARGET PkgConfig::NICE)
    set(GLIB_TARGETS PkgConfig::GLIB)
endif()

# --- 3. Define Project Sources (Unified List) ---
set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    resources.qrc
    filetransfer.h
    chattypes.h
    chatview.h
    chatview.cpp
    settingspanel.h
    settingspanel.cpp
    databasemanager.cpp
    databasemanager.h
    ChatNotifier.h
    ChatController.cpp
    ChatController.hpp
    CryptoEngine.cpp
    CryptoEngine.hpp
    MailboxClient.cpp
    MailboxClient.hpp
    RendezvousClient.cpp
    RendezvousClient.hpp
    NiceConnection.cpp
    NiceConnection.hpp
    onboardingdialog.h
    onboardingdialog.cpp
    NoiseState.hpp
    NoiseState.cpp
    RatchetSession.hpp
    RatchetSession.cpp
    SessionStore.hpp
    SessionStore.cpp
    SessionManager.hpp
    SessionManager.cpp
    SealedEnvelope.hpp
    SealedEnvelope.cpp
    FileTransferManager.hpp
    FileTransferManager.cpp
    ${app_icon_resource}
)

# --- 4. Create Executable ---
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(Peer2Pear_QtProj
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(Peer2Pear_QtProj SHARED ${PROJECT_SOURCES})
    else()
        add_executable(Peer2Pear_QtProj ${PROJECT_SOURCES})
    endif()
endif()

# --- 5. Link Dependencies ---
# Suppress qDebug output only for explicit non-Debug configurations so
# single-config generators with an unset CMAKE_BUILD_TYPE keep local debug output.
target_compile_definitions(Peer2Pear_QtProj PRIVATE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:QT_NO_DEBUG_OUTPUT>
)

target_link_libraries(Peer2Pear_QtProj PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Sql
    unofficial-sodium::sodium
    ${NICE_TARGET}
    ${GLIB_TARGETS}
)

# Windows needs Winsock and IP helper for libnice/glib networking
if(WIN32)
    target_link_libraries(Peer2Pear_QtProj PRIVATE ws2_32 iphlpapi)
endif()

# --- Build speed: Precompiled headers ---
target_precompile_headers(Peer2Pear_QtProj PRIVATE
    <QObject>
    <QString>
    <QByteArray>
    <QDebug>
    <QWidget>
    <QJsonObject>
    <QJsonDocument>
    <QJsonArray>
    <QNetworkAccessManager>
    <QNetworkReply>
    <QSqlDatabase>
    <QSqlQuery>
    <memory>
    <vector>
    <functional>
)

# --- 6. Bundle and Platform Properties ---
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.Peer2Pear_QtProj)
endif()

set_target_properties(Peer2Pear_QtProj PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# --- 7. Installation Rules ---
include(GNUInstallDirs)
install(TARGETS Peer2Pear_QtProj
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(Peer2Pear_QtProj)
endif()