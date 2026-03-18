cmake_minimum_required(VERSION 3.16)

# Force the vcpkg toolchain — must come BEFORE project()
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(Peer2Pear_QtProj VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- 1. Find Qt Packages ---
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network Sql)

if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -framework CoreFoundation -framework AppKit -framework Carbon")
endif()

# --- 2. Find vcpkg / pkg-config Dependencies ---
find_package(unofficial-sodium CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NICE REQUIRED IMPORTED_TARGET nice)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gobject-2.0 gio-2.0)

if(APPLE)
    set_property(TARGET PkgConfig::NICE PROPERTY INTERFACE_LINK_OPTIONS "")
    set_property(TARGET PkgConfig::GLIB PROPERTY INTERFACE_LINK_OPTIONS "")
endif()

# --- 3. Project Sources (single canonical list — no duplicates) ---
set(PROJECT_SOURCES
    main.cpp

    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    resources.qrc

    chattypes.h
    filetransfer.h

    chatview.cpp
    chatview.h
    settingspanel.cpp
    settingspanel.h
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
target_link_libraries(Peer2Pear_QtProj PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Sql
    unofficial-sodium::sodium
    PkgConfig::NICE
    PkgConfig::GLIB
)

# --- 6. Bundle and Platform Properties ---
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.Peer2Pear_QtProj)
endif()

set_target_properties(Peer2Pear_QtProj PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION        ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING  ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# --- 7. Installation Rules ---
include(GNUInstallDirs)
install(TARGETS Peer2Pear_QtProj
    BUNDLE  DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(Peer2Pear_QtProj)
endif()
