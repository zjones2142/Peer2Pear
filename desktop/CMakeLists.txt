# ── Peer2Pear Desktop Application ─────────────────────────────────────────────
#
# Qt Widgets desktop client. Links libpeer2pear-core for all protocol logic
# and adds desktop-specific UI, ICE/QUIC P2P transport, and notifications.

set(DESKTOP_SOURCES
    main.cpp
    mainwindow.cpp      mainwindow.h        mainwindow.ui
    chatview.cpp         chatview.h
    settingspanel.cpp    settingspanel.h
    onboardingdialog.cpp onboardingdialog.h
    ChatNotifier.h
    QtWebSocket.hpp
    QtHttpClient.hpp
    databasemanager.cpp  databasemanager.h
    NiceConnection.cpp   NiceConnection.hpp
    QuicConnection.cpp   QuicConnection.hpp
    resources.qrc
)

if(WIN32)
    list(APPEND DESKTOP_SOURCES windows_icon.rc)
endif()

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(Peer2Pear
        MANUAL_FINALIZATION
        ${DESKTOP_SOURCES}
    )
else()
    if(ANDROID)
        add_library(Peer2Pear SHARED ${DESKTOP_SOURCES})
    else()
        add_executable(Peer2Pear ${DESKTOP_SOURCES})
    endif()
endif()

# Enable P2P transport in the core library for this build.
# Core's ChatController.cpp conditionally includes QuicConnection.hpp when
# PEER2PEAR_P2P is defined, which pulls in NiceConnection.hpp → nice/agent.h
# → glib-object.h and msquic.h. Core needs these include paths but does NOT
# link the libraries (QuicConnection/NiceConnection are compiled by desktop).
target_compile_definitions(peer2pear-core PUBLIC PEER2PEAR_P2P)
target_include_directories(peer2pear-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    $<TARGET_PROPERTY:PkgConfig::NICE,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:PkgConfig::GLIB,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msquic,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:Qt${QT_VERSION_MAJOR}::Network,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(Peer2Pear PRIVATE
    peer2pear-core
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::WebSockets
    msquic
    PkgConfig::NICE
    PkgConfig::GLIB
)

# ── Bundle and Platform Properties ────────────────────────────────────────────
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.peer2pear.desktop)
endif()

set_target_properties(Peer2Pear PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# ── Installation Rules ────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS Peer2Pear
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(Peer2Pear)
endif()
