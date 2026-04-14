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

target_link_libraries(Peer2Pear PRIVATE
    peer2pear-core
    Qt${QT_VERSION_MAJOR}::Widgets
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
