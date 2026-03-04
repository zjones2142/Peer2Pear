cmake_minimum_required(VERSION 3.16)

project(Peer2Pear_QtProj VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- 1. Find Qt Packages ---
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

# --- 2. Handle libsodium (Find System OR Fetch) ---

# Find headers
find_path(SODIUM_INCLUDE_DIR sodium.h
    PATHS /opt/homebrew/include /usr/local/include /usr/include
)

# Find library
find_library(SODIUM_LIB sodium
    PATHS /opt/homebrew/lib /usr/local/lib /usr/lib
)

if (SODIUM_LIB AND SODIUM_INCLUDE_DIR)
    message(STATUS "Found system libsodium: ${SODIUM_LIB}")
    message(STATUS "Found libsodium headers: ${SODIUM_INCLUDE_DIR}")
    set(SODIUM_LINK_TARGET ${SODIUM_LIB})
    set(SODIUM_INCLUDE_TARGET ${SODIUM_INCLUDE_DIR})
else()
    message(STATUS "System libsodium not found. Fetching via community CMake wrapper...")
    include(FetchContent)
    FetchContent_Declare(
      libsodium_fetched
      GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
      GIT_TAG        master
    )
    FetchContent_MakeAvailable(libsodium_fetched)

    # Wrapper creates target named 'sodium'
    set(SODIUM_LINK_TARGET sodium)
    set(SODIUM_INCLUDE_TARGET "") # not needed if wrapper exports include dirs
endif()

# --- 3. Define Project Sources (Unified List) ---
set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    resources.qrc
    ChatController.cpp
    ChatController.hpp
    CryptoEngine.cpp
    CryptoEngine.hpp
    MailboxClient.cpp
    MailboxClient.hpp
    RendezvousClient.cpp
    RendezvousClient.hpp
)

# --- 4. Create Executable ---
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(Peer2Pear_QtProj
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        settingspanel.h settingspanel.cpp
        chatview.h chatview.cpp
        ChatNotifier.h
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
    ${SODIUM_LINK_TARGET}
)

if (SODIUM_INCLUDE_TARGET)
    target_include_directories(Peer2Pear_QtProj PRIVATE ${SODIUM_INCLUDE_TARGET})
endif()

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
