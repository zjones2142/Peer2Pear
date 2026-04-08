cmake_minimum_required(VERSION 3.16)

# Find Qt Test module
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)

# ── Group chat unit tests ─────────────────────────────────────────────────────
add_executable(tst_groupchat
    tst_groupchat.cpp

    # Pull in the minimal set of project sources needed to compile
    ../chattypes.h
    ../ChatController.cpp
    ../ChatController.hpp
    ../CryptoEngine.cpp
    ../CryptoEngine.hpp
    ../MailboxClient.cpp
    ../MailboxClient.hpp
    ../RendezvousClient.cpp
    ../RendezvousClient.hpp
    ../NiceConnection.cpp
    ../NiceConnection.hpp
    ../NoiseState.cpp
    ../NoiseState.hpp
    ../RatchetSession.cpp
    ../RatchetSession.hpp
    ../SessionStore.cpp
    ../SessionStore.hpp
    ../SessionManager.cpp
    ../SessionManager.hpp
    ../SealedEnvelope.cpp
    ../SealedEnvelope.hpp
    ../FileTransferManager.cpp
    ../FileTransferManager.hpp
    README.md
)

target_link_libraries(tst_groupchat PRIVATE
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Sql
    unofficial-sodium::sodium
    PkgConfig::NICE
    PkgConfig::GLIB
)

add_test(NAME GroupChatTests COMMAND tst_groupchat)
