cmake_minimum_required(VERSION 3.16)

find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)

# ── Shared source list (everything the test binaries need to link against) ──
set(APP_SOURCES
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
)

set(TEST_LINK_LIBS
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::Sql
    unofficial-sodium::sodium
    PkgConfig::NICE
    PkgConfig::GLIB
)

# ── Helper function so each test is one line ──────────────────────────────────
function(add_p2p_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${APP_SOURCES})
    target_link_libraries(${TEST_NAME} PRIVATE ${TEST_LINK_LIBS})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

# ── Test targets ──────────────────────────────────────────────────────────────
add_p2p_test(tst_groupchat       tst_groupchat.cpp)
add_p2p_test(tst_cryptoengine    tst_cryptoengine.cpp)
add_p2p_test(tst_ratchetsession  tst_ratchetsession.cpp)
add_p2p_test(tst_noisestate      tst_noisestate.cpp)
add_p2p_test(tst_sealedenvelope  tst_sealedenvelope.cpp)
add_p2p_test(tst_sessionstore    tst_sessionstore.cpp)
add_p2p_test(tst_filetransfer    tst_filetransfer.cpp)
add_p2p_test(tst_chatcontroller  tst_chatcontroller.cpp)

# DatabaseManager test needs databasemanager.cpp too
add_executable(tst_databasemanager tst_databasemanager.cpp ${APP_SOURCES}
    ../databasemanager.cpp
    ../databasemanager.h
    ../filetransfer.h
)
target_link_libraries(tst_databasemanager PRIVATE ${TEST_LINK_LIBS})
add_test(NAME tst_databasemanager COMMAND tst_databasemanager)
