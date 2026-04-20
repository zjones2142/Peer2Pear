# ── core/tests — GoogleTest suite for libpeer2pear-core ──────────────────────
#
# One binary per module (test_<module>).  Each links against
# libpeer2pear-core (and its transitive deps) plus GTest.  Register every
# binary with ctest so `cmake --build build --target test` (or ctest from
# the build dir) runs the whole suite.
#
# Only built when -DBUILD_TESTS=ON — defaults to ON for desktop builds
# (via BUILD_DESKTOP) and OFF when cross-compiling for iOS / Android.
#
# See `core/tests/README.md` for the per-tier plan.

find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

# Common config for every test binary: the core library, GTest, and C++17.
# Compile commands mirror the core/ compile flags (SQLITE_HAS_CODEC etc.
# already come through peer2pear-core's INTERFACE definitions).
function(peer2pear_add_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE
        peer2pear-core
        GTest::gtest
        GTest::gtest_main
    )
    target_compile_features(${name} PRIVATE cxx_std_17)
    # Test sources never use Qt's signals/slots — skip the AUTOMOC /
    # AUTOUIC / AUTORCC passes the top-level CMakeLists turns on by
    # default (they're Qt-Widgets-era conveniences).
    set_target_properties(${name} PROPERTIES
        AUTOMOC OFF
        AUTOUIC OFF
        AUTORCC OFF
    )
    # Auto-discover each TEST() in the binary so ctest prints per-case status
    # instead of one line per binary.
    gtest_discover_tests(${name}
        DISCOVERY_MODE PRE_TEST
        PROPERTIES TIMEOUT 60
    )
endfunction()

peer2pear_add_test(test_crypto_engine)
peer2pear_add_test(test_sqlcipher_db)
peer2pear_add_test(test_sealed_envelope)
peer2pear_add_test(test_ratchet_session)
peer2pear_add_test(test_session_manager)
peer2pear_add_test(test_file_transfer)
peer2pear_add_test(test_e2e_two_clients)
peer2pear_add_test(test_c_api)
peer2pear_add_test(test_relay_cover_traffic)

# test_c_api + test_e2e_two_clients both instantiate ChatController, which — when built with
# PEER2PEAR_P2P=ON — has ctor/dtor paths that reference QuicConnection and
# NiceConnection.  Those .cpp files live in desktop/, not core/, so the
# static library alone leaves the symbols unresolved at link time.  Pull
# them in (and their msquic / libnice / glib deps) just for this binary.
# Mobile builds set PEER2PEAR_P2P=OFF and this block compiles out.
if(PEER2PEAR_P2P)
    foreach(_p2p_test test_e2e_two_clients test_c_api)
        target_sources(${_p2p_test} PRIVATE
            ${CMAKE_SOURCE_DIR}/desktop/QuicConnection.cpp
            ${CMAKE_SOURCE_DIR}/desktop/NiceConnection.cpp
        )
        target_include_directories(${_p2p_test} PRIVATE
            ${CMAKE_SOURCE_DIR}/desktop
        )
        target_link_libraries(${_p2p_test} PRIVATE
            msquic
            PkgConfig::NICE
            PkgConfig::GLIB
        )
    endforeach()
endif()
