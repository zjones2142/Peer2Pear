# ── libpeer2pear-core ──────────────────────────────────────────────────────────
#
# Static library containing the Peer2Pear messaging protocol:
#   - Cryptography (Ed25519, X25519, ML-KEM-768, ML-DSA-65, AEAD)
#   - Noise IK handshake (classical + hybrid post-quantum)
#   - Double Ratchet with KEM augmentation
#   - Sealed Sender envelopes (hybrid X25519 + ML-KEM-768)
#   - Session management and encrypted persistence
#   - WebSocket relay transport (anonymous send, push receive)
#   - Chunked encrypted file transfers
#
# Does NOT depend on Qt::Widgets, libnice, GLib, or msquic.
# Desktop-only transport (ICE/QUIC) lives in the desktop/ target.

set(CORE_SOURCES
    CryptoEngine.cpp        CryptoEngine.hpp
    NoiseState.cpp          NoiseState.hpp
    RatchetSession.cpp      RatchetSession.hpp
    SealedEnvelope.cpp      SealedEnvelope.hpp
    OnionWrap.cpp           OnionWrap.hpp
    SessionManager.cpp      SessionManager.hpp
    SessionStore.cpp        SessionStore.hpp
    SqlCipherDb.cpp         SqlCipherDb.hpp
    AppDataStore.cpp        AppDataStore.hpp
    SessionSealer.cpp       SessionSealer.hpp
    SenderChain.cpp         SenderChain.hpp
    GroupProtocol.cpp       GroupProtocol.hpp
    FileProtocol.cpp        FileProtocol.hpp
    ChatController.cpp      ChatController.hpp
    RelayClient.cpp         RelayClient.hpp
    FileTransferManager.cpp FileTransferManager.hpp
    MigrationCrypto.cpp     MigrationCrypto.hpp
    IWebSocket.hpp
    IHttpClient.hpp
    peer2pear.h
    peer2pear_api.cpp
)

add_library(peer2pear-core STATIC ${CORE_SOURCES})

# NOTE: PEER2PEAR_P2P is declared at the top-level CMakeLists.txt so it
# can drive vcpkg manifest features.  Don't redeclare it here.

# Public include directory so desktop/ (and future mobile/) can
# #include "ChatController.hpp" etc. without path prefixes.
target_include_directories(peer2pear-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(peer2pear-core PUBLIC cxx_std_17)

target_link_libraries(peer2pear-core PUBLIC
    unofficial-sodium::sodium
    OQS::oqs
    nlohmann_json::nlohmann_json
    ${SQLCIPHER_TARGET}
)

# Qt::Core is **conditional**, not unconditional, after Phase 7c (2026-04-18).
#
# The two Qt holdouts that justify linking it:
#   1. ChatController.cpp uses QObject::connect / QByteArray bridges to talk
#      to QuicConnection (a QObject in desktop/) — only when PEER2PEAR_P2P=ON.
#   2. CryptoEngine.cpp + FileTransferManager.cpp use QStandardPaths to find
#      the platform default data/download directory — only when QT_CORE_LIB
#      is defined (which is automatic when Qt::Core is on the link line).
#   3. SqlCipherDb.hpp exposes QString/QByteArray convenience overloads for
#      desktop callers that haven't migrated — also `#ifdef QT_CORE_LIB`.
#
# Mobile builds (iOS/Android) turn PEER2PEAR_P2P off and pass
# WITH_QT_CORE=OFF, in which case core/ links zero Qt libraries.  Desktop
# still pulls Qt::Core in transitively via Qt::Widgets either way.
option(WITH_QT_CORE "Link core/ against Qt::Core (desktop default; iOS=OFF)" ON)
if(WITH_QT_CORE)
    target_link_libraries(peer2pear-core PUBLIC Qt${QT_VERSION_MAJOR}::Core)
endif()

# NOTE: Qt::Network and Qt::WebSockets removed from core — abstracted behind
# IHttpClient and IWebSocket interfaces. Desktop provides Qt implementations.

# Suppress qDebug in release builds
target_compile_definitions(peer2pear-core PRIVATE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:QT_NO_DEBUG_OUTPUT>
)
