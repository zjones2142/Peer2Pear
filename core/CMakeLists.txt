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
    SessionManager.cpp      SessionManager.hpp
    SessionStore.cpp        SessionStore.hpp
    SqlCipherDb.cpp         SqlCipherDb.hpp
    ChatController.cpp      ChatController.hpp
    RelayClient.cpp         RelayClient.hpp
    FileTransferManager.cpp FileTransferManager.hpp
    chattypes.h
    filetransfer.h
)

add_library(peer2pear-core STATIC ${CORE_SOURCES})

# Public include directory so desktop/ (and future mobile/) can
# #include "ChatController.hpp" etc. without path prefixes.
target_include_directories(peer2pear-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(peer2pear-core PUBLIC cxx_std_17)

target_link_libraries(peer2pear-core PUBLIC
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Network
    Qt${QT_VERSION_MAJOR}::WebSockets
    unofficial-sodium::sodium
    OQS::oqs
    ${SQLCIPHER_TARGET}
)

# Suppress qDebug in release builds
target_compile_definitions(peer2pear-core PRIVATE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:QT_NO_DEBUG_OUTPUT>
)
