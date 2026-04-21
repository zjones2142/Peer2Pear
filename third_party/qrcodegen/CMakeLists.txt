# ── qrcodegen — Project Nayuki's MIT-licensed QR encoder ────────────────────
#
# Vendored single-pair (qrcodegen.hpp + qrcodegen.cpp) QR Code generator,
# used by desktop/ to render the user's peer ID as a scannable QR for the
# Edit Profile dialog.  The library is pure C++17 — no external deps.
#
# Mobile (iOS) uses CoreImage's built-in qrCodeGenerator filter and does
# not link this library; it's therefore only added when BUILD_DESKTOP is on.
# (The top-level CMakeLists guards add_subdirectory accordingly.)

add_library(qrcodegen STATIC qrcodegen.cpp qrcodegen.hpp)

# Pure C++ — skip the Qt AUTOMOC/AUTOUIC/AUTORCC passes the top-level
# CMakeLists turns on globally (same reasoning as third_party/sqlcipher).
set_target_properties(qrcodegen PROPERTIES
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)

target_compile_features(qrcodegen PUBLIC cxx_std_17)

# Consumers #include "qrcodegen.hpp" — expose its directory.
target_include_directories(qrcodegen PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
