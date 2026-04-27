#pragma once

// Migration-blob crypto for Phase 4 backup-strategy step 2 —
// device-to-device account transfer.  Hybrid X25519 + ML-KEM-768
// AEAD seal, mirroring the rest of the protocol's hybrid-PQ
// posture (NoiseState, SealedEnvelope, RatchetSession all use the
// same primitive set).
//
// All functions are stateless + pure.  Caller is responsible for
// wiping returned private keys (secureZero).
//
// Wire format (envelope bytes):
//   [1  byte]   version
//   [32 bytes] sender ephemeral X25519 public key
//   [1088 bytes] ML-KEM-768 ciphertext (encapsulation output)
//   [12 bytes] ChaChaPoly nonce
//   [N+16 bytes] AEAD ciphertext + Poly1305 tag
//
// Total fixed overhead: 1149 bytes.  Identity-only payload (~5KB
// JSON) fits comfortably in MultipeerConnectivity stream-message
// budgets.
//
// Cross-platform: every primitive (libsodium X25519, libsodium
// ChaCha20-Poly1305 IETF, liboqs ML-KEM-768, RFC 5869 HKDF-SHA256)
// is byte-for-byte interoperable with the desktop's Qt build (also
// links libsodium + liboqs).  AAD construction, HKDF parameters,
// and field byte ordering are all fixed at the implementation
// level — when porting to desktop, copy verbatim.

#include "bytes_util.hpp"
#include <cstdint>

namespace MigrationCrypto {

// Public-key sizes — exposed as constexpr so callers (including
// the C API surface) can size their buffers without magic numbers.
constexpr int kX25519PubLen     = 32;
constexpr int kX25519PrivLen    = 32;
constexpr int kMlkemPubLen      = 1184;
constexpr int kMlkemPrivLen     = 2400;
constexpr int kMlkemCtLen       = 1088;
constexpr int kFingerprintLen   = 16;
constexpr int kHandshakeNonceLen = 16;
constexpr int kEnvelopeOverhead = 1
                                 + kX25519PubLen
                                 + kMlkemCtLen
                                 + 12          // ChaChaPoly nonce
                                 + 16;         // Poly1305 tag

constexpr uint8_t kEnvelopeVersion = 1;

struct Keypairs {
    Bytes x25519Pub;   // 32 bytes
    Bytes x25519Priv;  // 32 bytes — caller wipes after use
    Bytes mlkemPub;    // 1184 bytes
    Bytes mlkemPriv;   // 2400 bytes — caller wipes after use
};

/// Generate fresh ephemeral keypairs for both X25519 and ML-KEM-768.
/// Returns a struct with all four members populated, or an
/// all-empty struct on failure (libsodium / liboqs error).
Keypairs generateKeypairs();

/// Compute the QR fingerprint for a pubkey pair.  16 bytes —
/// enough collision resistance for handshake authentication
/// (attacker would need to grind ~2^64 KEM keypairs to find a
/// matching prefix).  Format: SHA-256(x25519_pub || mlkem_pub)[0..16].
/// Returns empty on malformed input.
Bytes fingerprint(const Bytes& x25519Pub, const Bytes& mlkemPub);

/// Seal a payload for transit.
///
/// Inputs:
///   payload        — opaque user data (Swift will pass JSON-encoded
///                     MigrationPayload bytes)
///   receiverX25519 — receiver's ephemeral X25519 pubkey (from QR + MPC)
///   receiverMlkem  — receiver's ephemeral ML-KEM-768 pubkey (from MPC)
///   handshakeNonce — 16-byte nonce from the QR handshake.  Mixed into
///                     HKDF salt so a stale QR can't be reused verbatim
///                     across migration sessions.
///
/// Returns the wire-shaped envelope bytes.  Empty on failure.
Bytes seal(const Bytes& payload,
            const Bytes& receiverX25519Pub,
            const Bytes& receiverMlkemPub,
            const Bytes& handshakeNonce);

/// Open a sealed envelope.
///
/// The receiver passes BOTH their pubs and privs — pubs are needed
/// to reconstruct the AAD identically to how the sender built it
/// (ML-KEM-768 doesn't have a "derive pub from priv" primitive,
/// and even if it did, asking the caller to keep the pubs around
/// avoids redundant key derivation).  The caller already has the
/// pubs in memory from generateKeypairs() at QR-display time.
///
/// Returns decrypted payload bytes, or empty on any failure
/// (auth tag mismatch, version mismatch, malformed wire format).
/// Failure modes are NOT distinguished by return value to avoid
/// giving an attacker an oracle.
Bytes open(const Bytes& envelope,
            const Bytes& receiverX25519Pub,
            const Bytes& receiverX25519Priv,
            const Bytes& receiverMlkemPub,
            const Bytes& receiverMlkemPriv,
            const Bytes& handshakeNonce);

}  // namespace MigrationCrypto
