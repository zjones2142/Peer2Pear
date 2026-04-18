#pragma once

#include <cstdint>
#include <string>
#include <vector>

/*
 * Onion layer for multi-hop relay routing.
 *
 * PROBLEM the audit found (#7):
 *   The old /v1/forward endpoint was "single-layer" — the outer body still
 *   began with [0x01][recipientEdPub(32)], so the intermediate relay saw
 *   BOTH the sender's IP and the final recipient.  Worst of both worlds.
 *
 * FIX: real onion routing.  Each hop decrypts its own layer using its own
 * X25519 private key, learning ONLY the next-hop URL and an opaque blob.
 * Only the final hop sees the recipient pubkey (unavoidable — someone has
 * to route).
 *
 * Wire format per hop:
 *
 *   [version(1=0x01)]
 *   [ephPub(32)]                      — client's ephemeral X25519 pub, this hop only
 *   [nonce(24)]                       — for crypto_box
 *   [boxCiphertext]                   — Box(relayPub, ephPriv, nonce, plaintext)
 *
 * Box plaintext =
 *   [nextHopUrlLen(2 BE)]
 *   [nextHopUrl UTF-8]                — full URL including path
 *                                        /v1/forward-onion for another onion hop
 *                                        /v1/send for the final hop
 *   [innerBlob]                       — the next layer (another onion) or the
 *                                        wrap-for-relay envelope at the final hop
 *
 * The crypto is crypto_box_easy (X25519-XSalsa20-Poly1305) — the same NaCl
 * Box used on both Go (x/crypto/nacl/box) and Python (pynacl.Box) relays.
 *
 * Types:
 *   bytes → std::vector<uint8_t>       (binary buffers)
 *   url   → std::string                (UTF-8)
 *
 * Ported off Qt containers 2026-04 as part of the core/ mobile-portability
 * refactor.  See REFACTOR_PLAN.md.
 */

class OnionWrap {
public:
    // Wrap a single onion layer for a hop at `relayX25519Pub`.
    // After the hop decrypts, it sees (nextHopUrl, innerBlob) and POSTs
    // innerBlob to nextHopUrl.
    //
    // @param relayX25519Pub   the hop's X25519 public key (32 bytes)
    // @param nextHopUrl       full URL the hop should forward to (UTF-8)
    // @param innerBlob        the next layer's bytes (another onion or
    //                         a wrap-for-relay envelope at the final hop)
    // @return onion envelope bytes; empty on failure
    static std::vector<uint8_t> wrap(const std::vector<uint8_t>& relayX25519Pub,
                                      const std::string&          nextHopUrl,
                                      const std::vector<uint8_t>& innerBlob);
};
