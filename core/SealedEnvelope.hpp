#pragma once

#include "types.hpp"

#include <cstdint>
#include <vector>

/*
 * Sealed Sender Envelope — hybrid X25519 + ML-KEM-768
 *
 * Hides the sender's identity from the relay server. The server only sees
 * the recipient (via the HTTP X-To header) and an opaque sealed blob.
 *
 * Classical v2 wire format (version 0x02):
 *   0x02 || ephPub(32) || AEAD(envelopeKey, AAD=ephPub||recipientEdPub,
 *                               envelopeId(16) || senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(key="Peer2Pear-SealedEnvelope-v2", ecdhShared)
 *
 * Hybrid v2 wire format (version 0x03):
 *   0x03 || ephPub(32) || kemCt(1088) || AEAD(envelopeKey, AAD=ephPub||recipientEdPub,
 *                                              envelopeId(16) || senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(key="Peer2Pear-SealedEnvelope-v2", ecdhShared || kemShared)
 *
 * The sender signs (envelopeId || innerPayload) with their Ed25519 key.
 * Binding recipientEdPub into the AEAD AAD prevents a malicious relay from
 * re-routing the sealed blob to a different recipient.
 * The envelopeId is 16 random bytes that the receiver uses for replay detection.
 *
 * Types: std::vector<uint8_t> for all binary buffers.
 */


struct UnsealResult {
    Bytes senderEdPub;   // 32 bytes — sender's Ed25519 public key
    Bytes innerPayload;  // decrypted inner ciphertext
    Bytes envelopeId;    // 16 bytes — unique per-envelope id, for replay dedup
    bool  valid = false;
};

// Inner-wire prefixes prepended to a sealed envelope before it's
// wrapped into a routing envelope.  They tell the receiver which
// decrypt path to take:
//
//   kSealedPrefix      — ratchet ciphertext.  Goes through
//                        SessionManager::decryptFromPeer.
//   kSealedFCPrefix    — AEAD-encrypted file chunk under a per-file
//                        key derived from the ratchet.  Handled by
//                        FileTransferManager::handleFileEnvelope.
//
// These are wire-format constants — changing their bytes breaks
// every deployed client.  The reference implementation used to
// duplicate them across SessionSealer.cpp and ChatController.cpp
// with a comment asking future authors to keep them in sync by
// hand; consolidating here means the compiler catches drift.
inline constexpr const char kSealedPrefix[]   = "SEALED:";
inline constexpr const char kSealedFCPrefix[] = "SEALEDFC:";

class SealedEnvelope {
public:
    // Seal a payload so only the recipient can read it and learn the sender.
    //
    // If recipientKemPub is non-empty (1184 bytes), a hybrid X25519 + ML-KEM-768
    // envelope is produced. Otherwise, a classical X25519-only envelope is used.
    //
    // If senderDsaPub/Priv are non-empty, a hybrid Ed25519 + ML-DSA-65 signature
    // is included alongside the classical Ed25519 signature.
    //
    // recipientCurvePub: recipient's X25519 public key (32)
    // recipientEdPub:    recipient's Ed25519 public key (32) — bound into AAD so
    //                    the envelope can't be re-routed to a different recipient
    // senderEdPub:       sender's Ed25519 public key (32)
    // senderEdPriv:      sender's Ed25519 private key (64)
    // innerPayload:      the ratchet ciphertext to seal
    // recipientKemPub:   recipient's ML-KEM-768 public key (1184, optional)
    // senderDsaPub:      sender's ML-DSA-65 public key (1952, optional)
    // senderDsaPriv:     sender's ML-DSA-65 private key (4032, optional)
    static Bytes seal(const Bytes& recipientCurvePub,
                      const Bytes& recipientEdPub,
                      const Bytes& senderEdPub,
                      const Bytes& senderEdPriv,
                      const Bytes& innerPayload,
                      const Bytes& recipientKemPub = {},
                      const Bytes& senderDsaPub = {},
                      const Bytes& senderDsaPriv = {});

    // Wrap a sealed envelope with a routing header + padding for relay transport.
    // Format: 0x01 || recipientEdPub(32) || innerLen(4 BE) || sealedBytes || randomPadding
    // Padded to fixed bucket sizes (2/16/256 KiB) so the relay can't distinguish
    // message types by size. The relay reads bytes 0-32 for routing only.
    static Bytes wrapForRelay(const Bytes& recipientEdPub,
                              const Bytes& sealedBytes);

    // Strip the routing header and padding, returning the inner sealed envelope.
    // Also extracts the recipientEdPub if non-null.
    // Returns empty if the header is malformed.
    static Bytes unwrapFromRelay(const Bytes& relayEnvelope,
                                 Bytes* recipientEdPub = nullptr);

    // Strip the routing header IFF `relayEnvelope` carries one, otherwise
    // return the input unchanged.  Useful for callers that need to hash or
    // sign the same shape the receiver naturally sees (post-strip), without
    // caring whether transport added the routing wrap.  Detection mirrors
    // ChatController::onEnvelope and onP2PDataReceived.
    static Bytes stripRoutingIfWrapped(const Bytes& relayEnvelope);

    // Pad a P2P QUIC-stream payload to the next fixed bucket so an
    // external network observer can't distinguish file chunks from
    // control frames by size alone.  Wire layout:
    //   innerLen(4 BE) || payload || randomPadding
    // Buckets are the same 2 / 16 / 256 KiB set used by wrapForRelay.
    // Unlike wrapForRelay, there's no routing header (P2P is already
    // addressed by the QUIC connection itself).
    static Bytes padForP2P(const Bytes& payload);

    // Strip the length header + padding added by padForP2P.  Returns
    // empty if the header is malformed or claims more bytes than the
    // framed buffer can hold.
    static Bytes unpadFromP2P(const Bytes& padded);

    // Unseal an envelope using the recipient's keys.
    //
    // recipientCurvePriv: recipient's X25519 private key (32)
    // recipientEdPub:     recipient's Ed25519 public key (32) — must match the
    //                     AAD the sender used, or AEAD decryption will fail.
    // sealedBytes:        the sealed envelope (classical v2 or hybrid v2)
    // recipientKemPriv:   recipient's ML-KEM-768 private key (2400, optional)
    //                     Required for hybrid envelopes (version 0x03).
    static UnsealResult unseal(const Bytes& recipientCurvePriv,
                               const Bytes& recipientEdPub,
                               const Bytes& sealedBytes,
                               const Bytes& recipientKemPriv = {});
};
