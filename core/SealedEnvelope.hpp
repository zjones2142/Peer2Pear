#pragma once
#include <QByteArray>

/*
 * Sealed Sender Envelope — hybrid X25519 + ML-KEM-768
 *
 * Hides the sender's identity from the relay server. The server only sees
 * the recipient (via the HTTP X-To header) and an opaque sealed blob.
 *
 * Classical v2 wire format (version 0x02):
 *   0x02 || ephPub(32) || AEAD(envelopeKey, AAD=ephPub||recipientEdPub,
 *                               envelopeId(16) || senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(ecdhShared)
 *
 * Hybrid v2 wire format (version 0x03):
 *   0x03 || ephPub(32) || kemCt(1088) || AEAD(envelopeKey, AAD=ephPub||recipientEdPub,
 *                                              envelopeId(16) || senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(ecdhShared || kemShared)
 *
 * The sender signs (envelopeId || innerPayload) with their Ed25519 key.
 * Binding recipientEdPub into the AEAD AAD prevents a malicious relay from
 * re-routing the sealed blob to a different recipient.
 * The envelopeId is 16 random bytes that the receiver uses for replay detection.
 */

struct UnsealResult {
    QByteArray senderEdPub;   // 32 bytes — sender's Ed25519 public key
    QByteArray innerPayload;  // decrypted inner ciphertext
    QByteArray envelopeId;    // 16 bytes — unique per-envelope id, for replay dedup
    bool       valid = false;
};

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
    static QByteArray seal(const QByteArray& recipientCurvePub,
                           const QByteArray& recipientEdPub,
                           const QByteArray& senderEdPub,
                           const QByteArray& senderEdPriv,
                           const QByteArray& innerPayload,
                           const QByteArray& recipientKemPub = {},
                           const QByteArray& senderDsaPub = {},
                           const QByteArray& senderDsaPriv = {});

    // Wrap a sealed envelope with a routing header + padding for relay transport.
    // Format: 0x01 || recipientEdPub(32) || innerLen(4 BE) || sealedBytes || randomPadding
    // Padded to fixed bucket sizes (2/16/256 KiB) so the relay can't distinguish
    // message types by size. The relay reads bytes 0-32 for routing only.
    static QByteArray wrapForRelay(const QByteArray& recipientEdPub,
                                    const QByteArray& sealedBytes);

    // Strip the routing header and padding, returning the inner sealed envelope.
    // Also extracts the recipientEdPub if non-null.
    // Returns empty if the header is malformed.
    static QByteArray unwrapFromRelay(const QByteArray& relayEnvelope,
                                      QByteArray* recipientEdPub = nullptr);

    // Unseal an envelope using the recipient's keys.
    //
    // recipientCurvePriv: recipient's X25519 private key (32)
    // recipientEdPub:     recipient's Ed25519 public key (32) — must match the
    //                     AAD the sender used, or AEAD decryption will fail.
    // sealedBytes:        the sealed envelope (classical v2 or hybrid v2)
    // recipientKemPriv:   recipient's ML-KEM-768 private key (2400, optional)
    //                     Required for hybrid envelopes (version 0x03).
    static UnsealResult unseal(const QByteArray& recipientCurvePriv,
                                const QByteArray& recipientEdPub,
                                const QByteArray& sealedBytes,
                                const QByteArray& recipientKemPriv = {});
};
