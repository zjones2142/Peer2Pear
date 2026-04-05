#pragma once
#include <QByteArray>

/*
 * Sealed Sender Envelope — hybrid X25519 + ML-KEM-768
 *
 * Hides the sender's identity from the relay server. The server only sees
 * the recipient (via the HTTP X-To header) and an opaque sealed blob.
 *
 * Classical wire format (version 0x00):
 *   0x00 || ephPub(32) || AEAD(envelopeKey, senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(ecdhShared)
 *
 * Hybrid wire format (version 0x01):
 *   0x01 || ephPub(32) || kemCt(1088) || AEAD(envelopeKey, senderEdPub(32) || sig(64) || innerCt)
 *   envelopeKey = BLAKE2b-256(ecdhShared || kemShared)
 *
 * The sender signs the inner ciphertext with their Ed25519 key to prove
 * identity to the recipient without exposing it to the server.
 */

struct UnsealResult {
    QByteArray senderEdPub;   // 32 bytes — sender's Ed25519 public key
    QByteArray innerPayload;  // decrypted inner ciphertext
    bool       valid = false;
};

class SealedEnvelope {
public:
    // Seal a payload so only the recipient can read it and learn the sender.
    //
    // If recipientKemPub is non-empty (1184 bytes), a hybrid X25519 + ML-KEM-768
    // envelope is produced. Otherwise, a classical X25519-only envelope is used.
    //
    // recipientCurvePub: recipient's X25519 public key (32)
    // senderEdPub:       sender's Ed25519 public key (32)
    // senderEdPriv:      sender's Ed25519 private key (64)
    // innerPayload:      the ratchet ciphertext to seal
    // recipientKemPub:   recipient's ML-KEM-768 public key (1184, optional)
    static QByteArray seal(const QByteArray& recipientCurvePub,
                           const QByteArray& senderEdPub,
                           const QByteArray& senderEdPriv,
                           const QByteArray& innerPayload,
                           const QByteArray& recipientKemPub = {});

    // Unseal an envelope using the recipient's keys.
    //
    // recipientCurvePriv: recipient's X25519 private key (32)
    // sealedBytes:        the sealed envelope (classical or hybrid)
    // recipientKemPriv:   recipient's ML-KEM-768 private key (2400, optional)
    //                     Required for hybrid envelopes (version 0x01).
    static UnsealResult unseal(const QByteArray& recipientCurvePriv,
                                const QByteArray& sealedBytes,
                                const QByteArray& recipientKemPriv = {});
};
