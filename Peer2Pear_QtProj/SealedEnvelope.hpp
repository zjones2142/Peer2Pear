#pragma once
#include <QByteArray>

/*
 * Sealed Sender Envelope
 *
 * Hides the sender's identity from the relay server. The server only sees
 * the recipient (via the HTTP X-To header) and an opaque sealed blob.
 *
 * Wire format:
 *   ephemeralPub(32) || AEAD(envelopeKey, senderEdPub(32) || signature(64) || innerCt)
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
    // Seal a payload so only the recipient can read it and learn the sender
    //
    // recipientCurvePub: recipient's X25519 public key (32)
    // senderEdPub:       sender's Ed25519 public key (32)
    // senderEdPriv:      sender's Ed25519 private key (64)
    // innerPayload:      the ratchet ciphertext to seal
    //
    // Returns: ephemeralPub(32) || AEAD(envelopeKey, senderEdPub || sig || innerPayload)
    static QByteArray seal(const QByteArray& recipientCurvePub,
                           const QByteArray& senderEdPub,
                           const QByteArray& senderEdPriv,
                           const QByteArray& innerPayload);

    // Unseal an envelope using the recipient's X25519 private key
    //
    // recipientCurvePriv: recipient's X25519 private key (32)
    // sealedBytes:        the sealed envelope
    //
    // Returns UnsealResult with valid=true on success
    static UnsealResult unseal(const QByteArray& recipientCurvePriv,
                                const QByteArray& sealedBytes);
};
