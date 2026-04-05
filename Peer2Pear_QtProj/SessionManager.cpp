#include "SessionManager.hpp"
#include <sodium.h>
#include <QDebug>
#include <QDataStream>
#include <QtEndian>
#include <cstring>

SessionManager::SessionManager(CryptoEngine& crypto, SessionStore& store)
    : m_crypto(crypto)
    , m_store(store)
{}

// ---------------------------
// Session cache
// ---------------------------

RatchetSession* SessionManager::getSession(const QString& peerIdB64u) {
    auto it = m_sessions.find(peerIdB64u);
    if (it != m_sessions.end() && it->isValid()) return &*it;

    // Try loading from DB
    QByteArray blob = m_store.loadSession(peerIdB64u);
    if (blob.isEmpty()) return nullptr;

    RatchetSession session = RatchetSession::deserialize(blob);
    if (!session.isValid()) return nullptr;

    m_sessions[peerIdB64u] = std::move(session);
    return &m_sessions[peerIdB64u];
}

void SessionManager::persistSession(const QString& peerIdB64u) {
    auto it = m_sessions.find(peerIdB64u);
    if (it == m_sessions.end()) return;
    m_store.saveSession(peerIdB64u, it->serialize());
}

bool SessionManager::hasSession(const QString& peerIdB64u) const {
    if (m_sessions.contains(peerIdB64u)) return true;
    return !m_store.loadSession(peerIdB64u).isEmpty();
}

void SessionManager::deleteSession(const QString& peerIdB64u) {
    m_sessions.remove(peerIdB64u);
    m_store.deleteSession(peerIdB64u);
}

// ---------------------------
// Encrypt
// ---------------------------

QByteArray SessionManager::encryptForPeer(const QString& peerIdB64u,
                                           const QByteArray& plaintext) {
    RatchetSession* session = getSession(peerIdB64u);

    if (session) {
        // Existing session — normal ratchet encrypt
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Ratchet encrypting for" << peerIdB64u.left(8) + "..."
                 << "| plaintext:" << plaintext.size() << "B";
#endif
        QByteArray ratchetCt = session->encrypt(plaintext);
        if (ratchetCt.isEmpty()) return {};

        m_lastMessageKey = session->lastMessageKey();
        persistSession(peerIdB64u);

        // [0x03][ratchet_ciphertext]
        QByteArray out;
        out.reserve(1 + ratchetCt.size());
        out.append(static_cast<char>(kRatchetMsg));
        out.append(ratchetCt);
        return out;
    }

    // No session — check if we already have a pending handshake in-flight.
    // If so, DON'T start a new one (that would overwrite the pending state
    // and cause a cryptographic mismatch when the response to the first arrives).
    // The caller will fall back to legacy encryption for this message.
    {
        int pendingRole = 0;
        QByteArray existing = m_store.loadPendingHandshake(peerIdB64u, pendingRole);
        if (!existing.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Handshake already in-flight for"
                     << peerIdB64u.left(8) + "... — skipping, caller uses legacy path";
#endif
            return {};
        }
    }

    // Initiate Noise IK handshake + bundle first ratchet message

    // Get peer's Ed25519 public key and convert to X25519
    QByteArray peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEdPub.size() != 32) return {};

    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(
            peerCurvePub,
            reinterpret_cast<const unsigned char*>(peerEdPub.constData())) != 0) {
        return {};
    }
    QByteArray remoteCurvePub(reinterpret_cast<const char*>(peerCurvePub), 32);

    // Create Noise IK initiator
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Initiating Noise IK handshake with" << peerIdB64u.left(8) + "...";
#endif
    NoiseState noise = NoiseState::createInitiator(
        m_crypto.curvePub(), m_crypto.curvePriv(), remoteCurvePub);

    // Write handshake message 1 (no payload in the handshake itself)
    QByteArray noiseMsg1 = noise.writeMessage1();
    if (noiseMsg1.isEmpty()) {
        qWarning() << "[SessionManager] Failed to write Noise msg1 for" << peerIdB64u.left(8) + "...";
        return {};
    }

    // Derive a one-shot key for the pre-key payload from the Noise chaining key

    // Generate a fresh ratchet DH keypair (independent of Noise ephemeral — key separation)
    auto [ratchetDhPub, ratchetDhPriv] = CryptoEngine::generateEphemeralX25519();

    // Save both the Noise state AND the ratchet DH keypair for when the response arrives
    // Format: [32-byte ratchetDhPub][32-byte ratchetDhPriv][noiseBlob...]
    QByteArray pendingBlob;
    pendingBlob.append(ratchetDhPub);
    pendingBlob.append(ratchetDhPriv);
    pendingBlob.append(noise.serialize());
    m_store.savePendingHandshake(peerIdB64u, NoiseState::Initiator, pendingBlob);
    // L4 fix: zero the local private key copy now that it's persisted (encrypted)
    sodium_memzero(ratchetDhPriv.data(), ratchetDhPriv.size());
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Saved pending handshake + ratchet DH for" << peerIdB64u.left(8) + "...";
#endif

    // Derive a one-shot key from the Noise chaining key after msg1 (secret, shared by both sides)
    QByteArray prekeyKey = CryptoEngine::hkdf(
        noise.postMsg1ChainingKey(), QByteArray("prekey-salt"), QByteArray("prekey-payload"), 32);

    QByteArray encPayload = m_crypto.aeadEncrypt(prekeyKey, plaintext);
    if (encPayload.isEmpty()) {
        qWarning() << "[SessionManager] Pre-key payload encryption failed for" << peerIdB64u.left(8) + "...";
        return {};
    }
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Encrypted pre-key message for" << peerIdB64u.left(8) + "..."
             << "| noiseMsg1:" << noiseMsg1.size() << "B | ratchetDhPub:" << ratchetDhPub.left(4).toHex()
             << "| payload:" << encPayload.size() << "B";
#endif

    // [0x01][4-byte noiseMsg1Len][noiseMsg1][32-byte ratchetDhPub][encPayload]
    quint32 msg1Len = static_cast<quint32>(noiseMsg1.size());
    quint32 msg1LenBE = qToBigEndian(msg1Len);

    QByteArray out;
    out.reserve(1 + 4 + noiseMsg1.size() + 32 + encPayload.size());
    out.append(static_cast<char>(kPreKeyMsg));
    out.append(reinterpret_cast<const char*>(&msg1LenBE), 4);
    out.append(noiseMsg1);
    out.append(ratchetDhPub);   // 32 bytes — responder uses this for initial ratchet DH
    out.append(encPayload);
    return out;
}

// ---------------------------
// Decrypt
// ---------------------------

QByteArray SessionManager::decryptFromPeer(const QString& senderIdB64u,
                                            const QByteArray& blob,
                                            QByteArray* msgKeyOut) {
    if (blob.isEmpty()) return {};

    quint8 msgType = static_cast<quint8>(blob[0]);

    if (msgType == kRatchetMsg) {
        // Normal ratchet message
        RatchetSession* session = getSession(senderIdB64u);
        if (!session) {
            qWarning() << "[SessionManager] No ratchet session for" << senderIdB64u.left(8) + "...";
            return {};
        }

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Decrypting ratchet message from" << senderIdB64u.left(8) + "..."
                 << "| size:" << blob.size() << "B";
#endif
        QByteArray pt = session->decrypt(blob.mid(1));
        if (pt.isEmpty()) {
            qWarning() << "[SessionManager] Ratchet decrypt failed from" << senderIdB64u.left(8) + "...";
            return {};
        }

        m_lastMessageKey = session->lastMessageKey();
        if (msgKeyOut)
            *msgKeyOut = m_lastMessageKey;  // M3 fix: return key directly
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Ratchet decrypt OK from" << senderIdB64u.left(8) + "..."
                 << "| plaintext:" << pt.size() << "B";
#endif
        persistSession(senderIdB64u);
        return pt;
    }

    if (msgType == kPreKeyMsg) {
        // Pre-key message: Noise msg1 + encrypted payload
        // We are the responder
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Received pre-key message from" << senderIdB64u.left(8) + "..."
                 << "| size:" << blob.size() << "B";
#endif

        if (blob.size() < 5) return {};
        quint32 msg1LenBE;
        memcpy(&msg1LenBE, blob.constData() + 1, 4);
        quint32 msg1Len = qFromBigEndian(msg1LenBE);

        // Wire format: [0x01][4-byte msg1Len][noiseMsg1][32-byte ratchetDhPub][encPayload]
        if (blob.size() < static_cast<int>(5 + msg1Len + 32)) return {};
        QByteArray noiseMsg1 = blob.mid(5, static_cast<int>(msg1Len));
        QByteArray initiatorRatchetDhPub = blob.mid(5 + static_cast<int>(msg1Len), 32);
        QByteArray encPayload = blob.mid(5 + static_cast<int>(msg1Len) + 32);

        // Create Noise responder
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Processing Noise IK handshake (responder) from" << senderIdB64u.left(8) + "...";
#endif
        NoiseState noise = NoiseState::createResponder(
            m_crypto.curvePub(), m_crypto.curvePriv());

        QByteArray handshakePayload;
        QByteArray noiseMsg2 = noise.readMessage1AndWriteMessage2(
            noiseMsg1, handshakePayload);
        if (noiseMsg2.isEmpty()) {
            qWarning() << "[SessionManager] Failed to process Noise msg1 from" << senderIdB64u.left(8) + "...";
            return {};
        }

        // Capture our ephemeral keypair BEFORE finish() — finish() zeros m_ek
        QByteArray ephPub  = noise.ephemeralPub();
        QByteArray ephPriv = noise.ephemeralPriv();

        // Complete the handshake
        HandshakeResult hr = noise.finish();
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Noise IK handshake complete (responder) for" << senderIdB64u.left(8) + "...";
#endif

        // Initialize ratchet with the initiator's fresh ratchet DH pub (from wire format)
        // This lets us derive both recv and send chains immediately — no LEGACY fallback
        RatchetSession ratchet = RatchetSession::initAsResponder(
            hr.sendCipher.key, ephPub, ephPriv, initiatorRatchetDhPub);

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Double Ratchet session initialized (responder) for" << senderIdB64u.left(8) + "...";
#endif

        // Decrypt the pre-key payload using the Noise chaining key after msg1 (secret)
        // Both sides snapshot m_ck after the same 4 DH ops (e, es, s, ss)
        QByteArray prekeyKey = CryptoEngine::hkdf(
            noise.postMsg1ChainingKey(), QByteArray("prekey-salt"), QByteArray("prekey-payload"), 32);
        QByteArray pt = m_crypto.aeadDecrypt(prekeyKey, encPayload);
        if (!pt.isEmpty()) {
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Pre-key payload decrypted OK |" << pt.size() << "B";
#endif
        } else {
            qWarning() << "[SessionManager] Pre-key payload decryption FAILED";
        }

        // Send back the Noise msg2 as a pre-key response
        if (m_sendResponse) {
            // [0x02][4-byte noiseMsg2Len][noiseMsg2]
            quint32 msg2Len = static_cast<quint32>(noiseMsg2.size());
            quint32 msg2LenBE = qToBigEndian(msg2Len);

            QByteArray response;
            response.reserve(1 + 4 + noiseMsg2.size());
            response.append(static_cast<char>(kPreKeyResponse));
            response.append(reinterpret_cast<const char*>(&msg2LenBE), 4);
            response.append(noiseMsg2);

            m_sendResponse(senderIdB64u, response);
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Sent Noise msg2 (pre-key response) to" << senderIdB64u.left(8) + "...";
#endif
        }

        return pt;
    }

    if (msgType == kPreKeyResponse) {
        // Pre-key response: Noise msg2 from responder
        // We are the initiator — complete the handshake
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Received pre-key response from" << senderIdB64u.left(8) + "...";
#endif

        if (blob.size() < 5) return {};
        quint32 msg2LenBE;
        memcpy(&msg2LenBE, blob.constData() + 1, 4);
        quint32 msg2Len = qFromBigEndian(msg2LenBE);

        if (blob.size() < static_cast<int>(5 + msg2Len)) return {};
        QByteArray noiseMsg2 = blob.mid(5, static_cast<int>(msg2Len));

        // Load our pending handshake state (format: [32 ratchetPub][32 ratchetPriv][noiseBlob...])
        int role = 0;
        QByteArray pendingBlob = m_store.loadPendingHandshake(senderIdB64u, role);
        if (pendingBlob.size() < 64 || role != NoiseState::Initiator) {
            qWarning() << "[SessionManager] No pending initiator handshake for" << senderIdB64u.left(8) + "...";
            return {};
        }

        // Extract saved ratchet DH keypair (fresh, independent of Noise ephemeral)
        QByteArray ratchetDhPub  = pendingBlob.left(32);
        QByteArray ratchetDhPriv = pendingBlob.mid(32, 32);
        QByteArray hsBlob        = pendingBlob.mid(64);

        NoiseState noise = NoiseState::deserialize(hsBlob);
        QByteArray responsePayload;
        if (!noise.readMessage2(noiseMsg2, responsePayload)) {
            qWarning() << "[SessionManager] Failed to process Noise msg2 from" << senderIdB64u.left(8) + "...";
            return {};
        }

        HandshakeResult hr = noise.finish();
        m_store.deletePendingHandshake(senderIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Noise IK handshake complete (initiator) for" << senderIdB64u.left(8) + "...";
#endif

        // Initialize ratchet with our saved fresh ratchet DH keypair
        // The responder's Noise ephemeral (first 32 bytes of msg2) is the remote DH pub
        QByteArray responderEphPub = noiseMsg2.left(32);

        RatchetSession ratchet = RatchetSession::initAsInitiator(
            hr.recvCipher.key, responderEphPub, ratchetDhPub, ratchetDhPriv);
        // L4 fix: zero extracted private key now that ratchet owns it
        sodium_memzero(ratchetDhPriv.data(), ratchetDhPriv.size());
        sodium_memzero(pendingBlob.data(), pendingBlob.size());

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Double Ratchet session initialized (initiator) for" << senderIdB64u.left(8) + "...";
#endif

        // The pre-key response may not carry user payload (it's a handshake completion)
        // Return the response payload if present
        return responsePayload;
    }

    qWarning() << "[SessionManager] Unknown message type" << msgType;
    return {};
}
