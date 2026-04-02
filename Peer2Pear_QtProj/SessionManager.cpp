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

    // No session — initiate Noise IK handshake + bundle first ratchet message

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
    NoiseState noise = NoiseState::createInitiator(
        m_crypto.curvePub(), m_crypto.curvePriv(), remoteCurvePub);

    // Write handshake message 1 (no payload in the handshake itself)
    QByteArray noiseMsg1 = noise.writeMessage1();
    if (noiseMsg1.isEmpty()) return {};

    // Save the noise state so we can process the response later
    m_store.savePendingHandshake(peerIdB64u, NoiseState::Initiator, noise.serialize());

    // We can't create a ratchet session yet (need the response),
    // but we can encrypt the payload with a temporary key derived from
    // the Noise state's current chaining key.
    // For now, we'll encrypt the payload using the static shared key
    // derived from ECDH (same as legacy) as a "pre-key payload".
    // The recipient will decrypt this after completing the handshake.

    // Actually, per the Noise spec, after writing msg1 in IK pattern,
    // the initiator already has transport encryption available (one-way).
    // But the Double Ratchet needs both sides' ephemeral keys.
    // So we bundle the plaintext encrypted with a one-shot key derived
    // from the Noise handshake's current state.

    // Derive a one-shot key from the Noise chaining key after msg1 (secret, shared by both sides)
    QByteArray prekeyKey = CryptoEngine::hkdf(
        noise.postMsg1ChainingKey(), QByteArray("prekey-salt"), QByteArray("prekey-payload"), 32);

    QByteArray encPayload = m_crypto.aeadEncrypt(prekeyKey, plaintext);
    if (encPayload.isEmpty()) return {};

    // [0x01][4-byte noiseMsg1Len][noiseMsg1][encPayload]
    quint32 msg1Len = static_cast<quint32>(noiseMsg1.size());
    quint32 msg1LenBE = qToBigEndian(msg1Len);

    QByteArray out;
    out.reserve(1 + 4 + noiseMsg1.size() + encPayload.size());
    out.append(static_cast<char>(kPreKeyMsg));
    out.append(reinterpret_cast<const char*>(&msg1LenBE), 4);
    out.append(noiseMsg1);
    out.append(encPayload);
    return out;
}

// ---------------------------
// Decrypt
// ---------------------------

QByteArray SessionManager::decryptFromPeer(const QString& senderIdB64u,
                                            const QByteArray& blob) {
    if (blob.isEmpty()) return {};

    quint8 msgType = static_cast<quint8>(blob[0]);

    if (msgType == kRatchetMsg) {
        // Normal ratchet message
        RatchetSession* session = getSession(senderIdB64u);
        if (!session) {
            qWarning() << "SessionManager: no session for ratchet message from" << senderIdB64u;
            return {};
        }

        QByteArray pt = session->decrypt(blob.mid(1));
        if (pt.isEmpty()) return {};

        persistSession(senderIdB64u);
        return pt;
    }

    if (msgType == kPreKeyMsg) {
        // Pre-key message: Noise msg1 + encrypted payload
        // We are the responder

        if (blob.size() < 5) return {};
        quint32 msg1LenBE;
        memcpy(&msg1LenBE, blob.constData() + 1, 4);
        quint32 msg1Len = qFromBigEndian(msg1LenBE);

        if (blob.size() < static_cast<int>(5 + msg1Len)) return {};
        QByteArray noiseMsg1 = blob.mid(5, static_cast<int>(msg1Len));
        QByteArray encPayload = blob.mid(5 + static_cast<int>(msg1Len));

        // Create Noise responder
        NoiseState noise = NoiseState::createResponder(
            m_crypto.curvePub(), m_crypto.curvePriv());

        QByteArray handshakePayload;
        QByteArray noiseMsg2 = noise.readMessage1AndWriteMessage2(
            noiseMsg1, handshakePayload);
        if (noiseMsg2.isEmpty()) {
            qWarning() << "SessionManager: failed to process Noise msg1 from" << senderIdB64u;
            return {};
        }

        // Complete the handshake
        HandshakeResult hr = noise.finish();

        // Initialize ratchet session as responder
        // Use the responder's Noise ephemeral as the initial DH ratchet key
        // The initiator's Noise ephemeral (first 32 bytes of msg1) is the remote DH pub
        QByteArray initiatorEphPub = noiseMsg1.left(32);

        // Create ratchet: we are responder, so we use our Noise ephemeral
        // as our initial DH ratchet keypair
        auto [ephPub, ephPriv] = CryptoEngine::generateEphemeralX25519();
        RatchetSession ratchet = RatchetSession::initAsResponder(
            hr.sendCipher.key, ephPub, ephPriv);

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);

        // Decrypt the pre-key payload using the Noise chaining key after msg1 (secret)
        // Both sides snapshot m_ck after the same 4 DH ops (e, es, s, ss)
        QByteArray prekeyKey = CryptoEngine::hkdf(
            noise.postMsg1ChainingKey(), QByteArray("prekey-salt"), QByteArray("prekey-payload"), 32);
        QByteArray pt = m_crypto.aeadDecrypt(prekeyKey, encPayload);

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
        }

        return pt;
    }

    if (msgType == kPreKeyResponse) {
        // Pre-key response: Noise msg2 from responder
        // We are the initiator — complete the handshake

        if (blob.size() < 5) return {};
        quint32 msg2LenBE;
        memcpy(&msg2LenBE, blob.constData() + 1, 4);
        quint32 msg2Len = qFromBigEndian(msg2LenBE);

        if (blob.size() < static_cast<int>(5 + msg2Len)) return {};
        QByteArray noiseMsg2 = blob.mid(5, static_cast<int>(msg2Len));

        // Load our pending handshake state
        int role = 0;
        QByteArray hsBlob = m_store.loadPendingHandshake(senderIdB64u, role);
        if (hsBlob.isEmpty() || role != NoiseState::Initiator) {
            qWarning() << "SessionManager: no pending initiator handshake for" << senderIdB64u;
            return {};
        }

        NoiseState noise = NoiseState::deserialize(hsBlob);
        QByteArray responsePayload;
        if (!noise.readMessage2(noiseMsg2, responsePayload)) {
            qWarning() << "SessionManager: failed to process Noise msg2 from" << senderIdB64u;
            return {};
        }

        HandshakeResult hr = noise.finish();
        m_store.deletePendingHandshake(senderIdB64u);

        // Initialize ratchet session as initiator
        // The responder's Noise ephemeral (first 32 bytes of msg2) is the remote DH pub
        QByteArray responderEphPub = noiseMsg2.left(32);

        RatchetSession ratchet = RatchetSession::initAsInitiator(
            hr.recvCipher.key, responderEphPub);

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);

        // The pre-key response may not carry user payload (it's a handshake completion)
        // Return the response payload if present
        return responsePayload;
    }

    qWarning() << "SessionManager: unknown message type" << msgType;
    return {};
}
