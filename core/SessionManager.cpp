#include "SessionManager.hpp"
#include "qt_bridge_temp.hpp"  // TEMP: bridge for SessionStore (still on Qt, Phase 6)
#include <sodium.h>
#include <QDebug>
#include <cstring>
#include <algorithm>

// ---------------------------
// Small local helpers
// ---------------------------

namespace {

// Display-only — first 8 chars of a peer ID plus ellipsis.  Used only for
// logging, never for identity comparisons.
inline QString peerPrefix(const std::string& id) {
    const size_t n = std::min<size_t>(8, id.size());
    return QString::fromStdString(id.substr(0, n)) + "...";
}

inline void write_u32_be(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
    dst[3] = static_cast<uint8_t>( v        & 0xFF);
}

inline uint32_t read_u32_be(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) <<  8) |
            static_cast<uint32_t>(src[3]);
}

inline void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
inline void append(Bytes& dst, const uint8_t* src, size_t n) {
    dst.insert(dst.end(), src, src + n);
}

inline Bytes slice(const Bytes& src, size_t off, size_t len) {
    if (off + len > src.size()) return {};
    return Bytes(src.begin() + off, src.begin() + off + len);
}
inline Bytes tail(const Bytes& src, size_t off) {
    if (off >= src.size()) return {};
    return Bytes(src.begin() + off, src.end());
}

}  // anonymous namespace

SessionManager::SessionManager(CryptoEngine& crypto, SessionStore& store)
    : m_crypto(crypto)
    , m_store(store)
{}

// ---------------------------
// Session cache
// ---------------------------

RatchetSession* SessionManager::getSession(const std::string& peerIdB64u) {
    auto it = m_sessions.find(peerIdB64u);
    if (it != m_sessions.end() && it->second.isValid()) return &it->second;

    // Try loading from DB
    Bytes blob = m_store.loadSession(peerIdB64u);
    if (blob.empty()) return nullptr;

    RatchetSession session = RatchetSession::deserialize(blob);
    if (!session.isValid()) return nullptr;

    m_sessions[peerIdB64u] = std::move(session);
    return &m_sessions[peerIdB64u];
}

void SessionManager::persistSession(const std::string& peerIdB64u) {
    auto it = m_sessions.find(peerIdB64u);
    if (it == m_sessions.end()) return;
    m_store.saveSession(peerIdB64u, it->second.serialize());
}

bool SessionManager::hasSession(const std::string& peerIdB64u) const {
    if (m_sessions.count(peerIdB64u)) return true;
    return !m_store.loadSession(peerIdB64u).empty();
}

void SessionManager::deleteSession(const std::string& peerIdB64u) {
    m_sessions.erase(peerIdB64u);
    m_store.deleteSession(peerIdB64u);
}

// ---------------------------
// Encrypt
// ---------------------------

Bytes SessionManager::encryptForPeer(const std::string& peerIdB64u,
                                      const Bytes& plaintext,
                                      const Bytes& peerKemPub) {
    using p2p::bridge::toBytes;
    using p2p::bridge::toQByteArray;
    using p2p::bridge::strBytes;

    RatchetSession* session = getSession(peerIdB64u);

    if (session) {
        // Existing session — normal ratchet encrypt
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Ratchet encrypting for" << peerPrefix(peerIdB64u)
                 << "| plaintext:" << int(plaintext.size()) << "B";
#endif
        Bytes ratchetCt = session->encrypt(plaintext);
        if (ratchetCt.empty()) return {};

        m_lastMessageKey = session->lastMessageKey();
        persistSession(peerIdB64u);

        // [0x03][ratchet_ciphertext]
        Bytes out;
        out.reserve(1 + ratchetCt.size());
        out.push_back(kRatchetMsg);
        append(out, ratchetCt);
        return out;
    }

    // No session — check if we already have a pending handshake in-flight.
    // If so, derive an additional pre-key message key from the Noise chaining
    // key and encrypt.  This lets Alice send multiple messages to Bob while
    // the handshake is pending — they'll all be decryptable once Bob processes
    // the handshake init.
    {
        int pendingRole = 0;
        Bytes existing = m_store.loadPendingHandshake(peerIdB64u, pendingRole);
        if (!existing.empty() && pendingRole == NoiseState::Initiator) {
            // Pending blob: [ratchetDhPub(32)][ratchetDhPriv(32)][ck(32)][counter(4 BE)][noiseBlob]
            if (existing.size() < 100) return {};  // sanity check

            Bytes ck = slice(existing, 64, 32);
            uint32_t counter = read_u32_be(existing.data() + 96) + 1;

            // Derive key_n = HKDF(ck, "prekey-salt", "prekey-additional-N")
            const std::string infoStr = "prekey-additional-" + std::to_string(counter);
            const Bytes info(infoStr.begin(), infoStr.end());
            Bytes prekeyKey = CryptoEngine::hkdf(ck, strBytes("prekey-salt"), info, 32);
            Bytes encPayload = m_crypto.aeadEncrypt(prekeyKey, plaintext);

            m_lastMessageKey = prekeyKey;
            CryptoEngine::secureZero(prekeyKey);

            if (encPayload.empty()) return {};

            // Update counter in the pending blob and re-save
            write_u32_be(existing.data() + 96, counter);
            m_store.savePendingHandshake(peerIdB64u, NoiseState::Initiator, existing);

#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Additional pre-key message #" << counter
                     << "for" << peerPrefix(peerIdB64u)
                     << "| payload:" << int(encPayload.size()) << "B";
#endif

            // Wire: [0x06][counter(4 BE)][encPayload]
            Bytes out;
            out.reserve(1 + 4 + encPayload.size());
            out.push_back(kAdditionalPreKey);
            uint8_t cbe[4];
            write_u32_be(cbe, counter);
            append(out, cbe, 4);
            append(out, encPayload);
            return out;
        } else if (!existing.empty()) {
            // We're the responder with a pending handshake — can't send yet
            return {};
        }
    }

    // Initiate Noise IK handshake + bundle first ratchet message

    // Get peer's Ed25519 public key and convert to X25519
    Bytes peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEdPub.size() != 32) return {};

    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
        return {};
    Bytes remoteCurvePub(peerCurvePub, peerCurvePub + 32);

    // Choose hybrid or classical Noise IK based on PQ key availability
    const bool useHybrid = (peerKemPub.size() == 1184 && m_crypto.hasPQKeys());
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Initiating" << (useHybrid ? "HYBRID PQ" : "classical")
             << "Noise IK handshake with" << peerPrefix(peerIdB64u);
#endif
    NoiseState noise = useHybrid
        ? NoiseState::createHybridInitiator(
              m_crypto.curvePub(), m_crypto.curvePriv(),
              remoteCurvePub,
              m_crypto.kemPub(), m_crypto.kemPriv(),
              peerKemPub)
        : NoiseState::createInitiator(
              m_crypto.curvePub(), m_crypto.curvePriv(),
              remoteCurvePub);

    // Write handshake message 1 (no payload in the handshake itself)
    Bytes noiseMsg1 = noise.writeMessage1();
    if (noiseMsg1.empty()) {
        qWarning() << "[SessionManager] Failed to write Noise msg1 for" << peerPrefix(peerIdB64u);
        return {};
    }

    // Generate a fresh ratchet DH keypair (key separation from Noise ephemeral)
    auto [ratchetDhPub, ratchetDhPriv] = CryptoEngine::generateEphemeralX25519();

    // Persist the pending handshake state.
    // Format: [ratchetDhPub(32)][ratchetDhPriv(32)][ckAfterMsg1(32)][prekeyCounter(4 BE)][noiseBlob]
    Bytes pendingBlob;
    pendingBlob.reserve(100 + noiseMsg1.size());
    append(pendingBlob, ratchetDhPub);
    append(pendingBlob, ratchetDhPriv);
    append(pendingBlob, noise.postMsg1ChainingKey());  // 32 bytes
    uint8_t counterBE[4];
    write_u32_be(counterBE, 0);
    append(pendingBlob, counterBE, 4);
    append(pendingBlob, noise.serialize());
    m_store.savePendingHandshake(peerIdB64u, NoiseState::Initiator, pendingBlob);
    // L4 fix: zero the local private key copy now that it's persisted (encrypted)
    sodium_memzero(ratchetDhPriv.data(), ratchetDhPriv.size());
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Saved pending handshake + ratchet DH for" << peerPrefix(peerIdB64u);
#endif

    // Derive a one-shot key from the Noise chaining key after msg1 (shared by both sides)
    Bytes prekeyKey = CryptoEngine::hkdf(
        noise.postMsg1ChainingKey(), strBytes("prekey-salt"), strBytes("prekey-payload"), 32);

    Bytes encPayload = m_crypto.aeadEncrypt(prekeyKey, plaintext);
    if (encPayload.empty()) {
        qWarning() << "[SessionManager] Pre-key payload encryption failed for" << peerPrefix(peerIdB64u);
        return {};
    }

    // B1 fix: expose the prekey-derived key so callers (e.g. sendFile) can use
    // it as a file encryption key.  Both sides derive the same prekeyKey from
    // the Noise chaining key, so the receiver's decryptFromPeer also has it.
    m_lastMessageKey = prekeyKey;
    CryptoEngine::secureZero(prekeyKey);
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[SessionManager] Encrypted pre-key message for" << peerPrefix(peerIdB64u)
             << "| noiseMsg1:" << int(noiseMsg1.size()) << "B"
             << "| payload:" << int(encPayload.size()) << "B";
#endif

    // Wire: [type][4-byte noiseMsg1Len][noiseMsg1][32-byte ratchetDhPub][encPayload]
    const uint8_t msgType = useHybrid ? kHybridPreKeyMsg : kPreKeyMsg;

    Bytes out;
    out.reserve(1 + 4 + noiseMsg1.size() + 32 + encPayload.size());
    out.push_back(msgType);
    uint8_t msg1LenBE[4];
    write_u32_be(msg1LenBE, static_cast<uint32_t>(noiseMsg1.size()));
    append(out, msg1LenBE, 4);
    append(out, noiseMsg1);
    append(out, ratchetDhPub);   // 32 bytes — responder uses this for initial ratchet DH
    append(out, encPayload);
    return out;
}

// ---------------------------
// Decrypt
// ---------------------------

Bytes SessionManager::decryptFromPeer(const std::string& senderIdB64u,
                                       const Bytes& blob,
                                       Bytes* msgKeyOut) {
    using p2p::bridge::toBytes;
    using p2p::bridge::toQByteArray;
    using p2p::bridge::strBytes;

    if (blob.empty()) return {};

    const uint8_t msgType = blob[0];

    if (msgType == kRatchetMsg) {
        // Normal ratchet message
        RatchetSession* session = getSession(senderIdB64u);
        if (!session) {
            qWarning() << "[SessionManager] No ratchet session for" << peerPrefix(senderIdB64u);
            return {};
        }

#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Decrypting ratchet message from" << peerPrefix(senderIdB64u)
                 << "| size:" << int(blob.size()) << "B";
#endif
        Bytes pt = session->decrypt(tail(blob, 1));
        if (pt.empty()) {
            qWarning() << "[SessionManager] Ratchet decrypt failed from" << peerPrefix(senderIdB64u);
            return {};
        }

        m_lastMessageKey = session->lastMessageKey();
        if (msgKeyOut) *msgKeyOut = m_lastMessageKey;  // M3 fix: return key directly
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Ratchet decrypt OK from" << peerPrefix(senderIdB64u)
                 << "| plaintext:" << int(pt.size()) << "B";
#endif
        persistSession(senderIdB64u);
        return pt;
    }

    if (msgType == kPreKeyMsg || msgType == kHybridPreKeyMsg) {
        // Pre-key message: Noise msg1 + encrypted payload
        // We are the responder
        const bool hybrid = (msgType == kHybridPreKeyMsg);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Received pre-key message from" << peerPrefix(senderIdB64u)
                 << "| size:" << int(blob.size()) << "B";
#endif

        if (blob.size() < 5) return {};
        const uint32_t msg1Len = read_u32_be(blob.data() + 1);

        // Wire format: [0x01][4-byte msg1Len][noiseMsg1][32-byte ratchetDhPub][encPayload]
        if (blob.size() < 5 + msg1Len + 32) return {};
        Bytes noiseMsg1                 = slice(blob, 5, msg1Len);
        Bytes initiatorRatchetDhPub     = slice(blob, 5 + msg1Len, 32);
        Bytes encPayload                = tail(blob, 5 + msg1Len + 32);

        // Create Noise responder (hybrid or classical based on message type)
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Processing" << (hybrid ? "HYBRID PQ" : "classical")
                 << "Noise IK handshake (responder) from" << peerPrefix(senderIdB64u);
#endif
        NoiseState noise = (hybrid && m_crypto.hasPQKeys())
            ? NoiseState::createHybridResponder(
                  m_crypto.curvePub(), m_crypto.curvePriv(),
                  m_crypto.kemPub(), m_crypto.kemPriv())
            : NoiseState::createResponder(
                  m_crypto.curvePub(), m_crypto.curvePriv());

        Bytes handshakePayload;
        Bytes noiseMsg2 = noise.readMessage1AndWriteMessage2(noiseMsg1, handshakePayload);
        if (noiseMsg2.empty()) {
            qWarning() << "[SessionManager] Failed to process Noise msg1 from" << peerPrefix(senderIdB64u);
            return {};
        }

        // Capture our ephemeral keypair BEFORE finish() — finish() zeros m_ek
        Bytes ephPub  = noise.ephemeralPub();
        Bytes ephPriv = noise.ephemeralPriv();

        // Complete the handshake
        HandshakeResult hr = noise.finish();
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Noise IK handshake complete (responder) for" << peerPrefix(senderIdB64u);
#endif

        // Initialize ratchet with the initiator's fresh ratchet DH pub (from wire format)
        // This lets us derive both recv and send chains immediately — no LEGACY fallback
        RatchetSession ratchet = RatchetSession::initAsResponder(
            hr.sendCipher.key, ephPub, ephPriv, initiatorRatchetDhPub, hybrid);

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Double Ratchet session initialized (responder) for"
                 << peerPrefix(senderIdB64u);
#endif

        // Store the chaining key so we can decrypt additional pre-key messages (type 0x06)
        m_pendingCk[senderIdB64u] = noise.postMsg1ChainingKey();

        // Decrypt the pre-key payload using the Noise chaining key after msg1 (secret)
        // Both sides snapshot m_ck after the same 4 DH ops (e, es, s, ss)
        Bytes prekeyKey = CryptoEngine::hkdf(
            noise.postMsg1ChainingKey(), strBytes("prekey-salt"), strBytes("prekey-payload"), 32);
        Bytes pt = m_crypto.aeadDecrypt(prekeyKey, encPayload);
        if (!pt.empty()) {
            // B1 fix: expose prekey-derived key so file_key announcements work
            m_lastMessageKey = prekeyKey;
            if (msgKeyOut) *msgKeyOut = m_lastMessageKey;
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Pre-key payload decrypted OK |" << int(pt.size()) << "B";
#endif
        } else {
            qWarning() << "[SessionManager] Pre-key payload decryption FAILED";
        }
        CryptoEngine::secureZero(prekeyKey);

        // Send back the Noise msg2 as a pre-key response
        if (m_sendResponse) {
            // [0x02][4-byte noiseMsg2Len][noiseMsg2]
            const uint8_t respType = hybrid ? kHybridPreKeyResp : kPreKeyResponse;
            Bytes response;
            response.reserve(1 + 4 + noiseMsg2.size());
            response.push_back(respType);
            uint8_t msg2LenBE[4];
            write_u32_be(msg2LenBE, static_cast<uint32_t>(noiseMsg2.size()));
            append(response, msg2LenBE, 4);
            append(response, noiseMsg2);

            m_sendResponse(senderIdB64u, response);
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Sent Noise msg2 (pre-key response) to" << peerPrefix(senderIdB64u);
#endif
        }

        return pt;
    }

    if (msgType == kPreKeyResponse || msgType == kHybridPreKeyResp) {
        // Pre-key response: Noise msg2 from responder
        // We are the initiator — complete the handshake
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Received pre-key response from" << peerPrefix(senderIdB64u);
#endif

        if (blob.size() < 5) return {};
        const uint32_t msg2Len = read_u32_be(blob.data() + 1);

        if (blob.size() < 5 + msg2Len) return {};
        Bytes noiseMsg2 = slice(blob, 5, msg2Len);

        // Load our pending handshake state
        int role = 0;
        Bytes pendingBlob = m_store.loadPendingHandshake(senderIdB64u, role);
        if (pendingBlob.size() < 64 || role != NoiseState::Initiator) {
            qWarning() << "[SessionManager] No pending initiator handshake for" << peerPrefix(senderIdB64u);
            return {};
        }

        // Extract saved ratchet DH keypair (fresh, independent of Noise ephemeral)
        // Pending blob: [ratchetDhPub(32)][ratchetDhPriv(32)][ck(32)][counter(4)][noiseBlob]
        Bytes ratchetDhPub  = slice(pendingBlob, 0, 32);
        Bytes ratchetDhPriv = slice(pendingBlob, 32, 32);
        // ck(32) and counter(4) at offsets 64-99 — not needed here
        Bytes hsBlob        = tail(pendingBlob, 100);

        NoiseState noise = NoiseState::deserialize(hsBlob);
        // C3 fix: re-inject static private key (not persisted since v3)
        noise.setStaticPrivateKey(m_crypto.curvePriv());
        Bytes responsePayload;
        if (!noise.readMessage2(noiseMsg2, responsePayload)) {
            qWarning() << "[SessionManager] Failed to process Noise msg2 from" << peerPrefix(senderIdB64u);
            return {};
        }

        HandshakeResult hr = noise.finish();
        m_store.deletePendingHandshake(senderIdB64u);
        m_pendingCk.erase(senderIdB64u);  // clean up chaining key (no longer needed)
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Noise IK handshake complete (initiator) for" << peerPrefix(senderIdB64u);
#endif

        // Initialize ratchet with our saved fresh ratchet DH keypair
        // The responder's Noise ephemeral (first 32 bytes of msg2) is the remote DH pub
        Bytes responderEphPub = slice(noiseMsg2, 0, 32);

        RatchetSession ratchet = RatchetSession::initAsInitiator(
            hr.recvCipher.key, responderEphPub,
            ratchetDhPub, ratchetDhPriv,
            noise.isHybrid());
        // L4 fix: zero extracted private key now that ratchet owns it
        sodium_memzero(ratchetDhPriv.data(), ratchetDhPriv.size());
        sodium_memzero(pendingBlob.data(), pendingBlob.size());

        m_sessions[senderIdB64u] = ratchet;
        persistSession(senderIdB64u);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[SessionManager] Double Ratchet session initialized (initiator) for"
                 << peerPrefix(senderIdB64u);
#endif

        // The pre-key response may not carry user payload (it's a handshake completion)
        // Return the response payload if present
        return responsePayload;
    }

    if (msgType == kAdditionalPreKey) {
        // Additional pre-key message: encrypted with a key derived from the
        // Noise chaining key + counter.  We must have already processed the
        // initial pre-key message (type 0x01/0x04) to have the chaining key.
        if (blob.size() < 5) return {};

        const uint32_t counter = read_u32_be(blob.data() + 1);

        auto ckIt = m_pendingCk.find(senderIdB64u);
        if (ckIt == m_pendingCk.end() || ckIt->second.empty()) {
            qWarning() << "[SessionManager] Additional pre-key msg from" << peerPrefix(senderIdB64u)
                       << "but no chaining key on record (initial handshake not yet received?)";
            return {};
        }

        Bytes encPayload = tail(blob, 5);
        const std::string infoStr = "prekey-additional-" + std::to_string(counter);
        const Bytes info(infoStr.begin(), infoStr.end());
        Bytes prekeyKey = CryptoEngine::hkdf(
            ckIt->second, strBytes("prekey-salt"), info, 32);
        Bytes pt = m_crypto.aeadDecrypt(prekeyKey, encPayload);

        if (!pt.empty()) {
            m_lastMessageKey = prekeyKey;
            if (msgKeyOut) *msgKeyOut = m_lastMessageKey;
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[SessionManager] Additional pre-key #" << counter
                     << "decrypted OK from" << peerPrefix(senderIdB64u)
                     << "|" << int(pt.size()) << "B";
#endif
        } else {
            qWarning() << "[SessionManager] Additional pre-key #" << counter
                       << "decrypt FAILED from" << peerPrefix(senderIdB64u);
        }
        CryptoEngine::secureZero(prekeyKey);
        return pt;
    }

    qWarning() << "[SessionManager] Unknown message type" << int(msgType);
    return {};
}
