#include "NoiseState.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QDataStream>
#include <QBuffer>
#include <cstring>

// Noise protocol name for IK with our chosen primitives
static const QByteArray kProtocolName =
    "Noise_IK_25519_XChaChaPoly_BLAKE2b";

// ---------------------------
// Symmetric-state helpers
// ---------------------------

void NoiseState::mixHash(const QByteArray& data) {
    // h = BLAKE2b-256(h || data)
    QByteArray combined = m_h + data;
    unsigned char out[32];
    (void)crypto_generichash(out, 32,
                             reinterpret_cast<const unsigned char*>(combined.constData()),
                             static_cast<size_t>(combined.size()),
                             nullptr, 0);
    m_h = QByteArray(reinterpret_cast<const char*>(out), 32);
}

void NoiseState::mixKey(const QByteArray& ikm) {
    // HKDF(ck, ikm) -> (new_ck, temp_k)
    // Extract: temp = BLAKE2b(key=ck, input=ikm)
    unsigned char temp[64];
    (void)crypto_generichash(temp, 64,
                             reinterpret_cast<const unsigned char*>(ikm.constData()),
                             static_cast<size_t>(ikm.size()),
                             reinterpret_cast<const unsigned char*>(m_ck.constData()),
                             static_cast<size_t>(m_ck.size()));

    // Split temp into two 32-byte halves
    m_ck = QByteArray(reinterpret_cast<const char*>(temp), 32);
    m_k  = QByteArray(reinterpret_cast<const char*>(temp + 32), 32);
    m_n  = 0;
    sodium_memzero(temp, sizeof(temp));
}

QByteArray NoiseState::encryptAndHash(const QByteArray& plaintext) {
    if (m_k.isEmpty()) {
        // No key yet — just pass through and mix into hash
        mixHash(plaintext);
        return plaintext;
    }

    // AEAD encrypt with m_k, nonce = m_n, aad = m_h
    // Nonce: 8-byte little-endian counter padded to 24 bytes for XChaCha20
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {};
    memcpy(nonce, &m_n, sizeof(m_n)); // little-endian on x86/ARM

    QByteArray ct;
    ct.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(ct.data()), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()),
        static_cast<unsigned long long>(plaintext.size()),
        reinterpret_cast<const unsigned char*>(m_h.constData()),
        static_cast<unsigned long long>(m_h.size()),
        nullptr, nonce,
        reinterpret_cast<const unsigned char*>(m_k.constData()));

    ct.resize(static_cast<int>(clen));
    mixHash(ct);
    ++m_n;
    return ct;
}

QByteArray NoiseState::decryptAndHash(const QByteArray& ciphertext) {
    if (m_k.isEmpty()) {
        mixHash(ciphertext);
        return ciphertext;
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {};
    memcpy(nonce, &m_n, sizeof(m_n));

    QByteArray pt;
    pt.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()),
            static_cast<unsigned long long>(ciphertext.size()),
            reinterpret_cast<const unsigned char*>(m_h.constData()),
            static_cast<unsigned long long>(m_h.size()),
            nonce,
            reinterpret_cast<const unsigned char*>(m_k.constData())) != 0) {
        return {}; // decryption failed
    }

    pt.resize(static_cast<int>(plen));
    mixHash(ciphertext);
    ++m_n;
    return pt;
}

QByteArray NoiseState::dh(const QByteArray& priv, const QByteArray& pub) {
    if (priv.size() != 32 || pub.size() != 32) return {};
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(priv.constData()),
                          reinterpret_cast<const unsigned char*>(pub.constData())) != 0) {
        return {};
    }
    QByteArray result(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));
    return result;
}

void NoiseState::split(CipherState& c1, CipherState& c2) {
    // HKDF(ck, empty) -> (k1, k2)
    unsigned char temp[64];
    QByteArray empty;
    (void)crypto_generichash(temp, 64,
                             reinterpret_cast<const unsigned char*>(empty.constData()), 0,
                             reinterpret_cast<const unsigned char*>(m_ck.constData()),
                             static_cast<size_t>(m_ck.size()));

    c1.key   = QByteArray(reinterpret_cast<const char*>(temp), 32);
    c1.nonce = 0;
    c2.key   = QByteArray(reinterpret_cast<const char*>(temp + 32), 32);
    c2.nonce = 0;
    sodium_memzero(temp, sizeof(temp));
}

// ---------------------------
// Factory methods
// ---------------------------

NoiseState NoiseState::createInitiator(const QByteArray& localStaticPub,
                                       const QByteArray& localStaticPriv,
                                       const QByteArray& remoteStaticPub) {
    NoiseState ns;
    ns.m_role = Initiator;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;
    ns.m_rs = remoteStaticPub;

    // Initialize symmetric state with protocol name
    // h = BLAKE2b-256(protocolName) if len <= 32, else hash it
    if (kProtocolName.size() <= 32) {
        ns.m_h = kProtocolName + QByteArray(32 - kProtocolName.size(), 0);
    } else {
        unsigned char h[32];
        (void)crypto_generichash(h, 32,
                                 reinterpret_cast<const unsigned char*>(kProtocolName.constData()),
                                 static_cast<size_t>(kProtocolName.size()),
                                 nullptr, 0);
        ns.m_h = QByteArray(reinterpret_cast<const char*>(h), 32);
    }
    ns.m_ck = ns.m_h;

    // IK prologue: mix in responder's static public key (pre-message pattern: <- s)
    ns.mixHash(remoteStaticPub);

    return ns;
}

NoiseState NoiseState::createResponder(const QByteArray& localStaticPub,
                                       const QByteArray& localStaticPriv) {
    NoiseState ns;
    ns.m_role = Responder;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;

    // Same initialization as initiator
    if (kProtocolName.size() <= 32) {
        ns.m_h = kProtocolName + QByteArray(32 - kProtocolName.size(), 0);
    } else {
        unsigned char h[32];
        (void)crypto_generichash(h, 32,
                                 reinterpret_cast<const unsigned char*>(kProtocolName.constData()),
                                 static_cast<size_t>(kProtocolName.size()),
                                 nullptr, 0);
        ns.m_h = QByteArray(reinterpret_cast<const char*>(h), 32);
    }
    ns.m_ck = ns.m_h;

    // IK prologue: mix in our static public key (pre-message pattern: <- s)
    ns.mixHash(localStaticPub);

    return ns;
}

// ---------------------------
// Handshake messages
// ---------------------------

QByteArray NoiseState::writeMessage1(const QByteArray& payload) {
    if (m_role != Initiator) return {};

    // Generate ephemeral keypair
    auto [ePub, ePriv] = CryptoEngine::generateEphemeralX25519();
    m_e  = ePub;
    m_ek = ePriv;

    QByteArray msg;

    // e: send ephemeral public key in the clear
    msg.append(m_e);
    mixHash(m_e);

    // es: DH(e, rs) — initiator's ephemeral with responder's static
    QByteArray dhResult = dh(m_ek, m_rs);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // s: encrypt and send initiator's static public key
    QByteArray encS = encryptAndHash(m_s);
    msg.append(encS);

    // ss: DH(s, rs) — initiator's static with responder's static
    dhResult = dh(m_sk, m_rs);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // Snapshot chaining key after msg1 (e, es, s, ss) for pre-key payload derivation
    m_ckAfterMsg1 = m_ck;

    // Encrypt payload (may be empty)
    QByteArray encPayload = encryptAndHash(payload);
    msg.append(encPayload);

    return msg;
}

QByteArray NoiseState::readMessage1AndWriteMessage2(const QByteArray& msg1,
                                                     QByteArray& payloadOut,
                                                     const QByteArray& msg2Payload) {
    if (m_role != Responder) return {};

    const int kPubLen = 32;
    const int kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

    // Parse message 1:
    // [e(32)][encrypted_s(32+16)][encrypted_payload(len+16)]
    if (msg1.size() < kPubLen + kPubLen + kTagLen + kTagLen) return {};

    int offset = 0;

    // e: read remote ephemeral
    m_re = msg1.mid(offset, kPubLen);
    offset += kPubLen;
    mixHash(m_re);

    // es: DH(s, re) — responder's static with initiator's ephemeral
    QByteArray dhResult = dh(m_sk, m_re);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // s: decrypt initiator's static public key
    QByteArray encS = msg1.mid(offset, kPubLen + kTagLen);
    offset += kPubLen + kTagLen;
    m_rs = decryptAndHash(encS);
    if (m_rs.size() != kPubLen) return {};

    // ss: DH(s, rs) — responder's static with initiator's static
    dhResult = dh(m_sk, m_rs);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // Decrypt payload
    QByteArray encPayload = msg1.mid(offset);
    payloadOut = decryptAndHash(encPayload);

    // Snapshot chaining key after msg1 (e, es, s, ss) for pre-key payload derivation
    m_ckAfterMsg1 = m_ck;

    // --- Now write message 2 ---

    // Generate responder ephemeral
    auto [ePub, ePriv] = CryptoEngine::generateEphemeralX25519();
    m_e  = ePub;
    m_ek = ePriv;

    QByteArray msg2;

    // e: send ephemeral
    msg2.append(m_e);
    mixHash(m_e);

    // ee: DH(e, re)
    dhResult = dh(m_ek, m_re);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // se: DH(s, re) — wait, Noise IK is: se means DH(responder_e, initiator_s)
    // Actually in the responder's perspective for "se" token:
    // se means the responder uses e, the initiator uses s
    // So: DH(e, rs) where rs is the initiator's static
    dhResult = dh(m_ek, m_rs);
    if (dhResult.isEmpty()) return {};
    mixKey(dhResult);

    // Encrypt payload
    QByteArray encMsg2Payload = encryptAndHash(msg2Payload);
    msg2.append(encMsg2Payload);

    m_complete = true;
    return msg2;
}

bool NoiseState::readMessage2(const QByteArray& msg2, QByteArray& payloadOut) {
    if (m_role != Initiator) return false;

    const int kPubLen = 32;
    const int kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

    if (msg2.size() < kPubLen + kTagLen) return false;

    int offset = 0;

    // e: read responder's ephemeral
    m_re = msg2.mid(offset, kPubLen);
    offset += kPubLen;
    mixHash(m_re);

    // ee: DH(e, re) — our ephemeral with their ephemeral
    QByteArray dhResult = dh(m_ek, m_re);
    if (dhResult.isEmpty()) return false;
    mixKey(dhResult);

    // se: DH(s, re) — for initiator, se means DH with our static and their ephemeral
    // Wait — in the initiator's view of the "se" token:
    // "se" means (the s of the sender of this message = responder_s) with
    // (the e of the other side = initiator_e)
    // But the sender of msg2 is the responder, so:
    // se = DH(responder_e, initiator_s) from responder's view
    // From initiator's view: DH(initiator_s, responder_e) = DH(sk, re)
    dhResult = dh(m_sk, m_re);
    if (dhResult.isEmpty()) return false;
    mixKey(dhResult);

    // Decrypt payload
    QByteArray encPayload = msg2.mid(offset);
    payloadOut = decryptAndHash(encPayload);

    m_complete = true;
    return true;
}

HandshakeResult NoiseState::finish() {
    HandshakeResult result;
    result.handshakeHash = m_h;

    split(m_c1, m_c2);

    if (m_role == Initiator) {
        result.sendCipher = m_c1; // initiator sends with c1
        result.recvCipher = m_c2; // initiator receives with c2
    } else {
        result.sendCipher = m_c2; // responder sends with c2
        result.recvCipher = m_c1; // responder receives with c1
    }

    // Zero sensitive material
    sodium_memzero(m_ek.data(), m_ek.size());
    sodium_memzero(m_sk.data(), m_sk.size());
    sodium_memzero(m_ck.data(), m_ck.size());
    sodium_memzero(m_k.data(), m_k.size());

    return result;
}

// ---------------------------
// Serialization
// ---------------------------

QByteArray NoiseState::serialize() const {
    QByteArray buf;
    QDataStream ds(&buf, QIODevice::WriteOnly);
    ds.setVersion(QDataStream::Qt_5_15);

    ds << quint8(2); // version
    ds << quint8(m_role);
    ds << m_complete;
    ds << m_ck << m_h << m_k << m_n;
    ds << m_s << m_sk << m_rs;
    ds << m_e << m_ek << m_re;
    ds << m_ckAfterMsg1;

    return buf;
}

NoiseState NoiseState::deserialize(const QByteArray& data) {
    NoiseState ns;
    QDataStream ds(data);
    ds.setVersion(QDataStream::Qt_5_15);

    quint8 version, role;
    ds >> version;
    if (version != 1 && version != 2) return ns;

    ds >> role;
    ns.m_role = static_cast<Role>(role);
    ds >> ns.m_complete;
    ds >> ns.m_ck >> ns.m_h >> ns.m_k >> ns.m_n;
    ds >> ns.m_s >> ns.m_sk >> ns.m_rs;
    ds >> ns.m_e >> ns.m_ek >> ns.m_re;
    if (version >= 2)
        ds >> ns.m_ckAfterMsg1;

    return ns;
}
