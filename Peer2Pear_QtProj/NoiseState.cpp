#include "NoiseState.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QDataStream>
#include <QBuffer>
#include <cstring>

// Noise protocol name for IK with our chosen primitives
static const QByteArray kProtocolName =
    "Noise_IK_25519_XChaChaPoly_BLAKE2b";

// Hybrid protocol name — distinct from classical so both sides agree on the pattern
static const QByteArray kHybridProtocolName =
    "Noise_IK_25519+MLKEM768_XChaChaPoly_BLAKE2b";

// ML-KEM-768 sizes
static constexpr int kKemPubLen = 1184;
static constexpr int kKemCtLen  = 1088;

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
    // Explicit little-endian encoding so the protocol is stable across architectures
    for (size_t i = 0; i < sizeof(m_n); ++i) {
        nonce[i] = static_cast<unsigned char>((m_n >> (8 * i)) & 0xff);
    }

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
    for (size_t i = 0; i < sizeof(m_n); ++i) {
        nonce[i] = static_cast<unsigned char>((m_n >> (8 * i)) & 0xff);
    }

    if (static_cast<size_t>(ciphertext.size()) < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return {};

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

// Helper: initialize symmetric state from a protocol name
static void initSymmetricState(const QByteArray& protoName, QByteArray& h, QByteArray& ck) {
    if (protoName.size() <= 32) {
        h = protoName + QByteArray(32 - protoName.size(), 0);
    } else {
        unsigned char hBuf[32];
        (void)crypto_generichash(hBuf, 32,
                                 reinterpret_cast<const unsigned char*>(protoName.constData()),
                                 static_cast<size_t>(protoName.size()),
                                 nullptr, 0);
        h = QByteArray(reinterpret_cast<const char*>(hBuf), 32);
    }
    ck = h;
}

NoiseState NoiseState::createInitiator(const QByteArray& localStaticPub,
                                       const QByteArray& localStaticPriv,
                                       const QByteArray& remoteStaticPub) {
    NoiseState ns;
    ns.m_role = Initiator;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;
    ns.m_rs = remoteStaticPub;

    initSymmetricState(kProtocolName, ns.m_h, ns.m_ck);
    ns.mixHash(remoteStaticPub);

    return ns;
}

NoiseState NoiseState::createHybridInitiator(const QByteArray& localStaticPub,
                                              const QByteArray& localStaticPriv,
                                              const QByteArray& remoteStaticPub,
                                              const QByteArray& localKemPub,
                                              const QByteArray& localKemPriv,
                                              const QByteArray& remoteKemPub) {
    NoiseState ns;
    ns.m_role = Initiator;
    ns.m_hybrid = true;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;
    ns.m_rs = remoteStaticPub;
    ns.m_kemPub  = localKemPub;
    ns.m_kemPriv = localKemPriv;
    ns.m_rsKem   = remoteKemPub;

    // Use distinct protocol name so both sides hash the same prologue
    initSymmetricState(kHybridProtocolName, ns.m_h, ns.m_ck);
    // IK prologue: mix in responder's static X25519 pub AND KEM pub
    ns.mixHash(remoteStaticPub);
    ns.mixHash(remoteKemPub);

    return ns;
}

NoiseState NoiseState::createResponder(const QByteArray& localStaticPub,
                                       const QByteArray& localStaticPriv) {
    NoiseState ns;
    ns.m_role = Responder;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;

    initSymmetricState(kProtocolName, ns.m_h, ns.m_ck);
    ns.mixHash(localStaticPub);

    return ns;
}

NoiseState NoiseState::createHybridResponder(const QByteArray& localStaticPub,
                                              const QByteArray& localStaticPriv,
                                              const QByteArray& localKemPub,
                                              const QByteArray& localKemPriv) {
    NoiseState ns;
    ns.m_role = Responder;
    ns.m_hybrid = true;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;
    ns.m_kemPub  = localKemPub;
    ns.m_kemPriv = localKemPriv;

    // Same prologue: mix our static X25519 + KEM pub
    initSymmetricState(kHybridProtocolName, ns.m_h, ns.m_ck);
    ns.mixHash(localStaticPub);
    ns.mixHash(localKemPub);

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

    // Hybrid: also KEM_es — encapsulate to responder's static KEM pub
    if (m_hybrid && m_rsKem.size() == kKemPubLen) {
        KemEncapsResult kemEs = CryptoEngine::kemEncaps(m_rsKem);
        if (kemEs.ciphertext.isEmpty()) { CryptoEngine::secureZero(dhResult); return {}; }
        msg.append(kemEs.ciphertext);   // 1088 bytes
        mixHash(kemEs.ciphertext);
        mixKey(dhResult + kemEs.sharedSecret);  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEs.sharedSecret);
    } else {
        mixKey(dhResult);
    }
    CryptoEngine::secureZero(dhResult);

    // s: encrypt and send initiator's static public key
    QByteArray encS = encryptAndHash(m_s);
    msg.append(encS);

    // In hybrid mode, also encrypt and send our KEM public key
    if (m_hybrid) {
        QByteArray encKemPub = encryptAndHash(m_kemPub);
        msg.append(encKemPub);
    }

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

    // Hybrid: also KEM_es — decapsulate the KEM ciphertext from initiator
    if (m_hybrid) {
        if (msg1.size() < offset + kKemCtLen) return {};
        QByteArray kemEsCt = msg1.mid(offset, kKemCtLen);
        offset += kKemCtLen;
        QByteArray kemEsSS = CryptoEngine::kemDecaps(kemEsCt, m_kemPriv);
        if (kemEsSS.isEmpty()) return {};
        mixHash(kemEsCt);
        mixKey(dhResult + kemEsSS);  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEsSS);
    } else {
        mixKey(dhResult);
    }

    // s: decrypt initiator's static public key
    QByteArray encS = msg1.mid(offset, kPubLen + kTagLen);
    offset += kPubLen + kTagLen;
    m_rs = decryptAndHash(encS);
    if (m_rs.size() != kPubLen) return {};

    // Hybrid: also decrypt initiator's KEM public key
    if (m_hybrid) {
        QByteArray encKemPub = msg1.mid(offset, kKemPubLen + kTagLen);
        offset += kKemPubLen + kTagLen;
        m_rsKem = decryptAndHash(encKemPub);
        if (m_rsKem.size() != kKemPubLen) return {};
    }

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

    // Hybrid: KEM_ee — encapsulate to initiator's KEM pub (learned from msg1)
    if (m_hybrid && m_rsKem.size() == kKemPubLen) {
        KemEncapsResult kemEe = CryptoEngine::kemEncaps(m_rsKem);
        if (kemEe.ciphertext.isEmpty()) return {};
        msg2.append(kemEe.ciphertext);  // 1088 bytes
        mixHash(kemEe.ciphertext);
        mixKey(dhResult + kemEe.sharedSecret);  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEe.sharedSecret);
    } else {
        mixKey(dhResult);
    }

    // se: DH(e, rs) where rs is the initiator's static
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

    // Hybrid: KEM_ee — decapsulate the KEM ciphertext from responder
    if (m_hybrid) {
        if (msg2.size() < offset + kKemCtLen) return false;
        QByteArray kemEeCt = msg2.mid(offset, kKemCtLen);
        offset += kKemCtLen;
        QByteArray kemEeSS = CryptoEngine::kemDecaps(kemEeCt, m_kemPriv);
        if (kemEeSS.isEmpty()) return false;
        mixHash(kemEeCt);
        mixKey(dhResult + kemEeSS);  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEeSS);
    } else {
        mixKey(dhResult);
    }

    // se: From initiator's view: DH(initiator_s, responder_e) = DH(sk, re)
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
    if (!m_kemPriv.isEmpty())
        CryptoEngine::secureZero(m_kemPriv);

    return result;
}

// ---------------------------
// Serialization
// ---------------------------

QByteArray NoiseState::serialize() const {
    QByteArray buf;
    QDataStream ds(&buf, QIODevice::WriteOnly);
    ds.setVersion(QDataStream::Qt_5_15);

    // v4: adds hybrid PQ fields. m_sk and m_kemPriv NOT persisted (C3 fix).
    ds << quint8(4); // version
    ds << quint8(m_role);
    ds << m_complete;
    ds << m_hybrid;
    ds << m_ck << m_h << m_k << m_n;
    ds << m_s << m_rs;
    ds << m_e << m_ek << m_re;
    ds << m_ckAfterMsg1;
    // v4 PQ fields (may be empty for classical handshakes)
    ds << m_kemPub << m_rsKem;

    return buf;
}

NoiseState NoiseState::deserialize(const QByteArray& data) {
    NoiseState ns;
    QDataStream ds(data);
    ds.setVersion(QDataStream::Qt_5_15);

    quint8 version, role;
    ds >> version;
    if (version < 1 || version > 4) return ns;

    ds >> role;
    ns.m_role = static_cast<Role>(role);
    ds >> ns.m_complete;

    if (version >= 4)
        ds >> ns.m_hybrid;

    ds >> ns.m_ck >> ns.m_h >> ns.m_k >> ns.m_n;

    if (version <= 2) {
        // Legacy: m_sk was serialized between m_s and m_rs
        ds >> ns.m_s >> ns.m_sk >> ns.m_rs;
    } else {
        // v3+: m_sk not persisted — caller must re-inject
        ds >> ns.m_s >> ns.m_rs;
    }

    ds >> ns.m_e >> ns.m_ek >> ns.m_re;
    if (version >= 2)
        ds >> ns.m_ckAfterMsg1;

    // v4: PQ fields
    if (version >= 4)
        ds >> ns.m_kemPub >> ns.m_rsKem;

    return ns;
}
