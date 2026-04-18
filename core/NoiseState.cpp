#include "NoiseState.hpp"
#include "CryptoEngine.hpp"
#include "binary_io.hpp"

#include <sodium.h>
#include <cstring>

// Noise protocol name for IK with our chosen primitives
static const Bytes kProtocolName = [] {
    const char s[] = "Noise_IK_25519_XChaChaPoly_BLAKE2b";
    return Bytes(s, s + sizeof(s) - 1);
}();

// Hybrid protocol name — distinct from classical so both sides agree on the pattern
static const Bytes kHybridProtocolName = [] {
    const char s[] = "Noise_IK_25519+MLKEM768_XChaChaPoly_BLAKE2b";
    return Bytes(s, s + sizeof(s) - 1);
}();

// ML-KEM-768 sizes
static constexpr int kKemPubLen = 1184;
static constexpr int kKemCtLen  = 1088;

// ── Small byte helpers ──────────────────────────────────────────────────────
static inline void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
static inline Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    append(out, a);
    append(out, b);
    return out;
}
static inline Bytes slice(const Bytes& src, size_t off, size_t len) {
    if (off + len > src.size()) return {};
    return Bytes(src.begin() + off, src.begin() + off + len);
}
static inline Bytes tail(const Bytes& src, size_t off) {
    if (off > src.size()) return {};
    return Bytes(src.begin() + off, src.end());
}

// ---------------------------
// Symmetric-state helpers
// ---------------------------

void NoiseState::mixHash(const Bytes& data) {
    // h = BLAKE2b-256(h || data)
    Bytes combined = concat(m_h, data);
    unsigned char out[32];
    (void)crypto_generichash(out, 32,
                             combined.data(),
                             combined.size(),
                             nullptr, 0);
    m_h.assign(out, out + 32);
}

void NoiseState::mixKey(const Bytes& ikm) {
    // HKDF(ck, ikm) -> (new_ck, temp_k)
    // Extract: temp = BLAKE2b(key=ck, input=ikm)
    unsigned char temp[64];
    (void)crypto_generichash(temp, 64,
                             ikm.data(),
                             ikm.size(),
                             m_ck.data(),
                             m_ck.size());

    // Split temp into two 32-byte halves
    m_ck.assign(temp, temp + 32);
    m_k.assign(temp + 32, temp + 64);
    m_n = 0;
    sodium_memzero(temp, sizeof(temp));
}

Bytes NoiseState::encryptAndHash(const Bytes& plaintext) {
    if (m_k.empty()) {
        // No key yet — just pass through and mix into hash
        mixHash(plaintext);
        return plaintext;
    }

    // AEAD encrypt with m_k, nonce = m_n, aad = m_h
    // Nonce: 8-byte little-endian counter padded to 24 bytes for XChaCha20
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {};
    for (size_t i = 0; i < sizeof(m_n); ++i) {
        nonce[i] = static_cast<unsigned char>((m_n >> (8 * i)) & 0xff);
    }

    Bytes ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &clen,
        plaintext.data(),
        plaintext.size(),
        m_h.data(),
        m_h.size(),
        nullptr, nonce,
        m_k.data());

    ct.resize(static_cast<size_t>(clen));
    mixHash(ct);
    ++m_n;
    return ct;
}

Bytes NoiseState::decryptAndHash(const Bytes& ciphertext) {
    if (m_k.empty()) {
        mixHash(ciphertext);
        return ciphertext;
    }

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {};
    for (size_t i = 0; i < sizeof(m_n); ++i) {
        nonce[i] = static_cast<unsigned char>((m_n >> (8 * i)) & 0xff);
    }

    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return {};

    Bytes pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen,
            nullptr,
            ciphertext.data(),
            ciphertext.size(),
            m_h.data(),
            m_h.size(),
            nonce,
            m_k.data()) != 0) {
        return {}; // decryption failed
    }

    pt.resize(static_cast<size_t>(plen));
    mixHash(ciphertext);
    ++m_n;
    return pt;
}

Bytes NoiseState::dh(const Bytes& priv, const Bytes& pub) {
    if (priv.size() != 32 || pub.size() != 32) return {};
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          priv.data(),
                          pub.data()) != 0) {
        return {};
    }
    Bytes result(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));
    return result;
}

void NoiseState::split(CipherState& c1, CipherState& c2) {
    // HKDF(ck, empty) -> (k1, k2)
    unsigned char temp[64];
    (void)crypto_generichash(temp, 64,
                             nullptr, 0,
                             m_ck.data(),
                             m_ck.size());

    c1.key.assign(temp, temp + 32);
    c1.nonce = 0;
    c2.key.assign(temp + 32, temp + 64);
    c2.nonce = 0;
    sodium_memzero(temp, sizeof(temp));
}

// ---------------------------
// Factory methods
// ---------------------------

// Helper: initialize symmetric state from a protocol name
static void initSymmetricState(const Bytes& protoName, Bytes& h, Bytes& ck) {
    if (protoName.size() <= 32) {
        h = protoName;
        h.resize(32, 0);  // pad with zeros
    } else {
        unsigned char hBuf[32];
        (void)crypto_generichash(hBuf, 32,
                                 protoName.data(),
                                 protoName.size(),
                                 nullptr, 0);
        h.assign(hBuf, hBuf + 32);
    }
    ck = h;
}

NoiseState NoiseState::createInitiator(const Bytes& localStaticPub,
                                       const Bytes& localStaticPriv,
                                       const Bytes& remoteStaticPub) {
    NoiseState ns;
    ns.m_role = Initiator;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;
    ns.m_rs = remoteStaticPub;

    initSymmetricState(kProtocolName, ns.m_h, ns.m_ck);
    ns.mixHash(remoteStaticPub);

    return ns;
}

NoiseState NoiseState::createHybridInitiator(const Bytes& localStaticPub,
                                              const Bytes& localStaticPriv,
                                              const Bytes& remoteStaticPub,
                                              const Bytes& localKemPub,
                                              const Bytes& localKemPriv,
                                              const Bytes& remoteKemPub) {
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

NoiseState NoiseState::createResponder(const Bytes& localStaticPub,
                                       const Bytes& localStaticPriv) {
    NoiseState ns;
    ns.m_role = Responder;
    ns.m_s  = localStaticPub;
    ns.m_sk = localStaticPriv;

    initSymmetricState(kProtocolName, ns.m_h, ns.m_ck);
    ns.mixHash(localStaticPub);

    return ns;
}

NoiseState NoiseState::createHybridResponder(const Bytes& localStaticPub,
                                              const Bytes& localStaticPriv,
                                              const Bytes& localKemPub,
                                              const Bytes& localKemPriv) {
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

Bytes NoiseState::writeMessage1(const Bytes& payload) {
    if (m_role != Initiator) return {};

    // Generate ephemeral keypair
    {
        auto kp = CryptoEngine::generateEphemeralX25519();
        m_e  = std::move(kp.first);
        m_ek = std::move(kp.second);
    }

    Bytes msg;

    // e: send ephemeral public key in the clear
    append(msg, m_e);
    mixHash(m_e);

    // es: DH(e, rs) — initiator's ephemeral with responder's static
    Bytes dhResult = dh(m_ek, m_rs);
    if (dhResult.empty()) return {};

    // Hybrid: also KEM_es — encapsulate to responder's static KEM pub
    if (m_hybrid && m_rsKem.size() == kKemPubLen) {
        KemEncapsResult kemEs = CryptoEngine::kemEncaps(m_rsKem);
        if (kemEs.ciphertext.empty()) {
            sodium_memzero(dhResult.data(), dhResult.size());
            return {};
        }
        append(msg, kemEs.ciphertext);  // 1088 bytes
        mixHash(kemEs.ciphertext);
        mixKey(concat(dhResult, kemEs.sharedSecret));  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEs.sharedSecret);
    } else {
        mixKey(dhResult);
    }
    sodium_memzero(dhResult.data(), dhResult.size());

    // s: encrypt and send initiator's static public key
    Bytes encS = encryptAndHash(m_s);
    append(msg, encS);

    // In hybrid mode, also encrypt and send our KEM public key
    if (m_hybrid) {
        Bytes encKemPub = encryptAndHash(m_kemPub);
        append(msg, encKemPub);
    }

    // ss: DH(s, rs) — initiator's static with responder's static
    dhResult = dh(m_sk, m_rs);
    if (dhResult.empty()) return {};
    mixKey(dhResult);

    // Snapshot chaining key after msg1 (e, es, s, ss) for pre-key payload derivation
    m_ckAfterMsg1 = m_ck;

    // Encrypt payload (may be empty)
    Bytes encPayload = encryptAndHash(payload);
    append(msg, encPayload);

    return msg;
}

Bytes NoiseState::readMessage1AndWriteMessage2(const Bytes& msg1,
                                                 Bytes& payloadOut,
                                                 const Bytes& msg2Payload) {
    if (m_role != Responder) return {};

    const size_t kPubLen = 32;
    const size_t kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

    // Parse message 1:
    // [e(32)][encrypted_s(32+16)][encrypted_payload(len+16)]
    if (msg1.size() < kPubLen + kPubLen + kTagLen + kTagLen) return {};

    size_t offset = 0;

    // e: read remote ephemeral
    m_re = slice(msg1, offset, kPubLen);
    offset += kPubLen;
    mixHash(m_re);

    // es: DH(s, re) — responder's static with initiator's ephemeral
    Bytes dhResult = dh(m_sk, m_re);
    if (dhResult.empty()) return {};

    // Hybrid: also KEM_es — decapsulate the KEM ciphertext from initiator
    if (m_hybrid) {
        if (msg1.size() < offset + kKemCtLen) return {};
        Bytes kemEsCt = slice(msg1, offset, kKemCtLen);
        offset += kKemCtLen;
        Bytes kemEsSS = CryptoEngine::kemDecaps(kemEsCt, m_kemPriv);
        if (kemEsSS.empty()) return {};
        mixHash(kemEsCt);
        mixKey(concat(dhResult, kemEsSS));  // hybrid: DH || KEM
        sodium_memzero(kemEsSS.data(), kemEsSS.size());
    } else {
        mixKey(dhResult);
    }

    // s: decrypt initiator's static public key
    Bytes encS = slice(msg1, offset, kPubLen + kTagLen);
    offset += kPubLen + kTagLen;
    m_rs = decryptAndHash(encS);
    if (m_rs.size() != kPubLen) return {};

    // Hybrid: also decrypt initiator's KEM public key
    if (m_hybrid) {
        Bytes encKemPub = slice(msg1, offset, kKemPubLen + kTagLen);
        offset += kKemPubLen + kTagLen;
        m_rsKem = decryptAndHash(encKemPub);
        if (m_rsKem.size() != kKemPubLen) return {};
    }

    // ss: DH(s, rs) — responder's static with initiator's static
    dhResult = dh(m_sk, m_rs);
    if (dhResult.empty()) return {};
    mixKey(dhResult);

    // Decrypt payload
    Bytes encPayload = tail(msg1, offset);
    payloadOut = decryptAndHash(encPayload);

    // Snapshot chaining key after msg1 (e, es, s, ss) for pre-key payload derivation
    m_ckAfterMsg1 = m_ck;

    // --- Now write message 2 ---

    // Generate responder ephemeral
    {
        auto kp = CryptoEngine::generateEphemeralX25519();
        m_e  = std::move(kp.first);
        m_ek = std::move(kp.second);
    }

    Bytes msg2;

    // e: send ephemeral
    append(msg2, m_e);
    mixHash(m_e);

    // ee: DH(e, re)
    dhResult = dh(m_ek, m_re);
    if (dhResult.empty()) return {};

    // Hybrid: KEM_ee — encapsulate to initiator's KEM pub (learned from msg1)
    if (m_hybrid && m_rsKem.size() == kKemPubLen) {
        KemEncapsResult kemEe = CryptoEngine::kemEncaps(m_rsKem);
        if (kemEe.ciphertext.empty()) return {};
        append(msg2, kemEe.ciphertext);  // 1088 bytes
        mixHash(kemEe.ciphertext);
        mixKey(concat(dhResult, kemEe.sharedSecret));  // hybrid: DH || KEM
        CryptoEngine::secureZero(kemEe.sharedSecret);
    } else {
        mixKey(dhResult);
    }

    // se: DH(e, rs) where rs is the initiator's static
    dhResult = dh(m_ek, m_rs);
    if (dhResult.empty()) return {};
    mixKey(dhResult);

    // Encrypt payload
    Bytes encMsg2Payload = encryptAndHash(msg2Payload);
    append(msg2, encMsg2Payload);

    m_complete = true;
    return msg2;
}

bool NoiseState::readMessage2(const Bytes& msg2, Bytes& payloadOut) {
    if (m_role != Initiator) return false;

    const size_t kPubLen = 32;
    const size_t kTagLen = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

    if (msg2.size() < kPubLen + kTagLen) return false;

    size_t offset = 0;

    // e: read responder's ephemeral
    m_re = slice(msg2, offset, kPubLen);
    offset += kPubLen;
    mixHash(m_re);

    // ee: DH(e, re) — our ephemeral with their ephemeral
    Bytes dhResult = dh(m_ek, m_re);
    if (dhResult.empty()) return false;

    // Hybrid: KEM_ee — decapsulate the KEM ciphertext from responder
    if (m_hybrid) {
        if (msg2.size() < offset + kKemCtLen) return false;
        Bytes kemEeCt = slice(msg2, offset, kKemCtLen);
        offset += kKemCtLen;
        Bytes kemEeSS = CryptoEngine::kemDecaps(kemEeCt, m_kemPriv);
        if (kemEeSS.empty()) return false;
        mixHash(kemEeCt);
        mixKey(concat(dhResult, kemEeSS));  // hybrid: DH || KEM
        sodium_memzero(kemEeSS.data(), kemEeSS.size());
    } else {
        mixKey(dhResult);
    }

    // se: From initiator's view: DH(initiator_s, responder_e) = DH(sk, re)
    dhResult = dh(m_sk, m_re);
    if (dhResult.empty()) return false;
    mixKey(dhResult);

    // Decrypt payload
    Bytes encPayload = tail(msg2, offset);
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
    if (!m_ek.empty()) sodium_memzero(m_ek.data(), m_ek.size());
    if (!m_sk.empty()) sodium_memzero(m_sk.data(), m_sk.size());
    if (!m_ck.empty()) sodium_memzero(m_ck.data(), m_ck.size());
    if (!m_k.empty())  sodium_memzero(m_k.data(),  m_k.size());
    if (!m_kemPriv.empty()) sodium_memzero(m_kemPriv.data(), m_kemPriv.size());

    return result;
}

// ---------------------------
// Serialization — matches the old QDataStream Qt_5_15 binary layout so
// existing persisted sessions deserialize unchanged.
// ---------------------------

Bytes NoiseState::serialize() const {
    p2p::BinaryWriter w;

    // v4: adds hybrid PQ fields. m_sk and m_kemPriv NOT persisted (C3 fix).
    w.u8(4);                         // version
    w.u8(static_cast<uint8_t>(m_role));
    w.boolean(m_complete);
    w.boolean(m_hybrid);
    w.bytes(m_ck);
    w.bytes(m_h);
    w.bytes(m_k);
    w.u64(m_n);
    w.bytes(m_s);
    w.bytes(m_rs);
    w.bytes(m_e);
    w.bytes(m_ek);
    w.bytes(m_re);
    w.bytes(m_ckAfterMsg1);
    // v4 PQ fields (may be empty for classical handshakes)
    w.bytes(m_kemPub);
    w.bytes(m_rsKem);

    return w.take();
}

NoiseState NoiseState::deserialize(const Bytes& data) {
    NoiseState ns;
    p2p::BinaryReader r(data);

    const uint8_t version = r.u8();
    if (!r.ok() || version < 1 || version > 4) return ns;

    ns.m_role = static_cast<Role>(r.u8());
    ns.m_complete = r.boolean();

    if (version >= 4) {
        ns.m_hybrid = r.boolean();
    }

    ns.m_ck = r.bytes();
    ns.m_h  = r.bytes();
    ns.m_k  = r.bytes();
    ns.m_n  = r.u64();

    if (version <= 2) {
        // Legacy: m_sk was serialized between m_s and m_rs
        ns.m_s  = r.bytes();
        ns.m_sk = r.bytes();
        ns.m_rs = r.bytes();
    } else {
        // v3+: m_sk not persisted — caller must re-inject
        ns.m_s  = r.bytes();
        ns.m_rs = r.bytes();
    }

    ns.m_e  = r.bytes();
    ns.m_ek = r.bytes();
    ns.m_re = r.bytes();

    if (version >= 2) {
        ns.m_ckAfterMsg1 = r.bytes();
    }

    // v4: PQ fields
    if (version >= 4) {
        ns.m_kemPub = r.bytes();
        ns.m_rsKem  = r.bytes();
    }

    if (!r.ok()) {
        // Short/corrupt blob — return a default (not-yet-complete) state.
        return NoiseState{};
    }
    return ns;
}
