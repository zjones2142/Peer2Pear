#include "RatchetSession.hpp"
#include "CryptoEngine.hpp"
#include "binary_io.hpp"
#include "log.hpp"
#include <sodium.h>
#include <cstring>
#include <algorithm>

// ---------------------------
// RatchetHeader
// ---------------------------

// ML-KEM-768 sizes
static constexpr size_t kKemPubLen = 1184;
static constexpr size_t kKemCtLen  = 1088;

namespace {

// Tiny helpers for Bytes manipulation — local to this file so we don't leak
// into the Bytes typedef's public namespace.  If they grow, move them into
// binary_io.hpp.
inline void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

inline void append(Bytes& dst, const uint8_t* data, size_t n) {
    dst.insert(dst.end(), data, data + n);
}

inline Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

inline Bytes slice(const Bytes& src, size_t start, size_t n) {
    if (start >= src.size()) return {};
    const size_t take = std::min(n, src.size() - start);
    return Bytes(src.begin() + start, src.begin() + start + take);
}

inline Bytes tail(const Bytes& src, size_t start) {
    if (start >= src.size()) return {};
    return Bytes(src.begin() + start, src.end());
}

inline void zeroBytes(Bytes& b) {
    if (!b.empty()) sodium_memzero(b.data(), b.size());
}

}  // anonymous namespace

Bytes RatchetHeader::serialize() const {
    Bytes out;
    out.reserve(kClassicalSize + (kemPub.empty() ? 0 : 2 + kemCt.size() + kemPub.size()));

    // Classical fields: dhPub(32) + prevChainLen(4) + messageNum(4)
    append(out, dhPub);
    // Big-endian 32-bit
    out.push_back(static_cast<uint8_t>((prevChainLen >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((prevChainLen >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((prevChainLen >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>( prevChainLen        & 0xFF));
    out.push_back(static_cast<uint8_t>((messageNum >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((messageNum >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((messageNum >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>( messageNum        & 0xFF));

    // Hybrid PQ fields: kemCtLen(2) + kemCt(0..1088) + kemPub(0..1184)
    if (!kemPub.empty()) {
        const uint16_t ctLen = static_cast<uint16_t>(kemCt.size());
        out.push_back(static_cast<uint8_t>((ctLen >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>( ctLen       & 0xFF));
        if (!kemCt.empty())
            append(out, kemCt);
        append(out, kemPub);
    }

    return out;
}

RatchetHeader RatchetHeader::deserialize(const Bytes& data, size_t& bytesRead) {
    RatchetHeader h;
    bytesRead = 0;
    if (data.size() < static_cast<size_t>(kClassicalSize)) return h;

    h.dhPub = slice(data, 0, 32);
    h.prevChainLen =
        (static_cast<uint32_t>(data[32]) << 24) |
        (static_cast<uint32_t>(data[33]) << 16) |
        (static_cast<uint32_t>(data[34]) <<  8) |
         static_cast<uint32_t>(data[35]);
    h.messageNum =
        (static_cast<uint32_t>(data[36]) << 24) |
        (static_cast<uint32_t>(data[37]) << 16) |
        (static_cast<uint32_t>(data[38]) <<  8) |
         static_cast<uint32_t>(data[39]);
    bytesRead = kClassicalSize;  // 40

    // Check for hybrid PQ extension: kemCtLen(2) + kemCt + kemPub
    if (data.size() >= bytesRead + 2) {
        const uint16_t ctLen =
            (static_cast<uint16_t>(data[bytesRead]) << 8) |
             static_cast<uint16_t>(data[bytesRead + 1]);

        // Validate KEM ciphertext size: must be 0 (no CT) or exactly 1088 (ML-KEM-768)
        if (ctLen != 0 && ctLen != kKemCtLen) return h;  // reject malformed

        const size_t pqSize = 2 + ctLen + kKemPubLen;
        if (data.size() >= bytesRead + pqSize) {
            bytesRead += 2;
            if (ctLen > 0) {
                h.kemCt = slice(data, bytesRead, ctLen);
                bytesRead += ctLen;
            }
            h.kemPub = slice(data, bytesRead, kKemPubLen);
            bytesRead += kKemPubLen;
        }
    }

    return h;
}

// ---------------------------
// KDF functions
// ---------------------------

std::pair<Bytes, Bytes> RatchetSession::kdfRootKey(const Bytes& rootKey,
                                                    const Bytes& dhOutput) {
    // HKDF-like: use BLAKE2b keyed hash
    // temp = BLAKE2b-512(key=rootKey, input=dhOutput)
    unsigned char temp[64];
    (void)crypto_generichash(temp, 64,
                             dhOutput.data(),
                             dhOutput.size(),
                             rootKey.data(),
                             rootKey.size());

    Bytes newRootKey(temp, temp + 32);
    Bytes chainKey(temp + 32, temp + 64);
    sodium_memzero(temp, sizeof(temp));
    return { newRootKey, chainKey };
}

std::pair<Bytes, Bytes> RatchetSession::kdfChainKey(const Bytes& chainKey) {
    // newChainKey = BLAKE2b-256(key=chainKey, input=0x01)
    // messageKey  = BLAKE2b-256(key=chainKey, input=0x02)
    unsigned char ck[32], mk[32];
    const unsigned char input1 = 0x01;
    const unsigned char input2 = 0x02;

    (void)crypto_generichash(ck, 32, &input1, 1,
                             chainKey.data(),
                             chainKey.size());
    (void)crypto_generichash(mk, 32, &input2, 1,
                             chainKey.data(),
                             chainKey.size());

    Bytes newChain(ck, ck + 32);
    Bytes msgKey(mk, mk + 32);
    sodium_memzero(ck, sizeof(ck));
    sodium_memzero(mk, sizeof(mk));
    return { newChain, msgKey };
}

// ---------------------------
// Factory methods
// ---------------------------

// Stable per-session id (8 bytes BLAKE2b of the initial root key).
// See header docstring for how Phase 1 group messaging uses this.
//
// Persistence: m_initialRootKey is round-tripped via serialize/
// deserialize at version >= 3.  Sessions persisted under v1 / v2
// (pre-Phase-1 deploys) carry an empty m_initialRootKey on load and
// sessionId() returns empty bytes — the v2 group sender path
// degrades gracefully (group_send_state lookups miss; the chain
// resumes from counter=1 on the next outbound, which a fresh
// handshake would have done anyway).
Bytes RatchetSession::sessionId() const
{
    if (m_initialRootKey.size() != 32) return {};
    Bytes out(8);
    (void)crypto_generichash(out.data(), out.size(),
                             m_initialRootKey.data(),
                             m_initialRootKey.size(),
                             nullptr, 0);
    return out;
}

RatchetSession RatchetSession::initAsInitiator(const Bytes& rootKey,
                                                const Bytes& remoteDhPub,
                                                const Bytes& localDhPub,
                                                const Bytes& localDhPriv,
                                                bool hybrid) {
    RatchetSession s;
    s.m_hybrid = hybrid;
    s.m_remoteDhPub = remoteDhPub;
    // Pin the handshake-time root key for stable per-session
    // identification (see sessionId() docstring).  Both sides receive
    // the same rootKey from the Noise chaining_key, so they compute
    // identical sessionId bytes without exchanging anything.
    s.m_initialRootKey = rootKey;

    // Use the provided DH keypair (Noise ephemeral) so the responder already knows our pub
    s.m_dhPub  = localDhPub;
    s.m_dhPriv = localDhPriv;

    // Hybrid: generate initial KEM keypair
    if (hybrid) {
        auto kp = CryptoEngine::generateKemKeypair();
        s.m_kemPub  = std::move(kp.first);
        s.m_kemPriv = std::move(kp.second);
    }

    // Reject all-zeros remote pubkey (low-order check is also performed
    // by crypto_scalarmult itself via its non-zero return).
    if (remoteDhPub.size() != 32 ||
        sodium_is_zero(remoteDhPub.data(), remoteDhPub.size())) {
        return {};
    }

    // Perform initial DH and derive sending chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          localDhPriv.data(),
                          remoteDhPub.data()) != 0) {
        return {};
    }

    Bytes dhOutput(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [newRoot, sendChain] = kdfRootKey(rootKey, dhOutput);
    s.m_rootKey      = newRoot;
    s.m_sendChainKey = sendChain;

    // Wipe the DH shared-secret and the chain-key intermediates now that
    // they've been copied into the RatchetSession.  Under std::vector
    // value semantics the copy is a real buffer copy, so zeroing the
    // locals doesn't touch the stored members.
    zeroBytes(dhOutput);
    zeroBytes(newRoot);
    zeroBytes(sendChain);

#ifndef QT_NO_DEBUG_OUTPUT
    P2P_LOG("[Ratchet] initAsInitiator: session created " << (hybrid ? "(hybrid PQ)" : ""));
#endif
    return s;
}

RatchetSession RatchetSession::initAsResponder(const Bytes& rootKey,
                                                const Bytes& localDhPub,
                                                const Bytes& localDhPriv,
                                                const Bytes& remoteDhPub,
                                                bool hybrid) {
    RatchetSession s;
    s.m_hybrid = hybrid;
    s.m_remoteDhPub = remoteDhPub;
    // Pin the handshake-time root key for sessionId() — see the
    // matching note in initAsInitiator above.
    s.m_initialRootKey = rootKey;

    // Reject all-zeros remote pubkey before the first scalarmult.
    if (remoteDhPub.size() != 32 ||
        sodium_is_zero(remoteDhPub.data(), remoteDhPub.size())) {
        return {};
    }

    // Step 1: Derive receiving chain from DH(our priv, initiator's pub)
    // This matches the initiator's sending chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          localDhPriv.data(),
                          remoteDhPub.data()) != 0) {
        return {};
    }
    Bytes dhOutput(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk1, recvChain] = kdfRootKey(rootKey, dhOutput);
    s.m_rootKey      = rk1;
    s.m_recvChainKey = recvChain;
    // Wipe intermediates post-copy.
    zeroBytes(dhOutput);
    zeroBytes(rk1);
    zeroBytes(recvChain);

    // Step 2: Generate new DH keypair and derive sending chain
    {
        auto kp = CryptoEngine::generateEphemeralX25519();
        s.m_dhPub  = std::move(kp.first);
        s.m_dhPriv = std::move(kp.second);
    }

    // Hybrid: generate initial KEM keypair for sending
    if (hybrid) {
        auto kp = CryptoEngine::generateKemKeypair();
        s.m_kemPub  = std::move(kp.first);
        s.m_kemPriv = std::move(kp.second);
    }

    if (crypto_scalarmult(shared,
                          s.m_dhPriv.data(),
                          remoteDhPub.data()) != 0) {
        return {};
    }
    dhOutput.assign(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk2, sendChain] = kdfRootKey(s.m_rootKey, dhOutput);
    s.m_rootKey      = rk2;
    s.m_sendChainKey = sendChain;
    // Wipe intermediates post-copy.
    zeroBytes(dhOutput);
    zeroBytes(rk2);
    zeroBytes(sendChain);

#ifndef QT_NO_DEBUG_OUTPUT
    P2P_LOG("[Ratchet] initAsResponder: session created " << (hybrid ? "(hybrid PQ)" : ""));
#endif
    return s;
}

// ---------------------------
// DH ratchet step
// ---------------------------

void RatchetSession::dhRatchetStep(const Bytes& remoteDhPub,
                                    const Bytes& kemCt) {
    // Reject all-zeros or low-order remote DH pubkeys.  Without this
    // check a peer (or malicious relay swapping bytes in the header)
    // could force the scalarmult to land on a known shared secret.
    // sodium_is_zero catches the all-zero case; crypto_scalarmult itself
    // returns non-zero on low-order inputs and we propagate that.
    if (remoteDhPub.size() != 32 ||
        sodium_is_zero(remoteDhPub.data(), remoteDhPub.size())) {
        return;
    }

    m_prevChainLen = m_sendMsgNum;
    m_sendMsgNum = 0;
    m_recvMsgNum = 0;
    m_remoteDhPub = remoteDhPub;

    // DH with our current private + new remote public -> receiving chain.
    // crypto_scalarmult returns non-zero on low-order points (libsodium
    // rejects them explicitly) — the if-return below propagates that.
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          m_dhPriv.data(),
                          remoteDhPub.data()) != 0)
        return;
    Bytes dhOutput(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    // Hybrid: if the peer included a KEM ciphertext, decapsulate and combine with DH
    if (m_hybrid && !kemCt.empty() && !m_kemPriv.empty()) {
        Bytes kemSS = CryptoEngine::kemDecaps(kemCt, m_kemPriv);
        if (!kemSS.empty()) {
            dhOutput = concat(dhOutput, kemSS);  // DH || KEM combined input
            CryptoEngine::secureZero(kemSS);
        }
    }

    auto [rk1, recvChain] = kdfRootKey(m_rootKey, dhOutput);
    zeroBytes(dhOutput);
    m_rootKey      = rk1;
    m_recvChainKey = recvChain;
    // Wipe chain-key intermediates post-copy.
    zeroBytes(rk1);
    zeroBytes(recvChain);

    // Generate new DH keypair for sending
    {
        auto kp = CryptoEngine::generateEphemeralX25519();
        m_dhPub  = std::move(kp.first);
        m_dhPriv = std::move(kp.second);
    }

    // Hybrid: generate new KEM keypair and encapsulate to peer's KEM pub
    m_pendingKemCt.clear();
    if (m_hybrid) {
        zeroBytes(m_kemPriv);
        {
            auto kp = CryptoEngine::generateKemKeypair();
            m_kemPub  = std::move(kp.first);
            m_kemPriv = std::move(kp.second);
        }

        // Encapsulate to the peer's KEM pub (received in their last header)
        // Store the ciphertext — it will be included in our next message header
        if (m_remoteKemPub.size() == kKemPubLen) {
            KemEncapsResult kemResult = CryptoEngine::kemEncaps(m_remoteKemPub);
            if (!kemResult.ciphertext.empty()) {
                m_pendingKemCt = std::move(kemResult.ciphertext);
                // Mix KEM SS into root key (peer will decaps and do the same)
                Bytes augmented = CryptoEngine::hkdf(
                    kemResult.sharedSecret, m_rootKey,
                    Bytes{'r','a','t','c','h','e','t','-','k','e','m'}, 32);
                CryptoEngine::secureZero(kemResult.sharedSecret);
                if (!augmented.empty())
                    m_rootKey = std::move(augmented);
            }
        }
    }

    // DH with new private + remote public -> sending chain
    if (crypto_scalarmult(shared,
                          m_dhPriv.data(),
                          remoteDhPub.data()) != 0)
        return;
    dhOutput.assign(shared, shared + sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk2, sendChain] = kdfRootKey(m_rootKey, dhOutput);
    zeroBytes(dhOutput);
    m_rootKey      = rk2;
    m_sendChainKey = sendChain;
    // Wipe chain-key intermediates post-copy.
    zeroBytes(rk2);
    zeroBytes(sendChain);
}

// ---------------------------
// Encrypt
// ---------------------------

Bytes RatchetSession::encrypt(const Bytes& plaintext) {
    if (m_sendChainKey.empty()) {
        P2P_WARN("[Ratchet] encrypt: sendChainKey is empty!");
        return {};
    }

    // Prevent nonce reuse from counter overflow.
    // uint32_t wraps at 2^32. Force a session reset well before that.
    if (m_sendMsgNum >= 0xFFFFFFF0u) {
        P2P_WARN("[Ratchet] encrypt: message counter near overflow — refusing to encrypt");
        return {};
    }

    auto [newChain, msgKey] = kdfChainKey(m_sendChainKey);
    m_sendChainKey = newChain;
    // Deep copy (explicit — std::vector doesn't COW, so a copy-assign is
    // already fine, but we keep a dedicated local for the zero-after-use
    // pattern below).
    m_lastMessageKey = Bytes(msgKey.begin(), msgKey.end());

    RatchetHeader header;
    header.dhPub        = m_dhPub;
    header.prevChainLen = m_prevChainLen;
    header.messageNum   = m_sendMsgNum++;

    // Hybrid: include our KEM pub so the peer can encapsulate back on their next
    // DH ratchet step. We do NOT encapsulate here — KEM encaps/decaps happens only
    // during dhRatchetStep() to stay synchronized with the DH ratchet pace.
    if (m_hybrid && !m_kemPub.empty()) {
        header.kemPub = m_kemPub;
        header.kemCt  = m_pendingKemCt;  // set during our last dhRatchetStep, if any
        m_pendingKemCt.clear();          // consume — don't send same ciphertext twice
    }

    P2P_LOG("[Ratchet] encrypt: msgNum=" << header.messageNum
            << " " << (m_hybrid ? "(hybrid PQ)" : ""));

    Bytes headerBytes = header.serialize();

    // AEAD encrypt: key=msgKey, aad=headerBytes
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    Bytes ct(sizeof(nonce) + plaintext.size() +
             crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data() + sizeof(nonce), &clen,
        plaintext.data(),
        static_cast<unsigned long long>(plaintext.size()),
        headerBytes.data(),
        static_cast<unsigned long long>(headerBytes.size()),
        nullptr, nonce,
        msgKey.data());

    std::memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(sizeof(nonce) + clen);

    zeroBytes(msgKey);

    // Output: header(40) || nonce(24) || ciphertext
    Bytes out = concat(headerBytes, ct);
    return out;
}

// ---------------------------
// Decrypt
// ---------------------------

Bytes RatchetSession::trySkippedKeys(const RatchetHeader& header,
                                      const Bytes& ciphertext) {
    auto key = std::make_pair(header.dhPub, header.messageNum);
    auto it = m_skippedKeys.find(key);
    if (it == m_skippedKeys.end()) return {};

    // Zero the value inside the map before we erase its node, then zero
    // our local copy on every exit path.  A plain std::map::erase would
    // free the buffer without wiping it, leaving the message key in the
    // heap until the allocator reused the slot.
    Bytes msgKey = it->second;
    zeroBytes(it->second);
    m_skippedKeys.erase(it);

    // Decrypt with the skipped key
    Bytes headerBytes = header.serialize();
    if (ciphertext.size() < (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                              crypto_aead_xchacha20poly1305_ietf_ABYTES)) {
        zeroBytes(msgKey);
        return {};
    }

    const unsigned char* nonce = ciphertext.data();
    const unsigned char* c = ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t cLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    Bytes pt(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            headerBytes.data(),
            static_cast<unsigned long long>(headerBytes.size()),
            nonce,
            msgKey.data()) != 0) {
        zeroBytes(msgKey);
        return {};
    }

    pt.resize(plen);
    // Store message key so callers can extract it for file sub-keys.
    m_lastMessageKey = Bytes(msgKey.begin(), msgKey.end());
    zeroBytes(msgKey);
    return pt;
}

bool RatchetSession::skipMessageKeys(const Bytes& dhPub, uint32_t until) {
    if (m_recvChainKey.empty()) return true; // no chain to skip in
    if (until > m_recvMsgNum + kMaxSkipped) return false; // too many to skip

    while (m_recvMsgNum < until) {
        auto [newChain, msgKey] = kdfChainKey(m_recvChainKey);
        m_recvChainKey = newChain;
        m_skippedKeys[std::make_pair(dhPub, m_recvMsgNum)] = msgKey;
        // Local msgKey's buffer would otherwise outlive this iteration
        // on the heap (the map copy is independent).
        zeroBytes(msgKey);
        zeroBytes(newChain);
        ++m_recvMsgNum;
    }

    // Prune if over limit — std::map erase first is O(log n).
    // Zero the evicted value before destructing the node.
    while (m_skippedKeys.size() > static_cast<size_t>(kMaxSkipped)) {
        auto victim = m_skippedKeys.begin();
        zeroBytes(victim->second);
        m_skippedKeys.erase(victim);
    }

    return true;
}

Bytes RatchetSession::decrypt(const Bytes& headerAndCiphertext) {
    if (headerAndCiphertext.size() < static_cast<size_t>(RatchetHeader::kClassicalSize)) {
        P2P_WARN("[Ratchet] decrypt: too short " << headerAndCiphertext.size());
        return {};
    }

    size_t headerLen = 0;
    RatchetHeader header = RatchetHeader::deserialize(headerAndCiphertext, headerLen);
    if (headerLen == 0) {
        P2P_WARN("[Ratchet] decrypt: header deserialize failed");
        return {};
    }

    Bytes ciphertext = tail(headerAndCiphertext, headerLen);
    P2P_LOG("[Ratchet] decrypt: msgNum=" << header.messageNum
            << " prevChain=" << header.prevChainLen);

    // Try skipped keys first
    Bytes skippedResult = trySkippedKeys(header, ciphertext);
    if (!skippedResult.empty()) return skippedResult;

    // If the DH key changed, perform a DH ratchet step
    if (header.dhPub != m_remoteDhPub) {
        P2P_LOG("[Ratchet] DH ratchet step " << (m_hybrid ? "(hybrid PQ)" : ""));
        // Skip any remaining messages in the current receiving chain
        if (!skipMessageKeys(m_remoteDhPub, header.prevChainLen))
            return {};

        // Hybrid: store the peer's KEM pub for our next dhRatchetStep to encaps to
        if (m_hybrid && header.kemPub.size() == kKemPubLen) {
            m_remoteKemPub = header.kemPub;
        }

        // Pass KEM ciphertext to dhRatchetStep — it handles decaps + root key mixing
        dhRatchetStep(header.dhPub, header.kemCt);
        P2P_LOG("[Ratchet] ratchet step complete");
    }

    // Skip ahead in the current chain if needed
    if (!skipMessageKeys(header.dhPub, header.messageNum))
        return {};

    // Derive the message key
    auto [newChain, msgKey] = kdfChainKey(m_recvChainKey);
    m_recvChainKey = newChain;
    ++m_recvMsgNum;

    // Decrypt
    Bytes headerBytes = header.serialize();
    if (ciphertext.size() < (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                              crypto_aead_xchacha20poly1305_ietf_ABYTES))
        return {};

    const unsigned char* nonce = ciphertext.data();
    const unsigned char* c = ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t cLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    Bytes pt(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            headerBytes.data(),
            static_cast<unsigned long long>(headerBytes.size()),
            nonce,
            msgKey.data()) != 0) {
        return {};
    }

    pt.resize(plen);

    // Store the message key before zeroing
    m_lastMessageKey = Bytes(msgKey.begin(), msgKey.end());
    zeroBytes(msgKey);
    return pt;
}

// ---------------------------
// Serialization
// ---------------------------

Bytes RatchetSession::serialize() const {
    p2p::BinaryWriter w;

    // Format versions:
    //   v1: legacy classical-only fields
    //   v2: + hybrid PQ state (kem keys, remote kem pub, pending kem ct)
    //   v3: + m_initialRootKey at the end so sessionId() round-trips
    //        across persistence (Phase 1 Causally-Linked Pairwise dep)
    w.u8(3);
    w.bytes(m_rootKey);
    w.bytes(m_sendChainKey);
    w.bytes(m_recvChainKey);
    w.bytes(m_dhPub);
    w.bytes(m_dhPriv);
    w.bytes(m_remoteDhPub);
    w.u32(m_sendMsgNum);
    w.u32(m_recvMsgNum);
    w.u32(m_prevChainLen);

    // Serialize skipped keys
    w.u32(static_cast<uint32_t>(m_skippedKeys.size()));
    for (const auto& [k, v] : m_skippedKeys) {
        w.bytes(k.first);   // dhPub
        w.u32(k.second);    // msgNum
        w.bytes(v);         // messageKey
    }

    // v2: hybrid PQ state
    w.boolean(m_hybrid);
    w.bytes(m_kemPub);
    w.bytes(m_kemPriv);
    w.bytes(m_remoteKemPub);
    w.bytes(m_pendingKemCt);

    // v3: handshake-time root key (stable sessionId source)
    w.bytes(m_initialRootKey);

    return w.take();
}

RatchetSession RatchetSession::deserialize(const Bytes& data) {
    RatchetSession s;
    p2p::BinaryReader r(data);

    const uint8_t version = r.u8();
    if (version < 1 || version > 3) return s;

    s.m_rootKey      = r.bytes();
    s.m_sendChainKey = r.bytes();
    s.m_recvChainKey = r.bytes();
    s.m_dhPub        = r.bytes();
    s.m_dhPriv       = r.bytes();
    s.m_remoteDhPub  = r.bytes();
    s.m_sendMsgNum   = r.u32();
    s.m_recvMsgNum   = r.u32();
    s.m_prevChainLen = r.u32();

    const uint32_t skippedCount = r.u32();
    for (uint32_t i = 0; i < skippedCount && i < static_cast<uint32_t>(kMaxSkipped); ++i) {
        Bytes dhPub = r.bytes();
        uint32_t msgNum = r.u32();
        Bytes key = r.bytes();
        s.m_skippedKeys[std::make_pair(std::move(dhPub), msgNum)] = std::move(key);
    }

    // v2: hybrid PQ state
    if (version >= 2) {
        s.m_hybrid       = r.boolean();
        s.m_kemPub       = r.bytes();
        s.m_kemPriv      = r.bytes();
        s.m_remoteKemPub = r.bytes();
        s.m_pendingKemCt = r.bytes();

        // Validate PQ key sizes — reject corrupted state
        if (s.m_hybrid) {
            if ((!s.m_kemPub.empty() && s.m_kemPub.size() != kKemPubLen) ||
                (!s.m_kemPriv.empty() && s.m_kemPriv.size() != 2400) ||
                (!s.m_remoteKemPub.empty() && s.m_remoteKemPub.size() != kKemPubLen) ||
                (!s.m_pendingKemCt.empty() && s.m_pendingKemCt.size() != kKemCtLen)) {
                return RatchetSession{};  // corrupted — return invalid
            }
        }
    }

    // v3: persisted handshake-time root key.  Pre-v3 sessions that
    // load through this path leave m_initialRootKey empty —
    // sessionId() returns empty bytes, signaling "this session was
    // persisted before sessionId support; UI degrades gracefully
    // (group_send_state lookups miss, peers fall back to a fresh
    // chain on the next outbound)."
    if (version >= 3) {
        s.m_initialRootKey = r.bytes();
    }

    if (!r.ok()) return RatchetSession{};
    return s;
}
