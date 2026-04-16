#include "RatchetSession.hpp"
#include "CryptoEngine.hpp"
#include <sodium.h>
#include <QDebug>
#include <QDataStream>
#include <QIODevice>
#include <QtEndian>
#include <cstring>

// ---------------------------
// RatchetHeader
// ---------------------------

// ML-KEM-768 sizes
static constexpr int kKemPubLen = 1184;
static constexpr int kKemCtLen  = 1088;

QByteArray RatchetHeader::serialize() const {
    QByteArray out;

    // Classical fields: dhPub(32) + prevChainLen(4) + messageNum(4)
    out.append(dhPub);
    quint32 pcl = qToBigEndian(prevChainLen);
    quint32 mn  = qToBigEndian(messageNum);
    out.append(reinterpret_cast<const char*>(&pcl), 4);
    out.append(reinterpret_cast<const char*>(&mn), 4);

    // Hybrid PQ fields: kemCtLen(2) + kemCt(0..1088) + kemPub(0..1184)
    // kemCtLen = 0 means no KEM ciphertext; kemPub follows only if kemCtLen > 0 or kemPub is non-empty
    if (!kemPub.isEmpty()) {
        quint16 ctLen = qToBigEndian(static_cast<quint16>(kemCt.size()));
        out.append(reinterpret_cast<const char*>(&ctLen), 2);
        if (!kemCt.isEmpty())
            out.append(kemCt);
        out.append(kemPub);
    }

    return out;
}

RatchetHeader RatchetHeader::deserialize(const QByteArray& data, int& bytesRead) {
    RatchetHeader h;
    bytesRead = 0;
    if (data.size() < kClassicalSize) return h;

    h.dhPub = data.left(32);
    quint32 pcl, mn;
    memcpy(&pcl, data.constData() + 32, 4);
    memcpy(&mn,  data.constData() + 36, 4);
    h.prevChainLen = qFromBigEndian(pcl);
    h.messageNum   = qFromBigEndian(mn);
    bytesRead = kClassicalSize;  // 40

    // Check for hybrid PQ extension: kemCtLen(2) + kemCt + kemPub
    if (data.size() >= bytesRead + 2) {
        quint16 ctLenBE;
        memcpy(&ctLenBE, data.constData() + bytesRead, 2);
        quint16 ctLen = qFromBigEndian(ctLenBE);

        // Validate KEM ciphertext size: must be 0 (no CT) or exactly 1088 (ML-KEM-768)
        if (ctLen != 0 && ctLen != kKemCtLen) return h;  // reject malformed

        const int pqSize = 2 + ctLen + kKemPubLen;
        if (data.size() >= bytesRead + pqSize) {
            bytesRead += 2;
            if (ctLen > 0) {
                h.kemCt = data.mid(bytesRead, ctLen);
                bytesRead += ctLen;
            }
            h.kemPub = data.mid(bytesRead, kKemPubLen);
            bytesRead += kKemPubLen;
        }
    }

    return h;
}

// ---------------------------
// KDF functions
// ---------------------------

QPair<QByteArray, QByteArray> RatchetSession::kdfRootKey(const QByteArray& rootKey,
                                                          const QByteArray& dhOutput) {
    // HKDF-like: use BLAKE2b keyed hash
    // temp = BLAKE2b-512(key=rootKey, input=dhOutput)
    unsigned char temp[64];
    (void)crypto_generichash(temp, 64,
                             reinterpret_cast<const unsigned char*>(dhOutput.constData()),
                             static_cast<size_t>(dhOutput.size()),
                             reinterpret_cast<const unsigned char*>(rootKey.constData()),
                             static_cast<size_t>(rootKey.size()));

    QByteArray newRootKey(reinterpret_cast<const char*>(temp), 32);
    QByteArray chainKey(reinterpret_cast<const char*>(temp + 32), 32);
    sodium_memzero(temp, sizeof(temp));
    return { newRootKey, chainKey };
}

QPair<QByteArray, QByteArray> RatchetSession::kdfChainKey(const QByteArray& chainKey) {
    // newChainKey = BLAKE2b-256(key=chainKey, input=0x01)
    // messageKey  = BLAKE2b-256(key=chainKey, input=0x02)
    unsigned char ck[32], mk[32];
    const unsigned char input1 = 0x01;
    const unsigned char input2 = 0x02;

    (void)crypto_generichash(ck, 32, &input1, 1,
                             reinterpret_cast<const unsigned char*>(chainKey.constData()),
                             static_cast<size_t>(chainKey.size()));
    (void)crypto_generichash(mk, 32, &input2, 1,
                             reinterpret_cast<const unsigned char*>(chainKey.constData()),
                             static_cast<size_t>(chainKey.size()));

    QByteArray newChain(reinterpret_cast<const char*>(ck), 32);
    QByteArray msgKey(reinterpret_cast<const char*>(mk), 32);
    sodium_memzero(ck, sizeof(ck));
    sodium_memzero(mk, sizeof(mk));
    return { newChain, msgKey };
}

// ---------------------------
// Factory methods
// ---------------------------

RatchetSession RatchetSession::initAsInitiator(const QByteArray& rootKey,
                                                const QByteArray& remoteDhPub,
                                                const QByteArray& localDhPub,
                                                const QByteArray& localDhPriv,
                                                bool hybrid) {
    RatchetSession s;
    s.m_hybrid = hybrid;
    s.m_remoteDhPub = remoteDhPub;

    // Use the provided DH keypair (Noise ephemeral) so the responder already knows our pub
    s.m_dhPub  = localDhPub;
    s.m_dhPriv = localDhPriv;

    // Hybrid: generate initial KEM keypair
    if (hybrid) {
        auto [kemPub, kemPriv] = CryptoEngine::generateKemKeypair();
        s.m_kemPub  = kemPub;
        s.m_kemPriv = kemPriv;
        CryptoEngine::secureZero(kemPriv);
    }

    // Perform initial DH and derive sending chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(localDhPriv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0) {
        return {};
    }

    QByteArray dhOutput(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [newRoot, sendChain] = kdfRootKey(rootKey, dhOutput);
    s.m_rootKey      = newRoot;
    s.m_sendChainKey = sendChain;

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Ratchet] initAsInitiator: session created" << (hybrid ? "(hybrid PQ)" : "");
#endif
    return s;
}

RatchetSession RatchetSession::initAsResponder(const QByteArray& rootKey,
                                                const QByteArray& localDhPub,
                                                const QByteArray& localDhPriv,
                                                const QByteArray& remoteDhPub,
                                                bool hybrid) {
    RatchetSession s;
    s.m_hybrid = hybrid;
    s.m_remoteDhPub = remoteDhPub;

    // Step 1: Derive receiving chain from DH(our priv, initiator's pub)
    // This matches the initiator's sending chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(localDhPriv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0) {
        return {};
    }
    QByteArray dhOutput(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk1, recvChain] = kdfRootKey(rootKey, dhOutput);
    s.m_rootKey      = rk1;
    s.m_recvChainKey = recvChain;

    // Step 2: Generate new DH keypair and derive sending chain
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    s.m_dhPub  = pub;
    s.m_dhPriv = priv;

    // Hybrid: generate initial KEM keypair for sending
    if (hybrid) {
        auto [kemPub, kemPriv] = CryptoEngine::generateKemKeypair();
        s.m_kemPub  = kemPub;
        s.m_kemPriv = kemPriv;
        CryptoEngine::secureZero(kemPriv);
    }

    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(priv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0) {
        return {};
    }
    dhOutput = QByteArray(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk2, sendChain] = kdfRootKey(s.m_rootKey, dhOutput);
    s.m_rootKey      = rk2;
    s.m_sendChainKey = sendChain;

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Ratchet] initAsResponder: session created" << (hybrid ? "(hybrid PQ)" : "");
#endif
    return s;
}

// ---------------------------
// DH ratchet step
// ---------------------------

void RatchetSession::dhRatchetStep(const QByteArray& remoteDhPub,
                                    const QByteArray& kemCt) {
    m_prevChainLen = m_sendMsgNum;
    m_sendMsgNum = 0;
    m_recvMsgNum = 0;
    m_remoteDhPub = remoteDhPub;

    // DH with our current private + new remote public -> receiving chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(m_dhPriv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0)
        return;
    QByteArray dhOutput(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    // Hybrid: if the peer included a KEM ciphertext, decapsulate and combine with DH
    if (m_hybrid && !kemCt.isEmpty() && !m_kemPriv.isEmpty()) {
        QByteArray kemSS = CryptoEngine::kemDecaps(kemCt, m_kemPriv);
        if (!kemSS.isEmpty()) {
            dhOutput = dhOutput + kemSS;  // DH || KEM combined input
            CryptoEngine::secureZero(kemSS);
        }
    }

    auto [rk1, recvChain] = kdfRootKey(m_rootKey, dhOutput);
    CryptoEngine::secureZero(dhOutput);
    m_rootKey      = rk1;
    m_recvChainKey = recvChain;

    // Generate new DH keypair for sending
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    m_dhPub  = pub;
    m_dhPriv = priv;

    // Hybrid: generate new KEM keypair and encapsulate to peer's KEM pub
    m_pendingKemCt.clear();
    if (m_hybrid) {
        CryptoEngine::secureZero(m_kemPriv);
        auto [kemPub, kemPriv] = CryptoEngine::generateKemKeypair();
        m_kemPub  = kemPub;
        m_kemPriv = kemPriv;
        CryptoEngine::secureZero(kemPriv);

        // Encapsulate to the peer's KEM pub (received in their last header)
        // Store the ciphertext — it will be included in our next message header
        if (m_remoteKemPub.size() == kKemPubLen) {
            KemEncapsResult kemResult = CryptoEngine::kemEncaps(m_remoteKemPub);
            if (!kemResult.ciphertext.isEmpty()) {
                m_pendingKemCt = kemResult.ciphertext;
                // Mix KEM SS into root key (peer will decaps and do the same)
                QByteArray kemIkm = kemResult.sharedSecret;
                CryptoEngine::secureZero(kemResult.sharedSecret);
                QByteArray augmented = CryptoEngine::hkdf(
                    kemIkm, m_rootKey, QByteArray("ratchet-kem"), 32);
                CryptoEngine::secureZero(kemIkm);
                if (!augmented.isEmpty())
                    m_rootKey = augmented;
            }
        }
    }

    // DH with new private + remote public -> sending chain
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(priv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0)
        return;
    dhOutput = QByteArray(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk2, sendChain] = kdfRootKey(m_rootKey, dhOutput);
    CryptoEngine::secureZero(dhOutput);
    CryptoEngine::secureZero(priv);  // H1 fix: zero ephemeral DH priv after use
    m_rootKey      = rk2;
    m_sendChainKey = sendChain;
}

// ---------------------------
// Encrypt
// ---------------------------

QByteArray RatchetSession::encrypt(const QByteArray& plaintext) {
    if (m_sendChainKey.isEmpty()) {
        qWarning() << "[Ratchet] encrypt: sendChainKey is empty!";
        return {};
    }

    // H1 fix: prevent nonce reuse from counter overflow.
    // quint32 wraps at 2^32. Force a session reset well before that.
    if (m_sendMsgNum >= 0xFFFFFFF0u) {
        qWarning() << "[Ratchet] encrypt: message counter near overflow — refusing to encrypt";
        return {};
    }

    auto [newChain, msgKey] = kdfChainKey(m_sendChainKey);
    m_sendChainKey = newChain;
    // Force a deep copy so m_lastMessageKey has its own independent buffer.
    // Without this, QByteArray's COW would share the buffer between m_lastMessageKey
    // and msgKey; when msgKey.data() is called below for sodium_memzero it would detach
    // msgKey into a fresh copy, zeroing only that copy and leaving the shared buffer
    // (still referenced by m_lastMessageKey) un-wiped in memory.
    m_lastMessageKey = QByteArray(msgKey.constData(), msgKey.size());

    RatchetHeader header;
    header.dhPub        = m_dhPub;
    header.prevChainLen = m_prevChainLen;
    header.messageNum   = m_sendMsgNum++;

    // Hybrid: include our KEM pub so the peer can encapsulate back on their next
    // DH ratchet step. We do NOT encapsulate here — KEM encaps/decaps happens only
    // during dhRatchetStep() to stay synchronized with the DH ratchet pace.
    if (m_hybrid && !m_kemPub.isEmpty()) {
        header.kemPub = m_kemPub;
        header.kemCt  = m_pendingKemCt;  // set during our last dhRatchetStep, if any
        m_pendingKemCt.clear();           // consume — don't send same ciphertext twice
    }

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Ratchet] encrypt: msgNum=" << header.messageNum
             << (m_hybrid ? "(hybrid PQ)" : "");
#endif

    QByteArray headerBytes = header.serialize();

    // AEAD encrypt: key=msgKey, aad=headerBytes
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    QByteArray ct;
    ct.resize(static_cast<int>(sizeof(nonce)) + plaintext.size() +
              crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(ct.data()) + sizeof(nonce), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()),
        static_cast<unsigned long long>(plaintext.size()),
        reinterpret_cast<const unsigned char*>(headerBytes.constData()),
        static_cast<unsigned long long>(headerBytes.size()),
        nullptr, nonce,
        reinterpret_cast<const unsigned char*>(msgKey.constData()));

    memcpy(ct.data(), nonce, sizeof(nonce));
    ct.resize(static_cast<int>(sizeof(nonce) + clen));

    sodium_memzero(msgKey.data(), msgKey.size());

    // Output: header(40) || nonce(24) || ciphertext
    return headerBytes + ct;
}

// ---------------------------
// Decrypt
// ---------------------------

QByteArray RatchetSession::trySkippedKeys(const RatchetHeader& header,
                                           const QByteArray& ciphertext) {
    auto key = qMakePair(header.dhPub, header.messageNum);
    auto it = m_skippedKeys.find(key);
    if (it == m_skippedKeys.end()) return {};

    QByteArray msgKey = it.value();
    m_skippedKeys.erase(it);

    // Decrypt with the skipped key
    QByteArray headerBytes = header.serialize();
    if (ciphertext.size() < static_cast<int>(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                              crypto_aead_xchacha20poly1305_ietf_ABYTES))
        return {};

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(ciphertext.constData());
    const unsigned char* c = reinterpret_cast<const unsigned char*>(
        ciphertext.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    int cLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    QByteArray pt;
    pt.resize(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            reinterpret_cast<const unsigned char*>(headerBytes.constData()),
            static_cast<unsigned long long>(headerBytes.size()),
            nonce,
            reinterpret_cast<const unsigned char*>(msgKey.constData())) != 0) {
        return {};
    }

    pt.resize(static_cast<int>(plen));
    // L7 fix: store message key so callers can extract it for file sub-keys
    m_lastMessageKey = QByteArray(msgKey.constData(), msgKey.size());
    sodium_memzero(msgKey.data(), msgKey.size());
    return pt;
}

bool RatchetSession::skipMessageKeys(const QByteArray& dhPub, quint32 until) {
    if (m_recvChainKey.isEmpty()) return true; // no chain to skip in
    if (until > m_recvMsgNum + kMaxSkipped) return false; // too many to skip

    while (m_recvMsgNum < until) {
        auto [newChain, msgKey] = kdfChainKey(m_recvChainKey);
        m_recvChainKey = newChain;
        m_skippedKeys.insert(qMakePair(dhPub, m_recvMsgNum), msgKey);
        ++m_recvMsgNum;
    }

    // Prune if over limit
    while (m_skippedKeys.size() > kMaxSkipped) {
        m_skippedKeys.erase(m_skippedKeys.begin());
    }

    return true;
}

QByteArray RatchetSession::decrypt(const QByteArray& headerAndCiphertext) {
    if (headerAndCiphertext.size() < RatchetHeader::kClassicalSize) {
        qWarning() << "[Ratchet] decrypt: too short" << headerAndCiphertext.size();
        return {};
    }

    int headerLen = 0;
    RatchetHeader header = RatchetHeader::deserialize(headerAndCiphertext, headerLen);
    if (headerLen == 0) {
        qWarning() << "[Ratchet] decrypt: header deserialize failed";
        return {};
    }

    QByteArray ciphertext = headerAndCiphertext.mid(headerLen);
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Ratchet] decrypt: msgNum=" << header.messageNum
             << "prevChain=" << header.prevChainLen;
#endif

    // Try skipped keys first
    QByteArray skippedResult = trySkippedKeys(header, ciphertext);
    if (!skippedResult.isEmpty()) return skippedResult;

    // If the DH key changed, perform a DH ratchet step
    if (header.dhPub != m_remoteDhPub) {
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[Ratchet] DH ratchet step" << (m_hybrid ? "(hybrid PQ)" : "");
#endif
        // Skip any remaining messages in the current receiving chain
        if (!skipMessageKeys(m_remoteDhPub, header.prevChainLen))
            return {};

        // Hybrid: store the peer's KEM pub for our next dhRatchetStep to encaps to
        if (m_hybrid && header.kemPub.size() == kKemPubLen) {
            m_remoteKemPub = header.kemPub;
        }

        // Pass KEM ciphertext to dhRatchetStep — it handles decaps + root key mixing
        dhRatchetStep(header.dhPub, header.kemCt);
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[Ratchet] ratchet step complete";
#endif
    }

    // Skip ahead in the current chain if needed
    if (!skipMessageKeys(header.dhPub, header.messageNum))
        return {};

    // Derive the message key
    auto [newChain, msgKey] = kdfChainKey(m_recvChainKey);
    m_recvChainKey = newChain;
    ++m_recvMsgNum;

    // Decrypt
    QByteArray headerBytes = header.serialize();
    if (ciphertext.size() < static_cast<int>(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                              crypto_aead_xchacha20poly1305_ietf_ABYTES))
        return {};

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(ciphertext.constData());
    const unsigned char* c = reinterpret_cast<const unsigned char*>(
        ciphertext.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    int cLen = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    QByteArray pt;
    pt.resize(cLen);
    unsigned long long plen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen, nullptr,
            c, static_cast<unsigned long long>(cLen),
            reinterpret_cast<const unsigned char*>(headerBytes.constData()),
            static_cast<unsigned long long>(headerBytes.size()),
            nonce,
            reinterpret_cast<const unsigned char*>(msgKey.constData())) != 0) {
        return {};
    }

    pt.resize(static_cast<int>(plen));

    // Store the message key before zeroing (deep copy for same reason as encrypt)
    m_lastMessageKey = QByteArray(msgKey.constData(), msgKey.size());
    sodium_memzero(msgKey.data(), msgKey.size());
    return pt;
}

// ---------------------------
// Serialization
// ---------------------------

QByteArray RatchetSession::serialize() const {
    QByteArray buf;
    QDataStream ds(&buf, QIODevice::WriteOnly);
    ds.setVersion(QDataStream::Qt_5_15);

    ds << quint8(2); // v2: adds hybrid PQ fields
    ds << m_rootKey << m_sendChainKey << m_recvChainKey;
    ds << m_dhPub << m_dhPriv << m_remoteDhPub;
    ds << m_sendMsgNum << m_recvMsgNum << m_prevChainLen;

    // Serialize skipped keys
    ds << static_cast<quint32>(m_skippedKeys.size());
    for (auto it = m_skippedKeys.constBegin(); it != m_skippedKeys.constEnd(); ++it) {
        ds << it.key().first;  // dhPub
        ds << it.key().second; // msgNum
        ds << it.value();      // messageKey
    }

    // v2: hybrid PQ state
    ds << m_hybrid;
    ds << m_kemPub << m_kemPriv << m_remoteKemPub << m_pendingKemCt;

    return buf;
}

RatchetSession RatchetSession::deserialize(const QByteArray& data) {
    RatchetSession s;
    QDataStream ds(data);
    ds.setVersion(QDataStream::Qt_5_15);

    quint8 version;
    ds >> version;
    if (version < 1 || version > 2) return s;

    ds >> s.m_rootKey >> s.m_sendChainKey >> s.m_recvChainKey;
    ds >> s.m_dhPub >> s.m_dhPriv >> s.m_remoteDhPub;
    ds >> s.m_sendMsgNum >> s.m_recvMsgNum >> s.m_prevChainLen;

    quint32 skippedCount;
    ds >> skippedCount;
    for (quint32 i = 0; i < skippedCount && i < kMaxSkipped; ++i) {
        QByteArray dhPub;
        quint32 msgNum;
        QByteArray key;
        ds >> dhPub >> msgNum >> key;
        s.m_skippedKeys.insert(qMakePair(dhPub, msgNum), key);
    }

    // v2: hybrid PQ state
    if (version >= 2) {
        ds >> s.m_hybrid;
        ds >> s.m_kemPub >> s.m_kemPriv >> s.m_remoteKemPub >> s.m_pendingKemCt;

        // Validate PQ key sizes — reject corrupted state
        if (s.m_hybrid) {
            if ((!s.m_kemPub.isEmpty() && s.m_kemPub.size() != kKemPubLen) ||
                (!s.m_kemPriv.isEmpty() && s.m_kemPriv.size() != 2400) ||
                (!s.m_remoteKemPub.isEmpty() && s.m_remoteKemPub.size() != kKemPubLen) ||
                (!s.m_pendingKemCt.isEmpty() && s.m_pendingKemCt.size() != kKemCtLen)) {
                return RatchetSession{};  // corrupted — return invalid
            }
        }
    }

    return s;
}
