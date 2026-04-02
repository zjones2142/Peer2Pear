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

QByteArray RatchetHeader::serialize() const {
    QByteArray out;
    out.reserve(kSerializedSize);
    out.append(dhPub);
    // Append prevChainLen and messageNum as big-endian 4 bytes each
    quint32 pcl = qToBigEndian(prevChainLen);
    quint32 mn  = qToBigEndian(messageNum);
    out.append(reinterpret_cast<const char*>(&pcl), 4);
    out.append(reinterpret_cast<const char*>(&mn), 4);
    return out;
}

RatchetHeader RatchetHeader::deserialize(const QByteArray& data, int& bytesRead) {
    RatchetHeader h;
    bytesRead = 0;
    if (data.size() < kSerializedSize) return h;

    h.dhPub = data.left(32);
    quint32 pcl, mn;
    memcpy(&pcl, data.constData() + 32, 4);
    memcpy(&mn,  data.constData() + 36, 4);
    h.prevChainLen = qFromBigEndian(pcl);
    h.messageNum   = qFromBigEndian(mn);
    bytesRead = kSerializedSize;
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
                                                const QByteArray& remoteDhPub) {
    RatchetSession s;
    s.m_remoteDhPub = remoteDhPub;

    // Generate our first DH ratchet keypair
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    s.m_dhPub  = pub;
    s.m_dhPriv = priv;

    // Perform initial DH and derive sending chain
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(priv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0) {
        return {};
    }

    QByteArray dhOutput(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [newRoot, sendChain] = kdfRootKey(rootKey, dhOutput);
    s.m_rootKey      = newRoot;
    s.m_sendChainKey = sendChain;
    // Receiving chain is empty until we get peer's first DH ratchet message

    qDebug() << "[Ratchet] initAsInitiator: inputRootKey=" << rootKey.left(4).toHex()
             << "dhPub=" << pub.left(4).toHex()
             << "remoteDhPub=" << remoteDhPub.left(4).toHex()
             << "derivedRootKey=" << newRoot.left(4).toHex();
    return s;
}

RatchetSession RatchetSession::initAsResponder(const QByteArray& rootKey,
                                                const QByteArray& localDhPub,
                                                const QByteArray& localDhPriv) {
    RatchetSession s;
    s.m_rootKey = rootKey;
    s.m_dhPub   = localDhPub;
    s.m_dhPriv  = localDhPriv;
    // Sending chain is empty until we perform our first DH ratchet
    // Receiving chain will be established when the first message arrives
    qDebug() << "[Ratchet] initAsResponder: rootKey=" << rootKey.left(4).toHex()
             << "dhPub=" << localDhPub.left(4).toHex();
    return s;
}

// ---------------------------
// DH ratchet step
// ---------------------------

void RatchetSession::dhRatchetStep(const QByteArray& remoteDhPub) {
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

    auto [rk1, recvChain] = kdfRootKey(m_rootKey, dhOutput);
    m_rootKey      = rk1;
    m_recvChainKey = recvChain;

    // Generate new DH keypair for sending
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    m_dhPub  = pub;
    m_dhPriv = priv;

    // DH with new private + remote public -> sending chain
    if (crypto_scalarmult(shared,
                          reinterpret_cast<const unsigned char*>(priv.constData()),
                          reinterpret_cast<const unsigned char*>(remoteDhPub.constData())) != 0)
        return;
    dhOutput = QByteArray(reinterpret_cast<const char*>(shared), sizeof(shared));
    sodium_memzero(shared, sizeof(shared));

    auto [rk2, sendChain] = kdfRootKey(m_rootKey, dhOutput);
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

    auto [newChain, msgKey] = kdfChainKey(m_sendChainKey);
    m_sendChainKey = newChain;
    m_lastMessageKey = msgKey;

    RatchetHeader header;
    header.dhPub        = m_dhPub;
    header.prevChainLen = m_prevChainLen;
    header.messageNum   = m_sendMsgNum++;

    qDebug() << "[Ratchet] encrypt: msgNum=" << header.messageNum
             << "dhPub=" << m_dhPub.left(4).toHex()
             << "rootKey=" << m_rootKey.left(4).toHex();

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
    if (headerAndCiphertext.size() < RatchetHeader::kSerializedSize) {
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
    qDebug() << "[Ratchet] decrypt: msgNum=" << header.messageNum
             << "prevChain=" << header.prevChainLen
             << "dhPub=" << header.dhPub.left(4).toHex()
             << "remoteDhPub=" << m_remoteDhPub.left(4).toHex()
             << "recvChainEmpty=" << m_recvChainKey.isEmpty()
             << "rootKey=" << m_rootKey.left(4).toHex();

    // Try skipped keys first
    QByteArray skippedResult = trySkippedKeys(header, ciphertext);
    if (!skippedResult.isEmpty()) return skippedResult;

    // If the DH key changed, perform a DH ratchet step
    if (header.dhPub != m_remoteDhPub) {
        qDebug() << "[Ratchet] DH key changed — performing ratchet step";
        // Skip any remaining messages in the current receiving chain
        if (!skipMessageKeys(m_remoteDhPub, header.prevChainLen))
            return {};
        dhRatchetStep(header.dhPub);
        qDebug() << "[Ratchet] after ratchet step: recvChainEmpty=" << m_recvChainKey.isEmpty()
                 << "rootKey=" << m_rootKey.left(4).toHex();
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

    ds << quint8(1); // version
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

    return buf;
}

RatchetSession RatchetSession::deserialize(const QByteArray& data) {
    RatchetSession s;
    QDataStream ds(data);
    ds.setVersion(QDataStream::Qt_5_15);

    quint8 version;
    ds >> version;
    if (version != 1) return s;

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

    return s;
}
