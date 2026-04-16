#include "OnionWrap.hpp"

#include <QtEndian>
#include <sodium.h>
#include <cstring>

static constexpr quint8 kOnionVersion = 0x01;

QByteArray OnionWrap::wrap(const QByteArray& relayX25519Pub,
                            const QString&    nextHopUrl,
                            const QByteArray& innerBlob)
{
    if (relayX25519Pub.size() != 32) return {};
    const QByteArray urlUtf8 = nextHopUrl.toUtf8();
    if (urlUtf8.size() == 0 || urlUtf8.size() > 0xFFFF) return {};
    if (innerBlob.isEmpty()) return {};

    // 1. Generate ephemeral X25519 keypair for this layer.
    unsigned char ephPub[crypto_box_PUBLICKEYBYTES];
    unsigned char ephPriv[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(ephPub, ephPriv);

    // 2. Build plaintext: [nextHopUrlLen(2 BE)][nextHopUrl][innerBlob]
    QByteArray plaintext;
    plaintext.reserve(2 + urlUtf8.size() + innerBlob.size());
    quint16 lenBE = qToBigEndian(static_cast<quint16>(urlUtf8.size()));
    plaintext.append(reinterpret_cast<const char*>(&lenBE), 2);
    plaintext.append(urlUtf8);
    plaintext.append(innerBlob);

    // 3. Random nonce.
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 4. crypto_box_easy — authenticated public-key encryption.
    QByteArray ct;
    ct.resize(plaintext.size() + crypto_box_MACBYTES);
    const int rc = crypto_box_easy(
        reinterpret_cast<unsigned char*>(ct.data()),
        reinterpret_cast<const unsigned char*>(plaintext.constData()),
        static_cast<unsigned long long>(plaintext.size()),
        nonce,
        reinterpret_cast<const unsigned char*>(relayX25519Pub.constData()),
        ephPriv);
    // Wipe ephemeral priv before any return path.
    sodium_memzero(ephPriv, sizeof(ephPriv));
    if (rc != 0) return {};

    // 5. Assemble: version(1) || ephPub(32) || nonce(24) || ct
    QByteArray out;
    out.reserve(1 + 32 + int(sizeof(nonce)) + ct.size());
    out.append(static_cast<char>(kOnionVersion));
    out.append(reinterpret_cast<const char*>(ephPub), 32);
    out.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    out.append(ct);
    return out;
}
