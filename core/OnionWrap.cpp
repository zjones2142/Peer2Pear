#include "OnionWrap.hpp"

#include <sodium.h>
#include <cstring>

static constexpr uint8_t kOnionVersion = 0x01;

// Big-endian 2-byte write helper — avoids pulling in QtEndian for one use.
static inline void write_u16_be(uint8_t* dst, uint16_t v)
{
    dst[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>( v       & 0xFF);
}

std::vector<uint8_t> OnionWrap::wrap(const std::vector<uint8_t>& relayX25519Pub,
                                      const std::string&          nextHopUrl,
                                      const std::vector<uint8_t>& innerBlob)
{
    if (relayX25519Pub.size() != 32) return {};
    if (nextHopUrl.empty() || nextHopUrl.size() > 0xFFFF) return {};
    if (innerBlob.empty()) return {};

    // 1. Generate ephemeral X25519 keypair for this layer.
    unsigned char ephPub[crypto_box_PUBLICKEYBYTES];
    unsigned char ephPriv[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(ephPub, ephPriv);

    // 2. Build plaintext: [nextHopUrlLen(2 BE)][nextHopUrl][innerBlob]
    std::vector<uint8_t> plaintext;
    plaintext.reserve(2 + nextHopUrl.size() + innerBlob.size());
    plaintext.resize(2);
    write_u16_be(plaintext.data(), static_cast<uint16_t>(nextHopUrl.size()));
    plaintext.insert(plaintext.end(), nextHopUrl.begin(), nextHopUrl.end());
    plaintext.insert(plaintext.end(), innerBlob.begin(), innerBlob.end());

    // 3. Random nonce.
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // 4. crypto_box_easy — authenticated public-key encryption.
    std::vector<uint8_t> ct(plaintext.size() + crypto_box_MACBYTES);
    const int rc = crypto_box_easy(
        ct.data(),
        plaintext.data(),
        static_cast<unsigned long long>(plaintext.size()),
        nonce,
        relayX25519Pub.data(),
        ephPriv);
    // Wipe ephemeral priv before any return path.
    sodium_memzero(ephPriv, sizeof(ephPriv));
    if (rc != 0) return {};

    // 5. Assemble: version(1) || ephPub(32) || nonce(24) || ct
    std::vector<uint8_t> out;
    out.reserve(1 + 32 + sizeof(nonce) + ct.size());
    out.push_back(kOnionVersion);
    out.insert(out.end(), ephPub, ephPub + 32);
    out.insert(out.end(), nonce, nonce + sizeof(nonce));
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}
