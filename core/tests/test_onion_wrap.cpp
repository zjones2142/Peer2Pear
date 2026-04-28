// test_onion_wrap.cpp — unit tests for OnionWrap.
//
// OnionWrap is the sender side of multi-hop relay routing.  Each call
// produces a single onion layer for one hop; nested calls build the
// full multi-hop envelope.  The receiver side lives in the Go relay
// (relay-go/onion.go HandleForwardOnion) and a handful of Go tests
// cover peel + SSRF rejection there.
//
// This binary pins the wire format, the crypto (NaCl Box with known
// sender + relay keys), and the layering invariants — so a later
// tweak to OnionWrap won't silently diverge from the Go peeler.
//
// Scope: unit tests, no live network.  A full two-relay integration
// test would need loopback forwarding enabled (currently the SSRF
// guard refuses 127.0.0.1), which belongs in the Go suite.

#include "types.hpp"
#include "OnionWrap.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstring>
#include <string>
#include <vector>


namespace {

constexpr int kVersionByte  = 0x01;
constexpr int kEphPubOffset = 1;
constexpr int kNonceOffset  = 1 + 32;
constexpr int kCtOffset     = 1 + 32 + 24;

// Generate a fresh X25519 keypair (Box keys).  crypto_box_keypair
// is the NaCl wrapper libsodium exposes; its output is wire-
// compatible with golang.org/x/crypto/nacl/box which the Go peeler
// uses.
struct BoxKeys {
    Bytes pub;   // 32 bytes
    Bytes priv;  // 32 bytes
};
BoxKeys makeBoxKeys() {
    BoxKeys k;
    k.pub.assign(crypto_box_PUBLICKEYBYTES, 0);
    k.priv.assign(crypto_box_SECRETKEYBYTES, 0);
    crypto_box_keypair(k.pub.data(), k.priv.data());
    return k;
}

// Unwrap one layer of the onion using `relayPriv`.  Mirrors the
// decrypt half of relay-go/onion.go HandleForwardOnion so we can
// validate OnionWrap's output from the client side without a live
// relay.  Returns (nextHopUrl, innerBlob) on success; empty strings
// on failure.
struct Peeled {
    std::string nextHopUrl;
    Bytes       innerBlob;
    bool        ok = false;
};
Peeled peelLayer(const Bytes& onion, const Bytes& relayPriv) {
    Peeled out;
    if (onion.size() < static_cast<size_t>(kCtOffset) + crypto_box_MACBYTES)
        return out;
    if (onion[0] != kVersionByte) return out;

    const uint8_t* ephPub = onion.data() + kEphPubOffset;
    const uint8_t* nonce  = onion.data() + kNonceOffset;
    const uint8_t* ct     = onion.data() + kCtOffset;
    const size_t   ctLen  = onion.size() - kCtOffset;

    Bytes plain(ctLen - crypto_box_MACBYTES, 0);
    if (crypto_box_open_easy(plain.data(), ct, ctLen,
                              nonce, ephPub, relayPriv.data()) != 0)
        return out;

    if (plain.size() < 2) return out;
    const uint16_t urlLen = (uint16_t(plain[0]) << 8) | uint16_t(plain[1]);
    if (urlLen == 0 || 2 + urlLen > plain.size()) return out;

    out.nextHopUrl.assign(plain.begin() + 2, plain.begin() + 2 + urlLen);
    out.innerBlob.assign(plain.begin() + 2 + urlLen, plain.end());
    out.ok = true;
    return out;
}

}  // namespace

// ── 1. Wire format: version byte + fixed offsets ───────────────────────

TEST(OnionWrap, WireFormatBytes) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys relay = makeBoxKeys();
    const std::string url = "https://next-hop.example.com/v1/forward-onion";
    const Bytes inner(200, 0xCD);

    const Bytes onion = OnionWrap::wrap(relay.pub, url, inner);

    ASSERT_FALSE(onion.empty()) << "wrap returned empty bytes";
    EXPECT_EQ(onion[0], uint8_t(kVersionByte));

    // Minimum size: version + ephPub(32) + nonce(24) + Box tag(16)
    // + plaintext(>= urlLen(2) + url + inner(200)) = 1+32+24+16+2+45+200 = 320
    ASSERT_GT(onion.size(), size_t(kCtOffset + crypto_box_MACBYTES + 2));
}

// ── 2. Round-trip: peel reveals the next-hop URL + inner blob ──────────

TEST(OnionWrap, RoundTripYieldsUrlAndInner) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys relay = makeBoxKeys();
    const std::string url = "https://exit-relay.example.com/v1/send";
    Bytes inner(128);
    for (size_t i = 0; i < inner.size(); ++i)
        inner[i] = uint8_t(i & 0xFF);

    const Bytes onion = OnionWrap::wrap(relay.pub, url, inner);
    ASSERT_FALSE(onion.empty());

    const Peeled p = peelLayer(onion, relay.priv);
    ASSERT_TRUE(p.ok)       << "peel failed (wrong key shape or wire layout)";
    EXPECT_EQ(p.nextHopUrl, url);
    EXPECT_EQ(p.innerBlob,  inner);
}

// ── 3. Layering: two-hop onion peels cleanly to the final hop ──────────

TEST(OnionWrap, TwoHopPeelsThroughBothRelays) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys hopA = makeBoxKeys();
    const BoxKeys hopB = makeBoxKeys();

    const std::string urlAtoB = "https://hopB.example.com/v1/forward-onion";
    const std::string urlBtoExit = "https://exit.example.com/v1/send";
    const Bytes recipientEnvelope(256, 0xAB);  // sealed /v1/send payload

    // Build B's layer: innerMost = recipientEnvelope wrapped to hopB with
    // nextHop = exit.  A hop peeling with hopB.priv should reveal
    // (urlBtoExit, recipientEnvelope).
    const Bytes innerLayer = OnionWrap::wrap(hopB.pub, urlBtoExit, recipientEnvelope);
    ASSERT_FALSE(innerLayer.empty());

    // Build A's layer: wraps innerLayer to hopA with nextHop = hopB.
    const Bytes outer = OnionWrap::wrap(hopA.pub, urlAtoB, innerLayer);
    ASSERT_FALSE(outer.empty());

    // A peels first.
    const Peeled pA = peelLayer(outer, hopA.priv);
    ASSERT_TRUE(pA.ok);
    EXPECT_EQ(pA.nextHopUrl, urlAtoB);
    EXPECT_EQ(pA.innerBlob,  innerLayer);

    // B then peels the inner.
    const Peeled pB = peelLayer(pA.innerBlob, hopB.priv);
    ASSERT_TRUE(pB.ok);
    EXPECT_EQ(pB.nextHopUrl, urlBtoExit);
    EXPECT_EQ(pB.innerBlob,  recipientEnvelope);
}

// ── 4. Tampered ciphertext breaks the AEAD tag ────────────────────────

TEST(OnionWrap, FlippedCiphertextByteBreaksDecrypt) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys relay = makeBoxKeys();
    Bytes onion = OnionWrap::wrap(relay.pub,
                                    "https://r.example.com/v1/send",
                                    Bytes(64, 0x11));
    ASSERT_FALSE(onion.empty());
    // Flip a byte inside the Box ciphertext (past header).
    ASSERT_GT(onion.size(), size_t(kCtOffset + 4));
    onion[kCtOffset + 4] ^= 0x80;

    const Peeled p = peelLayer(onion, relay.priv);
    EXPECT_FALSE(p.ok)
        << "peel succeeded on tampered ciphertext (regression)";
}

// ── 5. Wrong key refuses to peel ───────────────────────────────────────

TEST(OnionWrap, WrongPrivKeyRefusesPeel) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys real  = makeBoxKeys();
    const BoxKeys wrong = makeBoxKeys();
    const Bytes onion = OnionWrap::wrap(real.pub,
                                          "https://r.example.com/v1/send",
                                          Bytes(64, 0x22));
    ASSERT_FALSE(onion.empty());

    const Peeled p = peelLayer(onion, wrong.priv);
    EXPECT_FALSE(p.ok);
}

// ── 6. Bad inputs return empty from wrap ───────────────────────────────

TEST(OnionWrap, RejectsBadInputs) {
    ASSERT_GE(sodium_init(), 0);

    const BoxKeys relay = makeBoxKeys();
    const Bytes inner(32, 0x55);

    // Wrong-size pubkey.
    EXPECT_TRUE(OnionWrap::wrap(Bytes{}, "u", inner).empty());
    EXPECT_TRUE(OnionWrap::wrap(Bytes(16, 0), "u", inner).empty());

    // Empty URL or empty inner.
    EXPECT_TRUE(OnionWrap::wrap(relay.pub, std::string{}, inner).empty());
    EXPECT_TRUE(OnionWrap::wrap(relay.pub, "u", Bytes{}).empty());
}
