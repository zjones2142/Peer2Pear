// test_ratchet_session.cpp — tests for RatchetSession (Double Ratchet).
//
// The Double Ratchet drives every in-session message after the Noise
// handshake.  Getting it right is load-bearing: a subtle bug shows up as
// "message 37 in a long conversation decrypts as garbage" rather than as
// an obvious failure, so the goal here is to lock in the *properties* that
// would catch such drift:
//
//   - Basic round-trip (classical + hybrid PQ).
//   - Bidirectional exchange with a DH-ratchet step on reply (the dhPub
//     in Alice's second send must differ from her first, proving the
//     ratchet rotated after she received Bob's reply).
//   - Out-of-order delivery: a message stream reordered by the network
//     still decrypts, because skipped message keys are cached.
//   - Tamper rejection, replay rejection, mismatched root rejection.
//   - State serialization survives a DB round-trip.
//   - `lastMessageKey()` changes every encrypt — the symmetric chain
//     actually advances instead of producing a static per-session key.
//
// Test keypairs come from libsodium / CryptoEngine directly; the ratchet
// doesn't care who produced them.  rootKey is a random 32-byte buffer
// stand-in for the chaining key that Noise IK would supply in production.

#include "RatchetSession.hpp"
#include "CryptoEngine.hpp"

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

struct Party {
    Bytes dhPub;
    Bytes dhPriv;
};

Party makeParty() {
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    return {pub, priv};
}

Bytes randomRootKey() {
    Bytes k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

Bytes bytesOf(const char* s) {
    const size_t n = std::strlen(s);
    return Bytes(reinterpret_cast<const uint8_t*>(s),
                 reinterpret_cast<const uint8_t*>(s) + n);
}

// Build a matched pair of sessions: `initiator` is the one who sends first.
// Mirrors what SessionManager would do after a Noise IK handshake completes.
struct Pair {
    RatchetSession initiator;
    RatchetSession responder;
};
Pair makePair(bool hybrid = false) {
    const Party alice = makeParty();
    const Party bob   = makeParty();
    const Bytes root  = randomRootKey();
    return {
        RatchetSession::initAsInitiator(root, bob.dhPub, alice.dhPub, alice.dhPriv, hybrid),
        RatchetSession::initAsResponder(root, bob.dhPub, bob.dhPriv, alice.dhPub, hybrid),
    };
}

class Bootstrap : public ::testing::Environment {
public:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};
::testing::Environment* const kBootstrap =
    ::testing::AddGlobalTestEnvironment(new Bootstrap);

}  // namespace

// ── 1. Classical round-trip (single message) ──────────────────────────────

TEST(RatchetSession, ClassicalRoundTrip) {
    auto p = makePair();
    ASSERT_TRUE(p.initiator.isValid());
    ASSERT_TRUE(p.responder.isValid());

    const Bytes pt = bytesOf("hello ratchet");
    const Bytes wire = p.initiator.encrypt(pt);
    ASSERT_FALSE(wire.empty());

    const Bytes rt = p.responder.decrypt(wire);
    EXPECT_EQ(rt, pt);
}

// ── 2. Hybrid (PQ) round-trip ─────────────────────────────────────────────

TEST(RatchetSession, HybridRoundTrip) {
    auto p = makePair(/*hybrid=*/true);
    ASSERT_TRUE(p.initiator.isValid());
    ASSERT_TRUE(p.responder.isValid());

    const Bytes pt = bytesOf("hybrid ratchet payload");
    const Bytes wire = p.initiator.encrypt(pt);
    ASSERT_FALSE(wire.empty());

    const Bytes rt = p.responder.decrypt(wire);
    EXPECT_EQ(rt, pt);
}

// ── 3. Bidirectional exchange across a DH-ratchet step ────────────────────
// Alice→Bob, Bob→Alice, Alice→Bob.  After Bob's reply, Alice's next
// ciphertext must carry a *new* DH ratchet public key in its header —
// that's the visible signature of the ratchet having stepped.

TEST(RatchetSession, BidirectionalExchangeStepsDhRatchet) {
    auto p = makePair();

    const Bytes a1 = p.initiator.encrypt(bytesOf("A -> B #1"));
    ASSERT_FALSE(a1.empty());
    EXPECT_EQ(p.responder.decrypt(a1), bytesOf("A -> B #1"));

    const Bytes b1 = p.responder.encrypt(bytesOf("B -> A #1"));
    ASSERT_FALSE(b1.empty());
    EXPECT_EQ(p.initiator.decrypt(b1), bytesOf("B -> A #1"));

    const Bytes a2 = p.initiator.encrypt(bytesOf("A -> B #2"));
    ASSERT_FALSE(a2.empty());
    EXPECT_EQ(p.responder.decrypt(a2), bytesOf("A -> B #2"));

    // Header layout starts with 32-byte dhPub; a fresh DH ratchet step
    // means a2's dhPub must differ from a1's dhPub.
    ASSERT_GE(a1.size(), 32u);
    ASSERT_GE(a2.size(), 32u);
    const Bytes dh1(a1.begin(), a1.begin() + 32);
    const Bytes dh2(a2.begin(), a2.begin() + 32);
    EXPECT_NE(dh1, dh2) << "Alice's second send should advertise a new DH pub after Bob's reply";
}

// ── 4. Out-of-order delivery uses the skipped-key cache ───────────────────
// Alice pipelines m1, m2, m3 without waiting for a reply.  Bob receives
// them in order m3 → m1 → m2.  All must decrypt, proving the skipped-key
// cache works.

TEST(RatchetSession, OutOfOrderDeliveryDecrypts) {
    auto p = makePair();

    const Bytes m1 = p.initiator.encrypt(bytesOf("one"));
    const Bytes m2 = p.initiator.encrypt(bytesOf("two"));
    const Bytes m3 = p.initiator.encrypt(bytesOf("three"));

    // Arrives m3 first (Bob skips+caches keys for m1, m2).
    EXPECT_EQ(p.responder.decrypt(m3), bytesOf("three"));
    // Then m1 — pulled from skipped-key cache.
    EXPECT_EQ(p.responder.decrypt(m1), bytesOf("one"));
    // Then m2.
    EXPECT_EQ(p.responder.decrypt(m2), bytesOf("two"));
}

// ── 5. Tampered ciphertext is rejected (MAC catches it) ───────────────────

TEST(RatchetSession, TamperedCiphertextRejected) {
    auto p = makePair();

    Bytes wire = p.initiator.encrypt(bytesOf("integrity check"));
    ASSERT_FALSE(wire.empty());

    // The header is 40 bytes for classical (dhPub[32] + prevChainLen[4] + msgNum[4]).
    // Flip a bit in the ciphertext body, past the header.
    const size_t target = 40 + 4;
    ASSERT_LT(target, wire.size());
    wire[target] ^= 0x01;

    const Bytes rt = p.responder.decrypt(wire);
    EXPECT_TRUE(rt.empty()) << "tampered ratchet ciphertext must not decrypt";
}

// ── 6. Replay of the same ciphertext must not decrypt twice ───────────────
// Once a message key has been consumed (or skipped-and-used), a second
// attempt to decrypt the identical bytes should return empty.  This is
// the ratchet-layer side of replay defense (the receiver app still adds
// an envelopeId dedup layer on top).

TEST(RatchetSession, ReplayReturnsEmpty) {
    auto p = makePair();

    const Bytes wire = p.initiator.encrypt(bytesOf("once"));
    ASSERT_FALSE(wire.empty());

    EXPECT_EQ(p.responder.decrypt(wire), bytesOf("once"));
    EXPECT_TRUE(p.responder.decrypt(wire).empty())
        << "the same ciphertext should not decrypt a second time";
}

// ── 7. Mismatched root key cannot decrypt ─────────────────────────────────
// If the two sides somehow ended up with different root keys (e.g. a
// mangled Noise chaining key), every chain diverges and the first message
// must fail closed rather than silently produce garbage.

TEST(RatchetSession, MismatchedRootKeyCannotDecrypt) {
    const Party alice = makeParty();
    const Party bob   = makeParty();

    RatchetSession aliceR = RatchetSession::initAsInitiator(
        randomRootKey(), bob.dhPub, alice.dhPub, alice.dhPriv);
    RatchetSession bobR   = RatchetSession::initAsResponder(
        randomRootKey() /* different! */, bob.dhPub, bob.dhPriv, alice.dhPub);

    ASSERT_TRUE(aliceR.isValid());
    ASSERT_TRUE(bobR.isValid());

    const Bytes wire = aliceR.encrypt(bytesOf("should not decode"));
    ASSERT_FALSE(wire.empty());
    EXPECT_TRUE(bobR.decrypt(wire).empty());
}

// ── 8. Serialize → deserialize round-trips a live session ─────────────────
// The receiver side is the more interesting one to persist (the app needs
// it across restarts to process incoming messages).  Freeze Bob, rehydrate
// him, confirm he can still decrypt Alice's next message.

TEST(RatchetSession, SerializeDeserializePreservesState) {
    auto p = makePair();

    // Drive the ratchet a little so serialized state has non-trivial contents.
    EXPECT_EQ(p.responder.decrypt(p.initiator.encrypt(bytesOf("warm up 1"))),
              bytesOf("warm up 1"));
    const Bytes bobReply = p.responder.encrypt(bytesOf("warm up 2"));
    EXPECT_EQ(p.initiator.decrypt(bobReply), bytesOf("warm up 2"));

    const Bytes frozen = p.responder.serialize();
    ASSERT_FALSE(frozen.empty());

    RatchetSession bobRehydrated = RatchetSession::deserialize(frozen);
    ASSERT_TRUE(bobRehydrated.isValid());

    // Alice sends; rehydrated Bob must still decrypt.
    const Bytes next = p.initiator.encrypt(bytesOf("after restart"));
    EXPECT_EQ(bobRehydrated.decrypt(next), bytesOf("after restart"));
}

// ── 9. lastMessageKey() advances per encrypt ──────────────────────────────
// The symmetric chain derives a fresh message key each step.  If two
// successive encrypts produce the same lastMessageKey, the chain isn't
// actually advancing — a silent forward-secrecy failure.

TEST(RatchetSession, LastMessageKeyDiffersPerEncrypt) {
    auto p = makePair();

    (void)p.initiator.encrypt(bytesOf("a"));
    const Bytes k1 = p.initiator.lastMessageKey();
    (void)p.initiator.encrypt(bytesOf("b"));
    const Bytes k2 = p.initiator.lastMessageKey();

    ASSERT_EQ(k1.size(), 32u);
    ASSERT_EQ(k2.size(), 32u);
    EXPECT_NE(k1, k2);
}

// ── 10. Malformed / short input rejected, not crashed on ──────────────────
// A hostile peer could hand us a ciphertext shorter than the header.
// decrypt() must return empty, not read past the buffer.

TEST(RatchetSession, MalformedInputRejected) {
    auto p = makePair();

    for (size_t n : {size_t(0), size_t(1), size_t(20), size_t(39)}) {
        EXPECT_TRUE(p.responder.decrypt(Bytes(n, 0x00)).empty()) << "len=" << n;
    }
}

// ── 11. All-zeros remote DH pub is rejected ───────────────────────────────
// A peer (or malicious relay) could substitute an all-zeros remote DH
// pubkey and force the scalarmult to land on a known shared secret.
// initAsInitiator / initAsResponder + dhRatchetStep all check for this.

TEST(RatchetSession, InitAsInitiatorRejectsAllZeroRemotePub) {
    const Party alice = makeParty();
    const Bytes zeros(32, 0x00);
    const Bytes root  = randomRootKey();

    RatchetSession s = RatchetSession::initAsInitiator(
        root, zeros, alice.dhPub, alice.dhPriv);
    EXPECT_FALSE(s.isValid())
        << "initiator must refuse an all-zeros remote DH public key";
}

TEST(RatchetSession, InitAsResponderRejectsAllZeroRemotePub) {
    const Party bob = makeParty();
    const Bytes zeros(32, 0x00);
    const Bytes root = randomRootKey();

    RatchetSession s = RatchetSession::initAsResponder(
        root, bob.dhPub, bob.dhPriv, zeros);
    EXPECT_FALSE(s.isValid())
        << "responder must refuse an all-zeros remote DH public key";
}

TEST(RatchetSession, DhRatchetStepRejectsAllZeroRemotePub) {
    auto p = makePair();

    // Drive one round-trip so the responder's first DH ratchet step
    // would fire on the NEXT received message from the initiator — we
    // synthesize that message with a zeroed dhPub in the header.
    const Bytes wire = p.initiator.encrypt(bytesOf("hello"));
    ASSERT_EQ(p.responder.decrypt(wire), bytesOf("hello"));

    // Tamper: set the 32-byte DH pub in the header to all zeros.  The
    // header layout is dhPub(32) || prevChainLen(4) || msgNum(4) for a
    // classical envelope.  We encrypt a fresh message, then zero its
    // dhPub slot before handing to the peer.
    Bytes tampered = p.initiator.encrypt(bytesOf("second"));
    ASSERT_GE(tampered.size(), 32u);
    std::fill(tampered.begin(), tampered.begin() + 32, uint8_t(0x00));

    const Bytes rt = p.responder.decrypt(tampered);
    EXPECT_TRUE(rt.empty())
        << "ratchet must refuse to step into an all-zeros remote DH pub";
}

// ── 12. Max-skip-key exhaustion bounded by kMaxSkipped ───────────────────
// A hostile peer could claim a message counter far beyond the current
// chain head to force the receiver to derive thousands of keys in one
// call.  skipMessageKeys caps the gap at kMaxSkipped (1000) and returns
// a failure signal — decrypt then returns empty rather than looping.

TEST(RatchetSession, MaxSkipKeysRefusesOverflow) {
    auto p = makePair();

    // Send one legitimate message to establish the receiver's chain.
    const Bytes m1 = p.initiator.encrypt(bytesOf("m1"));
    ASSERT_EQ(p.responder.decrypt(m1), bytesOf("m1"));

    // Fabricate a message claiming a wildly-high counter (kMaxSkipped+500).
    // Encrypt a real message, then overwrite its msgNum field.  The dhPub
    // header is identical to m1's (same chain), so the skip path is taken.
    Bytes bogus = p.initiator.encrypt(bytesOf("bogus"));
    ASSERT_GE(bogus.size(), 40u);
    const uint32_t huge = static_cast<uint32_t>(RatchetSession::kMaxSkipped) + 500;
    bogus[36] = uint8_t((huge >> 24) & 0xFF);
    bogus[37] = uint8_t((huge >> 16) & 0xFF);
    bogus[38] = uint8_t((huge >>  8) & 0xFF);
    bogus[39] = uint8_t( huge        & 0xFF);

    EXPECT_TRUE(p.responder.decrypt(bogus).empty())
        << "attempting to skip > kMaxSkipped keys must fail closed";
}

// ── Phase 1: stable per-session id ──────────────────────────────────────
//
// sessionId() is the foundation for the Causally-Linked Pairwise group
// protocol's session_id namespacing.  Both sides must compute identical
// bytes (so chain_state lookups match across the peer pair) and the
// value must be stable for the life of the session — DH ratchet steps
// MUST NOT change it.

TEST(RatchetSession, SessionIdMatchesBetweenInitiatorAndResponder) {
    auto p = makePair();
    const Bytes a = p.initiator.sessionId();
    const Bytes b = p.responder.sessionId();
    ASSERT_EQ(a.size(), 8u) << "sessionId is 8 bytes";
    EXPECT_EQ(a, b)
        << "both sides of the same DR session must agree on sessionId";
}

TEST(RatchetSession, SessionIdIsStableAcrossDhRatchets) {
    auto p = makePair();
    const Bytes initial = p.initiator.sessionId();

    // Drive a few message round-trips so each side performs at least
    // one DH ratchet step.  m_rootKey evolves; m_initialRootKey must not.
    for (int i = 0; i < 3; ++i) {
        Bytes ct = p.initiator.encrypt(bytesOf("ping"));
        ASSERT_FALSE(p.responder.decrypt(ct).empty());
        Bytes ct2 = p.responder.encrypt(bytesOf("pong"));
        ASSERT_FALSE(p.initiator.decrypt(ct2).empty());
    }

    EXPECT_EQ(p.initiator.sessionId(), initial)
        << "sessionId must not move when m_rootKey ratchets forward";
    EXPECT_EQ(p.responder.sessionId(), initial)
        << "responder's sessionId must also be stable across DH steps";
}

TEST(RatchetSession, SessionIdDiffersAcrossFreshHandshakes) {
    auto p1 = makePair();
    auto p2 = makePair();   // independent handshake, fresh root key
    EXPECT_NE(p1.initiator.sessionId(), p2.initiator.sessionId())
        << "two distinct sessions MUST yield distinct sessionIds — "
        << "this is what receivers use to detect a session reset";
}

TEST(RatchetSession, SessionIdEmptyOnDefaultConstructed) {
    RatchetSession s;
    EXPECT_TRUE(s.sessionId().empty());
}

TEST(RatchetSession, SessionIdSurvivesSerializeRoundTrip) {
    // The Causally-Linked Pairwise group protocol uses sessionId to
    // namespace per-(sender, group, recipient) counters on the wire.
    // If a process restart clobbered sessionId, every restart would
    // look like a session reset — group_send_state would miss, lost-
    // message events would fire spuriously, and counters would be
    // recomputed from scratch.  serialize/deserialize MUST carry the
    // initial root key so sessionId() is stable across persistence.

    auto p = makePair();
    const Bytes original = p.initiator.sessionId();
    ASSERT_EQ(original.size(), 8u);

    // Drive a few message round-trips so m_rootKey ratchets forward
    // (and would diverge from m_initialRootKey).  Then serialize the
    // state, deserialize into a fresh instance, and verify the
    // sessionId is preserved.
    for (int i = 0; i < 3; ++i) {
        Bytes ct = p.initiator.encrypt(bytesOf("ping"));
        ASSERT_FALSE(p.responder.decrypt(ct).empty());
    }

    Bytes blob = p.initiator.serialize();
    ASSERT_FALSE(blob.empty());

    RatchetSession reloaded = RatchetSession::deserialize(blob);
    ASSERT_TRUE(reloaded.isValid());
    EXPECT_EQ(reloaded.sessionId(), original)
        << "serialize → deserialize MUST preserve sessionId so a "
        << "process restart doesn't look like a session reset";
}

TEST(RatchetSession, SessionIdEmptyOnLegacyV2DeserializedSession) {
    // Pre-Phase-1 sessions persisted under format v=2 carried no
    // m_initialRootKey.  Loading one through the current
    // deserialize must yield an empty sessionId — the v2 group
    // sender path checks for this and degrades gracefully.
    //
    // Construct a v=2 blob by hand: same wire shape as serialize
    // produces today, but with the leading version byte forced to 2
    // and the trailing m_initialRootKey field omitted.

    auto p = makePair();
    Bytes v3blob = p.initiator.serialize();
    ASSERT_FALSE(v3blob.empty());

    // Stamp the version byte back to 2 and truncate the trailing
    // initialRootKey field.  The v=2 reader stops before that field
    // anyway, so trimming the bytes mirrors what an old serializer
    // would have produced.  Here we just patch the version — the
    // deserializer is robust to trailing bytes via BinaryReader::ok.
    Bytes v2blob = v3blob;
    v2blob[0] = 2;

    RatchetSession reloaded = RatchetSession::deserialize(v2blob);
    ASSERT_TRUE(reloaded.isValid());
    EXPECT_TRUE(reloaded.sessionId().empty())
        << "pre-v3 sessions on disk MUST yield empty sessionId so "
        << "the v2 group sender's missing-deps fallback kicks in "
        << "rather than emitting wire-format pv=2 with junk session";
}
