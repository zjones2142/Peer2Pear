// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — NoiseState Unit Tests
// ════════════════════════════════════════════════════════════════════════════
//
// Tests for:
//   - Noise IK handshake completion (initiator + responder)
//   - Transport key derivation
//   - Handshake hash channel binding
//   - Serialization/deserialization of mid-handshake state
//   - CipherState validation
//   - Ephemeral key exposure
//   - Static private key re-injection (C3 fix)
//
// Framework: Qt Test (QTest)
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <sodium.h>

#include "../NoiseState.hpp"
#include "../CryptoEngine.hpp"

class TestNoiseState : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();

    // ── CipherState ──────────────────────────────────────────────────────────
    void cipherStateDefaultIsInvalid();
    void cipherStateWith32ByteKeyIsValid();

    // ── Handshake Completion ─────────────────────────────────────────────────
    void fullHandshakeCompletes();
    void handshakeProducesValidTransportKeys();
    void handshakeHashIs32Bytes();
    void bothSidesAgreeOnTransportKeys();
    void handshakeHashMatchesBothSides();

    // ── Ephemeral Keys ───────────────────────────────────────────────────────
    void initiatorEphemeralKeysAvailableAfterMsg1();
    void responderEphemeralKeysAvailableAfterMsg2();

    // ── Remote Static Key ────────────────────────────────────────────────────
    void responderLearnsInitiatorStaticKey();

    // ── Serialization ────────────────────────────────────────────────────────
    void initiatorSerializeAfterMsg1();
    void deserializeInvalidDataReturnsIncomplete();

    // ── Role Tracking ────────────────────────────────────────────────────────
    void initiatorRoleIsCorrect();
    void responderRoleIsCorrect();

    // ── Post-msg1 Chaining Key ───────────────────────────────────────────────
    void chainingKeyAvailableAfterMsg1();
    void chainingKeyIs32Bytes();
};

void TestNoiseState::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize");
}

// ═══════════════════════════════════════════════════════════════════════════
// CipherState
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::cipherStateDefaultIsInvalid()
{
    CipherState cs;
    QVERIFY2(!cs.isValid(), "Default CipherState must be invalid (empty key)");
    QCOMPARE(cs.nonce, quint64(0));
}

void TestNoiseState::cipherStateWith32ByteKeyIsValid()
{
    CipherState cs;
    cs.key = QByteArray(32, '\xAA');
    QVERIFY2(cs.isValid(), "CipherState with 32-byte key must be valid");
}

// ═══════════════════════════════════════════════════════════════════════════
// Handshake Completion
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::fullHandshakeCompletes()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    // Initiator writes msg1
    QByteArray msg1 = initiator.writeMessage1();
    QVERIFY2(!msg1.isEmpty(), "msg1 must not be empty");

    // Responder reads msg1, writes msg2
    QByteArray payloadOut;
    QByteArray msg2 = responder.readMessage1AndWriteMessage2(msg1, payloadOut);
    QVERIFY2(!msg2.isEmpty(), "msg2 must not be empty");

    // Initiator reads msg2
    QByteArray payloadOut2;
    bool ok = initiator.readMessage2(msg2, payloadOut2);
    QVERIFY2(ok, "readMessage2 must succeed");
}

void TestNoiseState::handshakeProducesValidTransportKeys()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    QByteArray msg2 = responder.readMessage1AndWriteMessage2(msg1, po);
    QByteArray po2;
    initiator.readMessage2(msg2, po2);

    HandshakeResult iResult = initiator.finish();
    HandshakeResult rResult = responder.finish();

    QVERIFY2(iResult.sendCipher.isValid(), "Initiator send cipher must be valid");
    QVERIFY2(iResult.recvCipher.isValid(), "Initiator recv cipher must be valid");
    QVERIFY2(rResult.sendCipher.isValid(), "Responder send cipher must be valid");
    QVERIFY2(rResult.recvCipher.isValid(), "Responder recv cipher must be valid");
}

void TestNoiseState::handshakeHashIs32Bytes()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    QByteArray msg2 = responder.readMessage1AndWriteMessage2(msg1, po);
    QByteArray po2;
    initiator.readMessage2(msg2, po2);

    HandshakeResult iResult = initiator.finish();
    QCOMPARE(iResult.handshakeHash.size(), 32);
}

void TestNoiseState::bothSidesAgreeOnTransportKeys()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    QByteArray msg2 = responder.readMessage1AndWriteMessage2(msg1, po);
    QByteArray po2;
    initiator.readMessage2(msg2, po2);

    HandshakeResult iR = initiator.finish();
    HandshakeResult rR = responder.finish();

    // Initiator's send key = Responder's recv key
    QCOMPARE(iR.sendCipher.key, rR.recvCipher.key);
    // Initiator's recv key = Responder's send key
    QCOMPARE(iR.recvCipher.key, rR.sendCipher.key);
}

void TestNoiseState::handshakeHashMatchesBothSides()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    QByteArray msg2 = responder.readMessage1AndWriteMessage2(msg1, po);
    QByteArray po2;
    initiator.readMessage2(msg2, po2);

    HandshakeResult iR = initiator.finish();
    HandshakeResult rR = responder.finish();

    QCOMPARE(iR.handshakeHash, rR.handshakeHash);
}

// ═══════════════════════════════════════════════════════════════════════════
// Ephemeral Keys
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::initiatorEphemeralKeysAvailableAfterMsg1()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    initiator.writeMessage1();

    QCOMPARE(initiator.ephemeralPub().size(), 32);
    QCOMPARE(initiator.ephemeralPriv().size(), 32);
}

void TestNoiseState::responderEphemeralKeysAvailableAfterMsg2()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    responder.readMessage1AndWriteMessage2(msg1, po);

    QCOMPARE(responder.ephemeralPub().size(), 32);
    QCOMPARE(responder.ephemeralPriv().size(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// Remote Static Key
// ════════════════════��══════════════════════════════════════════════════════

void TestNoiseState::responderLearnsInitiatorStaticKey()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    NoiseState responder = NoiseState::createResponder(rPub, rPriv);

    QByteArray msg1 = initiator.writeMessage1();
    QByteArray po;
    responder.readMessage1AndWriteMessage2(msg1, po);

    QCOMPARE(responder.remoteStaticPub(), iPub);
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialization
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::initiatorSerializeAfterMsg1()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    initiator.writeMessage1();

    QByteArray blob = initiator.serialize();
    QVERIFY2(!blob.isEmpty(), "Serialized handshake state must not be empty");

    NoiseState restored = NoiseState::deserialize(blob);
    QCOMPARE(restored.role(), NoiseState::Initiator);
    QVERIFY2(!restored.isComplete(), "Restored initiator must not be complete yet");

    // Re-inject private key (C3 fix)
    restored.setStaticPrivateKey(iPriv);
    QCOMPARE(restored.ephemeralPub(), initiator.ephemeralPub());
}

void TestNoiseState::deserializeInvalidDataReturnsIncomplete()
{
    NoiseState s = NoiseState::deserialize("garbage");
    QVERIFY2(!s.isComplete(), "Deserializing garbage must not produce a complete state");
}

// ═══════════════════════════════════════════════════════════════════════════
// Role Tracking
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::initiatorRoleIsCorrect()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    QCOMPARE(initiator.role(), NoiseState::Initiator);
}

void TestNoiseState::responderRoleIsCorrect()
{
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState responder = NoiseState::createResponder(rPub, rPriv);
    QCOMPARE(responder.role(), NoiseState::Responder);
}

// ═══════════════════════════════════════════════════════════════════════════
// Post-msg1 Chaining Key
// ═══════════════════════════════════════════════════════════════════════════

void TestNoiseState::chainingKeyAvailableAfterMsg1()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    initiator.writeMessage1();

    QVERIFY2(!initiator.postMsg1ChainingKey().isEmpty(),
             "Chaining key must be available after writeMessage1()");
}

void TestNoiseState::chainingKeyIs32Bytes()
{
    auto [iPub, iPriv] = CryptoEngine::generateEphemeralX25519();
    auto [rPub, rPriv] = CryptoEngine::generateEphemeralX25519();

    NoiseState initiator = NoiseState::createInitiator(iPub, iPriv, rPub);
    initiator.writeMessage1();

    QCOMPARE(initiator.postMsg1ChainingKey().size(), 32);
}

QTEST_MAIN(TestNoiseState)
#include "tst_noisestate.moc"