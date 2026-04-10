// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — SealedEnvelope Unit Tests
// ════════════════════════════════════════════════════════════════════════════
//
// IMPORTANT: CryptoEngine persists identity to disk. Only ONE CryptoEngine
// instance can exist per test binary. A raw Ed25519/X25519 keypair is used
// as the "other party" to avoid the disk conflict.
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <QStandardPaths>
#include <QFile>
#include <sodium.h>

#include "../SealedEnvelope.hpp"
#include "../CryptoEngine.hpp"

class TestSealedEnvelope : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();

    // ── Seal / Unseal ────────────────────────────────────────────────────────
    void sealUnsealRoundTrip();
    void sealedOutputContainsEphemeralPub();
    void unsealRecoversCorrectSenderKey();
    void unsealRecoversCorrectPayload();

    // ── Failure Cases ─────��──────────────────────────────────────────────────
    void unsealWithWrongKeyFails();
    void unsealTamperedDataFails();
    void unsealTooShortDataFails();
    void unsealEmptyDataFails();

    // ── Multiple Envelopes ───────────────────────────────────────────────────
    void twoSealsProduceDifferentCiphertexts();

private:
    void deleteIdentityFile();

    // "Us" — the one CryptoEngine that owns the on-disk identity
    std::unique_ptr<CryptoEngine> m_engine;

    // "Peer" — raw keypair, no disk persistence needed
    QByteArray m_peerEdPub;   // 32
    QByteArray m_peerEdPriv;  // 64
    QByteArray m_peerCurvePub;  // 32
    QByteArray m_peerCurvePriv; // 32
};

void TestSealedEnvelope::deleteIdentityFile()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QFile::remove(base + "/keys/identity.json");
}

void TestSealedEnvelope::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize");

    // ── Set up "us" (CryptoEngine with disk identity) ────────────────────────
    deleteIdentityFile();
    m_engine = std::make_unique<CryptoEngine>();
    m_engine->setPassphrase("sealed-envelope-test");
    m_engine->ensureIdentity();

    // ── Set up "peer" (raw keypair, no CryptoEngine) ─────────────────────────
    unsigned char edPk[crypto_sign_PUBLICKEYBYTES];
    unsigned char edSk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(edPk, edSk);

    m_peerEdPub  = QByteArray(reinterpret_cast<const char*>(edPk), sizeof(edPk));
    m_peerEdPriv = QByteArray(reinterpret_cast<const char*>(edSk), sizeof(edSk));
    sodium_memzero(edSk, sizeof(edSk));

    // Derive X25519 keys from Ed25519 for sealing
    unsigned char curvePk[crypto_box_PUBLICKEYBYTES];
    unsigned char curveSk[crypto_box_SECRETKEYBYTES];
    crypto_sign_ed25519_pk_to_curve25519(curvePk,
                                         reinterpret_cast<const unsigned char*>(m_peerEdPub.constData()));
    crypto_sign_ed25519_sk_to_curve25519(curveSk,
                                         reinterpret_cast<const unsigned char*>(m_peerEdPriv.constData()));

    m_peerCurvePub  = QByteArray(reinterpret_cast<const char*>(curvePk), sizeof(curvePk));
    m_peerCurvePriv = QByteArray(reinterpret_cast<const char*>(curveSk), sizeof(curveSk));
    sodium_memzero(curveSk, sizeof(curveSk));
}

void TestSealedEnvelope::cleanupTestCase()
{
    m_engine.reset();
    deleteIdentityFile();
    CryptoEngine::secureZero(m_peerEdPriv);
    CryptoEngine::secureZero(m_peerCurvePriv);
}

// ═══════════════════════════════════════════════════════════════════════════
// Seal / Unseal
// ═══════════════════════════════════════════════════════════════════════════

void TestSealedEnvelope::sealUnsealRoundTrip()
{
    // "Us" seals TO the peer
    QByteArray payload = "Secret message inside envelope";

    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub,              // recipient's X25519 pub
        m_engine->identityPub(),     // sender's Ed25519 pub
        m_engine->identityPriv(),    // sender's Ed25519 priv
        payload);
    QVERIFY2(!sealed.isEmpty(), "Sealed envelope must not be empty");

    // Peer unseals with their X25519 private key
    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, sealed);
    QVERIFY2(result.valid, "Unseal must succeed with correct recipient key");
    QCOMPARE(result.innerPayload, payload);
    QCOMPARE(result.senderEdPub, m_engine->identityPub());
}

void TestSealedEnvelope::sealedOutputContainsEphemeralPub()
{
    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), "test");

    // Sealed output must be > 32 bytes (ephPub + sender pub + AEAD overhead)
    QVERIFY2(sealed.size() > 32, "Sealed output must be > 32 bytes");
}

void TestSealedEnvelope::unsealRecoversCorrectSenderKey()
{
    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), "key check");

    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, sealed);
    QVERIFY(result.valid);
    QCOMPARE(result.senderEdPub, m_engine->identityPub());
    QCOMPARE(result.senderEdPub.size(), 32);
}

void TestSealedEnvelope::unsealRecoversCorrectPayload()
{
    QByteArray payload = "The quick brown fox jumps over the lazy dog";
    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), payload);

    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, sealed);
    QVERIFY(result.valid);
    QCOMPARE(result.innerPayload, payload);
}

// ═══════════════════════════════════════════════════════════════════════════
// Failure Cases
// ═══════════════════════════════════════════════════════════════════════════

void TestSealedEnvelope::unsealWithWrongKeyFails()
{
    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), "wrong key test");

    // Generate a random wrong key
    unsigned char wrongSk[crypto_box_SECRETKEYBYTES];
    unsigned char wrongPk[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(wrongPk, wrongSk);
    QByteArray wrongPriv(reinterpret_cast<const char*>(wrongSk), sizeof(wrongSk));
    sodium_memzero(wrongSk, sizeof(wrongSk));

    UnsealResult result = SealedEnvelope::unseal(wrongPriv, sealed);
    QVERIFY2(!result.valid, "Unseal with wrong recipient key must fail");
}

void TestSealedEnvelope::unsealTamperedDataFails()
{
    QByteArray sealed = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), "tamper test");

    // Flip a byte after the ephemeral public key
    if (sealed.size() > 40) {
        sealed[40] ^= 0xFF;
    }

    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, sealed);
    QVERIFY2(!result.valid, "Tampered sealed envelope must fail authentication");
}

void TestSealedEnvelope::unsealTooShortDataFails()
{
    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, QByteArray(10, '\x00'));
    QVERIFY2(!result.valid, "Too-short data must fail unseal");
}

void TestSealedEnvelope::unsealEmptyDataFails()
{
    UnsealResult result = SealedEnvelope::unseal(m_peerCurvePriv, {});
    QVERIFY2(!result.valid, "Empty data must fail unseal");
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple Envelopes
// ═══════════════════════════════════════════════════════════════════════════

void TestSealedEnvelope::twoSealsProduceDifferentCiphertexts()
{
    QByteArray payload = "same payload";

    QByteArray sealed1 = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), payload);
    QByteArray sealed2 = SealedEnvelope::seal(
        m_peerCurvePub, m_engine->identityPub(), m_engine->identityPriv(), payload);

    QVERIFY2(sealed1 != sealed2,
             "Two seals of the same payload must differ (different ephemeral key each time)");
}

QTEST_MAIN(TestSealedEnvelope)
#include "tst_sealedenvelope.moc"
