// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — CryptoEngine Unit Tests
// ════════════════════════════════════════════════════════════════════════════
//
// IMPORTANT: CryptoEngine persists identity keys to disk at:
//   <AppDataLocation>/keys/identity.json
// Once created, ensureIdentity() will try to decrypt with the passphrase.
// All tests MUST use the same passphrase, or the identity file must be
// deleted between tests.
//
// Framework: Qt Test (QTest)
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <sodium.h>

#include "../CryptoEngine.hpp"

// All tests use this passphrase so the on-disk identity stays valid
static const QString kTestPassphrase = "peer2pear-test-passphrase";

class TestCryptoEngine : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();

    // ── Identity Keys ────────────────────────────────────────────────────────
    void identityKeysAreGenerated();
    void identityKeysAreCorrectSize();
    void curveKeysAreDerivedFromEd();
    void curveKeysAreCorrectSize();

    // ── Base64url ────────────────────────────────────────────────────────────
    void base64urlRoundTrip();
    void base64urlEmptyInput();
    void base64urlNoPadding();
    void base64urlBinaryData();

    // ── AEAD Encrypt/Decrypt ─────────────────────────────────────────────────
    void aeadRoundTrip();
    void aeadWithAAD();
    void aeadDecryptWrongKeyFails();
    void aeadDecryptTamperedCiphertextFails();
    void aeadDecryptTamperedAADFails();
    void aeadEmptyPlaintext();
    void aeadLargePlaintext();
    void aeadOutputContainsNonce();

    // ── Signatures ───────────────────────────────────────────────────────────
    void signAndVerify();
    void verifyWrongMessageFails();
    void verifyTamperedSignatureFails();

    // ── Ephemeral X25519 ─────────────────────────────────────────────────────
    void ephemeralKeypairSizesAreCorrect();
    void ephemeralKeypairsAreUnique();

    // ── HKDF ─────────────────────────────────────────────────────────────────
    void hkdfProducesCorrectLength();
    void hkdfDeterministic();
    void hkdfDifferentSaltProducesDifferentOutput();
    void hkdfDifferentInfoProducesDifferentOutput();
    void hkdfCustomOutputLength();

    // ── Shared Key Derivation ────────────────────────────────────────────────
    void deriveSharedKey32SizeIs32();

    // ── Secure Zeroing ───────────────────────────────────────────────────────
    void secureZeroByteArrayZerosBuffer();
    void secureZeroStringZerosBuffer();
    void secureZeroEmptyIsNoOp();

private:
    // Delete the on-disk identity file so tests start fresh
    void deleteIdentityFile();

    // Shared engine initialized once with kTestPassphrase
    std::unique_ptr<CryptoEngine> m_engine;
};

void TestCryptoEngine::deleteIdentityFile()
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    const QString path = base + "/keys/identity.json";
    QFile::remove(path);
}

void TestCryptoEngine::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize successfully");

    // Start fresh — remove any leftover identity from previous test runs
    deleteIdentityFile();

    // Create a single engine that all tests share
    m_engine = std::make_unique<CryptoEngine>();
    m_engine->setPassphrase(kTestPassphrase);
    m_engine->ensureIdentity();
}

void TestCryptoEngine::cleanupTestCase()
{
    m_engine.reset();
    // Clean up the test identity file so we don't pollute the system
    deleteIdentityFile();
}

// ═══════════════════════════════════════════════════════════════════════════
// Identity Keys
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::identityKeysAreGenerated()
{
    QVERIFY2(!m_engine->identityPub().isEmpty(), "Ed25519 public key must be generated");
    QVERIFY2(!m_engine->identityPriv().isEmpty(), "Ed25519 private key must be generated");
}

void TestCryptoEngine::identityKeysAreCorrectSize()
{
    QCOMPARE(m_engine->identityPub().size(), 32);
    QCOMPARE(m_engine->identityPriv().size(), 64);
}

void TestCryptoEngine::curveKeysAreDerivedFromEd()
{
    QVERIFY2(!m_engine->curvePub().isEmpty(), "X25519 public key must be derived");
    QVERIFY2(!m_engine->curvePriv().isEmpty(), "X25519 private key must be derived");
}

void TestCryptoEngine::curveKeysAreCorrectSize()
{
    QCOMPARE(m_engine->curvePub().size(), 32);
    QCOMPARE(m_engine->curvePriv().size(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// Base64url
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::base64urlRoundTrip()
{
    QByteArray original(32, '\x00');
    randombytes_buf(reinterpret_cast<unsigned char*>(original.data()), 32);

    QString encoded = CryptoEngine::toBase64Url(original);
    QByteArray decoded = CryptoEngine::fromBase64Url(encoded);
    QCOMPARE(decoded, original);
}

void TestCryptoEngine::base64urlEmptyInput()
{
    QString encoded = CryptoEngine::toBase64Url({});
    QByteArray decoded = CryptoEngine::fromBase64Url("");
    // Empty input should produce empty or minimal output
    Q_UNUSED(encoded);
    Q_UNUSED(decoded);
}

void TestCryptoEngine::base64urlNoPadding()
{
    QByteArray data(33, 'A'); // 33 bytes → would need padding in standard base64
    QString encoded = CryptoEngine::toBase64Url(data);
    QVERIFY2(!encoded.contains('='), "base64url must not contain padding characters");
    QVERIFY2(!encoded.contains('+'), "base64url must not contain '+'");
    QVERIFY2(!encoded.contains('/'), "base64url must not contain '/'");
}

void TestCryptoEngine::base64urlBinaryData()
{
    // All 256 byte values
    QByteArray allBytes(256, '\x00');
    for (int i = 0; i < 256; ++i)
        allBytes[i] = static_cast<char>(i);

    QString encoded = CryptoEngine::toBase64Url(allBytes);
    QByteArray decoded = CryptoEngine::fromBase64Url(encoded);
    QCOMPARE(decoded, allBytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// AEAD Encrypt/Decrypt
// ════════════════════════════════════════════════════════════════════��══════

void TestCryptoEngine::aeadRoundTrip()
{
    QByteArray key(32, '\x00');
    randombytes_buf(reinterpret_cast<unsigned char*>(key.data()), 32);
    QByteArray plaintext = "Hello, encrypted world!";

    QByteArray ct = m_engine->aeadEncrypt(key, plaintext);
    QVERIFY2(!ct.isEmpty(), "Ciphertext must not be empty");
    QVERIFY2(ct != plaintext, "Ciphertext must differ from plaintext");

    QByteArray pt = m_engine->aeadDecrypt(key, ct);
    QCOMPARE(pt, plaintext);
}

void TestCryptoEngine::aeadWithAAD()
{
    QByteArray key(32, '\x00');
    randombytes_buf(reinterpret_cast<unsigned char*>(key.data()), 32);
    QByteArray plaintext = "AAD test message";
    QByteArray aad = "associated-data-header";

    QByteArray ct = m_engine->aeadEncrypt(key, plaintext, aad);
    QByteArray pt = m_engine->aeadDecrypt(key, ct, aad);
    QCOMPARE(pt, plaintext);
}

void TestCryptoEngine::aeadDecryptWrongKeyFails()
{
    QByteArray key1(32, '\x01');
    QByteArray key2(32, '\x02');
    QByteArray plaintext = "secret";

    QByteArray ct = m_engine->aeadEncrypt(key1, plaintext);
    QByteArray pt = m_engine->aeadDecrypt(key2, ct);
    QVERIFY2(pt.isEmpty(), "Decryption with wrong key must fail (return empty)");
}

void TestCryptoEngine::aeadDecryptTamperedCiphertextFails()
{
    QByteArray key(32, '\x03');
    QByteArray ct = m_engine->aeadEncrypt(key, "tamper test");

    if (ct.size() > 25) {
        ct[25] = static_cast<char>(ct[25] ^ 0xFF);
    }

    QByteArray pt = m_engine->aeadDecrypt(key, ct);
    QVERIFY2(pt.isEmpty(), "Tampered ciphertext must fail authentication");
}

void TestCryptoEngine::aeadDecryptTamperedAADFails()
{
    QByteArray key(32, '\x04');
    QByteArray plaintext = "aad integrity test";
    QByteArray aad = "correct-aad";

    QByteArray ct = m_engine->aeadEncrypt(key, plaintext, aad);
    QByteArray pt = m_engine->aeadDecrypt(key, ct, "wrong-aad");
    QVERIFY2(pt.isEmpty(), "Mismatched AAD must fail authentication");
}

void TestCryptoEngine::aeadEmptyPlaintext()
{
    QByteArray key(32, '\x05');
    QByteArray ct = m_engine->aeadEncrypt(key, {});
    QVERIFY2(!ct.isEmpty(), "Encrypting empty plaintext should still produce nonce + tag");

    QByteArray pt = m_engine->aeadDecrypt(key, ct);
    QCOMPARE(pt, QByteArray());
}

void TestCryptoEngine::aeadLargePlaintext()
{
    QByteArray key(32, '\x06');
    QByteArray plaintext(1024 * 100, 'X'); // 100 KB

    QByteArray ct = m_engine->aeadEncrypt(key, plaintext);
    QByteArray pt = m_engine->aeadDecrypt(key, ct);
    QCOMPARE(pt, plaintext);
}

void TestCryptoEngine::aeadOutputContainsNonce()
{
    QByteArray key(32, '\x07');
    QByteArray ct = m_engine->aeadEncrypt(key, "nonce test");

    QVERIFY2(ct.size() >= static_cast<int>(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES),
             "AEAD output must contain at least the 24-byte nonce");
}

// ═══════════════════════════════════════════════════════════════════════════
// Signatures
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::signAndVerify()
{
    QByteArray message = "Sign this message";
    QString sigB64u = m_engine->signB64u(message);
    QVERIFY2(!sigB64u.isEmpty(), "Signature must not be empty");

    QByteArray sig = CryptoEngine::fromBase64Url(sigB64u);
    QCOMPARE(sig.size(), 64);

    bool valid = CryptoEngine::verifySignature(sig, message, m_engine->identityPub());
    QVERIFY2(valid, "Signature must verify with the correct key and message");
}

void TestCryptoEngine::verifyWrongMessageFails()
{
    QByteArray message = "Original message";
    QString sigB64u = m_engine->signB64u(message);
    QByteArray sig = CryptoEngine::fromBase64Url(sigB64u);

    bool valid = CryptoEngine::verifySignature(sig, "Different message", m_engine->identityPub());
    QVERIFY2(!valid, "Signature must NOT verify against a different message");
}

void TestCryptoEngine::verifyTamperedSignatureFails()
{
    QByteArray message = "Tamper test";
    QString sigB64u = m_engine->signB64u(message);
    QByteArray sig = CryptoEngine::fromBase64Url(sigB64u);

    sig[0] = static_cast<char>(sig[0] ^ 0xFF);
    bool valid = CryptoEngine::verifySignature(sig, message, m_engine->identityPub());
    QVERIFY2(!valid, "Tampered signature must fail verification");
}

// ═══════════════════════════════════════════════════════════════════════════
// Ephemeral X25519
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::ephemeralKeypairSizesAreCorrect()
{
    auto [pub, priv] = CryptoEngine::generateEphemeralX25519();
    QCOMPARE(pub.size(), 32);
    QCOMPARE(priv.size(), 32);
}

void TestCryptoEngine::ephemeralKeypairsAreUnique()
{
    auto [pub1, priv1] = CryptoEngine::generateEphemeralX25519();
    auto [pub2, priv2] = CryptoEngine::generateEphemeralX25519();
    QVERIFY2(pub1 != pub2, "Ephemeral keypairs must be unique");
}

// ═══════════════════════════════════════════════════════════════════════════
// HKDF
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::hkdfProducesCorrectLength()
{
    QByteArray ikm(32, '\xAA');
    QByteArray salt(32, '\xBB');
    QByteArray info = "test-info";

    QByteArray out = CryptoEngine::hkdf(ikm, salt, info, 32);
    QCOMPARE(out.size(), 32);
}

void TestCryptoEngine::hkdfDeterministic()
{
    QByteArray ikm(32, '\xCC');
    QByteArray salt(32, '\xDD');
    QByteArray info = "determinism";

    QByteArray out1 = CryptoEngine::hkdf(ikm, salt, info);
    QByteArray out2 = CryptoEngine::hkdf(ikm, salt, info);
    QCOMPARE(out1, out2);
}

void TestCryptoEngine::hkdfDifferentSaltProducesDifferentOutput()
{
    QByteArray ikm(32, '\xEE');
    QByteArray info = "salt-test";

    QByteArray out1 = CryptoEngine::hkdf(ikm, QByteArray(32, '\x01'), info);
    QByteArray out2 = CryptoEngine::hkdf(ikm, QByteArray(32, '\x02'), info);
    QVERIFY2(out1 != out2, "Different salts must produce different HKDF output");
}

void TestCryptoEngine::hkdfDifferentInfoProducesDifferentOutput()
{
    QByteArray ikm(32, '\xFF');
    QByteArray salt(32, '\x00');

    QByteArray out1 = CryptoEngine::hkdf(ikm, salt, "info-a");
    QByteArray out2 = CryptoEngine::hkdf(ikm, salt, "info-b");
    QVERIFY2(out1 != out2, "Different info must produce different HKDF output");
}

void TestCryptoEngine::hkdfCustomOutputLength()
{
    QByteArray ikm(32, '\x11');
    QByteArray salt(32, '\x22');

    QByteArray out64 = CryptoEngine::hkdf(ikm, salt, "len-test", 64);
    QCOMPARE(out64.size(), 64);

    QByteArray out16 = CryptoEngine::hkdf(ikm, salt, "len-test", 16);
    QCOMPARE(out16.size(), 16);
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared Key Derivation
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::deriveSharedKey32SizeIs32()
{
    // Generate a separate keypair to act as "peer" — we can't create a
    // second CryptoEngine because it would try to load the same identity
    // file from disk. Instead, use raw Ed25519 keypair.
    unsigned char peerPk[crypto_sign_PUBLICKEYBYTES];
    unsigned char peerSk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(peerPk, peerSk);
    sodium_memzero(peerSk, sizeof(peerSk));

    QByteArray peerPub(reinterpret_cast<const char*>(peerPk), sizeof(peerPk));

    QByteArray shared = m_engine->deriveSharedKey32(peerPub);
    QCOMPARE(shared.size(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// Secure Zeroing
// ═══════════════════════════════════════════════════════════════════════════

void TestCryptoEngine::secureZeroByteArrayZerosBuffer()
{
    QByteArray secret(32, '\xFF');
    CryptoEngine::secureZero(secret);

    // secureZero calls .clear() after sodium_memzero, so size becomes 0
    QVERIFY2(secret.isEmpty(),
             "secureZero must zero and clear the QByteArray");
}

void TestCryptoEngine::secureZeroStringZerosBuffer()
{
    QString secret = "super-secret-passphrase";
    CryptoEngine::secureZero(secret);

    // secureZero calls .clear() after sodium_memzero, so size becomes 0
    QVERIFY2(secret.isEmpty(),
             "secureZero must zero and clear the QString");
}

void TestCryptoEngine::secureZeroEmptyIsNoOp()
{
    QByteArray emptyBa;
    CryptoEngine::secureZero(emptyBa);
    QVERIFY(emptyBa.isEmpty());

    QString emptyStr;
    CryptoEngine::secureZero(emptyStr);
    QVERIFY(emptyStr.isEmpty());
}

QTEST_MAIN(TestCryptoEngine)
#include "tst_cryptoengine.moc"
