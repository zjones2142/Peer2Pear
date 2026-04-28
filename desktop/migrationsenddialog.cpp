#include "migrationsenddialog.h"
#include "peer2pear.h"

#include <QAbstractSocket>
#include <QByteArray>
#include <QFile>
#include <QHostAddress>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTcpSocket>
#include <QTimer>
#include <QVBoxLayout>

#include <sodium.h>

namespace {

constexpr int kHandshakeMinVersion = 1;
constexpr int kHandshakeMaxVersion = 2;

QByteArray base64UrlDecode(const QString &s)
{
    QString b64 = s;
    b64.replace('-', '+');
    b64.replace('_', '/');
    while (b64.size() % 4 != 0) b64.append('=');
    return QByteArray::fromBase64(b64.toLatin1());
}

}  // namespace

MigrationSendDialog::MigrationSendDialog(const QString &keysDir,
                                          const QByteArray &appDataSnapshotJson,
                                          const QJsonObject &userDefaults,
                                          QWidget *parent)
    : QDialog(parent)
    , m_keysDir(keysDir)
    , m_appDataSnapshotJson(appDataSnapshotJson)
    , m_userDefaults(userDefaults)
{
    setWindowTitle("Transfer to Another Device");
    setModal(true);
    setMinimumSize(440, 480);
    buildUi();
}

MigrationSendDialog::~MigrationSendDialog()
{
    // Socket is parented to `this`, cleaned up automatically.
    // No private-key material to wipe — sender doesn't generate
    // its own keypair (envelope is sealed under the receiver's
    // pubkey from the QR; the receiver wipes its privs).
}

void MigrationSendDialog::buildUi()
{
    setStyleSheet(
        "QDialog { background-color: #0a0a0a; }"
        "QLabel { color: #e0e0e0; }"
        "QLabel#instructions { color: #cccccc; font-size: 13px; }"
        "QLabel#caption { color: #888888; font-size: 11px; }"
        "QLabel#status { color: #aaaaaa; font-size: 12px; }"
        "QLabel#error { color: #d05050; font-size: 12px; }"
        "QPlainTextEdit { background-color: #1a1a1a; color: #f0f0f0; "
        "  border: 1px solid #2a2a2a; border-radius: 6px; "
        "  padding: 6px; font-family: monospace; font-size: 11px; }"
        "QPushButton#primary { background-color: #2e8b3a; color: #ffffff; "
        "  border: none; border-radius: 8px; padding: 8px 16px; "
        "  font-size: 13px; font-weight: bold; }"
        "QPushButton#primary:hover:enabled { background-color: #38a844; }"
        "QPushButton#primary:disabled { background-color: #1a3a1f; "
        "  color: #666666; }"
        "QPushButton#secondary { background-color: transparent; "
        "  color: #aaaaaa; border: 1px solid #333333; border-radius: 8px; "
        "  padding: 8px 16px; font-size: 12px; }"
        "QPushButton#secondary:hover { color: #ffffff; }");

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 24, 24, 20);
    root->setSpacing(14);

    auto *title = new QLabel("Transfer to another device", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("color: #ffffff; font-size: 20px; "
                         "font-weight: bold;");
    root->addWidget(title);

    auto *instructions = new QLabel(
        "On the new device, open Peer2Pear and choose "
        "\"Transfer from another device\".  Paste the code it "
        "displays into the box below.", this);
    instructions->setObjectName("instructions");
    instructions->setAlignment(Qt::AlignCenter);
    instructions->setWordWrap(true);
    root->addWidget(instructions);

    m_pasteBox = new QPlainTextEdit(this);
    m_pasteBox->setPlaceholderText(
        "Paste the pairing code from the new device…");
    m_pasteBox->setFixedHeight(72);
    connect(m_pasteBox, &QPlainTextEdit::textChanged,
            this, &MigrationSendDialog::onPasteEdited);
    root->addWidget(m_pasteBox);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName("error");
    m_errorLabel->setWordWrap(true);
    m_errorLabel->setVisible(false);
    root->addWidget(m_errorLabel);

    m_connectBtn = new QPushButton("Send", this);
    m_connectBtn->setObjectName("primary");
    m_connectBtn->setEnabled(false);
    connect(m_connectBtn, &QPushButton::clicked,
            this, &MigrationSendDialog::onConnectClicked);
    root->addWidget(m_connectBtn);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setObjectName("status");
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_statusLabel->setWordWrap(true);
    root->addWidget(m_statusLabel);

    auto *note = new QLabel(
        "Both devices need to be on the same Wi-Fi or LAN.  "
        "After a successful transfer, the new device prompts "
        "for your passphrase to apply the data.", this);
    note->setObjectName("caption");
    note->setAlignment(Qt::AlignCenter);
    note->setWordWrap(true);
    root->addWidget(note);

    root->addStretch(1);

    m_cancelBtn = new QPushButton("Cancel", this);
    m_cancelBtn->setObjectName("secondary");
    connect(m_cancelBtn, &QPushButton::clicked,
            this, &MigrationSendDialog::onCancel);
    root->addWidget(m_cancelBtn);
}

void MigrationSendDialog::onPasteEdited()
{
    if (m_errorLabel) {
        m_errorLabel->clear();
        m_errorLabel->setVisible(false);
    }
    const QString text = m_pasteBox->toPlainText().trimmed();
    m_connectBtn->setEnabled(!text.isEmpty());
}

bool MigrationSendDialog::decodeHandshake(const QString &encoded)
{
    const QByteArray jsonBytes = base64UrlDecode(encoded.trimmed());
    if (jsonBytes.isEmpty()) {
        if (m_errorLabel) {
            m_errorLabel->setText(
                "That doesn't look like a valid pairing code.");
            m_errorLabel->setVisible(true);
        }
        return false;
    }
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(jsonBytes, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        if (m_errorLabel) {
            m_errorLabel->setText(
                "Pairing code couldn't be parsed.  Try copying it again.");
            m_errorLabel->setVisible(true);
        }
        return false;
    }
    const QJsonObject obj = doc.object();
    const int version = obj.value("version").toInt(-1);
    if (version < kHandshakeMinVersion || version > kHandshakeMaxVersion) {
        if (m_errorLabel) {
            m_errorLabel->setText(
                "The other device is running an unsupported version "
                "of Peer2Pear.  Update both ends and try again.");
            m_errorLabel->setVisible(true);
        }
        return false;
    }
    m_handshakeFingerprint =
        QByteArray::fromBase64(obj.value("fingerprint").toString().toLatin1());
    m_handshakeNonce =
        QByteArray::fromBase64(obj.value("nonce").toString().toLatin1());
    if (m_handshakeFingerprint.size() != P2P_MIGRATION_FINGERPRINT_LEN ||
        m_handshakeNonce.size()       != P2P_MIGRATION_NONCE_LEN) {
        if (m_errorLabel) {
            m_errorLabel->setText(
                "Pairing code is malformed (fingerprint/nonce wrong size).");
            m_errorLabel->setVisible(true);
        }
        return false;
    }
    if (version >= 2) {
        m_recvAddr = obj.value("addr").toString();
        const int p = obj.value("port").toInt(-1);
        if (m_recvAddr.isEmpty() || p <= 0 || p > 65535) {
            if (m_errorLabel) {
                m_errorLabel->setText(
                    "Pairing code is missing the receiver's address.  "
                    "Make sure the new device shows a v2 code (you may "
                    "need to update it).");
                m_errorLabel->setVisible(true);
            }
            return false;
        }
        m_recvPort = static_cast<quint16>(p);
    } else {
        if (m_errorLabel) {
            m_errorLabel->setText(
                "The new device is using an iOS-only pairing code (v1).  "
                "Cross-platform transfer needs the v2 code that the "
                "next-version receiver displays.");
            m_errorLabel->setVisible(true);
        }
        return false;
    }
    return true;
}

void MigrationSendDialog::onConnectClicked()
{
    if (!decodeHandshake(m_pasteBox->toPlainText())) return;
    if (m_socket) return;   // already connecting / connected

    m_connectBtn->setEnabled(false);
    if (m_statusLabel) m_statusLabel->setText(
        QStringLiteral("Connecting to %1:%2…")
            .arg(m_recvAddr).arg(m_recvPort));

    m_socket = new QTcpSocket(this);
    connect(m_socket, &QTcpSocket::connected,
            this, &MigrationSendDialog::onSocketConnected);
    connect(m_socket, &QTcpSocket::readyRead,
            this, &MigrationSendDialog::onSocketReadyRead);
    connect(m_socket, &QTcpSocket::errorOccurred,
            this, &MigrationSendDialog::onSocketError);
    m_socket->connectToHost(QHostAddress(m_recvAddr), m_recvPort);
}

void MigrationSendDialog::onSocketConnected()
{
    if (m_statusLabel) m_statusLabel->setText(
        "Connected — exchanging keys…");
}

void MigrationSendDialog::onSocketReadyRead()
{
    if (!m_socket) return;
    m_readBuf.append(m_socket->readAll());
    while (tryConsumeFrame()) { /* keep consuming */ }
}

bool MigrationSendDialog::tryConsumeFrame()
{
    if (m_readBuf.size() < 5) return false;
    const auto tag = static_cast<quint8>(m_readBuf[0]);
    const quint32 len =
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[1])) << 24) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[2])) << 16) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[3])) <<  8) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[4])));
    constexpr quint32 kMaxFrameBody = 256u * 1024u * 1024u;
    if (len > kMaxFrameBody) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — receiver announced an oversized frame.");
        m_socket->disconnectFromHost();
        return false;
    }
    if (m_readBuf.size() < static_cast<int>(5 + len)) return false;
    const QByteArray body = m_readBuf.mid(5, static_cast<int>(len));
    m_readBuf.remove(0, static_cast<int>(5 + len));

    if (tag == 0x01) {
        handlePubkeysOffer(body);
        return true;
    }
    if (m_statusLabel) m_statusLabel->setText(
        QStringLiteral("Aborted — unexpected message tag 0x%1 from receiver.")
            .arg(QString::number(tag, 16)));
    m_socket->disconnectFromHost();
    return false;
}

void MigrationSendDialog::handlePubkeysOffer(const QByteArray &json)
{
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — receiver sent malformed PubkeysOffer.");
        m_socket->disconnectFromHost();
        return;
    }
    const QJsonObject obj = doc.object();
    m_recvX25519Pub =
        QByteArray::fromBase64(obj.value("x25519Pub").toString().toLatin1());
    m_recvMlkemPub =
        QByteArray::fromBase64(obj.value("mlkemPub").toString().toLatin1());
    if (m_recvX25519Pub.size() != P2P_MIGRATION_X25519_PUB_LEN ||
        m_recvMlkemPub.size()  != P2P_MIGRATION_MLKEM_PUB_LEN) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — receiver pubkeys are wrong size.");
        m_socket->disconnectFromHost();
        return;
    }
    // MITM check — recompute the fingerprint from received
    // pubkeys + compare with the one on the QR.  Mismatch = a
    // third party intercepted the pairing.
    QByteArray fp(P2P_MIGRATION_FINGERPRINT_LEN, '\0');
    const int fpRc = p2p_migration_fingerprint(
        reinterpret_cast<const uint8_t*>(m_recvX25519Pub.constData()),
        reinterpret_cast<const uint8_t*>(m_recvMlkemPub.constData()),
        reinterpret_cast<uint8_t*>(fp.data()));
    if (fpRc != 0 ||
        sodium_memcmp(fp.constData(),
                       m_handshakeFingerprint.constData(),
                       P2P_MIGRATION_FINGERPRINT_LEN) != 0) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — fingerprint mismatch.  Someone may be "
            "intercepting the pairing.  Try again on a trusted network.");
        m_socket->disconnectFromHost();
        return;
    }
    if (m_statusLabel) m_statusLabel->setText("Verified.  Sending payload…");
    if (!buildAndSendEnvelope()) {
        m_socket->disconnectFromHost();
    }
}

bool MigrationSendDialog::buildAndSendEnvelope()
{
    if (m_envelopeSent) return true;   // idempotent guard

    // ── Build payload ────────────────────────────────────────
    // MigrationPayload v3 JSON shape matches iOS MigrationBlob.swift.
    // Identity + salt are read straight from disk; appDataSnapshot
    // and userDefaults are empty in this cut (Step 4 will fill
    // them once the receiver-side apply path is wired).  iOS
    // receivers tolerate empty values per their MigrationBlob
    // docstring.
    QFile idFile(m_keysDir + "/identity.json");
    QFile saltFile(m_keysDir + "/db_salt.bin");
    if (!idFile.open(QIODevice::ReadOnly) ||
        !saltFile.open(QIODevice::ReadOnly)) {
        if (m_statusLabel) m_statusLabel->setText(
            "Couldn't read identity files — has this device unlocked yet?");
        return false;
    }
    const QByteArray identityBytes = idFile.readAll();
    const QByteArray saltBytes     = saltFile.readAll();
    if (identityBytes.isEmpty() || saltBytes.isEmpty()) {
        if (m_statusLabel) m_statusLabel->setText(
            "Identity files are empty — please relaunch and try again.");
        return false;
    }

    QJsonObject payload;
    payload.insert("appDataSnapshot",
                    QString::fromLatin1(m_appDataSnapshotJson.toBase64()));
    payload.insert("identityFile",
                    QString::fromLatin1(identityBytes.toBase64()));
    payload.insert("saltFile",
                    QString::fromLatin1(saltBytes.toBase64()));
    payload.insert("userDefaults", m_userDefaults);
    payload.insert("version", 3);
    const QByteArray payloadBytes =
        QJsonDocument(payload).toJson(QJsonDocument::Compact);

    // ── Seal ─────────────────────────────────────────────────
    QByteArray envelope(
        payloadBytes.size() + P2P_MIGRATION_ENVELOPE_OVERHEAD, '\0');
    const int sealedLen = p2p_migration_seal(
        reinterpret_cast<const uint8_t*>(payloadBytes.constData()),
        payloadBytes.size(),
        reinterpret_cast<const uint8_t*>(m_recvX25519Pub.constData()),
        reinterpret_cast<const uint8_t*>(m_recvMlkemPub.constData()),
        reinterpret_cast<const uint8_t*>(m_handshakeNonce.constData()),
        reinterpret_cast<uint8_t*>(envelope.data()),
        envelope.size());
    if (sealedLen < 0) {
        if (m_statusLabel) m_statusLabel->setText(
            "Couldn't seal the payload (cryptographic error).");
        return false;
    }
    envelope.truncate(sealedLen);

    // ── Frame + send ─────────────────────────────────────────
    QByteArray frame;
    frame.reserve(1 + 4 + envelope.size());
    frame.append(static_cast<char>(0x02));
    const quint32 len = static_cast<quint32>(envelope.size());
    frame.append(static_cast<char>((len >> 24) & 0xff));
    frame.append(static_cast<char>((len >> 16) & 0xff));
    frame.append(static_cast<char>((len >>  8) & 0xff));
    frame.append(static_cast<char>((len      ) & 0xff));
    frame.append(envelope);
    m_socket->write(frame);
    m_envelopeSent = true;

    if (m_statusLabel) m_statusLabel->setText(
        QStringLiteral("Transfer complete (%1 bytes sealed).  "
                        "The new device will prompt for your passphrase "
                        "to apply.")
            .arg(sealedLen));
    return true;
}

void MigrationSendDialog::onSocketError()
{
    if (!m_socket) return;
    if (m_envelopeSent) return;   // benign disconnect after send
    if (m_statusLabel) m_statusLabel->setText(
        QStringLiteral("Connection failed: %1.  Make sure both devices "
                        "are on the same network.")
            .arg(m_socket->errorString()));
    m_connectBtn->setEnabled(true);
}

void MigrationSendDialog::onCancel()
{
    if (m_socket) m_socket->disconnectFromHost();
    reject();
}
