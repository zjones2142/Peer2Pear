#include "migrationreceivedialog.h"
#include "peer2pear.h"   // P2P_MIGRATION_*_LEN + p2p_migration_keypair / fingerprint
#include "QrImage.hpp"

#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QFile>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QImage>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QVBoxLayout>

#include <sodium.h>

namespace {

// v2 = adds optional addr + port to the handshake JSON so a sender
// on any platform can connect to the receiver's LAN TCP listener
// directly — no third-party server in the data path.  v1 (no
// addr/port) is still understood by senders that fall back to a
// platform-native discovery transport (iOS MultipeerConnectivity);
// once iOS gains the NWListener-based TCP path it'll emit v2 too.
constexpr int kHandshakeVersion = 2;

/// Standard base64 → base64url with no padding.  Matches iOS
/// `Data.base64URLEncodedString()` byte-for-byte (which is what
/// MigrationHandshake.encodeForQR uses to wrap the JSON before
/// QR/paste display).
QByteArray base64UrlEncode(const QByteArray &raw)
{
    QByteArray b64 = raw.toBase64();
    b64.replace('+', '-');
    b64.replace('/', '_');
    while (!b64.isEmpty() && b64.endsWith('=')) b64.chop(1);
    return b64;
}

/// Test whether `ip` is in one of the RFC1918 private ranges
/// (10/8, 172.16/12, 192.168/16).  Operates on the numeric IPv4
/// value rather than string prefixes — `startsWith("172.2")`
/// would falsely include 172.2.x.x and 172.250.x.x.
bool isRFC1918(quint32 v4)
{
    const quint8 a = (v4 >> 24) & 0xff;
    const quint8 b = (v4 >> 16) & 0xff;
    if (a == 10) return true;                        // 10.0.0.0/8
    if (a == 192 && b == 168) return true;           // 192.168.0.0/16
    if (a == 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    return false;
}

/// Pick the most-likely-routable LAN IPv4 address for the
/// receiver's listening socket.  Walks every QNetworkInterface,
/// keeps active non-loopback interfaces, and prefers RFC1918
/// addresses over public IPv4 (which a v2 handshake QR shouldn't
/// carry across the public internet).  Returns an empty string
/// if no suitable address is found — caller falls back to v1 +
/// surfaces a warning.
QString pickLanIPv4()
{
    QString publicCandidate;
    for (const QNetworkInterface &iface : QNetworkInterface::allInterfaces()) {
        const auto flags = iface.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp))         continue;
        if (!flags.testFlag(QNetworkInterface::IsRunning))    continue;
        if (flags.testFlag(QNetworkInterface::IsLoopBack))    continue;
        for (const QNetworkAddressEntry &entry : iface.addressEntries()) {
            const QHostAddress ip = entry.ip();
            if (ip.protocol() != QAbstractSocket::IPv4Protocol) continue;
            if (ip.isLoopback() || ip.isLinkLocal())            continue;
            if (isRFC1918(ip.toIPv4Address())) return ip.toString();
            if (publicCandidate.isEmpty())     publicCandidate = ip.toString();
        }
    }
    return publicCandidate;
}

}  // namespace

MigrationReceiveDialog::MigrationReceiveDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Transfer from Another Device");
    setModal(true);
    // Sized for the 240-px QR + paste box + status row without
    // forcing a horizontal scroll.
    setMinimumSize(420, 600);

    if (!prepareSession()) {
        // Surface the failure as a popup so the user understands
        // why the dialog isn't proceeding, then defer rejection
        // until the event loop spins (so the parent paints first).
        QTimer::singleShot(0, this, [this]() {
            QMessageBox::critical(
                this,
                "Migration Setup Failed",
                "Couldn't generate the migration keypair on this "
                "device.  Try restarting the app; if the issue "
                "persists, report it.");
            reject();
        });
        return;
    }

    buildUi();
}

MigrationReceiveDialog::~MigrationReceiveDialog()
{
    // Best-effort zero the private-key material before the
    // QByteArrays release their backing memory.  QByteArray's COW
    // means a copy elsewhere wouldn't be wiped, but we don't hand
    // these out to other code in Phase A — they only live here.
    if (!m_x25519Priv.isEmpty()) {
        sodium_memzero(m_x25519Priv.data(), m_x25519Priv.size());
    }
    if (!m_mlkemPriv.isEmpty()) {
        sodium_memzero(m_mlkemPriv.data(), m_mlkemPriv.size());
    }
}

bool MigrationReceiveDialog::prepareSession()
{
    m_x25519Pub.resize(P2P_MIGRATION_X25519_PUB_LEN);
    m_x25519Priv.resize(P2P_MIGRATION_X25519_PRIV_LEN);
    m_mlkemPub.resize(P2P_MIGRATION_MLKEM_PUB_LEN);
    m_mlkemPriv.resize(P2P_MIGRATION_MLKEM_PRIV_LEN);

    const int kpRc = p2p_migration_keypair(
        reinterpret_cast<uint8_t*>(m_x25519Pub.data()),
        reinterpret_cast<uint8_t*>(m_x25519Priv.data()),
        reinterpret_cast<uint8_t*>(m_mlkemPub.data()),
        reinterpret_cast<uint8_t*>(m_mlkemPriv.data()));
    if (kpRc != 0) return false;

    m_fingerprint.resize(P2P_MIGRATION_FINGERPRINT_LEN);
    const int fpRc = p2p_migration_fingerprint(
        reinterpret_cast<const uint8_t*>(m_x25519Pub.constData()),
        reinterpret_cast<const uint8_t*>(m_mlkemPub.constData()),
        reinterpret_cast<uint8_t*>(m_fingerprint.data()));
    if (fpRc != 0) return false;

    m_nonce.resize(P2P_MIGRATION_NONCE_LEN);
    randombytes_buf(m_nonce.data(), m_nonce.size());

    // ── LAN TCP listener ────────────────────────────────────
    // Bind on QHostAddress::Any with port=0 so the OS picks a
    // free ephemeral port; report whatever it picked in the v2
    // handshake.  Failures here are non-fatal — fall back to
    // v1 (no addr/port) and surface a warning so the user
    // understands the sender won't be able to reach this device.
    m_tcpServer = new QTcpServer(this);
    if (m_tcpServer->listen(QHostAddress::Any, /*port=*/0)) {
        m_listenPort = m_tcpServer->serverPort();
        m_listenAddr = pickLanIPv4();
        connect(m_tcpServer, &QTcpServer::newConnection,
                this, &MigrationReceiveDialog::onTcpConnection);
    }

    // Build the JSON handshake.  Key order matches iOS's
    // JSONEncoder(.sortedKeys) output: alphabetical.
    // QJsonObject iterates alphabetically too, so
    // QJsonDocument::Compact emits the same shape.  Data fields
    // are standard base64 (NOT base64url) inside the JSON,
    // matching Swift's default Data Codable behaviour; the
    // OUTER wrap is base64url.
    QJsonObject obj;
    if (!m_listenAddr.isEmpty() && m_listenPort != 0) {
        obj.insert("addr", m_listenAddr);
    }
    obj.insert("fingerprint",
               QString::fromLatin1(m_fingerprint.toBase64()));
    obj.insert("nonce",
               QString::fromLatin1(m_nonce.toBase64()));
    if (!m_listenAddr.isEmpty() && m_listenPort != 0) {
        obj.insert("port", static_cast<int>(m_listenPort));
    }
    // Bump to v2 only when we're actually emitting addr+port —
    // a v1 handshake without a transport hint is honest about
    // what we can offer (the senders that understand v1 know to
    // use a platform-native discovery transport).
    const int version =
        (!m_listenAddr.isEmpty() && m_listenPort != 0) ? kHandshakeVersion : 1;
    obj.insert("version", version);
    const QByteArray json =
        QJsonDocument(obj).toJson(QJsonDocument::Compact);
    m_handshakeEncoded = QString::fromLatin1(base64UrlEncode(json));
    return true;
}

void MigrationReceiveDialog::buildUi()
{
    setStyleSheet(
        "QDialog { background-color: #0a0a0a; }"
        "QLabel { color: #e0e0e0; }"
        "QLabel#instructions { color: #cccccc; font-size: 13px; }"
        "QLabel#caption { color: #888888; font-size: 11px; }"
        "QLabel#status { color: #aaaaaa; font-size: 12px; }"
        "QPlainTextEdit { background-color: #1a1a1a; color: #f0f0f0; "
        "  border: 1px solid #2a2a2a; border-radius: 6px; "
        "  padding: 6px; font-family: monospace; font-size: 11px; }"
        "QPushButton#primary { background-color: #2e8b3a; color: #ffffff; "
        "  border: none; border-radius: 8px; padding: 8px 16px; "
        "  font-size: 13px; font-weight: bold; }"
        "QPushButton#primary:hover { background-color: #38a844; }"
        "QPushButton#secondary { background-color: transparent; "
        "  color: #aaaaaa; border: 1px solid #333333; border-radius: 8px; "
        "  padding: 8px 16px; font-size: 12px; }"
        "QPushButton#secondary:hover { color: #ffffff; }");

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 24, 24, 20);
    root->setSpacing(14);

    auto *title = new QLabel("Transfer from another device", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("color: #ffffff; font-size: 20px; "
                         "font-weight: bold;");
    root->addWidget(title);

    m_instructions = new QLabel(this);
    m_instructions->setObjectName("instructions");
    m_instructions->setAlignment(Qt::AlignCenter);
    m_instructions->setWordWrap(true);
    m_instructions->setText(
        "On your old device, open Peer2Pear → Settings → "
        "Transfer to new device.  Scan this QR code, or paste "
        "the code below.");
    root->addWidget(m_instructions);

    // ── QR display ───────────────────────────────────────────
    m_qrLabel = new QLabel(this);
    m_qrLabel->setAlignment(Qt::AlignCenter);
    m_qrLabel->setFixedSize(260, 260);
    m_qrLabel->setStyleSheet(
        "background-color: #ffffff; border-radius: 8px;");
    QImage qr = QrImage::encodeText(m_handshakeEncoded, /*pixelsPerModule=*/6);
    if (!qr.isNull()) {
        m_qrLabel->setPixmap(
            QPixmap::fromImage(qr).scaled(
                240, 240, Qt::KeepAspectRatio, Qt::FastTransformation));
    } else {
        m_qrLabel->setText("QR generation failed");
        m_qrLabel->setStyleSheet(
            "color: #888888; font-size: 11px; "
            "background-color: #1a1a1a; border-radius: 8px;");
    }
    auto *qrRow = new QHBoxLayout();
    qrRow->addStretch(1);
    qrRow->addWidget(m_qrLabel);
    qrRow->addStretch(1);
    root->addLayout(qrRow);

    // ── Paste-code fallback ──────────────────────────────────
    m_pasteHeader = new QLabel(
        "Or paste this code on your old device:", this);
    m_pasteHeader->setObjectName("caption");
    root->addWidget(m_pasteHeader);

    m_pasteBox = new QPlainTextEdit(this);
    m_pasteBox->setReadOnly(true);
    m_pasteBox->setPlainText(m_handshakeEncoded);
    m_pasteBox->setFixedHeight(56);
    root->addWidget(m_pasteBox);

    m_copyBtn = new QPushButton("Copy code", this);
    m_copyBtn->setObjectName("primary");
    connect(m_copyBtn, &QPushButton::clicked,
            this, &MigrationReceiveDialog::onCopyCode);
    root->addWidget(m_copyBtn);

    // ── Status row ───────────────────────────────────────────
    const QString statusText = (m_listenAddr.isEmpty() || m_listenPort == 0)
        ? QStringLiteral("Network unreachable — couldn't start the LAN "
                          "listener.  Check your network connection.")
        : QStringLiteral("Listening on %1:%2.  Waiting for the old "
                          "device to connect…")
              .arg(m_listenAddr).arg(m_listenPort);
    m_statusLabel = new QLabel(statusText, this);
    m_statusLabel->setObjectName("status");
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_statusLabel->setWordWrap(true);
    root->addSpacing(4);
    root->addWidget(m_statusLabel);

    m_phaseNote = new QLabel(this);
    m_phaseNote->setObjectName("caption");
    m_phaseNote->setAlignment(Qt::AlignCenter);
    m_phaseNote->setWordWrap(true);
    m_phaseNote->setText(
        "Both devices need to be on the same Wi-Fi or LAN.  After "
        "the old device connects + sends its data, this screen "
        "will ask for your passphrase to apply.");
    root->addWidget(m_phaseNote);

    // ── Apply-stage UI (hidden until envelope decrypts) ──────
    // Mirrors iOS TransferReceiveView's `applyPassphrasePrompt`
    // shape: a heading explaining what's about to happen, the
    // SecureField, an inline error label, and an Apply button.
    m_applyTitle = new QLabel("Decryption successful.", this);
    m_applyTitle->setStyleSheet(
        "color: #ffffff; font-size: 18px; font-weight: bold;");
    m_applyTitle->setAlignment(Qt::AlignCenter);
    m_applyTitle->setVisible(false);
    root->addWidget(m_applyTitle);

    m_applyHint = new QLabel(
        "Enter the passphrase you use on your old device.  This "
        "is the only piece of state that doesn't transfer — the "
        "new device needs it to unlock the migrated identity.",
        this);
    m_applyHint->setObjectName("caption");
    m_applyHint->setWordWrap(true);
    m_applyHint->setAlignment(Qt::AlignCenter);
    m_applyHint->setVisible(false);
    root->addWidget(m_applyHint);

    m_applyPassField = new QLineEdit(this);
    m_applyPassField->setEchoMode(QLineEdit::Password);
    m_applyPassField->setPlaceholderText("Passphrase");
    m_applyPassField->setVisible(false);
    connect(m_applyPassField, &QLineEdit::textEdited,
            this, &MigrationReceiveDialog::onApplyPassphraseEdited);
    connect(m_applyPassField, &QLineEdit::returnPressed,
            this, &MigrationReceiveDialog::onApplyClicked);
    root->addWidget(m_applyPassField);

    m_applyError = new QLabel(this);
    m_applyError->setStyleSheet("color: #d05050; font-size: 12px;");
    m_applyError->setWordWrap(true);
    m_applyError->setAlignment(Qt::AlignCenter);
    m_applyError->setVisible(false);
    root->addWidget(m_applyError);

    m_applyButton = new QPushButton("Apply", this);
    m_applyButton->setObjectName("primary");
    m_applyButton->setEnabled(false);
    m_applyButton->setVisible(false);
    connect(m_applyButton, &QPushButton::clicked,
            this, &MigrationReceiveDialog::onApplyClicked);
    root->addWidget(m_applyButton);

    root->addStretch(1);

    m_cancelBtn = new QPushButton("Cancel", this);
    m_cancelBtn->setObjectName("secondary");
    connect(m_cancelBtn, &QPushButton::clicked,
            this, &MigrationReceiveDialog::onCancel);
    root->addWidget(m_cancelBtn);
}

void MigrationReceiveDialog::onCopyCode()
{
    QApplication::clipboard()->setText(m_handshakeEncoded);
    if (!m_copyBtn) return;
    m_copyBtn->setText("Copied!");
    QTimer::singleShot(1500, this, [this]() {
        if (m_copyBtn) m_copyBtn->setText("Copy code");
    });
}

void MigrationReceiveDialog::onCancel()
{
    reject();
}

void MigrationReceiveDialog::onTcpConnection()
{
    if (!m_tcpServer) return;
    while (QTcpSocket *sock = m_tcpServer->nextPendingConnection()) {
        // Reject stray second-and-later connections — only one
        // migration session at a time.  A browser / port scanner
        // hitting the listener mid-flow doesn't get to disrupt
        // the in-flight transfer.
        if (m_activeSocket) {
            sock->disconnectFromHost();
            sock->deleteLater();
            continue;
        }
        m_activeSocket = sock;
        m_readBuf.clear();
        connect(sock, &QTcpSocket::readyRead,
                this, &MigrationReceiveDialog::onSocketReadyRead);
        connect(sock, &QTcpSocket::disconnected,
                this, &MigrationReceiveDialog::onSocketDisconnected);

        if (m_statusLabel) {
            m_statusLabel->setText(
                QStringLiteral("Connected to %1 — exchanging keys…")
                    .arg(sock->peerAddress().toString()));
        }
        sendPubkeysOffer();
    }
}

void MigrationReceiveDialog::sendPubkeysOffer()
{
    if (!m_activeSocket) return;
    // PubkeysOffer JSON shape mirrors iOS MigrationSession.swift's
    // `PubkeysOffer` struct: `{x25519Pub, mlkemPub}` with Data
    // fields encoded as standard base64 (Swift Codable default).
    // Key order alphabetical so QJsonObject + JSONEncoder
    // produce the same bytes — ensures iOS senders parse
    // desktop-emitted offers identically.
    QJsonObject offer;
    offer.insert("mlkemPub",
                  QString::fromLatin1(m_mlkemPub.toBase64()));
    offer.insert("x25519Pub",
                  QString::fromLatin1(m_x25519Pub.toBase64()));
    const QByteArray body =
        QJsonDocument(offer).toJson(QJsonDocument::Compact);

    // Frame: [1 byte tag][4 byte BE length][body].  Length is
    // BE uint32 over the network, decoded the same way on every
    // platform — Qt's QDataStream defaults to big-endian, so
    // matching iOS NWConnection / desktop QTcpSocket / Android
    // ServerSocket parsers stay simple.
    QByteArray frame;
    frame.reserve(1 + 4 + body.size());
    frame.append(static_cast<char>(0x01));
    const quint32 len = static_cast<quint32>(body.size());
    frame.append(static_cast<char>((len >> 24) & 0xff));
    frame.append(static_cast<char>((len >> 16) & 0xff));
    frame.append(static_cast<char>((len >>  8) & 0xff));
    frame.append(static_cast<char>((len      ) & 0xff));
    frame.append(body);
    m_activeSocket->write(frame);
}

void MigrationReceiveDialog::onSocketReadyRead()
{
    if (!m_activeSocket) return;
    m_readBuf.append(m_activeSocket->readAll());
    while (tryConsumeFrame()) { /* keep consuming */ }
}

bool MigrationReceiveDialog::tryConsumeFrame()
{
    // Need at least 1 (tag) + 4 (length) bytes for any frame.
    if (m_readBuf.size() < 5) return false;
    const auto tag = static_cast<quint8>(m_readBuf[0]);
    const quint32 len =
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[1])) << 24) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[2])) << 16) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[3])) <<  8) |
        (static_cast<quint32>(static_cast<quint8>(m_readBuf[4])));
    // Bound the body size so a malicious sender can't pin our
    // memory by claiming a multi-GB frame.  Realistic upper
    // bound for a v3 payload (identity + salt + DB snapshot +
    // settings) is well under 100 MB; cap at 256 MB for headroom.
    constexpr quint32 kMaxFrameBody = 256u * 1024u * 1024u;
    if (len > kMaxFrameBody) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — sender announced an oversized frame.");
        if (m_activeSocket) m_activeSocket->disconnectFromHost();
        return false;
    }
    if (m_readBuf.size() < static_cast<int>(5 + len)) return false;

    const QByteArray body = m_readBuf.mid(5, static_cast<int>(len));
    m_readBuf.remove(0, static_cast<int>(5 + len));

    if (tag == 0x02) {
        handleEnvelope(body);
        return true;
    }
    // 0x01 PubkeysOffer is sender→receiver in iOS's MPC flow,
    // but on desktop receivers we INITIATE with our own offer.
    // A tag we don't recognise is a protocol error — close.
    if (m_statusLabel) m_statusLabel->setText(
        QStringLiteral("Aborted — unexpected message tag 0x%1 from sender.")
            .arg(QString::number(tag, 16)));
    if (m_activeSocket) m_activeSocket->disconnectFromHost();
    return false;
}

void MigrationReceiveDialog::handleEnvelope(const QByteArray &envelope)
{
    // Decrypt via the C-side migration crypto.  Output bound:
    // payload <= envelope - overhead.  Allocate a buffer that
    // size and trust the C return value to tell us the actual
    // plaintext length.
    const int maxPlain =
        envelope.size() - P2P_MIGRATION_ENVELOPE_OVERHEAD;
    if (maxPlain <= 0) {
        if (m_statusLabel) m_statusLabel->setText(
            "Aborted — envelope is too short to be valid.");
        return;
    }
    QByteArray plain(maxPlain, '\0');
    const int rc = p2p_migration_open(
        reinterpret_cast<const uint8_t*>(envelope.constData()),
        envelope.size(),
        reinterpret_cast<const uint8_t*>(m_x25519Pub.constData()),
        reinterpret_cast<const uint8_t*>(m_x25519Priv.constData()),
        reinterpret_cast<const uint8_t*>(m_mlkemPub.constData()),
        reinterpret_cast<const uint8_t*>(m_mlkemPriv.constData()),
        reinterpret_cast<const uint8_t*>(m_nonce.constData()),
        reinterpret_cast<uint8_t*>(plain.data()),
        plain.size());
    if (rc < 0) {
        if (m_statusLabel) m_statusLabel->setText(
            "Couldn't decrypt — wrong handshake or tampered transfer.");
        return;
    }
    plain.truncate(rc);
    m_decryptedPayload = plain;
    enterApplyStage();
}

void MigrationReceiveDialog::enterApplyStage()
{
    // Hide the pairing-stage UI — once the envelope has
    // arrived, the QR + paste-code are stale (sender is done
    // with them) and would only confuse the user about what to
    // do next.  Stop the listener too: a second sender
    // connecting while we're applying serves no purpose.
    if (m_qrLabel)         m_qrLabel->setVisible(false);
    if (m_pasteHeader)     m_pasteHeader->setVisible(false);
    if (m_pasteBox)        m_pasteBox->setVisible(false);
    if (m_copyBtn)         m_copyBtn->setVisible(false);
    if (m_phaseNote)       m_phaseNote->setVisible(false);
    if (m_instructions)    m_instructions->setVisible(false);
    if (m_statusLabel)     m_statusLabel->setVisible(false);
    if (m_tcpServer) {
        m_tcpServer->close();
    }

    if (m_applyTitle)      m_applyTitle->setVisible(true);
    if (m_applyHint)       m_applyHint->setVisible(true);
    if (m_applyPassField) {
        m_applyPassField->setVisible(true);
        m_applyPassField->setFocus();
    }
    if (m_applyButton)     m_applyButton->setVisible(true);
}

void MigrationReceiveDialog::onApplyPassphraseEdited()
{
    if (m_applyError && m_applyError->isVisible()) {
        m_applyError->clear();
        m_applyError->setVisible(false);
    }
    if (m_applyButton && m_applyPassField) {
        m_applyButton->setEnabled(!m_applyPassField->text().isEmpty());
    }
}

void MigrationReceiveDialog::onApplyClicked()
{
    if (!m_applyPassField || !m_applyButton) return;
    const QString pass = m_applyPassField->text();
    if (pass.isEmpty()) return;

    // Disable the button while writing — atomic-ish: avoid a
    // double-click racing two parallel write attempts at the
    // identity files.
    m_applyButton->setEnabled(false);

    if (!writeIdentityFiles()) {
        m_applyButton->setEnabled(true);
        return;
    }

    // Files written.  Pass the passphrase up to PassphraseDialog
    // via accept() — the unlock loop in mainwindow will derive
    // the SQLCipher key from this passphrase + the migrated
    // salt and open the DB.  Wrong passphrase is detected there
    // (DB open fails); user lands back at the unlock screen + can
    // retry without re-running migration.
    m_appliedPassphrase = pass;
    m_wasApplied        = true;
    accept();
}

bool MigrationReceiveDialog::writeIdentityFiles()
{
    if (m_decryptedPayload.isEmpty()) {
        if (m_applyError) {
            m_applyError->setText("Internal error — no payload to apply.");
            m_applyError->setVisible(true);
        }
        return false;
    }

    QJsonParseError perr{};
    const QJsonDocument doc =
        QJsonDocument::fromJson(m_decryptedPayload, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        if (m_applyError) {
            m_applyError->setText(
                "Migration data is malformed.  Try again on both devices.");
            m_applyError->setVisible(true);
        }
        return false;
    }
    const QJsonObject obj = doc.object();
    const int version = obj.value("version").toInt(-1);
    if (version != 3) {
        if (m_applyError) {
            m_applyError->setText(
                "Migration data uses an incompatible format.  Update both "
                "devices to the same Peer2Pear release.");
            m_applyError->setVisible(true);
        }
        return false;
    }

    // The Codable Data fields on iOS encode as base64 strings;
    // QJsonValue::toString gives us the raw base64 to decode.
    const QByteArray identityBytes =
        QByteArray::fromBase64(obj.value("identityFile").toString().toLatin1());
    const QByteArray saltBytes =
        QByteArray::fromBase64(obj.value("saltFile").toString().toLatin1());
    // Stash the appDataSnapshot bytes (may be empty — desktop
    // senders pre-Step-4b ship an empty placeholder; iOS senders
    // always include the JSON snapshot).  Mainwindow's unlock
    // loop applies after DB open.
    m_appDataSnapshotBytes =
        QByteArray::fromBase64(obj.value("appDataSnapshot").toString().toLatin1());
    // Stash the userDefaults dict — keyed by iOS UserDefaults
    // key, each value is base64-of-JSON-wrapper.
    // `MigrationSettings::applySnapshot` decodes per-key after
    // the DB opens.  Empty when sender shipped no settings.
    m_userDefaultsObj = obj.value("userDefaults").toObject();
    if (identityBytes.isEmpty() || saltBytes.isEmpty()) {
        if (m_applyError) {
            m_applyError->setText(
                "Other device sent an empty payload.  This is likely a "
                "development build or a known bug — please report it.");
            m_applyError->setVisible(true);
        }
        return false;
    }

    // Same directory layout the unlock loop expects:
    // <AppDataLocation>/keys/{identity.json, db_salt.bin}.
    const QString keysDir = QStandardPaths::writableLocation(
        QStandardPaths::AppDataLocation) + "/keys";
    if (!QDir().mkpath(keysDir)) {
        if (m_applyError) {
            m_applyError->setText(
                QStringLiteral("Couldn't create the keys directory at %1.")
                    .arg(keysDir));
            m_applyError->setVisible(true);
        }
        return false;
    }

    // Write both files; if the second write fails after the
    // first succeeded, remove the first so the next launch
    // doesn't see a half-applied state (firstRun heuristic
    // checks for db_salt.bin only, but identity.json on its own
    // would still confuse the unlock loop).
    const QString idPath   = keysDir + "/identity.json";
    const QString saltPath = keysDir + "/db_salt.bin";
    QFile idFile(idPath);
    if (!idFile.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
        idFile.write(identityBytes) != identityBytes.size()) {
        if (m_applyError) {
            m_applyError->setText("Couldn't write identity.json to disk.");
            m_applyError->setVisible(true);
        }
        return false;
    }
    idFile.close();

    QFile saltFile(saltPath);
    if (!saltFile.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
        saltFile.write(saltBytes) != saltBytes.size()) {
        QFile::remove(idPath);   // roll back the partial state
        if (m_applyError) {
            m_applyError->setText("Couldn't write db_salt.bin to disk.");
            m_applyError->setVisible(true);
        }
        return false;
    }
    saltFile.close();

    return true;
}

void MigrationReceiveDialog::onSocketDisconnected()
{
    if (!m_activeSocket) return;
    m_activeSocket->deleteLater();
    m_activeSocket = nullptr;
    m_readBuf.clear();
    // Don't update the status label here — the last meaningful
    // line ("Payload received…" or an error) should stay visible.
    // The user closes the dialog manually after success / retry.
}
