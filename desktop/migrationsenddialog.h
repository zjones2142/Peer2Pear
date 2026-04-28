#pragma once
#include <QDialog>
#include <QByteArray>
#include <QJsonObject>
#include <QString>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTcpSocket;

// MigrationSendDialog — desktop sender for device-to-device
// migration.  Opens via "Transfer to new device" in Settings on
// the unlocked source device.  Mirrors iOS TransferSendView's
// flow: paste/scan the receiver's handshake QR, connect over
// LAN TCP to addr:port from the v2 handshake, verify the
// receiver's pubkeys against the QR fingerprint, build the
// payload (identity.json + db_salt.bin + AppDataSnapshot +
// settings), seal via p2p_migration_seal, ship the envelope.
//
// Wire format on the socket matches the desktop receiver +
// future iOS NWConnection sender: `[1 byte tag][4 byte BE
// length][body]`.  Tag 0x01 = PubkeysOffer (receiver→sender),
// 0x02 = Envelope (sender→receiver).
//
// Phase coverage: this dialog implements steps 1-7 of the iOS
// sender flow.  AppDataSnapshot + UserDefaults snippets in the
// payload are empty in this cut (Step 4 will populate them
// once the receiver-side apply path is wired).  Identity-only
// migration is enough to validate the transport end-to-end.
class MigrationSendDialog : public QDialog
{
    Q_OBJECT

public:
    /// `appDataSnapshotJson` — JSON-encoded `MigrationAppDataSnapshot`
    /// bytes the caller already built from the live AppDataStore.
    /// `userDefaults` — already-translated UserDefaults dict
    /// (iOS-keyed; values are base64-of-JSON-wrapper).
    /// Both pre-built by MainWindow because the dialog doesn't
    /// have access to m_store / SettingsPanel — keeps the dialog
    /// transport-only.  Empty values are valid (degraded-but-
    /// functional migration).
    explicit MigrationSendDialog(const QString &keysDir,
                                  const QByteArray &appDataSnapshotJson,
                                  const QJsonObject &userDefaults,
                                  QWidget *parent = nullptr);
    ~MigrationSendDialog() override;

private slots:
    void onPasteEdited();
    void onConnectClicked();
    void onCancel();
    void onSocketConnected();
    void onSocketReadyRead();
    void onSocketError();

private:
    void buildUi();
    /// Decode the pasted/scanned handshake string.  Stores
    /// fingerprint/nonce/addr/port in members on success;
    /// returns false + surfaces inline error on malformed
    /// input.  Mirrors iOS MigrationHandshake.decode validation
    /// (version 1 or 2; fingerprint = 16; nonce = 16; addr+port
    /// both-or-neither; port 1-65535).
    bool decodeHandshake(const QString &encoded);
    bool tryConsumeFrame();
    /// Verify fingerprint(receivedPubkeys) matches the handshake
    /// fingerprint we got from the QR.  MITM detector.
    void handlePubkeysOffer(const QByteArray &json);
    /// Build the MigrationPayload, seal, ship the envelope.
    /// Returns false on local build / seal error (file read,
    /// JSON encode, crypto failure).  Surfaces inline.
    bool buildAndSendEnvelope();

    const QString     m_keysDir;          // ~/Library/Application Support/.../keys
    const QByteArray  m_appDataSnapshotJson;
    const QJsonObject m_userDefaults;
    QByteArray     m_handshakeFingerprint;
    QByteArray     m_handshakeNonce;
    QByteArray     m_recvX25519Pub;    // populated from PubkeysOffer
    QByteArray     m_recvMlkemPub;
    QString        m_recvAddr;
    quint16        m_recvPort = 0;

    QTcpSocket    *m_socket    = nullptr;
    QByteArray     m_readBuf;
    bool           m_envelopeSent = false;

    QPlainTextEdit *m_pasteBox     = nullptr;
    QLabel         *m_statusLabel  = nullptr;
    QLabel         *m_errorLabel   = nullptr;
    QPushButton    *m_connectBtn   = nullptr;
    QPushButton    *m_cancelBtn    = nullptr;
};
