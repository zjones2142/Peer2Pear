#pragma once
#include <QDialog>
#include <QByteArray>
#include <QJsonObject>
#include <QString>

class QLabel;
class QPushButton;
class QPlainTextEdit;
class QTcpServer;

// MigrationReceiveDialog — desktop receiver-side scaffolding for
// device-to-device migration (project_backup_strategy.md step 2).
// Mirrors iOS TransferReceiveView's "advertising" state: generate
// ephemeral X25519 + ML-KEM-768 keypairs, compute the 16-byte
// fingerprint, render a QR + manual-paste code carrying the same
// base64url-of-JSON handshake the iOS receiver displays.
//
// Phase A (this cut): UI + key derivation + handshake encoding
// only.  No transport plumbing — the dialog sits at "waiting for
// sender" and offers a Cancel button.  Phase B will add the
// relay-mediated channel + envelope receive path; Phase C will
// add the apply (decrypt envelope, write identity files, re-run
// the unlock loop).
//
// The keypair private bytes are wiped via libsodium's sodium_memzero
// in the destructor — the QByteArrays holding them are
// best-effort-zeroed on dialog close.
class MigrationReceiveDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MigrationReceiveDialog(QWidget *parent = nullptr);
    ~MigrationReceiveDialog() override;

public:
    /// Plaintext payload (JSON `MigrationPayload` bytes) once a
    /// sender has connected, sent the envelope, and decrypt
    /// succeeded.  Empty until then.
    QByteArray decryptedPayload() const { return m_decryptedPayload; }

    /// True once the user has typed the source-device passphrase
    /// AND the identity files have been written to disk.  At
    /// that point `appliedPassphrase()` is valid and
    /// PassphraseDialog can pass it up to the unlock loop.
    bool wasApplied() const { return m_wasApplied; }

    /// The source-device passphrase the user typed in the apply
    /// stage.  Caller is responsible for `secureZeroQ` after
    /// it's been consumed.
    QString appliedPassphrase() const { return m_appliedPassphrase; }

    /// JSON-encoded `MigrationAppDataSnapshot` bytes extracted
    /// from the payload's `appDataSnapshot` field.  Empty when
    /// the sender shipped an identity-only migration (early
    /// versions of the desktop sender did this; iOS senders
    /// always include the snapshot).  Caller (mainwindow's
    /// unlock loop, after DB open) decodes + bulk-inserts.
    QByteArray appDataSnapshotBytes() const { return m_appDataSnapshotBytes; }

    /// `MigrationPayload.userDefaults` JSON object — keyed by
    /// iOS UserDefaults key, each value is a base64-of-JSON-
    /// wrapper-object blob.  Empty when the sender shipped no
    /// settings (default-only iOS / pre-Step-4c desktop).
    /// Caller passes through to `MigrationSettings::applySnapshot`
    /// after the DB opens.
    QJsonObject userDefaultsObject() const { return m_userDefaultsObj; }

private slots:
    void onCopyCode();
    void onCancel();
    void onTcpConnection();   // QTcpServer::newConnection
    void onSocketReadyRead();
    void onSocketDisconnected();
    void onApplyPassphraseEdited();
    void onApplyClicked();

private:
    void buildUi();
    /// Generate the keypairs + nonce and populate m_handshakeEncoded
    /// with the base64url-of-JSON the QR + paste-box display.
    /// Returns false on libsodium / liboqs error — caller surfaces
    /// the error inline rather than showing a broken QR.
    bool prepareSession();

    // Handshake material — generated once on construction, kept
    // alive for the lifetime of the dialog so Phase B / C can
    // pick them up via getters when those land.
    QByteArray m_x25519Pub;
    QByteArray m_x25519Priv;
    QByteArray m_mlkemPub;
    QByteArray m_mlkemPriv;
    QByteArray m_fingerprint;       // 16 bytes
    QByteArray m_nonce;              // 16 bytes
    QString    m_handshakeEncoded;   // base64url-of-JSON for QR + paste

    QLabel         *m_qrLabel       = nullptr;
    QPlainTextEdit *m_pasteBox      = nullptr;
    QPushButton    *m_copyBtn       = nullptr;
    QLabel         *m_statusLabel   = nullptr;
    QPushButton    *m_cancelBtn     = nullptr;
    QLabel         *m_phaseNote     = nullptr;
    QLabel         *m_pasteHeader   = nullptr;
    QLabel         *m_instructions  = nullptr;

    /// Apply-stage UI — hidden until envelope decrypts.  Once
    /// shown, the QR + paste-box panel hides; user types the
    /// source-device passphrase + clicks Apply, which writes
    /// identity.json + db_salt.bin and accepts the dialog.
    class QLineEdit *m_applyPassField  = nullptr;
    QLabel          *m_applyTitle      = nullptr;
    QLabel          *m_applyHint       = nullptr;
    QLabel          *m_applyError      = nullptr;
    QPushButton     *m_applyButton     = nullptr;
    QString          m_appliedPassphrase;
    QByteArray       m_appDataSnapshotBytes;
    QJsonObject      m_userDefaultsObj;
    bool             m_wasApplied      = false;
    /// Switch the dialog UI to the apply-stage layout.  Called
    /// from `handleEnvelope` after `p2p_migration_open` succeeds.
    void enterApplyStage();
    /// Parse `m_decryptedPayload` as `MigrationPayload` JSON,
    /// extract identity + salt bytes, write to disk.  Returns
    /// false on JSON / IO error and surfaces the message via
    /// `m_applyError`.
    bool writeIdentityFiles();

    /// LAN TCP listener.  Bound on QHostAddress::Any with an
    /// ephemeral port chosen by the OS; the actual port + the
    /// device's primary RFC1918 IPv4 address get embedded in the
    /// v2 handshake JSON so the sender can reach us directly.
    /// Stub-only in Phase A (logs incoming + closes); Phase B
    /// adds the framed PubkeysOffer + Envelope read path.
    QTcpServer *m_tcpServer = nullptr;
    QString     m_listenAddr;
    quint16     m_listenPort = 0;

    /// Active migration socket — only one allowed at a time.
    /// Subsequent connections get rejected so a stray browser
    /// or scanner can't disrupt the in-flight transfer.
    class QTcpSocket *m_activeSocket = nullptr;
    /// Accumulated read buffer for the framed parser.  Frames
    /// are `[1 tag][4 BE length][body]`; bytes accumulate here
    /// until a full frame is available, then it's consumed.
    QByteArray m_readBuf;
    /// Decrypted MigrationPayload bytes (Step 2 surfaces; Step 4
    /// applies).  Empty until envelope decrypt succeeds.
    QByteArray m_decryptedPayload;

    /// Send the receiver's PubkeysOffer (`[0x01][len][JSON]`) to
    /// the sender.  Called once on successful connection.  The
    /// sender then verifies SHA-256(received pubkeys) matches
    /// the QR fingerprint before sealing the envelope.
    void sendPubkeysOffer();
    /// Process accumulated bytes from `m_readBuf`; consume any
    /// complete frame.  Returns false on protocol error (caller
    /// closes the socket + surfaces the error in status).
    bool tryConsumeFrame();
    /// Handle a 0x02 envelope frame — decrypt via
    /// `p2p_migration_open`, populate `m_decryptedPayload`,
    /// surface success/failure in the status row.
    void handleEnvelope(const QByteArray &envelope);
};
