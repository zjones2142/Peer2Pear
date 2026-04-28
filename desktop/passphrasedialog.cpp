#include "passphrasedialog.h"
#include "peer2pear.h"  // P2P_MIN_PASSPHRASE_BYTES
#include "migrationreceivedialog.h"

#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QFrame>
#include <QInputDialog>
#include <QMessageBox>
#include <QDir>
#include <QSettings>
#include <QStandardPaths>
#include <QTimer>
#include <QSpacerItem>

namespace {

// Match iOS's `kMinPassphraseLength` and the core's
// P2P_MIN_PASSPHRASE_BYTES.  Surface inline rather than letting
// the unlock fail downstream with a vague error.
constexpr int kMinPassphraseLength = 8;

}  // namespace

PassphraseDialog::PassphraseDialog(Mode mode, QWidget *parent)
    : QDialog(parent)
    , m_mode(mode)
{
    setWindowTitle(mode == CreateNew ? "Welcome to Peer2Pear"
                                       : "Unlock Peer2Pear");
    setModal(true);
    // Sized so the layout doesn't reflow when the confirm field +
    // warning card reveal/hide on the CreateNew branch.  Width
    // comfortable for "Save this passphrase somewhere safe…" copy
    // wrap on two lines.
    setMinimumSize(440, 520);

    buildUi();
    updateState();
}

PassphraseDialog::~PassphraseDialog() = default;

void PassphraseDialog::buildUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(32, 32, 32, 24);
    root->setSpacing(14);

    // ── Brand header ─────────────────────────────────────────
    // Logo lives in the resources.qrc; if missing for any reason
    // the QLabel falls back to its empty pixmap.  Centered.
    auto *logo = new QLabel(this);
    logo->setAlignment(Qt::AlignCenter);
    QPixmap pm(":/icons/peer2pear.png");
    if (!pm.isNull()) {
        logo->setPixmap(pm.scaledToHeight(64, Qt::SmoothTransformation));
    } else {
        // Text fallback — green bubble emoji as a recognizable
        // placeholder so the dialog still looks intentional even
        // without the real asset.
        logo->setText(QStringLiteral("💬"));
        logo->setStyleSheet("font-size: 56px;");
    }
    root->addWidget(logo);

    auto *title = new QLabel("Peer2Pear", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("color: #ffffff; font-size: 26px; font-weight: bold;");
    root->addWidget(title);

    auto *tagline = new QLabel(this);
    tagline->setAlignment(Qt::AlignCenter);
    tagline->setWordWrap(true);
    tagline->setStyleSheet("color: #888888; font-size: 13px;");
    tagline->setText(m_mode == CreateNew
        ? QStringLiteral("Private messaging.\nNo phone number.  No servers you don't control.")
        : QStringLiteral("Welcome back.\nEnter your passphrase to unlock."));
    root->addWidget(tagline);

    root->addSpacing(8);

    // ── Passphrase field ─────────────────────────────────────
    m_passField = new QLineEdit(this);
    m_passField->setEchoMode(QLineEdit::Password);
    m_passField->setPlaceholderText("Passphrase");
    m_passField->setStyleSheet(
        "QLineEdit { background-color: #1a1a1a; color: #f0f0f0; "
        "border: 1px solid #2a2a2a; border-radius: 8px; "
        "padding: 8px 12px; font-size: 14px; }"
        "QLineEdit:focus { border-color: #3a9e48; }");
    connect(m_passField, &QLineEdit::textEdited,
            this, &PassphraseDialog::onPassphraseEdited);
    connect(m_passField, &QLineEdit::returnPressed,
            this, &PassphraseDialog::onSubmit);
    root->addWidget(m_passField);

    // ── Confirm field (CreateNew only, hidden until length gate) ─
    m_confirmField = new QLineEdit(this);
    m_confirmField->setEchoMode(QLineEdit::Password);
    m_confirmField->setPlaceholderText("Confirm passphrase");
    m_confirmField->setStyleSheet(m_passField->styleSheet());
    m_confirmField->setVisible(false);
    connect(m_confirmField, &QLineEdit::textEdited,
            this, &PassphraseDialog::onConfirmEdited);
    connect(m_confirmField, &QLineEdit::returnPressed,
            this, &PassphraseDialog::onSubmit);
    root->addWidget(m_confirmField);

    // ── Hint line (always visible, content per state) ────────
    m_hintLabel = new QLabel(this);
    m_hintLabel->setWordWrap(true);
    m_hintLabel->setStyleSheet("color: #888888; font-size: 11px;");
    root->addWidget(m_hintLabel);

    // ── Warning card (CreateNew only, revealed with confirm) ─
    // Orange-tinted rounded card, mirrors iOS's first-launch
    // unrecoverable-data warning toast.
    m_warningCard = new QFrame(this);
    m_warningCard->setObjectName("warningCard");
    m_warningCard->setStyleSheet(
        "QFrame#warningCard { background-color: rgba(255, 165, 0, 30); "
        "border: 1px solid rgba(255, 165, 0, 130); "
        "border-radius: 8px; }"
        "QFrame#warningCard QLabel { color: #ffb84d; }");
    auto *wLayout = new QHBoxLayout(m_warningCard);
    wLayout->setContentsMargins(12, 10, 12, 10);
    wLayout->setSpacing(10);
    auto *wIcon = new QLabel("⚠️", m_warningCard);
    wIcon->setAlignment(Qt::AlignTop);
    wLayout->addWidget(wIcon);
    auto *wText = new QLabel(
        "Save this passphrase somewhere safe.  If you forget it, your data is "
        "permanently unrecoverable — there's no recovery email or reset link.",
        m_warningCard);
    wText->setWordWrap(true);
    wText->setStyleSheet("font-size: 11px;");
    wLayout->addWidget(wText, /*stretch=*/1);
    m_warningCard->setVisible(false);
    root->addWidget(m_warningCard);

    root->addStretch(1);

    // ── Submit button ────────────────────────────────────────
    m_submitButton = new QPushButton(
        m_mode == CreateNew ? "Get Started" : "Unlock",
        this);
    m_submitButton->setStyleSheet(
        "QPushButton { background-color: #2e8b3a; color: #ffffff; "
        "border: none; border-radius: 8px; padding: 10px 16px; "
        "font-size: 14px; font-weight: bold; }"
        "QPushButton:hover:enabled { background-color: #38a844; }"
        "QPushButton:disabled { background-color: #1a3a1f; color: #666666; }");
    m_submitButton->setMinimumHeight(40);
    m_submitButton->setDefault(true);
    connect(m_submitButton, &QPushButton::clicked,
            this, &PassphraseDialog::onSubmit);
    root->addWidget(m_submitButton);

    // ── Footer affordances ───────────────────────────────────
    // Forgot Password on Unlock branch (recovery path); Transfer
    // from another device on CreateNew branch (Phase 2 hook).
    auto *footer = new QHBoxLayout();
    footer->setContentsMargins(0, 4, 0, 0);
    footer->setSpacing(12);

    if (m_mode == Unlock) {
        m_forgotBtn = new QPushButton("Forgot Password?", this);
        m_forgotBtn->setFlat(true);
        m_forgotBtn->setStyleSheet(
            "QPushButton { color: #888888; background: transparent; "
            "border: none; font-size: 11px; }"
            "QPushButton:hover { color: #aaaaaa; }");
        m_forgotBtn->setCursor(Qt::PointingHandCursor);
        connect(m_forgotBtn, &QPushButton::clicked,
                this, &PassphraseDialog::onForgotPassword);
        footer->addStretch(1);
        footer->addWidget(m_forgotBtn);
        footer->addStretch(1);
    } else {  // CreateNew
        m_transferBtn = new QPushButton("Transfer from another device", this);
        m_transferBtn->setFlat(true);
        m_transferBtn->setStyleSheet(
            "QPushButton { color: #888888; background: transparent; "
            "border: none; font-size: 11px; }"
            "QPushButton:hover { color: #aaaaaa; }");
        m_transferBtn->setCursor(Qt::PointingHandCursor);
        connect(m_transferBtn, &QPushButton::clicked,
                this, &PassphraseDialog::onTransferFromAnotherDevice);
        footer->addStretch(1);
        footer->addWidget(m_transferBtn);
        footer->addStretch(1);
    }

    root->addLayout(footer);

    // Window-level styling: dark background matching the rest of
    // the app.  Picked up by buildUi above for child widgets.
    setStyleSheet("QDialog { background-color: #0a0a0a; }");
}

// MARK: - State updates

void PassphraseDialog::onPassphraseEdited()
{
    // Mirror iOS's onChange-of-passphrase reset: when the primary
    // shrinks below the length gate, hide the confirm field and
    // wipe its value so a stale confirm can't sneak back into
    // view when the primary re-grows.
    if (m_mode == CreateNew
        && m_passField->text().toUtf8().size() < kMinPassphraseLength) {
        if (!m_confirmField->text().isEmpty()) m_confirmField->clear();
    }
    updateState();
}

void PassphraseDialog::onConfirmEdited()
{
    updateState();
}

void PassphraseDialog::updateState()
{
    const QByteArray bytes  = m_passField->text().toUtf8();
    const int        length = bytes.size();

    const bool lengthOK    = length >= kMinPassphraseLength;
    const bool showConfirm = m_mode == CreateNew && lengthOK;

    if (m_confirmField->isVisible() != showConfirm) {
        m_confirmField->setVisible(showConfirm);
    }
    if (m_warningCard->isVisible() != showConfirm) {
        m_warningCard->setVisible(showConfirm);
    }

    // Hint text — instructional, not error-shaped (orange) unless
    // user is actively below the length gate after typing.
    QString hint;
    QString hintColor = "#888888";
    if (length == 0) {
        hint = m_mode == CreateNew
            ? QStringLiteral("Passphrase protects your identity key on this device.")
            : QStringLiteral("Your passphrase unlocks this device's identity key.");
    } else if (!lengthOK) {
        hint = QStringLiteral("At least %1 characters (%2/%1).")
                   .arg(kMinPassphraseLength).arg(length);
        hintColor = "#ffb84d";  // orange — gentle "not done yet"
    } else if (m_mode == CreateNew && m_confirmField->text().isEmpty()) {
        hint = QStringLiteral("Re-enter to confirm.");
    } else if (m_mode == CreateNew
               && m_confirmField->text() != m_passField->text()) {
        // Stay neutral on mismatch — don't surface "passphrases
        // don't match" in real time (mirrors iOS rationale: the
        // live flip leaks match-state info to anyone observing).
        hint = QStringLiteral("Re-enter to confirm.");
    } else {
        hint = QStringLiteral("Looks good.");
    }
    m_hintLabel->setText(hint);
    m_hintLabel->setStyleSheet(
        QStringLiteral("color: %1; font-size: 11px;").arg(hintColor));

    m_submitButton->setEnabled(validateForSubmit());
}

bool PassphraseDialog::validateForSubmit() const
{
    const int length = m_passField->text().toUtf8().size();
    if (length < kMinPassphraseLength) return false;
    if (m_mode == CreateNew) {
        if (m_confirmField->text() != m_passField->text()) return false;
    }
    return true;
}

// MARK: - Actions

void PassphraseDialog::onSubmit()
{
    if (!validateForSubmit()) return;
    m_passphrase = m_passField->text();
    accept();
}

void PassphraseDialog::onForgotPassword()
{
    // Type-RESET-to-confirm wipe — mirrors iOS's Forgot Password
    // recovery path + desktop's Settings → Factory Reset.  The
    // user's data is gone after this; we explicitly require them
    // to type a confirmation phrase rather than gating behind a
    // single OK click.
    bool ok = false;
    const QString typed = QInputDialog::getText(
        this,
        "Reset Identity",
        QStringLiteral(
            "There's no way to recover a forgotten passphrase — your data is "
            "encrypted with it.  The only path forward is to erase everything "
            "on this device and start over.\n\n"
            "Type RESET to confirm."),
        QLineEdit::Normal,
        "",
        &ok);
    if (!ok || typed != QLatin1String("RESET")) return;

    wipeAppDataAndAccept();
}

void PassphraseDialog::wipeAppDataAndAccept()
{
    // Mirrors mainwindow.cpp's factoryResetClicked handler:
    // remove every file in AppDataLocation + clear QSettings.
    // Difference: no DB to close here (we haven't unlocked).
    const QString base = QStandardPaths::writableLocation(
        QStandardPaths::AppDataLocation);
    if (!base.isEmpty()) {
        QDir d(base);
        if (d.exists()) d.removeRecursively();
    }
    QSettings().clear();

    m_wasReset = true;
    m_passphrase.clear();
    accept();
}

void PassphraseDialog::onTransferFromAnotherDevice()
{
    MigrationReceiveDialog dlg(this);
    dlg.exec();
    // If the receive dialog ran to completion (decrypted the
    // envelope, user typed the source passphrase, identity files
    // landed on disk), forward the passphrase up to the unlock
    // loop by accepting ourselves with the migrated passphrase.
    // The unlock loop then derives the SQLCipher key against the
    // migrated salt + opens the DB — same code path as a
    // returning-user unlock, no migration-specific branch needed.
    // Cancellation leaves the dialog open so the user can still
    // pick Unlock / Get Started.
    if (dlg.wasApplied()) {
        m_passphrase             = dlg.appliedPassphrase();
        m_pendingAppDataSnapshot = dlg.appDataSnapshotBytes();
        m_pendingUserDefaults    = dlg.userDefaultsObject();
        m_wasMigrationApplied    = true;
        accept();
    }
}
