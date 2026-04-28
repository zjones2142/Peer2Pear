#pragma once
#include <QDialog>
#include <QByteArray>
#include <QJsonObject>
#include <QString>

class QLineEdit;
class QLabel;
class QPushButton;
class QFrame;
class QVBoxLayout;

// PassphraseDialog — branded first-run / unlock screen for desktop.
//
// Replaces the older QInputDialog-based prompts in mainwindow.cpp's
// identity-unlock loop with a proper window that mirrors iOS's
// OnboardingView shape: brand mark + tagline + passphrase field(s)
// + warning toast + secondary affordances (Forgot Password,
// Transfer from another device).
//
// Two modes:
//   * CreateNew  — first-run.  Passphrase + confirm field + orange
//                   "data is permanently unrecoverable" warning
//                   reveal once the user clears the 8-char gate.
//                   "Get Started" submits.  Footer offers
//                   "Transfer from another device" (Phase 2 hook).
//
//   * Unlock     — returning user.  Single passphrase field, "Unlock"
//                   button.  Footer offers "Forgot Password?" — same
//                   type-RESET-to-confirm wipe the iOS Onboarding
//                   uses, mirrored here so a forgotten-passphrase
//                   user has a recovery path beyond reinstalling.
//
// Result is read via the getters after exec() returns.
class PassphraseDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode { CreateNew, Unlock };

    explicit PassphraseDialog(Mode mode, QWidget *parent = nullptr);
    ~PassphraseDialog() override;

    /// The passphrase the user typed.  Empty if the dialog was
    /// dismissed via Cancel / X.  Caller is responsible for
    /// secureZeroQ()-ing it once the unlock attempt finishes.
    QString passphrase() const { return m_passphrase; }

    /// True when the user chose Forgot Password and confirmed
    /// the type-RESET-to-confirm wipe.  By the time exec()
    /// returns with this true, the app data directory has
    /// already been removed; caller should restart the unlock
    /// loop (which will see firstRun=true since the salt is
    /// gone) rather than trying to apply the (empty) passphrase.
    bool wasReset() const { return m_wasReset; }

    /// True when the user chose "Transfer from another device".
    /// On a successful migration the receive dialog applies the
    /// new identity files to disk and we accept() with
    /// `passphrase()` populated — the unlock loop then derives
    /// the SQLCipher key against the migrated salt and opens
    /// the DB normally (no separate code path needed).  Set
    /// without `wasMigrationApplied()` only when the user
    /// cancelled mid-flow.
    bool wasTransferRequested() const { return m_wasTransferRequested; }

    /// True when the migration receive dialog wrote identity.json
    /// + db_salt.bin to disk and surfaced the source-device
    /// passphrase via `passphrase()`.  Caller (mainwindow's
    /// unlock loop) treats this exactly like a returning-user
    /// unlock — derive against the migrated salt + open the DB.
    bool wasMigrationApplied() const { return m_wasMigrationApplied; }

    /// JSON-encoded `MigrationAppDataSnapshot` bytes from the
    /// migration receive flow.  Empty when the sender shipped
    /// identity-only.  Mainwindow's unlock loop applies this to
    /// AppDataStore AFTER opening the DB — a snapshot that
    /// arrives before the DB is keyed has nowhere to land.
    QByteArray pendingAppDataSnapshot() const { return m_pendingAppDataSnapshot; }

    /// `MigrationPayload.userDefaults` dict from the receive
    /// flow.  Keyed by iOS UserDefaults keys.
    /// `MigrationSettings::applySnapshot` consumes this after
    /// the unlock loop opens the DB.  Empty when sender shipped
    /// no settings.
    QJsonObject pendingUserDefaults() const { return m_pendingUserDefaults; }

private slots:
    void onPassphraseEdited();
    void onConfirmEdited();
    void onSubmit();
    void onForgotPassword();
    void onTransferFromAnotherDevice();

private:
    void buildUi();
    void updateState();    // hint text, warning visibility, button enable
    bool validateForSubmit() const;
    void wipeAppDataAndAccept();

    const Mode   m_mode;
    QString      m_passphrase;
    QByteArray   m_pendingAppDataSnapshot;
    QJsonObject  m_pendingUserDefaults;
    bool         m_wasReset             = false;
    bool         m_wasTransferRequested = false;
    bool         m_wasMigrationApplied  = false;

    QLineEdit   *m_passField    = nullptr;
    QLineEdit   *m_confirmField = nullptr;
    QFrame      *m_warningCard  = nullptr;
    QLabel      *m_hintLabel    = nullptr;
    QPushButton *m_submitButton = nullptr;
    QPushButton *m_forgotBtn    = nullptr;
    QPushButton *m_transferBtn  = nullptr;
};
