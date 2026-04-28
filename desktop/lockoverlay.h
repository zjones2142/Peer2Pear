#pragma once
#include <QWidget>
#include <QString>

class QLineEdit;
class QLabel;
class QPushButton;

// LockOverlay — desktop equivalent of iOS's LockOverlay in
// Peer2PearApp.swift.  Shown over the main chat UI when the user
// has locked the app but the underlying session is still alive
// (lock modes Quick / QuickWithEviction).  Strict on desktop
// quits the process instead of going through this overlay — see
// MainWindow::lock().
//
// Layout mirrors PassphraseDialog's Unlock branch but lives
// embedded in the main window rather than as a modal dialog —
// keeps the tray interaction responsive (clicking Show from the
// tray brings the window forward to the unlock prompt instead of
// stacking another modal on top).
//
// Signals back via unlockRequested(); MainWindow drives the
// actual verifier compare + state restore via quickUnlock().
class LockOverlay : public QWidget
{
    Q_OBJECT

public:
    explicit LockOverlay(QWidget *parent = nullptr);

    /// Reset the overlay's password field + error label and focus
    /// the field — call when raise()-ing it so the user lands on
    /// a clean state every lock cycle.
    void prepareForShow();

    /// Surface a "Wrong passphrase" error inline + clear the field.
    /// MainWindow calls this when quickUnlock returns false.
    void showWrongPassphrase();

signals:
    /// Emitted when the user submits the field.  MainWindow
    /// passes the typed passphrase into its quickUnlock path
    /// and either hides the overlay (on success) or calls
    /// showWrongPassphrase() (on miss).
    void unlockRequested(const QString &passphrase);

private slots:
    void onSubmit();
    void onTextEdited();

private:
    void buildUi();

    QLineEdit   *m_passField    = nullptr;
    QLabel      *m_errorLabel   = nullptr;
    QPushButton *m_submitButton = nullptr;
};
