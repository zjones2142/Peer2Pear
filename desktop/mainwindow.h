#pragma once
#include "ChatController.hpp"
#include "QtWebSocket.hpp"
#include "QtHttpClient.hpp"
#include "QtTimer.hpp"
#include <QCloseEvent>
#include <QMainWindow>
#include <QResizeEvent>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>

#include "settingspanel.h"
#include "chatview.h"
#include "ChatNotifier.h"
#include "qt_str_helpers.hpp"
#include "AppDataStore.hpp"
#include "SqlCipherDb.hpp"

#include <QByteArray>
#include <QJsonObject>

class LockOverlay;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;
    // Override close so the X button hides the window to the
    // system tray instead of quitting the process.  Lets the app
    // stay in the background to receive messages + notifications
    // — same posture as Slack / Discord / Element on desktop.
    // True quit goes through the tray menu's "Quit Peer2Pear" or
    // QApplication::quit().
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onSettingsClicked();
    void onSettingsBackClicked();
    void onExportContacts();
    void onImportContacts();
    // Tray-icon plumbing.  Single-click on Linux/Windows toggles
    // the window; macOS uses the menu only (single-click on the
    // status bar always opens the menu there).
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void showFromTray();

    // Lock-mode plumbing.  Mirrors iOS Peer2PearClient's lock /
    // quickUnlock pair — lock() routes to one of three behaviours
    // based on m_lockMode (Strict = quit; QuickWithEviction =
    // overlay + clear visible message buffers; Quick = overlay
    // only).  quickUnlock verifies against the in-memory
    // SHA-256 verifier and dismisses the overlay on success.
    void lock();
    void quickUnlock(const QString &passphrase);
    // Hooked to QApplication::applicationStateChanged: stamps
    // the background-time on transition out of Active and arms
    // the auto-lock timer when m_autoLockMinutes > 0.  On
    // transition back to Active, checks the elapsed time and
    // calls lock() if the threshold is met.
    void onApplicationStateChanged(Qt::ApplicationState state);
    void onAutoLockTimerExpired();

private:
    Ui::MainWindow  *ui;
    // App-data layer.  m_db is the raw SQLCipher handle (page-level
    // encryption); m_store is the table-level CRUD that lives on top
    // and adds per-field XChaCha20-Poly1305.  chatview / settingspanel
    // call m_store directly with AppDataStore types; Qt↔std conversion
    // happens at render/save sites via qt_str_helpers.hpp.
    SqlCipherDb        m_db;
    AppDataStore       m_store;
    // Factory replaces the previous single QtWebSocket member: it
    // creates fresh QtWebSocket instances per RelayClient subscribe
    // (one for the primary, one per addSubscribeRelay()).  Each
    // QtWebSocket is parented to MainWindow for thread affinity.
    QtWebSocketFactory m_wsFactory;
    QtHttpClient       m_httpClient;
    QtTimerFactory     m_timerFactory;
    ChatController     m_controller;
    ChatView        *m_chatView      = nullptr;
    ChatNotifier    *m_notifier      = nullptr;
    QStackedWidget  *m_mainStack     = nullptr;
    SettingsPanel   *m_settingsPanel = nullptr;

    // System tray icon.  Created in MainWindow's constructor when
    // QSystemTrayIcon::isSystemTrayAvailable() is true.  Owned by
    // the MainWindow as a Qt parent; auto-cleaned on destruction.
    // Null on platforms / desktop environments where the tray is
    // unavailable — closeEvent then falls back to a real quit.
    QSystemTrayIcon *m_tray              = nullptr;
    // Set on paths that should bypass closeEvent's hide-to-tray
    // and let the close fall through to a real quit — currently:
    // (a) tray menu's "Quit Peer2Pear", (b) Strict-mode lock().
    bool             m_bypassHideToTray  = false;
    bool             m_shownTrayHint     = false;  // gate one-time "still running" balloon

    // Lock state.  m_isUILocked tracks the runtime overlay flag;
    // m_verifierSalt + m_verifierHash drive the in-memory quick-
    // unlock compare (SHA-256 of salt + passphrase, matching
    // iOS).  Verifier is wiped in Strict mode (where lock=quit
    // anyway, so the in-memory copy never outlives the lock).
    LockOverlay *m_lockOverlay = nullptr;
    bool         m_isUILocked   = false;
    QByteArray   m_verifierSalt;
    QByteArray   m_verifierHash;
    void         recordVerifier(const QString &passphrase);
    bool         verifyPassphrase(const QString &passphrase) const;
    /// Position the overlay over m_mainStack and bring it to the
    /// top of the z-order.  Idempotent.
    void         showLockOverlay();
    void         hideLockOverlay();
    /// Re-position the overlay whenever the main stack resizes.
    /// resizeEvent calls this so the overlay tracks window size.
    void         updateLockOverlayGeometry();

    // Auto-lock timer.  Independent of m_resizeDebounce — fires
    // once after the user-configured idle window expires while
    // the app is in the Suspended / Hidden state.  On Active
    // re-entry we cancel + re-evaluate to avoid firing a stale
    // lock() against a now-foregrounded session.
    QTimer       m_autoLockTimer;

    // Debounce: only reload bubbles after resize activity stops
    QTimer m_resizeDebounce;

    // Top-bar relay-status indicator.  Mirrors the iOS connectivity
    // popover (wifi icon → tap → card showing "Connected" / "Offline"
    // + relay URL + backup relays).  Tracks live state via the
    // RelayClient's onConnected / onDisconnected callbacks; click
    // the 📡 button to see the popover.
    bool m_relayConnected = false;
    void updateConnectivityIndicator();
    void showConnectivityPopover();

    /// Pending JSON `MigrationAppDataSnapshot` bytes the unlock
    /// loop will apply after the DB opens.  Stashed at MainWindow
    /// scope (rather than the PassphraseDialog's local scope) so a
    /// wrong-passphrase retry loop doesn't lose the snapshot — the
    /// migration wrote identity files but the user still needs to
    /// derive the right key + open the DB before chat history can
    /// land.  Cleared on successful apply.
    QByteArray  m_pendingMigrationSnapshot;
    /// Pending `MigrationPayload.userDefaults` dict from a
    /// migration receive.  Same wrong-passphrase-retry rationale
    /// as `m_pendingMigrationSnapshot` — stashed at MainWindow
    /// scope, applied via `MigrationSettings::applySnapshot`
    /// after the DB opens, then cleared.
    QJsonObject m_pendingMigrationSettings;

    // ── Migration helpers ─────────────────────────────────────────────────────
    // Serialize the local AppDataStore to the wire-format JSON the
    // iOS receiver expects (`MigrationAppDataSnapshot` v1 — see
    // ios/.../Migration/MigrationAppDataSnapshot.swift).  Walks the
    // store via its public CRUD readers; all field-encrypted fields
    // are read in plaintext form (the JSON is itself encrypted by
    // the migration AEAD before going on the wire).
    QByteArray buildMigrationAppDataSnapshot() const;
    /// Apply a `MigrationAppDataSnapshot` (JSON bytes) to the
    /// already-keyed local AppDataStore.  Called by the unlock
    /// loop once the migrated identity files have been written
    /// and the DB is open.  Returns false on JSON parse / version
    /// mismatch; individual row-write failures are swallowed +
    /// counted so a partial migration succeeds rather than
    /// stranding the user with no chat history.
    bool applyMigrationAppDataSnapshot(const QByteArray &snapshotJson);
};
