#ifndef SETTINGSPANEL_H
#define SETTINGSPANEL_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QSpinBox>
#include <QComboBox>

class AppDataStore;

class SettingsPanel : public QWidget
{
    Q_OBJECT

public:
    // Notification-content privacy mode.  Controls how much plaintext
    // reaches the OS-level notification store (macOS NotificationCenter
    // DB, Windows Action Center, Linux notification daemons) where
    // forensic tools can read it even after the app wipes its own
    // state.  Default is Hidden — generic banner only.  See the
    // matching enum on iOS (Peer2PearClient.NotificationContentMode).
    enum class NotificationMode {
        Hidden     = 0,   // "Peer2Pear — new message"
        SenderOnly = 1,   // "<senderName> sent a new message"
        Full       = 2    // "<senderName>: <message text>"
    };

    explicit SettingsPanel(QWidget *parent = nullptr);

    // Returns whether notifications are currently enabled
    bool notificationsEnabled() const { return m_notificationsEnabled; }

    // Currently-selected notification content mode.  Defaults to
    // Hidden (most private) until the user explicitly opts up.
    NotificationMode notificationMode() const { return m_notifMode; }

    // Call after construction to populate profile fields
    void setProfileInfo(const QString &displayName, const QString &publicKey);

    // Attach the app-data store for persisting settings, then load saved state
    void setAppDataStore(AppDataStore *store);

signals:
    void backClicked();
    void notificationsToggled(bool enabled);
    void notificationModeChanged(SettingsPanel::NotificationMode mode);
    void exportContactsClicked();
    void importContactsClicked();

    // Open the Archived Chats recovery dialog.  MainWindow listens
    // and routes through ChatView so the underlying chat list can
    // be re-synced after Restore / Delete.
    void archivedChatsClicked();

    // File-transfer consent settings changed.
    void fileAutoAcceptMaxChanged(int mb);
    void fileHardMaxChanged(int mb);
    void fileRequireP2PToggled(bool on);

    // When on, files from peers whose safety number isn't verified are
    // silently declined.  Pure UI-side filter — desktop ChatView's
    // onFileAcceptRequested checks this before raising the QMessageBox.
    void fileRequireVerifiedToggled(bool on);

    // Relay URL the client should connect to.  MainWindow hooks this and
    // drops the existing WS connection + reconnects with the new URL.
    void relayUrlChanged(const QString &url);

    // Privacy level (0 = Standard, 1 = Enhanced, 2 = Maximum).  Controls
    // send jitter, cover traffic, and multi-hop onion routing in the
    // RelayClient.  MainWindow forwards to m_controller.relay().setPrivacyLevel.
    void privacyLevelChanged(int level);

    // Safety-numbers: when on, messages to/from peers whose safety number
    // changed are refused at the ChatController layer.  MainWindow forwards
    // to m_controller.setHardBlockOnKeyChange.
    void hardBlockOnKeyChangeToggled(bool on);

    // Parallel fan-out (REDUNDANCY): post each message to all configured
    // relays so a single relay being down doesn't drop delivery.
    // MainWindow forwards to m_controller.relay().setParallelFanOut.
    void parallelFanOutToggled(bool on);

    // Multi-hop onion routing (ANONYMITY): chain envelopes through
    // multiple relays so no single relay sees both sender and recipient.
    // MainWindow forwards to m_controller.relay().setMultiHopEnabled.
    void multiHopToggled(bool on);

private slots:
    void onToggleNotifications();
    void onToggleDnd();
    void onFileAutoAcceptSpin(int mb);
    void onFileHardMaxSpin(int mb);
    void onToggleRequireP2P();
    void onToggleRequireVerifiedFiles();
    void onApplyRelayUrl();
    void onResetRelayUrl();
    void onPrivacyLevelChanged(int level);
    void onToggleHardBlockOnKeyChange();
    void onToggleParallelFanOut();
    void onToggleMultiHop();

private:
    void buildUI();
    void applyNotificationState();   // sync UI labels to m_notificationsEnabled
    void applyDndState();            // sync UI labels to m_dndEnabled
    void applyRequireP2PState();
    void applyRequireVerifiedFilesState();
    QWidget *makeProfileSection();
    QWidget *makeSection(const QString &sectionTitle,
                         const QList<QPair<QString, QString>> &rows);
    QWidget *makeNotificationsSection();
    QWidget *makeDataSection();
    QWidget *makeFileTransferSection();
    QWidget *makeRelaySection();
    QWidget *makePrivacySection();
    QWidget *makeArchivedChatsSection();
    QWidget *makeAboutHelpSection();

    // Profile
    QLabel      *m_displayNameLabel     = nullptr;
    QLabel      *m_publicKeyLabel       = nullptr;
    QString      m_fullPublicKey;

    // Database (not owned)
    AppDataStore *m_store               = nullptr;

    // Notifications
    bool             m_notificationsEnabled = true;
    NotificationMode m_notifMode            = NotificationMode::Hidden;
    QComboBox       *m_notifModeCombo       = nullptr;
    QLabel          *m_notifModeHelp        = nullptr;
    QPushButton *m_notifToggleBtn       = nullptr;
    QLabel      *m_notifStatusLabel     = nullptr;
    QLabel      *m_messageAlertsLabel   = nullptr;
    QLabel      *m_soundLabel           = nullptr;
    // Do Not Disturb
    bool         m_dndEnabled           = false;
    QPushButton *m_dndToggleBtn         = nullptr;
    QLabel      *m_dndStatusLabel       = nullptr;

    // File-transfer consent
    QSpinBox    *m_fileAutoAcceptSpin   = nullptr;  // MB
    QSpinBox    *m_fileHardMaxSpin      = nullptr;  // MB
    bool         m_requireP2PEnabled    = false;
    QPushButton *m_requireP2PToggleBtn  = nullptr;
    QLabel      *m_requireP2PStatusLbl  = nullptr;

    bool         m_requireVerifiedFilesEnabled    = false;
    QPushButton *m_requireVerifiedFilesToggleBtn  = nullptr;
    QLabel      *m_requireVerifiedFilesStatusLbl  = nullptr;

    // Relay URL
    QLineEdit   *m_relayUrlEdit         = nullptr;
    QPushButton *m_relayApplyBtn        = nullptr;
    QLabel      *m_relayStatusLabel     = nullptr;
    QString      m_lastAppliedRelayUrl;

    // Privacy level (0/1/2) — three selectable buttons.
    int          m_privacyLevel         = 0;
    QPushButton *m_privacyBtn0          = nullptr;
    QPushButton *m_privacyBtn1          = nullptr;
    QPushButton *m_privacyBtn2          = nullptr;
    QLabel      *m_privacyDescLabel     = nullptr;

    // Safety-numbers hard-block toggle.
    bool         m_hardBlockKeyChangeEnabled = false;
    QPushButton *m_hardBlockKeyChangeToggleBtn = nullptr;
    QLabel      *m_hardBlockKeyChangeStatusLbl = nullptr;
    void applyHardBlockKeyChangeState();

    // Parallel fan-out toggle (redundancy).  Independent of the
    // privacy-level slider — power users can flip this on/off
    // regardless of preset.  Persisted in AppDataStore as
    // "parallelFanOutEnabled".
    bool         m_parallelFanOutEnabled       = false;
    QPushButton *m_parallelFanOutToggleBtn     = nullptr;
    QLabel      *m_parallelFanOutStatusLbl     = nullptr;
    void applyParallelFanOutState();

    // Multi-hop onion routing toggle (anonymity).  Independent
    // dial.  Persisted as "multiHopEnabled".
    bool         m_multiHopEnabled             = false;
    QPushButton *m_multiHopToggleBtn           = nullptr;
    QLabel      *m_multiHopStatusLbl           = nullptr;
    void applyMultiHopState();

    // Appearance — three buttons styled like the privacy level picker.
    // The selected preference itself lives on ThemeManager (single
    // source of truth); this class only owns the button pointers.
    QPushButton    *m_themeBtnDark     = nullptr;
    QPushButton    *m_themeBtnLight    = nullptr;
    QPushButton    *m_themeBtnSystem   = nullptr;
    QWidget *makeAppearanceSection();
    void applyThemeButtonStyles();

    // Walks every child widget tagged with one of our p2p* objectNames
    // (p2pCard / p2pSectionHeading / p2pKeyLabel / p2pValueLabel /
    // p2pDivider) and overwrites its stylesheet with one built from the
    // currently-active Theme.  Called at end of buildUI() and again
    // every time ThemeManager::themeChanged fires.  Cheap (single
    // findChildren walk per tag); no widget-tree rebuild required.
    void applyThemeStyles();
};

#endif // SETTINGSPANEL_H
