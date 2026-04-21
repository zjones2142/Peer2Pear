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

class DatabaseManager;

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

    // Appearance preference.  Default is Dark because the app's per-
    // widget stylesheets were written assuming a dark palette — Light
    // remaps the palette via Qt Fusion but per-widget overrides
    // (SettingsPanel, MainWindow chrome) still dominate until those
    // stylesheets are centralized.  System follows the OS.
    enum class ThemePreference {
        Dark   = 0,
        Light  = 1,
        System = 2
    };

    explicit SettingsPanel(QWidget *parent = nullptr);

    // Returns whether notifications are currently enabled
    bool notificationsEnabled() const { return m_notificationsEnabled; }

    // Currently-selected notification content mode.  Defaults to
    // Hidden (most private) until the user explicitly opts up.
    NotificationMode notificationMode() const { return m_notifMode; }

    // Call after construction to populate profile fields
    void setProfileInfo(const QString &displayName, const QString &publicKey);

    // Attach a DatabaseManager for persisting settings, then load saved state
    void setDatabase(DatabaseManager *db);

signals:
    void backClicked();
    void notificationsToggled(bool enabled);
    void notificationModeChanged(SettingsPanel::NotificationMode mode);
    void exportContactsClicked();
    void importContactsClicked();

    // File-transfer consent settings changed.
    void fileAutoAcceptMaxChanged(int mb);
    void fileHardMaxChanged(int mb);
    void fileRequireP2PToggled(bool on);

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

    // Dark/Light/System appearance toggle.  MainWindow applies the
    // Fusion palette + any widget-level refresh when this fires.
    void themeChanged(SettingsPanel::ThemePreference pref);

private slots:
    void onToggleNotifications();
    void onToggleDnd();
    void onFileAutoAcceptSpin(int mb);
    void onFileHardMaxSpin(int mb);
    void onToggleRequireP2P();
    void onApplyRelayUrl();
    void onResetRelayUrl();
    void onPrivacyLevelChanged(int level);
    void onToggleHardBlockOnKeyChange();

private:
    void buildUI();
    void applyNotificationState();   // sync UI labels to m_notificationsEnabled
    void applyRequireP2PState();
    QWidget *makeProfileSection();
    QWidget *makeSection(const QString &sectionTitle,
                         const QList<QPair<QString, QString>> &rows);
    QWidget *makeNotificationsSection();
    QWidget *makeDataSection();
    QWidget *makeFileTransferSection();
    QWidget *makeRelaySection();
    QWidget *makePrivacySection();
    QWidget *makeAboutHelpSection();

    // Profile
    QLabel      *m_displayNameLabel     = nullptr;
    QLabel      *m_publicKeyLabel       = nullptr;
    QString      m_fullPublicKey;

    // Database (not owned)
    DatabaseManager *m_db               = nullptr;

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

    // Appearance — three buttons styled like the privacy level picker.
    ThemePreference m_themePref        = ThemePreference::Dark;
    QPushButton    *m_themeBtnDark     = nullptr;
    QPushButton    *m_themeBtnLight    = nullptr;
    QPushButton    *m_themeBtnSystem   = nullptr;
    QWidget *makeAppearanceSection();
    void applyThemeButtonStyles();
};

#endif // SETTINGSPANEL_H
