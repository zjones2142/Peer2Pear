#ifndef SETTINGSPANEL_H
#define SETTINGSPANEL_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QSpinBox>

class DatabaseManager;

class SettingsPanel : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsPanel(QWidget *parent = nullptr);

    // Returns whether notifications are currently enabled
    bool notificationsEnabled() const { return m_notificationsEnabled; }

    // Call after construction to populate profile fields
    void setProfileInfo(const QString &displayName, const QString &publicKey);

    // Attach a DatabaseManager for persisting settings, then load saved state
    void setDatabase(DatabaseManager *db);

signals:
    void backClicked();
    void notificationsToggled(bool enabled);
    void exportContactsClicked();
    void importContactsClicked();

    // Phase 2: file-transfer consent settings changed.
    void fileAutoAcceptMaxChanged(int mb);
    void fileHardMaxChanged(int mb);
    void fileRequireP2PToggled(bool on);

private slots:
    void onToggleNotifications();
    void onToggleDnd();
    void onFileAutoAcceptSpin(int mb);
    void onFileHardMaxSpin(int mb);
    void onToggleRequireP2P();

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
    QWidget *makeAboutHelpSection();

    // Profile
    QLabel      *m_displayNameLabel     = nullptr;
    QLabel      *m_publicKeyLabel       = nullptr;
    QString      m_fullPublicKey;

    // Database (not owned)
    DatabaseManager *m_db               = nullptr;

    // Notifications
    bool         m_notificationsEnabled = true;
    QPushButton *m_notifToggleBtn       = nullptr;
    QLabel      *m_notifStatusLabel     = nullptr;
    QLabel      *m_messageAlertsLabel   = nullptr;
    QLabel      *m_soundLabel           = nullptr;
    // Do Not Disturb
    bool         m_dndEnabled           = false;
    QPushButton *m_dndToggleBtn         = nullptr;
    QLabel      *m_dndStatusLabel       = nullptr;

    // Phase 2: file-transfer consent
    QSpinBox    *m_fileAutoAcceptSpin   = nullptr;  // MB
    QSpinBox    *m_fileHardMaxSpin      = nullptr;  // MB
    bool         m_requireP2PEnabled    = false;
    QPushButton *m_requireP2PToggleBtn  = nullptr;
    QLabel      *m_requireP2PStatusLbl  = nullptr;
};

#endif // SETTINGSPANEL_H
