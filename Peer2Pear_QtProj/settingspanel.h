#ifndef SETTINGSPANEL_H
#define SETTINGSPANEL_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>

class SettingsPanel : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsPanel(QWidget *parent = nullptr);

    // Returns whether notifications are currently enabled
    bool notificationsEnabled() const { return m_notificationsEnabled; }

    // Call after construction to populate profile fields
    void setProfileInfo(const QString &displayName, const QString &publicKey);

signals:
    void backClicked();
    void notificationsToggled(bool enabled);
    void exportContactsClicked();
    void importContactsClicked();

private slots:
    void onToggleNotifications();
    void onToggleDnd();

private:
    void buildUI();
    QWidget *makeProfileSection();
    QWidget *makeSection(const QString &sectionTitle,
                         const QList<QPair<QString, QString>> &rows);
    QWidget *makeNotificationsSection();
    QWidget *makeDataSection();

    // Profile
    QLabel      *m_displayNameLabel     = nullptr;
    QLabel      *m_publicKeyLabel       = nullptr;
    QString      m_fullPublicKey;

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
};

#endif // SETTINGSPANEL_H
