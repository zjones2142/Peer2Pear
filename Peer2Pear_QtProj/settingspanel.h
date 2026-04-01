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

signals:
    void backClicked();
    void notificationsToggled(bool enabled);
    void exportContactsClicked();
    void importContactsClicked();

private slots:
    void onToggleNotifications();

private:
    void buildUI();
    QWidget *makeSection(const QString &sectionTitle,
                         const QList<QPair<QString, QString>> &rows);
    QWidget *makeNotificationsSection();
    QWidget *makeDataSection();

    bool         m_notificationsEnabled = true;
    QPushButton *m_notifToggleBtn       = nullptr;
    QLabel      *m_notifStatusLabel     = nullptr;
};

#endif // SETTINGSPANEL_H
