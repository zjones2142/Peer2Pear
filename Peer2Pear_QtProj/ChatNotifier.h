#pragma once

#include <QObject>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QStyle>

// ── ChatNotifier ──────────────────────────────────────────────────────────────
// Wraps QSystemTrayIcon to deliver chat message balloon notifications.
// Respects the notifications enabled/disabled setting from SettingsPanel.
// ─────────────────────────────────────────────────────────────────────────────
class ChatNotifier : public QObject
{
    Q_OBJECT

public:
    explicit ChatNotifier(QObject *parent = nullptr) : QObject(parent)
    {
        if (!QSystemTrayIcon::isSystemTrayAvailable())
            return;

        m_trayIcon = new QSystemTrayIcon(this);

        QIcon icon = QApplication::windowIcon();
        if (icon.isNull())
            icon = QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation);

        m_trayIcon->setIcon(icon);
        m_trayIcon->setToolTip("Peer2Pear");

        QMenu *menu = new QMenu();
        QAction *quitAction = new QAction("Quit Peer2Pear", menu);
        connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
        menu->addAction(quitAction);
        m_trayIcon->setContextMenu(menu);

        m_trayIcon->show();
    }

    bool isAvailable()          const { return m_trayIcon != nullptr; }
    bool notificationsEnabled() const { return m_enabled; }

public slots:
    // Wired directly to SettingsPanel::notificationsToggled(bool)
    void setEnabled(bool enabled) { m_enabled = enabled; }

    // Called from ChatView::onIncomingMessage for background chat messages
    void notify(const QString &senderName, const QString &messageText)
    {
        if (!m_enabled || !m_trayIcon) return;

        const QString body = messageText.length() > 80
                                 ? messageText.left(77) + "…"
                                 : messageText;

        m_trayIcon->showMessage(
            senderName,
            body,
            QSystemTrayIcon::Information,
            4000
            );
    }

private:
    QSystemTrayIcon *m_trayIcon = nullptr;
    bool             m_enabled  = true;
};
