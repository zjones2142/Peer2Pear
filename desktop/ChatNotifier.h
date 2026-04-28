#pragma once

#include <QObject>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QStyle>
#include <QTimer>

#include "settingspanel.h"  // SettingsPanel::NotificationMode

// ── ChatNotifier ──────────────────────────────────────────────────────────────
//
// Wraps QSystemTrayIcon to deliver balloon notifications for incoming
// chat events.  Two orthogonal settings gate what the user actually
// sees:
//
//   1. Global enable (`setEnabled`) — honours the top-of-panel
//      on/off switch + Do-Not-Disturb.
//   2. Content mode (`setContentMode`) — how much of the plaintext
//      reaches the OS notification store.  Default is Hidden so
//      sensitive content doesn't land in the macOS NotificationCenter
//      DB, Windows Action Center, or Linux notification daemons —
//      stores that sit outside the app sandbox and survive message
//      deletion.
//
// Callers hand the notifier a full (senderName, body, [groupName])
// triple; the notifier alone decides which of those strings actually
// reach QSystemTrayIcon::showMessage.
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

    SettingsPanel::NotificationMode contentMode() const { return m_mode; }

public slots:
    // Wired directly to SettingsPanel::notificationsToggled(bool)
    void setEnabled(bool enabled) { m_enabled = enabled; }

    // Wired to SettingsPanel::notificationModeChanged(mode).  Applied
    // to every subsequent notify() call.
    void setContentMode(SettingsPanel::NotificationMode mode) { m_mode = mode; }

    // Incoming 1:1 message.  `senderName` is the display name the app
    // resolved from the peer_id (or a fingerprint prefix if no contact
    // entry exists).  `messageText` is the decrypted plaintext.
    void notify(const QString &senderName, const QString &messageText)
    {
        if (!m_enabled || !m_trayIcon) return;
        show(bannerTitle(senderName, /*groupName=*/QString()),
             bannerBody (senderName, messageText));
    }

    // Incoming group message.  `groupName` appears in the banner when
    // content mode is Full or SenderOnly; otherwise suppressed.
    void notifyGroup(const QString &senderName,
                     const QString &groupName,
                     const QString &messageText)
    {
        if (!m_enabled || !m_trayIcon) return;
        show(bannerTitle(senderName, groupName),
             bannerBody (senderName, messageText));
    }

private:
    QString bannerTitle(const QString &senderName,
                        const QString &groupName) const
    {
        switch (m_mode) {
        case SettingsPanel::NotificationMode::Hidden:
            return QStringLiteral("Peer2Pear");
        case SettingsPanel::NotificationMode::SenderOnly:
        case SettingsPanel::NotificationMode::Full:
            if (!groupName.isEmpty()) return groupName;
            return senderName.isEmpty() ? QStringLiteral("Peer2Pear")
                                        : senderName;
        }
        return QStringLiteral("Peer2Pear");
    }

    QString bannerBody(const QString &senderName,
                       const QString &messageText) const
    {
        switch (m_mode) {
        case SettingsPanel::NotificationMode::Hidden:
            return QStringLiteral("New message");
        case SettingsPanel::NotificationMode::SenderOnly:
            return QStringLiteral("New message from %1")
                .arg(senderName.isEmpty() ? QStringLiteral("unknown")
                                          : senderName);
        case SettingsPanel::NotificationMode::Full:
            return messageText.length() > 80
                       ? messageText.left(77) + QStringLiteral("…")
                       : messageText;
        }
        return QStringLiteral("New message");
    }

    void show(const QString &title, const QString &body)
    {
        // Post through the event loop so the caller isn't paused on
        // the platform notification call (some backends are slow).
        QTimer::singleShot(0, this, [this, title, body]() {
            if (m_trayIcon && m_trayIcon->isVisible())
                m_trayIcon->showMessage(title, body,
                                         QSystemTrayIcon::Information, 4000);
        });
    }

    QSystemTrayIcon *m_trayIcon = nullptr;
    bool             m_enabled  = true;
    SettingsPanel::NotificationMode m_mode =
        SettingsPanel::NotificationMode::Hidden;
};
