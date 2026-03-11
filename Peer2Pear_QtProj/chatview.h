#pragma once

#include <QObject>
#include <QVector>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <functional>
#include <QLabel>

#include "ChatController.hpp"
#include "ChatNotifier.h"
#include "chattypes.h"
#include "databasemanager.h"

// Forward-declare the generated UI class so we don't pull in the whole header here
namespace Ui { class MainWindow; }


// ── ChatView ──────────────────────────────────────────────────────────────────
// Owns all chat-list and message-bubble logic.
// Receives a raw pointer to the shared Ui and ChatController so it can
// drive the existing widgets without owning them.
class ChatView : public QObject
{
    Q_OBJECT

public:
    explicit ChatView(Ui::MainWindow *ui,
                      ChatController *controller,
                      DatabaseManager *db,
                      QObject *parent = nullptr);

    // Called by MainWindow::resizeEvent so bubbles re-flow on resize
    void reloadCurrentChat();

    // Called by MainWindow to tell ChatView when to show a system toast
    void setShouldToastFn(std::function<bool()> fn) { m_shouldToastFn = std::move(fn);}

    // Called by MainWindow after it creates the ChatNotifier
    void setNotifier(ChatNotifier *notifier) { m_notifier = notifier; }

public slots:
    // Wired to ChatController signals by MainWindow
    void onIncomingMessage(const QString &fromPeerIdB64u, const QString &text, const QDateTime &timestamp);
    void onStatus(const QString &s);
    // Handle Group message with mailbox
    void onIncomingGroupMessage(const QString &fromPeerIdB64u,
                                const QString &groupId,
                                const QString &groupName,
                                const QString &text,
                                const QDateTime &ts);

signals:
    // NEW: emitted whenever unread counts change (for dot + badge)
    void unreadChanged(int totalUnread);

private slots:
    void onChatSelected(int index);
    void onSendMessage();
    void onSearchChanged(const QString &text);

    void onEditProfile();
    void onEditContact(int index);
    void onAddContact();

private:
    // Chat-list helpers
    void initChats();
    void rebuildChatList();
    QLabel *m_emptyLabel = nullptr;
    void loadChat(int index);
    void promoteChatToTop(int index);

    // Message-area helpers
    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);
    void addDateSeparator(const QDateTime &dt);

    // ── Members ──
    Ui::MainWindow  *m_ui         = nullptr;
    ChatController  *m_controller = nullptr;
    ChatNotifier *m_notifier = nullptr;
    DatabaseManager *m_db         = nullptr;

    std::function<bool()> m_shouldToastFn;

    QVector<ChatData> m_chats;
    int               m_currentChat = -1;

    QStringList m_profileKeys;
    // NEW: unread counts per chat
    QVector<int> m_unread;

    int totalUnread() const;
    void ensureUnreadSize();
};
