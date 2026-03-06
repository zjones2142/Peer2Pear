#pragma once

#include <QObject>
#include <QVector>
#include <QPair>
#include <QString>
#include <QStringList>
#include <functional>

#include "ChatController.hpp"
#include "ChatNotifier.h"

// Forward-declare the generated UI class so we don't pull in the whole header here
namespace Ui { class MainWindow; }

// ── Data model ────────────────────────────────────────────────────────────────
struct ChatData {
    QString     name;
    QString     subtitle;
    QString     peerIdB64u;   // peer identity key (base64url ed25519 pub)
    QStringList keys;         // all public keys for this contact
    QVector<QPair<bool, QString>> messages;
};

// ── ChatView ──────────────────────────────────────────────────────────────────
// Owns all chat-list and message-bubble logic.
// Receives a raw pointer to the shared Ui and ChatController so it can
// drive the existing widgets without owning them.
class ChatView : public QObject
{
    Q_OBJECT

public:
    explicit ChatView(Ui::MainWindow *ui, ChatController *controller, QObject *parent = nullptr);

    // Called by MainWindow::resizeEvent so bubbles re-flow on resize
    void reloadCurrentChat();

    // Called by MainWindow to tell ChatView when to show a system toast
    void setShouldToastFn(std::function<bool()> fn) { m_shouldToastFn = std::move(fn);}

    // Called by MainWindow after it creates the ChatNotifier
    void setNotifier(ChatNotifier *notifier) { m_notifier = notifier; }

public slots:
    // Wired to ChatController signals by MainWindow
    void onIncomingMessage(const QString &fromPeerIdB64u, const QString &text);
    void onStatus(const QString &s);

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
    void loadChat(int index);
    void promoteChatToTop(int index);

    // Message-area helpers
    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);

    // ── Members ──
    Ui::MainWindow  *m_ui         = nullptr;
    ChatController  *m_controller = nullptr;
    ChatNotifier *m_notifier = nullptr;

    std::function<bool()> m_shouldToastFn;

    QVector<ChatData> m_chats;
    int               m_currentChat = -1;

    QStringList m_profileKeys;
    // NEW: unread counts per chat
    QVector<int> m_unread;

    int totalUnread() const;
    void ensureUnreadSize();
};
