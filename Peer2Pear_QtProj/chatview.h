#pragma once

#include "ChatController.hpp"
#include <QObject>
#include <QVector>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QMap>
#include <QSet>
#include <functional>
#include <QLabel>
#include <QFrame>

#include "ChatNotifier.h"
#include "chattypes.h"
#include "databasemanager.h"
#include "filetransfer.h"

namespace Ui { class MainWindow; }

class ChatView : public QObject
{
    Q_OBJECT

public:
    explicit ChatView(Ui::MainWindow *ui,
                      ChatController *controller,
                      DatabaseManager *db,
                      QObject *parent = nullptr);

    void reloadCurrentChat();

    void setShouldToastFn(std::function<bool()> fn) { m_shouldToastFn = std::move(fn); }
    void setNotifier(ChatNotifier *notifier)         { m_notifier = notifier; }

    void startPresencePolling(int intervalMs = 180000);

public slots:
    void onPresenceChanged(const QString &peerIdB64u, bool online);
    void onIncomingMessage(const QString &fromPeerIdB64u,
                           const QString &text,
                           const QDateTime &timestamp,
                           const QString &msgId);

    void onStatus(const QString &s);

    void onIncomingGroupMessage(const QString &fromPeerIdB64u,
                                const QString &groupId,
                                const QString &groupName,
                                const QStringList &memberKeys,
                                const QString &text,
                                const QDateTime &ts,
                                const QString &msgId);
    void onGroupMemberLeft(const QString& fromPeerIdB64u,
                           const QString& groupId,
                           const QString& groupName,
                           const QStringList& memberKeys,
                           const QDateTime& ts,
                           const QString& msgId);

    void onAvatarReceived(const QString &peerIdB64u,
                          const QString &displayName,
                          const QString &avatarB64);
    void onGroupRenamed(const QString &groupId, const QString &newName);
    void onGroupAvatarReceived(const QString &groupId, const QString &avatarB64);

    // Fired for every arriving chunk.
    // fileData is non-empty only when chunksReceived == chunksTotal (transfer complete).
    void onFileChunkReceived(const QString &fromPeerIdB64u,
                             const QString &transferId,
                             const QString &fileName,
                             qint64         fileSize,
                             int            chunksReceived,
                             int            chunksTotal,
                             const QByteArray &fileData,
                             const QDateTime  &timestamp,
                             const QString &groupId = {},
                             const QString &groupName = {});

signals:
    void unreadChanged(int totalUnread);

private slots:
    void onChatSelected(int index);
    void onSendMessage();
    void onSearchChanged(const QString &text);
    void onAttachFile();

    void onEditProfile();
    void onEditContact(int index);
    void onAddContact();

public:
    void initChats();

private:
    void rebuildChatList();
    void loadChat(int index);
    void promoteChatToTop(int index);
    QLabel *m_emptyLabel = nullptr;

    void clearMessages();
    void addMessageBubble(const QString &text, bool sent, const QString &senderName = QString());
    void addFileBubble(const QString &fileName, qint64 fileSize, bool sent);
    void addDateSeparator(const QDateTime &dt);

    // File tab — buildFileCard returns an owned QFrame; rebuildFilesTab places it
    void    rebuildFilesTab();
    QFrame *buildFileCard(const FileTransferRecord &rec, QWidget *parent);

    int findOrCreateChatForPeer(const QString &peerIdB64u);
    static QString chatKey(const ChatData &c);

    Ui::MainWindow  *m_ui         = nullptr;
    ChatController  *m_controller = nullptr;
    ChatNotifier    *m_notifier   = nullptr;
    DatabaseManager *m_db         = nullptr;

    std::function<bool()> m_shouldToastFn;

    QVector<ChatData> m_chats;
    int               m_currentChat = -1;

    QStringList m_profileKeys;
    QVector<int> m_unread;
    QTimer       m_presenceTimer;

    // File records keyed by stable chatKey() — never needs index remapping
    QMap<QString, QVector<FileTransferRecord>> m_filesByKey;

    int  totalUnread() const;
    void ensureUnreadSize();

    void showToast(const QString &message);
    QLabel *m_toastLabel = nullptr;
};
