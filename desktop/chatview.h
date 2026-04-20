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
    bool eventFilter(QObject *obj, QEvent *event) override;

    void setShouldToastFn(std::function<bool()> fn) { m_shouldToastFn = std::move(fn); }
    void setNotifier(ChatNotifier *notifier)         { m_notifier = notifier; }

    void startPresencePolling(int intervalMs = 30000);
    void subscribeAllPresence();

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

    // Fired for every arriving chunk. Files are streamed to disk by
    // FileTransferManager — savedPath is the on-disk location of the final
    // file and is non-empty only when chunksReceived == chunksTotal.
    void onFileChunkReceived(const QString &fromPeerIdB64u,
                             const QString &transferId,
                             const QString &fileName,
                             qint64         fileSize,
                             int            chunksReceived,
                             int            chunksTotal,
                             const QString &savedPath,
                             const QDateTime  &timestamp,
                             const QString &groupId = {},
                             const QString &groupName = {});

    // Fired for every outbound chunk dispatched.  Sender-side counterpart
    // to onFileChunkReceived; drives the progress indicator on the
    // file card the sender sees while their file is being transmitted.
    void onFileChunkSent(const QString &toPeerIdB64u,
                         const QString &transferId,
                         const QString &fileName,
                         qint64         fileSize,
                         int            chunksSent,
                         int            chunksTotal,
                         const QDateTime  &timestamp,
                         const QString &groupId = {},
                         const QString &groupName = {});

    // Phase 2: a peer is offering a file and needs consent.
    void onFileAcceptRequested(const QString &fromPeerIdB64u,
                               const QString &transferId,
                               const QString &fileName,
                               qint64 fileSize);

    // Phase 2: transfer was canceled/declined by either side.
    void onFileTransferCanceled(const QString &transferId, bool byReceiver);

    // Phase 3: sender-side — receiver confirmed delivery.
    void onFileTransferDelivered(const QString &transferId);

    // Phase 3: transport policy blocked the transfer (no P2P + requireP2P on).
    void onFileTransferBlocked(const QString &transferId, bool byReceiver);

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
    /// Safety-numbers: called when ChatController::onPeerKeyChanged
    /// fires, so the contact list re-renders its verification badges.
    void refreshAfterKeyChange() { rebuildChatList(); }

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

    QVector<int> m_unread;
    QTimer       m_presenceTimer;

    // Per-member online status (peerIdB64u → online); shared across DM and group chats
    QMap<QString, bool> m_memberOnline;

    // File records keyed by stable chatKey() — never needs index remapping
    QMap<QString, QVector<FileTransferRecord>> m_filesByKey;

    int  totalUnread() const;
    void ensureUnreadSize();

    void showToast(const QString &message);
    QLabel *m_toastLabel = nullptr;

    // ── Search state ────────────────────────────────────────────────────────
    QString m_searchQuery;                    // current lowered search text
    QVector<int> m_searchMatchIndices;        // indices into current chat's messages
    int          m_searchMatchCurrent = -1;   // which match is focused (-1 = none)
    void highlightSearchMatches();            // apply/remove gold highlight on bubbles
    void scrollToMatch(int matchIdx);         // scroll message area to a matched bubble
    void navigateSearch(int delta);           // +1 = next, -1 = prev
};
