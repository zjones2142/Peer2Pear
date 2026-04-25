#pragma once

#include "ChatController.hpp"
#include "AppDataStore.hpp"
#include "qt_str_helpers.hpp"

#include <QObject>
#include <QVector>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QMap>
#include <QSet>
#include <QLabel>
#include <QFrame>

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "ChatNotifier.h"
#include "filetransfer.h"

namespace Ui { class MainWindow; }

class ChatView : public QObject
{
    Q_OBJECT

public:
    explicit ChatView(Ui::MainWindow *ui,
                      ChatController *controller,
                      AppDataStore *store,
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

    // A peer is offering a file and needs consent.
    void onFileAcceptRequested(const QString &fromPeerIdB64u,
                               const QString &transferId,
                               const QString &fileName,
                               qint64 fileSize);

    // Transfer was canceled/declined by either side.
    void onFileTransferCanceled(const QString &transferId, bool byReceiver);

    // Sender-side — receiver confirmed delivery.
    void onFileTransferDelivered(const QString &transferId);

    // Transport policy blocked the transfer (no P2P + requireP2P on).
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
    void onChatListContextMenu(const QPoint &pos);
    void onDeleteConversation(int index);
    void onOpenContactsPicker();

public:
    void initChats();
    /// Safety-numbers: called when ChatController::onPeerKeyChanged
    /// fires, so the contact list re-renders its verification badges.
    void refreshAfterKeyChange() { rebuildChatList(); }
    /// "Only accept files from verified contacts" UI policy.  Set
    /// from MainWindow when SettingsPanel emits the toggle.  Pure
    /// presentation-layer filter — onFileAcceptRequested checks this
    /// + peerTrust before raising the consent QMessageBox.
    void setRequireVerifiedFiles(bool on) { m_requireVerifiedFiles = on; }

private:
    void rebuildChatList();
    void loadChat(int index);
    void promoteChatToTop(int index);
    QLabel *m_emptyLabel = nullptr;

    void clearMessages();
    /// Render one message bubble.  Pass `msgId` + `chatKey` (peerIdB64u
    /// for 1:1s, groupId for groups) to make the bubble long-press /
    /// right-click deletable; leaving them empty produces a static
    /// system bubble (e.g. "No keys saved for this contact") with no
    /// context menu.
    void addMessageBubble(const QString &text, bool sent,
                          const QString &senderName = QString(),
                          const QString &msgId = QString(),
                          const QString &chatKey = QString());
    void onDeleteSingleMessage(const QString &chatKey, const QString &msgId);
    void addFileBubble(const QString &fileName, qint64 fileSize, bool sent);
    void addDateSeparator(const QDateTime &dt);

    // File tab — the per-file card lives in desktop/dialogs.{h,cpp}
    void rebuildFilesTab();

    // Find the 1:1 chat index for a peer (-1 if none).  Skips group
    // chats — groups are matched by groupId via their own helpers.
    int findChatForPeer(const QString &peerIdB64u) const;
    // As above but auto-creates a nameless stub chat (rendered by key
    // is found.  Used for inbound traffic from a peer we haven't
    // explicitly added yet.
    int findOrCreateChatForPeer(const QString &peerIdB64u);
    static QString chatKey(const AppDataStore::Contact &c);

    Ui::MainWindow  *m_ui         = nullptr;
    ChatController  *m_controller = nullptr;
    ChatNotifier    *m_notifier   = nullptr;
    AppDataStore    *m_store      = nullptr;

    std::function<bool()> m_shouldToastFn;

    std::vector<AppDataStore::Contact> m_chats;
    bool              m_requireVerifiedFiles = false;
    int               m_currentChat = -1;

    QVector<int> m_unread;
    QTimer       m_presenceTimer;

    // Per-member online status (peerIdB64u → online); shared across DM and group chats
    QMap<QString, bool> m_memberOnline;

    // Messages keyed by peerIdB64u (DMs) or groupId (groups) — kept
    // in-memory alongside m_chats since AppDataStore::Contact no
    // longer carries an embedded message list.
    std::unordered_map<std::string, std::vector<AppDataStore::Message>> m_messagesByPeer;

    // File records keyed by stable chatKey() — never needs index remapping
    QMap<QString, std::vector<AppDataStore::FileRecord>> m_filesByKey;

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
