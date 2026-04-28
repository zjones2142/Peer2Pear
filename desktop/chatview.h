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
#include <unordered_set>
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

    /// pv=2 Causally-Linked Pairwise: a sender's stream in `groupId`
    /// is blocked at the gap [fromCtr, toCtr].  ChatController has
    /// already fired a gap_request — this callback only updates the
    /// in-memory map driving the chat-header banner.
    void onGroupStreamBlocked(const QString& groupId,
                               const QString& senderPeerId,
                               qint64 fromCtr, qint64 toCtr);

    /// pv=2: `count` buffered messages from `senderPeerId` in
    /// `groupId` were dropped on a session reset.  Surfaced as a
    /// status-line message in the conversation pane (toast-style).
    void onGroupMessagesLost(const QString& groupId,
                              const QString& senderPeerId,
                              qint64 count);

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

private:
    /// Open the address-book editor for a peer.  When the peer
    /// already has a `contacts` row we hydrate from it; otherwise a
    /// blank Contact stub is presented so the user can curate them
    /// into the address book in one step.  Persistence + in-memory
    /// cache update happen here so the caller (group / conversation
    /// editor) doesn't have to know about saveContact / deleteContact.
    void openContactDialogForPeer(const QString &peerIdB64u);

    /// Open Add-Contact with the public-key field pre-filled.  Used
    /// by the conversation editor's "Add Contact" affordance when the
    /// peer is not yet in the address book — keeps the existing
    /// add-contact validation + duplicate-key checks in one place.
    void openAddContactPrefilled(const QString &peerIdB64u);

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

    /// Read-only view of the in-memory address book.  Returned by
    /// reference so callers can hand the snapshot to dialogs (e.g.
    /// the Archived Chats dialog) without copying — the map is
    /// stable for the lifetime of ChatView and only mutated by
    /// initChats / openContactDialogForPeer.
    const std::unordered_map<std::string, AppDataStore::Contact> &
    addressBookSnapshot() const { return m_contactsByPeer; }

    /// Refresh the chat list after the user restored or permanently
    /// deleted a row from the Archived Chats dialog.  A Restored row
    /// must reappear in the visible list; a Deleted row must drop
    /// any in-memory state we still hold for it.  initChats is the
    /// less-clever, more-robust path — archive actions are not
    /// high-frequency, so a full reload is acceptable.
    void reloadAfterArchiveAction() { initChats(); rebuildChatList(); }

private:
    void rebuildChatList();
    void loadChat(int index);
    void promoteChatToTop(int index);
    QLabel *m_emptyLabel = nullptr;

    void clearMessages();
    /// Render one message bubble.  Pass `msgId` + `convId` (the
    /// conversation UUID) to make the bubble long-press / right-click
    /// deletable; leaving them empty produces a static system bubble
    /// (e.g. "No keys saved for this contact") with no context menu.
    void addMessageBubble(const QString &text, bool sent,
                          const QString &senderName = QString(),
                          const QString &msgId = QString(),
                          const QString &convId = QString());
    void onDeleteSingleMessage(const QString &convId, const QString &msgId);
    void addFileBubble(const QString &fileName, qint64 fileSize, bool sent);
    void addDateSeparator(const QDateTime &dt);

    // File tab — the per-file card lives in desktop/dialogs.{h,cpp}
    void rebuildFilesTab();

    // Find the 1:1 chat row index for `peerIdB64u` (-1 if none).
    // Skips groups; matches on Conversation::directPeerId.
    int findChatForPeer(const QString &peerIdB64u) const;
    // As above but auto-creates a 1:1 conversation row (via
    // m_store->findOrCreateDirectConversation) when missing.  Used for
    // inbound traffic from a peer we haven't explicitly added.
    int findOrCreateDirectChatForPeer(const QString &peerIdB64u);

    // Display helpers that hide the contact / group split from callers.
    QString displayNameFor(const AppDataStore::Conversation &conv) const;
    QString avatarB64For (const AppDataStore::Conversation &conv) const;
    bool    isMutedFor   (const AppDataStore::Conversation &conv) const;
    bool    isBlockedFor (const AppDataStore::Conversation &conv) const;

    Ui::MainWindow  *m_ui         = nullptr;
    ChatController  *m_controller = nullptr;
    ChatNotifier    *m_notifier   = nullptr;
    AppDataStore    *m_store      = nullptr;

    std::function<bool()> m_shouldToastFn;

    // v3 split: conversations drive the chat list; contacts are the
    // address-book side-table looked up by `directPeerId`; blocked_keys
    // is its own thing (Phase 3h) — independent of contacts and groups.
    std::vector<AppDataStore::Conversation> m_chats;
    std::unordered_map<std::string, std::vector<std::string>> m_membersByConv;
    std::unordered_map<std::string, AppDataStore::Contact>    m_contactsByPeer;
    std::unordered_set<std::string>                            m_blockedKeys;

    bool              m_requireVerifiedFiles = false;
    int               m_currentChat = -1;

    QVector<int> m_unread;
    QTimer       m_presenceTimer;

    // Per-member online status (peerIdB64u → online); shared across DM and group chats
    QMap<QString, bool> m_memberOnline;

    // Messages keyed by conversation UUID — replaces the old
    // peer-id-or-group-id chatKey indirection.
    std::unordered_map<std::string, std::vector<AppDataStore::Message>> m_messagesByConv;

    // File records keyed by conversation UUID — same key namespace as
    // m_messagesByConv so promoteChatToTop never needs to remap.
    std::unordered_map<std::string, std::vector<AppDataStore::FileRecord>> m_filesByConv;

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
