#include "chatview.h"
#include "QrImage.hpp"
#include "dialogs.h"
#include "peer2pear.h"
#include "shared.hpp"
#include "theme.h"
#include "theme_styles.h"
#include "ui_mainwindow.h"

#include <algorithm>
#include <utility>
#include <unordered_set>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QScrollArea>
#include <QScrollBar>
#include <QFontMetrics>
#include <QApplication>
#include <QDialog>
#include <QFrame>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QListWidget>
#include <QMenu>
#include <QAction>
#include <QToolButton>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <QUuid>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QTimer>
#include <QRegularExpression>
#include <QDesktopServices>
#include <QUrl>
#include <QPainter>
#include <QPainterPath>
#include <QBuffer>
#include <QColorDialog>
#include <QKeyEvent>
#include <QClipboard>

// ── Key validation ───────────────────────────────────────────────────────────
// Delegates to the shared C API so desktop + iOS never disagree on what
// counts as a valid peer ID.
static bool isValidPublicKey(const QString &key)
{
    return p2p_is_valid_peer_id(key.toStdString().c_str()) == 1;
}

// ── ChatController boundary helpers ─────────────────────────────────────────
// ChatController's public surface is std-typed.  Convert at the boundary;
// the desktop UI keeps using QString/QStringList internally.
static std::vector<std::string> qListToStd(const QStringList& qs)
{
    std::vector<std::string> out;
    out.reserve(int(qs.size()));
    for (const QString& s : qs) out.push_back(s.toStdString());
    return out;
}

// Avatar/style helpers and openContactEditor live in desktop/dialogs.{h,cpp}
// — extracted dialogs share that file rather than each gaining their own
// 2-symbol header pair.
using dialogs::renderInitialsAvatar;

// ── Avatar palette ────────────────────────────────────────────────────────────
// One palette shared by all avatar-rendering sites in this file.
static const QList<QColor> kAvatarPalette = {
    QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
    QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a), QColor(0x1a, 0x4a, 0x6a),
};

// Returns a stable palette color derived from the contact name.
// Uses Qt's qHash for a well-distributed, overflow-safe result.
static QColor avatarColorForName(const QString &name)
{
    const uint hash = qHash(name);
    return kAvatarPalette[hash % static_cast<uint>(kAvatarPalette.size())];
}

using dialogs::makeCircularPixmap;

// ── Last-seen formatter ──────────────────────────────────────────────────────
static QString formatLastSeen(const QDateTime &utc)
{
    if (!utc.isValid()) return "Offline";
    const QDateTime local = utc.toLocalTime();
    const QDateTime now   = QDateTime::currentDateTime();
    const qint64 secsAgo  = local.secsTo(now);

    if (secsAgo <        60) return "Last seen just now";
    if (secsAgo <      3600) return QString("Last seen %1m ago").arg(secsAgo / 60);
    if (secsAgo <     86400) return QString("Last seen %1h ago").arg(secsAgo / 3600);
    if (local.date() == now.date().addDays(-1))
        return "Last seen yesterday " + local.toString("h:mm AP");
    if (secsAgo < 7 * 86400)
        return "Last seen " + local.toString("ddd h:mm AP");
    return "Last seen " + local.toString("MMM d");
}

// ── Constants ─────────────────────────────────────────────────────────────────
static constexpr int kDateSepSecs = 60 * 60 * 2; // 2-hour gap → date separator

// ── Date separator label ──────────────────────────────────────────────────────
static QString formatSepLabel(const QDateTime &dt)
{
    const QDate today     = QDate::currentDate();
    const QDate yesterday = today.addDays(-1);
    const QDate d         = dt.toLocalTime().date();

    QString part = (d == today) ? "Today"
                   : (d == yesterday) ? "Yesterday"
                                      : dt.toLocalTime().toString("ddd, MMM d");
    return part + " at " + dt.toLocalTime().toString("h:mm AP");
}

// ── Text-layout helpers ───────────────────────────────────────────────────────
static QString hyphenateWord(const QString &word, const QFontMetrics &fm, int maxW)
{
    QString result, cur;
    for (QChar c : word) {
        QString test = cur + c;
        if (fm.horizontalAdvance(test + "-") >= maxW && !cur.isEmpty()) {
            result += cur + "-\n";
            cur = c;
        } else {
            cur = test;
        }
    }
    return result + cur;
}

static QString processText(const QString &text, const QFontMetrics &fm, int maxW)
{
    QStringList out;
    for (const QString &w : text.split(' '))
        out << (fm.horizontalAdvance(w) > maxW ? hyphenateWord(w, fm, maxW) : w);
    return out.join(' ');
}

using dialogs::openContactEditor;
using dialogs::openConversationEditor;
using dialogs::openGroupEditor;
using ContactEditorResult      = dialogs::ContactEditorResult;
using ConversationEditorResult = dialogs::ConversationEditorResult;
using GroupEditorResult        = dialogs::GroupEditorResult;

// ── ChatView implementation ───────────────────────────────────────────────────

// v3 display helpers.  A 1:1 conversation has no embedded display name —
// it points at a contact row via `directPeerId`.  When that row is
// missing (we received from a stranger we haven't curated), we fall
// back to a key-prefix label so the row is never blank.

QString ChatView::displayNameFor(const AppDataStore::Conversation &conv) const
{
    if (conv.kind == AppDataStore::ConversationKind::Group)
        return qtbridge::qstr(conv.groupName);
    auto it = m_contactsByPeer.find(conv.directPeerId);
    if (it != m_contactsByPeer.end() && !it->second.name.empty())
        return qtbridge::qstr(it->second.name);
    if (!conv.directPeerId.empty())
        return qtbridge::qstr(p2p::peerPrefix(conv.directPeerId)) + "…";
    return QString();
}

QString ChatView::avatarB64For(const AppDataStore::Conversation &conv) const
{
    if (conv.kind == AppDataStore::ConversationKind::Group)
        return qtbridge::qstr(conv.groupAvatarB64);
    auto it = m_contactsByPeer.find(conv.directPeerId);
    if (it != m_contactsByPeer.end()) return qtbridge::qstr(it->second.avatarB64);
    return QString();
}

// Effective mute = per-thread mute OR per-person mute.  The contact-
// level mute silences a peer everywhere they show up (all their 1:1s
// and groups they're in); per-thread mute targets only this row.
bool ChatView::isMutedFor(const AppDataStore::Conversation &conv) const
{
    if (conv.muted) return true;
    if (conv.kind == AppDataStore::ConversationKind::Direct) {
        auto it = m_contactsByPeer.find(conv.directPeerId);
        if (it != m_contactsByPeer.end() && it->second.muted) return true;
    }
    return false;
}

// Block lives in `blocked_keys` (Phase 3h), independent of contacts.
// Groups have no per-thread block; per-member blocks fall back through
// the same direct-peer check inside group dispatch.
bool ChatView::isBlockedFor(const AppDataStore::Conversation &conv) const
{
    if (conv.kind != AppDataStore::ConversationKind::Direct) return false;
    return m_blockedKeys.count(conv.directPeerId) > 0;
}

ChatView::ChatView(Ui::MainWindow *ui, ChatController *controller,
                   AppDataStore *store, QObject *parent)
    : QObject(parent), m_ui(ui), m_controller(controller), m_store(store)
{
    initChats();
    ensureUnreadSize();

    connect(m_ui->chatList,      &QListWidget::currentRowChanged, this, &ChatView::onChatSelected);
    m_ui->chatList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_ui->chatList, &QListWidget::customContextMenuRequested,
            this, &ChatView::onChatListContextMenu);
    connect(m_ui->sendBtn,       &QPushButton::clicked,           this, &ChatView::onSendMessage);
    connect(m_ui->messageInput,  &QLineEdit::returnPressed,       this, &ChatView::onSendMessage);
    connect(m_ui->searchEdit_12, &QLineEdit::textChanged,         this, &ChatView::onSearchChanged);

    // Enter / Shift+Enter to navigate search matches
    m_ui->searchEdit_12->installEventFilter(this);

    connect(m_ui->editProfileBtn,&QToolButton::clicked,           this, &ChatView::onEditProfile);
    connect(m_ui->addContactBtn, &QToolButton::clicked,           this, &ChatView::onAddContact);
    connect(m_ui->attachBtn,     &QToolButton::clicked,           this, &ChatView::onAttachFile);

    // Inject a "Contacts" button into the sidebar footer alongside
    // the existing + (add-contact) button.  Done programmatically to
    // avoid a .ui roundtrip; style mirrors the + button.
    if (auto *footerLayout = qobject_cast<QHBoxLayout*>(m_ui->sidebarFooter->layout())) {
        auto *contactsBtn = new QToolButton(m_ui->sidebarFooter);
        contactsBtn->setText("👥");
        contactsBtn->setToolTip("Contacts");
        contactsBtn->setFixedSize(36, 36);
        contactsBtn->setCursor(Qt::PointingHandCursor);
        contactsBtn->setStyleSheet(
            "QToolButton { background-color: #1a2e1c; border: 1px solid #2e5e30;"
            " color: #5dd868; font-size: 16px; border-radius: 18px; }"
            "QToolButton:hover { background-color: #223a24; border-color: #3a9e48; }");
        // Insert before the + button (which is the last widget in the row).
        footerLayout->insertWidget(footerLayout->count() - 1, contactsBtn);
        connect(contactsBtn, &QToolButton::clicked, this, &ChatView::onOpenContactsPicker);
    }

    rebuildChatList();
    m_ui->chatList->setCurrentRow(0);

    // Start presence polling (check every 30 seconds)
    startPresencePolling(30000);

    // Re-style chat surfaces (bubbles, sender labels, ...) on theme
    // flips.  ThemeManager handles the qApp-wide palette + stylesheet;
    // this call covers widgets ChatView created at runtime with their
    // own setStyleSheet.
    QObject::connect(&ThemeManager::instance(), &ThemeManager::themeChanged,
                     this, [this](const Theme& t) {
        if (m_ui && m_ui->centralwidget) {
            themeStyles::reapplyForChildren(m_ui->centralwidget, t);
        }
    });
    // Initial pass: handles whatever bubbles already landed during
    // initChats() before the ThemeManager preference is loaded from DB.
    if (m_ui && m_ui->centralwidget) {
        themeStyles::reapplyForChildren(m_ui->centralwidget,
                                         ThemeManager::instance().current());
    }
}

bool ChatView::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == m_ui->searchEdit_12 && event->type() == QEvent::KeyPress) {
        auto *ke = static_cast<QKeyEvent*>(event);
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            if (ke->modifiers() & Qt::ShiftModifier)
                navigateSearch(-1);   // Shift+Enter = previous
            else
                navigateSearch(+1);   // Enter = next
            return true;              // consume the event
        }
        if (ke->key() == Qt::Key_Escape) {
            m_ui->searchEdit_12->clear();
            m_ui->searchEdit_12->clearFocus();
            return true;
        }
    }
    return QObject::eventFilter(obj, event);
}

void ChatView::startPresencePolling(int /*intervalMs*/)
{
    // Subscribe to presence updates via the relay (push-based, not polling).
    // ChatController is no longer a QObject; we assign its onRelayConnected
    // callback directly.  Assignment replaces any prior handler — that's fine
    // because only ChatView registers for this event.
    m_controller->onRelayConnected = [this]() {
        subscribeAllPresence();
    };

    // Initial subscription (if relay is already connected)
    QTimer::singleShot(500, this, [this]() {
        subscribeAllPresence();
    });
}

void ChatView::subscribeAllPresence()
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> peerIds;
    const std::string myKey = m_controller->myIdB64u();

    auto trimStd = [](const std::string& k) {
        // Whitespace-trim in place — keys can ride along newlines from paste.
        const auto first = k.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last  = k.find_last_not_of(" \t\r\n");
        return k.substr(first, last - first + 1);
    };

    for (const auto &c : m_chats) {
        if (c.kind == AppDataStore::ConversationKind::Direct) {
            std::string t = trimStd(c.directPeerId);
            if (!t.empty() && t != myKey && seen.insert(t).second)
                peerIds.push_back(std::move(t));
        } else {
            const auto it = m_membersByConv.find(c.id);
            if (it == m_membersByConv.end()) continue;
            for (const std::string &k : it->second) {
                std::string t = trimStd(k);
                if (t.empty() || t == myKey) continue;
                if (seen.insert(t).second)
                    peerIds.push_back(std::move(t));
            }
        }
    }
    if (!peerIds.empty())
        m_controller->subscribePresence(peerIds);
}

void ChatView::onPresenceChanged(const QString &peerIdB64u, bool online)
{
    // Update global member-online map
    m_memberOnline[peerIdB64u] = online;
    const std::string peerIdStd = peerIdB64u.toStdString();

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].kind == AppDataStore::ConversationKind::Group) {
            // Membership check via the conversation_members map.
            const auto memIt = m_membersByConv.find(m_chats[i].id);
            if (memIt == m_membersByConv.end()) continue;
            bool isMember = false;
            for (const std::string &k : memIt->second)
                if (trimStd(k) == peerIdStd) { isMember = true; break; }
            if (!isMember) continue;

            // Update group header if this is the currently selected chat
            if (i == m_currentChat) {
                const std::string myKey = m_controller->myIdB64u();
                int onlineCount = 0, totalMembers = 0;
                for (const std::string &k : memIt->second) {
                    const std::string trimmed = trimStd(k);
                    if (trimmed.empty() || trimmed == myKey) continue;
                    ++totalMembers;
                    if (m_memberOnline.value(qtbridge::qstr(trimmed), false))
                        ++onlineCount;
                }
                const QString statusText = (totalMembers == 0)
                    ? QString("Group chat")
                    : QString("%1 of %2 members online").arg(onlineCount).arg(totalMembers);
                m_ui->chatSubLabel->setText(statusText);
                themeStyles::applyRole(m_ui->chatSubLabel,
                    onlineCount > 0 ? "onlineStatus" : "offlineStatus",
                    onlineCount > 0
                        ? themeStyles::onlineStatusCss(ThemeManager::instance().current())
                        : themeStyles::offlineStatusCss(ThemeManager::instance().current()));
            }
            continue;  // don't return — this peer may be in multiple groups
        }

        // 1:1 DM chat — match on directPeerId.
        if (trimStd(m_chats[i].directPeerId) != peerIdStd) continue;

        // Send our avatar on first contact only if it's a real photo.
        // The "first contact" check looks at the contact row; if no
        // avatar was ever stored for this peer, we treat this as the
        // first time we're online with them.
        QString existingAvatar = avatarB64For(m_chats[i]);
        if (online && existingAvatar.isEmpty() && m_store
                && m_store->loadSetting("avatarIsPhoto") == "true") {
            const std::string myName   = m_store->loadSetting("displayName");
            const std::string myAvatar = m_store->loadSetting("avatarData");
            if (!myName.empty())
                m_controller->sendAvatar(peerIdStd, myName, myAvatar);
        }

        // Update the header if this is the currently selected chat
        if (i == m_currentChat) {
            const QString statusText = online
                                           ? "Online"
                                           : formatLastSeen(qtbridge::qdate(m_chats[i].lastActiveSecs));
            m_ui->chatSubLabel->setText("● " + statusText);
            themeStyles::applyRole(m_ui->chatSubLabel,
                online ? "onlineStatus" : "offlineStatus",
                online ? themeStyles::onlineStatusCss(ThemeManager::instance().current())
                       : themeStyles::offlineStatusCss(ThemeManager::instance().current()));
        }
    }
}

void ChatView::reloadCurrentChat()
{
    if (m_emptyLabel) {
        m_emptyLabel->resize(m_ui->contentWidget->size());
        m_emptyLabel->raise();
        m_emptyLabel->setVisible(m_chats.empty());
    }
}

// ── Incoming messages ─────────────────────────────────────────────────────────

void ChatView::onIncomingMessage(const QString &fromPeerIdB64u,
                                 const QString &text,
                                 const QDateTime &timestamp,
                                 const QString &msgId)
{
    const QString from = fromPeerIdB64u.trimmed();
    const std::string fromStd  = from.toStdString();
    const std::string textStd  = text.toStdString();
    const std::string msgIdStd = msgId.toStdString();
    const int64_t tsSecs       = qtbridge::epochSecs(timestamp);
    ensureUnreadSize();

    auto shouldToast = [&]() { return m_shouldToastFn ? m_shouldToastFn() : true; };

    // First-inbound from a stranger: v3 mints a conversation row only —
    // no auto-stub Contact.  findOrCreateDirectConversation is idempotent
    // so any second receipt before our in-memory row catches up still
    // converges on the same id.
    int idx = findChatForPeer(from);
    if (idx == -1) {
        if (!m_store) return;
        const std::string convId = m_store->findOrCreateDirectConversation(fromStd);
        if (convId.empty()) return;

        AppDataStore::Conversation conv;
        if (!m_store->loadConversation(convId, conv)) return;

        // Push the new conversation to the top — onIncomingMessage's
        // job is to surface the thread.  Members for a 1:1 are just
        // [self, peer]; we only need the peer for presence subscription.
        m_chats.insert(m_chats.begin(), conv);
        m_membersByConv[conv.id] = { fromStd };
        ensureUnreadSize();
        m_unread.prepend(0);
        if (m_currentChat >= 0) m_currentChat += 1;
        idx = 0;
    }

    if (isBlockedFor(m_chats[idx])) return;

    const std::string convId = m_chats[idx].id;
    auto &msgs = m_messagesByConv[convId];

    // UI-side dedup against already-stored messages
    if (!msgIdStd.empty())
        for (const auto &m : msgs)
            if (m.msgId == msgIdStd) return;

    const bool needsSep = msgs.empty() ||
                          (tsSecs - msgs.back().timestampSecs) >= kDateSepSecs;

    AppDataStore::Message msg{false, textStd, tsSecs, msgIdStd, fromStd, ""};
    msgs.push_back(msg);
    m_chats[idx].lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    // saveMessage bumps conversations.last_active in the same TX, so we
    // don't need a separate touchConversation call.
    if (m_store) m_store->saveMessage(convId, msg);

    if (idx == m_currentChat) {
        if (needsSep) addDateSeparator(timestamp);
        addMessageBubble(text, false, /*senderName=*/QString(),
                          qtbridge::qstr(msgIdStd), qtbridge::qstr(convId));
        promoteChatToTop(idx);
        rebuildChatList();
    } else {
        m_unread[idx] += 1;
        emit unreadChanged(totalUnread());
        promoteChatToTop(idx);
        rebuildChatList();
        // After promote, the source row is now at index 0.
        if (m_notifier && shouldToast() && !isMutedFor(m_chats[0])) {
            const QString label = displayNameFor(m_chats[0]);
            m_notifier->notify(label, text);
        }
    }
}

void ChatView::onStatus(const QString &s)
{
    // Status strings come from the core's onStatus channel — group-send
    // failures, relay retry / give-up, encrypted-session unavailable,
    // etc.  Surface them as a bottom-of-screen toast so the user sees
    // when a message didn't land instead of silently losing it.
    qDebug() << "[status]" << s;
    if (!s.isEmpty()) showToast(s);
}

void ChatView::onGroupStreamBlocked(const QString& groupId,
                                       const QString& senderPeerId,
                                       qint64 fromCtr, qint64 toCtr)
{
    // pv=2 receiver hit a gap — ChatController already fired a
    // gap_request to the sender.  Surface a status toast so the user
    // knows recent messages from this peer are still in transit.
    // Once the gap fills, drained messages flow through
    // onIncomingGroupMessage as normal.
    Q_UNUSED(groupId);
    const QString senderShort = senderPeerId.left(8) + QStringLiteral("…");
    QString msg;
    if (fromCtr == toCtr) {
        msg = QString::fromUtf8("Waiting for message %1 from %2…")
                  .arg(fromCtr).arg(senderShort);
    } else {
        msg = QString::fromUtf8("Waiting for messages %1–%2 from %3…")
                  .arg(fromCtr).arg(toCtr).arg(senderShort);
    }
    qDebug() << "[group v2 blocked]" << groupId << senderPeerId
              << fromCtr << "-" << toCtr;
    showToast(msg);
}

void ChatView::onGroupMessagesLost(const QString& groupId,
                                      const QString& senderPeerId,
                                      qint64 count)
{
    // pv=2 session reset on the sender side dropped `count` buffered
    // messages from this peer.  Surface as a toast — same mechanism
    // as the blocked-stream banner.  Mobile (iOS) shows a one-shot
    // alert dialog; desktop opts for the lighter toast pattern that
    // matches the rest of the chatview.
    Q_UNUSED(groupId);
    const QString senderShort = senderPeerId.left(8) + QStringLiteral("…");
    const QString msg = count == 1
        ? QString::fromUtf8("1 message from %1 was lost during reconnection.")
              .arg(senderShort)
        : QString::fromUtf8("%1 messages from %2 were lost during reconnection.")
              .arg(count).arg(senderShort);
    qDebug() << "[group v2 lost]" << groupId << senderPeerId << count;
    showToast(msg);
}

void ChatView::onIncomingGroupMessage(const QString &fromPeerIdB64u,
                                      const QString &groupId,
                                      const QString &groupName,
                                      const QStringList &memberKeys,
                                      const QString &text,
                                      const QDateTime &ts,
                                      const QString &msgId)
{
    const std::string groupIdStd  = groupId.toStdString();
    const std::string fromStd     = fromPeerIdB64u.toStdString();
    const std::string textStd     = text.toStdString();
    const std::string msgIdStd    = msgId.toStdString();
    const int64_t     tsSecs      = qtbridge::epochSecs(ts);

    // ChatController already wired the v3 conversation row + members
    // table via setKnownGroupMembers (called from the group_msg dispatch
    // before this slot fires).  We just locate the in-memory copy and,
    // if it's missing, hydrate from the store.
    int idx = -1;
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
        if (m_chats[i].kind == AppDataStore::ConversationKind::Group
            && m_chats[i].id == groupIdStd) { idx = i; break; }

    if (idx == -1) {
        if (!m_store) return;
        AppDataStore::Conversation conv;
        if (!m_store->loadConversation(groupIdStd, conv)) {
            // ChatController.ensureGroupConversation hasn't run yet (or
            // failed); skip rather than minting a nameless local row.
            return;
        }
        // Some legacy callers ship the group_msg before setKnownMembers;
        // backfill the name + members the wire delivered.
        if (conv.groupName.empty() && !groupName.isEmpty()) {
            conv.groupName = groupName.toStdString();
            m_store->saveConversation(conv);
        }
        m_chats.push_back(conv);
        idx = static_cast<int>(m_chats.size()) - 1;

        // Pull authoritative member roster from the store.
        std::vector<std::string> mem;
        m_store->loadConversationMembers(conv.id, [&](const std::string& p) {
            mem.push_back(p);
        });
        m_membersByConv[conv.id] = std::move(mem);
        ensureUnreadSize();
        rebuildChatList();
    }

    if (isBlockedFor(m_chats[idx])) return;

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    // Merge any new member keys we didn't know about before — this is
    // how members discover each other without manual key exchange.
    // ChatController writes the same set into conversation_members on
    // its end via upsertMembersFromTrustedMessage; we're keeping the
    // in-memory copy aligned for the chat-list / presence subscriber.
    auto &members = m_membersByConv[m_chats[idx].id];
    bool membersUpdated = false;
    const std::string myKey = m_controller->myIdB64u();
    for (const QString &key : memberKeys) {
        const std::string keyStd = key.toStdString();
        const std::string keyTrimmed = trimStd(keyStd);
        if (keyTrimmed.empty()) continue;
        if (keyTrimmed == myKey) continue;
        if (std::find(members.begin(), members.end(), keyStd) == members.end()) {
            members.push_back(keyStd);
            membersUpdated = true;
        }
    }
    if (membersUpdated && m_store)
        m_store->setConversationMembers(m_chats[idx].id, members);

    // If text is empty this was a member-update-only message (no chat bubble needed).
    // Member merge above already ran, so just bail out.
    if (text.isEmpty()) return;

    const std::string convId = m_chats[idx].id;
    auto &msgs = m_messagesByConv[convId];

    if (!msgIdStd.empty())
        for (const auto &m : msgs)
            if (m.msgId == msgIdStd) return;

    const bool needsSep = msgs.empty() ||
                          (tsSecs - msgs.back().timestampSecs) >= kDateSepSecs;

    // Look up sender name from the address book.  Empty name => stick
    // with the 8-char key-prefix fallback rather than blank.
    QString senderName = fromPeerIdB64u.left(8) + "...";
    auto contactIt = m_contactsByPeer.find(fromStd);
    if (contactIt != m_contactsByPeer.end() && !contactIt->second.name.empty())
        senderName = qtbridge::qstr(contactIt->second.name);

    AppDataStore::Message msg{false, textStd, tsSecs, msgIdStd, fromStd,
                               senderName.toStdString()};
    msgs.push_back(msg);
    m_chats[idx].lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    if (m_store) m_store->saveMessage(convId, msg);

    if (idx == m_currentChat) {
        if (needsSep) addDateSeparator(ts);
        addMessageBubble(text, false, senderName,
                          qtbridge::qstr(msgIdStd), qtbridge::qstr(convId));
        promoteChatToTop(idx);
        rebuildChatList();
    } else {
        const QString chatName = displayNameFor(m_chats[idx]);

        m_unread[idx] += 1;
        emit unreadChanged(totalUnread());
        promoteChatToTop(idx);
        rebuildChatList();
        if (m_notifier && !isMutedFor(m_chats[0]))
            m_notifier->notifyGroup(senderName, chatName, text);
    }
}

void ChatView::onGroupMemberLeft(const QString& fromPeerIdB64u,
                                 const QString& groupId,
                                 const QString& groupName,
                                 const QStringList& /*memberKeys*/,
                                 const QDateTime& ts,
                                 const QString& /*msgId*/)
{
    Q_UNUSED(groupName);
    const std::string fromStd    = fromPeerIdB64u.toStdString();
    const std::string groupIdStd = groupId.toStdString();
    const int64_t     tsSecs     = qtbridge::epochSecs(ts);

    // Find the group
    int targetIndex = -1;
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].kind == AppDataStore::ConversationKind::Group
            && m_chats[i].id == groupIdStd) {
            targetIndex = i;
            break;
        }
    }
    if (targetIndex == -1) return;

    // Remove the leaver from our local group member list (mirror to
    // conversation_members so a relaunch sees the trimmed roster).
    auto &members = m_membersByConv[groupIdStd];
    members.erase(std::remove(members.begin(), members.end(), fromStd), members.end());
    if (m_store) m_store->removeConversationMember(groupIdStd, fromStd);

    // Find a display name for the leaver via the address book.
    QString leaverName = fromPeerIdB64u.left(8) + "..."; // fallback to truncated key
    auto contactIt = m_contactsByPeer.find(fromStd);
    if (contactIt != m_contactsByPeer.end() && !contactIt->second.name.empty())
        leaverName = qtbridge::qstr(contactIt->second.name);

    // System message — sender_id empty marks it as locally-generated.
    const QString systemText = leaverName + " left the group";
    AppDataStore::Message systemMsg{ false, systemText.toStdString(), tsSecs, "", "", "" };
    m_messagesByConv[groupIdStd].push_back(systemMsg);
    if (m_store) m_store->saveMessage(groupIdStd, systemMsg);

    if (targetIndex == m_currentChat) {
        addMessageBubble(systemText, false);
        rebuildChatList();
    } else {
        m_unread[targetIndex] += 1;
        emit unreadChanged(totalUnread());
        rebuildChatList();
    }
}
// ── File chunk received ───────────────────────────────────────────────────────

void ChatView::onFileChunkReceived(const QString &fromPeerIdB64u,
                                   const QString &transferId,
                                   const QString &fileName,
                                   qint64         fileSize,
                                   int            chunksReceived,
                                   int            chunksTotal,
                                   const QString &savedPath,
                                   const QDateTime  &timestamp,
                                   const QString &groupId,
                                   const QString &groupName)
{
    const QString from = fromPeerIdB64u.trimmed();
    const std::string fromStd     = from.toStdString();
    const std::string groupIdStd  = groupId.toStdString();
    const std::string transferStd = transferId.toStdString();

    // Locate the chat this file belongs to — group chat or 1:1
    int chatIndex = -1;
    if (!groupIdStd.empty()) {
        // Find existing group chat by id; if missing the conversation
        // row should already exist (set up by setKnownGroupMembers
        // before any group_msg fires).  Fall back to a hydrate-from-DB
        // pass like onIncomingGroupMessage does.
        for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
            if (m_chats[i].kind == AppDataStore::ConversationKind::Group
                && m_chats[i].id == groupIdStd) { chatIndex = i; break; }

        if (chatIndex == -1) {
            if (!m_store) return;
            AppDataStore::Conversation conv;
            if (!m_store->loadConversation(groupIdStd, conv)) return;
            if (conv.groupName.empty() && !groupName.isEmpty()) {
                conv.groupName = groupName.toStdString();
                m_store->saveConversation(conv);
            }
            m_chats.push_back(conv);
            std::vector<std::string> mem;
            m_store->loadConversationMembers(conv.id, [&](const std::string& p) {
                mem.push_back(p);
            });
            m_membersByConv[conv.id] = std::move(mem);
            chatIndex = static_cast<int>(m_chats.size()) - 1;
            ensureUnreadSize();
            rebuildChatList();
        }
    } else {
        chatIndex = findOrCreateDirectChatForPeer(from);
    }
    if (chatIndex < 0) return;
    if (isBlockedFor(m_chats[chatIndex])) return;   // drop files from blocked contacts
    const std::string convId = m_chats[chatIndex].id;

    // Find an existing in-progress record for this transferId, or create one
    auto &records = m_filesByConv[convId];
    AppDataStore::FileRecord *rec = nullptr;
    for (auto &r : records)
        if (r.transferId == transferStd) { rec = &r; break; }

    if (!rec) {
        // First chunk we've heard about — create the record
        AppDataStore::FileRecord newRec;
        newRec.transferId    = transferStd;
        newRec.chatKey       = convId;
        newRec.fileName      = fileName.toStdString();
        newRec.fileSize      = fileSize;
        newRec.peerIdB64u    = fromStd;
        newRec.peerName      = displayNameFor(m_chats[chatIndex]).toStdString();
        newRec.timestampSecs = qtbridge::epochSecs(timestamp);
        newRec.sent          = false;
        newRec.status        = static_cast<int>(FileTransferStatus::Receiving);
        newRec.chunksTotal   = chunksTotal;
        newRec.chunksComplete = 0;
        records.push_back(newRec);
        rec = &records.back();
    }

    rec->chunksComplete = chunksReceived;
    rec->chunksTotal    = chunksTotal;

    const bool complete = (chunksReceived == chunksTotal);

    if (complete) {
        m_chats[chatIndex].lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();

        // FileTransferManager has already streamed the file to disk at savedPath.
        // An empty savedPath means the transfer failed (hash mismatch, write error, etc).
        const bool saved = !savedPath.isEmpty() && QFileInfo::exists(savedPath);
        if (saved) {
            rec->status    = static_cast<int>(FileTransferStatus::Complete);
            rec->savedPath = savedPath.toStdString();
        } else {
            rec->status = static_cast<int>(FileTransferStatus::Failed);
            qWarning() << "File transfer failed:" << fileName << "(no savedPath)";
        }

        if (m_store) m_store->saveFileRecord(convId, *rec);

        // In-app toast + system tray notification
        {
            const QString senderName = displayNameFor(m_chats[chatIndex]);
            const QString toastMsg = saved
                ? QString("📎 %1 from %2").arg(fileName, senderName)
                : QString("⚠ File from %1 failed: %2").arg(senderName, fileName);
            showToast(toastMsg);
            if (m_notifier && !isMutedFor(m_chats[chatIndex]))
                m_notifier->notify(senderName, toastMsg);
        }

        // Clickable file bubble in chat
        if (chatIndex == m_currentChat)
            addFileBubble(fileName, fileSize, false);

        // Bump unread on the chat if it isn't currently open
        if (chatIndex != m_currentChat) {
            m_unread[chatIndex] += 1;
            emit unreadChanged(totalUnread());
            promoteChatToTop(chatIndex);
            rebuildChatList();
        }
    }

    // Refresh Files tab if this chat is visible
    if (chatIndex == m_currentChat)
        rebuildFilesTab();
}

// ── File chunk sent (sender-side progress) ────────────────────────────────────
// Updates the outbound FileRecord created in onAttachFile to show
// the running chunk count.  On the last chunk we flip status → Complete.
// Delivery confirmation arrives separately via onFileTransferDelivered.

void ChatView::onFileChunkSent(const QString &toPeerIdB64u,
                                const QString &transferId,
                                const QString & /*fileName*/,
                                qint64         /*fileSize*/,
                                int            chunksSent,
                                int            chunksTotal,
                                const QDateTime & /*timestamp*/,
                                const QString &groupId,
                                const QString & /*groupName*/)
{
    const std::string groupIdStd  = groupId.toStdString();
    const std::string transferStd = transferId.toStdString();

    // Locate the chat — group or 1:1.  For groups we key off groupId
    // (the transfer is per-group even though chunks fan out per-member).
    int chatIndex = -1;
    if (!groupIdStd.empty()) {
        for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
            if (m_chats[i].kind == AppDataStore::ConversationKind::Group
                && m_chats[i].id == groupIdStd) { chatIndex = i; break; }
    } else {
        chatIndex = findChatForPeer(toPeerIdB64u.trimmed());
    }
    if (chatIndex < 0) return;

    const std::string convId = m_chats[chatIndex].id;
    auto &records = m_filesByConv[convId];
    AppDataStore::FileRecord *rec = nullptr;
    for (auto &r : records) {
        if (r.transferId == transferStd && r.sent) { rec = &r; break; }
    }
    // No record yet?  onAttachFile creates the Sending record before chunks
    // fly, so this shouldn't happen — but guard against group fan-out races
    // where a second member's chunk arrives before the record was saved.
    if (!rec) return;

    rec->chunksComplete = chunksSent;
    rec->chunksTotal    = chunksTotal;
    if (chunksSent >= chunksTotal && chunksTotal > 0) {
        rec->status = static_cast<int>(FileTransferStatus::Complete);
        if (m_store) m_store->saveFileRecord(convId, *rec);
    }

    if (chatIndex == m_currentChat)
        rebuildFilesTab();
}

// ── Avatar received ───────────────────────────────────────────────────────────

void ChatView::onAvatarReceived(const QString &peerIdB64u,
                                const QString &displayName,
                                const QString &avatarB64)
{
    const std::string peerIdStd   = peerIdB64u.toStdString();
    const std::string avatarStd   = avatarB64.toStdString();
    const std::string displayStd  = displayName.toStdString();

    // v3 rule: address-book is user-curated.  An avatar broadcast does
    // NOT auto-create a contact.  We do, however, refresh existing
    // contact rows + the displayed avatar on any conversation row that
    // points at this peer.
    bool firstTime = false;
    auto contactIt = m_contactsByPeer.find(peerIdStd);
    if (contactIt != m_contactsByPeer.end()) {
        firstTime = contactIt->second.avatarB64.empty() && !avatarStd.empty();
        // Update name only when we don't already have one — never
        // clobber the user's local nickname with the peer's broadcast.
        if (!displayStd.empty() && contactIt->second.name.empty())
            contactIt->second.name = displayStd;
        contactIt->second.avatarB64 = avatarStd;
        if (m_store) {
            // Persist via the dedicated UPDATE (saveContact would also
            // rewrite name/subtitle/etc unnecessarily; saveContactAvatar
            // is a single-column UPDATE).  Push the rebuilt name only
            // when we touched it above.
            if (!displayStd.empty() && contactIt->second.name == displayStd)
                m_store->saveContact(contactIt->second);
            m_store->saveContactAvatar(peerIdStd, avatarStd);
        }
    }

    // Find the matching 1:1 conversation row (if any) so we can refresh
    // its rendering.  The conversation persists regardless of contact —
    // a stranger we received from earlier already has a row.
    int idx = findChatForPeer(peerIdB64u);

    // Reciprocate first-contact only when we have an established
    // conversation (i.e. the peer has actually messaged us).  Avoids
    // sending our avatar to a random peer that just dropped a profile
    // broadcast.
    if (firstTime && idx >= 0 && m_store) {
        const std::string myName   = m_store->loadSetting("displayName");
        const std::string myAvatar = m_store->loadSetting("avatarData");
        if (!myName.empty()) {
            const std::string myAvatarIsPhoto = m_store->loadSetting("avatarIsPhoto");
            const std::string broadcastAvatar = (myAvatarIsPhoto == "true") ? myAvatar : std::string();
            m_controller->sendAvatar(peerIdStd, myName, broadcastAvatar);
        }
    }

    if (idx < 0) return;

    // Rebuild the list so the avatar label updates immediately
    rebuildChatList();

    // Refresh the active chat header avatar if this contact is selected
    if (m_currentChat == idx) {
        const QString qName = displayNameFor(m_chats[idx]);
        if (!avatarB64.isEmpty()) {
            QPixmap px;
            px.loadFromData(QByteArray::fromBase64(avatarB64.toUtf8()));
            if (!px.isNull()) {
                m_ui->chatAvatarLabel->setPixmap(makeCircularPixmap(px, 44));
                m_ui->chatAvatarLabel->setText("");
            }
        } else {
            const QString ch = qName.isEmpty() ? "?" : QString(qName[0]);
            m_ui->chatAvatarLabel->setPixmap(
                renderInitialsAvatar(ch, avatarColorForName(qName), 44));
            m_ui->chatAvatarLabel->setText("");
        }
        m_ui->chatTitleLabel->setText(qName);
    }

    if (firstTime)
        showToast(displayNameFor(m_chats[idx]) + "'s profile has been updated");
}

void ChatView::onGroupRenamed(const QString &groupId, const QString &newName)
{
    const std::string groupIdStd = groupId.toStdString();
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].kind != AppDataStore::ConversationKind::Group
            || m_chats[i].id != groupIdStd) continue;
        m_chats[i].groupName = newName.toStdString();
        if (m_store) m_store->saveConversation(m_chats[i]);
        rebuildChatList();
        if (m_currentChat == i)
            m_ui->chatTitleLabel->setText(newName);
        return;
    }
}

void ChatView::onGroupAvatarReceived(const QString &groupId, const QString &avatarB64)
{
    const std::string groupIdStd = groupId.toStdString();
    const std::string avatarStd  = avatarB64.toStdString();
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].kind != AppDataStore::ConversationKind::Group
            || m_chats[i].id != groupIdStd) continue;

        // Only relay and persist if this is actually new to us
        if (m_chats[i].groupAvatarB64 == avatarStd) return;

        m_chats[i].groupAvatarB64 = avatarStd;
        if (m_store) m_store->saveConversation(m_chats[i]);

        // Relay to all group members so stragglers receive it too
        const auto memIt = m_membersByConv.find(groupIdStd);
        if (m_controller && memIt != m_membersByConv.end() && !memIt->second.empty())
            m_controller->sendGroupAvatar(groupIdStd, avatarStd, memIt->second);

        rebuildChatList();
        if (m_currentChat == i) loadChat(i);
        return;
    }
}

// ── Attach / send file ────────────────────────────────────────────────────────

void ChatView::onAttachFile()
{
    if (m_currentChat < 0) return;

    const AppDataStore::Conversation &chat = m_chats[m_currentChat];
    const bool isGroup = (chat.kind == AppDataStore::ConversationKind::Group);

    // Recipient pre-flight: 1:1 needs a peer id; group needs at least
    // one member.  Either being empty is a logic bug — bail with a
    // user-visible warning rather than dispatching to nowhere.
    const auto memIt = m_membersByConv.find(chat.id);
    const bool hasMembers =
        isGroup ? (memIt != m_membersByConv.end() && !memIt->second.empty())
                : !chat.directPeerId.empty();
    if (!hasMembers) {
        QMessageBox::warning(m_ui->centralwidget, "No Recipient",
                             isGroup ? "This group has no members yet — cannot send a file."
                                     : "This contact has no public key — cannot send a file securely.");
        return;
    }

    const QString path = QFileDialog::getOpenFileName(
        m_ui->centralwidget, "Send File",
        QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    if (path.isEmpty()) return;

    // Path-based: we never load the file into RAM. Just stat its size.
    QFileInfo finfo(path);
    if (!finfo.exists() || !finfo.isFile()) {
        QMessageBox::warning(m_ui->centralwidget, "Error", "File not found.");
        return;
    }
    const qint64 fileSize = finfo.size();
    constexpr qint64 kMax = ChatController::maxFileBytes();
    if (fileSize > kMax) {
        QMessageBox::warning(m_ui->centralwidget, "File Too Large",
                             QString("Maximum file size is %1 MB.\nThis file is %2.")
                                 .arg(kMax / (1024 * 1024)).arg(formatFileSize(fileSize)));
        return;
    }

    const QString fileName = finfo.fileName();

    // ── Dispatch to controller ──────────────────────────────────────────────
    std::string localTransferId;
    int totalChunks = 0;
    constexpr qint64 kChunk = 240LL * 1024;

    if (isGroup) {
        localTransferId = m_controller->sendGroupFile(
            chat.id, chat.groupName,
            memIt->second, fileName.toStdString(), path.toStdString());
        if (!localTransferId.empty())
            totalChunks = int((fileSize + kChunk - 1) / kChunk);
    } else {
        localTransferId = m_controller->sendFile(
            chat.directPeerId, fileName.toStdString(), path.toStdString());
        if (!localTransferId.empty())
            totalChunks = int((fileSize + kChunk - 1) / kChunk);
    }

    if (localTransferId.empty()) return; // dispatch failed

    // Record the outbound transfer as IN-FLIGHT.  Chunks don't fly until
    // the receiver ack's the file_key announcement, so marking Complete
    // here would be a lie — we track real progress via onFileChunkSent
    // callbacks instead and flip to Complete on the last chunk.
    // savedPath = original path so the Download/Open button always
    // points at the still-local source file.
    AppDataStore::FileRecord rec;
    rec.transferId     = localTransferId;
    rec.chatKey        = chat.id;
    rec.fileName       = fileName.toStdString();
    rec.fileSize       = fileSize;
    rec.peerIdB64u     = isGroup ? std::string{} : chat.directPeerId;
    rec.peerName       = displayNameFor(chat).toStdString();
    rec.timestampSecs  = QDateTime::currentDateTime().toSecsSinceEpoch();
    rec.sent           = true;
    rec.status         = static_cast<int>(FileTransferStatus::Sending);
    rec.chunksTotal    = totalChunks;
    rec.chunksComplete = 0;
    rec.savedPath      = path.toStdString();
    m_filesByConv[chat.id].push_back(rec);
    if (m_store) m_store->saveFileRecord(chat.id, rec);

    rebuildFilesTab();

    // "You sent <file>" bubble in the chat transcript.  Progress still
    // animates on the file card in the Files tab via onFileChunkSent.
    addFileBubble(fileName, fileSize, true);
}

// ── Private slots ─────────────────────────────────────────────────────────────

void ChatView::onChatSelected(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chats.size()) || index == m_currentChat) return;
    m_currentChat = index;
    loadChat(index);
    ensureUnreadSize();
    if (m_unread[index] > 0) {
        m_unread[index] = 0;
        emit unreadChanged(totalUnread());
        rebuildChatList();
    }

    // Tier 1 PQ — kick an async fetch of the peer's identity
    // bundle so the kem_pub is in our DB by the time the user
    // types + sends msg1.  ChatController dedupes on (a) already-
    // cached and (b) in-flight, so this is safe to call on every
    // chat selection.  Group conversations don't have a single
    // direct peer; we fetch only for direct chats.
    const auto& conv = m_chats[index];
    if (conv.kind == AppDataStore::ConversationKind::Direct &&
        !conv.directPeerId.empty() && m_controller) {
        m_controller->requestIdentityBundleFetch(conv.directPeerId);
    }

    // Re-apply search highlights when switching chats
    if (!m_searchQuery.isEmpty()) {
        m_searchMatchIndices.clear();
        m_searchMatchCurrent = -1;
        const std::string queryStd = m_searchQuery.toLower().toStdString();
        const auto &msgs = m_messagesByConv[m_chats[m_currentChat].id];
        for (int i = 0; i < static_cast<int>(msgs.size()); ++i) {
            QString lowered = qtbridge::qstr(msgs[i].text).toLower();
            if (lowered.contains(m_searchQuery))
                m_searchMatchIndices.append(i);
        }
        (void)queryStd;
        highlightSearchMatches();
    }
}

void ChatView::onSendMessage()
{
    if (m_currentChat < 0) return;
    QString text = m_ui->messageInput->text().trimmed();
    if (text.isEmpty()) return;

    AppDataStore::Conversation &cur = m_chats[m_currentChat];
    const bool isGroup = (cur.kind == AppDataStore::ConversationKind::Group);

    // Pre-flight: 1:1 needs a directPeerId, group needs at least one
    // member.  The "no keys" path used to fire a system bubble; preserve
    // that affordance so users get a visible cue rather than silent drop.
    const auto memIt = m_membersByConv.find(cur.id);
    const bool hasRecipient =
        isGroup ? (memIt != m_membersByConv.end() && !memIt->second.empty())
                : !cur.directPeerId.empty();
    if (!hasRecipient) {
        addMessageBubble(isGroup ? "Group has no members."
                                  : "No public key for this conversation.", false);
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    const int64_t nowSecs = now.toSecsSinceEpoch();
    auto &msgs = m_messagesByConv[cur.id];
    if (msgs.empty() || (nowSecs - msgs.back().timestampSecs) >= kDateSepSecs)
        addDateSeparator(now);

    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    // Outbound messages set senderId="" — caller is self by definition.
    AppDataStore::Message msg{true, text.toStdString(), nowSecs,
                               msgId.toStdString(), "", ""};
    msgs.push_back(msg);

    if (m_store) m_store->saveMessage(cur.id, msg);

    addMessageBubble(text, true, /*senderName=*/QString(), msgId, qtbridge::qstr(cur.id));
    m_ui->messageInput->clear();

    // Promote the current chat to the top of the list so outbound
    // activity surfaces the thread the same way inbound does.
    // saveMessage already bumped conversations.last_active inside its
    // transaction; we mirror it on the in-memory copy.
    cur.lastActiveSecs = nowSecs;
    if (m_currentChat > 0) {
        promoteChatToTop(m_currentChat);
        rebuildChatList();
        m_ui->chatList->setCurrentRow(0);
    }

    if (isGroup) {
        m_controller->sendGroupMessageViaMailbox(
            cur.id, cur.groupName, memIt->second, text.toStdString());
    } else {
        m_controller->sendText(cur.directPeerId, text.toStdString());
    }
}

void ChatView::onSearchChanged(const QString &text)
{
    const QString q = text.trimmed().toLower();
    m_searchQuery = q;
    m_searchMatchIndices.clear();
    m_searchMatchCurrent = -1;

    // ── 1. Filter sidebar chats ──────────────────────────────────────────────
    for (int i = 0; i < m_ui->chatList->count(); ++i) {
        const AppDataStore::Conversation &c = m_chats[i];
        bool match = q.isEmpty() || displayNameFor(c).toLower().contains(q);
        if (!match) {
            const auto it = m_messagesByConv.find(c.id);
            if (it != m_messagesByConv.end()) {
                for (const auto &m : it->second)
                    if (qtbridge::qstr(m.text).toLower().contains(q)) { match = true; break; }
            }
        }
        m_ui->chatList->item(i)->setHidden(!match);
    }
    if (m_currentChat >= 0) {
        auto *cur = m_ui->chatList->item(m_currentChat);
        if (cur && cur->isHidden()) m_ui->chatList->clearSelection();
    }

    // ── 2. Highlight matching messages in current chat ────────────────────────
    if (m_currentChat >= 0 && m_currentChat < static_cast<int>(m_chats.size()) && !q.isEmpty()) {
        const auto &msgs = m_messagesByConv[m_chats[m_currentChat].id];
        for (int i = 0; i < static_cast<int>(msgs.size()); ++i)
            if (qtbridge::qstr(msgs[i].text).toLower().contains(q))
                m_searchMatchIndices.append(i);
    }
    highlightSearchMatches();

    // ── 3. Filter file cards in Files tab ────────────────────────────────────
    rebuildFilesTab();
}

// ── Search highlight helpers ─────────────────────────────────────────────────

void ChatView::highlightSearchMatches()
{
    QLayout *layout = m_ui->scrollAreaWidgetContents->layout();
    if (!layout) return;

    // Walk the layout items — each is either a date separator or a message row.
    // Date separators have a fixed height of 28 (see addDateSeparator).
    // We track message index separately.
    const bool hasQuery = !m_searchQuery.isEmpty();
    int msgIdx = 0;
    const QSet<int> matchSet(m_searchMatchIndices.begin(), m_searchMatchIndices.end());

    for (int i = 0; i < layout->count(); ++i) {
        QWidget *w = layout->itemAt(i)->widget();
        if (!w) continue;

        // Skip date separators (fixed height 28) and the bottom spacer
        if (w->maximumHeight() == 28) continue;

        // Find the QLabel bubble inside this message row
        QList<QLabel*> labels = w->findChildren<QLabel*>();
        for (QLabel *lbl : labels) {
            // Bubbles have border-radius:14px in their style; sender name labels don't
            if (!lbl->styleSheet().contains("border-radius:14px")) continue;

            if (hasQuery && matchSet.contains(msgIdx)) {
                // Highlight: add a gold border, shrink padding to compensate
                // so total box size stays the same and text doesn't reflow.
                // Original padding: 10px 14px
                const bool isFocused = (m_searchMatchCurrent >= 0 &&
                                        m_searchMatchCurrent < m_searchMatchIndices.size() &&
                                        m_searchMatchIndices[m_searchMatchCurrent] == msgIdx);
                const QString borderColor = isFocused ? "#ffb300" : "#997a00";
                const int bw = isFocused ? 2 : 1;
                const int pV = 10 - bw, pH = 14 - bw;   // compensated padding
                QString ss = lbl->styleSheet();
                ss.remove(QRegularExpression("border:\\d+px solid #[0-9a-fA-F]+;"));
                ss.replace(QRegularExpression("padding:\\d+px \\d+px;"),
                           QString("padding:%1px %2px;").arg(pV).arg(pH));
                ss.append(QString("border:%1px solid %2;").arg(bw).arg(borderColor));
                lbl->setStyleSheet(ss);
            } else {
                // Remove search border, restore original padding
                QString ss = lbl->styleSheet();
                ss.remove(QRegularExpression("border:\\d+px solid #[0-9a-fA-F]+;"));
                ss.replace(QRegularExpression("padding:\\d+px \\d+px;"),
                           QString("padding:10px 14px;"));
                lbl->setStyleSheet(ss);
            }
        }
        msgIdx++;
    }

    // If we have matches and none is focused yet, focus the first
    if (!m_searchMatchIndices.isEmpty() && m_searchMatchCurrent < 0) {
        m_searchMatchCurrent = 0;
        highlightSearchMatches();          // re-run to apply focused style
        scrollToMatch(m_searchMatchCurrent);
    }
}

void ChatView::scrollToMatch(int matchIdx)
{
    if (matchIdx < 0 || matchIdx >= m_searchMatchIndices.size()) return;

    const int targetMsgIdx = m_searchMatchIndices[matchIdx];
    QLayout *layout = m_ui->scrollAreaWidgetContents->layout();
    if (!layout) return;

    int msgIdx = 0;
    for (int i = 0; i < layout->count(); ++i) {
        QWidget *w = layout->itemAt(i)->widget();
        if (!w) continue;
        if (w->maximumHeight() == 28) continue; // date separator
        if (msgIdx == targetMsgIdx) {
            m_ui->messageScroll->ensureWidgetVisible(w, 50, 80);
            return;
        }
        msgIdx++;
    }
}

void ChatView::navigateSearch(int delta)
{
    if (m_searchMatchIndices.isEmpty()) return;
    m_searchMatchCurrent += delta;
    if (m_searchMatchCurrent >= m_searchMatchIndices.size())
        m_searchMatchCurrent = 0;
    if (m_searchMatchCurrent < 0)
        m_searchMatchCurrent = m_searchMatchIndices.size() - 1;
    highlightSearchMatches();
    scrollToMatch(m_searchMatchCurrent);
}

void ChatView::onEditProfile()
{
    dialogs::ProfileInput in;
    in.currentName      = m_ui->profileNameLabel->text();
    in.currentAvatarB64 = m_store ? qtbridge::qstr(m_store->loadSetting("avatarData")) : QString();
    in.myKey            = QString::fromStdString(m_controller->myIdB64u());

    dialogs::ProfileOutput out;
    if (!dialogs::openProfileEditor(m_ui->centralwidget, in, out)) return;

    const QString displayName = out.newName.isEmpty() ? "Me" : out.newName;
    m_ui->profileNameLabel->setText(displayName);
    m_ui->profileAvatarLabel->setPixmap(makeCircularPixmap(out.thumb200, 40));
    m_ui->profileAvatarLabel->setText("");

    if (m_store) {
        m_store->saveSetting("displayName",   displayName.toStdString());
        m_store->saveSetting("avatarData",    out.newAvatarB64.toStdString());
        m_store->saveSetting("avatarIsPhoto", out.usingPhoto ? "true" : "false");
    }

    // Broadcast to all 1:1 conversations. Empty avatar when using
    // initials so the receiver falls back to initials derived from
    // their own saved name for us.
    const std::string broadcastAvatar = out.usingPhoto ? out.newAvatarB64.toStdString() : std::string();
    for (const auto &chat : m_chats) {
        if (chat.kind == AppDataStore::ConversationKind::Direct
            && !chat.directPeerId.empty())
            m_controller->sendAvatar(chat.directPeerId, displayName.toStdString(), broadcastAvatar);
    }
}

void ChatView::onEditContact(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chats.size())) return;
    AppDataStore::Conversation &conv = m_chats[index];
    const bool isGroup = (conv.kind == AppDataStore::ConversationKind::Group);

    if (isGroup) {
        // ── Group editor ────────────────────────────────────────────────────
        QString     name    = qtbridge::qstr(conv.groupName);
        QString     avatar  = qtbridge::qstr(conv.groupAvatarB64);
        bool        muted   = conv.muted;
        QStringList members = qtbridge::qstrList(m_membersByConv[conv.id]);

        const QString oldName    = name;
        const QString oldAvatar  = avatar;
        const QStringList oldMembers = members;

        // Build the address-book snapshot the picker draws from.  The
        // dialog keeps display-name lookup local rather than reaching
        // back into ChatView state.
        std::vector<dialogs::GroupAddressBookEntry> book;
        const std::string myKey = m_controller->myIdB64u();
        for (const auto &kv : m_contactsByPeer) {
            if (kv.first == myKey) continue;     // never self-list
            dialogs::GroupAddressBookEntry e;
            e.peerId      = qtbridge::qstr(kv.first);
            e.displayName = qtbridge::qstr(kv.second.name);
            book.push_back(std::move(e));
        }

        // Member double-click drills into the per-member contact
        // editor.  Modal-on-modal: the group editor stays alive while
        // the contact dialog runs, so the user can drill in, edit, and
        // back out without losing in-progress group edits.
        auto onMemberActivated = [this](const QString &peerId) {
            openContactDialogForPeer(peerId);
        };

        const GroupEditorResult result = openGroupEditor(
            m_ui->centralwidget, "Edit Group",
            name, avatar, muted, members, book,
            /*showDestructiveActions=*/true,
            std::move(onMemberActivated));

        if (result == GroupEditorResult::Saved && !name.isEmpty()) {
            conv.groupName       = name.toStdString();
            conv.groupAvatarB64  = avatar.toStdString();
            conv.muted           = muted;
            const std::vector<std::string> stdMembers = qtbridge::stdstrList(members);
            m_membersByConv[conv.id] = stdMembers;

            if (m_store) {
                m_store->saveConversation(conv);
                m_store->setConversationMembers(conv.id, stdMembers);
            }
            rebuildChatList();
            if (m_currentChat == index)
                m_ui->chatTitleLabel->setText(name);

            // Broadcast group changes to current member set
            if (name != oldName)
                m_controller->sendGroupRename(conv.id, name.toStdString(), stdMembers);
            if (avatar != oldAvatar)
                m_controller->sendGroupAvatar(conv.id, avatar.toStdString(), stdMembers);
            if (members != oldMembers)
                m_controller->sendGroupMemberUpdate(conv.id, conv.groupName, stdMembers);
        } else if (result == GroupEditorResult::Removed) {
            // "Delete Group" is local-only — wipe the chat view, files,
            // local message store via CASCADE.  No network broadcast:
            // other members aren't told we deleted, only that we left
            // (which is a separate user action).
            if (m_store) m_store->deleteConversation(conv.id);
            m_messagesByConv.erase(conv.id);
            m_filesByConv.erase(conv.id);
            m_membersByConv.erase(conv.id);
            m_chats.erase(m_chats.begin() + index);
            m_unread.remove(index);
            if (m_currentChat == index) m_currentChat = -1;
            else if (m_currentChat > index) m_currentChat -= 1;
            rebuildChatList();
            if (!m_chats.empty() && m_currentChat < 0)
                m_ui->chatList->setCurrentRow(0);
        } else if (result == GroupEditorResult::Left) {
            // "Leave Group" is purely a network-side signal: broadcast
            // group_leave so peers drop us from their rosters.  Local
            // chat data stays put — to also wipe locally the user
            // chooses Delete Group as a separate action.  We don't
            // hide here either; archive is a separate user action.
            const auto memSnapshot = m_membersByConv[conv.id];
            m_controller->sendGroupLeaveNotification(
                conv.id, conv.groupName, memSnapshot);
            rebuildChatList();
            if (!m_chats.empty() && m_currentChat < 0)
                m_ui->chatList->setCurrentRow(0);
        } else if (result == GroupEditorResult::SessionsReset) {
            // Causally-Linked Pairwise: there's no group-level session,
            // only one DR session per (us, member) pair.  "Reset
            // Sessions" iterates every member and wipes the pair.
            // Each member's safety number changes; the user has to
            // re-verify each one.  Self is excluded (we don't have a
            // session with ourselves).
            const std::string me = m_controller->myIdB64u();
            for (const std::string &member : m_membersByConv[conv.id]) {
                if (member.empty() || member == me) continue;
                m_controller->resetSession(member);
            }
        }
        return;
    }

    // ── 1:1 conversation editor ────────────────────────────────────────────
    // Edits the conversation row itself: thread-mute, archive (in
    // chat list), and Delete Chat.  The address-book entry for the
    // peer is reached via a "View Contact" / "Add Contact" drill-in
    // that pushes a nested modal openContactEditor.
    const AppDataStore::Contact *contactPtr = nullptr;
    auto it = m_contactsByPeer.find(conv.directPeerId);
    if (it != m_contactsByPeer.end()) contactPtr = &it->second;

    auto onViewContact = [this](const QString &peerId) {
        openContactDialogForPeer(peerId);
    };
    auto onAddContact = [this](const QString &peerId) {
        openAddContactPrefilled(peerId);
    };

    const std::string convId = conv.id;
    const ConversationEditorResult result =
        openConversationEditor(m_ui->centralwidget, conv, contactPtr,
                               m_controller,
                               std::move(onViewContact),
                               std::move(onAddContact));

    if (result == ConversationEditorResult::Saved) {
        // openConversationEditor mutates conv.muted / conv.inChatList
        // in place; persist via the dedicated per-field updaters so we
        // don't round-trip the encrypted name/avatar columns.
        if (m_store) {
            m_store->setConversationMuted(conv.id, conv.muted);
            m_store->setConversationInChatList(conv.id, conv.inChatList);
        }

        // Archived rows drop off the visible chat list immediately,
        // mirroring the Leave Group pathway above.
        if (!conv.inChatList) {
            m_chats.erase(m_chats.begin() + index);
            m_unread.remove(index);
            if (m_currentChat == index) m_currentChat = -1;
            else if (m_currentChat > index) m_currentChat -= 1;
        }
        rebuildChatList();
        if (m_currentChat == index)
            m_ui->chatTitleLabel->setText(displayNameFor(conv));
    } else if (result == ConversationEditorResult::Deleted) {
        // CASCADE-delete the conversation row (messages + files +
        // members go with it via FK ON DELETE CASCADE).  The
        // address-book contact stays put — that's the whole point of
        // the v3 split.
        if (m_store) m_store->deleteConversation(convId);
        m_messagesByConv.erase(convId);
        m_filesByConv.erase(convId);
        m_membersByConv.erase(convId);
        m_chats.erase(m_chats.begin() + index);
        m_unread.remove(index);
        if (m_currentChat == index) {
            m_currentChat = -1;
            clearMessages();
        } else if (m_currentChat > index) {
            m_currentChat -= 1;
        }
        rebuildChatList();
        if (!m_chats.empty() && m_currentChat < 0)
            m_ui->chatList->setCurrentRow(0);
        emit unreadChanged(totalUnread());
    } else if (result == ConversationEditorResult::SessionReset) {
        // Wipe the pairwise DR session with this peer.  Next message
        // (in either direction) triggers a fresh handshake; the safety
        // number changes after that, so the user has to re-verify.
        if (!conv.directPeerId.empty())
            m_controller->resetSession(conv.directPeerId);
    }
}

void ChatView::openContactDialogForPeer(const QString &peerIdB64u)
{
    if (peerIdB64u.isEmpty()) return;

    // Hydrate from the address book if a row exists; otherwise present
    // a blank Contact stub keyed by peer id so the editor can curate
    // them in.  saveContact is upsert by PK so either path round-trips
    // through the same path.
    const std::string peerStd = peerIdB64u.toStdString();
    AppDataStore::Contact contact;
    bool hasContact = false;
    auto it = m_contactsByPeer.find(peerStd);
    if (it != m_contactsByPeer.end()) { contact = it->second; hasContact = true; }
    else                              { contact.peerIdB64u = peerStd; }

    // Block state lives in `blocked_keys` (Phase 3h) — round-tripped
    // out-of-band so the dialog never has to know about a separate
    // table.  On Blocked result we sync our in-memory mirror + persist
    // via the dedicated CRUD without touching the contact row.
    bool isBlockedInOut = m_blockedKeys.count(peerStd) > 0;
    const ContactEditorResult result =
        openContactEditor(m_ui->centralwidget, contact, isBlockedInOut,
                          m_controller, /*showDestructiveActions=*/true);

    if (result == ContactEditorResult::Saved
        || result == ContactEditorResult::Blocked) {
        if (m_store) m_store->saveContact(contact);
        m_contactsByPeer[contact.peerIdB64u] = contact;
        if (result == ContactEditorResult::Blocked && m_store) {
            if (isBlockedInOut) {
                m_store->addBlockedKey(peerStd,
                    QDateTime::currentSecsSinceEpoch());
                m_blockedKeys.insert(peerStd);
            } else {
                m_store->removeBlockedKey(peerStd);
                m_blockedKeys.erase(peerStd);
            }
        }
        rebuildChatList();
        if (m_currentChat >= 0
            && m_currentChat < static_cast<int>(m_chats.size())) {
            m_ui->chatTitleLabel->setText(displayNameFor(m_chats[m_currentChat]));
        }
    } else if (result == ContactEditorResult::Removed) {
        // "Remove from Address Book" = forget the contacts row only.
        // Chat history with this peer stays — Delete Chat in the
        // conversation editor wipes the transcript separately.
        if (hasContact && m_store) m_store->deleteContact(contact.peerIdB64u);
        m_contactsByPeer.erase(contact.peerIdB64u);
        rebuildChatList();
    } else if (result == ContactEditorResult::SessionReset) {
        // Persist any name/avatar/etc. edits the user made before
        // hitting Reset, then wipe the ratchet so the next message
        // triggers a fresh handshake.
        if (m_store) m_store->saveContact(contact);
        m_contactsByPeer[contact.peerIdB64u] = contact;
        if (!contact.peerIdB64u.empty())
            m_controller->resetSession(contact.peerIdB64u);
        rebuildChatList();
    }
}

void ChatView::openAddContactPrefilled(const QString &peerIdB64u)
{
    if (peerIdB64u.isEmpty()) return;
    if (!isValidPublicKey(peerIdB64u)) {
        QMessageBox::warning(m_ui->centralwidget, "Invalid Key",
            "The peer's key is not a valid 43-character public key.");
        return;
    }
    const std::string peerStd = peerIdB64u.toStdString();
    if (m_contactsByPeer.count(peerStd)) {
        // Already a contact — nothing to do.  Drill straight into the
        // address-book editor instead.
        openContactDialogForPeer(peerIdB64u);
        return;
    }

    // Lightweight inline dialog for naming a peer that's already
    // talking to us but isn't yet in the address book.  We don't
    // re-route to onAddContact() because that flow also offers the
    // Create-Group path, which doesn't make sense in this context.
    QDialog dlg(m_ui->centralwidget);
    dlg.setWindowTitle("Add Contact");
    dialogs::applyStyle(&dlg);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(14); layout->setContentsMargins(24, 24, 24, 24);
    auto *ttl = new QLabel("Add Contact", &dlg);
    ttl->setObjectName("dlgTitle");
    layout->addWidget(ttl);

    auto *sp = new QFrame(&dlg);
    sp->setFrameShape(QFrame::HLine);
    sp->setStyleSheet("color:#2a2a2a;");
    layout->addWidget(sp);

    layout->addWidget(new QLabel("Display Name", &dlg));
    auto *nameEdit = new QLineEdit(&dlg);
    nameEdit->setPlaceholderText("Give this contact a nickname…");
    layout->addWidget(nameEdit);

    layout->addWidget(new QLabel("Public Key", &dlg));
    auto *keyDisplay = new QLineEdit(peerIdB64u, &dlg);
    keyDisplay->setReadOnly(true);
    themeStyles::applyRole(keyDisplay, "keyDisplay",
        themeStyles::keyDisplayCss(ThemeManager::instance().current()));
    layout->addWidget(keyDisplay);

    layout->addStretch();

    auto *br  = new QHBoxLayout;
    auto *can = new QPushButton("Cancel", &dlg); can->setObjectName("cancelBtn");
    auto *sav = new QPushButton("Save",   &dlg); sav->setObjectName("saveBtn");
    sav->setDefault(true);
    br->setSpacing(10); br->addStretch();
    br->addWidget(can); br->addWidget(sav);
    layout->addLayout(br);

    QObject::connect(can, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(sav, &QPushButton::clicked, &dlg, &QDialog::accept);

    if (dlg.exec() != QDialog::Accepted) return;

    const QString name = nameEdit->text().trimmed();
    if (name.isEmpty()) return;

    AppDataStore::Contact nc;
    nc.peerIdB64u = peerStd;
    nc.name       = name.toStdString();
    nc.subtitle   = "Secure chat";
    if (m_store) m_store->saveContact(nc);
    m_contactsByPeer[peerStd] = nc;
    rebuildChatList();
}

void ChatView::onAddContact()
{
    QDialog dlg(m_ui->centralwidget);
    dlg.setWindowTitle("Add Contact"); dialogs::applyStyle(&dlg);
    dlg.setMinimumWidth(420); dlg.setModal(true);

    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(14); layout->setContentsMargins(24,24,24,24);
    auto *ttl = new QLabel("Add Contact",&dlg); ttl->setObjectName("dlgTitle");
    layout->addWidget(ttl);
    auto *sp = new QFrame(&dlg); sp->setFrameShape(QFrame::HLine);
    sp->setStyleSheet("color:#2a2a2a;"); layout->addWidget(sp);
    layout->addWidget(new QLabel("Display Name",&dlg));
    auto *nameEdit = new QLineEdit(&dlg); layout->addWidget(nameEdit);
    layout->addWidget(new QLabel("Public Key",&dlg));
    auto *keyRow_   = new QHBoxLayout;
    keyRow_->setSpacing(8);
    auto *keyInput  = new QLineEdit(&dlg);
    keyInput->setPlaceholderText("Paste their 43-character public key…");
    keyRow_->addWidget(keyInput, 1);
    auto *pasteBtn  = new QPushButton("Paste", &dlg);
    pasteBtn->setAutoDefault(false);
    themeStyles::applyRole(pasteBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    QObject::connect(pasteBtn, &QPushButton::clicked, [keyInput]() {
        // Trim whitespace/newlines that often ride along when a key is
        // copied from a chat message — saves the user a manual edit
        // before isValidPublicKey rejects it for length.
        keyInput->setText(QApplication::clipboard()->text().trimmed());
    });
    keyRow_->addWidget(pasteBtn);
    layout->addLayout(keyRow_);

    layout->addStretch();

    auto *br     = new QHBoxLayout;
    auto *grpBtn = new QPushButton("Create Group Chat",&dlg);
    auto *can    = new QPushButton("Cancel",&dlg); can->setObjectName("cancelBtn");
    auto *sav    = new QPushButton("Save",  &dlg); sav->setObjectName("saveBtn");
    themeStyles::applyRole(grpBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    br->setSpacing(10); br->addWidget(grpBtn); br->addStretch();
    br->addWidget(can); br->addWidget(sav);
    layout->addLayout(br);

    bool createGroup = false;
    QObject::connect(can,    &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(sav,    &QPushButton::clicked, &dlg, &QDialog::accept);
    QObject::connect(grpBtn, &QPushButton::clicked, [&](){ createGroup=true; dlg.accept(); });

    if (dlg.exec() != QDialog::Accepted) return;

    if (createGroup) {
        if (m_contactsByPeer.empty()) {
            QMessageBox::information(m_ui->centralwidget,"No Contacts",
                                     "Add some contacts first before creating a group."); return; }

        QDialog gd(m_ui->centralwidget);
        gd.setWindowTitle("New Group Chat"); dialogs::applyStyle(&gd);
        gd.setMinimumWidth(380);
        auto *gl = new QVBoxLayout(&gd); gl->setSpacing(12); gl->setContentsMargins(24,24,24,24);
        auto *gt = new QLabel("New Group Chat",&gd); gt->setObjectName("dlgTitle");
        gl->addWidget(gt); gl->addWidget(new QLabel("Group Name",&gd));
        auto *gn = new QLineEdit(&gd); gn->setPlaceholderText("Enter group name…");
        gl->addWidget(gn); gl->addWidget(new QLabel("Select Members",&gd));
        auto *ml = new QListWidget(&gd); ml->setFixedHeight(160);
        const std::string myKey = m_controller->myIdB64u();
        // Map address-book entries by display label so the post-pick
        // lookup can find the peer id from the QListWidget row.
        for (const auto &kv : m_contactsByPeer) {
            const auto &c = kv.second;
            if (c.peerIdB64u == myKey) continue;
            const QString label = c.name.empty()
                ? qtbridge::qstr(c.peerIdB64u).left(8) + "…"
                : qtbridge::qstr(c.name);
            auto *it = new QListWidgetItem(label, ml);
            it->setCheckState(Qt::Unchecked);
            it->setData(Qt::UserRole, qtbridge::qstr(c.peerIdB64u));
        }
        gl->addWidget(ml);
        auto *gbr = new QHBoxLayout;
        auto *gc  = new QPushButton("Cancel",&gd); gc->setObjectName("cancelBtn");
        auto *gcr = new QPushButton("Create",&gd); gcr->setObjectName("saveBtn");
        gbr->addStretch(); gbr->addWidget(gc); gbr->addWidget(gcr);
        gl->addLayout(gbr);
        QObject::connect(gc, &QPushButton::clicked, &gd, &QDialog::reject);
        QObject::connect(gcr,&QPushButton::clicked, &gd, &QDialog::accept);
        if (gd.exec() != QDialog::Accepted) return;

        const QString gname = gn->text().trimmed(); if(gname.isEmpty()) return;
        std::vector<std::string> gmembers;
        for(int i=0;i<ml->count();++i) {
            if(ml->item(i)->checkState()==Qt::Checked) {
                const std::string peerId =
                    ml->item(i)->data(Qt::UserRole).toString().toStdString();
                if (!peerId.empty()) gmembers.push_back(peerId);
            }
        }
        if(gmembers.empty()){ QMessageBox::warning(m_ui->centralwidget,"No Members",
                                 "Select at least one member."); return; }

        // Mint a fresh group conversation.  saveConversation persists
        // the row; setConversationMembers attaches the roster.
        AppDataStore::Conversation ng;
        ng.id             = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString();
        ng.kind           = AppDataStore::ConversationKind::Group;
        ng.groupName      = gname.toStdString();
        ng.lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
        ng.inChatList     = true;
        if(m_store) {
            m_store->saveConversation(ng);
            m_store->setConversationMembers(ng.id, gmembers);
        }
        m_chats.push_back(ng);
        m_membersByConv[ng.id] = gmembers;
        // Tell ChatController so GroupProtocol's roster auth and group_*
        // FK constraints both have the parent + members in place before
        // the first send.
        if (m_controller)
            m_controller->setKnownGroupMembers(ng.id, gmembers);
        rebuildChatList();
        m_ui->chatList->setCurrentRow(static_cast<int>(m_chats.size())-1);
        return;
    }

    const QString name = nameEdit->text().trimmed(); if(name.isEmpty()) return;
    const QString singleKey = keyInput->text().trimmed();
    if (singleKey.isEmpty()) return;
    if (!isValidPublicKey(singleKey)) {
        QMessageBox::warning(m_ui->centralwidget, "Invalid Key",
                             "Public key must be exactly 43 base64url characters.");
        return;
    }
    const std::string singleKeyStd = singleKey.toStdString();
    // Prevent duplicate contacts (address-book scoped — a duplicate
    // peer id collides on the contacts table's PK anyway).
    if (m_contactsByPeer.count(singleKeyStd)) {
        QMessageBox::warning(m_ui->centralwidget, "Duplicate Key",
            QString("Key already belongs to contact \"%1\".")
                .arg(qtbridge::qstr(m_contactsByPeer[singleKeyStd].name)));
        return;
    }

    // Persist contact + ensure a 1:1 conversation exists for them.
    AppDataStore::Contact nc;
    nc.name = name.toStdString();
    nc.subtitle = "Secure chat";
    nc.peerIdB64u = singleKeyStd;
    if (m_store) m_store->saveContact(nc);
    m_contactsByPeer[singleKeyStd] = nc;

    if (m_store) {
        const std::string convId = m_store->findOrCreateDirectConversation(singleKeyStd);
        if (!convId.empty()) {
            // Hydrate the in-memory state if this conversation isn't
            // already there (it might be — peer may have messaged us
            // first).  findChatForPeer is the source of truth.
            int existing = findChatForPeer(singleKey);
            if (existing < 0) {
                AppDataStore::Conversation conv;
                if (m_store->loadConversation(convId, conv)) {
                    m_chats.push_back(conv);
                    m_membersByConv[conv.id] = { singleKeyStd };
                    ensureUnreadSize();
                }
            }
        }
    }

    // Send our avatar to the new contact
    const std::string myName   = m_store ? m_store->loadSetting("displayName") : std::string();
    const std::string myAvatar = m_store ? m_store->loadSetting("avatarData")  : std::string();
    if (!myName.empty())
        m_controller->sendAvatar(singleKeyStd, myName, myAvatar);

    rebuildChatList();
    if (!m_chats.empty())
        m_ui->chatList->setCurrentRow(static_cast<int>(m_chats.size())-1);
}

void ChatView::onOpenContactsPicker()
{
    if (!m_store) return;

    // Load the full contact roster from the DB — the in-memory
    // m_chats is message-filtered so it won't include fresh contacts
    // the user hasn't started chatting with yet.
    std::vector<AppDataStore::Contact> all;
    m_store->loadAllContacts([&](const AppDataStore::Contact &c) {
        all.push_back(c);
    });

    const QString myId = QString::fromStdString(m_controller
                                                    ? m_controller->myIdB64u()
                                                    : std::string());
    const QString picked = dialogs::openContactsPicker(m_ui->centralwidget,
                                                        all, myId);
    if (picked.isEmpty()) return;

    // Mirror iOS's ContactsListView → ContactDetailView flow: selecting
    // a contact opens their address-book entry (nickname, safety
    // number, block / verify actions), NOT a chat.  Going through the
    // dedicated contact editor — same one used by group-member tap
    // and the conversation editor's "View Contact" drill-in — keeps
    // the address-book and chat-list concepts cleanly separated.
    openContactDialogForPeer(picked);
}

void ChatView::onDeleteSingleMessage(const QString &convId, const QString &msgId)
{
    const std::string convIdStd = convId.toStdString();
    const std::string msgIdStd  = msgId.toStdString();
    if (m_store) m_store->deleteMessage(convIdStd, msgIdStd);

    // Drop from the in-memory cache then re-render the current chat.
    auto &msgs = m_messagesByConv[convIdStd];
    msgs.erase(std::remove_if(msgs.begin(), msgs.end(),
        [&](const AppDataStore::Message &m) { return m.msgId == msgIdStd; }),
        msgs.end());
    if (m_currentChat >= 0) loadChat(m_currentChat);
}

void ChatView::onChatListContextMenu(const QPoint &pos)
{
    QListWidgetItem *item = m_ui->chatList->itemAt(pos);
    if (!item) return;
    const int index = m_ui->chatList->row(item);
    if (index < 0 || index >= static_cast<int>(m_chats.size())) return;

    QMenu menu(m_ui->chatList);
    QAction *del = menu.addAction("Delete Conversation");
    QAction *chosen = menu.exec(m_ui->chatList->viewport()->mapToGlobal(pos));
    if (chosen == del) onDeleteConversation(index);
}

void ChatView::onDeleteConversation(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chats.size())) return;

    const QString label = displayNameFor(m_chats[index]);
    const QString prompt = label.isEmpty()
        ? QString("Delete this conversation?\n\nMessages and file records "
                  "are wiped; the contact stays in your address book.")
        : QString("Delete the conversation with \"%1\"?\n\nMessages and file "
                  "records are wiped; the contact stays in your address "
                  "book.").arg(label);

    if (QMessageBox::question(m_ui->centralwidget, "Delete Conversation",
                              prompt, QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No) != QMessageBox::Yes) return;

    // Snapshot the conversation id (and kind) before we mutate m_chats.
    const std::string convId = m_chats[index].id;
    const bool wasGroup = (m_chats[index].kind == AppDataStore::ConversationKind::Group);

    if (m_store) {
        // For 1:1s we keep the conversation row + just wipe messages
        // and files — the address-book contact persists, and a fresh
        // inbound from this peer should resume into the same row.
        // For groups we hide via in_chat_list=false so the row drops
        // off the visible list but the membership / group_* state
        // sticks around in case we re-join.  Hard-deleting (and
        // CASCADE-wiping group_send_state etc.) would lock us out of
        // future replays.
        m_store->deleteMessages(convId);
        m_store->deleteFileRecordsForChat(convId);
        if (wasGroup) {
            m_store->setConversationInChatList(convId, false);
        }
    }

    m_messagesByConv.erase(convId);
    m_filesByConv.erase(convId);
    m_chats.erase(m_chats.begin() + index);
    m_unread.remove(index);

    if (m_currentChat == index) {
        m_currentChat = -1;
        clearMessages();
    } else if (m_currentChat > index) {
        m_currentChat -= 1;
    }

    rebuildChatList();
    if (!m_chats.empty() && m_currentChat < 0)
        m_ui->chatList->setCurrentRow(0);
    emit unreadChanged(totalUnread());
}

// ── Private helpers ───────────────────────────────────────────────────────────

int ChatView::findChatForPeer(const QString &peerIdB64u) const
{
    const std::string peerStd = peerIdB64u.trimmed().toStdString();
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].kind != AppDataStore::ConversationKind::Direct) continue;
        if (m_chats[i].directPeerId == peerStd) return i;
    }
    return -1;
}

int ChatView::findOrCreateDirectChatForPeer(const QString &peerIdB64u)
{
    const int existing = findChatForPeer(peerIdB64u);
    if (existing >= 0) return existing;
    if (!m_store) return -1;

    const std::string peerStd = peerIdB64u.trimmed().toStdString();
    // findOrCreateDirectConversation is idempotent + adds the peer as
    // the sole member in one TX, so we don't need a follow-up
    // setConversationMembers call.
    const std::string convId = m_store->findOrCreateDirectConversation(peerStd);
    if (convId.empty()) return -1;

    AppDataStore::Conversation conv;
    if (!m_store->loadConversation(convId, conv)) return -1;

    m_chats.insert(m_chats.begin(), conv);
    m_membersByConv[conv.id] = { peerStd };
    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;
    rebuildChatList();
    return 0;
}

void ChatView::initChats()
{
    if (m_store) {
        const QString savedName = qtbridge::qstr(m_store->loadSetting("displayName"));
        if (!savedName.isEmpty()) {
            m_ui->profileNameLabel->setText(savedName);
            m_ui->profileAvatarLabel->setText(QString(savedName[0]).toUpper());
        }

        const QString avatarB64 = qtbridge::qstr(m_store->loadSetting("avatarData"));
        if (!avatarB64.isEmpty()) {
            QPixmap px;
            px.loadFromData(QByteArray::fromBase64(avatarB64.toUtf8()));
            if (!px.isNull()) {
                m_ui->profileAvatarLabel->setPixmap(makeCircularPixmap(px, 40));
                m_ui->profileAvatarLabel->setText("");
            }
        }
    }

    m_chats.clear();
    m_messagesByConv.clear();
    m_filesByConv.clear();
    m_membersByConv.clear();
    m_contactsByPeer.clear();

    if (m_store) {
        // 0. Block state — independent of contacts (Phase 3h).  Hydrate
        //    upfront so isBlockedFor / inbound dispatch can consult it
        //    before any contact lookup runs.
        m_blockedKeys.clear();
        m_store->loadAllBlockedKeys(
            [this](const std::string &p, int64_t /*blockedAt*/) {
                m_blockedKeys.insert(p);
            });

        // 1. Address book — keyed by peer id; separate from chat list now.
        m_store->loadAllContacts([this](const AppDataStore::Contact &c) {
            m_contactsByPeer[c.peerIdB64u] = c;
        });

        // 2. Conversations = chat list.  In-chat-list filter is the
        //    persisted "show me here" bit; rows hidden via "Leave Group"
        //    or future archive UX skip the visible chat list.
        m_store->loadAllConversations(
            [this](const AppDataStore::Conversation &c) {
                if (!c.inChatList) return;
                m_chats.push_back(c);
            });

        // 3. Per-conversation: members, messages, files.  Streaming
        //    independently keeps memory flat for large rosters.
        for (const auto &c : m_chats) {
            std::vector<std::string> mem;
            m_store->loadConversationMembers(c.id,
                [&mem](const std::string &p) { mem.push_back(p); });
            if (!mem.empty()) m_membersByConv[c.id] = std::move(mem);

            auto &msgs = m_messagesByConv[c.id];
            m_store->loadMessages(c.id,
                [&msgs](const AppDataStore::Message &m) { msgs.push_back(m); });

            std::vector<AppDataStore::FileRecord> records;
            m_store->loadFileRecords(c.id,
                [&records](const AppDataStore::FileRecord &r) { records.push_back(r); });
            if (!records.empty())
                m_filesByConv[c.id] = std::move(records);
        }
    }

    m_ui->chatList->clear();
    for (const auto &c : m_chats) m_ui->chatList->addItem(displayNameFor(c));

    // Show first 8 chars of public key as handle
    const QString fullKey = QString::fromStdString(m_controller->myIdB64u());
    if (!fullKey.isEmpty()) {
        m_ui->profileHandleLabel->setText(fullKey.left(8) + "…");
        m_ui->profileHandleLabel->setToolTip(fullKey);
    }
}

void ChatView::rebuildChatList()
{
    // Re-subscribe presence when contact list changes
    subscribeAllPresence();

    // Prune m_memberOnline: drop keys that no longer belong to any
    // active conversation.  Walk both 1:1 directPeerIds and group
    // member rosters so a peer that's still reachable through any
    // surface stays subscribed.
    {
        QSet<QString> activeKeys;
        for (const auto &c : m_chats) {
            if (c.kind == AppDataStore::ConversationKind::Direct) {
                const QString t = qtbridge::qstr(c.directPeerId).trimmed();
                if (!t.isEmpty()) activeKeys.insert(t);
            } else {
                const auto it = m_membersByConv.find(c.id);
                if (it == m_membersByConv.end()) continue;
                for (const std::string &k : it->second) {
                    const QString t = qtbridge::qstr(k).trimmed();
                    if (!t.isEmpty()) activeKeys.insert(t);
                }
            }
        }
        for (auto it = m_memberOnline.begin(); it != m_memberOnline.end(); ) {
            if (!activeKeys.contains(it.key()))
                it = m_memberOnline.erase(it);
            else
                ++it;
        }
    }

    disconnect(m_ui->chatList, &QListWidget::currentRowChanged,
               this, &ChatView::onChatSelected);
    m_ui->chatList->clear();

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        const AppDataStore::Conversation &conv = m_chats[i];
        const bool isGroup = (conv.kind == AppDataStore::ConversationKind::Group);

        auto *item = new QListWidgetItem(m_ui->chatList);
        item->setSizeHint(QSize(0, 64));
        auto *row = new QWidget;
        row->setStyleSheet("background:transparent;");
        auto *hl = new QHBoxLayout(row);
        hl->setContentsMargins(14,0,14,0); hl->setSpacing(6);

        // displayNameFor handles the contact-removed / stranger case
        // by falling back to a key-prefix label.  Group rows always
        // carry a groupName at this point (saved at creation).
        QString label = displayNameFor(conv);
        auto *nameLbl = new QLabel(label, row);
        nameLbl->setStyleSheet("color:#d0d0d0;font-size:14px;background:transparent;");
        hl->addWidget(nameLbl, 1);

        // Safety-number verification indicator (1:1 contacts only —
        // groups inherit verification per-member and are shown inside
        // the group editor's member list).  Green check = Verified;
        // orange "!" = Mismatch (peer's safety number changed); no
        // indicator for Unverified (the default first-contact state).
        if (!isGroup && m_controller && !conv.directPeerId.empty()) {
            const auto trust = m_controller->peerTrust(conv.directPeerId);
            if (trust != ChatController::PeerTrust::Unverified) {
                auto *badge = new QLabel(row);
                badge->setFixedSize(16, 16);
                badge->setAlignment(Qt::AlignCenter);
                if (trust == ChatController::PeerTrust::Verified) {
                    badge->setText("✓");
                    badge->setStyleSheet(
                        "QLabel{color:#5dd868;font-size:13px;"
                        "font-weight:bold;background:transparent;}");
                    badge->setToolTip("Verified safety number");
                } else {
                    badge->setText("!");
                    badge->setStyleSheet(
                        "QLabel{color:#e6a33a;font-size:13px;"
                        "font-weight:bold;background:#3a2b12;"
                        "border-radius:8px;}");
                    badge->setToolTip("Safety number changed — re-verify");
                }
                hl->addWidget(badge);
            }
        }

        ensureUnreadSize();
        if (m_unread[i] > 0) {
            auto *dot = new QLabel(row); dot->setFixedSize(8,8);
            dot->setStyleSheet("QLabel{background-color:#5dd868;border-radius:4px;}");
            hl->addWidget(dot);
        }

        // Avatar label — shows received photo, group initials, or neutral placeholder
        auto *avatarLbl = new QLabel(row);
        avatarLbl->setFixedSize(34, 34);
        avatarLbl->setAlignment(Qt::AlignCenter);
        const QString avB64 = avatarB64For(conv);
        if (!avB64.isEmpty()) {
            QPixmap px;
            px.loadFromData(QByteArray::fromBase64(avB64.toUtf8()));
            if (!px.isNull())
                avatarLbl->setPixmap(makeCircularPixmap(px, 34));
        } else {
            static const QList<QColor> kPalette = {
                QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
                QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a), QColor(0x1a, 0x4a, 0x6a),
            };
            const QString ch = label.isEmpty() ? (isGroup ? "#" : "?") : QString(label[0]);
            const uint hash = qHash(label);
            const QColor bg = isGroup
                ? QColor(0x2e, 0x8b, 0x3a)
                : kPalette[hash % static_cast<uint>(kPalette.size())];
            avatarLbl->setPixmap(renderInitialsAvatar(ch, bg, 34));
        }
        hl->addWidget(avatarLbl);

        auto *editBtn = new QToolButton(row);
        editBtn->setText("✎"); editBtn->setFixedSize(28,28);
        themeStyles::applyRole(editBtn, "toolIconBtn",
            themeStyles::toolIconBtnCss(ThemeManager::instance().current()));
        hl->addWidget(editBtn);
        m_ui->chatList->setItemWidget(item, row);
        connect(editBtn, &QToolButton::clicked, this, [this,i](){ onEditContact(i); });
    }

    connect(m_ui->chatList, &QListWidget::currentRowChanged,
            this, &ChatView::onChatSelected);
    if (m_currentChat >= 0 && m_currentChat < m_ui->chatList->count())
        m_ui->chatList->setCurrentRow(m_currentChat);

    if (!m_emptyLabel) {
        m_emptyLabel = new QLabel(m_ui->contentWidget);
        m_emptyLabel->setText("💬\n\nNo contacts yet\nClick + to add a contact\nand start chatting");
        m_emptyLabel->setAlignment(Qt::AlignCenter);
        m_emptyLabel->setStyleSheet(
            "color:#555555;font-size:14px;background-color:#0a0a0a;padding:40px;");
        m_emptyLabel->setWordWrap(true);
        m_emptyLabel->setAttribute(Qt::WA_TransparentForMouseEvents, false);
    }
    m_emptyLabel->resize(m_ui->contentWidget->size());
    m_emptyLabel->move(0,0); m_emptyLabel->raise();
    if (m_chats.empty()) {
        QTimer::singleShot(0, this, [this](){ if(m_emptyLabel){
            m_emptyLabel->resize(m_ui->contentWidget->size());
            m_emptyLabel->raise(); m_emptyLabel->show(); } });
    } else {
        if (m_emptyLabel) m_emptyLabel->hide();
    }
}

void ChatView::loadChat(int index)
{
    const AppDataStore::Conversation &chat = m_chats[index];
    const bool isGroup = (chat.kind == AppDataStore::ConversationKind::Group);
    const QString chatName = displayNameFor(chat);
    m_ui->chatTitleLabel->setText(chatName);

    // Show online / last-seen for DM chats, group subtitle for groups
    if (!isGroup) {
        const bool isOnline = m_memberOnline.value(qtbridge::qstr(chat.directPeerId), false);
        const QString statusText = isOnline
                                       ? "Online"
                                       : formatLastSeen(qtbridge::qdate(chat.lastActiveSecs));
        m_ui->chatSubLabel->setText("● " + statusText);
        m_ui->chatSubLabel->setStyleSheet(
            isOnline
                ? "color: #3a9e48; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
                : "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
    } else {
        // Show per-member presence summary for groups, but only after
        // at least one member's presence has been resolved — avoids a
        // misleading "0 of N online" flash before the first poll returns.
        const QString myKey = QString::fromStdString(m_controller->myIdB64u());
        int onlineCount = 0, totalMembers = 0;
        bool anyResolved = false;
        const auto memIt = m_membersByConv.find(chat.id);
        if (memIt != m_membersByConv.end()) {
            for (const std::string &k : memIt->second) {
                const QString trimmed = qtbridge::qstr(k).trimmed();
                if (trimmed.isEmpty() || trimmed == myKey) continue;
                ++totalMembers;
                if (m_memberOnline.contains(trimmed)) {
                    anyResolved = true;
                    if (m_memberOnline.value(trimmed))
                        ++onlineCount;
                }
            }
        }
        if (!anyResolved || totalMembers == 0) {
            // No presence data yet — show a neutral subtitle.  v3
            // dropped the per-row stored subtitle; "Group chat" is the
            // sensible static fallback.
            m_ui->chatSubLabel->setText(QStringLiteral("Group chat"));
            m_ui->chatSubLabel->setStyleSheet(
                "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
        } else {
            m_ui->chatSubLabel->setText(
                QString("%1 of %2 members online").arg(onlineCount).arg(totalMembers));
            m_ui->chatSubLabel->setStyleSheet(
                onlineCount > 0
                    ? "color: #3a9e48; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
                    : "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
        }
    }

    const QString avB64 = avatarB64For(chat);
    if (!avB64.isEmpty()) {
        QPixmap px;
        px.loadFromData(QByteArray::fromBase64(avB64.toUtf8()));
        if (!px.isNull()) {
            m_ui->chatAvatarLabel->setPixmap(makeCircularPixmap(px, 44));
            m_ui->chatAvatarLabel->setText("");
        }
    } else if (isGroup) {
        const QString ch = chatName.isEmpty() ? "#" : QString(chatName[0]);
        m_ui->chatAvatarLabel->setPixmap(renderInitialsAvatar(ch, QColor(0x2e, 0x8b, 0x3a), 44));
        m_ui->chatAvatarLabel->setText("");
    } else {
        const QString ch = chatName.isEmpty() ? "?" : QString(chatName[0]);
        const QColor bg = avatarColorForName(chatName);
        m_ui->chatAvatarLabel->setPixmap(renderInitialsAvatar(ch, bg, 44));
        m_ui->chatAvatarLabel->setText("");
    }
    clearMessages();

    QDateTime lastShown;
    const auto &msgs = m_messagesByConv[chat.id];
    for (const auto &msg : msgs) {
        const QDateTime msgTs = qtbridge::qdate(msg.timestampSecs);
        if (!lastShown.isValid() || lastShown.secsTo(msgTs) >= kDateSepSecs) {
            addDateSeparator(msgTs);
            lastShown = msgTs;
        }

        QString senderName;
        if (isGroup && !msg.sent && !msg.senderName.empty()) {
            senderName = qtbridge::qstr(msg.senderName);
        }
        addMessageBubble(qtbridge::qstr(msg.text), msg.sent, senderName,
                          qtbridge::qstr(msg.msgId), qtbridge::qstr(chat.id));
    }
    rebuildFilesTab();
}

void ChatView::promoteChatToTop(int index)
{
    // promoteChatToTop does NOT remap m_filesByConv / m_messagesByConv:
    // both are keyed by the stable conversation UUID, not by list
    // index.  Only m_unread needs adjustment.
    if (index <= 0 || index >= static_cast<int>(m_chats.size())) return;

    AppDataStore::Conversation promoted = std::move(m_chats[index]);
    m_chats.erase(m_chats.begin() + index);
    m_chats.insert(m_chats.begin(), std::move(promoted));

    ensureUnreadSize();
    int u = m_unread[index];
    m_unread.remove(index);
    m_unread.prepend(u);

    if (m_currentChat == index)              m_currentChat = 0;
    else if (m_currentChat >= 0 && m_currentChat < index) m_currentChat += 1;
}

void ChatView::clearMessages()
{
    QLayout *l = m_ui->scrollAreaWidgetContents->layout();
    if (!l) return;
    while (l->count() > 1) {
        QLayoutItem *it = l->takeAt(0);
        if (it->widget()) delete it->widget();
        delete it;
    }
}

void ChatView::addDateSeparator(const QDateTime &dt)
{
    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;
    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(28);
    auto *hl = new QHBoxLayout(row); hl->setContentsMargins(0,4,0,4); hl->setSpacing(0);
    auto *lbl = new QLabel(formatSepLabel(dt), row);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet("color:#666666;font-size:11px;background:transparent;");
    hl->addStretch(); hl->addWidget(lbl); hl->addStretch();
    layout->insertWidget(layout->count()-1, row);
}

void ChatView::addMessageBubble(const QString &text, bool sent,
                                const QString &senderName,
                                const QString &msgId,
                                const QString &chatKey)
{
    QFont f = QApplication::font(); f.setPixelSize(13);
    QFontMetrics fm(f);
    int vpW   = m_ui->messageScroll->viewport()->width();
    int maxW  = qMax(int(vpW * 0.65), 120);
    int hPad  = 28, vPad = 28, avail = maxW - hPad;
    QString disp  = processText(text, fm, avail);
    int     slw   = fm.horizontalAdvance(disp);
    bool    wrap  = (slw > avail) || disp.contains('\n');
    int     bw    = wrap ? maxW : qMin(slw + hPad + 4, maxW);
    int     bh;
    if (wrap) {
        int lines = 0;
        for (const QString &p : disp.split('\n')) {
            if (p.isEmpty()) { lines++; continue; }
            int lw = 0, pl = 1;
            for (const QString &w : p.split(' ')) {
                int ww = fm.horizontalAdvance(w + " ");
                if (lw+ww > avail && lw > 0) { pl++; lw = ww; } else lw += ww;
            }
            lines += pl;
        }
        bh = fm.height()*lines + vPad + (lines-1)*fm.leading() + 1;
    } else {
        bh = fm.height() + vPad + 1;
    }

    // ── Outer widget holds optional name label + bubble row ───────────────────
    const bool showName = !sent && !senderName.isEmpty();
    const int nameHeight = showName ? 16 : 0;

    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(bh + nameHeight + 4);

    auto *outerLayout = new QVBoxLayout(row);
    outerLayout->setContentsMargins(0, 2, 0, 2);
    outerLayout->setSpacing(2);

    // ── Sender name — group received messages only ────────────────────────────
    if (showName) {
        auto *nameRow = new QHBoxLayout;
        nameRow->setContentsMargins(0, 0, 0, 0);
        auto *nameLbl = new QLabel(senderName, row);
        nameLbl->setProperty("p2pRole", "senderName");
        nameLbl->setStyleSheet(
            "color: #5dd868; font-size: 11px; background: transparent; padding-left: 4px;"
            );
        nameRow->addWidget(nameLbl);
        nameRow->addStretch();
        outerLayout->addLayout(nameRow);
    }

    // ── Bubble row ────────────────────────────────────────────────────────────
    auto *rl = new QHBoxLayout;
    rl->setContentsMargins(0, 0, 0, 0);
    rl->setSpacing(0);

    auto *bubble = new QLabel(disp, row);
    bubble->setFont(f); bubble->setFixedSize(bw, bh);
    bubble->setWordWrap(wrap);
    bubble->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    bubble->setTextInteractionFlags(Qt::TextSelectableByMouse);

    // Tag BEFORE setting the stylesheet so the theme classifier can
    // find this bubble again on every flip — classifier prefers the
    // p2pRole property over stylesheet-content matching, which only
    // works the first pass (once we rewrite the sheet, the original
    // #222222 / #2e8b3a literal is gone and substring match fails).
    bubble->setProperty("p2pRole", sent ? "bubbleSelf" : "bubbleOther");
    if (sent) {
        bubble->setStyleSheet("background-color:#2e8b3a;color:#ffffff;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addStretch(); rl->addWidget(bubble);
    } else {
        bubble->setStyleSheet("background-color:#222222;color:#eeeeee;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addWidget(bubble); rl->addStretch();
    }
    // Re-classify just the new row so a bubble added in light mode
    // doesn't briefly flash dark before the next themeChanged.
    themeStyles::reapplyForChildren(row, ThemeManager::instance().current());
    outerLayout->addLayout(rl);

    // Right-click → Copy / Delete.  Only wired for real messages
    // (system-rendered bubbles pass empty msgId and stay static).
    if (!msgId.isEmpty() && !chatKey.isEmpty()) {
        bubble->setContextMenuPolicy(Qt::CustomContextMenu);
        const QString capturedText    = text;
        const QString capturedMsgId   = msgId;
        const QString capturedChatKey = chatKey;
        connect(bubble, &QWidget::customContextMenuRequested, this,
                [this, bubble, capturedText, capturedMsgId, capturedChatKey](const QPoint &pos) {
            QMenu menu(bubble);
            QAction *copyAct = menu.addAction("Copy");
            QAction *delAct  = menu.addAction("Delete Message");
            QAction *chosen  = menu.exec(bubble->mapToGlobal(pos));
            if (chosen == copyAct) {
                QApplication::clipboard()->setText(capturedText);
            } else if (chosen == delAct) {
                // Defer one event-loop turn so the bubble's signal
                // dispatch unwinds before clearMessages() deletes it.
                // Calling loadChat() synchronously here destroys the
                // QLabel whose customContextMenuRequested slot we're
                // still inside, which crashes on return.
                QTimer::singleShot(0, this, [this, capturedChatKey, capturedMsgId]() {
                    onDeleteSingleMessage(capturedChatKey, capturedMsgId);
                });
            }
        });
    }

    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;
    layout->insertWidget(layout->count()-1, row);
    QTimer::singleShot(5, this, [this](){
        m_ui->messageScroll->verticalScrollBar()->setValue(
            m_ui->messageScroll->verticalScrollBar()->maximum());
    });
}

// ── Clickable file bubble ─────────────────────────────────────────────────────

void ChatView::addFileBubble(const QString &fileName, qint64 fileSize, bool sent)
{
    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;

    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    auto *rl = new QHBoxLayout(row);
    rl->setContentsMargins(0, 2, 0, 2);
    rl->setSpacing(0);

    const QString label = QString("📎  %1  ·  %2\nTap to view files")
                              .arg(fileName, formatFileSize(fileSize));

    auto *btn = new QPushButton(label, row);
    btn->setFont([]{ QFont f = QApplication::font(); f.setPixelSize(13); return f; }());
    btn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    btn->setMinimumHeight(52);
    btn->setMaximumWidth(int(m_ui->messageScroll->viewport()->width() * 0.65));
    btn->setCursor(Qt::PointingHandCursor);
    btn->setFlat(true);

    const QString bgColor = sent ? "#2e8b3a" : "#222222";
    btn->setStyleSheet(
        QString("QPushButton { background-color:%1; color:#ffffff;"
                " border-radius:14px; padding:10px 14px; font-size:13px;"
                " text-align:left; }"
                "QPushButton:hover { background-color:%2; }"
                "QPushButton:pressed { background-color:%3; }")
            .arg(bgColor,
                 sent ? "#36a344" : "#2a2a2a",
                 sent ? "#256e30" : "#1a1a1a"));

    QObject::connect(btn, &QPushButton::clicked, this, [this]{
        m_ui->mainTabs->setCurrentIndex(1);
    });

    if (sent) {
        rl->addStretch();
        rl->addWidget(btn);
    } else {
        rl->addWidget(btn);
        rl->addStretch();
    }

    layout->insertWidget(layout->count() - 1, row);
    QTimer::singleShot(5, this, [this]{
        m_ui->messageScroll->verticalScrollBar()->setValue(
            m_ui->messageScroll->verticalScrollBar()->maximum());
    });
}

// ── Files tab ─────────────────────────────────────────────────────────────────
//
// Layout strategy: we fully replace the contents of filesScrollContents' layout
// each rebuild so we can switch between an empty placeholder, an in-progress
// placeholder, and a 3-column QGridLayout of cards without fighting the static
// QHBoxLayout / spacer that the .ui file placed there at design time.

void ChatView::rebuildFilesTab()
{
    QLayout *outerRaw = m_ui->filesScrollContents->layout();
    if (!outerRaw) return;

    // ── Clear everything currently in the scroll area ─────────────────────────
    // We need to remove widgets AND sub-layouts recursively.
    auto clearLayout = [](QLayout *l) {
        while (l->count() > 0) {
            QLayoutItem *it = l->takeAt(0);
            if (it->widget()) {
                it->widget()->hide();
                delete it->widget();
            } else if (it->layout()) {
                // Clear the sub-layout's own children first
                QLayout *sub = it->layout();
                while (sub->count() > 0) {
                    QLayoutItem *s = sub->takeAt(0);
                    if (s->widget()) { s->widget()->hide(); delete s->widget(); }
                    delete s;
                }
            }
            delete it;
        }
    };
    clearLayout(outerRaw);

    auto *outer = qobject_cast<QVBoxLayout*>(outerRaw);
    if (!outer) return;

    if (m_currentChat < 0) return;

    const std::string convId = m_chats[m_currentChat].id;
    static const std::vector<AppDataStore::FileRecord> kEmpty;
    auto recIt = m_filesByConv.find(convId);
    const auto &records = (recIt == m_filesByConv.end()) ? kEmpty : recIt->second;

    // ── Filter records by search query if active ───────────────────────────
    std::vector<AppDataStore::FileRecord> filtered;
    if (!m_searchQuery.isEmpty()) {
        for (const auto &r : records)
            if (qtbridge::qstr(r.fileName).toLower().contains(m_searchQuery) ||
                qtbridge::qstr(r.peerName).toLower().contains(m_searchQuery))
                filtered.push_back(r);
    } else {
        filtered = records;
    }

    if (filtered.empty()) {
        // ── Empty state ───────────────────────────────────────────────────────
        auto *ph = new QLabel(m_ui->filesScrollContents);
        if (!m_searchQuery.isEmpty())
            ph->setText("🔍\n\nNo files matching \"" + m_searchQuery + "\"");
        else
            ph->setText("📎\n\nNo files shared yet\n\nClick the  ⬆  button below to send a file");
        ph->setAlignment(Qt::AlignCenter);
        ph->setWordWrap(true);
        ph->setStyleSheet(
            "color:#444444;font-size:13px;background:transparent;border:none;");
        outer->addStretch();
        outer->addWidget(ph);
        outer->addStretch();
        return;
    }

    // ── Grid of cards (3 per row) ─────────────────────────────────────────────
    auto *gridWidget = new QWidget(m_ui->filesScrollContents);
    gridWidget->setStyleSheet("background:transparent;");
    auto *grid = new QGridLayout(gridWidget);
    grid->setSpacing(16);
    grid->setContentsMargins(0, 0, 0, 0);

    static constexpr int kCols = 3;
    for (int i = 0; i < static_cast<int>(filtered.size()); ++i) {
        auto *card = new dialogs::FileCard(filtered[i], gridWidget);
        connect(card, &dialogs::FileCard::deleteRequested,
                this, [this](const QString &transferId) {
                    if (m_store) m_store->deleteFileRecord(transferId.toStdString());
                    if (m_currentChat >= 0 && m_currentChat < static_cast<int>(m_chats.size())) {
                        const std::string ck = m_chats[m_currentChat].id;
                        const std::string idStd = transferId.toStdString();
                        auto &files = m_filesByConv[ck];
                        files.erase(std::remove_if(files.begin(), files.end(),
                            [&](const AppDataStore::FileRecord &r){ return r.transferId == idStd; }),
                            files.end());
                    }
                    rebuildFilesTab();
                });
        connect(card, &dialogs::FileCard::cancelRequested,
                this, [this](const QString &transferId) {
                    m_controller->cancelFileTransfer(transferId.toStdString());
                });
        grid->addWidget(card, i / kCols, i % kCols);
    }

    // Equal-width columns so cards fill the available space
    for (int c = 0; c < kCols; ++c)
        grid->setColumnStretch(c, 1);

    outer->addWidget(gridWidget);
    outer->addStretch();
}

void ChatView::ensureUnreadSize()
{
    if (m_unread.size() < m_chats.size())
        m_unread.resize(m_chats.size());
}

int ChatView::totalUnread() const
{
    int s = 0; for (int n : m_unread) s += n; return s;
}

void ChatView::showToast(const QString &message)
{
    if (!m_toastLabel) {
        m_toastLabel = new QLabel(m_ui->centralwidget);
        m_toastLabel->setAlignment(Qt::AlignCenter);
        m_toastLabel->setStyleSheet(
            "background-color:#1a2e1c;"
            "color:#5dd868;"
            "font-size:12px;"
            "padding:8px 16px;"
            "border-radius:8px;"
            "border:1px solid #2e5e30;");
        m_toastLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
    }
    m_toastLabel->setText(message);
    m_toastLabel->adjustSize();
    // Position at bottom-center of centralwidget
    const QSize ws = m_ui->centralwidget->size();
    m_toastLabel->move((ws.width() - m_toastLabel->width()) / 2,
                        ws.height() - m_toastLabel->height() - 24);
    m_toastLabel->raise();
    m_toastLabel->show();
    QTimer::singleShot(3000, m_toastLabel, &QLabel::hide);
}

// ── File transfer consent + cancel ───────────────────────────────────────────

void ChatView::onFileAcceptRequested(const QString &fromPeerIdB64u,
                                      const QString &transferId,
                                      const QString &fileName,
                                      qint64 fileSize)
{
    // Verified-contacts gate: when SettingsPanel's "Only accept from
    // verified contacts" toggle is on AND the sender's safety number
    // hasn't been confirmed, silently decline.  Same semantic as the
    // iOS-side filter — the core has already accepted the envelope;
    // we just refuse without bothering the user.
    if (m_requireVerifiedFiles && m_controller) {
        const auto trust = m_controller->peerTrust(fromPeerIdB64u.toStdString());
        if (trust != ChatController::PeerTrust::Verified) {
            m_controller->declineFileTransfer(transferId.toStdString());
            return;
        }
    }

    // Figure out which contact this is so we can show a friendly name.
    // Same prefix-fallback rule as the group-message handler: empty name
    // (un-added peer) stays on the key prefix.
    QString senderName = fromPeerIdB64u.left(8) + "...";
    const std::string fromStd = fromPeerIdB64u.toStdString();
    auto contactIt = m_contactsByPeer.find(fromStd);
    if (contactIt != m_contactsByPeer.end() && !contactIt->second.name.empty())
        senderName = qtbridge::qstr(contactIt->second.name);

    QMessageBox box(m_ui->centralwidget);
    box.setWindowTitle("Incoming File");
    box.setText(QString("<b>%1</b> wants to send you a file:<br><br>"
                        "<b>%2</b><br>"
                        "<span style='color:#888'>%3</span>")
                    .arg(senderName, fileName, formatFileSize(fileSize)));
    box.setIcon(QMessageBox::Question);

    QPushButton *acceptBtn  = box.addButton("Accept",  QMessageBox::AcceptRole);
    QPushButton *declineBtn = box.addButton("Decline", QMessageBox::RejectRole);
    box.setDefaultButton(acceptBtn);

    box.exec();
    if (box.clickedButton() == acceptBtn) {
        // Respect the user's global "require P2P" setting — ChatController
        // will OR it with our per-call flag.
        m_controller->acceptFileTransfer(transferId.toStdString(), /*requireP2P=*/false);
    } else {
        m_controller->declineFileTransfer(transferId.toStdString());
    }
    Q_UNUSED(declineBtn);
}

void ChatView::onFileTransferCanceled(const QString &transferId, bool byReceiver)
{
    const std::string transferStd = transferId.toStdString();
    // Walk every conversation's file records and mark the matching transfer as failed.
    for (auto &kv : m_filesByConv) {
        auto &records = kv.second;
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            if (static_cast<FileTransferStatus>(rec.status) == FileTransferStatus::Complete) return; // too late
            rec.status = static_cast<int>(FileTransferStatus::Failed);
            if (m_store) m_store->saveFileRecord(kv.first, rec);
            rebuildFilesTab();
            break;
        }
    }

    const QString msg = byReceiver
        ? "File transfer was declined or canceled by the recipient."
        : "File transfer canceled by sender.";
    showToast(msg);
}

void ChatView::onFileTransferDelivered(const QString &transferId)
{
    const std::string transferStd = transferId.toStdString();
    // Sender-side: flip the record's status to Complete with a confirmation.
    for (auto &kv : m_filesByConv) {
        auto &records = kv.second;
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            if (!rec.sent) return; // only meaningful on sender side
            // Transfer landed + hash verified. Keep status Complete but reflect delivery.
            rec.chunksComplete = rec.chunksTotal;
            rec.status         = static_cast<int>(FileTransferStatus::Complete);
            if (m_store) m_store->saveFileRecord(kv.first, rec);
            rebuildFilesTab();
            showToast(QString("Delivered: %1").arg(qtbridge::qstr(rec.fileName)));
            return;
        }
    }
}

void ChatView::onFileTransferBlocked(const QString &transferId, bool byReceiver)
{
    const std::string transferStd = transferId.toStdString();
    // Mark as failed + toast explanation.
    for (auto &kv : m_filesByConv) {
        auto &records = kv.second;
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            rec.status = static_cast<int>(FileTransferStatus::Failed);
            if (m_store) m_store->saveFileRecord(kv.first, rec);
            rebuildFilesTab();
            break;
        }
    }

    const QString msg = byReceiver
        ? "Recipient requires a direct connection for files. Transfer aborted."
        : "Your privacy settings block relay fallback for files. Transfer aborted.";
    showToast(msg);
}
