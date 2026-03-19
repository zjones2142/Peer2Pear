#include "chatview.h"
#include "ui_mainwindow.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QScrollBar>
#include <QFontMetrics>
#include <QApplication>
#include <QDialog>
#include <QFrame>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QListWidget>
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
#include <QDesktopServices>
#include <QUrl>

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

// ── Shared dialog stylesheet ──────────────────────────────────────────────────
static const char *kDlgStyle =
    "QDialog { background-color: #111111; color: #f0f0f0; }"
    "QLabel { color: #aaaaaa; font-size: 12px; }"
    "QLabel#dlgTitle { color: #ffffff; font-size: 15px; font-weight: bold; }"
    "QLineEdit { background-color: #1a1a1a; color: #f0f0f0; border: 1px solid #2a2a2a;"
    "  border-radius: 8px; padding: 8px 12px; font-size: 13px; }"
    "QLineEdit:focus { border: 1px solid #3a9e48; }"
    "QListWidget { background-color: #1a1a1a; color: #dddddd; border: 1px solid #2a2a2a;"
    "  border-radius: 8px; font-size: 13px; }"
    "QListWidget::item { padding: 6px 10px; border-bottom: 1px solid #222222; }"
    "QListWidget::item:selected { background-color: #162818; color: #ffffff; }"
    "QPushButton { background-color: #1a2e1c; color: #5dd868; border: 1px solid #2e5e30;"
    "  border-radius: 8px; font-size: 13px; padding: 8px 16px; }"
    "QPushButton:hover { background-color: #223a24; border-color: #3a9e48; }"
    "QPushButton#saveBtn   { background-color: #2e8b3a; color: #ffffff; border: none; }"
    "QPushButton#saveBtn:hover { background-color: #38a844; }"
    "QPushButton#cancelBtn { background-color: #1e1e1e; color: #888888; border: 1px solid #2a2a2a; }"
    "QPushButton#cancelBtn:hover { background-color: #252525; color: #cccccc; }"
    "QPushButton#removeKeyBtn { background-color: #2e1a1a; color: #cc5555; border: 1px solid #5e2e2e; }"
    "QPushButton#removeKeyBtn:hover { background-color: #3a2020; }";

// ── Contact editor dialog ─────────────────────────────────────────────────────
enum class ContactEditorResult { Cancelled, Saved, Blocked, Removed };

static ContactEditorResult openContactEditor(QWidget *parent,
                                             const QString &title,
                                             QString &nameInOut,
                                             QStringList &keysInOut,
                                             bool showDestructive = true,
                                             bool isBlocked = false)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setStyleSheet(kDlgStyle);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    auto *titleLbl = new QLabel(title, &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    root->addWidget(new QLabel("Display Name", &dlg));
    auto *nameEdit = new QLineEdit(nameInOut, &dlg);
    root->addWidget(nameEdit);

    root->addWidget(new QLabel("Public Keys", &dlg));
    auto *keyList = new QListWidget(&dlg);
    keyList->setFixedHeight(130);
    for (const QString &k : keysInOut) keyList->addItem(k);
    root->addWidget(keyList);

    auto *kr    = new QHBoxLayout;
    auto *keyIn = new QLineEdit(&dlg);
    keyIn->setPlaceholderText("Paste public key…");
    auto *addK  = new QPushButton("Add Key", &dlg);
    auto *remK  = new QPushButton("Remove", &dlg);
    remK->setObjectName("removeKeyBtn");
    kr->addWidget(keyIn, 1); kr->addWidget(addK); kr->addWidget(remK);
    root->addLayout(kr);

    QObject::connect(addK, &QPushButton::clicked, [&]() {
        QString k = keyIn->text().trimmed();
        if (k.isEmpty()) return;
        for (int i = 0; i < keyList->count(); ++i)
            if (keyList->item(i)->text() == k) {
                QMessageBox::warning(&dlg, "Duplicate Key", "Key already present.");
                return;
            }
        keyList->addItem(k); keyIn->clear();
    });
    QObject::connect(remK, &QPushButton::clicked, [&]() { delete keyList->currentItem(); });

    root->addStretch();
    ContactEditorResult result = ContactEditorResult::Cancelled;

    if (showDestructive) {
        auto *dsep = new QFrame(&dlg);
        dsep->setFrameShape(QFrame::HLine);
        dsep->setStyleSheet("color:#2a2a2a;");
        root->addWidget(dsep);

        auto *ar    = new QHBoxLayout;
        auto *blkBtn = new QPushButton(isBlocked ? "Unblock Contact" : "Block Contact", &dlg);
        auto *rmBtn  = new QPushButton("Remove Contact", &dlg);
        const QString ds =
            "QPushButton{background-color:#2e1a1a;color:#cc5555;border:1px solid #5e2e2e;"
            "border-radius:8px;padding:8px 16px;}QPushButton:hover{background-color:#3a2020;}";
        blkBtn->setStyleSheet(ds); rmBtn->setStyleSheet(ds);
        ar->addWidget(blkBtn); ar->addWidget(rmBtn); ar->addStretch();
        root->addLayout(ar);

        QObject::connect(blkBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, isBlocked?"Unblock":"Block",
                                      isBlocked?"Unblock this contact?":
                                          "Block this contact? They won't be able to send you messages.",
                                      QMessageBox::Yes|QMessageBox::No) == QMessageBox::Yes)
            { result = ContactEditorResult::Blocked; dlg.accept(); }
        });
        QObject::connect(rmBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Remove Contact",
                                      "Remove this contact? This cannot be undone.",
                                      QMessageBox::Yes|QMessageBox::No) == QMessageBox::Yes)
            { result = ContactEditorResult::Removed; dlg.accept(); }
        });
    }

    auto *br  = new QHBoxLayout;
    auto *can = new QPushButton("Cancel", &dlg); can->setObjectName("cancelBtn");
    auto *sav = new QPushButton("Save",   &dlg); sav->setObjectName("saveBtn");
    br->setSpacing(10); br->addStretch(); br->addWidget(can); br->addWidget(sav);
    root->addLayout(br);

    QObject::connect(can, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(sav, &QPushButton::clicked, [&]() {
        result = ContactEditorResult::Saved; dlg.accept();
    });

    dlg.exec();

    if (result == ContactEditorResult::Saved) {
        nameInOut = nameEdit->text().trimmed();
        keysInOut.clear();
        for (int i = 0; i < keyList->count(); ++i)
            keysInOut << keyList->item(i)->text();
    }
    return result;
}

// ── ChatView ──────────────────────────────────────────────────────────────────

// Returns a stable string key for file-record lookup: peerIdB64u for DMs,
// groupId for group chats.  Never changes when the chat is reordered.
QString ChatView::chatKey(const ChatData &c)
{
    if (c.isGroup)             return c.groupId;
    if (!c.peerIdB64u.isEmpty()) return c.peerIdB64u;
    return "name:" + c.name;
}

ChatView::ChatView(Ui::MainWindow *ui, ChatController *controller,
                   DatabaseManager *db, QObject *parent)
    : QObject(parent), m_ui(ui), m_controller(controller), m_db(db)
{
    initChats();
    ensureUnreadSize();

    connect(m_ui->chatList,      &QListWidget::currentRowChanged, this, &ChatView::onChatSelected);
    connect(m_ui->sendBtn,       &QPushButton::clicked,           this, &ChatView::onSendMessage);
    connect(m_ui->messageInput,  &QLineEdit::returnPressed,       this, &ChatView::onSendMessage);
    connect(m_ui->searchEdit_12, &QLineEdit::textChanged,         this, &ChatView::onSearchChanged);
    connect(m_ui->editProfileBtn,&QToolButton::clicked,           this, &ChatView::onEditProfile);
    connect(m_ui->addContactBtn, &QToolButton::clicked,           this, &ChatView::onAddContact);
    connect(m_ui->attachBtn,     &QToolButton::clicked,           this, &ChatView::onAttachFile);

    rebuildChatList();
    m_ui->chatList->setCurrentRow(0);
}

void ChatView::reloadCurrentChat()
{
    if (m_emptyLabel) {
        m_emptyLabel->resize(m_ui->contentWidget->size());
        m_emptyLabel->raise();
        m_emptyLabel->setVisible(m_chats.isEmpty());
    }
}

// ── Incoming messages ─────────────────────────────────────────────────────────

void ChatView::onIncomingMessage(const QString &fromPeerIdB64u,
                                 const QString &text,
                                 const QDateTime &timestamp,
                                 const QString &msgId)
{
    const QString from = fromPeerIdB64u.trimmed();
    ensureUnreadSize();

    auto shouldToast = [&]() { return m_shouldToastFn ? m_shouldToastFn() : true; };

    for (int i = 0; i < m_chats.size(); ++i) {
        if (m_chats[i].isGroup) continue;

        bool hit = (m_chats[i].peerIdB64u.trimmed() == from);
        if (!hit) for (const QString &k : m_chats[i].keys)
                if (k.trimmed() == from) { hit = true; break; }
        if (!hit) continue;

        if (m_chats[i].isBlocked) return;

        // UI-side dedup against already-stored messages
        if (!msgId.isEmpty())
            for (const Message &m : m_chats[i].messages)
                if (m.msgId == msgId) return;

        const bool needsSep = m_chats[i].messages.isEmpty() ||
                              m_chats[i].messages.last().timestamp.secsTo(timestamp) >= kDateSepSecs;

        Message msg{false, text, timestamp, msgId};
        m_chats[i].messages.append(msg);
        if (m_db) { m_db->saveContact(m_chats[i]); m_db->saveMessage(m_chats[i].peerIdB64u, msg); }

        if (i == m_currentChat) {
            if (needsSep) addDateSeparator(timestamp);
            addMessageBubble(text, false);
            promoteChatToTop(i);
            rebuildChatList();
        } else {
            m_unread[i] += 1;
            emit unreadChanged(totalUnread());
            promoteChatToTop(i);
            rebuildChatList();
            if (m_notifier && shouldToast()) m_notifier->notify(m_chats[0].name, text);
        }
        return;
    }

    // Unknown sender — auto-create chat
    Message msg{false, text, timestamp, msgId};
    ChatData nc; nc.name = "Unknown contact"; nc.subtitle = "Secure chat";
    nc.peerIdB64u = from; nc.keys.append(from); nc.messages.append(msg);
    m_chats.prepend(nc);
    if (m_db) { m_db->saveContact(nc); m_db->saveMessage(from, msg); }
    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;
    m_unread[0] += 1;
    emit unreadChanged(totalUnread());
    if (m_notifier && shouldToast()) m_notifier->notify("Unknown contact", text);
    rebuildChatList();
}

void ChatView::onStatus(const QString &s) { qDebug() << "[status]" << s; }

void ChatView::onIncomingGroupMessage(const QString &fromPeerIdB64u,
                                      const QString &groupId,
                                      const QString &groupName,
                                      const QStringList &memberKeys,
                                      const QString &text,
                                      const QDateTime &ts,
                                      const QString &msgId)
{
    int idx = -1;
    for (int i = 0; i < m_chats.size(); ++i)
        if (m_chats[i].isGroup && m_chats[i].groupId == groupId) { idx = i; break; }

    if (idx == -1) {
        ChatData ng; ng.isGroup = true; ng.groupId = groupId;
        ng.peerIdB64u = groupId;
        ng.name = groupName.isEmpty() ? "Group Chat" : groupName;
        ng.subtitle = "Group chat"; ng.keys.append(fromPeerIdB64u);
        m_chats.append(ng);
        if (m_db) m_db->saveContact(ng);
        idx = m_chats.size() - 1;
        ensureUnreadSize();
        rebuildChatList();
    }

    ChatData &chat = m_chats[idx];
    if (chat.isBlocked) return;

    if (!msgId.isEmpty())
        for (const Message &m : chat.messages)
            if (m.msgId == msgId) return;

    bool updated = false;
    for (const QString &k : memberKeys)
        if (!k.trimmed().isEmpty() && !chat.keys.contains(k)) { chat.keys << k; updated = true; }
    if (updated && m_db) m_db->saveContact(chat);

    const bool needsSep = chat.messages.isEmpty() ||
                          chat.messages.last().timestamp.secsTo(ts) >= kDateSepSecs;

    Message msg{false, text, ts, msgId};
    chat.messages.append(msg);
    if (m_db) m_db->saveMessage(chat.groupId.isEmpty() ? "name:"+chat.name : chat.groupId, msg);

    if (idx == m_currentChat) {
        if (needsSep) addDateSeparator(ts);
        addMessageBubble(text, false);
        promoteChatToTop(idx);
        rebuildChatList();
    } else {
        m_unread[idx] += 1;
        emit unreadChanged(totalUnread());
        promoteChatToTop(idx);
        rebuildChatList();
        if (m_notifier) m_notifier->notify(chat.name, text);
    }
}

// ── File chunk received ───────────────────────────────────────────────────────

void ChatView::onFileChunkReceived(const QString &fromPeerIdB64u,
                                   const QString &transferId,
                                   const QString &fileName,
                                   qint64         fileSize,
                                   int            chunksReceived,
                                   int            chunksTotal,
                                   const QByteArray &fileData,
                                   const QDateTime  &timestamp)
{
    const QString from = fromPeerIdB64u.trimmed();

    // Locate the chat this file belongs to (or create one)
    const int chatIndex = findOrCreateChatForPeer(from);
    if (chatIndex < 0) return;
    const QString key = chatKey(m_chats[chatIndex]);

    // Find an existing in-progress record for this transferId, or create one
    auto &records = m_filesByKey[key];
    FileTransferRecord *rec = nullptr;
    for (auto &r : records)
        if (r.transferId == transferId) { rec = &r; break; }

    if (!rec) {
        // First chunk we've heard about — create the record
        FileTransferRecord newRec;
        newRec.transferId    = transferId;
        newRec.fileName      = fileName;
        newRec.fileSize      = fileSize;
        newRec.peerIdB64u    = from;
        newRec.peerName      = m_chats[chatIndex].name;
        newRec.timestamp     = timestamp;
        newRec.sent          = false;
        newRec.status        = FileTransferStatus::Receiving;
        newRec.chunksTotal   = chunksTotal;
        newRec.chunksComplete = 0;
        records.append(newRec);
        rec = &records.last();
    }

    rec->chunksComplete = chunksReceived;
    rec->chunksTotal    = chunksTotal;

    const bool complete = (chunksReceived == chunksTotal);

    if (complete) {
        rec->status = FileTransferStatus::Complete;

        // Auto-save to Downloads/Peer2Pear/<transferId>/filename
        const QString saveDir = QStandardPaths::writableLocation(
                                    QStandardPaths::DownloadLocation)
                                + "/Peer2Pear/" + transferId;
        QDir().mkpath(saveDir);
        const QString savePath = saveDir + "/" + fileName;
        QFile f(savePath);
        bool saved = false;
        if (f.open(QIODevice::WriteOnly)) {
            f.write(fileData);
            f.close();
            saved = true;
            rec->savedPath = savePath;
        } else {
            qWarning() << "Could not auto-save file to" << savePath << ":" << f.errorString();
            rec->status = FileTransferStatus::Failed;
        }

        // System tray notification
        if (m_notifier) {
            const QString msg = saved
                                    ? QString("File ready: %1 (%2)").arg(fileName, formatFileSize(fileSize))
                                    : QString("File received but could not save: %1").arg(fileName);
            m_notifier->notify(m_chats[chatIndex].name, msg);
        }

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

// ── Attach / send file ────────────────────────────────────────────────────────

void ChatView::onAttachFile()
{
    if (m_currentChat < 0) return;

    const ChatData &chat = m_chats[m_currentChat];

    if (chat.keys.isEmpty()) {
        QMessageBox::warning(m_ui->centralwidget, "No Keys",
                             "This contact has no public keys — cannot send a file securely.");
        return;
    }
    if (chat.isGroup) {
        QMessageBox::information(m_ui->centralwidget, "Not Supported",
                                 "File sharing to group chats is not yet supported.\n"
                                 "Send files to individual contacts.");
        return;
    }

    const QString path = QFileDialog::getOpenFileName(
        m_ui->centralwidget, "Send File",
        QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(m_ui->centralwidget, "Error",
                             "Could not open file: " + f.errorString());
        return;
    }
    const QByteArray data = f.readAll();
    f.close();

    constexpr qint64 kMax = 8LL * 1024 * 1024;
    if (data.size() > kMax) {
        QMessageBox::warning(m_ui->centralwidget, "File Too Large",
                             "Maximum file size is 8 MB.\nThis file is " + formatFileSize(data.size()) + ".");
        return;
    }

    const QString fileName = QFileInfo(path).fileName();

    // ── Send to all keys for this contact ─────────────────────────────────────
    // Use the first key's transferId for the local record (all keys get the same
    // file but with their own encrypted copies; only one record shown per send).
    QString localTransferId;
    int totalChunks = 0;

    for (const QString &key : chat.keys) {
        if (key.trimmed().isEmpty()) continue;
        const QString tid = m_controller->sendFile(key.trimmed(), fileName, data);
        if (!tid.isEmpty() && localTransferId.isEmpty()) {
            localTransferId = tid;
            // Compute chunk count the same way ChatController does
            constexpr qint64 kChunk = 240LL * 1024;
            totalChunks = int((data.size() + kChunk - 1) / kChunk);
        }
    }

    if (localTransferId.isEmpty()) return; // all keys failed

    // Record sent transfer with accurate chunk count and Sending status.
    // savedPath stores the original file path so the Download button can re-open it.
    const QString key = chatKey(chat);
    FileTransferRecord rec;
    rec.transferId     = localTransferId;
    rec.fileName       = fileName;
    rec.fileSize       = data.size();
    rec.peerIdB64u     = chat.peerIdB64u;
    rec.peerName       = chat.name;
    rec.timestamp      = QDateTime::currentDateTime();
    rec.sent           = true;
    rec.status         = FileTransferStatus::Complete;
    rec.chunksTotal    = totalChunks;
    rec.chunksComplete = totalChunks;
    rec.savedPath      = path;   // original file — lets Download open it directly
    m_filesByKey[key].append(rec);

    rebuildFilesTab();

    // Delivery notice bubble in chat
    addMessageBubble(
        QString("📎  %1  (%2)").arg(fileName, formatFileSize(data.size())), true);
}

// ── Private slots ─────────────────────────────────────────────────────────────

void ChatView::onChatSelected(int index)
{
    if (index < 0 || index >= m_chats.size() || index == m_currentChat) return;
    m_currentChat = index;
    loadChat(index);
    ensureUnreadSize();
    if (m_unread[index] > 0) {
        m_unread[index] = 0;
        emit unreadChanged(totalUnread());
        rebuildChatList();
    }
}

void ChatView::onSendMessage()
{
    if (m_currentChat < 0) return;
    QString text = m_ui->messageInput->text().trimmed();
    if (text.isEmpty()) return;

    if (m_chats[m_currentChat].keys.isEmpty()) {
        addMessageBubble("No keys saved for this contact.", false);
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    const auto &msgs = m_chats[m_currentChat].messages;
    if (msgs.isEmpty() || msgs.last().timestamp.secsTo(now) >= kDateSepSecs)
        addDateSeparator(now);

    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    Message msg{true, text, now, msgId};
    m_chats[m_currentChat].messages.append(msg);

    if (m_db) {
        const QString dbKey = m_chats[m_currentChat].isGroup
                                  ? (m_chats[m_currentChat].groupId.isEmpty()
                                         ? "name:" + m_chats[m_currentChat].name
                                         : m_chats[m_currentChat].groupId)
                                  : (m_chats[m_currentChat].keys.isEmpty()
                                         ? "name:" + m_chats[m_currentChat].name
                                         : m_chats[m_currentChat].keys.first());
        m_db->saveMessage(dbKey, msg);
    }

    addMessageBubble(text, true);
    m_ui->messageInput->clear();

    if (m_chats[m_currentChat].isGroup) {
        const QString gid = m_chats[m_currentChat].groupId.isEmpty()
        ? m_chats[m_currentChat].name : m_chats[m_currentChat].groupId;
        m_controller->sendGroupMessageViaMailbox(
            gid, m_chats[m_currentChat].name, m_chats[m_currentChat].keys, text);
    } else {
        for (const QString &k : m_chats[m_currentChat].keys)
            if (!k.trimmed().isEmpty()) m_controller->sendText(k.trimmed(), text);
    }
}

void ChatView::onSearchChanged(const QString &text)
{
    const QString q = text.trimmed().toLower();
    for (int i = 0; i < m_ui->chatList->count(); ++i) {
        const ChatData &c = m_chats[i];
        bool match = q.isEmpty() || c.name.toLower().contains(q);
        if (!match) for (const auto &m : c.messages)
                if (m.text.toLower().contains(q)) { match = true; break; }
        m_ui->chatList->item(i)->setHidden(!match);
    }
    if (m_currentChat >= 0) {
        auto *cur = m_ui->chatList->item(m_currentChat);
        if (cur && cur->isHidden()) m_ui->chatList->clearSelection();
    }
}

void ChatView::onEditProfile()
{
    QString name = m_ui->profileNameLabel->text();
    QStringList keys = m_profileKeys;
    const QString myKey = m_controller->myIdB64u();
    if (!myKey.isEmpty() && !keys.contains(myKey)) keys << myKey;

    if (openContactEditor(m_ui->centralwidget, "Edit Your Profile", name, keys, false)
        == ContactEditorResult::Saved) {
        m_ui->profileNameLabel->setText(name.isEmpty() ? "Me" : name);
        m_ui->profileAvatarLabel->setText(name.isEmpty() ? "Y" : QString(name[0]).toUpper());
        m_profileKeys = keys;
        m_controller->setSelfKeys(m_profileKeys);
        if (m_db) {
            m_db->saveSetting("displayName", name);
            m_db->saveSetting("profileKeys", m_profileKeys.join(','));
        }
    }
}

void ChatView::onEditContact(int index)
{
    if (index < 0 || index >= m_chats.size()) return;
    QString     name = m_chats[index].name;
    QStringList keys = m_chats[index].keys;
    const auto result = openContactEditor(m_ui->centralwidget, "Edit Contact",
                                          name, keys, true, m_chats[index].isBlocked);

    if (result == ContactEditorResult::Saved && !name.isEmpty()) {
        m_chats[index].name = name; m_chats[index].keys = keys;
        if (m_chats[index].peerIdB64u.isEmpty() && !keys.isEmpty())
            m_chats[index].peerIdB64u = keys.first();
        if (m_db) m_db->saveContact(m_chats[index]);
        rebuildChatList();
        if (m_currentChat == index) {
            m_ui->chatTitleLabel->setText(name);
            m_ui->chatAvatarLabel->setText(QString(name[0]).toUpper());
        }
    } else if (result == ContactEditorResult::Removed) {
        const QString key = chatKey(m_chats[index]);
        if (m_db) m_db->deleteContact(m_chats[index].peerIdB64u);
        m_filesByKey.remove(key);
        m_chats.remove(index);
        m_unread.remove(index);
        m_currentChat = -1;
        rebuildChatList();
        if (!m_chats.isEmpty()) m_ui->chatList->setCurrentRow(0);
    } else if (result == ContactEditorResult::Blocked) {
        m_chats[index].isBlocked = !m_chats[index].isBlocked;
        if (m_db) m_db->saveContact(m_chats[index]);
        rebuildChatList();
    }
}

void ChatView::onAddContact()
{
    QString name; QStringList keys;

    QDialog dlg(m_ui->centralwidget);
    dlg.setWindowTitle("Add Contact"); dlg.setStyleSheet(kDlgStyle);
    dlg.setMinimumWidth(420); dlg.setModal(true);

    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(14); layout->setContentsMargins(24,24,24,24);
    auto *ttl = new QLabel("Add Contact",&dlg); ttl->setObjectName("dlgTitle");
    layout->addWidget(ttl);
    auto *sp = new QFrame(&dlg); sp->setFrameShape(QFrame::HLine);
    sp->setStyleSheet("color:#2a2a2a;"); layout->addWidget(sp);
    layout->addWidget(new QLabel("Display Name",&dlg));
    auto *nameEdit = new QLineEdit(&dlg); layout->addWidget(nameEdit);
    layout->addWidget(new QLabel("Public Keys",&dlg));
    auto *keyList = new QListWidget(&dlg); keyList->setFixedHeight(130);
    layout->addWidget(keyList);

    auto *kr   = new QHBoxLayout;
    auto *ki   = new QLineEdit(&dlg); ki->setPlaceholderText("Paste public key…");
    auto *addK = new QPushButton("Add Key",&dlg);
    auto *remK = new QPushButton("Remove",&dlg); remK->setObjectName("removeKeyBtn");
    kr->addWidget(ki,1); kr->addWidget(addK); kr->addWidget(remK);
    layout->addLayout(kr);

    QObject::connect(addK,&QPushButton::clicked,[&](){
        const QString k = ki->text().trimmed(); if(k.isEmpty()) return;
        for(int i=0;i<keyList->count();++i) if(keyList->item(i)->text()==k){
                QMessageBox::warning(&dlg,"Duplicate Key","Key already present."); return; }
        keyList->addItem(k); ki->clear();
    });
    QObject::connect(remK,&QPushButton::clicked,[&](){ delete keyList->currentItem(); });

    layout->addStretch();

    auto *br     = new QHBoxLayout;
    auto *grpBtn = new QPushButton("Create Group Chat",&dlg);
    auto *can    = new QPushButton("Cancel",&dlg); can->setObjectName("cancelBtn");
    auto *sav    = new QPushButton("Save",  &dlg); sav->setObjectName("saveBtn");
    grpBtn->setStyleSheet(
        "QPushButton{background-color:#1a2e1c;color:#5dd868;border:1px solid #2e5e30;"
        "border-radius:8px;padding:8px 16px;}QPushButton:hover{background-color:#223a24;}");
    br->setSpacing(10); br->addWidget(grpBtn); br->addStretch();
    br->addWidget(can); br->addWidget(sav);
    layout->addLayout(br);

    bool createGroup = false;
    QObject::connect(can,    &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(sav,    &QPushButton::clicked, &dlg, &QDialog::accept);
    QObject::connect(grpBtn, &QPushButton::clicked, [&](){ createGroup=true; dlg.accept(); });

    if (dlg.exec() != QDialog::Accepted) return;

    if (createGroup) {
        if (m_chats.isEmpty()) {
            QMessageBox::information(m_ui->centralwidget,"No Contacts",
                                     "Add some contacts first before creating a group."); return; }

        QDialog gd(m_ui->centralwidget);
        gd.setWindowTitle("New Group Chat"); gd.setStyleSheet(kDlgStyle);
        gd.setMinimumWidth(380);
        auto *gl = new QVBoxLayout(&gd); gl->setSpacing(12); gl->setContentsMargins(24,24,24,24);
        auto *gt = new QLabel("New Group Chat",&gd); gt->setObjectName("dlgTitle");
        gl->addWidget(gt); gl->addWidget(new QLabel("Group Name",&gd));
        auto *gn = new QLineEdit(&gd); gn->setPlaceholderText("Enter group name…");
        gl->addWidget(gn); gl->addWidget(new QLabel("Select Members",&gd));
        auto *ml = new QListWidget(&gd); ml->setFixedHeight(160);
        for (const ChatData &c : m_chats) {
            if (c.isGroup) continue;
            auto *it = new QListWidgetItem(c.name, ml); it->setCheckState(Qt::Unchecked);
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
        QStringList gkeys, mnames;
        for(int i=0;i<ml->count();++i) {
            if(ml->item(i)->checkState()==Qt::Checked)
                for(const ChatData &c:m_chats)
                    if(c.name==ml->item(i)->text()&&!c.isGroup){
                        gkeys<<c.keys; mnames<<c.name; break; }
        }
        if(gkeys.isEmpty()){ QMessageBox::warning(m_ui->centralwidget,"No Members",
                                 "Select at least one member."); return; }

        ChatData ng; ng.name = gname;
        ng.subtitle = QString("Group · %1 member%2").arg(mnames.size())
                          .arg(mnames.size()==1?"":"s");
        ng.isGroup = true; ng.keys = gkeys;
        ng.groupId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        ng.peerIdB64u = ng.groupId;
        m_chats.append(ng);
        if(m_db) m_db->saveContact(ng);
        rebuildChatList();
        m_ui->chatList->setCurrentRow(m_chats.size()-1);
        return;
    }

    name = nameEdit->text().trimmed(); if(name.isEmpty()) return;
    for(int i=0;i<keyList->count();++i) keys<<keyList->item(i)->text();
    ChatData nc; nc.name=name; nc.subtitle="Secure chat"; nc.keys=keys;
    if(!keys.isEmpty()) nc.peerIdB64u=keys.first();
    m_chats.append(nc);
    if(m_db) m_db->saveContact(nc);
    rebuildChatList();
    m_ui->chatList->setCurrentRow(m_chats.size()-1);
}

// ── Private helpers ───────────────────────────────────────────────────────────

int ChatView::findOrCreateChatForPeer(const QString &peerIdB64u)
{
    for (int i = 0; i < m_chats.size(); ++i) {
        if (m_chats[i].isGroup) continue;
        if (m_chats[i].peerIdB64u.trimmed() == peerIdB64u) return i;
        for (const QString &k : m_chats[i].keys)
            if (k.trimmed() == peerIdB64u) return i;
    }
    // Unknown sender — auto-create
    ChatData nc; nc.name = "Unknown contact"; nc.subtitle = "Secure chat";
    nc.peerIdB64u = peerIdB64u; nc.keys.append(peerIdB64u);
    m_chats.prepend(nc);
    if (m_db) m_db->saveContact(nc);
    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;
    rebuildChatList();
    return 0;
}

void ChatView::initChats()
{
    if (m_db) {
        const QString savedName = m_db->loadSetting("displayName");
        if (!savedName.isEmpty()) {
            m_ui->profileNameLabel->setText(savedName);
            m_ui->profileAvatarLabel->setText(QString(savedName[0]).toUpper());
        }
    }

    if (m_db) m_chats = m_db->loadAllContacts();

    m_ui->chatList->clear();
    for (const auto &c : m_chats) m_ui->chatList->addItem(c.name);

    if (m_db) {
        const QString sk = m_db->loadSetting("profileKeys");
        if (!sk.isEmpty()) m_profileKeys = sk.split(',', Qt::SkipEmptyParts);
    }
    m_controller->setSelfKeys(m_profileKeys);

    // Show first 8 chars of public key as handle
    const QString fullKey = m_controller->myIdB64u();
    if (!fullKey.isEmpty()) {
        m_ui->profileHandleLabel->setText(fullKey.left(8) + "…");
        m_ui->profileHandleLabel->setToolTip(fullKey);
    }
}

void ChatView::rebuildChatList()
{
    disconnect(m_ui->chatList, &QListWidget::currentRowChanged,
               this, &ChatView::onChatSelected);
    m_ui->chatList->clear();

    for (int i = 0; i < m_chats.size(); ++i) {
        auto *item = new QListWidgetItem(m_ui->chatList);
        item->setSizeHint(QSize(0, 52));
        auto *row = new QWidget;
        row->setStyleSheet("background:transparent;");
        auto *hl = new QHBoxLayout(row);
        hl->setContentsMargins(14,0,8,0); hl->setSpacing(6);

        auto *nameLbl = new QLabel(m_chats[i].name, row);
        nameLbl->setStyleSheet("color:#d0d0d0;font-size:14px;background:transparent;");
        hl->addWidget(nameLbl, 1);

        ensureUnreadSize();
        if (m_unread[i] > 0) {
            auto *dot = new QLabel(row); dot->setFixedSize(8,8);
            dot->setStyleSheet("QLabel{background-color:#5dd868;border-radius:4px;}");
            hl->addWidget(dot);
        }

        auto *editBtn = new QToolButton(row);
        editBtn->setText("✎"); editBtn->setFixedSize(28,28);
        editBtn->setStyleSheet(
            "QToolButton{background:transparent;border:none;color:#444444;"
            "font-size:15px;border-radius:6px;}"
            "QToolButton:hover{color:#5dd868;background:#1a2e1c;}");
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
    if (m_chats.isEmpty()) {
        QTimer::singleShot(0,[this](){ if(m_emptyLabel){
            m_emptyLabel->resize(m_ui->contentWidget->size());
            m_emptyLabel->raise(); m_emptyLabel->show(); } });
    } else {
        if (m_emptyLabel) m_emptyLabel->hide();
    }
}

void ChatView::loadChat(int index)
{
    const ChatData &chat = m_chats[index];
    m_ui->chatTitleLabel->setText(chat.name);
    m_ui->chatSubLabel->setText("● " + chat.subtitle);
    m_ui->chatAvatarLabel->setText(chat.name.isEmpty() ? "?" : QString(chat.name[0]).toUpper());
    clearMessages();

    QDateTime lastShown;
    for (const Message &msg : chat.messages) {
        if (!lastShown.isValid() || lastShown.secsTo(msg.timestamp) >= kDateSepSecs) {
            addDateSeparator(msg.timestamp);
            lastShown = msg.timestamp;
        }
        addMessageBubble(msg.text, msg.sent);
    }
    rebuildFilesTab();
}

void ChatView::promoteChatToTop(int index)
{
    // promoteChatToTop does NOT remap m_filesByKey because that map is keyed by
    // the stable peer ID — not by list index.  Only m_unread needs adjustment.
    if (index <= 0 || index >= m_chats.size()) return;

    ChatData promoted = m_chats.takeAt(index);
    m_chats.prepend(promoted);

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

void ChatView::addMessageBubble(const QString &text, bool sent)
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

    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(bh+4);
    auto *rl = new QHBoxLayout(row); rl->setContentsMargins(0,2,0,2); rl->setSpacing(0);

    auto *bubble = new QLabel(disp, row);
    bubble->setFont(f); bubble->setFixedSize(bw, bh);
    bubble->setWordWrap(wrap);
    bubble->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    bubble->setTextInteractionFlags(Qt::TextSelectableByMouse);

    if (sent) {
        bubble->setStyleSheet("background-color:#2e8b3a;color:#ffffff;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addStretch(); rl->addWidget(bubble);
    } else {
        bubble->setStyleSheet("background-color:#222222;color:#eeeeee;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addWidget(bubble); rl->addStretch();
    }

    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;
    layout->insertWidget(layout->count()-1, row);
    QTimer::singleShot(5,[this](){
        m_ui->messageScroll->verticalScrollBar()->setValue(
            m_ui->messageScroll->verticalScrollBar()->maximum()); });
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

    const QString key     = chatKey(m_chats[m_currentChat]);
    const auto   &records = m_filesByKey.value(key);

    if (records.isEmpty()) {
        // ── Empty state ───────────────────────────────────────────────────────
        auto *ph = new QLabel(m_ui->filesScrollContents);
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
    for (int i = 0; i < records.size(); ++i)
        grid->addWidget(buildFileCard(records[i], gridWidget), i / kCols, i % kCols);

    // Equal-width columns so cards fill the available space
    for (int c = 0; c < kCols; ++c)
        grid->setColumnStretch(c, 1);

    outer->addWidget(gridWidget);
    outer->addStretch();
}

QFrame *ChatView::buildFileCard(const FileTransferRecord &rec, QWidget *parent)
{
    const bool inFlight = (rec.status == FileTransferStatus::Sending ||
                           rec.status == FileTransferStatus::Receiving);

    // ── Card shell ────────────────────────────────────────────────────────────
    auto *card = new QFrame(parent);
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    card->setStyleSheet(
        "QFrame#fileCard{"
        "  background-color:#1a1a1a;"
        "  border:1px solid #2a2a2a;"
        "  border-radius:12px;"
        "}"
        );
    card->setObjectName("fileCard");

    auto *vl = new QVBoxLayout(card);
    vl->setContentsMargins(0, 0, 0, 16);
    vl->setSpacing(0);

    // ── Thumbnail / icon area ─────────────────────────────────────────────────
    auto *thumbWidget = new QWidget(card);
    thumbWidget->setMinimumHeight(220);
    thumbWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    thumbWidget->setStyleSheet(
        "background-color:#242424;"
        "border-radius:10px 10px 0 0;"
        );

    auto *thumbLayout = new QVBoxLayout(thumbWidget);
    thumbLayout->setContentsMargins(0, 0, 0, 0);

    auto *iconLbl = new QLabel(fileIcon(rec.fileName), thumbWidget);
    iconLbl->setAlignment(Qt::AlignCenter);
    iconLbl->setStyleSheet(
        "background:transparent;"
        "color:#555555;"
        "font-size:64px;"
        "border:none;"
        );
    thumbLayout->addStretch();
    thumbLayout->addWidget(iconLbl);

    // Progress bar overlaid at the bottom of the thumb area (in-flight only)
    if (inFlight && rec.chunksTotal > 0) {
        auto *pb = new QProgressBar(thumbWidget);
        pb->setRange(0, rec.chunksTotal);
        pb->setValue(rec.chunksComplete);
        pb->setFixedHeight(4);
        pb->setTextVisible(false);
        pb->setStyleSheet(
            "QProgressBar{background-color:#333333;border-radius:0;border:none;margin:0;}"
            "QProgressBar::chunk{background-color:#3a9e48;border-radius:0;}");
        thumbLayout->addWidget(pb);
    } else {
        thumbLayout->addStretch();
    }

    vl->addWidget(thumbWidget);

    // ── Text block ────────────────────────────────────────────────────────────
    auto *textWidget = new QWidget(card);
    textWidget->setStyleSheet("background:transparent;");
    auto *tl = new QVBoxLayout(textWidget);
    tl->setContentsMargins(14, 12, 14, 0);
    tl->setSpacing(3);

    // Filename (elided to one line)
    auto *nameLbl = new QLabel(textWidget);
    {
        QFont nf = nameLbl->font();
        nf.setBold(true);
        nf.setPixelSize(13);
        nameLbl->setFont(nf);
    }
    nameLbl->setStyleSheet("color:#eeeeee;background:transparent;border:none;");
    nameLbl->setToolTip(rec.fileName);
    // Elide done after card is painted; use a sizePolicy hint for now
    nameLbl->setText(rec.fileName);
    nameLbl->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Size label
    auto *sizeLbl = new QLabel(formatFileSize(rec.fileSize), textWidget);
    sizeLbl->setStyleSheet("color:#888888;font-size:12px;background:transparent;border:none;");

    // Direction / status label
    QString dirText;
    if (inFlight) {
        dirText = QString("%1 / %2 chunks…")
                      .arg(rec.chunksComplete).arg(rec.chunksTotal);
    } else {
        dirText = rec.sent ? "You sent this" : "From other";
    }
    auto *dirLbl = new QLabel(dirText, textWidget);
    dirLbl->setStyleSheet(
        inFlight ? "color:#5dd868;font-size:12px;background:transparent;border:none;"
                 : "color:#666666;font-size:12px;background:transparent;border:none;");

    tl->addWidget(nameLbl);
    tl->addWidget(sizeLbl);
    tl->addWidget(dirLbl);
    vl->addWidget(textWidget);

    // ── Download button (complete state only) ─────────────────────────────────
    if (rec.status == FileTransferStatus::Complete && !rec.savedPath.isEmpty()) {
        auto *btnContainer = new QWidget(card);
        btnContainer->setStyleSheet("background:transparent;");
        auto *bl = new QVBoxLayout(btnContainer);
        bl->setContentsMargins(14, 10, 14, 0);

        auto *dlBtn = new QPushButton("↓   Download", btnContainer);
        dlBtn->setFixedHeight(42);
        dlBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        dlBtn->setStyleSheet(
            "QPushButton{"
            "  background-color:#2e8b3a;"
            "  color:#ffffff;"
            "  border:none;"
            "  border-radius:8px;"
            "  font-size:13px;"
            "  font-weight:bold;"
            "}"
            "QPushButton:hover{ background-color:#38a844; }"
            "QPushButton:pressed{ background-color:#226228; }"
            );

        const QString savedPath = rec.savedPath;
        const QString fileName  = rec.fileName;
        const bool    isSent    = rec.sent;

        QObject::connect(dlBtn, &QPushButton::clicked, [=]() {
            if (isSent) {
                // Sent file: the savedPath IS the original file — just open its folder
                if (QFile::exists(savedPath)) {
                    QDesktopServices::openUrl(
                        QUrl::fromLocalFile(QFileInfo(savedPath).absolutePath()));
                } else {
                    QMessageBox::warning(m_ui->centralwidget, "File Not Found",
                                         "The original file could not be found at:\n" + savedPath);
                }
                return;
            }

            // Received file: offer Save As into a location the user chooses
            const QString defaultDest =
                QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
                + "/" + fileName;
            const QString dest = QFileDialog::getSaveFileName(
                m_ui->centralwidget, "Save File", defaultDest);
            if (dest.isEmpty()) return;

            if (!QFile::exists(savedPath)) {
                QMessageBox::warning(m_ui->centralwidget, "File Not Found",
                                     "The auto-saved copy could not be found:\n" + savedPath);
                return;
            }
            if (QFile::exists(dest)) QFile::remove(dest);
            if (QFile::copy(savedPath, dest)) {
                QMessageBox::information(m_ui->centralwidget, "Saved",
                                         "File saved to:\n" + dest);
            } else {
                QMessageBox::warning(m_ui->centralwidget, "Copy Failed",
                                     "Could not copy file to:\n" + dest);
            }
        });

        bl->addWidget(dlBtn);
        vl->addWidget(btnContainer);
    }

    return card;
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
