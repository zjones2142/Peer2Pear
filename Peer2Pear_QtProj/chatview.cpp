#include "chatview.h"
#include "ui_mainwindow.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollBar>
#include <QFontMetrics>
#include <QApplication>
#include <QDialog>
#include <QFrame>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QToolButton>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>

// ── DATE SEPARATOR: how many seconds of silence before we show a divider ─────
static constexpr int kDateSeparatorThresholdSecs = 60 * 60 * 2; // 2 hour(changed the multiplier at the end to incr hours of time

// ── DATE SEPARATOR: format a QDateTime into label text ─────────
// Produces e.g.  "Thu, Feb 26 at 1:39 PM"
// If the message is from today we just show "Today at 1:39 PM".
// If it was yesterday we show "Yesterday at 1:39 PM".
static QString formatSeparatorLabel(const QDateTime &dt)
{
    const QDate today     = QDate::currentDate();
    const QDate yesterday = today.addDays(-1);
    const QDate msgDate   = dt.toLocalTime().date();

    QString datePart;
    if (msgDate == today)
        datePart = "Today";
    else if (msgDate == yesterday)
        datePart = "Yesterday";
    else
        datePart = dt.toLocalTime().toString("ddd, MMM d");   // "Thu, Feb 26"

    const QString timePart = dt.toLocalTime().toString("h:mm AP"); // "1:39 PM"
    return datePart + " at " + timePart;
}

// ── Text-layout helpers ───────────────────────────────────────────────────────

// Break a long unbreakable word into hyphenated chunks that fit within maxWidth
static QString hyphenateWord(const QString &word, const QFontMetrics &fm, int maxWidth)
{
    QString result;
    QString current;

    for (int i = 0; i < word.length(); ++i) {
        QString test = current + word[i];
        QString testWithHyphen = test + "-";
        if (fm.horizontalAdvance(testWithHyphen) >= maxWidth && !current.isEmpty()) {
            result += current + "-\n";
            current = word[i];
        } else {
            current = test;
        }
    }
    result += current;
    return result;
}

// Hyphenate any word that won't fit on one line
static QString processText(const QString &text, const QFontMetrics &fm, int maxWidth)
{
    QStringList words = text.split(' ');
    QStringList processed;

    for (const QString &word : words) {
        if (fm.horizontalAdvance(word) > maxWidth)
            processed << hyphenateWord(word, fm, maxWidth);
        else
            processed << word;
    }

    return processed.join(' ');
}

// ── Shared dialog stylesheet ──────────────────────────────────────────────────
static const char *kDialogStyle =
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
    "QPushButton#saveBtn { background-color: #2e8b3a; color: #ffffff; border: none; }"
    "QPushButton#saveBtn:hover { background-color: #38a844; }"
    "QPushButton#cancelBtn { background-color: #1e1e1e; color: #888888; border: 1px solid #2a2a2a; }"
    "QPushButton#cancelBtn:hover { background-color: #252525; color: #cccccc; }"
    "QPushButton#removeKeyBtn { background-color: #2e1a1a; color: #cc5555; border: 1px solid #5e2e2e; }"
    "QPushButton#removeKeyBtn:hover { background-color: #3a2020; }";

// Opens a modal dialog to edit a contact name + list of public keys.
// nameInOut and keysInOut are updated on Save; returns false on Cancel.
enum class ContactEditorResult { Cancelled, Saved, Blocked, Removed };
static ContactEditorResult openContactEditor(QWidget *parent,
                                             const QString &title,
                                             QString &nameInOut,
                                             QStringList &keysInOut,
                                             bool showDestructiveActions = true)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setStyleSheet(kDialogStyle);
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
    sep->setStyleSheet("color: #2a2a2a;");
    root->addWidget(sep);

    auto *nameLbl = new QLabel("Display Name", &dlg);
    root->addWidget(nameLbl);
    auto *nameEdit = new QLineEdit(nameInOut, &dlg);
    root->addWidget(nameEdit);

    auto *keysLbl = new QLabel("Public Keys", &dlg);
    root->addWidget(keysLbl);

    auto *keyList = new QListWidget(&dlg);
    keyList->setFixedHeight(130);
    for (const QString &k : keysInOut)
        keyList->addItem(k);
    root->addWidget(keyList);

    auto *keyRow = new QHBoxLayout;
    keyRow->setSpacing(8);
    auto *keyInput    = new QLineEdit(&dlg);
    keyInput->setPlaceholderText("Paste public key...");
    auto *addKeyBtn   = new QPushButton("Add Key", &dlg);
    auto *removeKeyBtn = new QPushButton("Remove", &dlg);
    removeKeyBtn->setObjectName("removeKeyBtn");
    keyRow->addWidget(keyInput, 1);
    keyRow->addWidget(addKeyBtn);
    keyRow->addWidget(removeKeyBtn);
    root->addLayout(keyRow);

    QObject::connect(addKeyBtn, &QPushButton::clicked, [&]() {
        QString k = keyInput->text().trimmed();
        if (!k.isEmpty()) {
            // Check for duplicate key
            bool duplicate = false;
            for (int i = 0; i < keyList->count(); ++i) {
                if (keyList->item(i)->text() == k) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                QMessageBox::warning(&dlg, "Duplicate Key",
                                     "This key already exists and was not added.");
            } else {
                keyList->addItem(k);
                keyInput->clear();
            }
        }
    });
    QObject::connect(removeKeyBtn, &QPushButton::clicked, [&]() {
        delete keyList->currentItem();
    });

    root->addStretch();
    ContactEditorResult result = ContactEditorResult::Cancelled;

    // ── Block and remove contact ───────────────────────────────────────────────
    if (showDestructiveActions) {
        auto *actionSep = new QFrame(&dlg);
        actionSep->setFrameShape(QFrame::HLine);
        actionSep->setStyleSheet("color: #2a2a2a;");
        root->addWidget(actionSep);

        auto *actionRow  = new QHBoxLayout;
        auto *blockBtn   = new QPushButton("Block Contact", &dlg);
        auto *removeBtn  = new QPushButton("Remove Contact", &dlg);
        const QString destructiveStyle =
            "QPushButton { background-color: #2e1a1a; color: #cc5555;"
            "  border: 1px solid #5e2e2e; border-radius: 8px; padding: 8px 16px; }"
            "QPushButton:hover { background-color: #3a2020; }";
        blockBtn->setStyleSheet(destructiveStyle);
        removeBtn->setStyleSheet(destructiveStyle);
        actionRow->addWidget(blockBtn);
        actionRow->addWidget(removeBtn);
        actionRow->addStretch();
        root->addLayout(actionRow);

        QObject::connect(blockBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Block Contact",
                                      "Block this contact? They won't be able to send you messages.",
                                      QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                result = ContactEditorResult::Blocked;
                dlg.accept();
            }
        });
        QObject::connect(removeBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Remove Contact",
                                      "Remove this contact? This cannot be undone.",
                                      QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                result = ContactEditorResult::Removed;
                dlg.accept();
            }
        });
    }

    auto *btnRow   = new QHBoxLayout;
    auto *cancelBtn = new QPushButton("Cancel", &dlg);
    cancelBtn->setObjectName("cancelBtn");
    auto *saveBtn   = new QPushButton("Save", &dlg);
    saveBtn->setObjectName("saveBtn");
    btnRow->setSpacing(10);
    btnRow->addStretch();
    btnRow->addWidget(cancelBtn);
    btnRow->addWidget(saveBtn);
    root->addLayout(btnRow);

    QObject::connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(saveBtn, &QPushButton::clicked, [&]() {
        result = ContactEditorResult::Saved;
        dlg.accept();
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

// ── ChatView implementation ───────────────────────────────────────────────────

ChatView::ChatView(Ui::MainWindow *ui, ChatController *controller,DatabaseManager *db, QObject *parent)
    : QObject(parent)
    , m_ui(ui)
    , m_controller(controller)
    , m_db(db)
{
    initChats();

    ensureUnreadSize();

    connect(m_ui->chatList, &QListWidget::currentRowChanged,
            this, &ChatView::onChatSelected);
    connect(m_ui->sendBtn, &QPushButton::clicked,
            this, &ChatView::onSendMessage);
    connect(m_ui->messageInput, &QLineEdit::returnPressed,
            this, &ChatView::onSendMessage);
    connect(m_ui->searchEdit_12, &QLineEdit::textChanged,
            this, &ChatView::onSearchChanged);
    connect(m_ui->editProfileBtn, &QToolButton::clicked,
            this, &ChatView::onEditProfile);
    connect(m_ui->addContactBtn, &QToolButton::clicked,
            this, &ChatView::onAddContact);

    rebuildChatList();
    m_ui->chatList->setCurrentRow(0);
}

// ── Public ────────────────────────────────────────────────────────────────────

void ChatView::reloadCurrentChat()
{
    if (m_emptyLabel) {
        m_emptyLabel->resize(m_ui->contentWidget->size());
        m_emptyLabel->raise();
        m_emptyLabel->setVisible(m_chats.isEmpty());
    }
}

// ── Slots (public — wired by MainWindow) ─────────────────────────────────────

void ChatView::onIncomingMessage(const QString &fromPeerIdB64u, const QString &text, const QDateTime &timestamp)
{
    const QString from = fromPeerIdB64u.trimmed();
    ensureUnreadSize();

    auto shouldToast = [&]() -> bool {
        return m_shouldToastFn ? m_shouldToastFn() : true; // default: toast if not provided
    };

    for (int i = 0; i < m_chats.size(); ++i) {
        auto matchesChat = [&](int idx) {
            return m_chats[idx].peerIdB64u.trimmed() == from;
        };

        bool hit = false;

        if (m_chats[i].peerIdB64u.trimmed() == from) {
            hit = true;
        } else {
            for (const QString &key : m_chats[i].keys) {
                if (key.trimmed() == from) { hit = true; break; }
            }
        }

        if (hit) {
            const QDateTime now = timestamp;

            const bool needsSeparator =
                m_chats[i].messages.isEmpty() ||
                m_chats[i].messages.last().timestamp.secsTo(now) >= kDateSeparatorThresholdSecs;

            Message msg{ false, text, now };
            m_chats[i].messages.append(msg);

            if (m_db){
                m_db->saveContact(m_chats[i]);
                m_db->saveMessage(m_chats[i].peerIdB64u, msg);
            }

            if (i == m_currentChat) {
                // Currently open — insert separator if needed, then the bubble
                if (needsSeparator)
                    addDateSeparator(now);
                addMessageBubble(text, false);
                promoteChatToTop(i);
                rebuildChatList();
            } else {
                m_unread[i] += 1;
                emit unreadChanged(totalUnread());
                promoteChatToTop(i);
                rebuildChatList();
                if (m_notifier && shouldToast())
                    m_notifier->notify(m_chats[0].name, text);
            }
            return;
        }
    }

    // Unknown sender — auto-create a chat for them
    qDebug() << "Received message from unknown peer:" << fromPeerIdB64u;

    const QDateTime now = timestamp;
    Message msg{ false, text, now };

    ChatData newChat;
    newChat.name       = "Unknown contact";
    newChat.subtitle   = "Secure chat";
    newChat.peerIdB64u = from;
    newChat.keys.append(from);
    newChat.messages.append(msg);
    m_chats.prepend(newChat);

    if (m_db) {//database save for new contact and message
        m_db->saveContact(newChat);
        m_db->saveMessage(from, msg);
    }

    ensureUnreadSize();
    m_unread.prepend(0);

    // New chat is always at index 0; m_currentChat shifts down by 1
    if (m_currentChat >= 0)
        m_currentChat += 1;

    m_unread[0] += 1;
    emit unreadChanged(totalUnread());

    if (m_notifier && shouldToast())
        m_notifier->notify("Unknown contact", text);

    rebuildChatList();
}

void ChatView::onStatus(const QString &s)
{
    qDebug() << "[status]" << s;
}

// ── Private slots ─────────────────────────────────────────────────────────────

void ChatView::onChatSelected(int index)
{
    if (index < 0 || index >= m_chats.size()) return;
    if (index == m_currentChat) return;
    m_currentChat = index;
    loadChat(index);

    // ── Mark as read ──────────────────────────────────────────────────────────
    ensureUnreadSize();
    if (m_unread[index] > 0) {
        m_unread[index] = 0;
        emit unreadChanged(totalUnread()); // clears dot + taskbar badge
        rebuildChatList();                 // removes the dot from the sidebar row
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

    const QDateTime now = QDateTime::currentDateTime();//updates the date on the message, and also used for date separator logic

    const auto &msgs = m_chats[m_currentChat].messages;
    const bool needsSeparator =
        msgs.isEmpty() ||
        msgs.last().timestamp.secsTo(now) >= kDateSeparatorThresholdSecs;

    if (needsSeparator)
        addDateSeparator(now);

    Message msg{ true, text, now };
    m_chats[m_currentChat].messages.append(msg);

    if (m_db) {
        const QString key = m_chats[m_currentChat].keys.isEmpty()
        ? "name:" + m_chats[m_currentChat].name
        : m_chats[m_currentChat].keys.first();
        m_db->saveMessage(key, msg);
    }


    addMessageBubble(text, true);
    m_ui->messageInput->clear();

    for (const QString &key : m_chats[m_currentChat].keys) {
        if (!key.trimmed().isEmpty())
            m_controller->sendTextViaMailbox(key.trimmed(), text);
    }
}

void ChatView::onSearchChanged(const QString &text)
{
    QString query = text.trimmed().toLower();

    for (int i = 0; i < m_ui->chatList->count(); ++i) {
        QListWidgetItem *item = m_ui->chatList->item(i);
        const ChatData  &chat = m_chats[i];
        bool matches = false;

        if (query.isEmpty()) {
            matches = true;
        } else {
            if (chat.name.toLower().contains(query))
                matches = true;
            if (!matches) {
                for (const auto &msg : chat.messages) {
                    if (msg.text.toLower().contains(query)) { matches = true; break; }
                }
            }
        }
        item->setHidden(!matches);
    }

    if (m_currentChat >= 0) {
        QListWidgetItem *current = m_ui->chatList->item(m_currentChat);
        if (current && current->isHidden())
            m_ui->chatList->clearSelection();
    }
}

void ChatView::onEditProfile()
{
    QString name = m_ui->profileNameLabel->text();
    QStringList keys = m_profileKeys;
    const QString myKey = m_controller->myIdB64u();
    if (!myKey.isEmpty() && !keys.contains(myKey))
        keys << myKey;

    if (openContactEditor(m_ui->centralwidget, "Edit Your Profile", name, keys, false)
        == ContactEditorResult::Saved) {
        m_ui->profileNameLabel->setText(name.isEmpty() ? "Me" : name);
        m_ui->profileAvatarLabel->setText(name.isEmpty() ? "Y" : QString(name[0]).toUpper());
        m_profileKeys = keys;
        m_controller->setSelfKeys(m_profileKeys); // poll all self-device mailboxes

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

    const ContactEditorResult result =
        openContactEditor(m_ui->centralwidget, "Edit Contact", name, keys);

    if (result == ContactEditorResult::Saved && !name.isEmpty()) {
        // Update the contact and save to the database
        m_chats[index].name = name;
        m_chats[index].keys = keys;
        if (m_chats[index].peerIdB64u.isEmpty() && !keys.isEmpty())
            m_chats[index].peerIdB64u = keys.first();
        if (m_db) m_db->saveContact(m_chats[index]);
        rebuildChatList();
        // Update the chat header if this contact is currently open
        if (m_currentChat == index) {
            m_ui->chatTitleLabel->setText(name);
            m_ui->chatAvatarLabel->setText(QString(name[0]).toUpper());
        }

    } else if (result == ContactEditorResult::Removed) {
        // Delete from the database and remove from the in-memory list
        if (m_db) m_db->deleteContact(m_chats[index].peerIdB64u);
        m_chats.remove(index);
        m_unread.remove(index);
        m_currentChat = -1;
        rebuildChatList();
        if (!m_chats.isEmpty())
            m_ui->chatList->setCurrentRow(0);

    } else if (result == ContactEditorResult::Blocked) {
        // Mark as blocked — incoming messages from this contact will be dropped
        m_chats[index].isBlocked = true;
        if (m_db) m_db->saveContact(m_chats[index]);
        rebuildChatList();
    }
}

void ChatView::onAddContact()
{
    QString name;
    QStringList keys;
    if (openContactEditor(m_ui->centralwidget, "Add Contact / Group", name, keys, false)
        == ContactEditorResult::Saved) {
        if (!name.isEmpty()) {
            ChatData newChat;
            newChat.name       = name;
            newChat.subtitle   = "Secure chat";
            newChat.keys       = keys;
            if (!keys.isEmpty()) newChat.peerIdB64u = keys.first();
            m_chats.append(newChat);

            if (m_db) m_db->saveContact(newChat);//database save for new contact

            rebuildChatList();
            m_ui->chatList->setCurrentRow(m_chats.size() - 1);
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

void ChatView::initChats()
{
    // ── DB: load saved display name and restore it to the profile labels ──────
    if (m_db) {
        const QString savedName = m_db->loadSetting("displayName");
        if (!savedName.isEmpty()) {
            m_ui->profileNameLabel->setText(savedName);
            m_ui->profileAvatarLabel->setText(QString(savedName[0]).toUpper());
        }
    }

    // -- load contacts from Db - start with empty list if none exists
    if (m_db) {
        m_chats = m_db->loadAllContacts(); // returns empty QVector on a fresh DB
    }

    m_ui->chatList->clear();
    for (const auto &c : m_chats)
        m_ui->chatList->addItem(c.name);

    // Load saved self-device keys and start polling all of them
    if (m_db) {
        const QString savedKeys = m_db->loadSetting("profileKeys");
        if (!savedKeys.isEmpty())
            m_profileKeys = savedKeys.split(',', Qt::SkipEmptyParts);
    }
    m_controller->setSelfKeys(m_profileKeys);
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
        row->setStyleSheet("background: transparent;");
        auto *hl = new QHBoxLayout(row);
        hl->setContentsMargins(14, 0, 8, 0);
        hl->setSpacing(6);

        auto *nameLbl = new QLabel(m_chats[i].name, row);
        nameLbl->setStyleSheet("color: #d0d0d0; font-size: 14px; background: transparent;");
        hl->addWidget(nameLbl, 1);

        // ── Unread dot ────────────────────────────────────────────────────────
        ensureUnreadSize();
        if (m_unread[i] > 0) {
            auto *dot = new QLabel(row);
            dot->setFixedSize(8, 8);
            dot->setStyleSheet(
                "QLabel { background-color: #5dd868; border-radius: 4px; }"
                );
            hl->addWidget(dot);
        }

        auto *editBtn = new QToolButton(row);
        editBtn->setText("✎");
        editBtn->setFixedSize(28, 28);
        editBtn->setStyleSheet(
            "QToolButton { background: transparent; border: none; color: #444444; font-size: 15px; border-radius: 6px; }"
            "QToolButton:hover { color: #5dd868; background: #1a2e1c; }"
            );
        editBtn->setToolTip("Edit contact");
        hl->addWidget(editBtn);

        m_ui->chatList->setItemWidget(item, row);

        connect(editBtn, &QToolButton::clicked, this, [this, i]() {
            onEditContact(i);
        });
    }

    connect(m_ui->chatList, &QListWidget::currentRowChanged,
            this, &ChatView::onChatSelected);

    if (m_currentChat >= 0 && m_currentChat < m_ui->chatList->count())
        m_ui->chatList->setCurrentRow(m_currentChat);

    // Show/hide empty state overlay
    if (!m_emptyLabel) {
        m_emptyLabel = new QLabel(m_ui->contentWidget);
        m_emptyLabel->setText("💬\n\nNo contacts yet\nClick + to add a contact\nand start chatting");
        m_emptyLabel->setAlignment(Qt::AlignCenter);
        m_emptyLabel->setStyleSheet(
            "color: #555555;"
            "font-size: 14px;"
            "background-color: #0a0a0a;"
            "padding: 40px;"
            );
        m_emptyLabel->setWordWrap(true);
        m_emptyLabel->setAttribute(Qt::WA_TransparentForMouseEvents, false);
    }
    m_emptyLabel->resize(m_ui->contentWidget->size());
    m_emptyLabel->move(0, 0);
    m_emptyLabel->raise();
    if (m_chats.isEmpty()) {
        QTimer::singleShot(0, [this]() {
            if (m_emptyLabel) {
                m_emptyLabel->resize(m_ui->contentWidget->size());
                m_emptyLabel->raise();
                m_emptyLabel->show();
            }
        });
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
        const bool needsSeparator =
            !lastShown.isValid() ||
            lastShown.secsTo(msg.timestamp) >= kDateSeparatorThresholdSecs;

        if (needsSeparator) {
            addDateSeparator(msg.timestamp);
            lastShown = msg.timestamp;
        }

        addMessageBubble(msg.text, msg.sent);
    }
}

void ChatView::promoteChatToTop(int index)
{
    if (index <= 0 || index >= m_chats.size())
        return; // already at top or invalid

    // Move the chat data to front
    ChatData promoted = m_chats.takeAt(index);
    m_chats.prepend(promoted);

    // Mirror the unread vector
    ensureUnreadSize();
    int unreadCount = m_unread[index];
    m_unread.remove(index);
    m_unread.prepend(unreadCount);

    // Keep m_currentChat pointing at the same chat
    if (m_currentChat == index) {
        m_currentChat = 0;
    } else if (m_currentChat >= 0 && m_currentChat < index) {
        m_currentChat += 1; // everything above index shifted down by one
    }
}

void ChatView::clearMessages()
{
    QLayout *layout = m_ui->scrollAreaWidgetContents->layout();
    if (!layout) return;

    while (layout->count() > 1) {
        QLayoutItem *item = layout->takeAt(0);
        if (item->widget()) delete item->widget();
        delete item;
    }
}

// ── DATE SEPARATOR: insert a centered iMessage-style date label ───────────────
void ChatView::addDateSeparator(const QDateTime &dt)
{
    QVBoxLayout *layout = qobject_cast<QVBoxLayout *>(
        m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;

    // Outer row — full width, centered
    QWidget *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(28);

    QHBoxLayout *hl = new QHBoxLayout(row);
    hl->setContentsMargins(0, 4, 0, 4);
    hl->setSpacing(0);

    QLabel *lbl = new QLabel(formatSeparatorLabel(dt), row);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet(
        "color: #666666;"          //gray muted color
        "font-size: 11px;"
        "background: transparent;"
        );

    hl->addStretch();
    hl->addWidget(lbl);
    hl->addStretch();

    layout->insertWidget(layout->count() - 1, row);
}

void ChatView::addMessageBubble(const QString &text, bool sent)
{
    QFont bubbleFont = QApplication::font();
    bubbleFont.setPixelSize(13);
    QFontMetrics fm(bubbleFont);

    // Dynamic max width — 65% of viewport like iMessage
    int viewportWidth   = m_ui->messageScroll->viewport()->width();
    int maxBubbleWidth  = qMax(static_cast<int>(viewportWidth * 0.65), 120);

    const int hPadding          = 28;
    const int vPadding          = 28;
    const int availableTextWidth = maxBubbleWidth - hPadding;

    QString displayText      = processText(text, fm, availableTextWidth);
    int singleLineTextWidth  = fm.horizontalAdvance(displayText);
    bool needsWrap           = (singleLineTextWidth > availableTextWidth)
                     || displayText.contains('\n');

    int bubbleWidth = needsWrap
                          ? maxBubbleWidth
                          : qMin(singleLineTextWidth + hPadding + 4, maxBubbleWidth);

    int bubbleHeight;
    if (needsWrap) {
        int lines = 0;
        for (const QString &para : displayText.split('\n')) {
            if (para.isEmpty()) { lines++; continue; }
            int lineWidth = 0, paraLines = 1;
            for (const QString &word : para.split(' ')) {
                int w = fm.horizontalAdvance(word + " ");
                if (lineWidth + w > availableTextWidth && lineWidth > 0) { paraLines++; lineWidth = w; }
                else lineWidth += w;
            }
            lines += paraLines;
        }
        bubbleHeight = (fm.height() * lines) + vPadding + ((lines - 1) * fm.leading()) + 1;
    } else {
        bubbleHeight = fm.height() + vPadding + 1;
    }

    QWidget *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(bubbleHeight + 4);

    QHBoxLayout *rowLayout = new QHBoxLayout(row);
    rowLayout->setContentsMargins(0, 2, 0, 2);
    rowLayout->setSpacing(0);

    QLabel *bubble = new QLabel(displayText, row);
    bubble->setFont(bubbleFont);
    bubble->setFixedSize(bubbleWidth, bubbleHeight);
    bubble->setWordWrap(needsWrap);
    bubble->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    bubble->setTextInteractionFlags(Qt::TextSelectableByMouse);

    if (sent) {bubble->setTextInteractionFlags(Qt::TextSelectableByMouse);
        bubble->setStyleSheet(
            "background-color: #2e8b3a; color: #ffffff;"
            "border-radius: 14px; padding: 10px 14px; font-size: 13px;"
            );
        rowLayout->addStretch();
        rowLayout->addWidget(bubble);
    } else {
        bubble->setStyleSheet(
            "background-color: #222222; color: #eeeeee;"
            "border-radius: 14px; padding: 10px 14px; font-size: 13px;"
            );
        rowLayout->addWidget(bubble);
        rowLayout->addStretch();
    }

    QVBoxLayout *layout = qobject_cast<QVBoxLayout *>(
        m_ui->scrollAreaWidgetContents->layout()
        );
    if (!layout) return;

    layout->insertWidget(layout->count() - 1, row);

    QApplication::processEvents();
    m_ui->messageScroll->verticalScrollBar()->setValue(
        m_ui->messageScroll->verticalScrollBar()->maximum()
        );
}

void ChatView::ensureUnreadSize()
{
    if (m_unread.size() < m_chats.size())
        m_unread.resize(m_chats.size());
}

int ChatView::totalUnread() const
{
    int sum = 0;
    for (int n : m_unread) sum += n;
    return sum;
}
