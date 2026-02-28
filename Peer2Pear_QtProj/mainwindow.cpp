#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QLabel>
#include <QPixmap>
#include <QImage>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollBar>
#include <QFontMetrics>
#include <QApplication>
#include <QResizeEvent>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QToolButton>
#include <QSignalMapper>
#include <QFrame>

static QPixmap removeWhiteBackground(const QPixmap &src, int threshold = 80)
{
    QImage img = src.toImage().convertToFormat(QImage::Format_ARGB32);
    for (int y = 0; y < img.height(); ++y) {
        for (int x = 0; x < img.width(); ++x) {
            QColor c = img.pixelColor(x, y);
            if (c.red()   > (255 - threshold) &&
                c.green() > (255 - threshold) &&
                c.blue()  > (255 - threshold))
            {
                img.setPixelColor(x, y, Qt::transparent);
            }
        }
    }
    return QPixmap::fromImage(img);
}

// Break a long unbreakable word into hyphenated chunks that fit within maxWidth
static QString hyphenateWord(const QString &word, const QFontMetrics &fm, int maxWidth)
{
    QString result;
    QString current;

    for (int i = 0; i < word.length(); ++i) {
        QString test = current + word[i];
        // Check if adding a hyphen would still fit
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

// Process text — hyphenate any word that won't fit on one line
static QString processText(const QString &text, const QFontMetrics &fm, int maxWidth)
{
    QStringList words = text.split(' ');
    QStringList processed;

    for (const QString &word : words) {
        if (fm.horizontalAdvance(word) > maxWidth) {
            processed << hyphenateWord(word, fm, maxWidth);
        } else {
            processed << word;
        }
    }

    return processed.join(' ');
}

// ── Shared dialog stylesheet ──────────────────────────────────────────────
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

// Opens a modal dialog to edit a contact name + list of keys.
// nameInOut and keysInOut are updated on Save.
static bool openContactEditor(QWidget *parent,
                              const QString &title,
                              QString &nameInOut,
                              QStringList &keysInOut)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setStyleSheet(kDialogStyle);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    // Title
    auto *titleLbl = new QLabel(title, &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    // Separator
    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color: #2a2a2a;");
    root->addWidget(sep);

    // Name field
    auto *nameLbl = new QLabel("Display Name", &dlg);
    root->addWidget(nameLbl);
    auto *nameEdit = new QLineEdit(nameInOut, &dlg);
    root->addWidget(nameEdit);

    // Keys section
    auto *keysLbl = new QLabel("Public Keys", &dlg);
    root->addWidget(keysLbl);

    auto *keyList = new QListWidget(&dlg);
    keyList->setFixedHeight(130);
    for (const QString &k : keysInOut)
        keyList->addItem(k);
    root->addWidget(keyList);

    // Key controls
    auto *keyRow = new QHBoxLayout;
    keyRow->setSpacing(8);
    auto *keyInput = new QLineEdit(&dlg);
    keyInput->setPlaceholderText("Paste public key...");
    auto *addKeyBtn = new QPushButton("Add Key", &dlg);
    auto *removeKeyBtn = new QPushButton("Remove", &dlg);
    removeKeyBtn->setObjectName("removeKeyBtn");
    keyRow->addWidget(keyInput, 1);
    keyRow->addWidget(addKeyBtn);
    keyRow->addWidget(removeKeyBtn);
    root->addLayout(keyRow);

    QObject::connect(addKeyBtn, &QPushButton::clicked, [&]() {
        QString k = keyInput->text().trimmed();
        if (!k.isEmpty()) {
            keyList->addItem(k);
            keyInput->clear();
        }
    });
    QObject::connect(removeKeyBtn, &QPushButton::clicked, [&]() {
        delete keyList->currentItem();
    });

    // Spacer
    root->addStretch();

    // Save / Cancel
    auto *btnRow = new QHBoxLayout;
    btnRow->setSpacing(10);
    auto *cancelBtn = new QPushButton("Cancel", &dlg);
    cancelBtn->setObjectName("cancelBtn");
    auto *saveBtn   = new QPushButton("Save", &dlg);
    saveBtn->setObjectName("saveBtn");
    btnRow->addStretch();
    btnRow->addWidget(cancelBtn);
    btnRow->addWidget(saveBtn);
    root->addLayout(btnRow);

    QObject::connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(saveBtn,   &QPushButton::clicked, &dlg, &QDialog::accept);

    if (dlg.exec() != QDialog::Accepted)
        return false;

    nameInOut = nameEdit->text().trimmed();
    keysInOut.clear();
    for (int i = 0; i < keyList->count(); ++i)
        keysInOut << keyList->item(i)->text();
    return true;
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QPixmap raw(":/logo.png");
    if (!raw.isNull()) {
        QPixmap logo = removeWhiteBackground(raw);
        ui->logoLabel->setPixmap(
            logo.scaled(44, 44, Qt::KeepAspectRatio, Qt::SmoothTransformation)
            );
        ui->logoLabel->setText("");
    }

    initChats();

    connect(ui->chatList, &QListWidget::currentRowChanged,
            this, &MainWindow::onChatSelected);
    connect(ui->sendBtn, &QPushButton::clicked,
            this, &MainWindow::onSendMessage);
    connect(ui->messageInput, &QLineEdit::returnPressed,
            this, &MainWindow::onSendMessage);
    connect(ui->searchEdit_12, &QLineEdit::textChanged,
            this, &MainWindow::onSearchChanged);
    connect(ui->editProfileBtn, &QToolButton::clicked,
            this, &MainWindow::onEditProfile);
    connect(ui->addContactBtn, &QToolButton::clicked,
            this, &MainWindow::onAddContact);
    connect(ui->settingsBtn_12, &QToolButton::clicked,
            this, &MainWindow::onOpenSettings);

    rebuildChatList();
    ui->chatList->setCurrentRow(0);
}

// Rebuilds the chat list, attaching an edit ✎ button to each row via setItemWidget.
void MainWindow::rebuildChatList()
{
    // Disconnect temporarily to avoid spurious selection changes
    disconnect(ui->chatList, &QListWidget::currentRowChanged,
               this, &MainWindow::onChatSelected);

    ui->chatList->clear();

    for (int i = 0; i < m_chats.size(); ++i) {
        auto *item = new QListWidgetItem(ui->chatList);
        item->setSizeHint(QSize(0, 52));

        auto *row = new QWidget;
        row->setStyleSheet("background: transparent;");
        auto *hl = new QHBoxLayout(row);
        hl->setContentsMargins(14, 0, 8, 0);
        hl->setSpacing(6);

        auto *nameLbl = new QLabel(m_chats[i].name, row);
        nameLbl->setStyleSheet("color: #d0d0d0; font-size: 14px; background: transparent;");
        hl->addWidget(nameLbl, 1);

        auto *editBtn = new QToolButton(row);
        editBtn->setText("✎");
        editBtn->setFixedSize(28, 28);
        editBtn->setStyleSheet(
            "QToolButton { background: transparent; border: none; color: #444444; font-size: 15px; border-radius: 6px; }"
            "QToolButton:hover { color: #5dd868; background: #1a2e1c; }"
        );
        editBtn->setToolTip("Edit contact");
        hl->addWidget(editBtn);

        ui->chatList->setItemWidget(item, row);

        // Capture index by value
        connect(editBtn, &QToolButton::clicked, this, [this, i]() {
            onEditContact(i);
        });
    }

    connect(ui->chatList, &QListWidget::currentRowChanged,
            this, &MainWindow::onChatSelected);

    if (m_currentChat >= 0 && m_currentChat < ui->chatList->count())
        ui->chatList->setCurrentRow(m_currentChat);
}

void MainWindow::onEditProfile()
{
    // For profile we reuse the same dialog; keys are empty placeholders for now
    QString name = ui->profileNameLabel->text();
    QStringList keys;
    if (openContactEditor(this, "Edit Your Profile", name, keys)) {
        ui->profileNameLabel->setText(name.isEmpty() ? "You" : name);
        ui->profileAvatarLabel->setText(name.isEmpty() ? "Y" : QString(name[0]).toUpper());
    }
}

void MainWindow::onEditContact(int index)
{
    if (index < 0 || index >= m_chats.size()) return;

    QString name = m_chats[index].name;
    QStringList keys; // placeholder — real keys would live in ChatData
    if (openContactEditor(this, "Edit Contact", name, keys)) {
        if (!name.isEmpty()) {
            m_chats[index].name = name;
            rebuildChatList();
            if (m_currentChat == index) {
                ui->chatTitleLabel->setText(name);
                ui->chatAvatarLabel->setText(QString(name[0]).toUpper());
            }
        }
    }
}

void MainWindow::onAddContact()
{
    QString name;
    QStringList keys;
    if (openContactEditor(this, "Add Contact / Group", name, keys)) {
        if (!name.isEmpty()) {
            ChatData newChat;
            newChat.name     = name;
            newChat.subtitle = "Secure chat";
            m_chats.append(newChat);
            rebuildChatList();
            ui->chatList->setCurrentRow(m_chats.size() - 1);
        }
    }
}

void MainWindow::onOpenSettings()
{
    QDialog dlg(this);
    dlg.setWindowTitle("Preferences");
    dlg.setStyleSheet(kDialogStyle);
    dlg.setMinimumSize(400, 300);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setContentsMargins(24, 24, 24, 24);
    root->setSpacing(12);

    auto *title = new QLabel("Preferences", &dlg);
    title->setObjectName("dlgTitle");
    root->addWidget(title);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color: #2a2a2a;");
    root->addWidget(sep);

    auto *placeholder = new QLabel("Settings coming soon...", &dlg);
    placeholder->setAlignment(Qt::AlignCenter);
    placeholder->setStyleSheet("color: #444444; font-size: 13px;");
    root->addWidget(placeholder, 1);

    auto *closeBtn = new QPushButton("Close", &dlg);
    closeBtn->setObjectName("cancelBtn");
    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);

    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    if (m_currentChat >= 0)
        loadChat(m_currentChat);
}

void MainWindow::initChats()
{
    ChatData alice;
    alice.name     = "Alice";
    alice.subtitle = "Secure chat";
    alice.messages = {
                      {false, "Hey! How are you?"},
                      {true,  "I'm doing great, thanks!"},
                      {false, "That's wonderful to hear"},
                      };
    m_chats.append(alice);

    ChatData bob;
    bob.name     = "Bob";
    bob.subtitle = "Secure chat";
    bob.messages = {
                    {false, "Did you see the game last night?"},
                    {true,  "Yeah, incredible finish!"},
                    };
    m_chats.append(bob);

    ChatData charlie;
    charlie.name     = "Charlie";
    charlie.subtitle = "Secure chat";
    charlie.messages = {
                        {true,  "Hey, sending over those files soon"},
                        {false, "Sounds good, no rush"},
                        };
    m_chats.append(charlie);

    ChatData group;
    group.name     = "Group Chat";
    group.subtitle = "Secure chat";
    group.messages = {
                      {false, "Welcome everyone!"},
                      {true,  "Thanks for having us"},
                      };
    m_chats.append(group);
}

void MainWindow::onSearchChanged(const QString &text)
{
    QString query = text.trimmed().toLower();

    for (int i = 0; i < ui->chatList->count(); ++i) {
        QListWidgetItem *item = ui->chatList->item(i);
        const ChatData &chat = m_chats[i];

        bool matches = false;

        if (query.isEmpty()) {
            matches = true;
        } else {
            if (chat.name.toLower().contains(query))
                matches = true;

            if (!matches) {
                for (const auto &msg : chat.messages) {
                    if (msg.second.toLower().contains(query)) {
                        matches = true;
                        break;
                    }
                }
            }
        }

        item->setHidden(!matches);
    }

    if (m_currentChat >= 0) {
        QListWidgetItem *current = ui->chatList->item(m_currentChat);
        if (current && current->isHidden())
            ui->chatList->clearSelection();
    }
}

void MainWindow::onSendMessage()
{
    if (m_currentChat < 0)
        return;

    QString text = ui->messageInput->text().trimmed();
    if (text.isEmpty())
        return;

    m_chats[m_currentChat].messages.append({true, text});
    addMessageBubble(text, true);
    ui->messageInput->clear();
}

void MainWindow::onChatSelected(int index)
{
    if (index < 0 || index >= m_chats.size())
        return;

    if (index == m_currentChat)
        return;

    m_currentChat = index;
    loadChat(index);
}

void MainWindow::loadChat(int index)
{
    const ChatData &chat = m_chats[index];

    ui->chatTitleLabel->setText(chat.name);
    ui->chatSubLabel->setText("● " + chat.subtitle);
    ui->chatAvatarLabel->setText(chat.name.isEmpty() ? "?" : QString(chat.name[0]).toUpper());

    clearMessages();
    for (const auto &msg : chat.messages)
        addMessageBubble(msg.second, msg.first);
}

void MainWindow::clearMessages()
{
    QLayout *layout = ui->scrollAreaWidgetContents->layout();
    if (!layout)
        return;

    while (layout->count() > 1) {
        QLayoutItem *item = layout->takeAt(0);
        if (item->widget())
            delete item->widget();
        delete item;
    }
}

void MainWindow::addMessageBubble(const QString &text, bool sent)
{
    QFont bubbleFont = QApplication::font();
    bubbleFont.setPixelSize(13);
    QFontMetrics fm(bubbleFont);

    // Dynamic max width — 65% of viewport like iMessage
    int viewportWidth = ui->messageScroll->viewport()->width();
    int maxBubbleWidth = qMax(static_cast<int>(viewportWidth * 0.65), 120);

    const int hPadding = 28;
    const int vPadding = 28;
    const int availableTextWidth = maxBubbleWidth - hPadding;

    // Process text — hyphenate any word too long to fit
    QString displayText = processText(text, fm, availableTextWidth);

    // Measure natural single-line width of processed text
    int singleLineTextWidth = fm.horizontalAdvance(displayText);
    bool needsWrap = (singleLineTextWidth > availableTextWidth)
                     || displayText.contains('\n');

    // Bubble width: tight for short, max for long
    int bubbleWidth = needsWrap
                          ? maxBubbleWidth
                          : qMin(singleLineTextWidth + hPadding + 4, maxBubbleWidth);

    // Count lines for height calculation
    int bubbleHeight;
    if (needsWrap) {
        // Split on explicit newlines first (from hyphenation), then count word-wrap lines
        int lines = 0;
        for (const QString &para : displayText.split('\n')) {
            if (para.isEmpty()) {
                lines++;
                continue;
            }
            int lineWidth = 0;
            int paraLines = 1;
            for (const QString &word : para.split(' ')) {
                int w = fm.horizontalAdvance(word + " ");
                if (lineWidth + w > availableTextWidth && lineWidth > 0) {
                    paraLines++;
                    lineWidth = w;
                } else {
                    lineWidth += w;
                }
            }
            lines += paraLines;
        }
        bubbleHeight = (fm.height() * lines) + vPadding + ((lines - 1) * fm.leading()) + 1;
    } else {
        bubbleHeight = fm.height() + vPadding + 1;
    }

    // Row — full viewport width
    QWidget *row = new QWidget(ui->scrollAreaWidgetContents);
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

    if (sent) {
        bubble->setStyleSheet(
            "background-color: #2e8b3a;"
            "color: #ffffff;"
            "border-radius: 14px;"
            "padding: 10px 14px;"
            "font-size: 13px;"
            );
        rowLayout->addStretch();
        rowLayout->addWidget(bubble);
    } else {
        bubble->setStyleSheet(
            "background-color: #222222;"
            "color: #eeeeee;"
            "border-radius: 14px;"
            "padding: 10px 14px;"
            "font-size: 13px;"
            );
        rowLayout->addWidget(bubble);
        rowLayout->addStretch();
    }

    QVBoxLayout *layout = qobject_cast<QVBoxLayout *>(
        ui->scrollAreaWidgetContents->layout()
        );
    if (!layout)
        return;

    layout->insertWidget(layout->count() - 1, row);

    QApplication::processEvents();
    ui->messageScroll->verticalScrollBar()->setValue(
        ui->messageScroll->verticalScrollBar()->maximum()
        );
}
