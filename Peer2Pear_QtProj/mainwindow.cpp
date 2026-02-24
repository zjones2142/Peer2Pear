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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Point to your Python server (change to EC2 URL when ready)
    m_controller.setServerBaseUrl(QUrl("http://127.0.0.1:8080"));
    m_controller.startPolling(2000);

    connect(&m_controller, &ChatController::messageReceived,
            this, &MainWindow::onIncomingMessage);

    connect(&m_controller, &ChatController::status,
            this, &MainWindow::onStatus);

    // show identity in sidebar
    ui->profileHandleLabel->setText(m_controller.myIdB64u());

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

    ui->chatList->setCurrentRow(0);
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
    // NOTE: Replace these with REAL peer IDs (base64url ed25519 pub) from other devices.
    // For quick testing, run two clients and copy each "profileHandleLabel" to the other's peerIdB64u.

    ChatData alice;
    alice.name     = "Alice";
    alice.subtitle = "Secure chat";
    alice.peerIdB64u = ""; // <-- paste Alice pubkey here on your device
    alice.messages = {
                      {false, "Hey! How are you?"},
                      {true,  "I'm doing great, thanks!"},
                      {false, "That's wonderful to hear"},
                      };
    m_chats.append(alice);

    ChatData bob;
    bob.name     = "Bob";
    bob.subtitle = "Secure chat";
    bob.peerIdB64u = ""; // <-- paste Bob pubkey
    bob.messages = {
                    {false, "Did you see the game last night?"},
                    {true,  "Yeah, incredible finish!"},
                    };
    m_chats.append(bob);

    ChatData charlie;
    charlie.name     = "Charlie";
    charlie.subtitle = "Secure chat";
    charlie.peerIdB64u = "";
    charlie.messages = {
                        {true,  "Hey, sending over those files soon"},
                        {false, "Sounds good, no rush"},
                        };
    m_chats.append(charlie);

    ChatData group;
    group.name     = "Group Chat";
    group.subtitle = "MVP (no MLS yet)";
    group.peerIdB64u = ""; // unused for now
    group.messages = {
                      {false, "Welcome everyone!"},
                      {true,  "Thanks for having us"},
                      };
    m_chats.append(group);

    // Populate sidebar list items from chats vector
    ui->chatList->clear();
    for (const auto& c : m_chats) {
        ui->chatList->addItem(c.name);
    }
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
    if (m_currentChat < 0) return;

    QString text = ui->messageInput->text().trimmed();
    if (text.isEmpty()) return;

    const QString peerId = m_chats[m_currentChat].peerIdB64u.trimmed();
    if (peerId.isEmpty()) {
        addMessageBubble("Peer ID missing for this chat (set peerIdB64u).", false);
        return;
    }

    // UI update (sent bubble)
    m_chats[m_currentChat].messages.append({true, text});
    addMessageBubble(text, true);
    ui->messageInput->clear();

    // Send encrypted via mailbox
    m_controller.sendTextViaMailbox(peerId, text);
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
    ui->chatSubLabel->setText(chat.subtitle);

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

void MainWindow::onIncomingMessage(const QString& fromPeerIdB64u, const QString& text)
{
    // Find matching chat by peer id
    for (int i = 0; i < m_chats.size(); ++i) {
        if (m_chats[i].peerIdB64u.trimmed() == fromPeerIdB64u.trimmed()) {
            m_chats[i].messages.append({false, text});
            if (i == m_currentChat) addMessageBubble(text, false);
            return;
        }
    }

    // If unknown peer, drop into current chat (or create new chat in real app)
    if (m_currentChat >= 0) {
        m_chats[m_currentChat].messages.append({false, text});
        addMessageBubble(QString("[Unknown sender] %1").arg(text), false);
    }
}

void MainWindow::onStatus(const QString& s)
{
    // could log to console for now
    qDebug() << "[status]" << s;
}
