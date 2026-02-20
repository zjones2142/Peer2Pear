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

    ui->chatList->setCurrentRow(0);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    // Reflow bubbles at new width whenever the window is resized
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
    // Font matches stylesheet font-size: 13px exactly
    QFont bubbleFont = QApplication::font();
    bubbleFont.setPixelSize(13);
    QFontMetrics fm(bubbleFont);

    // Dynamic max width — 65% of the scroll area viewport, like iMessage
    int viewportWidth = ui->messageScroll->viewport()->width();
    int maxBubbleWidth = static_cast<int>(viewportWidth * 0.65);
    // Clamp to a sensible minimum so tiny windows don't break
    maxBubbleWidth = qMax(maxBubbleWidth, 120);

    const int hPadding = 28;  // 14px left + 14px right
    const int vPadding = 28;  // 10px top + 10px bottom
    const int availableTextWidth = maxBubbleWidth - hPadding;

    // Elide any word too long to wrap (URLs etc)
    bool hasLongWord = false;
    for (const QString &word : text.split(' ')) {
        if (fm.horizontalAdvance(word) > availableTextWidth) {
            hasLongWord = true;
            break;
        }
    }

    QString displayText = hasLongWord
                              ? fm.elidedText(text, Qt::ElideRight, availableTextWidth)
                              : text;

    // Measure natural single-line width
    int singleLineTextWidth = fm.horizontalAdvance(displayText);
    bool needsWrap = (singleLineTextWidth > availableTextWidth);

    // Bubble width: tight for short, max for long
    int bubbleWidth = needsWrap
                          ? maxBubbleWidth
                          : qMin(singleLineTextWidth + hPadding + 4, maxBubbleWidth);

    // Bubble height: count wrapped lines for accurate height
    int bubbleHeight;
    if (needsWrap) {
        int lineWidth = 0;
        int lines = 1;
        for (const QString &word : displayText.split(' ')) {
            int w = fm.horizontalAdvance(word + " ");
            if (lineWidth + w > availableTextWidth && lineWidth > 0) {
                lines++;
                lineWidth = w;
            } else {
                lineWidth += w;
            }
        }
        bubbleHeight = (fm.height() * lines) + vPadding + ((lines - 1) * fm.leading());
    } else {
        bubbleHeight = fm.height() + vPadding;
    }

    // Row — full viewport width, aligns bubble to correct side
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
