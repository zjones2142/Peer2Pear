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
#include <QStackedWidget>
#include <QPushButton>
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

    // contentWidget + settingsPanel as pages 0 and 1.

    QHBoxLayout *rootLayout = qobject_cast<QHBoxLayout *>(ui->rootWidget->layout());

    // Remove contentWidget from the layout (it stays parented to rootWidget for now)
    rootLayout->removeWidget(ui->contentWidget);

    // Create the stacked widget, re-parent contentWidget into it
    m_mainStack = new QStackedWidget(ui->rootWidget);
    m_mainStack->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->contentWidget->setParent(m_mainStack);
    m_mainStack->addWidget(ui->contentWidget);   // ndex 0 – normal chat view

    // Build and add settings panel
    buildSettingsPanel();                         //creates m_settingsPanel
    m_mainStack->addWidget(m_settingsPanel);      //index 1 – settings view

    rootLayout->addWidget(m_mainStack);

    // Connections
    initChats();

    connect(ui->chatList, &QListWidget::currentRowChanged,
            this, &MainWindow::onChatSelected);
    connect(ui->sendBtn, &QPushButton::clicked,
            this, &MainWindow::onSendMessage);
    connect(ui->messageInput, &QLineEdit::returnPressed,
            this, &MainWindow::onSendMessage);
    connect(ui->searchEdit_12, &QLineEdit::textChanged,
            this, &MainWindow::onSearchChanged);
    connect(ui->settingsBtn_12, &QToolButton::clicked,//add the settings button connection
            this, &MainWindow::onSettingsClicked);

    ui->chatList->setCurrentRow(0);
}

MainWindow::~MainWindow()
{
    delete ui;
}

// Settings panel builder
void MainWindow::buildSettingsPanel()
{
    m_settingsPanel = new QWidget();
    m_settingsPanel->setObjectName("settingsPanel");
    m_settingsPanel->setStyleSheet(
        "QWidget#settingsPanel { background-color: #0d0d0d; }"
        );

    QVBoxLayout *outerLayout = new QVBoxLayout(m_settingsPanel);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Top bar
    QWidget *settingsHeader = new QWidget();
    settingsHeader->setObjectName("settingsHeader");
    settingsHeader->setFixedHeight(72);
    settingsHeader->setStyleSheet(
        "QWidget#settingsHeader { background-color: #0d0d0d; border-bottom: 1px solid #1e1e1e; }"
        );

    QHBoxLayout *headerLayout = new QHBoxLayout(settingsHeader);
    headerLayout->setContentsMargins(20, 12, 20, 4);
    headerLayout->setSpacing(12);

    QPushButton *backBtn = new QPushButton("← Back");
    backBtn->setObjectName("settingsBackBtn");
    backBtn->setFixedSize(80, 32);
    backBtn->setStyleSheet(
        "QPushButton#settingsBackBtn {"
        "  background-color: transparent;"
        "  color: #888888;"
        "  border: 1px solid #333333;"
        "  border-radius: 8px;"
        "  font-size: 13px;"
        "  padding: 4px 10px;"
        "}"
        "QPushButton#settingsBackBtn:hover { color: #ffffff; border-color: #555555; }"
        );

    QLabel *titleLabel = new QLabel("Settings");
    titleLabel->setStyleSheet("color: #ffffff; font-size: 16px; font-weight: bold;");

    headerLayout->addWidget(backBtn);
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();

    connect(backBtn, &QPushButton::clicked, this, &MainWindow::onSettingsBackClicked);

    // Scrollable settings body
    QScrollArea *scroll = new QScrollArea();
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet("background-color: #0d0d0d; border: none;");

    QWidget *body = new QWidget();
    body->setStyleSheet("background-color: #0d0d0d;");
    QVBoxLayout *bodyLayout = new QVBoxLayout(body);
    bodyLayout->setContentsMargins(32, 24, 32, 24);
    bodyLayout->setSpacing(24);

    // creates a settings section card (subject to change when we find out what we want in here)
    auto makeSection = [&](const QString &sectionTitle,
                           const QList<QPair<QString,QString>> &rows) -> QWidget *
    {
        QWidget *card = new QWidget();
        card->setStyleSheet(
            "background-color: #111111;"
            "border: 1px solid #1e1e1e;"
            "border-radius: 10px;"
            );

        QVBoxLayout *cardLayout = new QVBoxLayout(card);
        cardLayout->setContentsMargins(0, 0, 0, 0);
        cardLayout->setSpacing(0);

        // Section heading
        QLabel *heading = new QLabel(sectionTitle);
        heading->setStyleSheet(
            "color: #4caf50;"
            "font-size: 11px;"
            "font-weight: bold;"
            "padding: 12px 16px 6px 16px;"
            "background: transparent;"
            "border: none;"
            );
        cardLayout->addWidget(heading);

        for (int i = 0; i < rows.size(); ++i) {
            QWidget *row = new QWidget();
            row->setStyleSheet("background: transparent; border: none;");

            QHBoxLayout *rl = new QHBoxLayout(row);
            rl->setContentsMargins(16, 10, 16, 10);
            rl->setSpacing(8);

            QLabel *key = new QLabel(rows[i].first);
            key->setStyleSheet("color: #cccccc; font-size: 13px; background: transparent; border: none;");

            QLabel *val = new QLabel(rows[i].second);
            val->setStyleSheet("color: #555555; font-size: 13px; background: transparent; border: none;");
            val->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

            rl->addWidget(key);
            rl->addStretch();
            rl->addWidget(val);

            cardLayout->addWidget(row);

            // Divider between rows (not after last)
            if (i < rows.size() - 1) {
                QFrame *divider = new QFrame();
                divider->setFrameShape(QFrame::HLine);
                divider->setStyleSheet("color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;");
                cardLayout->addWidget(divider);
            }
        }

        return card;
    };

    // ── Profile section ──────────────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("PROFILE", {
                                                  { "Display Name",  "You"       },
                                                  { "Handle",        "@handle"   },
                                                  { "Status",        "Online"    },
                                                  }));

    // ── Privacy section ──────────────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("PRIVACY & SECURITY", {
                                                             { "End-to-End Encryption",  "Enabled"  },
                                                             { "Read Receipts",          "On"       },
                                                             { "Last Seen",              "Everyone" },
                                                             }));

    // ── Notifications section ────────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("NOTIFICATIONS", {
                                                        { "Message Alerts",   "On"  },
                                                        { "Sound",            "On"  },
                                                        { "Do Not Disturb",   "Off" },
                                                        }));

    // ── About section ────────────────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("ABOUT", {
                                                { "Version",     "0.1.0"      },
                                                { "Protocol",    "Peer2Pear"  },
                                                }));

    bodyLayout->addStretch();
    scroll->setWidget(body);

    outerLayout->addWidget(settingsHeader);
    outerLayout->addWidget(scroll);
}

// Slot: open settings
void MainWindow::onSettingsClicked()
{
    m_mainStack->setCurrentIndex(1);  // show settings panel
}

// Slot: close settings
void MainWindow::onSettingsBackClicked()
{
    m_mainStack->setCurrentIndex(0);  // back to chat view
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
