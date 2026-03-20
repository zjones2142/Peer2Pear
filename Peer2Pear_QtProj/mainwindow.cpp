#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QPixmap>
#include <QHBoxLayout>
#include <QStackedWidget>
#include <QTimer>
#include <QInputDialog>
#include <QMessageBox>
#include <QLineEdit>
#include <QToolButton>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // ── DB ────────────────────────────────────────────────────────────────────
    if (!m_db.open()) {
        QMessageBox::critical(this, "Database Error",
                              "Could not open the local chat database.\n"
                              "Chat history will not be saved this session.");
    }

    // ── Identity unlock ───────────────────────────────────────────────────────
    while (true) {
        bool ok = false;
        QString pass = QInputDialog::getText(this, "Unlock Identity",
                                             "Enter passphrase to unlock this device identity:",
                                             QLineEdit::Password, "", &ok);

        if (!ok) { QTimer::singleShot(0, qApp, &QCoreApplication::quit); return; }
        if (pass.isEmpty()) {
            QMessageBox::warning(this, "Passphrase Required", "Passphrase cannot be empty.");
            continue;
        }
        try {
            m_controller.setPassphrase(pass);
            break;
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Identity Unlock Failed", e.what());
        }
    }

    // ── Server + polling ──────────────────────────────────────────────────────
    m_controller.setServerBaseUrl(QUrl("http://3.141.14.234"));
    m_controller.startPolling(2000);

    // ── Profile handle: first 8 chars of public key ───────────────────────────
    const QString fullKey = m_controller.myIdB64u();
    ui->profileHandleLabel->setText(fullKey.left(8) + "…");
    ui->profileHandleLabel->setToolTip(fullKey);

    // ── Logo ──────────────────────────────────────────────────────────────────
    QPixmap raw(":/logo.png");
    if (!raw.isNull()) {
        ui->logoLabel->setPixmap(
            raw.scaled(50, 50, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        ui->logoLabel->setText("");
    }

    // ── Stacked widget ────────────────────────────────────────────────────────
    QHBoxLayout *rootLayout = qobject_cast<QHBoxLayout*>(ui->rootWidget->layout());
    rootLayout->removeWidget(ui->contentWidget);

    m_mainStack = new QStackedWidget(ui->rootWidget);
    m_mainStack->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->contentWidget->setParent(m_mainStack);
    m_mainStack->addWidget(ui->contentWidget);  // index 0 – chat

    m_settingsPanel = new SettingsPanel(ui->rootWidget);
    m_mainStack->addWidget(m_settingsPanel);    // index 1 – settings

    rootLayout->addWidget(m_mainStack);

    // ── ChatView ──────────────────────────────────────────────────────────────
    m_chatView = new ChatView(ui, &m_controller, &m_db, this);

    m_chatView->setShouldToastFn([this]() -> bool {
        return isMinimized() || !isVisible() || !isActiveWindow();
    });

    // ── Wire signals ──────────────────────────────────────────────────────────
    connect(&m_controller, &ChatController::messageReceived,
            m_chatView,    &ChatView::onIncomingMessage);
    connect(&m_controller, &ChatController::status,
            m_chatView,    &ChatView::onStatus);
    connect(&m_controller, &ChatController::groupMessageReceived,
            m_chatView,    &ChatView::onIncomingGroupMessage);
    connect(&m_controller, &ChatController::groupMemberLeft,
            m_chatView,    &ChatView::onGroupMemberLeft);
    connect(&m_controller, &ChatController::fileChunkReceived,
            m_chatView,    &ChatView::onFileChunkReceived);
    connect(&m_controller, &ChatController::presenceChanged,
            m_chatView,    &ChatView::onPresenceChanged);

    // ── Notifier ──────────────────────────────────────────────────────────────
    m_notifier = new ChatNotifier(this);
    m_chatView->setNotifier(m_notifier);

    // ── Settings ──────────────────────────────────────────────────────────────
    connect(ui->settingsBtn_12,  &QToolButton::clicked,
            this, &MainWindow::onSettingsClicked);
    connect(m_settingsPanel, &SettingsPanel::backClicked,
            this, &MainWindow::onSettingsBackClicked);
    connect(m_settingsPanel, &SettingsPanel::notificationsToggled,
            m_notifier,      &ChatNotifier::setEnabled);

    // ── Resize debounce ───────────────────────────────────────────────────────
    m_resizeDebounce.setSingleShot(true);
    m_resizeDebounce.setInterval(100);
    connect(&m_resizeDebounce, &QTimer::timeout, this, [this]() {
        if (m_chatView) m_chatView->reloadCurrentChat();
    });
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    m_resizeDebounce.start(); // coalesce rapid resize events
}

void MainWindow::onSettingsClicked()    { m_mainStack->setCurrentIndex(1); }
void MainWindow::onSettingsBackClicked(){ m_mainStack->setCurrentIndex(0); }
