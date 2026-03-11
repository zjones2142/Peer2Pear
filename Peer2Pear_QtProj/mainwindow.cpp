#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QPixmap>
#include <QImage>
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

    // ── DB: open the database as early as possible ────────────────────────────
    if (!m_db.open()) {
        QMessageBox::critical(this, "Database Error",
                              "Could not open the local chat database.\n"
                              "Chat history will not be saved this session.");
    }

    // --- Strict identity unlock (wrong passphrase => do not create new identity) ---
    while (true) {
        bool ok = false;
        QString pass = QInputDialog::getText(
            this,
            "Unlock Identity",
            "Enter passphrase to unlock this device identity:",
            QLineEdit::Password,
            "",
            &ok
            );

        if (!ok) {
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }

        if (pass.isEmpty()) {
            QMessageBox::warning(this, "Passphrase Required",
                                 "Passphrase cannot be empty.");
            continue;
        }

        try {
            m_controller.setPassphrase(pass);
            break; // success
        } catch (const std::exception& e) {
            QMessageBox::warning(this, "Identity Unlock Failed", e.what());
        }
    }


    // Point to Python server (change to EC2 URL when ready)
    m_controller.setServerBaseUrl(QUrl("http://3.141.14.234"));
    m_controller.startPolling(2000);

    // Publish this device to the rendezvous server so peers can reach us directly.
    // Port 0 = let the OS assign a free port automatically.
    // Replace "0.0.0.0" with your actual public IP if behind NAT,
    // or use a STUN lookup to auto-detect it.
    m_controller.publishMyAddress("0.0.0.0", 0);

    // Show identity in sidebar
    ui->profileHandleLabel->setText(m_controller.myIdB64u());

    // Logo
    QPixmap raw(":/logo.png");
    if (!raw.isNull()) {
        QPixmap logo = raw;
        ui->logoLabel->setPixmap(
            logo.scaled(50, 50, Qt::KeepAspectRatio, Qt::SmoothTransformation)
            );
        ui->logoLabel->setText("");
    }

    // ── Build stacked widget (chat view = 0, settings = 1) ───────────────────
    QHBoxLayout *rootLayout = qobject_cast<QHBoxLayout *>(ui->rootWidget->layout());

    rootLayout->removeWidget(ui->contentWidget);

    m_mainStack = new QStackedWidget(ui->rootWidget);
    m_mainStack->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->contentWidget->setParent(m_mainStack);
    m_mainStack->addWidget(ui->contentWidget); // index 0 – chat view

    m_settingsPanel = new SettingsPanel(ui->rootWidget);
    m_mainStack->addWidget(m_settingsPanel);   // index 1 – settings view

    rootLayout->addWidget(m_mainStack);

    // ── Create ChatView (owns all chat logic) ─────────────────────────────────
    m_chatView = new ChatView(ui, &m_controller, &m_db, this);

    m_chatView->setShouldToastFn([this]() -> bool {
        // toast when not actively viewing the app
        return this->isMinimized() || !this->isVisible() || !this->isActiveWindow();
    });

    // Wire ChatController signals → ChatView slots
    connect(&m_controller, &ChatController::messageReceived,
            m_chatView,    &ChatView::onIncomingMessage);
    connect(&m_controller, &ChatController::status,
            m_chatView,    &ChatView::onStatus);

    // ── Create notifier and hand it to ChatView ───────────────────────────────
    m_notifier = new ChatNotifier(this);
    m_chatView->setNotifier(m_notifier);


    // ── Settings connections ───────────────────────────────────────────────────
    connect(ui->settingsBtn_12, &QToolButton::clicked,
            this, &MainWindow::onSettingsClicked);
    connect(m_settingsPanel, &SettingsPanel::backClicked,
            this, &MainWindow::onSettingsBackClicked);
    connect(m_settingsPanel, &SettingsPanel::notificationsToggled,
            m_notifier,      &ChatNotifier::setEnabled);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    if (m_chatView)
        m_chatView->reloadCurrentChat();
}

void MainWindow::onSettingsClicked()
{
    m_mainStack->setCurrentIndex(1); // show settings
}

void MainWindow::onSettingsBackClicked()
{
    m_mainStack->setCurrentIndex(0); // back to chat
}
