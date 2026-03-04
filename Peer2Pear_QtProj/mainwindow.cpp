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

    // Show identity in sidebar
    ui->profileHandleLabel->setText(m_controller.myIdB64u());

    // Logo
    QPixmap raw(":/logo.png");
    if (!raw.isNull()) {
        QPixmap logo = removeWhiteBackground(raw);
        ui->logoLabel->setPixmap(
            logo.scaled(44, 44, Qt::KeepAspectRatio, Qt::SmoothTransformation)
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
    m_chatView = new ChatView(ui, &m_controller, this);

    // Wire ChatController signals → ChatView slots
    connect(&m_controller, &ChatController::messageReceived,
            m_chatView,    &ChatView::onIncomingMessage);
    connect(&m_controller, &ChatController::status,
            m_chatView,    &ChatView::onStatus);

    // ── Settings connections ───────────────────────────────────────────────────
    connect(ui->settingsBtn_12, &QToolButton::clicked,
            this, &MainWindow::onSettingsClicked);
    connect(m_settingsPanel, &SettingsPanel::backClicked,
            this, &MainWindow::onSettingsBackClicked);
    connect(m_settingsPanel, &SettingsPanel::notificationsToggled,
            this, [](bool enabled) {
                qDebug() << "[settings] notifications enabled:" << enabled;//test qDebug delete later
            });
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
