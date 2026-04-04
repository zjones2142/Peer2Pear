#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "onboardingdialog.h"

#include <QPixmap>
#include <QHBoxLayout>
#include <QSet>
#include <QStackedWidget>
#include <QTimer>
#include <QInputDialog>
#include <QMessageBox>
#include <QLineEdit>
#include <QToolButton>
#include <QDebug>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

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
            // Derive a DB encryption key from the passphrase (secret) for at-rest protection.
            // Also provide the old key (derived from public ID) so existing encrypted
            // messages can still be read during migration.
            QByteArray newKey = ChatController::blake2b256(
                pass.toUtf8() + QByteArray("peer2pear-dbkey"));
            QByteArray legacyKey = ChatController::blake2b256(
                m_controller.myIdB64u().toUtf8() + QByteArray("peer2pear-dbkey"));
            m_db.setEncryptionKey(newKey, legacyKey);
            CryptoEngine::secureZero(newKey);
            CryptoEngine::secureZero(legacyKey);
            // Wire DB to ChatController for Noise/Ratchet session persistence
            m_controller.setDatabase(m_db.database());
            CryptoEngine::secureZero(pass);
            break;
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Identity Unlock Failed", e.what());
        }
    }

    // ── First-time onboarding ─────────────────────────────────────────────────
    if (m_db.loadSetting("displayName").isEmpty()) {
        OnboardingDialog dlg(this);
        if (dlg.exec() != QDialog::Accepted) {
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }
        m_db.saveSetting("displayName", dlg.displayName());
        if (!dlg.avatarData().isEmpty()) {
            m_db.saveSetting("avatarData", dlg.avatarData());
            m_db.saveSetting("avatarIsPhoto", dlg.isPhotoAvatar() ? "true" : "false");
        }
    }

    // ── Server + polling ──────────────────────────────────────────────────────
    // One-time migration: move existing users from the old HTTP IP to the new HTTPS domain
    {
        const QString old = m_db.loadSetting("serverUrl");
        if (old == "http://3.141.14.234" || old == "http://3.141.14.234/") {
            m_db.saveSetting("serverUrl", "https://peer2pear.com");
        }
    }
    const QString serverUrl = m_db.loadSetting("serverUrl", "https://peer2pear.com");
    m_controller.setServerBaseUrl(QUrl(serverUrl));

    // TURN relay for symmetric NAT fallback — configure before polling starts
    const QString turnHost = m_db.loadSetting("turnHost", "peer2pear.com");
    const int     turnPort = m_db.loadSetting("turnPort", "3478").toInt();
    const QString turnUser = m_db.loadSetting("turnUser", "peer2pear");
    const QString turnPass = m_db.loadSetting("turnPass", "peer2pear");
    if (!turnHost.isEmpty())
        m_controller.setTurnServer(turnHost, turnPort, turnUser, turnPass);

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
    m_settingsPanel->setProfileInfo(m_db.loadSetting("displayName"),
                                    m_controller.myIdB64u());
    m_settingsPanel->setDatabase(&m_db);
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
    connect(&m_controller, &ChatController::avatarReceived,
            m_chatView,    &ChatView::onAvatarReceived);
    connect(&m_controller, &ChatController::groupRenamed,
            m_chatView,    &ChatView::onGroupRenamed);
    connect(&m_controller, &ChatController::groupAvatarReceived,
            m_chatView,    &ChatView::onGroupAvatarReceived);

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
    connect(m_settingsPanel, &SettingsPanel::exportContactsClicked,
            this, &MainWindow::onExportContacts);
    connect(m_settingsPanel, &SettingsPanel::importContactsClicked,
            this, &MainWindow::onImportContacts);

    // Apply persisted notification state to the notifier
    m_notifier->setEnabled(m_settingsPanel->notificationsEnabled());

    // ── Resize debounce ───────────────────────────────────────────────────────
    m_resizeDebounce.setSingleShot(true);
    m_resizeDebounce.setInterval(100);
    connect(&m_resizeDebounce, &QTimer::timeout, this, [this]() {
        if (m_chatView) m_chatView->reloadCurrentChat();
    });
}

MainWindow::~MainWindow() {
    m_controller.stopPolling();   // unpublish presence so peers see us offline
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    m_resizeDebounce.start(); // coalesce rapid resize events
}

void MainWindow::onSettingsClicked()    { m_mainStack->setCurrentIndex(1); }
void MainWindow::onSettingsBackClicked(){ m_mainStack->setCurrentIndex(0); }

void MainWindow::onExportContacts()
{
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Contacts", "peer2pear_contacts.json",
        "JSON Files (*.json)");
    if (path.isEmpty()) return;

    const QVector<ChatData> contacts = m_db.loadAllContacts();

    QJsonArray arr;
    for (const auto &c : contacts) {
        if (c.isBlocked) continue; // never export blocked contacts
        QJsonObject obj;
        obj["name"] = c.name;
        obj["keys"] = QJsonArray::fromStringList(c.keys);
        arr.append(obj);
    }

    QJsonObject root;
    root["version"]  = 1;
    root["contacts"] = arr;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Export Failed",
                             "Could not write to:\n" + path);
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();

    QMessageBox::information(this, "Export Complete",
                             QString("Exported %1 contact(s).").arg(arr.size()));
}

void MainWindow::onImportContacts()
{
    const QString path = QFileDialog::getOpenFileName(
        this, "Import Contacts", QString(),
        "JSON Files (*.json)");
    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Import Failed",
                             "Could not read:\n" + path);
        return;
    }

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &err);
    file.close();

    if (doc.isNull()) {
        QMessageBox::warning(this, "Import Failed",
                             "Invalid JSON:\n" + err.errorString());
        return;
    }

    const QJsonObject root = doc.object();
    const QJsonArray  arr  = root["contacts"].toArray();
    if (arr.isEmpty()) {
        QMessageBox::information(this, "Import", "No contacts found in file.");
        return;
    }

    // Build a set of existing contact identifiers so we never overwrite them.
    // Contacts with a real peer ID use that; name-only contacts use "name:<name>".
    const QVector<ChatData> existing = m_db.loadAllContacts();
    QSet<QString> existingIds;
    for (const auto &e : existing) {
        if (!e.peerIdB64u.isEmpty())
            existingIds.insert(e.peerIdB64u);
        else if (!e.name.isEmpty())
            existingIds.insert(QLatin1String("name:") + e.name);
    }

    int imported = 0;
    for (const QJsonValue &v : arr) {
        const QJsonObject obj = v.toObject();

        ChatData chat;
        chat.name = obj["name"].toString().trimmed();
        const QJsonArray keysArr = obj["keys"].toArray();
        for (const QJsonValue &k : keysArr)
            chat.keys.append(k.toString());

        // Derive peerIdB64u from the first key when available.
        // In this app the first public key doubles as the peer identifier.
        if (!chat.keys.isEmpty())
            chat.peerIdB64u = chat.keys.first();

        // Skip entries with no name and no keys
        if (chat.name.isEmpty() && chat.keys.isEmpty())
            continue;

        // Determine the effective storage key (mirrors DatabaseManager::contactKey)
        const QString effectiveKey = chat.peerIdB64u.isEmpty()
            ? QLatin1String("name:") + chat.name
            : chat.peerIdB64u;

        // Skip if the contact already exists — never overwrite
        if (existingIds.contains(effectiveKey))
            continue;

        chat.subtitle = "Secure chat";
        m_db.saveContact(chat);
        existingIds.insert(effectiveKey); // prevent duplicates within the file
        ++imported;
    }

    // Reload the chat list so newly imported contacts appear
    if (m_chatView) m_chatView->initChats();

    QMessageBox::information(this, "Import Complete",
                             QString("Imported %1 contact(s).").arg(imported));
}
