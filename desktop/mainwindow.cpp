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
#include <QStandardPaths>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // ── Identity unlock ───────────────────────────────────────────────────────
    // Passphrase must be obtained BEFORE opening the DB so we can derive the
    // SQLCipher page-level encryption key via Argon2id.
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
            // ── Unified key derivation (single Argon2id call) ────────────────
            const QString keysDir = QStandardPaths::writableLocation(
                QStandardPaths::AppDataLocation) + "/keys";
            QByteArray salt = CryptoEngine::loadOrCreateSalt(keysDir + "/db_salt.bin");
            if (salt.isEmpty()) {
                QMessageBox::critical(this, "Salt File Error",
                    "The encryption salt file is corrupt and no backup exists.\n"
                    "Your database cannot be decrypted.\n\n"
                    "Contact support or delete the app data directory to start fresh.");
                CryptoEngine::secureZero(pass);
                QTimer::singleShot(0, qApp, &QCoreApplication::quit);
                return;
            }
            QByteArray masterKey = CryptoEngine::deriveMasterKey(pass, salt);
            if (masterKey.isEmpty()) {
                QMessageBox::critical(this, "Key Derivation Failed",
                                      "Could not derive encryption key from passphrase.");
                CryptoEngine::secureZero(pass);
                continue;
            }

            // Derive all purpose-specific subkeys from one master key
            QByteArray identityKey = CryptoEngine::deriveSubkey(masterKey, "identity-unlock");
            QByteArray dbKey       = CryptoEngine::deriveSubkey(masterKey, "sqlcipher-db-key");
            QByteArray fieldKey    = CryptoEngine::deriveSubkey(masterKey, "field-encryption");
            CryptoEngine::secureZero(masterKey);

            // ── Identity unlock (uses identityKey instead of separate Argon2) ─
            // setPassphrase(pass, identityKey) still needs pass for legacy v4
            // migration (deriveKeyFromPassphrase inside loadIdentityFromDisk).
            // Once migrated to v5, the passphrase is never used for identity.
            m_controller.setPassphrase(pass, identityKey);
            CryptoEngine::secureZero(identityKey);

            // ── Open DB with SQLCipher encryption ────────────────────────────
            if (!m_db.open(dbKey)) {
                QMessageBox::critical(this, "Database Error",
                                      "Could not open the local chat database.\n"
                                      "The passphrase may be incorrect.");
                CryptoEngine::secureZero(dbKey);
                CryptoEngine::secureZero(fieldKey);
                CryptoEngine::secureZero(pass);
                continue;
            }
            CryptoEngine::secureZero(dbKey);

            // Set per-field encryption key (backward compat with ENC: fields).
            // Legacy keys cover all previous key derivation generations:
            //   Gen 1: BLAKE2b(publicId + "peer2pear-dbkey")
            //   Gen 2: BLAKE2b(passphrase + "peer2pear-dbkey")
            // decryptField() tries the primary key first, then each legacy
            // key in order until one succeeds.
            QByteArray legacyGen1 = ChatController::blake2b256(
                m_controller.myIdB64u().toUtf8() + QByteArray("peer2pear-dbkey"));
            QByteArray legacyGen2 = ChatController::blake2b256(
                pass.toUtf8() + QByteArray("peer2pear-dbkey"));
            m_db.setEncryptionKey(fieldKey, {legacyGen2, legacyGen1});
            CryptoEngine::secureZero(fieldKey);
            CryptoEngine::secureZero(legacyGen1);
            CryptoEngine::secureZero(legacyGen2);

            // Wire DB to ChatController for Noise/Ratchet session persistence
            m_controller.setDatabase(m_db.database());

            // GAP5: restore persisted group sequence counters
            m_controller.setGroupSeqCounters(m_db.loadGroupSeqOut(),
                                              m_db.loadGroupSeqIn());

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

        // ── Welcome guide (shown once after first onboarding) ────────────────
        QMessageBox welcome(this);
        welcome.setWindowTitle("Welcome to Peer2Pear");
        welcome.setIcon(QMessageBox::Information);
        welcome.setText(
            "<h3>You're all set!</h3>"
            "<p>Here's how to get started:</p>"
            "<ol>"
            "<li><b>Copy your public key</b> from Settings and share it with friends.</li>"
            "<li><b>Add a contact</b> by tapping New Chat and pasting their key.</li>"
            "<li><b>Send a message</b> — it's encrypted end-to-end automatically.</li>"
            "</ol>"
            "<p style='color:gray;'>You can find a full guide anytime in "
            "<b>Settings > About & Help</b>.</p>"
            );
        welcome.setStyleSheet(
            "QMessageBox { background-color: #1a1a1a; }"
            "QLabel { color: #cccccc; font-size: 13px; }"
            "QPushButton { background-color: #2e8b3a; color: white; border: none; "
            "border-radius: 6px; padding: 8px 20px; font-weight: bold; }"
            "QPushButton:hover { background-color: #38a844; }"
            );
        welcome.exec();
    }

    // ── Relay connection ─────────────────────────────────────────────────────
    // One-time migration: move existing users from the old HTTP IP to the new HTTPS domain
    {
        const QString old = m_db.loadSetting("relayUrl",
                                m_db.loadSetting("serverUrl")); // fallback to old key
        if (old == "http://3.141.14.234" || old == "http://3.141.14.234/") {
            m_db.saveSetting("relayUrl", "https://peer2pear.com");
        }
    }
    const QString relayUrl = m_db.loadSetting("relayUrl", "http://localhost:8443");
    m_controller.setRelayUrl(QUrl(relayUrl));

    // TURN relay for symmetric NAT fallback
    const QString turnHost = m_db.loadSetting("turnHost", "peer2pear.com");
    const int     turnPort = m_db.loadSetting("turnPort", "3478").toInt();
    const QString turnUser = m_db.loadSetting("turnUser", "peer2pear");
    const QString turnPass = m_db.loadSetting("turnPass", "peer2pear");
    if (!turnHost.isEmpty())
        m_controller.setTurnServer(turnHost, turnPort, turnUser, turnPass);

    m_controller.connectToRelay();

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
    m_controller.disconnectFromRelay();

    // GAP5: persist group sequence counters before shutdown
    m_db.saveGroupSeqOut(m_controller.groupSeqOut());
    m_db.saveGroupSeqIn(m_controller.groupSeqIn());

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
