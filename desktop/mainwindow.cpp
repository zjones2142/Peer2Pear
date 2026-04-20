#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "onboardingdialog.h"
#include "qt_interop.hpp"  // Qt↔std boundary helpers for CryptoEngine calls
#include "bytes_util.hpp"  // strBytes helper (Qt-free)

#include <QPixmap>
#include <QHBoxLayout>
#include <QSet>
#include <QStackedWidget>
#include <QTimer>
#include <QDateTime>
#include <QTimeZone>
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
    , m_controller(m_webSocket, m_httpClient, m_timerFactory)
{
    ui->setupUi(this);

    // ── Identity unlock ───────────────────────────────────────────────────────
    // Passphrase must be obtained BEFORE opening the DB so we can derive the
    // SQLCipher page-level encryption key via Argon2id.
    //
    // On first run the salt file doesn't exist yet — show a "create passphrase"
    // flow with a double-entry confirmation so a typo doesn't silently lock
    // the user out of an identity they can't recover.  On subsequent runs we
    // show a simple unlock prompt.
    const QString keysDirForCheck = QStandardPaths::writableLocation(
        QStandardPaths::AppDataLocation) + "/keys";

    while (true) {
        // Re-check each iteration so if a prior iteration partially succeeded
        // (e.g., salt got created but DB open failed), subsequent prompts
        // correctly use the unlock wording rather than the create wording.
        const bool firstRun = !QFile::exists(keysDirForCheck + "/db_salt.bin");

        bool ok = false;
        const QString title = firstRun ? "Create Passphrase" : "Unlock Identity";
        const QString prompt = firstRun
            ? QStringLiteral(
                "Welcome to Peer2Pear.\n\n"
                "Create a passphrase to protect your identity and local data.\n"
                "This passphrase cannot be recovered if you forget it \u2014 write it "
                "down somewhere safe.")
            : QStringLiteral(
                "Enter passphrase to unlock this device identity:");

        QString pass = QInputDialog::getText(this, title, prompt,
                                             QLineEdit::Password, "", &ok);
        if (!ok) { QTimer::singleShot(0, qApp, &QCoreApplication::quit); return; }
        if (pass.isEmpty()) {
            QMessageBox::warning(this, "Passphrase Required", "Passphrase cannot be empty.");
            continue;
        }

        // First-run: require double-entry.  A mismatched confirm is far cheaper
        // to recover from than a silent typo the user will never type again.
        if (firstRun) {
            QString confirm = QInputDialog::getText(this, "Confirm Passphrase",
                "Re-enter the passphrase to confirm:",
                QLineEdit::Password, "", &ok);
            if (!ok) {
                p2p::bridge::secureZeroQ(pass);
                QTimer::singleShot(0, qApp, &QCoreApplication::quit);
                return;
            }
            if (confirm != pass) {
                QMessageBox::warning(this, "Passphrases Don't Match",
                    "The two passphrases didn't match. Please try again.");
                p2p::bridge::secureZeroQ(pass);
                p2p::bridge::secureZeroQ(confirm);
                continue;
            }
            p2p::bridge::secureZeroQ(confirm);
        }
        try {
            // ── Unified key derivation (single Argon2id call) ────────────────
            const QString keysDir = QStandardPaths::writableLocation(
                QStandardPaths::AppDataLocation) + "/keys";
            QByteArray salt = p2p::bridge::toQByteArray(CryptoEngine::loadOrCreateSalt(
                (keysDir + "/db_salt.bin").toStdString()));
            if (salt.isEmpty()) {
                QMessageBox::critical(this, "Salt File Error",
                    "The encryption salt file is corrupt and no backup exists.\n"
                    "Your database cannot be decrypted.\n\n"
                    "Contact support or delete the app data directory to start fresh.");
                p2p::bridge::secureZeroQ(pass);
                QTimer::singleShot(0, qApp, &QCoreApplication::quit);
                return;
            }
            QByteArray masterKey = p2p::bridge::toQByteArray(CryptoEngine::deriveMasterKey(
                pass.toStdString(), p2p::bridge::toBytes(salt)));
            if (masterKey.isEmpty()) {
                QMessageBox::critical(this, "Key Derivation Failed",
                                      "Could not derive encryption key from passphrase.");
                p2p::bridge::secureZeroQ(pass);
                continue;
            }

            // Derive all purpose-specific subkeys from one master key
            using namespace p2p::bridge;
            QByteArray identityKey = toQByteArray(CryptoEngine::deriveSubkey(
                toBytes(masterKey), strBytes("identity-unlock")));
            QByteArray dbKey       = toQByteArray(CryptoEngine::deriveSubkey(
                toBytes(masterKey), strBytes("sqlcipher-db-key")));
            QByteArray fieldKey    = toQByteArray(CryptoEngine::deriveSubkey(
                toBytes(masterKey), strBytes("field-encryption")));
            p2p::bridge::secureZeroQ(masterKey);

            // ── Identity unlock (uses identityKey instead of separate Argon2) ─
            // setPassphrase(pass, identityKey) still needs pass for legacy v4
            // migration (deriveKeyFromPassphrase inside loadIdentityFromDisk).
            // Once migrated to v5, the passphrase is never used for identity.
            m_controller.setPassphrase(pass.toStdString(), p2p::bridge::toBytes(identityKey));
            p2p::bridge::secureZeroQ(identityKey);

            // ── Open DB with SQLCipher encryption ────────────────────────────
            if (!m_db.open(dbKey)) {
                QMessageBox::critical(this, "Database Error",
                                      "Could not open the local chat database.\n"
                                      "The passphrase may be incorrect.");
                p2p::bridge::secureZeroQ(dbKey);
                p2p::bridge::secureZeroQ(fieldKey);
                p2p::bridge::secureZeroQ(pass);
                continue;
            }
            p2p::bridge::secureZeroQ(dbKey);

            // Set per-field encryption key (backward compat with ENC: fields).
            // Legacy keys cover all previous key derivation generations:
            //   Gen 1: BLAKE2b(publicId + "peer2pear-dbkey")
            //   Gen 2: BLAKE2b(passphrase + "peer2pear-dbkey")
            // decryptField() tries the primary key first, then each legacy
            // key in order until one succeeds.
            // ChatController::blake2b256 now takes Bytes, not QByteArray — build
            // the legacy key inputs as byte vectors directly.
            auto bytesConcat = [](const std::string& a, const char* b) {
                Bytes out(a.begin(), a.end());
                out.insert(out.end(), b, b + std::strlen(b));
                return out;
            };
            QByteArray legacyGen1 = p2p::bridge::toQByteArray(ChatController::blake2b256(
                bytesConcat(m_controller.myIdB64u(), "peer2pear-dbkey")));
            QByteArray legacyGen2 = p2p::bridge::toQByteArray(ChatController::blake2b256(
                bytesConcat(pass.toStdString(), "peer2pear-dbkey")));
            m_db.setEncryptionKey(fieldKey, {legacyGen2, legacyGen1});
            p2p::bridge::secureZeroQ(fieldKey);
            p2p::bridge::secureZeroQ(legacyGen1);
            p2p::bridge::secureZeroQ(legacyGen2);

            // Wire DB to ChatController for Noise/Ratchet session persistence
            m_controller.setDatabase(m_db.database());

            // GAP5: restore persisted group sequence counters
            auto qMapToStd = [](const QMap<QString, qint64>& qm) {
                std::map<std::string, int64_t> out;
                for (auto it = qm.cbegin(); it != qm.cend(); ++it)
                    out.emplace(it.key().toStdString(), int64_t(it.value()));
                return out;
            };
            m_controller.setGroupSeqCounters(qMapToStd(m_db.loadGroupSeqOut()),
                                              qMapToStd(m_db.loadGroupSeqIn()));

            p2p::bridge::secureZeroQ(pass);
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
    // One-time migrations: rewrite stored relayUrl for users still pointing at
    // obsolete endpoints so they land on the current production relay without
    // having to wipe their local DB.
    {
        const QString old = m_db.loadSetting("relayUrl",
                                m_db.loadSetting("serverUrl")); // fallback to old key
        const bool staleIp      = (old == "http://3.141.14.234" ||
                                   old == "http://3.141.14.234/");
        const bool staleLocal   = (old == "http://localhost:8443" ||
                                   old == "http://localhost:8443/");
        if (staleIp || staleLocal) {
            m_db.saveSetting("relayUrl", "https://peer2pear.com");
        }
    }
    // Default for a fresh install: the production relay on peer2pear.com.
    // Users who self-host can override this via the settings table (no UI
    // yet — edit `SELECT value FROM settings WHERE key='relayUrl';` via
    // SQLCipher, or plumb in a Settings field).
    const QString relayUrl = m_db.loadSetting("relayUrl", "https://peer2pear.com");
    m_controller.setRelayUrl(relayUrl.toStdString());

#ifdef PEER2PEAR_P2P
    // TURN relay for symmetric NAT fallback — only meaningful when P2P is
    // compiled in.  setTurnServer() itself is declared behind the same flag.
    const QString turnHost = m_db.loadSetting("turnHost", "peer2pear.com");
    const int     turnPort = m_db.loadSetting("turnPort", "3478").toInt();
    const QString turnUser = m_db.loadSetting("turnUser", "peer2pear");
    const QString turnPass = m_db.loadSetting("turnPass", "peer2pear");
    if (!turnHost.isEmpty())
        m_controller.setTurnServer(turnHost.toStdString(), turnPort,
                                    turnUser.toStdString(), turnPass.toStdString());
#endif

    m_controller.connectToRelay();

    // ── Profile handle: first 8 chars of public key ───────────────────────────
    const QString fullKey = QString::fromStdString(m_controller.myIdB64u());
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
                                    QString::fromStdString(m_controller.myIdB64u()));
    m_settingsPanel->setDatabase(&m_db);
    m_mainStack->addWidget(m_settingsPanel);    // index 1 – settings

    rootLayout->addWidget(m_mainStack);

    // ── ChatView ──────────────────────────────────────────────────────────────
    m_chatView = new ChatView(ui, &m_controller, &m_db, this);

    m_chatView->setShouldToastFn([this]() -> bool {
        return isMinimized() || !isVisible() || !isActiveWindow();
    });

    // ── Wire callbacks ────────────────────────────────────────────────────────
    // ChatController is a plain class (Phase 7b); direct assignment replaces
    // QObject::connect.  The lambdas bounce into ChatView's slots, converting
    // std:: types to Qt at the boundary.  MainWindow owns both halves so
    // lifetimes match.
    //
    // Helpers for the std → Qt conversion.  Local lambdas so the intent is
    // obvious at each site.
    auto toQ  = [](const std::string& s) { return QString::fromStdString(s); };
    auto toQL = [](const std::vector<std::string>& v) {
        QStringList out;
        out.reserve(int(v.size()));
        for (const std::string& s : v) out << QString::fromStdString(s);
        return out;
    };
    auto toDT = [](int64_t secs) {
        return secs > 0
            ? QDateTime::fromSecsSinceEpoch(secs, QTimeZone::utc()).toLocalTime()
            : QDateTime::currentDateTime();
    };

    m_controller.onMessageReceived =
        [cv = m_chatView, toQ, toDT](const std::string& from, const std::string& text,
                                     int64_t tsSecs, const std::string& msgId) {
            cv->onIncomingMessage(toQ(from), toQ(text), toDT(tsSecs), toQ(msgId));
        };
    m_controller.onStatus =
        [cv = m_chatView, toQ](const std::string& s) { cv->onStatus(toQ(s)); };
    m_controller.onGroupMessageReceived =
        [cv = m_chatView, toQ, toQL, toDT](const std::string& from, const std::string& gid,
                                            const std::string& gn, const std::vector<std::string>& members,
                                            const std::string& text, int64_t tsSecs,
                                            const std::string& msgId) {
            cv->onIncomingGroupMessage(toQ(from), toQ(gid), toQ(gn), toQL(members),
                                        toQ(text), toDT(tsSecs), toQ(msgId));
        };
    m_controller.onGroupMemberLeft =
        [cv = m_chatView, toQ, toQL, toDT](const std::string& from, const std::string& gid,
                                            const std::string& gn, const std::vector<std::string>& members,
                                            int64_t tsSecs, const std::string& msgId) {
            cv->onGroupMemberLeft(toQ(from), toQ(gid), toQ(gn), toQL(members),
                                   toDT(tsSecs), toQ(msgId));
        };
    m_controller.onFileChunkReceived =
        [cv = m_chatView, toQ, toDT](const std::string& from, const std::string& tid,
                                     const std::string& fn, int64_t fsize,
                                     int rcvd, int total, const std::string& saved,
                                     int64_t tsSecs, const std::string& gid,
                                     const std::string& gn) {
            cv->onFileChunkReceived(toQ(from), toQ(tid), toQ(fn), fsize, rcvd, total,
                                     toQ(saved), toDT(tsSecs), toQ(gid), toQ(gn));
        };
    m_controller.onFileChunkSent =
        [cv = m_chatView, toQ, toDT](const std::string& to, const std::string& tid,
                                     const std::string& fn, int64_t fsize,
                                     int sent, int total, int64_t tsSecs,
                                     const std::string& gid, const std::string& gn) {
            cv->onFileChunkSent(toQ(to), toQ(tid), toQ(fn), fsize, sent, total,
                                 toDT(tsSecs), toQ(gid), toQ(gn));
        };
    m_controller.onPresenceChanged =
        [cv = m_chatView, toQ](const std::string& peerId, bool online) {
            cv->onPresenceChanged(toQ(peerId), online);
        };
    m_controller.onAvatarReceived =
        [cv = m_chatView, toQ](const std::string& peerId, const std::string& name,
                                const std::string& b64) {
            cv->onAvatarReceived(toQ(peerId), toQ(name), toQ(b64));
        };
    m_controller.onGroupRenamed =
        [cv = m_chatView, toQ](const std::string& gid, const std::string& newName) {
            cv->onGroupRenamed(toQ(gid), toQ(newName));
        };
    m_controller.onGroupAvatarReceived =
        [cv = m_chatView, toQ](const std::string& gid, const std::string& b64) {
            cv->onGroupAvatarReceived(toQ(gid), toQ(b64));
        };

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

    // Phase 2: file transfer consent settings → ChatController
    // ChatController isn't a QObject anymore, so route the SettingsPanel
    // signals through small lambdas that invoke the regular methods.
    connect(m_settingsPanel, &SettingsPanel::fileAutoAcceptMaxChanged,
            this, [this](int mb) { m_controller.setFileAutoAcceptMaxMB(mb); });
    connect(m_settingsPanel, &SettingsPanel::fileHardMaxChanged,
            this, [this](int mb) { m_controller.setFileHardMaxMB(mb); });
    connect(m_settingsPanel, &SettingsPanel::fileRequireP2PToggled,
            this, [this](bool on) { m_controller.setFileRequireP2P(on); });

    // Relay URL — settings UI can live-switch which relay we're connected
    // to.  Drop the existing WS, point the RelayClient at the new URL, and
    // kick off a fresh connect.  Presence is implicit in the WS so that
    // re-announces too; any pending envelopes the new relay has for us
    // arrive on reconnect via the server's deliver-on-auth path.
    connect(m_settingsPanel, &SettingsPanel::relayUrlChanged,
            this, [this](const QString &url) {
        m_controller.disconnectFromRelay();
        m_controller.setRelayUrl(url.toStdString());
        m_controller.connectToRelay();
    });

    // Privacy level — forwards to RelayClient, which toggles jitter,
    // cover traffic, and multi-hop onion routing accordingly.
    connect(m_settingsPanel, &SettingsPanel::privacyLevelChanged,
            this, [this](int level) {
        m_controller.relay().setPrivacyLevel(level);
    });

    // Safety numbers — hard-block on key change.
    connect(m_settingsPanel, &SettingsPanel::hardBlockOnKeyChangeToggled,
            this, [this](bool on) {
        m_controller.setHardBlockOnKeyChange(on);
    });

    // Surface safety-number mismatches as a status message + rebuild
    // the chat list so the warning badge appears next to the display
    // name.  UI will pick up details from peerTrust() on next render.
    m_controller.onPeerKeyChanged =
        [this, toQ](const std::string& peerId,
                    const Bytes& /*oldFp*/, const Bytes& /*newFp*/) {
        (void)peerId;
        if (m_chatView) m_chatView->refreshAfterKeyChange();
    };

    // Phase 2: file accept/decline prompt + cancel notifications → ChatView
    m_controller.onFileAcceptRequested =
        [cv = m_chatView, toQ](const std::string& from, const std::string& tid,
                                const std::string& fn, int64_t size) {
            cv->onFileAcceptRequested(toQ(from), toQ(tid), toQ(fn), size);
        };
    m_controller.onFileTransferCanceled =
        [cv = m_chatView, toQ](const std::string& tid, bool byReceiver) {
            cv->onFileTransferCanceled(toQ(tid), byReceiver);
        };

    // Phase 3: delivery confirmation + transport-policy block
    m_controller.onFileTransferDelivered =
        [cv = m_chatView, toQ](const std::string& tid) {
            cv->onFileTransferDelivered(toQ(tid));
        };
    m_controller.onFileTransferBlocked =
        [cv = m_chatView, toQ](const std::string& tid, bool byReceiver) {
            cv->onFileTransferBlocked(toQ(tid), byReceiver);
        };

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
    auto stdToQ = [](const std::map<std::string, int64_t>& m) {
        QMap<QString, qint64> out;
        for (const auto& kv : m)
            out.insert(QString::fromStdString(kv.first), qint64(kv.second));
        return out;
    };
    m_db.saveGroupSeqOut(stdToQ(m_controller.groupSeqOut()));
    m_db.saveGroupSeqIn(stdToQ(m_controller.groupSeqIn()));

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
