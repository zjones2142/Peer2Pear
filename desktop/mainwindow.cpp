#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "dialogs.h"        // openArchivedChatsDialog
#include "onboardingdialog.h"
#include "passphrasedialog.h"
#include "lockoverlay.h"
#include "migrationsenddialog.h"
#include "migrationsettings.h"
#include "qt_interop.hpp"  // Qt↔std boundary helpers for CryptoEngine calls
#include "bytes_util.hpp"  // strBytes helper (Qt-free)
#include "peer2pear.h"     // P2P_MIN_PASSPHRASE_BYTES — single source of truth
#include "theme.h"         // ThemeManager — dark/light palette + global stylesheet
#include "theme_styles.h"  // tagChromeWidgets + reapplyForChildren
                            // with the C API; desktop uses ChatController
                            // directly, not the C API, but the constant is
                            // shared policy so we mirror it from here.

#include <QPixmap>
#include <QHBoxLayout>
#include <QSet>
#include <QStackedWidget>
#include <QTimer>
#include <QApplication>
#include <QSettings>
#include <QDateTime>
#include <QTimeZone>
#include <QDir>
#include <QFile>
#include <QInputDialog>
#include <QIODevice>
#include <QMessageBox>
#include <QLineEdit>
#include <QAction>
#include <QIcon>
#include <QSystemTrayIcon>
#include <QToolButton>
#include <QMenu>
#include <QWidgetAction>
#include <QFrame>
#include <QLabel>
#include <QClipboard>
#include <QDebug>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QStandardPaths>

#include <sodium.h>
#include <sqlite3.h>

namespace {

// Best-effort secure delete: overwrite + unlink.  Used by the legacy
// plaintext-DB migration to scrub the WAL/SHM and original .db before
// the encrypted copy takes its place.  On copy-on-write filesystems
// (APFS, btrfs) the overwrite isn't guaranteed to land on the same
// physical blocks, but the attempt is still worth more than nothing.
void secureRemoveFile(const QString &filePath)
{
    QFile f(filePath);
    if (!f.exists()) return;
    const qint64 sz = f.size();
    if (sz > 0 && f.open(QIODevice::WriteOnly)) {
        QByteArray noise(static_cast<int>(qMin(sz, qint64(1 << 20))), 0);
        qint64 remaining = sz;
        while (remaining > 0) {
            int chunk = static_cast<int>(qMin(remaining, qint64(noise.size())));
            randombytes_buf(reinterpret_cast<unsigned char*>(noise.data()),
                            static_cast<size_t>(chunk));
            f.write(noise.constData(), chunk);
            remaining -= chunk;
        }
        f.flush();
        f.close();
    }
    QFile::remove(filePath);
}

// One-shot legacy-plaintext → SQLCipher migration.  Returns true if the
// upgrade ran (or was unnecessary because the DB was already empty);
// false on failure or "DB is already encrypted" — both of which the
// caller treats as "fine, just open it normally."  Marker-file gated
// upstream so we don't probe the DB on every launch.
bool migratePlaintextDbToSqlCipher(const QString &dbPath, const QByteArray &dbKey)
{
    const QString encPath    = dbPath + ".encrypted";
    const QString backupPath = dbPath + ".backup";

    QFile::remove(encPath);
    QFile::remove(encPath + "-wal");
    QFile::remove(encPath + "-shm");
    if (QFile::exists(backupPath) && !QFile::exists(dbPath)) {
        qWarning() << "Migration: found orphaned .backup — restoring original DB";
        QFile::rename(backupPath, dbPath);
    }
    QFile::remove(backupPath);

    sqlite3* plainDb = nullptr;
    int rc = sqlite3_open_v2(dbPath.toUtf8().constData(), &plainDb,
                             SQLITE_OPEN_READWRITE, nullptr);
    if (rc != SQLITE_OK) {
        if (plainDb) sqlite3_close_v2(plainDb);
        return false;
    }
    sqlite3_exec(plainDb, "PRAGMA locking_mode=EXCLUSIVE;", nullptr, nullptr, nullptr);

    rc = sqlite3_exec(plainDb, "SELECT count(*) FROM sqlite_master;",
                      nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close_v2(plainDb);
        return false;  // Already encrypted (or corrupt) — nothing to migrate.
    }

    int tableCount = 0;
    sqlite3_stmt* countStmt = nullptr;
    if (sqlite3_prepare_v2(plainDb,
                           "SELECT count(*) FROM sqlite_master WHERE type='table';",
                           -1, &countStmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(countStmt) == SQLITE_ROW)
            tableCount = sqlite3_column_int(countStmt, 0);
        sqlite3_finalize(countStmt);
    }
    sqlite3_exec(plainDb, "PRAGMA wal_checkpoint(TRUNCATE);", nullptr, nullptr, nullptr);
    sqlite3_close_v2(plainDb);

    if (tableCount == 0) {
        QFile::remove(dbPath);
        QFile::remove(dbPath + "-wal");
        QFile::remove(dbPath + "-shm");
        return true;
    }

    SqlCipherDb encDb;
    Bytes dbKeyBytes(reinterpret_cast<const uint8_t*>(dbKey.constData()),
                                    reinterpret_cast<const uint8_t*>(dbKey.constData()) + dbKey.size());
    if (!encDb.open(encPath.toStdString(), dbKeyBytes)) {
        qWarning() << "Migration: failed to create encrypted DB";
        QFile::remove(encPath);
        return false;
    }

    QString escapedPlain = dbPath;
    escapedPlain.replace(QLatin1Char('\''), QLatin1String("''"));
    const QString attachSql = QStringLiteral(
        "ATTACH DATABASE '%1' AS plaintext KEY '';").arg(escapedPlain);

    char* err = nullptr;
    rc = sqlite3_exec(encDb.handle(), attachSql.toUtf8().constData(),
                      nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        sqlite3_free(err);
        encDb.close();
        QFile::remove(encPath);
        return false;
    }

    err = nullptr;
    rc = sqlite3_exec(encDb.handle(),
                      "SELECT sqlcipher_export('main', 'plaintext');",
                      nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        sqlite3_free(err);
        sqlite3_exec(encDb.handle(), "DETACH DATABASE plaintext;",
                     nullptr, nullptr, nullptr);
        encDb.close();
        QFile::remove(encPath);
        return false;
    }
    sqlite3_exec(encDb.handle(), "DETACH DATABASE plaintext;",
                 nullptr, nullptr, nullptr);
    encDb.close();

    if (!QFile::rename(dbPath, backupPath)) {
        QFile::remove(encPath);
        return false;
    }
    if (!QFile::rename(encPath, dbPath)) {
        QFile::rename(backupPath, dbPath);
        return false;
    }
    secureRemoveFile(dbPath + "-wal");
    secureRemoveFile(dbPath + "-shm");
    secureRemoveFile(backupPath);
    return true;
}

// Centralises the desktop's per-user app-data DB path + the legacy-
// plaintext migration check.  Caller (MainWindow::ctor) opens the
// SqlCipherDb after this returns, then binds an AppDataStore to it.
bool openAppDataDb(SqlCipherDb &db, const QByteArray &dbKey)
{
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(base);
    const QString dbPath = base + "/peer2PearUser.db";
    const QString migratedMarker = base + "/.sqlcipher_migrated";

    if (!dbKey.isEmpty() && QFile::exists(dbPath) && !QFile::exists(migratedMarker)) {
        migratePlaintextDbToSqlCipher(dbPath, dbKey);
        // Always write the marker after probing — success or "already
        // encrypted" both mean "don't probe again on next launch."
        QFile marker(migratedMarker);
        if (marker.open(QIODevice::WriteOnly)) marker.close();
    }

    Bytes dbKeyBytes(reinterpret_cast<const uint8_t*>(dbKey.constData()),
                                    reinterpret_cast<const uint8_t*>(dbKey.constData()) + dbKey.size());
    return db.open(dbPath.toStdString(), dbKeyBytes);
}

}  // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_wsFactory(this)
    , m_controller(m_wsFactory, m_httpClient, m_timerFactory)
{
    ui->setupUi(this);

    // Tag the .ui-defined chrome widgets with p2pRole properties so
    // subsequent theme flips can live-update them through the
    // theme_styles classifier.  applyTheme (wired via SettingsPanel's
    // themeChanged signal further below) then reapplies the palette +
    // walks centralwidget's children on every flip.
    themeStyles::tagChromeWidgets(this, ThemeManager::instance().current());
    connect(&ThemeManager::instance(), &ThemeManager::themeChanged,
            this, [this](const Theme& t) {
        themeStyles::tagChromeWidgets(this, t);
        if (centralWidget()) {
            themeStyles::reapplyForChildren(centralWidget(), t);
        }
    });

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

        PassphraseDialog dlg(firstRun ? PassphraseDialog::CreateNew
                                       : PassphraseDialog::Unlock,
                              this);
        const int dlgResult = dlg.exec();

        // Forgot Password recovery path: dialog already wiped the
        // app data directory + cleared QSettings.  Loop back to the
        // top - firstRun=true now, so the next iteration shows the
        // CreateNew branch and the user can start fresh.
        if (dlg.wasReset()) {
            continue;
        }

        // User picked "Transfer from another device".  Phase 2 hook:
        // dialog already showed a "Coming soon" message, didn't
        // accept().  Fall through with empty passphrase -> handle
        // like a cancel (quit).  Once the migration receiver lands,
        // branch into it here instead.
        if (dlg.wasTransferRequested() && dlg.passphrase().isEmpty()) {
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }

        // Plain dismissal - Cancel / X / Esc.  Quit cleanly so the
        // user doesn't end up at a half-initialised main window.
        if (dlgResult != QDialog::Accepted || dlg.passphrase().isEmpty()) {
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }

        // Migration arrived — stash the snapshot + settings on
        // MainWindow-scope buffers so a wrong-passphrase retry
        // loop doesn't lose them.  Files are already on disk;
        // user just needs to derive the right key.
        if (dlg.wasMigrationApplied()) {
            if (!dlg.pendingAppDataSnapshot().isEmpty()) {
                m_pendingMigrationSnapshot = dlg.pendingAppDataSnapshot();
            }
            if (!dlg.pendingUserDefaults().isEmpty()) {
                m_pendingMigrationSettings = dlg.pendingUserDefaults();
            }
        }

        QString pass = dlg.passphrase();
        // Enforce the same byte-length floor the core does in
        // p2p_set_passphrase_v2.  Surface the reason inline instead of
        // letting the core silently reject it a few lines down.  The
        // gate runs on both create + unlock so UX is consistent —
        // anyone with a shorter legacy passphrase would already be
        // unable to unlock via the core.
        if (pass.toUtf8().size() < P2P_MIN_PASSPHRASE_BYTES) {
            QMessageBox::warning(this, "Passphrase Too Short",
                QString("Passphrase must be at least %1 characters.")
                    .arg(P2P_MIN_PASSPHRASE_BYTES));
            p2p::bridge::secureZeroQ(pass);
            continue;
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
            // Once migrated, the passphrase is never used for identity.
            m_controller.setPassphrase(pass.toStdString(), p2p::bridge::toBytes(identityKey));
            p2p::bridge::secureZeroQ(identityKey);

            // ── Open DB with SQLCipher encryption ────────────────────────────
            if (!openAppDataDb(m_db, dbKey)) {
                QMessageBox::critical(this, "Database Error",
                                      "Could not open the local chat database.\n"
                                      "The passphrase may be incorrect.");
                p2p::bridge::secureZeroQ(dbKey);
                p2p::bridge::secureZeroQ(fieldKey);
                p2p::bridge::secureZeroQ(pass);
                continue;
            }
            p2p::bridge::secureZeroQ(dbKey);

            // Bind the app-data table layer to the handle.  Creates
            // contacts/messages/settings/file_transfers/group_seq_counters
            // tables on first run, idempotent on upgrade.
            m_store.bind(m_db);

            // Set per-field encryption key (backward compat with ENC: fields).
            // Legacy keys cover previous key derivation generations:
            //   Gen 1: BLAKE2b(publicId + "peer2pear-dbkey")
            //   Gen 2: BLAKE2b(passphrase + "peer2pear-dbkey")
            // decryptField() tries the primary key first, then each legacy
            // key in order until one succeeds.
            auto bytesConcat = [](const std::string& a, const char* b) {
                Bytes out(a.begin(), a.end());
                out.insert(out.end(), b, b + std::strlen(b));
                return out;
            };
            QByteArray legacyGen1 = p2p::bridge::toQByteArray(ChatController::blake2b256(
                bytesConcat(m_controller.myIdB64u(), "peer2pear-dbkey")));
            QByteArray legacyGen2 = p2p::bridge::toQByteArray(ChatController::blake2b256(
                bytesConcat(pass.toStdString(), "peer2pear-dbkey")));
            auto qbaToBytes = [](const QByteArray& b) -> Bytes {
                return Bytes(
                    reinterpret_cast<const uint8_t*>(b.constData()),
                    reinterpret_cast<const uint8_t*>(b.constData()) + b.size());
            };
            m_store.setEncryptionKey(qbaToBytes(fieldKey),
                                      {qbaToBytes(legacyGen2), qbaToBytes(legacyGen1)});
            p2p::bridge::secureZeroQ(fieldKey);
            p2p::bridge::secureZeroQ(legacyGen1);
            p2p::bridge::secureZeroQ(legacyGen2);

            // Wire DB to ChatController for Noise/Ratchet session persistence
            m_controller.setDatabase(m_db);

            // Hand the AppDataStore pointer to ChatController so the
            // GroupProtocol v2 receive path can persist its monotonic
            // counters, replay cache, and chain state.  Without this,
            // dispatchGroupMessageV2 logs "no AppDataStore wired" and
            // drops every inbound group message — m_store is already
            // bind()'d + keyed by this point.  iOS does the equivalent
            // call from peer2pear_api.cpp's p2p_set_passphrase_v2;
            // desktop missed it when GroupProtocol grew the
            // AppDataStore dependency.
            m_controller.setAppDataStore(&m_store);

            // Restore persisted group sequence counters — AppDataStore
            // returns std::map directly so no Qt-bridge conversion needed.
            m_controller.setGroupSeqCounters(m_store.loadGroupSeqOut(),
                                              m_store.loadGroupSeqIn());

            // If migration just landed an AppDataSnapshot, apply
            // it now — the DB is keyed + bound + the controller
            // sees the store, so bulk inserts are safe.  Apply
            // before recordVerifier / break so a partial-failure
            // log surfaces alongside the unlock progress, not
            // mid-chat-list-render.
            if (!m_pendingMigrationSnapshot.isEmpty()) {
                applyMigrationAppDataSnapshot(m_pendingMigrationSnapshot);
                m_pendingMigrationSnapshot.clear();
            }
            // Apply migrated settings (relayUrl, lockMode, theme,
            // etc.) — translates iOS UserDefaults keys to
            // desktop's m_store keys.  Must run BEFORE the
            // settingspanel.setAppDataStore() call further down
            // (line ~518) so the panel's initial-load picks up
            // the migrated values rather than the desktop
            // defaults.
            if (!m_pendingMigrationSettings.isEmpty()) {
                MigrationSettings::applySnapshot(
                    m_pendingMigrationSettings, m_store);
                m_pendingMigrationSettings = {};
            }

            // Cache the verifier so the lock overlay can re-unlock
            // without re-running Argon2id.  Mirrors iOS
            // OnboardingView's `client.recordVerifier(passphrase:)`
            // call after a successful start().
            recordVerifier(pass);

            p2p::bridge::secureZeroQ(pass);
            break;
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Identity Unlock Failed", e.what());
        }
    }

    // ── First-time onboarding ─────────────────────────────────────────────────
    if (m_store.loadSetting("displayName").empty()) {
        OnboardingDialog dlg(this);
        if (dlg.exec() != QDialog::Accepted) {
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }
        m_store.saveSetting("displayName", dlg.displayName().toStdString());
        if (!dlg.avatarData().isEmpty()) {
            m_store.saveSetting("avatarData", dlg.avatarData().toStdString());
            m_store.saveSetting("avatarIsPhoto",
                                 dlg.isPhotoAvatar() ? "true" : "false");
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
        const std::string old = m_store.loadSetting("relayUrl",
                                m_store.loadSetting("serverUrl")); // fallback to old key
        const bool staleIp      = (old == "http://3.141.14.234" ||
                                   old == "http://3.141.14.234/");
        const bool staleLocal   = (old == "http://localhost:8443" ||
                                   old == "http://localhost:8443/");
        if (staleIp || staleLocal) {
            m_store.saveSetting("relayUrl", "https://peer2pear.com");
        }
    }
    // Default for a fresh install: the production relay on peer2pear.com.
    // Users who self-host can override this via the settings table (no UI
    // yet — edit `SELECT value FROM settings WHERE key='relayUrl';` via
    // SQLCipher, or plumb in a Settings field).
    const std::string relayUrl = m_store.loadSetting("relayUrl", "https://peer2pear.com");
    m_controller.setRelayUrl(relayUrl);

#ifdef PEER2PEAR_P2P
    // TURN relay for symmetric NAT fallback — only meaningful when P2P is
    // compiled in.  setTurnServer() itself is declared behind the same flag.
    const std::string turnHost = m_store.loadSetting("turnHost", "peer2pear.com");
    int turnPort = 3478;
    try { turnPort = std::stoi(m_store.loadSetting("turnPort", "3478")); }
    catch (...) { turnPort = 3478; }
    const std::string turnUser = m_store.loadSetting("turnUser", "peer2pear");
    const std::string turnPass = m_store.loadSetting("turnPass", "peer2pear");
    if (!turnHost.empty())
        m_controller.setTurnServer(turnHost, turnPort, turnUser, turnPass);
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
    m_settingsPanel->setProfileInfo(qtbridge::qstr(m_store.loadSetting("displayName")),
                                    QString::fromStdString(m_controller.myIdB64u()));
    m_settingsPanel->setAppDataStore(&m_store);
    m_mainStack->addWidget(m_settingsPanel);    // index 1 – settings

    rootLayout->addWidget(m_mainStack);

    // ── Lock overlay ──────────────────────────────────────────────────────────
    // Parented to centralWidget() so it can cover both the chat
    // pane and the settings pane (different stack indexes).
    // Hidden on creation; shown on lock() via showLockOverlay().
    // Geometry tracks the centralWidget via resizeEvent +
    // showLockOverlay's setGeometry call.
    m_lockOverlay = new LockOverlay(centralWidget());
    m_lockOverlay->hide();
    connect(m_lockOverlay, &LockOverlay::unlockRequested,
            this, &MainWindow::quickUnlock);

    // ── ChatView ──────────────────────────────────────────────────────────────
    m_chatView = new ChatView(ui, &m_controller, &m_store, this);

    m_chatView->setShouldToastFn([this]() -> bool {
        return isMinimized() || !isVisible() || !isActiveWindow();
    });

    // ── Wire callbacks ────────────────────────────────────────────────────────
    // ChatController is a plain class; direct assignment replaces
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

    // pv=2 (Causally-Linked Pairwise) UX events.  See ChatView for
    // the banner / status surfaces on the receiving side.
    m_controller.onGroupStreamBlocked =
        [cv = m_chatView, toQ](const std::string& gid,
                                  const std::string& sender,
                                  int64_t fromCtr, int64_t toCtr) {
            cv->onGroupStreamBlocked(toQ(gid), toQ(sender), fromCtr, toCtr);
        };
    m_controller.onGroupMessagesLost =
        [cv = m_chatView, toQ](const std::string& gid,
                                  const std::string& sender,
                                  int64_t count) {
            cv->onGroupMessagesLost(toQ(gid), toQ(sender), count);
        };

    // ── Notifier ──────────────────────────────────────────────────────────────
    m_notifier = new ChatNotifier(this);
    m_chatView->setNotifier(m_notifier);

    // ── Connectivity indicator ───────────────────────────────────────────────
    // Mirror the iOS top-bar wifi icon: green when the relay
    // WebSocket is authenticated, red otherwise.  Click → popover
    // showing the relay URL + any user-configured backup relays.
    // Bound here (not earlier in init) because we need m_controller
    // wired AND the .ui's connectivityBtn to exist.
    m_controller.onRelayConnected =
        [this]() {
            // RelayClient's onConnected fires from its own thread;
            // marshal to the main thread via Qt's queued connection
            // so we can safely touch widgets.
            QMetaObject::invokeMethod(this, [this] {
                m_relayConnected = true;
                updateConnectivityIndicator();
            }, Qt::QueuedConnection);
        };
    m_controller.relay().onDisconnected =
        [this]() {
            QMetaObject::invokeMethod(this, [this] {
                m_relayConnected = false;
                updateConnectivityIndicator();
            }, Qt::QueuedConnection);
        };
    updateConnectivityIndicator();   // paint initial offline state
    connect(ui->connectivityBtn, &QToolButton::clicked,
            this, &MainWindow::showConnectivityPopover);

    // ── Settings ──────────────────────────────────────────────────────────────
    connect(ui->settingsBtn_12,  &QToolButton::clicked,
            this, &MainWindow::onSettingsClicked);
    connect(m_settingsPanel, &SettingsPanel::backClicked,
            this, &MainWindow::onSettingsBackClicked);
    connect(m_settingsPanel, &SettingsPanel::notificationsToggled,
            m_notifier,      &ChatNotifier::setEnabled);
    connect(m_settingsPanel, &SettingsPanel::notificationModeChanged,
            m_notifier,      &ChatNotifier::setContentMode);

    connect(m_settingsPanel, &SettingsPanel::exportContactsClicked,
            this, &MainWindow::onExportContacts);
    connect(m_settingsPanel, &SettingsPanel::importContactsClicked,
            this, &MainWindow::onImportContacts);

    // Archived Chats — opens the recovery dialog.  The dialog is
    // self-contained (reads + writes the store directly); we just
    // hand it the address-book snapshot for display-name resolution
    // and route the per-row action callback through ChatView so
    // m_chats / m_messagesByConv / etc. stay in sync.
    connect(m_settingsPanel, &SettingsPanel::archivedChatsClicked,
            this, [this]() {
        if (!m_chatView) return;
        dialogs::openArchivedChatsDialog(
            m_settingsPanel,
            &m_store,
            m_chatView->addressBookSnapshot(),
            [cv = m_chatView](const dialogs::ArchivedChatEvent &) {
                cv->reloadAfterArchiveAction();
            });
    });

    // Factory reset — wipe everything, quit.  SettingsPanel's button
    // already gated this behind a type-RESET-to-confirm dialog, so by
    // the time we get here the user has explicitly opted in.  Order:
    // close the DB → remove every file in the AppDataLocation dir
    // (keys/identity.json, peer2PearUser.db, .sqlcipher_migrated
    // marker, file_transfers/*, etc.) → wipe QSettings →
    // QApplication::quit().  User relaunches manually for a clean
    // first-run experience.
    connect(m_settingsPanel, &SettingsPanel::factoryResetClicked,
            this, [this]() {
        m_db.close();
        const QString base = QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation);
        if (!base.isEmpty()) {
            QDir d(base);
            if (d.exists()) d.removeRecursively();
        }
        QSettings().clear();
        QApplication::quit();
    });

    // Apply persisted notification state to the notifier.  Both the
    // global on/off and the content-privacy mode are mirrored from
    // whatever the DB restored — avoids a window between construction
    // and the first user toggle where banners could leak plaintext.
    m_notifier->setEnabled(m_settingsPanel->notificationsEnabled());
    m_notifier->setContentMode(m_settingsPanel->notificationMode());

    // File transfer consent settings → ChatController
    // ChatController isn't a QObject anymore, so route the SettingsPanel
    // signals through small lambdas that invoke the regular methods.
    connect(m_settingsPanel, &SettingsPanel::fileAutoAcceptMaxChanged,
            this, [this](int mb) { m_controller.setFileAutoAcceptMaxMB(mb); });
    connect(m_settingsPanel, &SettingsPanel::fileHardMaxChanged,
            this, [this](int mb) { m_controller.setFileHardMaxMB(mb); });
    connect(m_settingsPanel, &SettingsPanel::fileRequireP2PToggled,
            this, [this](bool on) { m_controller.setFileRequireP2P(on); });
    connect(m_settingsPanel, &SettingsPanel::fileRequireVerifiedToggled,
            this, [this](bool on) { m_chatView->setRequireVerifiedFiles(on); });

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

    // Independent transport dials — wire each directly to the
    // RelayClient toggle.  These let power users override the
    // preset's bundled choices without moving the privacy slider.
    connect(m_settingsPanel, &SettingsPanel::parallelFanOutToggled,
            this, [this](bool on) {
        m_controller.relay().setParallelFanOut(on);
    });
    connect(m_settingsPanel, &SettingsPanel::multiHopToggled,
            this, [this](bool on) {
        m_controller.relay().setMultiHopEnabled(on);
    });

    // Safety numbers — hard-block on key change.
    connect(m_settingsPanel, &SettingsPanel::hardBlockOnKeyChangeToggled,
            this, [this](bool on) {
        m_controller.setHardBlockOnKeyChange(on);
    });

    // ── Lock-mode wiring ─────────────────────────────────────────────────────
    // lockMode + autoLockMinutes are cached on SettingsPanel and
    // read on demand in lock() / onApplicationStateChanged via its
    // getters, so we don't observe lockModeChanged.  We DO observe
    // autoLockMinutesChanged so a longer/never threshold cancels
    // any timer armed against the older shorter value — otherwise
    // a stale fire would lock the user out mid-session.
    connect(m_settingsPanel, &SettingsPanel::autoLockMinutesChanged,
            this, [this](int /*mins*/) {
        m_autoLockTimer.stop();
    });
    connect(m_settingsPanel, &SettingsPanel::lockNowClicked,
            this, &MainWindow::lock);

    // ── Transfer to new device ──────────────────────────────────────────────
    // Receiver-side scaffolding lives behind the unlock-screen
    // PassphraseDialog (footer "Transfer from another device"
    // button); the SENDER side belongs in Settings on the
    // already-unlocked source device.  Reads identity files
    // straight from disk via the keys directory; the user has
    // already proven passphrase ownership by virtue of being
    // unlocked, so no extra prompt is needed here.
    connect(m_settingsPanel, &SettingsPanel::transferToNewDeviceClicked,
            this, [this]() {
        const QString keysDir = QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation) + "/keys";
        // Pre-build the snapshot + settings here (we have m_store
        // + SettingsPanel; the dialog doesn't).  Empty payloads
        // would degrade to identity-only migration; the receiver
        // tolerates either.
        const QByteArray snapshotJson = buildMigrationAppDataSnapshot();
        const QJsonObject userDefaults =
            MigrationSettings::buildSnapshotJson(m_store);
        MigrationSendDialog dlg(keysDir, snapshotJson,
                                  userDefaults, this);
        dlg.exec();
    });

    // QApplication::applicationStateChanged drives the auto-lock
    // timer.  Connected through qApp because it's an app-level
    // signal, not window-level.  Kicks the timer when the app
    // leaves Active and cancels it on return.
    connect(qApp, &QApplication::applicationStateChanged,
            this, &MainWindow::onApplicationStateChanged);

    m_autoLockTimer.setSingleShot(true);
    connect(&m_autoLockTimer, &QTimer::timeout,
            this, &MainWindow::onAutoLockTimerExpired);

    // Surface safety-number mismatches as a status message + rebuild
    // the chat list so the warning badge appears next to the display
    // name.  UI will pick up details from peerTrust() on next render.
    m_controller.onPeerKeyChanged =
        [this, toQ](const std::string& peerId,
                    const Bytes& /*oldFp*/, const Bytes& /*newFp*/) {
        (void)peerId;
        if (m_chatView) m_chatView->refreshAfterKeyChange();
    };

    // File accept/decline prompt + cancel notifications → ChatView
    m_controller.onFileAcceptRequested =
        [cv = m_chatView, toQ](const std::string& from, const std::string& tid,
                                const std::string& fn, int64_t size) {
            cv->onFileAcceptRequested(toQ(from), toQ(tid), toQ(fn), size);
        };
    m_controller.onFileTransferCanceled =
        [cv = m_chatView, toQ](const std::string& tid, bool byReceiver) {
            cv->onFileTransferCanceled(toQ(tid), byReceiver);
        };

    // Delivery confirmation + transport-policy block
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

    // ── System tray icon ──────────────────────────────────────────────────────
    // Stay-running-in-background pattern: closing the main window
    // hides it to the tray instead of quitting, so the relay
    // connection + ChatController stay live and inbound messages
    // keep arriving + posting notifications.  Same posture as
    // Slack / Discord / Element / Signal-desktop.  Real quit goes
    // through the tray menu's "Quit Peer2Pear" item or
    // QApplication::quit() (e.g. Cmd-Q on macOS, Alt-F4 on Linux
    // when the tray isn't available).
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        m_tray = new QSystemTrayIcon(this);
        // Resource icon falls back to the app's own window icon if
        // the asset isn't bundled (covers headless / first-run
        // builds where resources.qrc didn't pick up icons/).
        QIcon trayIcon(":/icons/peer2pear.png");
        if (trayIcon.isNull()) {
            trayIcon = windowIcon();
        }
        m_tray->setIcon(trayIcon);
        m_tray->setToolTip("Peer2Pear");

        auto *menu = new QMenu(this);
        QAction *showAct = menu->addAction("Show Peer2Pear");
        connect(showAct, &QAction::triggered,
                this, &MainWindow::showFromTray);

        QAction *lockAct = menu->addAction("Lock now");
        connect(lockAct, &QAction::triggered, this, [this]() {
            // Bring the window forward first so the user lands on
            // the lock overlay (or the unlock prompt after a
            // Strict-mode relaunch) instead of "the tray icon
            // changed but nothing else seems to have happened".
            showFromTray();
            lock();
        });

        menu->addSeparator();
        QAction *quitAct = menu->addAction("Quit Peer2Pear");
        connect(quitAct, &QAction::triggered, this, [this]() {
            // Mark the quit path so closeEvent below lets the
            // event through instead of hiding-to-tray.
            m_bypassHideToTray = true;
            close();   // triggers closeEvent → real quit
            qApp->quit();
        });

        m_tray->setContextMenu(menu);
        connect(m_tray, &QSystemTrayIcon::activated,
                this, &MainWindow::onTrayActivated);
        m_tray->show();
    }
}

MainWindow::~MainWindow() {
    m_controller.disconnectFromRelay();

    // Persist group sequence counters before shutdown.  AppDataStore
    // takes std::map natively so no Qt-bridge round-trip required.
    m_store.saveGroupSeqOut(m_controller.groupSeqOut());
    m_store.saveGroupSeqIn(m_controller.groupSeqIn());

    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    m_resizeDebounce.start(); // coalesce rapid resize events
    // Keep the lock overlay tracking the central widget's size so
    // resizing the window doesn't expose the chat behind it.
    if (m_isUILocked) updateLockOverlayGeometry();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // Without a tray icon (Linux desktop without status notifier,
    // headless test runner, etc.) there's nowhere to hide-to —
    // accept the close and let the app quit normally.
    if (!m_tray || m_bypassHideToTray) {
        QMainWindow::closeEvent(event);
        return;
    }

    // Hide-to-tray.  Stay-running posture so inbound messages keep
    // arriving + posting notifications while the window is closed.
    // First time only, surface a balloon explaining what just
    // happened so the user doesn't think we crashed.  QSettings
    // tracks the gate across launches.
    QSettings s;
    if (!s.value("ui.shownTrayHint", false).toBool()) {
        m_tray->showMessage(
            "Peer2Pear is still running",
            "Closing the window keeps the app in the tray so you "
            "still get messages.  Right-click the tray icon to "
            "fully quit.",
            QSystemTrayIcon::Information,
            6000);
        s.setValue("ui.shownTrayHint", true);
        m_shownTrayHint = true;
    }
    hide();
    event->ignore();
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    // macOS routes single-clicks on the status bar straight to
    // the context menu, so only Trigger (left click on Linux /
    // Windows) toggles visibility there.  DoubleClick remains a
    // common idiom on KDE / Windows — handle both.
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        showFromTray();
        break;
    default:
        break;
    }
}

void MainWindow::showFromTray()
{
    // raise() + activateWindow() because just calling show() on a
    // window that was minimised-then-hidden leaves it behind other
    // windows on some compositors (notably KWin).  isMinimized()
    // check restores from the dock too.
    if (isMinimized()) {
        showNormal();
    } else {
        show();
    }
    raise();
    activateWindow();
}

// ── Lock-mode plumbing ──────────────────────────────────────────────────────
// recordVerifier / verifyPassphrase use libsodium's SHA-256 to
// match iOS's CryptoKit.SHA256 byte-for-byte (same salt format,
// same hash construction).

namespace {
constexpr int kVerifierSaltBytes = 16;

QByteArray sha256Verifier(const QByteArray &salt, const QString &passphrase)
{
    const QByteArray passUtf8 = passphrase.toUtf8();
    QByteArray combined;
    combined.reserve(salt.size() + passUtf8.size());
    combined.append(salt);
    combined.append(passUtf8);
    QByteArray hash(crypto_hash_sha256_BYTES, '\0');
    crypto_hash_sha256(
        reinterpret_cast<unsigned char*>(hash.data()),
        reinterpret_cast<const unsigned char*>(combined.constData()),
        combined.size());
    return hash;
}
}  // namespace

void MainWindow::recordVerifier(const QString &passphrase)
{
    QByteArray salt(kVerifierSaltBytes, '\0');
    randombytes_buf(salt.data(), salt.size());
    m_verifierSalt = salt;
    m_verifierHash = sha256Verifier(salt, passphrase);
}

bool MainWindow::verifyPassphrase(const QString &passphrase) const
{
    if (m_verifierSalt.isEmpty() || m_verifierHash.isEmpty()) {
        return false;
    }
    const QByteArray candidate = sha256Verifier(m_verifierSalt, passphrase);
    // Constant-time compare so a timing leak doesn't turn the
    // verifier into a passphrase oracle.
    return sodium_memcmp(
        candidate.constData(), m_verifierHash.constData(),
        crypto_hash_sha256_BYTES) == 0;
}

void MainWindow::lock()
{
    if (!m_settingsPanel) return;   // unlock loop hasn't completed yet
    // SettingsPanel::lockMode() returns the cached parsed enum —
    // no SQLCipher round-trip on each call (unlike the earlier
    // m_store.loadSetting path).
    switch (m_settingsPanel->lockMode()) {
    case SettingsPanel::LockMode::Strict:
        // Full teardown on desktop = process exit.  Re-running the
        // app re-runs the unlock loop fresh.  Equivalent to iOS
        // .strict's "myPeerId="" + back to OnboardingView" since
        // both rebuild from a cold start.
        m_bypassHideToTray = true;
        qApp->quit();
        return;

    case SettingsPanel::LockMode::QuickWithEviction:
    case SettingsPanel::LockMode::Quick:
        // On desktop, Quick + QuickWithEviction land at the same
        // behavioural place: an opaque overlay covers the chat
        // pane (chat list + bubble area + composer) so neither
        // visual state nor pixel-level screen capture sees
        // plaintext.  iOS's eviction semantics — clearing the
        // SwiftUI @Published mirrors so the rendered view tree
        // doesn't hold message bodies — don't translate cleanly
        // to Qt's QWidget tree, which keeps content in widget
        // properties regardless of overlay z-order.  Properly
        // evicting on desktop would require destroying the chat
        // widgets and rebuilding from m_store on unlock — too
        // invasive for this phase.  The eviction setting still
        // round-trips with iOS via migration, and the option is
        // surfaced in Settings so users on cross-platform
        // accounts see consistent explainers.
        showLockOverlay();
        break;
    }

    m_isUILocked = true;
    // Cancel any pending auto-lock fire — we just locked manually
    // (or via the auto-lock timer itself); double-fire would be a
    // no-op but stop() avoids a stale timer ticking under us.
    m_autoLockTimer.stop();
}

void MainWindow::quickUnlock(const QString &passphrase)
{
    if (!m_isUILocked) return;
    if (!verifyPassphrase(passphrase)) {
        if (m_lockOverlay) m_lockOverlay->showWrongPassphrase();
        return;
    }
    m_isUILocked = false;
    hideLockOverlay();

    // QuickWithEviction cleared the visible buffer in lock(); the
    // overlay was over the chat-pane while it was reloading, so
    // calling reloadCurrentChat() again here is a no-op for that
    // mode and harmless for Quick mode.  Leaving it out so that
    // Quick mode (full mirror retained) doesn't pay an unnecessary
    // re-render on every unlock.
}

void MainWindow::showLockOverlay()
{
    if (!m_lockOverlay) return;
    m_lockOverlay->prepareForShow();
    updateLockOverlayGeometry();
    m_lockOverlay->raise();
    m_lockOverlay->show();
}

void MainWindow::hideLockOverlay()
{
    if (!m_lockOverlay) return;
    m_lockOverlay->hide();
}

void MainWindow::updateLockOverlayGeometry()
{
    if (!m_lockOverlay) return;
    if (auto *cw = centralWidget()) {
        m_lockOverlay->setGeometry(cw->rect());
    }
}

void MainWindow::onApplicationStateChanged(Qt::ApplicationState state)
{
    if (!m_settingsPanel) return;   // unlock loop hasn't completed yet
    const int autoLockMinutes = m_settingsPanel->autoLockMinutes();

    if (state == Qt::ApplicationActive) {
        // Coming back from background — cancel any armed timer so
        // it doesn't fire late once the window is foreground again.
        m_autoLockTimer.stop();
        return;
    }

    // Any other state means the window isn't the user-focused
    // surface (Suspended on macOS when minimised, Hidden on
    // Linux/Windows when minimised or behind another window).
    // Don't lock if already locked — re-arming would just push
    // the timer out further with no behavioural change.
    if (m_isUILocked) return;

    if (autoLockMinutes < 0) {
        // -1 = never; user opted out of idle locking.
        return;
    }
    if (autoLockMinutes == 0) {
        // Lock immediately on backgrounding — banking-app posture
        // even within the chosen mode.
        lock();
        return;
    }

    m_autoLockTimer.start(autoLockMinutes * 60 * 1000);
}

void MainWindow::onAutoLockTimerExpired()
{
    if (m_isUILocked) return;          // raced with a manual lock
    if (isActiveWindow()) return;       // user came back; race-safe
    lock();
}

// ── Migration snapshot build / apply ───────────────────────────────────────
// Wire format matches iOS `MigrationAppDataSnapshot` v1
// (ios/Peer2Pear/Sources/Migration/MigrationAppDataSnapshot.swift):
//
//   { "version": 1,
//     "contacts": [{peerId, name, subtitle, avatarB64, muted, lastActiveSecs}, ...],
//     "conversations": [{id, kind, directPeerId, groupName, groupAvatarB64,
//                         muted, lastActiveSecs, inChatList}, ...],
//     "conversationMembers": [{conversationId, peerIds: [...]}, ...],
//     "messages": [{conversationId, message: {sent, text, timestampSecs,
//                                              msgId, senderId, senderName,
//                                              sendFailed}}, ...],
//     "blockedKeys": ["peerId", ...] }
//
// Cross-platform: emitted byte-identically on iOS + desktop senders;
// accepted byte-identically on iOS + desktop receivers.

QByteArray MainWindow::buildMigrationAppDataSnapshot() const
{
    QJsonObject out;
    out.insert("version", 1);

    QJsonArray contactsArr;
    m_store.loadAllContacts([&](const AppDataStore::Contact &c) {
        QJsonObject o;
        o.insert("peerId",         QString::fromStdString(c.peerIdB64u));
        o.insert("name",           QString::fromStdString(c.name));
        o.insert("subtitle",       QString::fromStdString(c.subtitle));
        o.insert("avatarB64",      QString::fromStdString(c.avatarB64));
        o.insert("muted",          c.muted);
        o.insert("lastActiveSecs", static_cast<qint64>(c.lastActiveSecs));
        contactsArr.append(o);
    });
    out.insert("contacts", contactsArr);

    // Conversations + members snapshot in one walk: collect rows
    // first, then walk the group rows again to fetch their member
    // rosters.  Two-pass since loadConversationMembers can't run
    // inside loadAllConversations' callback (potential cursor reuse).
    std::vector<AppDataStore::Conversation> convList;
    m_store.loadAllConversations([&](const AppDataStore::Conversation &c) {
        convList.push_back(c);
    });

    QJsonArray convArr;
    QJsonArray membersArr;
    for (const auto &c : convList) {
        QJsonObject o;
        o.insert("id",             QString::fromStdString(c.id));
        o.insert("kind",
                  c.kind == AppDataStore::ConversationKind::Group
                  ? "group" : "direct");
        o.insert("directPeerId",   QString::fromStdString(c.directPeerId));
        o.insert("groupName",      QString::fromStdString(c.groupName));
        o.insert("groupAvatarB64", QString::fromStdString(c.groupAvatarB64));
        o.insert("muted",          c.muted);
        o.insert("lastActiveSecs", static_cast<qint64>(c.lastActiveSecs));
        o.insert("inChatList",     c.inChatList);
        convArr.append(o);

        if (c.kind == AppDataStore::ConversationKind::Group) {
            QJsonArray peersArr;
            m_store.loadConversationMembers(c.id,
                [&](const std::string &peerId) {
                    peersArr.append(QString::fromStdString(peerId));
                });
            QJsonObject m;
            m.insert("conversationId", QString::fromStdString(c.id));
            m.insert("peerIds",        peersArr);
            membersArr.append(m);
        }
    }
    out.insert("conversations",       convArr);
    out.insert("conversationMembers", membersArr);

    QJsonArray msgsArr;
    for (const auto &c : convList) {
        m_store.loadMessages(c.id, [&](const AppDataStore::Message &m) {
            QJsonObject mo;
            mo.insert("sent",          m.sent);
            mo.insert("text",          QString::fromStdString(m.text));
            mo.insert("timestampSecs", static_cast<qint64>(m.timestampSecs));
            mo.insert("msgId",         QString::fromStdString(m.msgId));
            mo.insert("senderId",      QString::fromStdString(m.senderId));
            mo.insert("senderName",    QString::fromStdString(m.senderName));
            mo.insert("sendFailed",    m.sendFailed);
            QJsonObject row;
            row.insert("conversationId", QString::fromStdString(c.id));
            row.insert("message",        mo);
            msgsArr.append(row);
        });
    }
    out.insert("messages", msgsArr);

    QJsonArray blockedArr;
    m_store.loadAllBlockedKeys(
        [&](const std::string &peerId, int64_t /*blockedAt*/) {
            blockedArr.append(QString::fromStdString(peerId));
        });
    out.insert("blockedKeys", blockedArr);

    return QJsonDocument(out).toJson(QJsonDocument::Compact);
}

bool MainWindow::applyMigrationAppDataSnapshot(const QByteArray &snapshotJson)
{
    QJsonParseError perr{};
    const QJsonDocument doc = QJsonDocument::fromJson(snapshotJson, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        QMessageBox::warning(this, "Migration Apply Failed",
            QStringLiteral("Migrated data is malformed: %1.  Your "
                            "identity was migrated but chat history "
                            "couldn't be restored.").arg(perr.errorString()));
        return false;
    }
    const QJsonObject root = doc.object();
    if (root.value("version").toInt(-1) != 1) {
        QMessageBox::warning(this, "Migration Apply Failed",
            "Migrated data uses an incompatible format.  Your "
            "identity was migrated but chat history couldn't be "
            "restored.  Update both devices to the same Peer2Pear "
            "release and try again.");
        return false;
    }

    int firstFailureRows = 0;
    QString firstFailureStage;
    auto recordFailure = [&](const char *stage) {
        ++firstFailureRows;
        if (firstFailureStage.isEmpty()) firstFailureStage = stage;
    };

    // 1. Conversations FIRST — messages + members FK off of them.
    for (const QJsonValue &v : root.value("conversations").toArray()) {
        const QJsonObject o = v.toObject();
        AppDataStore::Conversation c;
        c.id           = o.value("id").toString().toStdString();
        c.kind         = (o.value("kind").toString() == "group")
                         ? AppDataStore::ConversationKind::Group
                         : AppDataStore::ConversationKind::Direct;
        c.directPeerId   = o.value("directPeerId").toString().toStdString();
        c.groupName      = o.value("groupName").toString().toStdString();
        c.groupAvatarB64 = o.value("groupAvatarB64").toString().toStdString();
        c.muted          = o.value("muted").toBool(false);
        c.lastActiveSecs = static_cast<int64_t>(
            o.value("lastActiveSecs").toVariant().toLongLong());
        c.inChatList     = o.value("inChatList").toBool(true);
        if (!m_store.saveConversation(c)) recordFailure("conversations");
    }

    // 2. Conversation members (group rosters).
    for (const QJsonValue &v : root.value("conversationMembers").toArray()) {
        const QJsonObject o = v.toObject();
        const std::string convId = o.value("conversationId").toString().toStdString();
        std::vector<std::string> peers;
        for (const QJsonValue &p : o.value("peerIds").toArray()) {
            peers.push_back(p.toString().toStdString());
        }
        if (!m_store.setConversationMembers(convId, peers)) {
            recordFailure("conversation_members");
        }
    }

    // 3. Contacts.
    for (const QJsonValue &v : root.value("contacts").toArray()) {
        const QJsonObject o = v.toObject();
        AppDataStore::Contact c;
        c.peerIdB64u     = o.value("peerId").toString().toStdString();
        c.name           = o.value("name").toString().toStdString();
        c.subtitle       = o.value("subtitle").toString().toStdString();
        c.avatarB64      = o.value("avatarB64").toString().toStdString();
        c.muted          = o.value("muted").toBool(false);
        c.lastActiveSecs = static_cast<int64_t>(
            o.value("lastActiveSecs").toVariant().toLongLong());
        if (!m_store.saveContact(c)) recordFailure("contacts");
    }

    // 4. Blocked keys — desktop's addBlockedKey takes a timestamp
    //    that iOS doesn't carry on the wire.  Use 0 ("blocked at
    //    unknown time") rather than fabricating "now" — it doesn't
    //    affect the runtime block check, only the display order
    //    in any future "blocked" picker.
    for (const QJsonValue &v : root.value("blockedKeys").toArray()) {
        const std::string peerId = v.toString().toStdString();
        if (!m_store.addBlockedKey(peerId, /*whenSecs=*/0)) {
            recordFailure("blocked_keys");
        }
    }

    // 5. Messages last (bulkiest).  Per-row failures are counted
    //    but don't abort the whole apply — partial history beats
    //    none for the user.
    for (const QJsonValue &v : root.value("messages").toArray()) {
        const QJsonObject row = v.toObject();
        const std::string convId =
            row.value("conversationId").toString().toStdString();
        const QJsonObject mo = row.value("message").toObject();
        AppDataStore::Message m;
        m.sent          = mo.value("sent").toBool(false);
        m.text          = mo.value("text").toString().toStdString();
        m.timestampSecs = static_cast<int64_t>(
            mo.value("timestampSecs").toVariant().toLongLong());
        m.msgId         = mo.value("msgId").toString().toStdString();
        m.senderId      = mo.value("senderId").toString().toStdString();
        m.senderName    = mo.value("senderName").toString().toStdString();
        m.sendFailed    = mo.value("sendFailed").toBool(false);
        if (!m_store.saveMessage(convId, m)) recordFailure("messages");
    }

    // ChatView reload happens later in the constructor flow after
    // m_chatView is constructed + wired (it's not built yet at the
    // moment apply runs).  buildChatList in ChatView's existing
    // construction path naturally picks up the migrated rows.

    if (firstFailureRows > 0) {
        QMessageBox::warning(this, "Migration partially applied",
            QStringLiteral("Some migrated data couldn't be written "
                            "(first failure: %1; %2 rows total).  "
                            "Your identity is in place; you may see "
                            "missing chat history.")
                .arg(firstFailureStage)
                .arg(firstFailureRows));
    }
    return true;
}

void MainWindow::onSettingsClicked()    { m_mainStack->setCurrentIndex(1); }
void MainWindow::onSettingsBackClicked(){ m_mainStack->setCurrentIndex(0); }

void MainWindow::onExportContacts()
{
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Contacts", "peer2pear_contacts.json",
        "JSON Files (*.json)");
    if (path.isEmpty()) return;

    const std::string json = m_store.exportContactsJson();

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Export Failed",
                             "Could not write to:\n" + path);
        return;
    }
    file.write(QByteArray::fromStdString(json));
    file.close();

    QMessageBox::information(this, "Export Complete", "Contacts exported.");
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
    const QByteArray bytes = file.readAll();
    file.close();

    const int imported = m_store.importContactsJson(
        std::string(bytes.constData(), static_cast<size_t>(bytes.size())));
    if (imported < 0) {
        QMessageBox::warning(this, "Import Failed", "Invalid JSON.");
        return;
    }

    // Reload the chat list so newly imported contacts appear
    if (m_chatView) m_chatView->initChats();

    QMessageBox::information(this, "Import Complete",
                             QString("Imported %1 contact(s).").arg(imported));
}

// ── Connectivity indicator ──────────────────────────────────────────────────
//
// Top-bar 📡 button.  Mirrors iOS's wifi-icon connectivity popover
// (ChatListView.swift::ConnectivityPopover) — at-a-glance signal of
// whether the relay WS is up + which relay we're talking to.
//
// State source: m_relayConnected, flipped by the
// onRelayConnected / onDisconnected lambdas wired in the init
// path.  Both lambdas marshal to the main thread before touching
// the widget.

void MainWindow::updateConnectivityIndicator()
{
    if (!ui || !ui->connectivityBtn) return;
    // Background-tinted circle around the icon — green when
    // connected, red when offline.  Pure stylesheet so it lives
    // in the .ui's theming surface, not in code-as-strings.
    const QString styleConnected =
        "QToolButton#connectivityBtn { background-color: #1a2e1c; "
        "color: #5dd868; border: 1px solid #2e5e30; "
        "border-radius: 18px; font-size: 18px; }"
        "QToolButton#connectivityBtn:hover { background-color: #223a24; }";
    const QString styleOffline =
        "QToolButton#connectivityBtn { background-color: #2e1a1a; "
        "color: #d85d5d; border: 1px solid #5e2e2e; "
        "border-radius: 18px; font-size: 18px; }"
        "QToolButton#connectivityBtn:hover { background-color: #3a2222; }";
    ui->connectivityBtn->setStyleSheet(
        m_relayConnected ? styleConnected : styleOffline);
    ui->connectivityBtn->setToolTip(
        m_relayConnected
            ? QStringLiteral("Connected — click for relay details")
            : QStringLiteral("Offline — click for relay details"));
}

void MainWindow::showConnectivityPopover()
{
    // Build a small QFrame card with the same shape as iOS's
    // popover: status header + relay URL + (optional) backup
    // relays.  Hosted inside a QMenu so QFocus / outside-click
    // dismissal works for free; the QMenu itself is invisible
    // (no background, just the embedded card).

    auto *frame = new QFrame;
    frame->setObjectName("connectivityCard");
    frame->setStyleSheet(
        "QFrame#connectivityCard { background-color: #141414; "
        "border: 1px solid #2a2a2a; border-radius: 10px; }"
        "QLabel { color: #f0f0f0; }"
        "QLabel#statusLabel { font-size: 15px; font-weight: bold; }"
        "QLabel#relayHeader { color: #888888; font-size: 11px; "
        "letter-spacing: 0.5px; }"
        "QLabel#relayUrl { font-family: monospace; font-size: 12px; "
        "color: #cccccc; }");

    auto *layout = new QVBoxLayout(frame);
    layout->setContentsMargins(14, 12, 14, 12);
    layout->setSpacing(8);

    // Status header — emoji + bold "Connected" or "Offline".
    auto *status = new QLabel(
        m_relayConnected
            ? QStringLiteral("🟢  Connected")
            : QStringLiteral("🔴  Offline"));
    status->setObjectName("statusLabel");
    status->setStyleSheet(
        QStringLiteral("color: %1; font-size: 15px; font-weight: bold;")
            .arg(m_relayConnected ? "#5dd868" : "#d85d5d"));
    layout->addWidget(status);

    // Thin divider.
    auto *div = new QFrame;
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("color: #2a2a2a; background-color: #2a2a2a;");
    div->setFixedHeight(1);
    layout->addWidget(div);

    // Primary relay row.
    auto *relayHeader = new QLabel(QStringLiteral("RELAY"));
    relayHeader->setObjectName("relayHeader");
    layout->addWidget(relayHeader);

    const QString primaryUrl = QString::fromStdString(
        m_store.loadSetting("relayUrl", "https://peer2pear.com"));
    auto *relayUrl = new QLabel(primaryUrl);
    relayUrl->setObjectName("relayUrl");
    relayUrl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    relayUrl->setWordWrap(true);
    layout->addWidget(relayUrl);

    // Backup relays — only render the section when there are any.
    // Stored in the settings table under "backupRelayUrls" as
    // newline-delimited URLs.  Currently no desktop UI writes this
    // key (iOS uses UserDefaults), so the section won't appear in
    // practice yet — but the read path is here for cross-platform
    // parity once a Settings → Backup Relays UI lands on desktop.
    const QString backupRaw = QString::fromStdString(
        m_store.loadSetting("backupRelayUrls", ""));
    QStringList backups;
    for (const QString& u :
            backupRaw.split('\n', Qt::SkipEmptyParts)) {
        const QString t = u.trimmed();
        if (!t.isEmpty()) backups.push_back(t);
    }
    if (!backups.isEmpty()) {
        auto *backupHeader = new QLabel(QStringLiteral("BACKUP RELAYS"));
        backupHeader->setObjectName("relayHeader");
        backupHeader->setStyleSheet(
            "color: #888888; font-size: 11px; "
            "letter-spacing: 0.5px; padding-top: 4px;");
        layout->addWidget(backupHeader);
        for (const QString& b : backups) {
            auto *bl = new QLabel(b);
            bl->setObjectName("relayUrl");
            bl->setTextInteractionFlags(Qt::TextSelectableByMouse);
            bl->setWordWrap(true);
            layout->addWidget(bl);
        }
    }

    frame->setMinimumWidth(280);
    frame->setMaximumWidth(360);

    // Mount in a QMenu so dismissal-on-outside-click is free.
    auto *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);
    auto *action = new QWidgetAction(menu);
    action->setDefaultWidget(frame);
    menu->addAction(action);

    // Position below + right-aligned with the button so the
    // popover anchors visually to its trigger.
    if (ui && ui->connectivityBtn) {
        const QPoint anchor = ui->connectivityBtn->mapToGlobal(
            QPoint(0, ui->connectivityBtn->height() + 4));
        menu->popup(anchor);
    } else {
        menu->popup(QCursor::pos());
    }
}
