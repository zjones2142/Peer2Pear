#include "settingspanel.h"
#include "AppDataStore.hpp"
#include "qt_str_helpers.hpp"
#include "theme.h"
#include "theme_styles.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
#include <QInputDialog>
#include <QLineEdit>
#include <QTimer>

// ── SettingsPanel ─────────────────────────────────────────────────────────────

SettingsPanel::SettingsPanel(QWidget *parent)
    : QWidget(parent)
{
    buildUI();
    // Re-style on theme change.  Cheap (single findChildren walk) and
    // also refreshes the appearance-picker button highlights.
    connect(&ThemeManager::instance(), &ThemeManager::themeChanged,
            this, [this](const Theme&) {
                applyThemeStyles();
                applyThemeButtonStyles();
            });
}

void SettingsPanel::buildUI()
{
    setObjectName("settingsPanel");
    setStyleSheet("QWidget#settingsPanel { background-color: #0d0d0d; }");

    QVBoxLayout *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // ── Top bar ───────────────────────────────────────────────────────────────
    QWidget *settingsHeader = new QWidget();
    // settingsHeader objectName drives the inline #settingsHeader sheet
    // below; p2pRole is what applyThemeStyles keys on for re-styling.
    settingsHeader->setObjectName("settingsHeader");
    settingsHeader->setProperty("p2pRole", "headerBar");
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
    themeStyles::applyRole(backBtn, "backBtn",
        themeStyles::backBtnCss(ThemeManager::instance().current()));

    QLabel *titleLabel = new QLabel("Settings");
    titleLabel->setProperty("p2pRole", "headerTitle");
    titleLabel->setStyleSheet("color: #ffffff; font-size: 16px; font-weight: bold;");

    headerLayout->addWidget(backBtn);
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();

    connect(backBtn, &QPushButton::clicked, this, &SettingsPanel::backClicked);

    // ── Scrollable body ───────────────────────────────────────────────────────
    QScrollArea *scroll = new QScrollArea();
    scroll->setProperty("p2pRole", "scroll");
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet("background-color: #0d0d0d; border: none;");

    QWidget *body = new QWidget();
    body->setProperty("p2pRole", "body");
    body->setStyleSheet("background-color: #0d0d0d;");
    QVBoxLayout *bodyLayout = new QVBoxLayout(body);
    bodyLayout->setContentsMargins(32, 24, 32, 24);
    bodyLayout->setSpacing(24);

    // ── Profile section ───────────────────────────────────────────────────────
    bodyLayout->addWidget(makeProfileSection());

    // ── Notifications section (interactive) ───────────────────────────────────
    bodyLayout->addWidget(makeNotificationsSection());

    // ── Data section (import / export) ──────────────────────────────────────
    bodyLayout->addWidget(makeDataSection());

    // ── File transfer settings ──────────────────────────────────────────────
    bodyLayout->addWidget(makeFileTransferSection());

    // ── Relay (network) settings ───────────────────────────────────────────
    bodyLayout->addWidget(makeRelaySection());

    // ── Privacy level ───────────────────────────────────────────────────────
    bodyLayout->addWidget(makePrivacySection());

    // ── Appearance (theme) ─────────────────────────────────────────────────
    bodyLayout->addWidget(makeAppearanceSection());

    // ── Archived Chats (recovery) ──────────────────────────────────────────
    // Sits between Appearance and About because it's a data-management
    // action — the user gets here when they realise they hid a chat and
    // want it back.  Empty most of the time; one-row card stays compact.
    bodyLayout->addWidget(makeArchivedChatsSection());

    // ── About section ─────────────────────────────────────────────────────────
    // Version    = app version (matches project(Peer2Pear VERSION ...) in CMakeLists.txt)
    // Protocol   = wire-protocol version (matches the relay's /healthz "version" field
    //              so interop can be reasoned about across client/server pairs)
    bodyLayout->addWidget(makeSection("ABOUT", {
                                                { "Version",  "0.2.0" },
                                                { "Protocol", "2.0.0" },
                                                }));

    // ── Getting Started / Help section ───────────────────────────────────────
    bodyLayout->addWidget(makeAboutHelpSection());

    // ── Factory Reset (always at the bottom) ─────────────────────────────────
    bodyLayout->addWidget(makeFactoryResetSection());

    bodyLayout->addStretch();
    scroll->setWidget(body);

    outerLayout->addWidget(settingsHeader);
    outerLayout->addWidget(scroll);

    // Final pass: every widget tagged with a p2pRole property gets its
    // stylesheet rewritten from the active Theme.  Inline stylesheets
    // set above are still emitted but get overwritten by this call,
    // which becomes important the first time the user flips Light mode.
    applyThemeStyles();
}

// Builds the Profile section card with display name and public key + copy button
QWidget *SettingsPanel::makeProfileSection()
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
    QLabel *heading = new QLabel("PROFILE");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);
    // ── Display Name row ──────────────────────────────────────────────────────
    QWidget *nameRow = new QWidget();
    nameRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *nl = new QHBoxLayout(nameRow);
    nl->setContentsMargins(16, 10, 16, 10);
    nl->setSpacing(8);
    QLabel *nameKey = new QLabel("Display Name");
    nameKey->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_displayNameLabel = new QLabel("—");
    m_displayNameLabel->setStyleSheet(
        "color: #555555; font-size: 13px; background: transparent; border: none;"
        );
    m_displayNameLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    nl->addWidget(nameKey);
    nl->addStretch();
    nl->addWidget(m_displayNameLabel);
    cardLayout->addWidget(nameRow);
    // Divider
    QFrame *div = new QFrame();
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet(
        "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
        );
    cardLayout->addWidget(div);
    // ── Public Key row ────────────────────────────────────────────────────────
    QWidget *keyRow = new QWidget();
    keyRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *kl = new QHBoxLayout(keyRow);
    kl->setContentsMargins(16, 10, 16, 10);
    kl->setSpacing(8);
    QLabel *keyLabel = new QLabel("Public Key");
    keyLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_publicKeyLabel = new QLabel("—");
    m_publicKeyLabel->setStyleSheet(
        "color: #555555; font-size: 12px; font-family: monospace; background: transparent; border: none;"
        );
    m_publicKeyLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    QPushButton *copyBtn = new QPushButton("Copy");
    // Pin the width so the row layout doesn't reflow when the label
    // toggles to "Copied!", but let the height size to the content +
    // dialogAccentBtnCss's vertical padding.  The previous 24px hard
    // cap clipped the descenders on "py" / "Copied!".
    copyBtn->setFixedWidth(76);
    themeStyles::applyRole(copyBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    connect(copyBtn, &QPushButton::clicked, this, [this, copyBtn]() {
        QApplication::clipboard()->setText(m_fullPublicKey);
        copyBtn->setText("Copied!");
        QTimer::singleShot(1500, copyBtn, [copyBtn]() { copyBtn->setText("Copy"); });
    });
    kl->addWidget(keyLabel);
    kl->addStretch();
    kl->addWidget(m_publicKeyLabel);
    kl->addSpacing(8);
    kl->addWidget(copyBtn);
    cardLayout->addWidget(keyRow);
    return card;
}
// Updates profile labels after the panel has been constructed
void SettingsPanel::setProfileInfo(const QString &displayName, const QString &publicKey)
{
    m_fullPublicKey = publicKey;
    if (m_displayNameLabel)
        m_displayNameLabel->setText(displayName.isEmpty() ? "—" : displayName);
    if (m_publicKeyLabel) {
        if (publicKey.isEmpty()) {
            m_publicKeyLabel->setText("—");
        } else {
            const QString truncated = publicKey.left(16) + (publicKey.length() > 16 ? "…" : "");
            m_publicKeyLabel->setText(truncated);
        }
    }
}

void SettingsPanel::setAppDataStore(AppDataStore *store)
{
    m_store = store;
    if (!m_store) return;
    // Load persisted notification state
    const std::string saved = m_store->loadSetting("notificationsEnabled", "true");
    m_notificationsEnabled = (saved == "true");
    applyNotificationState();
    // DND has no persisted value today (session-only); paint the
    // default-off state with theme-correct colors on first show.
    applyDndState();

    // Load notification content-privacy mode.  Default is Hidden —
    // generic "New message" banners keep plaintext out of the OS-
    // level notification store.  Users can opt up in the UI.
    {
        const std::string raw = m_store->loadSetting("notificationMode", "hidden");
        if (raw == "full")         m_notifMode = NotificationMode::Full;
        else if (raw == "sender")  m_notifMode = NotificationMode::SenderOnly;
        else                        m_notifMode = NotificationMode::Hidden;
        if (m_notifModeCombo) {
            QSignalBlocker blocker(m_notifModeCombo);
            m_notifModeCombo->setCurrentIndex(static_cast<int>(m_notifMode));
        }
        emit notificationModeChanged(m_notifMode);
    }

    // Load file-transfer consent settings.  Defaults: everything ≤100 MB
    // accepts, no relay requirement.
    auto parseIntSetting = [this](const std::string& key, int defaultValue) {
        try { return std::stoi(m_store->loadSetting(key, std::to_string(defaultValue))); }
        catch (...) { return defaultValue; }
    };
    const int softMB = parseIntSetting("fileAutoAcceptMaxMB", 100);
    const int hardMB = parseIntSetting("fileHardMaxMB",       100);
    if (m_fileAutoAcceptSpin) {
        QSignalBlocker blocker(m_fileAutoAcceptSpin);
        m_fileAutoAcceptSpin->setValue(softMB);
    }
    if (m_fileHardMaxSpin) {
        QSignalBlocker blocker(m_fileHardMaxSpin);
        m_fileHardMaxSpin->setValue(hardMB);
    }

    m_requireP2PEnabled = (m_store->loadSetting("fileRequireP2P", "false") == "true");
    m_requireVerifiedFilesEnabled =
        (m_store->loadSetting("fileRequireVerified", "false") == "true");
    applyRequireP2PState();
    applyRequireVerifiedFilesState();

    m_hardBlockKeyChangeEnabled =
        (m_store->loadSetting("hardBlockOnKeyChange", "false") == "true");
    applyHardBlockKeyChangeState();

    m_parallelFanOutEnabled =
        (m_store->loadSetting("parallelFanOutEnabled", "false") == "true");
    applyParallelFanOutState();

    m_multiHopEnabled =
        (m_store->loadSetting("multiHopEnabled", "false") == "true");
    applyMultiHopState();

    // Emit initial values so MainWindow/ChatController sync up.
    emit fileAutoAcceptMaxChanged(softMB);
    emit fileHardMaxChanged(hardMB);
    emit fileRequireP2PToggled(m_requireP2PEnabled);
    emit fileRequireVerifiedToggled(m_requireVerifiedFilesEnabled);
    emit hardBlockOnKeyChangeToggled(m_hardBlockKeyChangeEnabled);
    emit parallelFanOutToggled(m_parallelFanOutEnabled);
    emit multiHopToggled(m_multiHopEnabled);

    // Relay URL — load whatever's stored (the mainwindow startup path is
    // the source of truth for the default; here we just reflect what's
    // actually in the DB so what the user sees matches what the client
    // is connected to).
    if (m_relayUrlEdit) {
        const QString url = qtbridge::qstr(m_store->loadSetting("relayUrl", "https://peer2pear.com"));
        QSignalBlocker blocker(m_relayUrlEdit);
        m_relayUrlEdit->setText(url);
        m_lastAppliedRelayUrl = url;
        if (m_relayApplyBtn) m_relayApplyBtn->setEnabled(false);
    }

    // Privacy level — 0 (Standard), 1 (Enhanced), 2 (Maximum).
    {
        int lvl = 0;
        try { lvl = std::stoi(m_store->loadSetting("privacyLevel", "0")); }
        catch (...) { lvl = 0; }
        // Triggers the slot which updates the visual + persists again +
        // emits privacyLevelChanged so MainWindow syncs RelayClient on load.
        onPrivacyLevelChanged(lvl);
    }

    // Appearance — default Dark matches the hardcoded dark palette.
    // setPreference cascades through reapply() → themeChanged signal →
    // applyThemeStyles + applyThemeButtonStyles via the connection in
    // our constructor.
    {
        const std::string raw = m_store->loadSetting("themePreference", "dark");
        const auto pref = raw == "light"  ? ThemeManager::Preference::Light
                        : raw == "system" ? ThemeManager::Preference::System
                        :                    ThemeManager::Preference::Dark;
        ThemeManager::instance().setPreference(pref);
    }
}

void SettingsPanel::applyNotificationState()
{
    const Theme& t = ThemeManager::instance().current();
    if (m_notificationsEnabled) {
        if (m_notifStatusLabel) {
            m_notifStatusLabel->setText("Enabled");
            m_notifStatusLabel->setStyleSheet(themeStyles::statusAccentCss(t));
        }
        if (m_notifToggleBtn) {
            m_notifToggleBtn->setText("Disable");
            m_notifToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
        }
        // Sub-labels reflect effective state: suppressed when DND is active
        const bool effective = !m_dndEnabled;
        if (m_messageAlertsLabel) m_messageAlertsLabel->setText(effective ? "On" : "Off");
        if (m_soundLabel)         m_soundLabel->setText(effective ? "On" : "Off");
    } else {
        if (m_notifStatusLabel) {
            m_notifStatusLabel->setText("Disabled");
            m_notifStatusLabel->setStyleSheet(themeStyles::statusMutedCss(t));
        }
        if (m_notifToggleBtn) {
            m_notifToggleBtn->setText("Enable");
            m_notifToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
        }
        if (m_messageAlertsLabel) m_messageAlertsLabel->setText("Off");
        if (m_soundLabel)         m_soundLabel->setText("Off");
    }
}

QWidget *SettingsPanel::makeSection(const QString &sectionTitle,
                                    const QList<QPair<QString, QString>> &rows)
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

        if (i < rows.size() - 1) {
            QFrame *divider = new QFrame();
            divider->setFrameShape(QFrame::HLine);
            divider->setStyleSheet(
                "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
                );
            cardLayout->addWidget(divider);
        }
    }

    return card;
}

// Builds the interactive Notifications section card with an Enable/Disable toggle
QWidget *SettingsPanel::makeNotificationsSection()
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
    QLabel *heading = new QLabel("NOTIFICATIONS");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // ── Enable / Disable row ──────────────────────────────────────────────────
    QWidget *toggleRow = new QWidget();
    toggleRow->setStyleSheet("background: transparent; border: none;");

    QHBoxLayout *tl = new QHBoxLayout(toggleRow);
    tl->setContentsMargins(16, 10, 16, 10);
    tl->setSpacing(8);

    QLabel *toggleLabel = new QLabel("Notifications");
    toggleLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    // Status label (shows "Enabled" / "Disabled")
    m_notifStatusLabel = new QLabel("Enabled");
    m_notifStatusLabel->setStyleSheet(
        "color: #4caf50; font-size: 13px; background: transparent; border: none;"
        );
    m_notifStatusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    // Toggle button
    m_notifToggleBtn = new QPushButton("Disable");
    m_notifToggleBtn->setFixedSize(76, 28);
    m_notifToggleBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2e1a1a;"
        "  color: #cc5555;"
        "  border: 1px solid #5e2e2e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: #3a2020; }"
        );

    connect(m_notifToggleBtn, &QPushButton::clicked,
            this, &SettingsPanel::onToggleNotifications);

    tl->addWidget(toggleLabel);
    tl->addStretch();
    tl->addWidget(m_notifStatusLabel);
    tl->addSpacing(8);
    tl->addWidget(m_notifToggleBtn);

    cardLayout->addWidget(toggleRow);

    // Divider
    auto addDivider = [&]() {
        QFrame *div = new QFrame();
        div->setFrameShape(QFrame::HLine);
        div->setStyleSheet(
            "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
            );
        cardLayout->addWidget(div);
    };

    // ── Message Alerts row ────────────────────────────────────────────────────
    addDivider();

    QWidget *alertsRow = new QWidget();
    alertsRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *al = new QHBoxLayout(alertsRow);
    al->setContentsMargins(16, 10, 16, 10);
    al->setSpacing(8);
    QLabel *alertsKey = new QLabel("Message Alerts");
    alertsKey->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_messageAlertsLabel = new QLabel("On");
    m_messageAlertsLabel->setStyleSheet(
        "color: #555555; font-size: 13px; background: transparent; border: none;"
        );
    m_messageAlertsLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    al->addWidget(alertsKey);
    al->addStretch();
    al->addWidget(m_messageAlertsLabel);
    cardLayout->addWidget(alertsRow);

    // ── Notification content (privacy) row ────────────────────────────────────
    //
    // Content-level control of what the OS notification store sees.
    // Default is "Hidden" because the macOS/Windows/Linux notification
    // history is outside the app's sandbox — once plaintext enters it,
    // our SQLCipher-at-rest posture is defeated.  Mirrors the iOS
    // setting so a user who opts up on one platform sees the same
    // label on the other.
    addDivider();

    QWidget *contentRow = new QWidget();
    contentRow->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *contentCol = new QVBoxLayout(contentRow);
    contentCol->setContentsMargins(16, 10, 16, 10);
    contentCol->setSpacing(4);

    QHBoxLayout *contentTop = new QHBoxLayout();
    contentTop->setSpacing(8);
    QLabel *contentKey = new QLabel("Show in banner");
    contentKey->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_notifModeCombo = new QComboBox();
    m_notifModeCombo->addItems({"Hidden", "Sender only", "Full content"});
    m_notifModeCombo->setCurrentIndex(0);
    m_notifModeCombo->setFixedWidth(160);
    themeStyles::applyRole(m_notifModeCombo, "themedCombo",
        themeStyles::comboCss(ThemeManager::instance().current(), 12));
    contentTop->addWidget(contentKey);
    contentTop->addStretch();
    contentTop->addWidget(m_notifModeCombo);
    contentCol->addLayout(contentTop);

    m_notifModeHelp = new QLabel(
        "Banners show only \"New message\".  Contents stay inside the "
        "app's encrypted store — the OS notification history sees nothing."
        );
    m_notifModeHelp->setWordWrap(true);
    m_notifModeHelp->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );
    contentCol->addWidget(m_notifModeHelp);

    cardLayout->addWidget(contentRow);

    connect(m_notifModeCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int idx) {
                m_notifMode = static_cast<NotificationMode>(
                    std::clamp(idx, 0, 2));
                if (m_store) {
                    const char* raw =
                        m_notifMode == NotificationMode::Full       ? "full"
                      : m_notifMode == NotificationMode::SenderOnly ? "sender"
                      :                                                "hidden";
                    m_store->saveSetting("notificationMode", raw);
                }
                if (m_notifModeHelp) {
                    switch (m_notifMode) {
                    case NotificationMode::Hidden:
                        m_notifModeHelp->setText(
                            "Banners show only \"New message\".  Contents "
                            "stay inside the app's encrypted store — the "
                            "OS notification history sees nothing.");
                        break;
                    case NotificationMode::SenderOnly:
                        m_notifModeHelp->setText(
                            "Banners name the sender.  The OS stores that "
                            "identifier; message text stays private.");
                        break;
                    case NotificationMode::Full:
                        m_notifModeHelp->setText(
                            "Banners include the message text.  Convenient, "
                            "but the OS retains the plaintext in its "
                            "notification history — readable by forensic "
                            "tools even after the message is deleted.");
                        break;
                    }
                }
                emit notificationModeChanged(m_notifMode);
            });

    // ── Sound row ─────────────────────────────────────────────────────────────
    addDivider();

    QWidget *soundRow = new QWidget();
    soundRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *sl = new QHBoxLayout(soundRow);
    sl->setContentsMargins(16, 10, 16, 10);
    sl->setSpacing(8);
    QLabel *soundKey = new QLabel("Sound");
    soundKey->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_soundLabel = new QLabel("On");
    m_soundLabel->setStyleSheet(
        "color: #555555; font-size: 13px; background: transparent; border: none;"
        );
    m_soundLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    sl->addWidget(soundKey);
    sl->addStretch();
    sl->addWidget(m_soundLabel);
    cardLayout->addWidget(soundRow);

    // ── Do Not Disturb row ────────────────────────────────────────────────────
    addDivider();

    QWidget *dndRow = new QWidget();
    dndRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *dl = new QHBoxLayout(dndRow);
    dl->setContentsMargins(16, 10, 16, 10);
    dl->setSpacing(8);

    QLabel *dndKey = new QLabel("Do Not Disturb");
    dndKey->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    m_dndStatusLabel = new QLabel("Off");
    m_dndStatusLabel->setStyleSheet(
        "color: #555555; font-size: 13px; background: transparent; border: none;"
        );
    m_dndStatusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_dndToggleBtn = new QPushButton("Enable");
    m_dndToggleBtn->setFixedSize(76, 28);
    m_dndToggleBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a2e1a;"
        "  color: #55cc55;"
        "  border: 1px solid #2e5e2e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: #203a20; }"
        );

    connect(m_dndToggleBtn, &QPushButton::clicked,
            this, &SettingsPanel::onToggleDnd);

    dl->addWidget(dndKey);
    dl->addStretch();
    dl->addWidget(m_dndStatusLabel);
    dl->addSpacing(8);
    dl->addWidget(m_dndToggleBtn);
    cardLayout->addWidget(dndRow);

    return card;
}

QWidget *SettingsPanel::makeDataSection()
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

    QLabel *heading = new QLabel("DATA");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // ── Export row ────────────────────────────────────────────────────────────
    QWidget *exportRow = new QWidget();
    exportRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *el = new QHBoxLayout(exportRow);
    el->setContentsMargins(16, 10, 16, 10);
    el->setSpacing(8);

    QLabel *exportLabel = new QLabel("Export Contacts");
    exportLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    QPushButton *exportBtn = new QPushButton("Export");
    exportBtn->setObjectName("exportContactsBtn");
    exportBtn->setFixedSize(76, 28);
    themeStyles::applyRole(exportBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    connect(exportBtn, &QPushButton::clicked,
            this, &SettingsPanel::exportContactsClicked);

    el->addWidget(exportLabel);
    el->addStretch();
    el->addWidget(exportBtn);
    cardLayout->addWidget(exportRow);

    // Divider
    QFrame *div = new QFrame();
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet(
        "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
        );
    cardLayout->addWidget(div);

    // ── Import row ────────────────────────────────────────────────────────────
    QWidget *importRow = new QWidget();
    importRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *il = new QHBoxLayout(importRow);
    il->setContentsMargins(16, 10, 16, 10);
    il->setSpacing(8);

    QLabel *importLabel = new QLabel("Import Contacts");
    importLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    QPushButton *importBtn = new QPushButton("Import");
    importBtn->setObjectName("importContactsBtn");
    importBtn->setFixedSize(76, 28);
    // Both Export + Import use the same accent pill — the previous
    // green/blue distinction is dropped for now so light-mode doesn't
    // ship a hardcoded blue button (no info-color token in Theme).
    // Action affordance is still clear from the labels.
    themeStyles::applyRole(importBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    connect(importBtn, &QPushButton::clicked,
            this, &SettingsPanel::importContactsClicked);

    il->addWidget(importLabel);
    il->addStretch();
    il->addWidget(importBtn);
    cardLayout->addWidget(importRow);

    return card;
}

// ── Archived Chats card ─────────────────────────────────────────────────────
//
// One-row entry that opens the recovery dialog.  Hidden conversations
// would otherwise be unreachable once the per-chat editor is gone from
// the chat list; this section is the way back in.
QWidget *SettingsPanel::makeArchivedChatsSection()
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

    QLabel *heading = new QLabel("ARCHIVED CHATS");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // Two-line layout (label + sub-label) on the left, "Open" button
    // on the right — mirrors the Auto-accept / Require-P2P rows that
    // already use a vertical column with a sub-label below.
    QWidget *row = new QWidget();
    row->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *rv = new QVBoxLayout(row);
    rv->setContentsMargins(16, 10, 16, 10);
    rv->setSpacing(4);

    QHBoxLayout *top = new QHBoxLayout();
    top->setContentsMargins(0, 0, 0, 0);
    top->setSpacing(8);

    QLabel *label = new QLabel("Archived Chats");
    label->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    QPushButton *openBtn = new QPushButton("Open");
    openBtn->setObjectName("openArchivedChatsBtn");
    openBtn->setFixedSize(76, 28);
    themeStyles::applyRole(openBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    connect(openBtn, &QPushButton::clicked,
            this, &SettingsPanel::archivedChatsClicked);

    top->addWidget(label);
    top->addStretch();
    top->addWidget(openBtn);
    rv->addLayout(top);

    QLabel *sub = new QLabel(
        "Hidden conversations. Restore a chat to bring it back to your "
        "list, or delete it permanently."
        );
    sub->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );
    sub->setWordWrap(true);
    rv->addWidget(sub);

    cardLayout->addWidget(row);

    return card;
}

void SettingsPanel::onToggleNotifications()
{
    m_notificationsEnabled = !m_notificationsEnabled;
    applyNotificationState();

    // Persist to DB
    if (m_store)
        m_store->saveSetting("notificationsEnabled",
                             m_notificationsEnabled ? "true" : "false");

    // DND overrides: if DND is on, keep notifications suppressed regardless
    emit notificationsToggled(m_notificationsEnabled && !m_dndEnabled);
}

void SettingsPanel::onToggleDnd()
{
    m_dndEnabled = !m_dndEnabled;
    applyDndState();
    applyNotificationState();  // sub-labels reflect effective state
    emit notificationsToggled(m_notificationsEnabled && !m_dndEnabled);
}

void SettingsPanel::applyDndState()
{
    if (!m_dndStatusLabel || !m_dndToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    // DND is special: "On" reads in DANGER red because it suppresses
    // notifications (opposite polarity from the other toggles, where
    // "On" = good).  Both button variants still match the standard
    // toggle palette.
    if (m_dndEnabled) {
        m_dndStatusLabel->setText("On");
        m_dndStatusLabel->setStyleSheet(QStringLiteral(
            "color: %1; font-size: 13px; background: transparent; border: none;"
        ).arg(t.dangerText.name()));
        m_dndToggleBtn->setText("Disable");
        m_dndToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_dndStatusLabel->setText("Off");
        m_dndStatusLabel->setStyleSheet(themeStyles::statusMutedCss(t));
        m_dndToggleBtn->setText("Enable");
        m_dndToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

// ── About & Help section ─────────────────────────────────────────────────────
QWidget *SettingsPanel::makeAboutHelpSection()
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

    // ── Section heading ──────────────────────────────────────────────────────
    QLabel *heading = new QLabel("GETTING STARTED");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // ── How to Use guide ─────────────────────────────────────────────────────
    QLabel *guideLabel = new QLabel(
        "<p style='color:#999999; font-size:12px; line-height:1.6;'>"
        "<b style='color:#cccccc; font-size:13px;'>Getting Started</b><br>"
        "<br>"
        "<b style='color:#4caf50;'>1. Share your public key</b><br>"
        "Your public key is your identity &mdash; 43 characters, base64url. "
        "Copy it from the Profile section above and share with contacts "
        "however you like (text, QR, in person). No phone number, email, "
        "or account required.<br>"
        "<br>"
        "<b style='color:#4caf50;'>2. Add a contact</b><br>"
        "Tap <b>New Chat</b>, paste their public key, and give them a "
        "display name you'll recognize.<br>"
        "<br>"
        "<b style='color:#4caf50;'>3. Start messaging</b><br>"
        "Select a contact and type. Every message is end-to-end encrypted "
        "with hybrid classical + post-quantum keys before it leaves your "
        "device.<br>"
        "<br>"
        "<b style='color:#4caf50;'>4. Send files</b><br>"
        "Use the paperclip to send files up to 100 MB. Files stream "
        "encrypted in 240 KB chunks with integrity checks, and resume "
        "automatically if your connection drops mid-transfer.<br>"
        "<br>"
        "<b style='color:#4caf50;'>5. Group chats</b><br>"
        "Create a group by adding multiple keys when starting a new chat. "
        "Each member gets their own encrypted copy of every message.<br>"
        "<br>"
        "<b style='color:#cccccc;'>How it works</b><br>"
        "Peer2Pear is relay-first: your messages travel through a simple "
        "WebSocket relay server, encrypted end-to-end. The relay never "
        "sees your plaintext, never learns who you're talking to "
        "(sealed sender), and can't re-route messages to anyone else "
        "(envelope-level AAD binding). When both peers are online and "
        "direct P2P is enabled, messages can flow directly between devices "
        "for lower latency &mdash; but the relay path always works as a "
        "fallback.<br>"
        "<br>"
        "<b style='color:#cccccc;'>Security</b><br>"
        "&bull; Hybrid post-quantum crypto (X25519 + ML-KEM-768) at every layer<br>"
        "&bull; Noise IK handshake + Double Ratchet for per-message forward secrecy<br>"
        "&bull; Sealed sender with envelope-level replay protection<br>"
        "&bull; Encrypted-at-rest local storage (SQLCipher AES-256)<br>"
        "&bull; Optional multi-hop onion routing via multiple relays<br>"
        "<br>"
        "Your messages are yours. Your keys never leave your device."
        "</p>"
        );
    guideLabel->setWordWrap(true);
    guideLabel->setTextFormat(Qt::RichText);
    guideLabel->setStyleSheet(
        "background: transparent; border: none; padding: 10px 16px 14px 16px;"
        );
    cardLayout->addWidget(guideLabel);

    return card;
}

// ── Factory reset (always at the bottom) ────────────────────────────────────
//
// One destructive button that wipes the whole local data dir + the
// SQLCipher DB.  MainWindow handles the actual mechanics (close DB,
// rm -rf dataDir, QSettings::clear, QApplication::quit) on the
// `factoryResetClicked` signal — this section just gates the click
// behind a type-to-confirm dialog so a stray hit can't nuke
// everything.
QWidget *SettingsPanel::makeFactoryResetSection()
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

    QLabel *heading = new QLabel("FACTORY RESET");
    heading->setStyleSheet(
        "color: #e57373;"  // muted red — distinct from the green
                            // section headers; signals destructive
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    QWidget *row = new QWidget();
    row->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *rv = new QVBoxLayout(row);
    rv->setContentsMargins(16, 10, 16, 14);
    rv->setSpacing(8);

    QPushButton *btn = new QPushButton("Erase Identity & All Data");
    btn->setObjectName("factoryResetBtn");
    themeStyles::applyRole(btn, "destructiveBtn",
        themeStyles::destructiveBtnCss(ThemeManager::instance().current()));
    connect(btn, &QPushButton::clicked, this, [this]() {
        // Type-to-confirm: a stray click on a destructive button
        // shouldn't be enough to nuke the user's identity.  We use a
        // QInputDialog with the canonical phrase the user has to
        // type back; cancel + empty + wrong-phrase are all no-ops.
        bool ok = false;
        const QString phrase = QInputDialog::getText(
            this,
            "Factory Reset",
            "This permanently erases your identity, contacts, message "
            "history, files, blocked keys, and every setting on this "
            "device.  Cannot be undone — peers won't know you've reset "
            "and will keep your old key as stale.\n\n"
            "Type RESET to confirm:",
            QLineEdit::Normal, QString(), &ok);
        if (!ok) return;
        if (phrase.trimmed() == "RESET") {
            emit factoryResetClicked();
        }
    });
    rv->addWidget(btn);

    QLabel *sub = new QLabel(
        "Wipes your identity keys, contacts, message history, files, "
        "blocked keys, and every setting on this device.  The app "
        "returns to first-launch state.  Peers won't be notified — "
        "they'll keep your old key as stale."
        );
    sub->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );
    sub->setWordWrap(true);
    rv->addWidget(sub);

    cardLayout->addWidget(row);

    return card;
}

// ── File transfer consent ───────────────────────────────────────────────────

QWidget *SettingsPanel::makeFileTransferSection()
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

    QLabel *heading = new QLabel("FILE TRANSFERS");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    auto addDivider = [&]() {
        QFrame *div = new QFrame();
        div->setFrameShape(QFrame::HLine);
        div->setStyleSheet(
            "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
            );
        cardLayout->addWidget(div);
    };

    // Shared row-row style for the two SpinBox rows.
    auto makeSpinRow = [&](const QString &labelText, const QString &sublabelText,
                            QSpinBox *spin, int defaultMB) -> QWidget * {
        QWidget *row = new QWidget();
        row->setStyleSheet("background: transparent; border: none;");

        QVBoxLayout *rv = new QVBoxLayout(row);
        rv->setContentsMargins(16, 10, 16, 10);
        rv->setSpacing(4);

        QHBoxLayout *top = new QHBoxLayout();
        top->setContentsMargins(0, 0, 0, 0);
        top->setSpacing(8);

        QLabel *mainLbl = new QLabel(labelText);
        mainLbl->setStyleSheet(
            "color: #cccccc; font-size: 13px; background: transparent; border: none;"
            );

        spin->setRange(1, 10000);
        spin->setValue(defaultMB);
        spin->setSuffix(" MB");
        spin->setFixedWidth(110);
        themeStyles::applyRole(spin, "themedSpin",
            themeStyles::spinBoxCss(ThemeManager::instance().current(), 13));

        top->addWidget(mainLbl);
        top->addStretch();
        top->addWidget(spin);
        rv->addLayout(top);

        QLabel *subLbl = new QLabel(sublabelText);
        subLbl->setStyleSheet(
            "color: #777777; font-size: 11px; background: transparent; border: none;"
            );
        subLbl->setWordWrap(true);
        rv->addWidget(subLbl);

        return row;
    };

    // Auto-accept row
    m_fileAutoAcceptSpin = new QSpinBox();
    cardLayout->addWidget(makeSpinRow(
        "Auto-accept files up to",
        "Files at or below this size download without asking.",
        m_fileAutoAcceptSpin,
        100));
    connect(m_fileAutoAcceptSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &SettingsPanel::onFileAutoAcceptSpin);

    addDivider();

    // Hard max row
    m_fileHardMaxSpin = new QSpinBox();
    cardLayout->addWidget(makeSpinRow(
        "Never accept files larger than",
        "Files above this size are declined automatically, no notification.",
        m_fileHardMaxSpin,
        100));
    connect(m_fileHardMaxSpin, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &SettingsPanel::onFileHardMaxSpin);

    addDivider();

    // Require P2P toggle row
    QWidget *p2pRow = new QWidget();
    p2pRow->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *pv = new QVBoxLayout(p2pRow);
    pv->setContentsMargins(16, 10, 16, 10);
    pv->setSpacing(4);

    QHBoxLayout *p2pTop = new QHBoxLayout();
    p2pTop->setContentsMargins(0, 0, 0, 0);
    p2pTop->setSpacing(8);

    QLabel *p2pLabel = new QLabel("Require direct connection for files");
    p2pLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    m_requireP2PStatusLbl = new QLabel("Off");
    m_requireP2PStatusLbl->setStyleSheet(
        "color: #888888; font-size: 13px; background: transparent; border: none;"
        );
    m_requireP2PStatusLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_requireP2PToggleBtn = new QPushButton("Enable");
    m_requireP2PToggleBtn->setFixedSize(76, 28);
    m_requireP2PToggleBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a2a1a;"
        "  color: #77cc77;"
        "  border: 1px solid #2e5e2e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: #203020; }"
        );
    connect(m_requireP2PToggleBtn, &QPushButton::clicked,
            this, &SettingsPanel::onToggleRequireP2P);

    p2pTop->addWidget(p2pLabel);
    p2pTop->addStretch();
    p2pTop->addWidget(m_requireP2PStatusLbl);
    p2pTop->addSpacing(8);
    p2pTop->addWidget(m_requireP2PToggleBtn);
    pv->addLayout(p2pTop);

    QLabel *p2pSub = new QLabel(
        "If on, files from contacts are only accepted when a direct P2P "
        "connection is available. Relayed files are refused."
        );
    p2pSub->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );
    p2pSub->setWordWrap(true);
    pv->addWidget(p2pSub);

    cardLayout->addWidget(p2pRow);

    // ── Verified-contacts gate ─────────────────────────────────────────
    // UI mirrors the Require-P2P row above.  Lives entirely in ChatView
    // (see onFileAcceptRequested) — when on, files from peers whose
    // safety number isn't verified are silently declined before the
    // consent QMessageBox is raised.
    QFrame *verRow = new QFrame(card);
    verRow->setObjectName("p2pSubrow");
    verRow->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *vv = new QVBoxLayout(verRow);
    vv->setContentsMargins(16, 10, 16, 10);
    vv->setSpacing(4);

    QHBoxLayout *verTop = new QHBoxLayout();
    verTop->setContentsMargins(0, 0, 0, 0);
    verTop->setSpacing(8);

    QLabel *verLabel = new QLabel("Only accept files from verified contacts");
    verLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );

    m_requireVerifiedFilesStatusLbl = new QLabel("Off");
    m_requireVerifiedFilesStatusLbl->setStyleSheet(
        "color: #888888; font-size: 13px; background: transparent; border: none;"
        );
    m_requireVerifiedFilesStatusLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    m_requireVerifiedFilesToggleBtn = new QPushButton("Enable");
    m_requireVerifiedFilesToggleBtn->setFixedSize(76, 28);
    m_requireVerifiedFilesToggleBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a2a1a;"
        "  color: #77cc77;"
        "  border: 1px solid #2e5e2e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: #203020; }"
        );
    connect(m_requireVerifiedFilesToggleBtn, &QPushButton::clicked,
            this, &SettingsPanel::onToggleRequireVerifiedFiles);

    verTop->addWidget(verLabel);
    verTop->addStretch();
    verTop->addWidget(m_requireVerifiedFilesStatusLbl);
    verTop->addSpacing(8);
    verTop->addWidget(m_requireVerifiedFilesToggleBtn);
    vv->addLayout(verTop);

    QLabel *verSub = new QLabel(
        "Files from peers whose safety number you haven't confirmed are "
        "silently declined.  Use Contact Info to verify."
        );
    verSub->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );
    verSub->setWordWrap(true);
    vv->addWidget(verSub);

    cardLayout->addWidget(verRow);

    return card;
}

void SettingsPanel::onFileAutoAcceptSpin(int mb)
{
    if (m_store) m_store->saveSetting("fileAutoAcceptMaxMB", std::to_string(mb));
    emit fileAutoAcceptMaxChanged(mb);
}

void SettingsPanel::onFileHardMaxSpin(int mb)
{
    if (m_store) m_store->saveSetting("fileHardMaxMB", std::to_string(mb));
    emit fileHardMaxChanged(mb);
}

void SettingsPanel::onToggleRequireP2P()
{
    m_requireP2PEnabled = !m_requireP2PEnabled;
    if (m_store) m_store->saveSetting("fileRequireP2P",
                                      m_requireP2PEnabled ? "true" : "false");
    applyRequireP2PState();
    emit fileRequireP2PToggled(m_requireP2PEnabled);
}

void SettingsPanel::applyRequireP2PState()
{
    if (!m_requireP2PStatusLbl || !m_requireP2PToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    if (m_requireP2PEnabled) {
        m_requireP2PStatusLbl->setText("On");
        m_requireP2PStatusLbl->setStyleSheet(themeStyles::statusAccentCss(t));
        m_requireP2PToggleBtn->setText("Disable");
        m_requireP2PToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_requireP2PStatusLbl->setText("Off");
        m_requireP2PStatusLbl->setStyleSheet(themeStyles::statusMutedCss(t));
        m_requireP2PToggleBtn->setText("Enable");
        m_requireP2PToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

void SettingsPanel::onToggleRequireVerifiedFiles()
{
    m_requireVerifiedFilesEnabled = !m_requireVerifiedFilesEnabled;
    if (m_store) m_store->saveSetting("fileRequireVerified",
                                      m_requireVerifiedFilesEnabled ? "true" : "false");
    applyRequireVerifiedFilesState();
    emit fileRequireVerifiedToggled(m_requireVerifiedFilesEnabled);
}

void SettingsPanel::applyRequireVerifiedFilesState()
{
    if (!m_requireVerifiedFilesStatusLbl || !m_requireVerifiedFilesToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    if (m_requireVerifiedFilesEnabled) {
        m_requireVerifiedFilesStatusLbl->setText("On");
        m_requireVerifiedFilesStatusLbl->setStyleSheet(themeStyles::statusAccentCss(t));
        m_requireVerifiedFilesToggleBtn->setText("Disable");
        m_requireVerifiedFilesToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_requireVerifiedFilesStatusLbl->setText("Off");
        m_requireVerifiedFilesStatusLbl->setStyleSheet(themeStyles::statusMutedCss(t));
        m_requireVerifiedFilesToggleBtn->setText("Enable");
        m_requireVerifiedFilesToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

// ── Relay URL ────────────────────────────────────────────────────────────────
//
// Card with a single QLineEdit for the relay URL, an Apply button (enabled
// only when the field differs from what's stored), and a Reset link to
// restore the default `https://peer2pear.com`.
//
// On Apply we persist to the DB and emit `relayUrlChanged` -- MainWindow
// hooks that and drops the current WS connection + reconnects at the new
// URL.  We don't validate the URL beyond "non-empty"; if it's malformed the
// RelayClient will fail to connect and the user will see a status message.

QWidget *SettingsPanel::makeRelaySection()
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

    // Heading
    QLabel *heading = new QLabel("RELAY");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // URL row: label + input + Apply button
    QWidget *urlRow = new QWidget();
    urlRow->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout *urlLayout = new QVBoxLayout(urlRow);
    urlLayout->setContentsMargins(16, 10, 16, 4);
    urlLayout->setSpacing(6);

    QLabel *urlLabel = new QLabel("Server URL");
    urlLabel->setStyleSheet(
        "color: #cccccc; font-size: 13px; background: transparent; border: none;"
        );
    urlLayout->addWidget(urlLabel);

    QHBoxLayout *inputRow = new QHBoxLayout();
    inputRow->setSpacing(8);

    m_relayUrlEdit = new QLineEdit();
    m_relayUrlEdit->setText("https://peer2pear.com");
    m_relayUrlEdit->setPlaceholderText("https://your-relay.example.com");
    themeStyles::applyRole(m_relayUrlEdit, "themedLineEdit",
        themeStyles::lineEditCss(ThemeManager::instance().current(), 13));

    m_relayApplyBtn = new QPushButton("Apply");
    m_relayApplyBtn->setEnabled(false);
    m_relayApplyBtn->setFixedWidth(78);
    themeStyles::applyRole(m_relayApplyBtn, "applyBtn",
        themeStyles::applyBtnCss(ThemeManager::instance().current()));

    inputRow->addWidget(m_relayUrlEdit, 1);
    inputRow->addWidget(m_relayApplyBtn);
    urlLayout->addLayout(inputRow);

    // Sub-text / reset link
    QHBoxLayout *subRow = new QHBoxLayout();
    subRow->setSpacing(8);
    subRow->setContentsMargins(0, 0, 0, 0);

    QLabel *helpLbl = new QLabel(
        "Server used for encrypted message delivery. "
        "Change only if you run your own relay."
        );
    helpLbl->setWordWrap(true);
    helpLbl->setStyleSheet(
        "color: #777777; font-size: 11px; background: transparent; border: none;"
        );

    QPushButton *resetBtn = new QPushButton("Reset to default");
    resetBtn->setFlat(true);
    resetBtn->setCursor(Qt::PointingHandCursor);
    resetBtn->setStyleSheet(
        "QPushButton {"
        "  background: transparent; border: none; color: #4caf50;"
        "  font-size: 11px; text-align: right;"
        "}"
        "QPushButton:hover { color: #6ac96a; text-decoration: underline; }"
        );

    subRow->addWidget(helpLbl, 1);
    subRow->addWidget(resetBtn);
    urlLayout->addLayout(subRow);

    cardLayout->addWidget(urlRow);

    // Bottom padding / optional status area
    m_relayStatusLabel = new QLabel("");
    m_relayStatusLabel->setStyleSheet(
        "color: #777777; font-size: 11px; padding: 4px 16px 12px 16px;"
        "background: transparent; border: none;"
        );
    m_relayStatusLabel->setWordWrap(true);
    cardLayout->addWidget(m_relayStatusLabel);

    // Enable/disable Apply as the user edits.
    connect(m_relayUrlEdit, &QLineEdit::textChanged, this,
            [this](const QString &text) {
        const bool changed  = text.trimmed() != m_lastAppliedRelayUrl;
        const bool nonEmpty = !text.trimmed().isEmpty();
        if (m_relayApplyBtn)
            m_relayApplyBtn->setEnabled(changed && nonEmpty);
    });
    connect(m_relayUrlEdit, &QLineEdit::returnPressed,
            this, &SettingsPanel::onApplyRelayUrl);
    connect(m_relayApplyBtn, &QPushButton::clicked,
            this, &SettingsPanel::onApplyRelayUrl);
    connect(resetBtn, &QPushButton::clicked,
            this, &SettingsPanel::onResetRelayUrl);

    return card;
}

void SettingsPanel::onApplyRelayUrl()
{
    if (!m_relayUrlEdit) return;
    const QString url = m_relayUrlEdit->text().trimmed();
    if (url.isEmpty()) return;

    if (m_store) m_store->saveSetting("relayUrl", url.toStdString());
    m_lastAppliedRelayUrl = url;
    if (m_relayApplyBtn) m_relayApplyBtn->setEnabled(false);

    if (m_relayStatusLabel) {
        m_relayStatusLabel->setText("Reconnecting to " + url + " ...");
        // Clear the status after a few seconds — ChatController's own
        // status signal carries the actual outcome.
        QTimer::singleShot(4000, m_relayStatusLabel, [this]() {
            if (m_relayStatusLabel) m_relayStatusLabel->setText("");
        });
    }

    emit relayUrlChanged(url);
}

void SettingsPanel::onResetRelayUrl()
{
    if (!m_relayUrlEdit) return;
    m_relayUrlEdit->setText("https://peer2pear.com");
    // textChanged handler enabled the Apply button; user still has to press it
    // to actually commit -- nothing is persisted by the reset alone.
}

// ── Privacy level ────────────────────────────────────────────────────────────
//
// Three selectable buttons (a "segmented control" pattern) plus a
// description block that changes text based on the selected level.
// This is the user-facing knob that turns on jitter + cover traffic +
// onion routing — features that already exist in RelayClient but
// default to off.

QWidget *SettingsPanel::makePrivacySection()
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

    // Heading
    QLabel *heading = new QLabel("PRIVACY");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    // Segmented button row
    QWidget *segRow = new QWidget();
    segRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *segLayout = new QHBoxLayout(segRow);
    segLayout->setContentsMargins(16, 8, 16, 4);
    segLayout->setSpacing(8);

    auto makeLevelButton = [](const QString &text) -> QPushButton * {
        QPushButton *btn = new QPushButton(text);
        btn->setCheckable(true);
        btn->setCursor(Qt::PointingHandCursor);
        themeStyles::applyRole(btn, "segmentBtn",
            themeStyles::segmentButtonCss(ThemeManager::instance().current()));
        return btn;
    };

    m_privacyBtn0 = makeLevelButton("Standard");
    m_privacyBtn1 = makeLevelButton("Enhanced");
    m_privacyBtn2 = makeLevelButton("Maximum");

    segLayout->addWidget(m_privacyBtn0, 1);
    segLayout->addWidget(m_privacyBtn1, 1);
    segLayout->addWidget(m_privacyBtn2, 1);
    cardLayout->addWidget(segRow);

    // Description area — text changes based on selected level.
    m_privacyDescLabel = new QLabel();
    m_privacyDescLabel->setWordWrap(true);
    m_privacyDescLabel->setTextFormat(Qt::RichText);
    m_privacyDescLabel->setStyleSheet(
        "color: #999999; font-size: 12px;"
        "padding: 6px 16px 14px 16px;"
        "background: transparent; border: none; line-height: 1.5;"
        );
    cardLayout->addWidget(m_privacyDescLabel);

    // Wire up the three buttons to the slot (pass the target level).
    connect(m_privacyBtn0, &QPushButton::clicked, this,
            [this]() { onPrivacyLevelChanged(0); });
    connect(m_privacyBtn1, &QPushButton::clicked, this,
            [this]() { onPrivacyLevelChanged(1); });
    connect(m_privacyBtn2, &QPushButton::clicked, this,
            [this]() { onPrivacyLevelChanged(2); });

    // ── Hard-block on peer key change (safety numbers) ──────────────────
    {
        QFrame *div = new QFrame();
        div->setFrameShape(QFrame::HLine);
        div->setStyleSheet("color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;");
        cardLayout->addWidget(div);

        QWidget *row = new QWidget();
        row->setStyleSheet("background: transparent; border: none;");
        QVBoxLayout *rv = new QVBoxLayout(row);
        rv->setContentsMargins(16, 10, 16, 10);
        rv->setSpacing(4);

        QHBoxLayout *top = new QHBoxLayout();
        top->setContentsMargins(0, 0, 0, 0);
        top->setSpacing(8);

        QLabel *label = new QLabel("Block contacts whose safety number changed");
        label->setStyleSheet(
            "color: #cccccc; font-size: 13px; background: transparent; border: none;");

        m_hardBlockKeyChangeStatusLbl = new QLabel("Off");
        m_hardBlockKeyChangeStatusLbl->setStyleSheet(
            "color: #888888; font-size: 13px; background: transparent; border: none;");
        m_hardBlockKeyChangeStatusLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        m_hardBlockKeyChangeToggleBtn = new QPushButton("Enable");
        m_hardBlockKeyChangeToggleBtn->setFixedSize(76, 28);
        m_hardBlockKeyChangeToggleBtn->setStyleSheet(
            "QPushButton {"
            "  background-color: #1a2a1a;"
            "  color: #77cc77;"
            "  border: 1px solid #2e5e2e;"
            "  border-radius: 6px;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover { background-color: #203020; }");
        connect(m_hardBlockKeyChangeToggleBtn, &QPushButton::clicked,
                this, &SettingsPanel::onToggleHardBlockOnKeyChange);

        top->addWidget(label);
        top->addStretch();
        top->addWidget(m_hardBlockKeyChangeStatusLbl);
        top->addSpacing(8);
        top->addWidget(m_hardBlockKeyChangeToggleBtn);
        rv->addLayout(top);

        QLabel *sub = new QLabel(
            "If on, the app refuses to send to (or accept from) a previously-"
            "verified contact whose safety number no longer matches. Default off: "
            "a mismatch shows a banner, you decide whether to continue.");
        sub->setStyleSheet(
            "color: #777777; font-size: 11px; background: transparent; border: none;");
        sub->setWordWrap(true);
        rv->addWidget(sub);

        cardLayout->addWidget(row);
    }

    // ── Advanced transport dials ──────────────────────────────────────────
    //
    // Two independent toggles surfaced separately from the privacy
    // preset above.  Different threats, different costs:
    //   parallel fan-out → REDUNDANCY (one relay down ≠ delivery loss)
    //   multi-hop onion  → ANONYMITY  (no relay sees both ends)
    // Help text below each toggle hammers the distinction so a user
    // can't mistake redundancy for anonymity.

    auto buildAdvancedToggle =
        [&](const QString& title, const QString& sub,
            QPushButton*& outBtn, QLabel*& outStatus,
            void (SettingsPanel::*onClick)()) {
        QFrame *div = new QFrame();
        div->setFrameShape(QFrame::HLine);
        div->setStyleSheet("color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;");
        cardLayout->addWidget(div);

        QWidget *row = new QWidget();
        row->setStyleSheet("background: transparent; border: none;");
        QVBoxLayout *rv = new QVBoxLayout(row);
        rv->setContentsMargins(16, 10, 16, 10);
        rv->setSpacing(4);

        QHBoxLayout *top = new QHBoxLayout();
        top->setContentsMargins(0, 0, 0, 0);
        top->setSpacing(8);

        QLabel *label = new QLabel(title);
        label->setStyleSheet(
            "color: #cccccc; font-size: 13px; background: transparent; border: none;");

        outStatus = new QLabel("Off");
        outStatus->setStyleSheet(
            "color: #888888; font-size: 13px; background: transparent; border: none;");
        outStatus->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        outBtn = new QPushButton("Enable");
        outBtn->setFixedSize(76, 28);
        outBtn->setStyleSheet(
            "QPushButton {"
            "  background-color: #1a2a1a;"
            "  color: #77cc77;"
            "  border: 1px solid #2e5e2e;"
            "  border-radius: 6px;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover { background-color: #203020; }");
        connect(outBtn, &QPushButton::clicked, this, onClick);

        top->addWidget(label);
        top->addStretch();
        top->addWidget(outStatus);
        top->addSpacing(8);
        top->addWidget(outBtn);
        rv->addLayout(top);

        QLabel *subLbl = new QLabel(sub);
        subLbl->setStyleSheet(
            "color: #777777; font-size: 11px; background: transparent; border: none;");
        subLbl->setWordWrap(true);
        rv->addWidget(subLbl);

        cardLayout->addWidget(row);
    };

    buildAdvancedToggle(
        "Send to multiple relays in parallel",
        "Posts every message to all configured relays simultaneously. "
        "If one relay is offline or blocks your traffic, others still "
        "deliver. Improves reliability — does not improve anonymity.",
        m_parallelFanOutToggleBtn, m_parallelFanOutStatusLbl,
        &SettingsPanel::onToggleParallelFanOut);

    buildAdvancedToggle(
        "Onion-route through multiple relays",
        "Routes each message through a chain of relays with layered "
        "encryption. No single relay sees both sender and recipient. "
        "Improves anonymity — does not improve reliability. Adds "
        "latency. Requires at least one backup relay.",
        m_multiHopToggleBtn, m_multiHopStatusLbl,
        &SettingsPanel::onToggleMultiHop);

    return card;
}

void SettingsPanel::onToggleHardBlockOnKeyChange()
{
    m_hardBlockKeyChangeEnabled = !m_hardBlockKeyChangeEnabled;
    if (m_store) m_store->saveSetting("hardBlockOnKeyChange",
                                      m_hardBlockKeyChangeEnabled ? "true" : "false");
    applyHardBlockKeyChangeState();
    emit hardBlockOnKeyChangeToggled(m_hardBlockKeyChangeEnabled);
}

void SettingsPanel::onToggleParallelFanOut()
{
    m_parallelFanOutEnabled = !m_parallelFanOutEnabled;
    if (m_store) m_store->saveSetting("parallelFanOutEnabled",
                                      m_parallelFanOutEnabled ? "true" : "false");
    applyParallelFanOutState();
    emit parallelFanOutToggled(m_parallelFanOutEnabled);
}

void SettingsPanel::onToggleMultiHop()
{
    m_multiHopEnabled = !m_multiHopEnabled;
    if (m_store) m_store->saveSetting("multiHopEnabled",
                                      m_multiHopEnabled ? "true" : "false");
    applyMultiHopState();
    emit multiHopToggled(m_multiHopEnabled);
}

void SettingsPanel::applyParallelFanOutState()
{
    if (!m_parallelFanOutStatusLbl || !m_parallelFanOutToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    if (m_parallelFanOutEnabled) {
        m_parallelFanOutStatusLbl->setText("On");
        m_parallelFanOutStatusLbl->setStyleSheet(themeStyles::statusAccentCss(t));
        m_parallelFanOutToggleBtn->setText("Disable");
        m_parallelFanOutToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_parallelFanOutStatusLbl->setText("Off");
        m_parallelFanOutStatusLbl->setStyleSheet(themeStyles::statusMutedCss(t));
        m_parallelFanOutToggleBtn->setText("Enable");
        m_parallelFanOutToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

void SettingsPanel::applyMultiHopState()
{
    if (!m_multiHopStatusLbl || !m_multiHopToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    if (m_multiHopEnabled) {
        m_multiHopStatusLbl->setText("On");
        m_multiHopStatusLbl->setStyleSheet(themeStyles::statusAccentCss(t));
        m_multiHopToggleBtn->setText("Disable");
        m_multiHopToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_multiHopStatusLbl->setText("Off");
        m_multiHopStatusLbl->setStyleSheet(themeStyles::statusMutedCss(t));
        m_multiHopToggleBtn->setText("Enable");
        m_multiHopToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

void SettingsPanel::applyHardBlockKeyChangeState()
{
    if (!m_hardBlockKeyChangeStatusLbl || !m_hardBlockKeyChangeToggleBtn) return;
    const Theme& t = ThemeManager::instance().current();
    if (m_hardBlockKeyChangeEnabled) {
        m_hardBlockKeyChangeStatusLbl->setText("On");
        m_hardBlockKeyChangeStatusLbl->setStyleSheet(themeStyles::statusAccentCss(t));
        m_hardBlockKeyChangeToggleBtn->setText("Disable");
        m_hardBlockKeyChangeToggleBtn->setStyleSheet(themeStyles::toggleDangerCss(t));
    } else {
        m_hardBlockKeyChangeStatusLbl->setText("Off");
        m_hardBlockKeyChangeStatusLbl->setStyleSheet(themeStyles::statusMutedCss(t));
        m_hardBlockKeyChangeToggleBtn->setText("Enable");
        m_hardBlockKeyChangeToggleBtn->setStyleSheet(themeStyles::toggleAccentCss(t));
    }
}

void SettingsPanel::onPrivacyLevelChanged(int level)
{
    if (level < 0 || level > 2) level = 0;
    m_privacyLevel = level;

    // Update the button visuals (exactly one checked).  Blocking signals
    // while calling setChecked() prevents a re-entry loop.
    if (m_privacyBtn0 && m_privacyBtn1 && m_privacyBtn2) {
        QSignalBlocker b0(m_privacyBtn0), b1(m_privacyBtn1), b2(m_privacyBtn2);
        m_privacyBtn0->setChecked(level == 0);
        m_privacyBtn1->setChecked(level == 1);
        m_privacyBtn2->setChecked(level == 2);
    }

    // Description text is rich-formatted so the per-level bullets render.
    if (m_privacyDescLabel) {
        QString desc;
        switch (level) {
        case 0:
            desc =
                "<b style='color:#cccccc;'>Standard</b> &mdash; baseline privacy.<br>"
                "&bull; Envelope size padding (hides message size from the relay)<br>"
                "&bull; Sealed sender (hides your identity from the relay)<br>"
                "&bull; End-to-end encryption (no operator can read content)<br>"
                "<br>"
                "Recommended for most users.";
            break;
        case 1:
            desc =
                "<b style='color:#cccccc;'>Enhanced</b> &mdash; adds traffic shaping and "
                "delivery redundancy.<br>"
                "&bull; All Standard protections<br>"
                "&bull; Send jitter (50&ndash;300&thinsp;ms random delay per message)<br>"
                "&bull; Cover traffic (periodic indistinguishable dummy envelopes)<br>"
                "&bull; Parallel relay fan-out: each message posted to all configured "
                "relays so a single relay being down doesn't drop delivery<br>"
                "<br>"
                "Slight latency cost; small bandwidth overhead. "
                "<i>Improves reliability &mdash; not anonymity.</i>";
            break;
        case 2:
            desc =
                "<b style='color:#cccccc;'>Maximum</b> &mdash; defends against colluding "
                "relay operators.<br>"
                "&bull; All Enhanced protections<br>"
                "&bull; Multi-hop onion routing: no single relay learns both your "
                "identity and your recipient<br>"
                "&bull; Higher-frequency cover traffic<br>"
                "&bull; Longer jitter (100&ndash;500&thinsp;ms)<br>"
                "<br>"
                "Highest latency; higher bandwidth. <i>Improves anonymity, on top of "
                "Enhanced's reliability.</i>";
            break;
        }
        m_privacyDescLabel->setText(desc);
    }

    // Persist and notify.
    if (m_store) m_store->saveSetting("privacyLevel", std::to_string(level));
    emit privacyLevelChanged(level);
}

QWidget *SettingsPanel::makeAppearanceSection()
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

    QLabel *heading = new QLabel("APPEARANCE");
    heading->setStyleSheet(
        "color: #4caf50;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
        );
    cardLayout->addWidget(heading);

    QWidget *segRow = new QWidget();
    segRow->setStyleSheet("background: transparent; border: none;");
    QHBoxLayout *segLayout = new QHBoxLayout(segRow);
    segLayout->setContentsMargins(16, 8, 16, 4);
    segLayout->setSpacing(8);

    auto makeThemeButton = [](const QString &text) -> QPushButton * {
        QPushButton *btn = new QPushButton(text);
        btn->setCheckable(true);
        btn->setCursor(Qt::PointingHandCursor);
        themeStyles::applyRole(btn, "segmentBtn",
            themeStyles::segmentButtonCss(ThemeManager::instance().current()));
        return btn;
    };

    m_themeBtnDark   = makeThemeButton("Dark");
    m_themeBtnLight  = makeThemeButton("Light");
    m_themeBtnSystem = makeThemeButton("System");

    segLayout->addWidget(m_themeBtnDark,   1);
    segLayout->addWidget(m_themeBtnLight,  1);
    segLayout->addWidget(m_themeBtnSystem, 1);
    cardLayout->addWidget(segRow);

    // Caption — honest about current scope.  The dark palette is
    // hardcoded in per-widget stylesheets throughout the app; Light
    // currently swaps the app-level Fusion palette so system widgets
    // (menus, dialogs, scrollbars) respect it but per-widget
    // stylesheets still paint dark.
    QLabel *caption = new QLabel(
        "Light theme is a work in progress — app-level chrome switches, "
        "but per-widget colors still follow the dark palette.  Full "
        "coverage is tracked as follow-up work."
        );
    caption->setWordWrap(true);
    caption->setStyleSheet(
        "color: #777777; font-size: 11px;"
        "padding: 6px 16px 14px 16px;"
        "background: transparent; border: none;"
        );
    cardLayout->addWidget(caption);

    auto pickTheme = [this](ThemeManager::Preference pref) {
        if (m_store) {
            const char* raw = pref == ThemeManager::Preference::Light  ? "light"
                             : pref == ThemeManager::Preference::System ? "system"
                                                                          : "dark";
            m_store->saveSetting("themePreference", raw);
        }
        // Single source of truth — ThemeManager fires themeChanged
        // which our constructor's connection routes to applyThemeStyles
        // + applyThemeButtonStyles, so the buttons re-highlight too.
        ThemeManager::instance().setPreference(pref);
    };
    connect(m_themeBtnDark,   &QPushButton::clicked, this,
            [pickTheme]() { pickTheme(ThemeManager::Preference::Dark); });
    connect(m_themeBtnLight,  &QPushButton::clicked, this,
            [pickTheme]() { pickTheme(ThemeManager::Preference::Light); });
    connect(m_themeBtnSystem, &QPushButton::clicked, this,
            [pickTheme]() { pickTheme(ThemeManager::Preference::System); });

    return card;
}

void SettingsPanel::applyThemeButtonStyles()
{
    if (!m_themeBtnDark || !m_themeBtnLight || !m_themeBtnSystem) return;
    const auto pref = ThemeManager::instance().preference();
    QSignalBlocker b0(m_themeBtnDark);
    QSignalBlocker b1(m_themeBtnLight);
    QSignalBlocker b2(m_themeBtnSystem);
    m_themeBtnDark  ->setChecked(pref == ThemeManager::Preference::Dark);
    m_themeBtnLight ->setChecked(pref == ThemeManager::Preference::Light);
    m_themeBtnSystem->setChecked(pref == ThemeManager::Preference::System);
}

// ── Theme application ───────────────────────────────────────────────────────
//
// Strategy: every section maker above has already emitted hardcoded dark
// stylesheets via setStyleSheet().  applyThemeStyles auto-classifies each
// child widget by inspecting that stylesheet (e.g. "background-color:
// #111111" + "border-radius: 10px" → card) and overwrites with a theme-
// driven sheet.  Auto-classification keeps the section makers simple
// (no per-widget tagging boilerplate) and the override-then-overwrite
// flow is harmless: in dark mode the rewritten sheet matches the
// original byte-for-byte; in light mode it actually flips colors.
//
// Roles handled:
//   • card        — section background + border + 10px radius
//   • heading     — green ALL-CAPS section label
//   • key         — left-side row label (e.g. "Display Name")
//   • value       — right-side dim row value (e.g. truncated key)
//   • divider     — 1px horizontal rule between rows
//   • outerChrome — settingsPanel / settingsHeader / scroll / body
//
// Buttons + segmented pickers are intentionally NOT covered yet —
// they have state-dependent stylesheets (enabled/disabled, checked/
// hover) that the existing apply*State() methods recompute on every
// toggle.  Migrating those is a follow-up.

void SettingsPanel::applyThemeStyles()
{
    const Theme& t = ThemeManager::instance().current();

    // Outer chrome — settingsPanel itself + the named header bar.
    // Scroll area + body widget are tagged via p2pRole so the
    // shared classifier doesn't have to know about the layout.
    setStyleSheet(QStringLiteral(
        "QWidget#settingsPanel { background-color: %1; }"
    ).arg(t.bg.name()));
    if (auto* header = findChild<QWidget*>("settingsHeader")) {
        header->setStyleSheet(QStringLiteral(
            "QWidget#settingsHeader {"
            "  background-color: %1;"
            "  border-bottom: 1px solid %2;"
            "}"
        ).arg(t.bg.name(), t.border.name()));
    }
    for (auto* w : findChildren<QWidget*>()) {
        const QString role = w->property("p2pRole").toString();
        if (role == "scroll" || role == "body") {
            w->setStyleSheet(QStringLiteral(
                "background-color: %1; border: none;"
            ).arg(t.bg.name()));
        }
    }

    // Cards / headings / key+value labels / dividers — shared with ChatView.
    themeStyles::reapplyForChildren(this, t);

    // State-dependent toggles (Notifications, DND, Require-P2P,
    // Safety-number hard-block) own their stylesheets per state — re-
    // invoke the apply*State methods so they pick up the new palette.
    applyNotificationState();
    applyDndState();
    applyRequireP2PState();
    applyHardBlockKeyChangeState();
}
