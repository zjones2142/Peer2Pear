#include "settingspanel.h"
#include "databasemanager.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
#include <QTimer>

// ── SettingsPanel ─────────────────────────────────────────────────────────────

SettingsPanel::SettingsPanel(QWidget *parent)
    : QWidget(parent)
{
    buildUI();
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

    connect(backBtn, &QPushButton::clicked, this, &SettingsPanel::backClicked);

    // ── Scrollable body ───────────────────────────────────────────────────────
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

    // ── Profile section ───────────────────────────────────────────────────────
    bodyLayout->addWidget(makeProfileSection());

    // ── Notifications section (interactive) ───────────────────────────────────
    bodyLayout->addWidget(makeNotificationsSection());

    // ── Data section (import / export) ──────────────────────────────────────
    bodyLayout->addWidget(makeDataSection());

    // ── About section ─────────────────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("ABOUT", {
                                                { "Version",  "0.1.0"     },
                                                { "Protocol", "Peer2Pear" },
                                                }));

    bodyLayout->addStretch();
    scroll->setWidget(body);

    outerLayout->addWidget(settingsHeader);
    outerLayout->addWidget(scroll);
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
    copyBtn->setFixedSize(52, 24);
    copyBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #1a1a2e;"
        "  color: #5588dd;"
        "  border: 1px solid #2e2e5e;"
        "  border-radius: 5px;"
        "  font-size: 11px;"
        "}"
        "QPushButton:hover { background-color: #22223a; }"
        );
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

void SettingsPanel::setDatabase(DatabaseManager *db)
{
    m_db = db;
    if (!m_db) return;
    // Load persisted notification state
    const QString saved = m_db->loadSetting("notificationsEnabled", "true");
    m_notificationsEnabled = (saved == "true");
    applyNotificationState();
}

void SettingsPanel::applyNotificationState()
{
    if (m_notificationsEnabled) {
        if (m_notifStatusLabel) {
            m_notifStatusLabel->setText("Enabled");
            m_notifStatusLabel->setStyleSheet(
                "color: #4caf50; font-size: 13px; background: transparent; border: none;"
                );
        }
        if (m_notifToggleBtn) {
            m_notifToggleBtn->setText("Disable");
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
        }
        if (m_messageAlertsLabel) m_messageAlertsLabel->setText("On");
        if (m_soundLabel)         m_soundLabel->setText("On");
    } else {
        if (m_notifStatusLabel) {
            m_notifStatusLabel->setText("Disabled");
            m_notifStatusLabel->setStyleSheet(
                "color: #555555; font-size: 13px; background: transparent; border: none;"
                );
        }
        if (m_notifToggleBtn) {
            m_notifToggleBtn->setText("Enable");
            m_notifToggleBtn->setStyleSheet(
                "QPushButton {"
                "  background-color: #1a2e1c;"
                "  color: #5dd868;"
                "  border: 1px solid #2e5e30;"
                "  border-radius: 6px;"
                "  font-size: 12px;"
                "}"
                "QPushButton:hover { background-color: #223a24; }"
                );
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
        "  background-color: #2e1a1a;"
        "  color: #cc5555;"
        "  border: 1px solid #5e2e2e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: #3a2020; }"
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
    exportBtn->setStyleSheet(
        "QPushButton#exportContactsBtn {"
        "  background-color: #1a2e1c;"
        "  color: #5dd868;"
        "  border: 1px solid #2e5e30;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton#exportContactsBtn:hover { background-color: #223a24; }"
        );
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
    importBtn->setStyleSheet(
        "QPushButton#importContactsBtn {"
        "  background-color: #1a1a2e;"
        "  color: #5588dd;"
        "  border: 1px solid #2e2e5e;"
        "  border-radius: 6px;"
        "  font-size: 12px;"
        "}"
        "QPushButton#importContactsBtn:hover { background-color: #22223a; }"
        );
    connect(importBtn, &QPushButton::clicked,
            this, &SettingsPanel::importContactsClicked);

    il->addWidget(importLabel);
    il->addStretch();
    il->addWidget(importBtn);
    cardLayout->addWidget(importRow);

    return card;
}

void SettingsPanel::onToggleNotifications()
{
    m_notificationsEnabled = !m_notificationsEnabled;
    applyNotificationState();

    // Persist to DB
    if (m_db)
        m_db->saveSetting("notificationsEnabled",
                          m_notificationsEnabled ? "true" : "false");

    // DND overrides: if DND is on, keep notifications suppressed regardless
    emit notificationsToggled(m_notificationsEnabled && !m_dndEnabled);
}

void SettingsPanel::onToggleDnd()
{
    m_dndEnabled = !m_dndEnabled;

    if (m_dndEnabled) {
        m_dndStatusLabel->setText("On");
        m_dndStatusLabel->setStyleSheet(
            "color: #cc5555; font-size: 13px; background: transparent; border: none;"
            );
        m_dndToggleBtn->setText("Disable");
        m_dndToggleBtn->setStyleSheet(
            "QPushButton {"
            "  background-color: #1a2e1c;"
            "  color: #5dd868;"
            "  border: 1px solid #2e5e30;"
            "  border-radius: 6px;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover { background-color: #223a24; }"
            );
    } else {
        m_dndStatusLabel->setText("Off");
        m_dndStatusLabel->setStyleSheet(
            "color: #555555; font-size: 13px; background: transparent; border: none;"
            );
        m_dndToggleBtn->setText("Enable");
        m_dndToggleBtn->setStyleSheet(
            "QPushButton {"
            "  background-color: #2e1a1a;"
            "  color: #cc5555;"
            "  border: 1px solid #5e2e2e;"
            "  border-radius: 6px;"
            "  font-size: 12px;"
            "}"
            "QPushButton:hover { background-color: #3a2020; }"
            );
    }

    // DND suppresses notifications; restores them when turned off if global toggle is on
    emit notificationsToggled(m_notificationsEnabled && !m_dndEnabled);
}
