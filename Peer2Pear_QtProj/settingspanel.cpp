#include "settingspanel.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QPushButton>

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
    bodyLayout->addWidget(makeSection("PROFILE", {
                                                  { "Display Name", "You"      },
                                                  { "Handle",       "@handle"  },
                                                  { "Status",       "Online"   },
                                                  }));

    // ── Privacy & Security section ────────────────────────────────────────────
    bodyLayout->addWidget(makeSection("PRIVACY & SECURITY", {
                                                             { "End-to-End Encryption", "Enabled"   },
                                                             { "Read Receipts",         "On"        },
                                                             { "Last Seen",             "Everyone"  },
                                                             }));

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

// Builds a static read-only section card
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
    QFrame *div1 = new QFrame();
    div1->setFrameShape(QFrame::HLine);
    div1->setStyleSheet(
        "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
        );
    cardLayout->addWidget(div1);

    // ── Message Alerts row ────────────────────────────────────────────────────
    auto makeStaticRow = [&](const QString &label, const QString &value) {
        QWidget *row = new QWidget();
        row->setStyleSheet("background: transparent; border: none;");

        QHBoxLayout *rl = new QHBoxLayout(row);
        rl->setContentsMargins(16, 10, 16, 10);
        rl->setSpacing(8);

        QLabel *key = new QLabel(label);
        key->setStyleSheet(
            "color: #cccccc; font-size: 13px; background: transparent; border: none;"
            );

        QLabel *val = new QLabel(value);
        val->setStyleSheet(
            "color: #555555; font-size: 13px; background: transparent; border: none;"
            );
        val->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        rl->addWidget(key);
        rl->addStretch();
        rl->addWidget(val);

        return row;
    };

    cardLayout->addWidget(makeStaticRow("Message Alerts", "On"));

    QFrame *div2 = new QFrame();
    div2->setFrameShape(QFrame::HLine);
    div2->setStyleSheet(
        "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
        );
    cardLayout->addWidget(div2);

    cardLayout->addWidget(makeStaticRow("Sound", "On"));

    QFrame *div3 = new QFrame();
    div3->setFrameShape(QFrame::HLine);
    div3->setStyleSheet(
        "color: #1e1e1e; background-color: #1e1e1e; border: none; max-height: 1px;"
        );
    cardLayout->addWidget(div3);

    cardLayout->addWidget(makeStaticRow("Do Not Disturb", "Off"));

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

    if (m_notificationsEnabled) {
        m_notifStatusLabel->setText("Enabled");
        m_notifStatusLabel->setStyleSheet(
            "color: #4caf50; font-size: 13px; background: transparent; border: none;"
            );
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
    } else {
        m_notifStatusLabel->setText("Disabled");
        m_notifStatusLabel->setStyleSheet(
            "color: #555555; font-size: 13px; background: transparent; border: none;"
            );
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

    emit notificationsToggled(m_notificationsEnabled);
}
