#include "chatview.h"
#include "QrImage.hpp"
#include "theme.h"
#include "theme_styles.h"
#include "ui_mainwindow.h"

#include <algorithm>
#include <utility>
#include <unordered_set>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QScrollArea>
#include <QScrollBar>
#include <QFontMetrics>
#include <QApplication>
#include <QDialog>
#include <QFrame>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QListWidget>
#include <QToolButton>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <QUuid>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QTimer>
#include <QRegularExpression>
#include <QDesktopServices>
#include <QUrl>
#include <QPainter>
#include <QPainterPath>
#include <QBuffer>
#include <QColorDialog>
#include <QKeyEvent>
#include <QClipboard>

// ── Key validation ───────────────────────────────────────────────────────────
// Ed25519 public key: 32 bytes → 43 base64url characters (no padding).
static bool isValidPublicKey(const QString &key)
{
    static const QRegularExpression rx("^[A-Za-z0-9_-]{43}$");
    return rx.match(key).hasMatch();
}

// ── ChatController boundary helpers ─────────────────────────────────────────
// ChatController's public surface is std-typed.  Convert at the boundary;
// the desktop UI keeps using QString/QStringList internally.
static std::vector<std::string> qListToStd(const QStringList& qs)
{
    std::vector<std::string> out;
    out.reserve(int(qs.size()));
    for (const QString& s : qs) out.push_back(s.toStdString());
    return out;
}

// ── renderInitialsAvatar ──────────────────────────────────────────────────────
static QPixmap renderInitialsAvatar(const QString &initial, const QColor &bg, int size)
{
    QPixmap pm(size, size);
    pm.setDevicePixelRatio(1.0);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(bg); p.setPen(Qt::NoPen);
    p.drawEllipse(0, 0, size, size);
    QFont f = p.font(); f.setBold(true); f.setPixelSize(size / 2); p.setFont(f);
    p.setPen(Qt::white);
    p.drawText(QRect(0, 0, size, size), Qt::AlignCenter, initial.toUpper());
    p.end();
    return pm;
}

// ── Avatar palette ────────────────────────────────────────────────────────────
// One palette shared by all avatar-rendering sites in this file.
static const QList<QColor> kAvatarPalette = {
    QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
    QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a), QColor(0x1a, 0x4a, 0x6a),
};

// Returns a stable palette color derived from the contact name.
// Uses Qt's qHash for a well-distributed, overflow-safe result.
static QColor avatarColorForName(const QString &name)
{
    const uint hash = qHash(name);
    return kAvatarPalette[hash % static_cast<uint>(kAvatarPalette.size())];
}

// ── makeCircularPixmap ────────────────────────────────────────────────────────
static QPixmap makeCircularPixmap(const QPixmap &src, int size)
{
    if (size <= 0 || src.isNull()) return QPixmap();
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);

    QPainterPath path;
    path.addEllipse(0, 0, size, size);
    p.setClipPath(path);
    const QPixmap scaled = src.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    p.drawPixmap((size - scaled.width()) / 2, (size - scaled.height()) / 2, scaled);
    p.end();
    return pm;
}

// ── Last-seen formatter ──────────────────────────────────────────────────────
static QString formatLastSeen(const QDateTime &utc)
{
    if (!utc.isValid()) return "Offline";
    const QDateTime local = utc.toLocalTime();
    const QDateTime now   = QDateTime::currentDateTime();
    const qint64 secsAgo  = local.secsTo(now);

    if (secsAgo <        60) return "Last seen just now";
    if (secsAgo <      3600) return QString("Last seen %1m ago").arg(secsAgo / 60);
    if (secsAgo <     86400) return QString("Last seen %1h ago").arg(secsAgo / 3600);
    if (local.date() == now.date().addDays(-1))
        return "Last seen yesterday " + local.toString("h:mm AP");
    if (secsAgo < 7 * 86400)
        return "Last seen " + local.toString("ddd h:mm AP");
    return "Last seen " + local.toString("MMM d");
}

// ── Constants ─────────────────────────────────────────────────────────────────
static constexpr int kDateSepSecs = 60 * 60 * 2; // 2-hour gap → date separator

// ── Date separator label ──────────────────────────────────────────────────────
static QString formatSepLabel(const QDateTime &dt)
{
    const QDate today     = QDate::currentDate();
    const QDate yesterday = today.addDays(-1);
    const QDate d         = dt.toLocalTime().date();

    QString part = (d == today) ? "Today"
                   : (d == yesterday) ? "Yesterday"
                                      : dt.toLocalTime().toString("ddd, MMM d");
    return part + " at " + dt.toLocalTime().toString("h:mm AP");
}

// ── Text-layout helpers ───────────────────────────────────────────────────────
static QString hyphenateWord(const QString &word, const QFontMetrics &fm, int maxW)
{
    QString result, cur;
    for (QChar c : word) {
        QString test = cur + c;
        if (fm.horizontalAdvance(test + "-") >= maxW && !cur.isEmpty()) {
            result += cur + "-\n";
            cur = c;
        } else {
            cur = test;
        }
    }
    return result + cur;
}

static QString processText(const QString &text, const QFontMetrics &fm, int maxW)
{
    QStringList out;
    for (const QString &w : text.split(' '))
        out << (fm.horizontalAdvance(w) > maxW ? hyphenateWord(w, fm, maxW) : w);
    return out.join(' ');
}

// Applies the theme-aware dialog stylesheet + tags the dialog so the
// classifier picks it up on a live theme flip while the dialog is
// open.  Replaces the previous `static const char* kDlgStyle` which
// was hardcoded dark.
static inline void applyDialogStyle(QWidget* dlg) {
    dlg->setProperty("p2pRole", QLatin1String("dialog"));
    dlg->setStyleSheet(themeStyles::dialogCss(
        ThemeManager::instance().current()));
}

// Opens a modal dialog to edit a contact name + list of public keys.
// nameInOut and keysInOut are updated on Save; returns false on Cancel.
enum class ContactEditorResult { Cancelled, Saved, Blocked, Removed, Left, SessionReset };
static ContactEditorResult openContactEditor(QWidget *parent,
                                             const QString &title,
                                             QString &nameInOut,
                                             QStringList &keysInOut,
                                             bool showDestructiveActions = true,
                                             bool isBlocked = false,
                                             bool isGroup = false,
                                             const std::vector<AppDataStore::Contact> *allContacts = nullptr,
                                             std::function<void(const AppDataStore::Contact&)> onNewContact = nullptr,
                                             QString *avatarInOut = nullptr,
                                             ChatController *controller = nullptr)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    applyDialogStyle(&dlg);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    auto *titleLbl = new QLabel(title, &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    // ── Group avatar row (only when avatarInOut provided) ─────────────────────
    QString localAvatar = avatarInOut ? *avatarInOut : QString();
    QPixmap localAvatarRaw; // raw upload — converted to base64 only at Save time
    // Declared at function scope so lambdas connected inside the if-block below
    // don't capture dangling references after the block exits.
    QLabel *avatarThumb = nullptr;
    std::function<void()> refreshGroupThumb;
    if (isGroup && avatarInOut) {
        auto *avatarRow = new QHBoxLayout;
        avatarRow->setSpacing(14);

        avatarThumb = new QLabel(&dlg);
        avatarThumb->setFixedSize(56, 56);
        avatarThumb->setAlignment(Qt::AlignCenter);

        refreshGroupThumb = [&]() {
            QPixmap px;
            if (!localAvatarRaw.isNull()) {
                px = makeCircularPixmap(localAvatarRaw, 56);
            } else if (!localAvatar.isEmpty()) {
                QPixmap src;
                src.loadFromData(QByteArray::fromBase64(localAvatar.toUtf8()));
                if (!src.isNull()) px = makeCircularPixmap(src, 56);
            }
            if (px.isNull()) {
                const QString ch = nameInOut.isEmpty() ? "#" : QString(nameInOut[0]);
                px = renderInitialsAvatar(ch, QColor(0x2e, 0x8b, 0x3a), 56);
            }
            avatarThumb->setPixmap(px);
        };
        refreshGroupThumb();

        auto *changePhotoBtn = new QPushButton("Change Photo", &dlg);
        changePhotoBtn->setAutoDefault(false);
        themeStyles::applyRole(changePhotoBtn, "dialogNeutralBtn",
            themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));

        // Inline photo options — toggled by changePhotoBtn
        auto *photoOptionsGroup = new QWidget(&dlg);
        photoOptionsGroup->setVisible(false);
        auto *poLayout = new QVBoxLayout(photoOptionsGroup);
        poLayout->setContentsMargins(0, 4, 0, 4);
        poLayout->setSpacing(8);

        auto *pUpload = new QPushButton("Upload Photo", photoOptionsGroup);
        pUpload->setAutoDefault(false);
        themeStyles::applyRole(pUpload, "dialogNeutralBtn",
            themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
        QObject::connect(pUpload, &QPushButton::clicked, [&]() {
            const QString path = QFileDialog::getOpenFileName(
                &dlg, "Choose Photo", QString(),
                "Images (*.png *.jpg *.jpeg *.bmp)");
            if (path.isEmpty()) return;
            QPixmap px(path);
            if (px.isNull()) return;
            localAvatarRaw = px;
            refreshGroupThumb();
        });
        poLayout->addWidget(pUpload);

        auto *pReset = new QPushButton("Reset to Default", photoOptionsGroup);
        pReset->setAutoDefault(false);
        pReset->setObjectName("cancelBtn");
        QObject::connect(pReset, &QPushButton::clicked, [&]() {
            localAvatarRaw = QPixmap();
            localAvatar.clear();
            refreshGroupThumb();
        });
        poLayout->addWidget(pReset);

        QObject::connect(changePhotoBtn, &QPushButton::clicked, [&, photoOptionsGroup, changePhotoBtn]() {
            const bool v = !photoOptionsGroup->isVisible();
            photoOptionsGroup->setVisible(v);
            changePhotoBtn->setText(v ? "Done" : "Change Photo");
            dlg.adjustSize();
        });

        avatarRow->addWidget(avatarThumb);
        avatarRow->addWidget(changePhotoBtn);
        avatarRow->addStretch();
        root->addLayout(avatarRow);
        root->addWidget(photoOptionsGroup);
    }

    root->addWidget(new QLabel("Display Name", &dlg));
    auto *nameEdit = new QLineEdit(nameInOut, &dlg);
    root->addWidget(nameEdit);

    // ── Keys / Members section ────────────────────────────────────────────────
    QListWidget *memberList = nullptr; // only used for groups
    QListWidget *keyList    = nullptr; // only used for contacts

    if (isGroup && allContacts) {
        auto *membersLbl = new QLabel("Members", &dlg);
        root->addWidget(membersLbl);

        memberList = new QListWidget(&dlg);
        memberList->setFixedHeight(160);

        for (const QString &key : keysInOut) {
            QString displayName = "Unknown Contact";
            const std::string keyStd = key.toStdString();
            for (const AppDataStore::Contact &c : *allContacts) {
                if (!c.isGroup && std::find(c.keys.begin(), c.keys.end(), keyStd) != c.keys.end()) {
                    displayName = qtbridge::qstr(c.name);
                    break;
                }
            }
            auto *item = new QListWidgetItem(displayName, memberList);
            item->setData(Qt::UserRole, key);
            item->setToolTip(key);
        }
        root->addWidget(memberList);

        auto *addMemberRow = new QHBoxLayout;
        auto *addMemberBtn = new QPushButton("Add Member", &dlg);
        addMemberRow->addStretch();
        addMemberRow->addWidget(addMemberBtn);
        root->addLayout(addMemberRow);

        // Double-click member to remove
        QObject::connect(memberList, &QListWidget::itemDoubleClicked, [&](QListWidgetItem *item) {
            const QString key  = item->data(Qt::UserRole).toString();
            const QString name = item->text();

            if (name == "Unknown Contact") {
                // Open contact editor directly — avoids triple-nested exec() on macOS
                QString newName;
                QStringList newKeys = { key };
                if (openContactEditor(nullptr, "Add Contact", newName, newKeys, false)
                        == ContactEditorResult::Saved && !newName.isEmpty()) {
                    item->setText(newName);
                    if (onNewContact) {
                        AppDataStore::Contact newContact;
                        newContact.name       = newName.toStdString();
                        newContact.subtitle   = "Secure chat";
                        newContact.keys       = qtbridge::stdstrList(newKeys);
                        newContact.peerIdB64u = newKeys.isEmpty() ? std::string() : newKeys.first().toStdString();
                        onNewContact(newContact);
                    }
                }
            } else {
                // Known contact — open their contact editor
                if (allContacts) {
                    const std::string keyStd = key.toStdString();
                    for (const AppDataStore::Contact &c : *allContacts) {
                        if (!c.isGroup && std::find(c.keys.begin(), c.keys.end(), keyStd) != c.keys.end()) {
                            QString contactName = qtbridge::qstr(c.name);
                            QStringList contactKeys = qtbridge::qstrList(c.keys);
                            openContactEditor(nullptr, "Edit Contact", contactName, contactKeys,
                                              false); // no destructive actions from inside group editor
                            // Update display name in case they were renamed
                            item->setText(contactName);
                            break;
                        }
                    }
                }
            }
        });

        // Add member — pick from contacts
        QObject::connect(addMemberBtn, &QPushButton::clicked, [&]() {
            QDialog picker(&dlg);
            picker.setWindowTitle("Add Member");
            applyDialogStyle(&picker);
            picker.setMinimumWidth(340);
            auto *pLayout = new QVBoxLayout(&picker);
            pLayout->setSpacing(12);
            pLayout->setContentsMargins(24, 24, 24, 24);

            auto *pTitle = new QLabel("Select Contact", &picker);
            pTitle->setObjectName("dlgTitle");
            pLayout->addWidget(pTitle);

            auto *pList = new QListWidget(&picker);
            for (const AppDataStore::Contact &c : *allContacts) {
                if (c.isGroup || c.keys.empty()) continue;
                const QString firstKey = qtbridge::qstr(c.keys.front());
                bool alreadyIn = false;
                for (int i = 0; i < memberList->count(); ++i) {
                    if (memberList->item(i)->data(Qt::UserRole).toString() == firstKey) {
                        alreadyIn = true;
                        break;
                    }
                }
                if (alreadyIn) continue;
                auto *item = new QListWidgetItem(qtbridge::qstr(c.name), pList);
                item->setData(Qt::UserRole, qtbridge::qstrList(c.keys).join('|'));
            }
            pLayout->addWidget(pList);

            auto *pBtnRow = new QHBoxLayout;
            auto *pCancel = new QPushButton("Cancel", &picker);
            auto *pAdd    = new QPushButton("Add", &picker);
            pCancel->setObjectName("cancelBtn");
            pAdd->setObjectName("saveBtn");
            pBtnRow->addStretch();
            pBtnRow->addWidget(pCancel);
            pBtnRow->addWidget(pAdd);
            pLayout->addLayout(pBtnRow);

            QObject::connect(pCancel, &QPushButton::clicked, &picker, &QDialog::reject);
            QObject::connect(pAdd,    &QPushButton::clicked, &picker, &QDialog::accept);

            if (picker.exec() != QDialog::Accepted) return;
            if (!pList->currentItem()) return;

            const QStringList contactKeys = pList->currentItem()
                                                ->data(Qt::UserRole).toString().split('|', Qt::SkipEmptyParts);
            const QString contactName = pList->currentItem()->text();

            for (const QString &key : contactKeys) {
                bool exists = false;
                for (int i = 0; i < memberList->count(); ++i) {
                    if (memberList->item(i)->data(Qt::UserRole).toString() == key) {
                        exists = true; break;
                    }
                }
                if (!exists) {
                    auto *newItem = new QListWidgetItem(contactName, memberList);
                    newItem->setData(Qt::UserRole, key);
                    newItem->setToolTip(key);
                }
            }
        });

    } else {
        // ── Regular contact — single public key ──────────────────────────────
        root->addWidget(new QLabel("Public Key", &dlg));

        auto *keyInput = new QLineEdit(&dlg);
        keyInput->setPlaceholderText("Paste their 43-character public key…");
        if (!keysInOut.isEmpty()) keyInput->setText(keysInOut.first());
        keyInput->setProperty("_singleKeyInput", true);   // tag for save logic
        root->addWidget(keyInput);
    }

    // ── Safety number (1:1 contacts only, controller available) ─────────
    // Shows the 60-digit out-of-band verification code.  User reads it
    // aloud (or scans a future QR) with the peer and taps "Mark as
    // verified" once confirmed.  Stored fingerprint is derived from
    // current (self, peer) Ed25519 pubs; unverify on request.
    if (!isGroup && controller && !keysInOut.isEmpty()) {
        const std::string peerIdStd = keysInOut.first().trimmed().toStdString();
        // Only show if the key is well-formed — otherwise the current
        // trust query returns junk.
        if (peerIdStd.size() == 43) {
            auto *sn = new QFrame(&dlg);
            sn->setFrameShape(QFrame::HLine);
            sn->setStyleSheet("color: #2a2a2a;");
            root->addWidget(sn);

            auto *lbl = new QLabel("Safety Number", &dlg);
            lbl->setStyleSheet("color:#d0d0d0;font-size:13px;background:transparent;");
            root->addWidget(lbl);

            const QString number = QString::fromStdString(
                controller->safetyNumber(peerIdStd));
            auto *numLbl = new QLabel(number, &dlg);
            numLbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
            themeStyles::applyRole(numLbl, "safetyNumber",
                themeStyles::safetyNumberCss(ThemeManager::instance().current()));
            numLbl->setWordWrap(true);
            root->addWidget(numLbl);

            const auto trust = controller->peerTrust(peerIdStd);
            auto *statusLbl = new QLabel(&dlg);
            auto *verifyBtn = new QPushButton(&dlg);
            verifyBtn->setAutoDefault(false);

            auto refresh = [controller, peerIdStd, statusLbl, verifyBtn]() {
                const Theme& th = ThemeManager::instance().current();
                const auto t = controller->peerTrust(peerIdStd);
                if (t == ChatController::PeerTrust::Verified) {
                    statusLbl->setText("✓ Verified — compared out of band");
                    themeStyles::applyRole(statusLbl, "statusVerified",
                        themeStyles::statusVerifiedCss(th));
                    verifyBtn->setText("Unverify");
                } else if (t == ChatController::PeerTrust::Mismatch) {
                    statusLbl->setText(
                        "! Safety number changed — either you or they reinstalled. "
                        "Compare again before continuing.");
                    themeStyles::applyRole(statusLbl, "statusWarning",
                        themeStyles::statusWarningCss(th));
                    verifyBtn->setText("Re-verify");
                } else {
                    statusLbl->setText("Not yet verified — compare this number "
                                       "with your contact out of band.");
                    themeStyles::applyRole(statusLbl, "statusUnverified",
                        themeStyles::statusUnverifiedCss(th));
                    verifyBtn->setText("Mark as Verified");
                }
            };
            refresh();
            statusLbl->setWordWrap(true);
            root->addWidget(statusLbl);

            themeStyles::applyRole(verifyBtn, "dialogNeutralBtn",
                themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
            QObject::connect(verifyBtn, &QPushButton::clicked,
                [controller, peerIdStd, refresh]() {
                    if (controller->peerTrust(peerIdStd)
                            == ChatController::PeerTrust::Verified) {
                        controller->unverifyPeer(peerIdStd);
                    } else {
                        controller->markPeerVerified(peerIdStd);
                    }
                    refresh();
                });

            auto *verifyRow = new QHBoxLayout;
            verifyRow->addStretch();
            verifyRow->addWidget(verifyBtn);
            root->addLayout(verifyRow);
        }
    }

    root->addStretch();
    ContactEditorResult result = ContactEditorResult::Cancelled;

    // ── Destructive actions ───────────────────────────────────────────────────
    if (showDestructiveActions) {
        auto *actionSep = new QFrame(&dlg);
        actionSep->setFrameShape(QFrame::HLine);
        actionSep->setStyleSheet("color: #2a2a2a;");
        root->addWidget(actionSep);

        auto *actionRow = new QHBoxLayout;
        // Built from the active theme so destructive buttons in
        // light mode render as light-red pills with dark-red text
        // (Theme.dangerBg / Theme.dangerText) instead of the dark
        // brown-red the previous hardcoded sheet baked in.
        const QString destructiveStyle =
            themeStyles::destructiveBtnCss(ThemeManager::instance().current());

        // Block — contacts only
        if (!isGroup) {
            auto *blockBtn = new QPushButton(isBlocked ? "Unblock Contact" : "Block Contact", &dlg);
            themeStyles::applyRole(blockBtn, "destructiveBtn", destructiveStyle);
            actionRow->addWidget(blockBtn);
            QObject::connect(blockBtn, &QPushButton::clicked, [&]() {
                const QString msg = isBlocked
                                        ? "Unblock this contact?"
                                        : "Block this contact? They won't be able to send you messages.";
                if (QMessageBox::question(&dlg, isBlocked ? "Unblock Contact" : "Block Contact",
                                          msg, QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                    result = ContactEditorResult::Blocked;
                    dlg.accept();
                }
            });

            // Reset Session — wipe ratchet state to force fresh handshake.
            auto *resetBtn = new QPushButton("Reset Session", &dlg);
            themeStyles::applyRole(resetBtn, "destructiveBtn", destructiveStyle);
            actionRow->addWidget(resetBtn);
            QObject::connect(resetBtn, &QPushButton::clicked, [&]() {
                if (QMessageBox::question(&dlg, "Reset Session",
                        "Reset the encrypted session with this contact?\n\n"
                        "A new handshake will happen automatically on the next message. "
                        "Use this if messages aren't decrypting properly.",
                        QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                    result = ContactEditorResult::SessionReset;
                    dlg.accept();
                }
            });
        }

        // Leave — groups only
        if (isGroup) {
            auto *leaveBtn = new QPushButton("Leave Group", &dlg);
            themeStyles::applyRole(leaveBtn, "destructiveBtn", destructiveStyle);
            actionRow->addWidget(leaveBtn);
            QObject::connect(leaveBtn, &QPushButton::clicked, [&]() {
                if (QMessageBox::question(&dlg, "Leave Group",
                                          "Leave this group? You will stop receiving messages.",
                                          QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                    result = ContactEditorResult::Left;
                    dlg.accept();
                }
            });
        }

        // Remove/Delete — always shown
        auto *removeBtn = new QPushButton(isGroup ? "Delete Group" : "Remove Contact", &dlg);
        themeStyles::applyRole(removeBtn, "destructiveBtn", destructiveStyle);
        actionRow->addWidget(removeBtn);
        actionRow->addStretch();
        root->addLayout(actionRow);

        QObject::connect(removeBtn, &QPushButton::clicked, [&]() {
            const QString msg = isGroup
                                    ? "Delete this group? This cannot be undone."
                                    : "Remove this contact? This cannot be undone.";
            if (QMessageBox::question(&dlg, isGroup ? "Delete Group" : "Remove Contact",
                                      msg, QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                result = ContactEditorResult::Removed;
                dlg.accept();
            }
        });
    }

    // ── Save / Cancel ─────────────────────────────────────────────────────────
    auto *btnRow    = new QHBoxLayout;
    auto *cancelBtn = new QPushButton("Cancel", &dlg);
    auto *saveBtn   = new QPushButton("Save", &dlg);
    cancelBtn->setObjectName("cancelBtn");
    saveBtn->setObjectName("saveBtn");
    saveBtn->setDefault(true);
    btnRow->setSpacing(10);
    btnRow->addStretch();
    btnRow->addWidget(cancelBtn);
    btnRow->addWidget(saveBtn);
    root->addLayout(btnRow);

    QObject::connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(saveBtn, &QPushButton::clicked, [&]() {
        result = ContactEditorResult::Saved;
        dlg.accept();
    });

    dlg.exec();

    if (result == ContactEditorResult::Saved) {
        nameInOut = nameEdit->text().trimmed();
        keysInOut.clear();
        if (isGroup && memberList) {
            for (int i = 0; i < memberList->count(); ++i)
                keysInOut << memberList->item(i)->data(Qt::UserRole).toString();
        } else {
            // Find the single-key QLineEdit we tagged earlier
            for (QLineEdit *le : dlg.findChildren<QLineEdit*>()) {
                if (le->property("_singleKeyInput").toBool()) {
                    const QString k = le->text().trimmed();
                    if (!k.isEmpty()) keysInOut << k;
                    break;
                }
            }
        }
        if (avatarInOut) {
            if (!localAvatarRaw.isNull()) {
                QPixmap circ = makeCircularPixmap(localAvatarRaw, 200);
                QByteArray bytes; QBuffer buf(&bytes);
                buf.open(QIODevice::WriteOnly);
                circ.save(&buf, "PNG");
                localAvatar = QString::fromLatin1(bytes.toBase64());
            }
            *avatarInOut = localAvatar;
        }
    }
    return result;
}
// ── ChatView implementation ───────────────────────────────────────────────────

// Returns a stable string key for file-record lookup: peerIdB64u for DMs,
// groupId for group chats.  Never changes when the chat is reordered.
QString ChatView::chatKey(const AppDataStore::Contact &c)
{
    if (c.isGroup)             return qtbridge::qstr(c.groupId);
    if (!c.peerIdB64u.empty()) return qtbridge::qstr(c.peerIdB64u);
    return "name:" + qtbridge::qstr(c.name);
}

ChatView::ChatView(Ui::MainWindow *ui, ChatController *controller,
                   AppDataStore *store, QObject *parent)
    : QObject(parent), m_ui(ui), m_controller(controller), m_store(store)
{
    initChats();
    ensureUnreadSize();

    connect(m_ui->chatList,      &QListWidget::currentRowChanged, this, &ChatView::onChatSelected);
    connect(m_ui->sendBtn,       &QPushButton::clicked,           this, &ChatView::onSendMessage);
    connect(m_ui->messageInput,  &QLineEdit::returnPressed,       this, &ChatView::onSendMessage);
    connect(m_ui->searchEdit_12, &QLineEdit::textChanged,         this, &ChatView::onSearchChanged);

    // Enter / Shift+Enter to navigate search matches
    m_ui->searchEdit_12->installEventFilter(this);

    connect(m_ui->editProfileBtn,&QToolButton::clicked,           this, &ChatView::onEditProfile);
    connect(m_ui->addContactBtn, &QToolButton::clicked,           this, &ChatView::onAddContact);
    connect(m_ui->attachBtn,     &QToolButton::clicked,           this, &ChatView::onAttachFile);

    rebuildChatList();
    m_ui->chatList->setCurrentRow(0);

    // Start presence polling (check every 30 seconds)
    startPresencePolling(30000);

    // Re-style chat surfaces (bubbles, sender labels, ...) on theme
    // flips.  ThemeManager handles the qApp-wide palette + stylesheet;
    // this call covers widgets ChatView created at runtime with their
    // own setStyleSheet.
    QObject::connect(&ThemeManager::instance(), &ThemeManager::themeChanged,
                     this, [this](const Theme& t) {
        if (m_ui && m_ui->centralwidget) {
            themeStyles::reapplyForChildren(m_ui->centralwidget, t);
        }
    });
    // Initial pass: handles whatever bubbles already landed during
    // initChats() before the ThemeManager preference is loaded from DB.
    if (m_ui && m_ui->centralwidget) {
        themeStyles::reapplyForChildren(m_ui->centralwidget,
                                         ThemeManager::instance().current());
    }
}

bool ChatView::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == m_ui->searchEdit_12 && event->type() == QEvent::KeyPress) {
        auto *ke = static_cast<QKeyEvent*>(event);
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            if (ke->modifiers() & Qt::ShiftModifier)
                navigateSearch(-1);   // Shift+Enter = previous
            else
                navigateSearch(+1);   // Enter = next
            return true;              // consume the event
        }
        if (ke->key() == Qt::Key_Escape) {
            m_ui->searchEdit_12->clear();
            m_ui->searchEdit_12->clearFocus();
            return true;
        }
    }
    return QObject::eventFilter(obj, event);
}

void ChatView::startPresencePolling(int /*intervalMs*/)
{
    // Subscribe to presence updates via the relay (push-based, not polling).
    // ChatController is no longer a QObject; we assign its onRelayConnected
    // callback directly.  Assignment replaces any prior handler — that's fine
    // because only ChatView registers for this event.
    m_controller->onRelayConnected = [this]() {
        subscribeAllPresence();
    };

    // Initial subscription (if relay is already connected)
    QTimer::singleShot(500, this, [this]() {
        subscribeAllPresence();
    });
}

void ChatView::subscribeAllPresence()
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> peerIds;
    const std::string myKey = m_controller->myIdB64u();
    for (const auto &c : m_chats) {
        for (const std::string &k : c.keys) {
            // Trim whitespace in place (keys may carry newlines from paste).
            const auto first = k.find_first_not_of(" \t\r\n");
            const auto last  = k.find_last_not_of(" \t\r\n");
            if (first == std::string::npos) continue;
            std::string trimmed = k.substr(first, last - first + 1);
            if (trimmed == myKey) continue;
            if (seen.insert(trimmed).second)
                peerIds.push_back(std::move(trimmed));
        }
    }
    if (!peerIds.empty())
        m_controller->subscribePresence(peerIds);
}

void ChatView::onPresenceChanged(const QString &peerIdB64u, bool online)
{
    // Update global member-online map
    m_memberOnline[peerIdB64u] = online;
    const std::string peerIdStd = peerIdB64u.toStdString();

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].isGroup) {
            // Check if this peer is a member of the group
            bool isMember = false;
            for (const std::string &k : m_chats[i].keys)
                if (trimStd(k) == peerIdStd) { isMember = true; break; }
            if (!isMember) continue;

            // Update group header if this is the currently selected chat
            if (i == m_currentChat) {
                const std::string myKey = m_controller->myIdB64u();
                int onlineCount = 0, totalMembers = 0;
                for (const std::string &k : m_chats[i].keys) {
                    const std::string trimmed = trimStd(k);
                    if (trimmed.empty() || trimmed == myKey) continue;
                    ++totalMembers;
                    if (m_memberOnline.value(qtbridge::qstr(trimmed), false))
                        ++onlineCount;
                }
                const QString statusText = (totalMembers == 0)
                    ? qtbridge::qstr(m_chats[i].subtitle)
                    : QString("%1 of %2 members online").arg(onlineCount).arg(totalMembers);
                m_ui->chatSubLabel->setText(statusText);
                themeStyles::applyRole(m_ui->chatSubLabel,
                    onlineCount > 0 ? "onlineStatus" : "offlineStatus",
                    onlineCount > 0
                        ? themeStyles::onlineStatusCss(ThemeManager::instance().current())
                        : themeStyles::offlineStatusCss(ThemeManager::instance().current()));
            }
            continue;  // don't return — this peer may be in multiple groups
        }

        // 1:1 DM chat
        bool match = (trimStd(m_chats[i].peerIdB64u) == peerIdStd);
        if (!match) {
            for (const std::string &k : m_chats[i].keys)
                if (trimStd(k) == peerIdStd) { match = true; break; }
        }
        if (!match) continue;

        const bool wasOnline = m_memberOnline.value(peerIdB64u, false);
        (void)wasOnline;

        // Send our avatar on first contact only if it's a real photo
        if (online && m_chats[i].avatarB64.empty() && m_store
                && m_store->loadSetting("avatarIsPhoto") == "true") {
            const std::string myName   = m_store->loadSetting("displayName");
            const std::string myAvatar = m_store->loadSetting("avatarData");
            if (!myName.empty())
                m_controller->sendAvatar(peerIdStd, myName, myAvatar);
        }

        // Update the header if this is the currently selected chat
        if (i == m_currentChat) {
            const QString statusText = online
                                           ? "Online"
                                           : formatLastSeen(qtbridge::qdate(m_chats[i].lastActiveSecs));
            m_ui->chatSubLabel->setText("● " + statusText);
            themeStyles::applyRole(m_ui->chatSubLabel,
                online ? "onlineStatus" : "offlineStatus",
                online ? themeStyles::onlineStatusCss(ThemeManager::instance().current())
                       : themeStyles::offlineStatusCss(ThemeManager::instance().current()));
        }
    }
}

void ChatView::reloadCurrentChat()
{
    if (m_emptyLabel) {
        m_emptyLabel->resize(m_ui->contentWidget->size());
        m_emptyLabel->raise();
        m_emptyLabel->setVisible(m_chats.empty());
    }
}

// ── Incoming messages ─────────────────────────────────────────────────────────

void ChatView::onIncomingMessage(const QString &fromPeerIdB64u,
                                 const QString &text,
                                 const QDateTime &timestamp,
                                 const QString &msgId)
{
    const QString from = fromPeerIdB64u.trimmed();
    const std::string fromStd  = from.toStdString();
    const std::string textStd  = text.toStdString();
    const std::string msgIdStd = msgId.toStdString();
    const int64_t tsSecs       = qtbridge::epochSecs(timestamp);
    ensureUnreadSize();

    auto shouldToast = [&]() { return m_shouldToastFn ? m_shouldToastFn() : true; };

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].isGroup) continue;

        bool hit = (trimStd(m_chats[i].peerIdB64u) == fromStd);
        if (!hit) for (const std::string &k : m_chats[i].keys)
                if (trimStd(k) == fromStd) { hit = true; break; }
        if (!hit) continue;

        if (m_chats[i].isBlocked) return;

        auto &msgs = m_messagesByPeer[m_chats[i].peerIdB64u];

        // UI-side dedup against already-stored messages
        if (!msgIdStd.empty())
            for (const auto &m : msgs)
                if (m.msgId == msgIdStd) return;

        const bool needsSep = msgs.empty() ||
                              (tsSecs - msgs.back().timestampSecs) >= kDateSepSecs;

        AppDataStore::Message msg{false, textStd, tsSecs, msgIdStd, ""};
        msgs.push_back(msg);
        m_chats[i].lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
        if (m_store) { m_store->saveContact(m_chats[i]); m_store->saveMessage(m_chats[i].peerIdB64u, msg); }

        if (i == m_currentChat) {
            if (needsSep) addDateSeparator(timestamp);
            addMessageBubble(text, false);
            promoteChatToTop(i);
            rebuildChatList();
        } else {
            m_unread[i] += 1;
            emit unreadChanged(totalUnread());
            promoteChatToTop(i);
            rebuildChatList();
            if (m_notifier && shouldToast()) m_notifier->notify(qtbridge::qstr(m_chats[0].name), text);
        }
        return;
    }

    // Unknown sender — auto-create chat
    AppDataStore::Message msg{false, textStd, tsSecs, msgIdStd, ""};
    AppDataStore::Contact nc;
    nc.name = "Unknown contact";
    nc.subtitle = "Secure chat";
    nc.peerIdB64u = fromStd;
    nc.keys.push_back(fromStd);
    m_messagesByPeer[nc.peerIdB64u].push_back(msg);
    m_chats.insert(m_chats.begin(), nc);
    if (m_store) { m_store->saveContact(nc); m_store->saveMessage(fromStd, msg); }
    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;
    m_unread[0] += 1;
    emit unreadChanged(totalUnread());
    if (m_notifier && shouldToast()) m_notifier->notify("Unknown contact", text);
    rebuildChatList();
}

void ChatView::onStatus(const QString &s) { qDebug() << "[status]" << s; }

void ChatView::onIncomingGroupMessage(const QString &fromPeerIdB64u,
                                      const QString &groupId,
                                      const QString &groupName,
                                      const QStringList &memberKeys,
                                      const QString &text,
                                      const QDateTime &ts,
                                      const QString &msgId)
{
    const std::string groupIdStd  = groupId.toStdString();
    const std::string fromStd     = fromPeerIdB64u.toStdString();
    const std::string textStd     = text.toStdString();
    const std::string msgIdStd    = msgId.toStdString();
    const int64_t     tsSecs      = qtbridge::epochSecs(ts);

    int idx = -1;
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
        if (m_chats[i].isGroup && m_chats[i].groupId == groupIdStd) { idx = i; break; }

    if (idx == -1) {
        AppDataStore::Contact ng;
        ng.isGroup = true;
        ng.groupId = groupIdStd;
        ng.peerIdB64u = groupIdStd;
        ng.name = groupName.isEmpty() ? std::string("Group Chat") : groupName.toStdString();
        ng.subtitle = "Group chat";
        ng.keys.push_back(fromStd);
        m_chats.push_back(ng);
        if (m_store) m_store->saveContact(ng);
        idx = static_cast<int>(m_chats.size()) - 1;
        ensureUnreadSize();
        rebuildChatList();
    }

    AppDataStore::Contact &chat = m_chats[idx];
    if (chat.isBlocked) return;

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    // Merge any new member keys we didn't know about before
    // This is how members discover each other without manual key exchange
    bool keysUpdated = false;
    const std::string myKey = m_controller->myIdB64u();
    for (const QString &key : memberKeys) {
        const std::string keyStd = key.toStdString();
        const std::string keyTrimmed = trimStd(keyStd);
        if (keyTrimmed.empty()) continue;
        if (keyTrimmed == myKey) continue; // don't add own key to group member list
        if (std::find(chat.keys.begin(), chat.keys.end(), keyStd) == chat.keys.end()) {
            chat.keys.push_back(keyStd);
            keysUpdated = true;
        }
    }
    if (keysUpdated && m_store)
        m_store->saveContact(chat); // persist the updated key list

    // If text is empty this was a member-update-only message (no chat bubble needed).
    // Key merge above already ran, so just bail out.
    if (text.isEmpty())
        return;

    const std::string dbKey = chat.groupId.empty() ? ("name:" + chat.name) : chat.groupId;
    auto &msgs = m_messagesByPeer[dbKey];

    if (!msgIdStd.empty())
        for (const auto &m : msgs)
            if (m.msgId == msgIdStd) return;

    const bool needsSep = msgs.empty() ||
                          (tsSecs - msgs.back().timestampSecs) >= kDateSepSecs;

    // Look up sender name from contacts
    QString senderName = fromPeerIdB64u.left(8) + "..."; // fallback to truncated key
    for (const auto &c : m_chats) {
        if (!c.isGroup && std::find(c.keys.begin(), c.keys.end(), fromStd) != c.keys.end()) {
            senderName = qtbridge::qstr(c.name);
            break;
        }
    }

    AppDataStore::Message msg{false, textStd, tsSecs, msgIdStd, senderName.toStdString()};
    msgs.push_back(msg);
    chat.lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
    if (m_store) m_store->saveMessage(dbKey, msg);

    if (idx == m_currentChat) {
        if (needsSep) addDateSeparator(ts);
        addMessageBubble(text, false, senderName);
        promoteChatToTop(idx);
        rebuildChatList();
    } else {
        const QString chatName = qtbridge::qstr(chat.name);

        m_unread[idx] += 1;
        emit unreadChanged(totalUnread());
        promoteChatToTop(idx);
        rebuildChatList();
        if (m_notifier) m_notifier->notifyGroup(senderName, chatName, text);
    }
}

void ChatView::onGroupMemberLeft(const QString& fromPeerIdB64u,
                                 const QString& groupId,
                                 const QString& groupName,
                                 const QStringList& /*memberKeys*/,
                                 const QDateTime& ts,
                                 const QString& /*msgId*/)
{
    Q_UNUSED(groupName);
    const std::string fromStd    = fromPeerIdB64u.toStdString();
    const std::string groupIdStd = groupId.toStdString();
    const int64_t     tsSecs     = qtbridge::epochSecs(ts);

    // Find the group
    int targetIndex = -1;
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].isGroup && m_chats[i].groupId == groupIdStd) {
            targetIndex = i;
            break;
        }
    }
    if (targetIndex == -1) return;

    AppDataStore::Contact &chat = m_chats[targetIndex];

    // Remove the leaver's key from our local group member list
    chat.keys.erase(std::remove(chat.keys.begin(), chat.keys.end(), fromStd), chat.keys.end());
    if (m_store) m_store->saveContact(chat);

    // Find a display name for the leaver
    QString leaverName = fromPeerIdB64u.left(8) + "..."; // fallback to truncated key
    for (const auto &c : m_chats) {
        if (!c.isGroup && std::find(c.keys.begin(), c.keys.end(), fromStd) != c.keys.end()) {
            leaverName = qtbridge::qstr(c.name);
            break;
        }
    }

    // Show system message like Snapchat
    const QString systemText = leaverName + " left the group";
    AppDataStore::Message systemMsg{ false, systemText.toStdString(), tsSecs, "", "" };
    const std::string dbKey = chat.groupId.empty() ? ("name:" + chat.name) : chat.groupId;
    m_messagesByPeer[dbKey].push_back(systemMsg);
    if (m_store) m_store->saveMessage(dbKey, systemMsg);

    if (targetIndex == m_currentChat) {
        addMessageBubble(systemText, false);
        rebuildChatList();
    } else {
        m_unread[targetIndex] += 1;
        emit unreadChanged(totalUnread());
        rebuildChatList();
    }
}
// ── File chunk received ───────────────────────────────────────────────────────

void ChatView::onFileChunkReceived(const QString &fromPeerIdB64u,
                                   const QString &transferId,
                                   const QString &fileName,
                                   qint64         fileSize,
                                   int            chunksReceived,
                                   int            chunksTotal,
                                   const QString &savedPath,
                                   const QDateTime  &timestamp,
                                   const QString &groupId,
                                   const QString &groupName)
{
    const QString from = fromPeerIdB64u.trimmed();
    const std::string fromStd     = from.toStdString();
    const std::string groupIdStd  = groupId.toStdString();
    const std::string transferStd = transferId.toStdString();

    // Locate the chat this file belongs to — group chat or 1:1
    int chatIndex = -1;
    if (!groupIdStd.empty()) {
        // Find existing group chat by groupId, or create one
        for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
            if (m_chats[i].isGroup && m_chats[i].groupId == groupIdStd) { chatIndex = i; break; }

        if (chatIndex == -1) {
            AppDataStore::Contact ng;
            ng.isGroup = true;
            ng.groupId = groupIdStd;
            ng.peerIdB64u = groupIdStd;
            ng.name = groupName.isEmpty() ? std::string("Group Chat") : groupName.toStdString();
            ng.subtitle = "Group chat";
            ng.keys.push_back(fromStd);
            m_chats.push_back(ng);
            if (m_store) m_store->saveContact(ng);
            chatIndex = static_cast<int>(m_chats.size()) - 1;
            ensureUnreadSize();
            rebuildChatList();
        }
    } else {
        chatIndex = findOrCreateChatForPeer(from);
    }
    if (chatIndex < 0) return;
    if (m_chats[chatIndex].isBlocked) return;   // drop files from blocked contacts
    const QString key = chatKey(m_chats[chatIndex]);

    // Find an existing in-progress record for this transferId, or create one
    auto &records = m_filesByKey[key];
    AppDataStore::FileRecord *rec = nullptr;
    for (auto &r : records)
        if (r.transferId == transferStd) { rec = &r; break; }

    if (!rec) {
        // First chunk we've heard about — create the record
        AppDataStore::FileRecord newRec;
        newRec.transferId    = transferStd;
        newRec.chatKey       = key.toStdString();
        newRec.fileName      = fileName.toStdString();
        newRec.fileSize      = fileSize;
        newRec.peerIdB64u    = fromStd;
        newRec.peerName      = m_chats[chatIndex].name;
        newRec.timestampSecs = qtbridge::epochSecs(timestamp);
        newRec.sent          = false;
        newRec.status        = static_cast<int>(FileTransferStatus::Receiving);
        newRec.chunksTotal   = chunksTotal;
        newRec.chunksComplete = 0;
        records.push_back(newRec);
        rec = &records.back();
    }

    rec->chunksComplete = chunksReceived;
    rec->chunksTotal    = chunksTotal;

    const bool complete = (chunksReceived == chunksTotal);

    if (complete) {
        m_chats[chatIndex].lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();

        // FileTransferManager has already streamed the file to disk at savedPath.
        // An empty savedPath means the transfer failed (hash mismatch, write error, etc).
        const bool saved = !savedPath.isEmpty() && QFileInfo::exists(savedPath);
        if (saved) {
            rec->status    = static_cast<int>(FileTransferStatus::Complete);
            rec->savedPath = savedPath.toStdString();
        } else {
            rec->status = static_cast<int>(FileTransferStatus::Failed);
            qWarning() << "File transfer failed:" << fileName << "(no savedPath)";
        }

        if (m_store) m_store->saveFileRecord(key.toStdString(), *rec);

        // In-app toast + system tray notification
        {
            const QString senderName = qtbridge::qstr(m_chats[chatIndex].name);
            const QString toastMsg = saved
                ? QString("📎 %1 from %2").arg(fileName, senderName)
                : QString("⚠ File from %1 failed: %2").arg(senderName, fileName);
            showToast(toastMsg);
            if (m_notifier)
                m_notifier->notify(senderName, toastMsg);
        }

        // Clickable file bubble in chat
        if (chatIndex == m_currentChat)
            addFileBubble(fileName, fileSize, false);

        // Bump unread on the chat if it isn't currently open
        if (chatIndex != m_currentChat) {
            m_unread[chatIndex] += 1;
            emit unreadChanged(totalUnread());
            promoteChatToTop(chatIndex);
            rebuildChatList();
        }
    }

    // Refresh Files tab if this chat is visible
    if (chatIndex == m_currentChat)
        rebuildFilesTab();
}

// ── File chunk sent (sender-side progress) ────────────────────────────────────
// Updates the outbound FileRecord created in onAttachFile to show
// the running chunk count.  On the last chunk we flip status → Complete.
// Delivery confirmation arrives separately via onFileTransferDelivered.

void ChatView::onFileChunkSent(const QString &toPeerIdB64u,
                                const QString &transferId,
                                const QString & /*fileName*/,
                                qint64         /*fileSize*/,
                                int            chunksSent,
                                int            chunksTotal,
                                const QDateTime & /*timestamp*/,
                                const QString &groupId,
                                const QString & /*groupName*/)
{
    const std::string groupIdStd  = groupId.toStdString();
    const std::string transferStd = transferId.toStdString();

    // Locate the chat — group or 1:1.  For groups we key off groupId
    // (the transfer is per-group even though chunks fan out per-member).
    int chatIndex = -1;
    if (!groupIdStd.empty()) {
        for (int i = 0; i < static_cast<int>(m_chats.size()); ++i)
            if (m_chats[i].isGroup && m_chats[i].groupId == groupIdStd) { chatIndex = i; break; }
    } else {
        chatIndex = findChatForPeer(toPeerIdB64u.trimmed());
    }
    if (chatIndex < 0) return;

    const QString key = chatKey(m_chats[chatIndex]);
    auto &records = m_filesByKey[key];
    AppDataStore::FileRecord *rec = nullptr;
    for (auto &r : records) {
        if (r.transferId == transferStd && r.sent) { rec = &r; break; }
    }
    // No record yet?  onAttachFile creates the Sending record before chunks
    // fly, so this shouldn't happen — but guard against group fan-out races
    // where a second member's chunk arrives before the record was saved.
    if (!rec) return;

    rec->chunksComplete = chunksSent;
    rec->chunksTotal    = chunksTotal;
    if (chunksSent >= chunksTotal && chunksTotal > 0) {
        rec->status = static_cast<int>(FileTransferStatus::Complete);
        if (m_store) m_store->saveFileRecord(key.toStdString(), *rec);
    }

    if (chatIndex == m_currentChat)
        rebuildFilesTab();
}

// ── Avatar received ───────────────────────────────────────────────────────────

void ChatView::onAvatarReceived(const QString &peerIdB64u,
                                const QString &displayName,
                                const QString &avatarB64)
{
    const std::string peerIdStd   = peerIdB64u.toStdString();
    const std::string avatarStd   = avatarB64.toStdString();
    const std::string displayStd  = displayName.toStdString();

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].isGroup) continue;
        if (trimStd(m_chats[i].peerIdB64u) != peerIdStd) continue;

        // First genuine contact = had no avatar and now receiving one
        const bool firstTime = m_chats[i].avatarB64.empty() && !avatarStd.empty();

        // If this was previously an auto-created "Unknown contact" (text
        // arrived before any avatar), upgrade the name now that we know it.
        if (!displayStd.empty() && m_chats[i].name == "Unknown contact") {
            m_chats[i].name = displayStd;
            if (m_store) m_store->saveContact(m_chats[i]);
        }

        // Empty avatarB64 means the sender reset to default — clear so the UI
        // falls back to initials derived from our locally saved name for them
        m_chats[i].avatarB64 = avatarStd;

        // Persist to DB
        if (m_store) m_store->saveContactAvatar(peerIdStd, avatarStd);

        // Send our avatar back only on first receive to avoid infinite exchange loop
        if (firstTime && m_store) {
            const std::string myName   = m_store->loadSetting("displayName");
            const std::string myAvatar = m_store->loadSetting("avatarData");
            if (!myName.empty()) {
                const std::string myAvatarIsPhoto = m_store->loadSetting("avatarIsPhoto");
                const std::string broadcastAvatar = (myAvatarIsPhoto == "true") ? myAvatar : std::string();
                m_controller->sendAvatar(peerIdStd, myName, broadcastAvatar);
            }
        }

        // Rebuild the list so the avatar label updates immediately
        rebuildChatList();

        // Refresh the active chat header avatar if this contact is selected
        if (m_currentChat == i) {
            if (!avatarB64.isEmpty()) {
                QPixmap px;
                px.loadFromData(QByteArray::fromBase64(avatarB64.toUtf8()));
                if (!px.isNull()) {
                    m_ui->chatAvatarLabel->setPixmap(makeCircularPixmap(px, 44));
                    m_ui->chatAvatarLabel->setText("");
                }
            } else {
                const QString qName = qtbridge::qstr(m_chats[i].name);
                const QString ch = qName.isEmpty() ? "?" : QString(qName[0]);
                m_ui->chatAvatarLabel->setPixmap(
                    renderInitialsAvatar(ch, avatarColorForName(qName), 44));
                m_ui->chatAvatarLabel->setText("");
            }
            m_ui->chatTitleLabel->setText(qtbridge::qstr(m_chats[i].name));
        }

        if (firstTime)
            showToast(qtbridge::qstr(m_chats[i].name) + "'s profile has been updated");
        return;
    }

    // ── First-contact avatar from unknown peer ──────────────────────────────
    //
    // If we fall through, no matching contact exists.  Create the contact
    // here using the peer's announced display name + avatar so the chat
    // list shows them correctly from the first message (otherwise the
    // follow-up text would create an "Unknown contact" row with no name).
    AppDataStore::Contact nc;
    nc.name        = displayStd.empty() ? std::string("Unknown contact") : displayStd;
    nc.subtitle    = "Secure chat";
    nc.peerIdB64u  = peerIdStd;
    nc.keys.push_back(peerIdStd);
    nc.avatarB64   = avatarStd;
    nc.lastActiveSecs = QDateTime::currentDateTimeUtc().toSecsSinceEpoch();

    m_chats.insert(m_chats.begin(), nc);
    if (m_store) {
        m_store->saveContact(nc);
        if (!avatarStd.empty()) m_store->saveContactAvatar(peerIdStd, avatarStd);
    }

    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;

    rebuildChatList();

    // Reciprocate with our own avatar so the peer also gets our display
    // name / picture.  Only done on first-contact creation to avoid loops.
    if (m_store) {
        const std::string myName = m_store->loadSetting("displayName");
        if (!myName.empty()) {
            const std::string myAvatar        = m_store->loadSetting("avatarData");
            const std::string myAvatarIsPhoto = m_store->loadSetting("avatarIsPhoto");
            const std::string broadcastAvatar = (myAvatarIsPhoto == "true") ? myAvatar : std::string();
            m_controller->sendAvatar(peerIdStd, myName, broadcastAvatar);
        }
    }

    showToast("New contact: " + qtbridge::qstr(nc.name));
}

void ChatView::onGroupRenamed(const QString &groupId, const QString &newName)
{
    const std::string groupIdStd = groupId.toStdString();
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (!m_chats[i].isGroup || m_chats[i].groupId != groupIdStd) continue;
        m_chats[i].name = newName.toStdString();
        if (m_store) m_store->saveContact(m_chats[i]);
        rebuildChatList();
        if (m_currentChat == i)
            m_ui->chatTitleLabel->setText(newName);
        return;
    }
}

void ChatView::onGroupAvatarReceived(const QString &groupId, const QString &avatarB64)
{
    const std::string groupIdStd = groupId.toStdString();
    const std::string avatarStd  = avatarB64.toStdString();
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (!m_chats[i].isGroup || m_chats[i].groupId != groupIdStd) continue;

        // Only relay and persist if this is actually new to us
        if (m_chats[i].avatarB64 == avatarStd) return;

        m_chats[i].avatarB64 = avatarStd;
        if (m_store) m_store->saveContactAvatar(m_chats[i].peerIdB64u, avatarStd);

        // Relay to all group members so stragglers receive it too
        if (m_controller && !m_chats[i].keys.empty())
            m_controller->sendGroupAvatar(groupIdStd, avatarStd, m_chats[i].keys);

        rebuildChatList();
        if (m_currentChat == i) loadChat(i);
        return;
    }
}

// ── Attach / send file ────────────────────────────────────────────────────────

void ChatView::onAttachFile()
{
    if (m_currentChat < 0) return;

    const AppDataStore::Contact &chat = m_chats[m_currentChat];

    if (chat.keys.empty()) {
        QMessageBox::warning(m_ui->centralwidget, "No Keys",
                             "This contact has no public keys — cannot send a file securely.");
        return;
    }

    const QString path = QFileDialog::getOpenFileName(
        m_ui->centralwidget, "Send File",
        QStandardPaths::writableLocation(QStandardPaths::HomeLocation));
    if (path.isEmpty()) return;

    // Path-based: we never load the file into RAM. Just stat its size.
    QFileInfo finfo(path);
    if (!finfo.exists() || !finfo.isFile()) {
        QMessageBox::warning(m_ui->centralwidget, "Error", "File not found.");
        return;
    }
    const qint64 fileSize = finfo.size();
    constexpr qint64 kMax = ChatController::maxFileBytes();
    if (fileSize > kMax) {
        QMessageBox::warning(m_ui->centralwidget, "File Too Large",
                             QString("Maximum file size is %1 MB.\nThis file is %2.")
                                 .arg(kMax / (1024 * 1024)).arg(formatFileSize(fileSize)));
        return;
    }

    const QString fileName = finfo.fileName();

    // ── Send to all keys for this contact / group ──────────────────────────────
    std::string localTransferId;
    int totalChunks = 0;
    constexpr qint64 kChunk = 240LL * 1024;

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    if (chat.isGroup) {
        localTransferId = m_controller->sendGroupFile(
            chat.groupId, chat.name,
            chat.keys, fileName.toStdString(), path.toStdString());
        if (!localTransferId.empty())
            totalChunks = int((fileSize + kChunk - 1) / kChunk);
    } else {
        // 1:1: send to every key belonging to this contact
        for (const std::string &key : chat.keys) {
            const std::string keyTrim = trimStd(key);
            if (keyTrim.empty()) continue;
            const std::string tid = m_controller->sendFile(
                keyTrim, fileName.toStdString(), path.toStdString());
            if (!tid.empty() && localTransferId.empty()) {
                localTransferId = tid;
                totalChunks = int((fileSize + kChunk - 1) / kChunk);
            }
        }
    }

    if (localTransferId.empty()) return; // all keys failed

    // Record the outbound transfer as IN-FLIGHT.  Chunks don't fly until
    // the receiver ack's the file_key announcement (Phase 2), so marking
    // Complete here would be a lie — we track real progress via
    // onFileChunkSent callbacks instead and flip to Complete on the last
    // chunk.  savedPath = original path so the Download/Open button
    // always points at the still-local source file.
    const QString key = chatKey(chat);
    AppDataStore::FileRecord rec;
    rec.transferId     = localTransferId;
    rec.chatKey        = key.toStdString();
    rec.fileName       = fileName.toStdString();
    rec.fileSize       = fileSize;
    rec.peerIdB64u     = chat.peerIdB64u;
    rec.peerName       = chat.name;
    rec.timestampSecs  = QDateTime::currentDateTime().toSecsSinceEpoch();
    rec.sent           = true;
    rec.status         = static_cast<int>(FileTransferStatus::Sending);
    rec.chunksTotal    = totalChunks;
    rec.chunksComplete = 0;
    rec.savedPath      = path.toStdString();
    m_filesByKey[key].push_back(rec);
    if (m_store) m_store->saveFileRecord(key.toStdString(), rec);

    rebuildFilesTab();

    // "You sent <file>" bubble in the chat transcript.  Progress still
    // animates on the file card in the Files tab via onFileChunkSent.
    addFileBubble(fileName, fileSize, true);
}

// ── Private slots ─────────────────────────────────────────────────────────────

void ChatView::onChatSelected(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chats.size()) || index == m_currentChat) return;
    m_currentChat = index;
    loadChat(index);
    ensureUnreadSize();
    if (m_unread[index] > 0) {
        m_unread[index] = 0;
        emit unreadChanged(totalUnread());
        rebuildChatList();
    }

    // Re-apply search highlights when switching chats
    if (!m_searchQuery.isEmpty()) {
        m_searchMatchIndices.clear();
        m_searchMatchCurrent = -1;
        const std::string queryStd = m_searchQuery.toLower().toStdString();
        const auto &msgs = m_messagesByPeer[m_chats[m_currentChat].peerIdB64u];
        for (int i = 0; i < static_cast<int>(msgs.size()); ++i) {
            QString lowered = qtbridge::qstr(msgs[i].text).toLower();
            if (lowered.contains(m_searchQuery))
                m_searchMatchIndices.append(i);
        }
        (void)queryStd;
        highlightSearchMatches();
    }
}

void ChatView::onSendMessage()
{
    if (m_currentChat < 0) return;
    QString text = m_ui->messageInput->text().trimmed();
    if (text.isEmpty()) return;

    AppDataStore::Contact &cur = m_chats[m_currentChat];
    if (cur.keys.empty()) {
        addMessageBubble("No keys saved for this contact.", false);
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    const int64_t nowSecs = now.toSecsSinceEpoch();
    auto &msgs = m_messagesByPeer[cur.peerIdB64u];
    if (msgs.empty() || (nowSecs - msgs.back().timestampSecs) >= kDateSepSecs)
        addDateSeparator(now);

    const QString msgId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    AppDataStore::Message msg{true, text.toStdString(), nowSecs, msgId.toStdString(), ""};
    msgs.push_back(msg);

    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };

    if (m_store) {
        const std::string dbKey = cur.isGroup
                                  ? (cur.groupId.empty()
                                         ? ("name:" + cur.name)
                                         : cur.groupId)
                                  : (cur.keys.empty()
                                         ? ("name:" + cur.name)
                                         : cur.keys.front());
        m_store->saveMessage(dbKey, msg);
    }

    addMessageBubble(text, true);
    m_ui->messageInput->clear();

    if (cur.isGroup) {
        const std::string gid = cur.groupId.empty() ? cur.name : cur.groupId;
        m_controller->sendGroupMessageViaMailbox(
            gid, cur.name, cur.keys, text.toStdString());
    } else {
        for (const std::string &k : cur.keys) {
            const std::string trimmed = trimStd(k);
            if (!trimmed.empty())
                m_controller->sendText(trimmed, text.toStdString());
        }
    }
}

void ChatView::onSearchChanged(const QString &text)
{
    const QString q = text.trimmed().toLower();
    m_searchQuery = q;
    m_searchMatchIndices.clear();
    m_searchMatchCurrent = -1;

    // ── 1. Filter sidebar chats ──────────────────────────────────────────────
    for (int i = 0; i < m_ui->chatList->count(); ++i) {
        const AppDataStore::Contact &c = m_chats[i];
        bool match = q.isEmpty() || qtbridge::qstr(c.name).toLower().contains(q);
        if (!match) {
            const auto it = m_messagesByPeer.find(c.peerIdB64u);
            if (it != m_messagesByPeer.end()) {
                for (const auto &m : it->second)
                    if (qtbridge::qstr(m.text).toLower().contains(q)) { match = true; break; }
            }
        }
        m_ui->chatList->item(i)->setHidden(!match);
    }
    if (m_currentChat >= 0) {
        auto *cur = m_ui->chatList->item(m_currentChat);
        if (cur && cur->isHidden()) m_ui->chatList->clearSelection();
    }

    // ── 2. Highlight matching messages in current chat ────────────────────────
    if (m_currentChat >= 0 && m_currentChat < static_cast<int>(m_chats.size()) && !q.isEmpty()) {
        const auto &msgs = m_messagesByPeer[m_chats[m_currentChat].peerIdB64u];
        for (int i = 0; i < static_cast<int>(msgs.size()); ++i)
            if (qtbridge::qstr(msgs[i].text).toLower().contains(q))
                m_searchMatchIndices.append(i);
    }
    highlightSearchMatches();

    // ── 3. Filter file cards in Files tab ────────────────────────────────────
    rebuildFilesTab();
}

// ── Search highlight helpers ─────────────────────────────────────────────────

void ChatView::highlightSearchMatches()
{
    QLayout *layout = m_ui->scrollAreaWidgetContents->layout();
    if (!layout) return;

    // Walk the layout items — each is either a date separator or a message row.
    // Date separators have a fixed height of 28 (see addDateSeparator).
    // We track message index separately.
    const bool hasQuery = !m_searchQuery.isEmpty();
    int msgIdx = 0;
    const QSet<int> matchSet(m_searchMatchIndices.begin(), m_searchMatchIndices.end());

    for (int i = 0; i < layout->count(); ++i) {
        QWidget *w = layout->itemAt(i)->widget();
        if (!w) continue;

        // Skip date separators (fixed height 28) and the bottom spacer
        if (w->maximumHeight() == 28) continue;

        // Find the QLabel bubble inside this message row
        QList<QLabel*> labels = w->findChildren<QLabel*>();
        for (QLabel *lbl : labels) {
            // Bubbles have border-radius:14px in their style; sender name labels don't
            if (!lbl->styleSheet().contains("border-radius:14px")) continue;

            if (hasQuery && matchSet.contains(msgIdx)) {
                // Highlight: add a gold border, shrink padding to compensate
                // so total box size stays the same and text doesn't reflow.
                // Original padding: 10px 14px
                const bool isFocused = (m_searchMatchCurrent >= 0 &&
                                        m_searchMatchCurrent < m_searchMatchIndices.size() &&
                                        m_searchMatchIndices[m_searchMatchCurrent] == msgIdx);
                const QString borderColor = isFocused ? "#ffb300" : "#997a00";
                const int bw = isFocused ? 2 : 1;
                const int pV = 10 - bw, pH = 14 - bw;   // compensated padding
                QString ss = lbl->styleSheet();
                ss.remove(QRegularExpression("border:\\d+px solid #[0-9a-fA-F]+;"));
                ss.replace(QRegularExpression("padding:\\d+px \\d+px;"),
                           QString("padding:%1px %2px;").arg(pV).arg(pH));
                ss.append(QString("border:%1px solid %2;").arg(bw).arg(borderColor));
                lbl->setStyleSheet(ss);
            } else {
                // Remove search border, restore original padding
                QString ss = lbl->styleSheet();
                ss.remove(QRegularExpression("border:\\d+px solid #[0-9a-fA-F]+;"));
                ss.replace(QRegularExpression("padding:\\d+px \\d+px;"),
                           QString("padding:10px 14px;"));
                lbl->setStyleSheet(ss);
            }
        }
        msgIdx++;
    }

    // If we have matches and none is focused yet, focus the first
    if (!m_searchMatchIndices.isEmpty() && m_searchMatchCurrent < 0) {
        m_searchMatchCurrent = 0;
        highlightSearchMatches();          // re-run to apply focused style
        scrollToMatch(m_searchMatchCurrent);
    }
}

void ChatView::scrollToMatch(int matchIdx)
{
    if (matchIdx < 0 || matchIdx >= m_searchMatchIndices.size()) return;

    const int targetMsgIdx = m_searchMatchIndices[matchIdx];
    QLayout *layout = m_ui->scrollAreaWidgetContents->layout();
    if (!layout) return;

    int msgIdx = 0;
    for (int i = 0; i < layout->count(); ++i) {
        QWidget *w = layout->itemAt(i)->widget();
        if (!w) continue;
        if (w->maximumHeight() == 28) continue; // date separator
        if (msgIdx == targetMsgIdx) {
            m_ui->messageScroll->ensureWidgetVisible(w, 50, 80);
            return;
        }
        msgIdx++;
    }
}

void ChatView::navigateSearch(int delta)
{
    if (m_searchMatchIndices.isEmpty()) return;
    m_searchMatchCurrent += delta;
    if (m_searchMatchCurrent >= m_searchMatchIndices.size())
        m_searchMatchCurrent = 0;
    if (m_searchMatchCurrent < 0)
        m_searchMatchCurrent = m_searchMatchIndices.size() - 1;
    highlightSearchMatches();
    scrollToMatch(m_searchMatchCurrent);
}

void ChatView::onEditProfile()
{
    // ── Avatar state (shared between main dialog and photo popup) ─────────────
    bool usingPhoto = false;
    QPixmap uploadedPhoto;
    QColor avatarColor(0x2e, 0x8b, 0x3a);

    const QString currentAvatarB64 = m_store ? qtbridge::qstr(m_store->loadSetting("avatarData")) : QString();
    if (!currentAvatarB64.isEmpty()) {
        QPixmap px;
        px.loadFromData(QByteArray::fromBase64(currentAvatarB64.toUtf8()));
        if (!px.isNull()) { usingPhoto = true; uploadedPhoto = px; }
    }


    // ── Main profile dialog ───────────────────────────────────────────────────
    QDialog dlg(m_ui->centralwidget);
    dlg.setWindowTitle("Edit Profile");
    applyDialogStyle(&dlg);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    auto *titleLbl = new QLabel("Edit Profile", &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    // ── Avatar row: preview + Change Photo button ─────────────────────────────
    auto *avatarRowLayout = new QHBoxLayout;
    avatarRowLayout->setSpacing(14);

    auto *avatarThumb = new QLabel(&dlg);
    avatarThumb->setFixedSize(56, 56);
    avatarThumb->setAlignment(Qt::AlignCenter);

    auto refreshThumb = [&]() {
        QPixmap px;
        if (usingPhoto && !uploadedPhoto.isNull())
            px = makeCircularPixmap(uploadedPhoto, 56);
        else {
            const QString nm = m_ui->profileNameLabel->text();
            const QString ch = nm.isEmpty() ? "?" : QString(nm[0]);
            px = makeCircularPixmap(renderInitialsAvatar(ch, avatarColor, 200), 56);
        }
        avatarThumb->setPixmap(px);
    };
    refreshThumb();

    auto *changePhotoBtn = new QPushButton("Change Photo", &dlg);
    changePhotoBtn->setAutoDefault(false);
    themeStyles::applyRole(changePhotoBtn, "dialogNeutralBtn",
        themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));

    avatarRowLayout->addWidget(avatarThumb);
    avatarRowLayout->addWidget(changePhotoBtn);
    avatarRowLayout->addStretch();
    root->addLayout(avatarRowLayout);

    // ── Inline photo options (toggled by Change Photo button) ─────────────────
    auto *photoOptionsWidget = new QWidget(&dlg);
    photoOptionsWidget->setVisible(false);
    auto *poLayout = new QVBoxLayout(photoOptionsWidget);
    poLayout->setContentsMargins(0, 4, 0, 4);
    poLayout->setSpacing(8);

    const QList<QColor> presets = {
        QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
        QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a),
    };
    auto swatchStyle = [](const QColor &col, bool sel) -> QString {
        return QString("QPushButton{background:%1;border:%2;border-radius:14px;}"
                       "QPushButton:hover{border:2px solid #888;border-radius:14px;}")
            .arg(col.name(), sel ? "2px solid white" : "none");
    };

    auto *pColorLbl = new QLabel("Background color", photoOptionsWidget);
    pColorLbl->setStyleSheet("color:#888888;font-size:11px;");
    poLayout->addWidget(pColorLbl);

    QList<QPushButton*> pSwatches;
    auto *pSwatchRow = new QHBoxLayout;
    pSwatchRow->setSpacing(8);
    pSwatchRow->addStretch();
    for (int i = 0; i < presets.size(); ++i) {
        auto *sb = new QPushButton(photoOptionsWidget);
        sb->setFixedSize(28, 28);
        sb->setAutoDefault(false);
        sb->setStyleSheet(swatchStyle(presets[i], !usingPhoto && presets[i] == avatarColor));
        pSwatches.append(sb);
        QObject::connect(sb, &QPushButton::clicked, [&, sb, i]() {
            usingPhoto  = false;
            avatarColor = presets[i];
            for (int j = 0; j < pSwatches.size(); ++j)
                pSwatches[j]->setStyleSheet(swatchStyle(presets[j], pSwatches[j] == sb));
            refreshThumb();
        });
        pSwatchRow->addWidget(sb);
    }
    auto *pCustom = new QPushButton("+", photoOptionsWidget);
    pCustom->setFixedSize(28, 28);
    pCustom->setAutoDefault(false);
    themeStyles::applyRole(pCustom, "dialogNeutralBtn",
        themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
    QObject::connect(pCustom, &QPushButton::clicked, [&]() {
        QColor c = QColorDialog::getColor(avatarColor, nullptr, "Choose Color");
        if (!c.isValid()) return;
        usingPhoto  = false;
        avatarColor = c;
        for (int j = 0; j < pSwatches.size(); ++j)
            pSwatches[j]->setStyleSheet(swatchStyle(presets[j], false));
        refreshThumb();
    });
    pSwatchRow->addWidget(pCustom);
    pSwatchRow->addStretch();
    poLayout->addLayout(pSwatchRow);

    auto *pUpload = new QPushButton("Upload Photo", photoOptionsWidget);
    pUpload->setAutoDefault(false);
    themeStyles::applyRole(pUpload, "dialogNeutralBtn",
        themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
    QObject::connect(pUpload, &QPushButton::clicked, [&]() {
        const QString path = QFileDialog::getOpenFileName(
            &dlg, "Choose Photo", QString(),
            "Images (*.png *.jpg *.jpeg *.bmp)");
        if (path.isEmpty()) return;
        QPixmap px(path);
        if (px.isNull()) return;
        usingPhoto    = true;
        uploadedPhoto = px;
        for (int j = 0; j < pSwatches.size(); ++j)
            pSwatches[j]->setStyleSheet(swatchStyle(presets[j], false));
        refreshThumb();
    });
    poLayout->addWidget(pUpload);

    root->addWidget(photoOptionsWidget);

    // ── Name ─────────────────────────────────────────────────────────────────
    root->addWidget(new QLabel("Display Name", &dlg));
    auto *nameEdit = new QLineEdit(m_ui->profileNameLabel->text(), &dlg);
    root->addWidget(nameEdit);

    // ── Your Public Key (read-only) ─────────────────────────────────────────
    root->addWidget(new QLabel("Your Public Key", &dlg));

    const QString myKey = QString::fromStdString(m_controller->myIdB64u());

    auto *keyRow = new QHBoxLayout;
    keyRow->setSpacing(8);

    auto *keyDisplay = new QLineEdit(myKey, &dlg);
    keyDisplay->setReadOnly(true);
    themeStyles::applyRole(keyDisplay, "keyDisplay",
        themeStyles::keyDisplayCss(ThemeManager::instance().current()));
    keyRow->addWidget(keyDisplay, 1);

    auto *copyBtn = new QPushButton("Copy", &dlg);
    copyBtn->setAutoDefault(false);
    themeStyles::applyRole(copyBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    QObject::connect(copyBtn, &QPushButton::clicked, [myKey, copyBtn]() {
        QApplication::clipboard()->setText(myKey);
        copyBtn->setText("Copied!");
        // Pass copyBtn as the QTimer context so Qt auto-disconnects
        // if the button is destroyed first (the dialog is modal and
        // stack-allocated — clicking Cancel inside the 1.5 s window
        // otherwise dangles the captured raw pointer and crashes).
        QTimer::singleShot(1500, copyBtn, [copyBtn]() {
            copyBtn->setText("Copy");
        });
    });
    keyRow->addWidget(copyBtn);
    root->addLayout(keyRow);

    // ── QR code preview ─────────────────────────────────────────────────────
    // Displayed alongside the Copy button so two in-person users can add each
    // other without typing: one pulls up Edit Profile, the other scans with
    // their phone camera.  The encoded payload is the raw 43-char key — byte
    // for byte what Copy puts on the clipboard, so either method produces the
    // same input on the receiving side.
    QImage qrImg = QrImage::encodeText(myKey, /*pixelsPerModule=*/4);
    if (!qrImg.isNull()) {
        auto *qrLabel = new QLabel(&dlg);
        qrLabel->setPixmap(QPixmap::fromImage(qrImg));
        qrLabel->setAlignment(Qt::AlignCenter);
        qrLabel->setStyleSheet(
            "QLabel{background:#fff;border:1px solid #2a2a2a;border-radius:8px;"
            "padding:8px;}");
        root->addWidget(qrLabel, 0, Qt::AlignCenter);
    }

    auto *keyHint = new QLabel("Share this key with contacts so they can message you. "
                                 "They can paste it or scan the QR code above.", &dlg);
    themeStyles::applyRole(keyHint, "caption11",
        themeStyles::captionCss(ThemeManager::instance().current(), 11));
    keyHint->setWordWrap(true);
    root->addWidget(keyHint);

    root->addStretch();

    // ── Cancel / Save ─────────────────────────────────────────────────────────
    auto *btnRow    = new QHBoxLayout;
    auto *cancelBtn = new QPushButton("Cancel", &dlg);
    auto *saveBtn   = new QPushButton("Save",   &dlg);
    cancelBtn->setObjectName("cancelBtn");
    saveBtn->setObjectName("saveBtn");
    saveBtn->setDefault(true);
    btnRow->setSpacing(10);
    btnRow->addStretch();
    btnRow->addWidget(cancelBtn);
    btnRow->addWidget(saveBtn);
    root->addLayout(btnRow);

    QObject::connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(saveBtn,   &QPushButton::clicked, &dlg, &QDialog::accept);

    // ── "Change Photo" toggles inline photo options ───────────────────────────
    QObject::connect(changePhotoBtn, &QPushButton::clicked, [&, photoOptionsWidget]() {
        const bool nowVisible = !photoOptionsWidget->isVisible();
        photoOptionsWidget->setVisible(nowVisible);
        changePhotoBtn->setText(nowVisible ? "Done" : "Change Photo");
        dlg.adjustSize();
    });

    if (dlg.exec() != QDialog::Accepted) return;

    // ── Commit ────────────────────────────────────────────────────────────────
    const QString newName = nameEdit->text().trimmed();

    QPixmap finalPx;
    if (usingPhoto && !uploadedPhoto.isNull()) {
        finalPx = makeCircularPixmap(uploadedPhoto, 200);
    } else {
        const QString ch = newName.isEmpty() ? "?" : QString(newName[0]);
        finalPx = renderInitialsAvatar(ch, avatarColor, 200);
    }

    QByteArray bytes;
    QBuffer buf(&bytes);
    buf.open(QIODevice::WriteOnly);
    finalPx.save(&buf, "PNG");
    const QString newAvatarB64 = QString::fromLatin1(bytes.toBase64());

    const QString displayName = newName.isEmpty() ? "Me" : newName;
    m_ui->profileNameLabel->setText(displayName);
    m_ui->profileAvatarLabel->setPixmap(makeCircularPixmap(finalPx, 40));
    m_ui->profileAvatarLabel->setText("");

    if (m_store) {
        m_store->saveSetting("displayName",  displayName.toStdString());
        m_store->saveSetting("avatarData",   newAvatarB64.toStdString());
        m_store->saveSetting("avatarIsPhoto", usingPhoto ? "true" : "false");
    }

    // Broadcast to all contacts. Send empty avatar when using default so the
    // receiver falls back to initials derived from their own saved name for us.
    {
        const std::string broadcastAvatar = usingPhoto ? newAvatarB64.toStdString() : std::string();
        for (const auto &chat : m_chats) {
            if (!chat.isGroup && !chat.peerIdB64u.empty())
                m_controller->sendAvatar(chat.peerIdB64u, displayName.toStdString(), broadcastAvatar);
        }
    }
}

void ChatView::onEditContact(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chats.size())) return;
    QString     name       = qtbridge::qstr(m_chats[index].name);
    QStringList keys       = qtbridge::qstrList(m_chats[index].keys);
    QString     avatar     = qtbridge::qstr(m_chats[index].avatarB64);
    const bool  wasGroup   = m_chats[index].isGroup;
    const QString oldName  = name;
    const QString oldAvatar = avatar;
    const QStringList oldKeys = keys;

    const ContactEditorResult result =
        openContactEditor(m_ui->centralwidget,
                          wasGroup ? "Edit Group" : "Edit Contact",
                          name, keys, true,
                          m_chats[index].isBlocked,
                          wasGroup,
                          &m_chats,
                          [this](const AppDataStore::Contact &newContact) {
                              m_chats.push_back(newContact);
                              if (m_store) m_store->saveContact(newContact);
                              rebuildChatList();
                          },
                          wasGroup ? &avatar : nullptr,
                          m_controller);

    if (result == ContactEditorResult::Saved && !name.isEmpty()) {
        // Validate key format and prevent duplicate keys — 1:1 contacts only
        if (!wasGroup) {
            if (keys.isEmpty()) {
                QMessageBox::warning(m_ui->centralwidget, "Missing Key",
                                     "A public key is required.");
                return;
            }
            if (!isValidPublicKey(keys.first())) {
                QMessageBox::warning(m_ui->centralwidget, "Invalid Key",
                                     "Public key must be exactly 43 base64url characters.");
                return;
            }

            // Prevent duplicate keys: check if any new key collides with another contact.
            bool conflict = false;
            for (const QString &k : std::as_const(keys)) {
                const std::string kStd = k.toStdString();
                for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
                    if (i == index || m_chats[i].isGroup) continue;
                    if (m_chats[i].peerIdB64u == kStd ||
                        std::find(m_chats[i].keys.begin(), m_chats[i].keys.end(), kStd) != m_chats[i].keys.end()) {
                        QMessageBox::warning(m_ui->centralwidget, "Duplicate Key",
                                             QString("Key already belongs to contact \"%1\".").arg(qtbridge::qstr(m_chats[i].name)));
                        conflict = true; break;
                    }
                }
                if (conflict) break;
            }
            if (conflict) return;
        }

        m_chats[index].name = name.toStdString();
        m_chats[index].keys = qtbridge::stdstrList(keys);
        if (wasGroup) m_chats[index].avatarB64 = avatar.toStdString();
        if (m_chats[index].peerIdB64u.empty() && !keys.isEmpty())
            m_chats[index].peerIdB64u = keys.first().toStdString();
        if (m_store) m_store->saveContact(m_chats[index]);
        if (wasGroup && !avatar.isEmpty())
            m_store->saveContactAvatar(m_chats[index].peerIdB64u, avatar.toStdString());
        rebuildChatList();
        if (m_currentChat == index)
            m_ui->chatTitleLabel->setText(name);

        // Broadcast group changes to all members
        if (wasGroup) {
            const std::vector<std::string> stdKeys = qtbridge::stdstrList(keys);
            if (name != oldName)
                m_controller->sendGroupRename(m_chats[index].groupId,
                                               name.toStdString(), stdKeys);
            if (avatar != oldAvatar)
                m_controller->sendGroupAvatar(m_chats[index].groupId,
                                               avatar.toStdString(), stdKeys);
            if (keys != oldKeys)
                m_controller->sendGroupMemberUpdate(m_chats[index].groupId,
                                                     m_chats[index].name, stdKeys);
        }
    } else if (result == ContactEditorResult::Removed) {
        // Use the same key logic as saveContact
        const std::string dbKey = m_chats[index].peerIdB64u.empty()
                                  ? ("name:" + m_chats[index].name)
                                  : m_chats[index].peerIdB64u;
        if (m_store) m_store->deleteContact(dbKey);
        m_chats.erase(m_chats.begin() + index);
        m_unread.remove(index);
        m_currentChat = -1;
        rebuildChatList();
        if (!m_chats.empty()) m_ui->chatList->setCurrentRow(0);
    } else if (result == ContactEditorResult::Blocked) {
        m_chats[index].isBlocked = !m_chats[index].isBlocked;
        if (m_store) m_store->saveContact(m_chats[index]);
        rebuildChatList();

    } else if (result == ContactEditorResult::SessionReset) {
        // Wipe ratchet state so next message triggers a fresh handshake.
        const std::string peerId = m_chats[index].peerIdB64u;
        if (!peerId.empty())
            m_controller->resetSession(peerId);
        if (m_store) m_store->saveContact(m_chats[index]);
        rebuildChatList();
    } else if (result == ContactEditorResult::Left) {
        // Notify all members you're leaving
        const std::string groupId = m_chats[index].groupId;
        m_controller->sendGroupLeaveNotification(
            groupId, m_chats[index].name, m_chats[index].keys);

        // Remove group locally
        const std::string dbKey = m_chats[index].peerIdB64u.empty()
                                  ? ("name:" + m_chats[index].name)
                                  : m_chats[index].peerIdB64u;
        if (m_store) m_store->deleteContact(dbKey);
        m_chats.erase(m_chats.begin() + index);
        m_unread.remove(index);
        m_currentChat = -1;
        rebuildChatList();
        if (!m_chats.empty())
            m_ui->chatList->setCurrentRow(0);
    }

}

void ChatView::onAddContact()
{
    QString name; QStringList keys;

    QDialog dlg(m_ui->centralwidget);
    dlg.setWindowTitle("Add Contact"); applyDialogStyle(&dlg);
    dlg.setMinimumWidth(420); dlg.setModal(true);

    auto *layout = new QVBoxLayout(&dlg);
    layout->setSpacing(14); layout->setContentsMargins(24,24,24,24);
    auto *ttl = new QLabel("Add Contact",&dlg); ttl->setObjectName("dlgTitle");
    layout->addWidget(ttl);
    auto *sp = new QFrame(&dlg); sp->setFrameShape(QFrame::HLine);
    sp->setStyleSheet("color:#2a2a2a;"); layout->addWidget(sp);
    layout->addWidget(new QLabel("Display Name",&dlg));
    auto *nameEdit = new QLineEdit(&dlg); layout->addWidget(nameEdit);
    layout->addWidget(new QLabel("Public Key",&dlg));
    auto *keyRow_   = new QHBoxLayout;
    keyRow_->setSpacing(8);
    auto *keyInput  = new QLineEdit(&dlg);
    keyInput->setPlaceholderText("Paste their 43-character public key…");
    keyRow_->addWidget(keyInput, 1);
    auto *pasteBtn  = new QPushButton("Paste", &dlg);
    pasteBtn->setAutoDefault(false);
    themeStyles::applyRole(pasteBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    QObject::connect(pasteBtn, &QPushButton::clicked, [keyInput]() {
        // Trim whitespace/newlines that often ride along when a key is
        // copied from a chat message — saves the user a manual edit
        // before isValidPublicKey rejects it for length.
        keyInput->setText(QApplication::clipboard()->text().trimmed());
    });
    keyRow_->addWidget(pasteBtn);
    layout->addLayout(keyRow_);

    layout->addStretch();

    auto *br     = new QHBoxLayout;
    auto *grpBtn = new QPushButton("Create Group Chat",&dlg);
    auto *can    = new QPushButton("Cancel",&dlg); can->setObjectName("cancelBtn");
    auto *sav    = new QPushButton("Save",  &dlg); sav->setObjectName("saveBtn");
    themeStyles::applyRole(grpBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    br->setSpacing(10); br->addWidget(grpBtn); br->addStretch();
    br->addWidget(can); br->addWidget(sav);
    layout->addLayout(br);

    bool createGroup = false;
    QObject::connect(can,    &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(sav,    &QPushButton::clicked, &dlg, &QDialog::accept);
    QObject::connect(grpBtn, &QPushButton::clicked, [&](){ createGroup=true; dlg.accept(); });

    if (dlg.exec() != QDialog::Accepted) return;

    if (createGroup) {
        if (m_chats.empty()) {
            QMessageBox::information(m_ui->centralwidget,"No Contacts",
                                     "Add some contacts first before creating a group."); return; }

        QDialog gd(m_ui->centralwidget);
        gd.setWindowTitle("New Group Chat"); applyDialogStyle(&gd);
        gd.setMinimumWidth(380);
        auto *gl = new QVBoxLayout(&gd); gl->setSpacing(12); gl->setContentsMargins(24,24,24,24);
        auto *gt = new QLabel("New Group Chat",&gd); gt->setObjectName("dlgTitle");
        gl->addWidget(gt); gl->addWidget(new QLabel("Group Name",&gd));
        auto *gn = new QLineEdit(&gd); gn->setPlaceholderText("Enter group name…");
        gl->addWidget(gn); gl->addWidget(new QLabel("Select Members",&gd));
        auto *ml = new QListWidget(&gd); ml->setFixedHeight(160);
        for (const auto &c : m_chats) {
            if (c.isGroup) continue;
            auto *it = new QListWidgetItem(qtbridge::qstr(c.name), ml); it->setCheckState(Qt::Unchecked);
        }
        gl->addWidget(ml);
        auto *gbr = new QHBoxLayout;
        auto *gc  = new QPushButton("Cancel",&gd); gc->setObjectName("cancelBtn");
        auto *gcr = new QPushButton("Create",&gd); gcr->setObjectName("saveBtn");
        gbr->addStretch(); gbr->addWidget(gc); gbr->addWidget(gcr);
        gl->addLayout(gbr);
        QObject::connect(gc, &QPushButton::clicked, &gd, &QDialog::reject);
        QObject::connect(gcr,&QPushButton::clicked, &gd, &QDialog::accept);
        if (gd.exec() != QDialog::Accepted) return;

        const QString gname = gn->text().trimmed(); if(gname.isEmpty()) return;
        std::vector<std::string> gkeys;
        QStringList mnames;
        for(int i=0;i<ml->count();++i) {
            if(ml->item(i)->checkState()==Qt::Checked) {
                const QString itemText = ml->item(i)->text();
                const std::string itemTextStd = itemText.toStdString();
                for(const auto &c : m_chats)
                    if(c.name==itemTextStd && !c.isGroup){
                        gkeys.insert(gkeys.end(), c.keys.begin(), c.keys.end());
                        mnames<<itemText;
                        break;
                    }
            }
        }
        if(gkeys.empty()){ QMessageBox::warning(m_ui->centralwidget,"No Members",
                                 "Select at least one member."); return; }

        AppDataStore::Contact ng;
        ng.name = gname.toStdString();
        ng.subtitle = QString("Group · %1 member%2").arg(mnames.size())
                          .arg(mnames.size()==1?"":"s").toStdString();
        ng.isGroup = true; ng.keys = gkeys;
        ng.groupId = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString();
        ng.peerIdB64u = ng.groupId;
        m_chats.push_back(ng);
        if(m_store) m_store->saveContact(ng);
        rebuildChatList();
        m_ui->chatList->setCurrentRow(static_cast<int>(m_chats.size())-1);
        return;
    }

    name = nameEdit->text().trimmed(); if(name.isEmpty()) return;
    const QString singleKey = keyInput->text().trimmed();
    if (singleKey.isEmpty()) return;
    if (!isValidPublicKey(singleKey)) {
        QMessageBox::warning(m_ui->centralwidget, "Invalid Key",
                             "Public key must be exactly 43 base64url characters.");
        return;
    }
    const std::string singleKeyStd = singleKey.toStdString();
    // Prevent duplicate contacts
    for (const auto &c : m_chats) {
        if (c.isGroup) continue;
        if (c.peerIdB64u == singleKeyStd ||
            std::find(c.keys.begin(), c.keys.end(), singleKeyStd) != c.keys.end()) {
            QMessageBox::warning(m_ui->centralwidget, "Duplicate Key",
                QString("Key already belongs to contact \"%1\".").arg(qtbridge::qstr(c.name)));
            return;
        }
    }
    keys << singleKey;

    AppDataStore::Contact nc;
    nc.name = name.toStdString();
    nc.subtitle = "Secure chat";
    nc.keys = qtbridge::stdstrList(keys);
    if(!nc.keys.empty()) nc.peerIdB64u = nc.keys.front();
    m_chats.push_back(nc);
    if(m_store) m_store->saveContact(nc);

    // Send our avatar to the new contact
    if (!nc.peerIdB64u.empty()) {
        const std::string myName   = m_store ? m_store->loadSetting("displayName") : std::string();
        const std::string myAvatar = m_store ? m_store->loadSetting("avatarData")  : std::string();
        if (!myName.empty())
            m_controller->sendAvatar(nc.peerIdB64u, myName, myAvatar);
    }

    rebuildChatList();
    m_ui->chatList->setCurrentRow(static_cast<int>(m_chats.size())-1);
}

// ── Private helpers ───────────────────────────────────────────────────────────

int ChatView::findChatForPeer(const QString &peerIdB64u) const
{
    const std::string peerStd = peerIdB64u.toStdString();
    auto trimStd = [](const std::string& s) {
        const auto first = s.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = s.find_last_not_of(" \t\r\n");
        return s.substr(first, last - first + 1);
    };
    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        if (m_chats[i].isGroup) continue;
        if (trimStd(m_chats[i].peerIdB64u) == peerStd) return i;
        for (const std::string &k : m_chats[i].keys)
            if (trimStd(k) == peerStd) return i;
    }
    return -1;
}

int ChatView::findOrCreateChatForPeer(const QString &peerIdB64u)
{
    const int existing = findChatForPeer(peerIdB64u);
    if (existing >= 0) return existing;

    // Unknown sender — auto-create at the top of the list.
    AppDataStore::Contact nc;
    nc.name = "Unknown contact";
    nc.subtitle = "Secure chat";
    nc.peerIdB64u = peerIdB64u.toStdString();
    nc.keys.push_back(peerIdB64u.toStdString());
    m_chats.insert(m_chats.begin(), nc);
    if (m_store) m_store->saveContact(nc);
    ensureUnreadSize();
    m_unread.prepend(0);
    if (m_currentChat >= 0) m_currentChat += 1;
    rebuildChatList();
    return 0;
}

void ChatView::initChats()
{
    if (m_store) {
        const QString savedName = qtbridge::qstr(m_store->loadSetting("displayName"));
        if (!savedName.isEmpty()) {
            m_ui->profileNameLabel->setText(savedName);
            m_ui->profileAvatarLabel->setText(QString(savedName[0]).toUpper());
        }

        const QString avatarB64 = qtbridge::qstr(m_store->loadSetting("avatarData"));
        if (!avatarB64.isEmpty()) {
            QPixmap px;
            px.loadFromData(QByteArray::fromBase64(avatarB64.toUtf8()));
            if (!px.isNull()) {
                m_ui->profileAvatarLabel->setPixmap(makeCircularPixmap(px, 40));
                m_ui->profileAvatarLabel->setText("");
            }
        }
    }

    m_chats.clear();
    m_messagesByPeer.clear();
    m_filesByKey.clear();

    if (m_store) {
        m_store->loadAllContacts([this](const AppDataStore::Contact &c) {
            m_chats.push_back(c);
        });

        // Load messages + file records per contact.  Done after the
        // contacts finish streaming so we don't hit the store recursively.
        for (const auto &c : m_chats) {
            auto &msgs = m_messagesByPeer[c.peerIdB64u];
            m_store->loadMessages(c.peerIdB64u, [&msgs](const AppDataStore::Message &m) {
                msgs.push_back(m);
            });

            const QString ck = chatKey(c);
            std::vector<AppDataStore::FileRecord> records;
            m_store->loadFileRecords(ck.toStdString(), [&records](const AppDataStore::FileRecord &r) {
                records.push_back(r);
            });
            if (!records.empty())
                m_filesByKey[ck] = std::move(records);
        }
    }

    m_ui->chatList->clear();
    for (const auto &c : m_chats) m_ui->chatList->addItem(qtbridge::qstr(c.name));

    // Show first 8 chars of public key as handle
    const QString fullKey = QString::fromStdString(m_controller->myIdB64u());
    if (!fullKey.isEmpty()) {
        m_ui->profileHandleLabel->setText(fullKey.left(8) + "…");
        m_ui->profileHandleLabel->setToolTip(fullKey);
    }
}

void ChatView::rebuildChatList()
{
    // Re-subscribe presence when contact list changes
    subscribeAllPresence();

    // Prune m_memberOnline: drop keys that no longer belong to any contact/group
    {
        QSet<QString> activeKeys;
        for (const auto &c : m_chats)
            for (const std::string &k : c.keys) {
                const QString t = qtbridge::qstr(k).trimmed();
                if (!t.isEmpty()) activeKeys.insert(t);
            }
        for (auto it = m_memberOnline.begin(); it != m_memberOnline.end(); ) {
            if (!activeKeys.contains(it.key()))
                it = m_memberOnline.erase(it);
            else
                ++it;
        }
    }

    disconnect(m_ui->chatList, &QListWidget::currentRowChanged,
               this, &ChatView::onChatSelected);
    m_ui->chatList->clear();

    for (int i = 0; i < static_cast<int>(m_chats.size()); ++i) {
        auto *item = new QListWidgetItem(m_ui->chatList);
        item->setSizeHint(QSize(0, 64));
        auto *row = new QWidget;
        row->setStyleSheet("background:transparent;");
        auto *hl = new QHBoxLayout(row);
        hl->setContentsMargins(14,0,14,0); hl->setSpacing(6);

        auto *nameLbl = new QLabel(qtbridge::qstr(m_chats[i].name), row);
        nameLbl->setStyleSheet("color:#d0d0d0;font-size:14px;background:transparent;");
        hl->addWidget(nameLbl, 1);

        // Safety-number verification indicator (1:1 contacts only — groups
        // inherit verification per-member and are shown in the contact
        // editor's member list).  Green check = Verified; orange "!" =
        // Mismatch (peer's safety number changed vs stored); no indicator
        // for Unverified (the default first-contact state).
        if (!m_chats[i].isGroup && m_controller && !m_chats[i].keys.empty()) {
            const std::string peerIdB64u =
                qtbridge::qstr(m_chats[i].keys.front()).trimmed().toStdString();
            const auto trust = m_controller->peerTrust(peerIdB64u);
            if (trust != ChatController::PeerTrust::Unverified) {
                auto *badge = new QLabel(row);
                badge->setFixedSize(16, 16);
                badge->setAlignment(Qt::AlignCenter);
                if (trust == ChatController::PeerTrust::Verified) {
                    badge->setText("✓");
                    badge->setStyleSheet(
                        "QLabel{color:#5dd868;font-size:13px;"
                        "font-weight:bold;background:transparent;}");
                    badge->setToolTip("Verified safety number");
                } else {
                    badge->setText("!");
                    badge->setStyleSheet(
                        "QLabel{color:#e6a33a;font-size:13px;"
                        "font-weight:bold;background:#3a2b12;"
                        "border-radius:8px;}");
                    badge->setToolTip("Safety number changed — re-verify");
                }
                hl->addWidget(badge);
            }
        }

        ensureUnreadSize();
        if (m_unread[i] > 0) {
            auto *dot = new QLabel(row); dot->setFixedSize(8,8);
            dot->setStyleSheet("QLabel{background-color:#5dd868;border-radius:4px;}");
            hl->addWidget(dot);
        }

        // Avatar label — shows received photo, group initials, or neutral placeholder
        auto *avatarLbl = new QLabel(row);
        avatarLbl->setFixedSize(34, 34);
        avatarLbl->setAlignment(Qt::AlignCenter);
        if (!m_chats[i].avatarB64.empty()) {
            QPixmap px;
            px.loadFromData(QByteArray::fromBase64(QByteArray::fromStdString(m_chats[i].avatarB64)));
            if (!px.isNull())
                avatarLbl->setPixmap(makeCircularPixmap(px, 34));
        } else {
            static const QList<QColor> kPalette = {
                QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
                QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a), QColor(0x1a, 0x4a, 0x6a),
            };
            const QString nm = qtbridge::qstr(m_chats[i].name);
            const QString ch  = nm.isEmpty() ? (m_chats[i].isGroup ? "#" : "?") : QString(nm[0]);
            const uint hash = qHash(nm);
            const QColor bg = m_chats[i].isGroup
                ? QColor(0x2e, 0x8b, 0x3a)
                : kPalette[hash % static_cast<uint>(kPalette.size())];
            avatarLbl->setPixmap(renderInitialsAvatar(ch, bg, 34));
        }
        hl->addWidget(avatarLbl);

        auto *editBtn = new QToolButton(row);
        editBtn->setText("✎"); editBtn->setFixedSize(28,28);
        themeStyles::applyRole(editBtn, "toolIconBtn",
            themeStyles::toolIconBtnCss(ThemeManager::instance().current()));
        hl->addWidget(editBtn);
        m_ui->chatList->setItemWidget(item, row);
        connect(editBtn, &QToolButton::clicked, this, [this,i](){ onEditContact(i); });
    }

    connect(m_ui->chatList, &QListWidget::currentRowChanged,
            this, &ChatView::onChatSelected);
    if (m_currentChat >= 0 && m_currentChat < m_ui->chatList->count())
        m_ui->chatList->setCurrentRow(m_currentChat);

    if (!m_emptyLabel) {
        m_emptyLabel = new QLabel(m_ui->contentWidget);
        m_emptyLabel->setText("💬\n\nNo contacts yet\nClick + to add a contact\nand start chatting");
        m_emptyLabel->setAlignment(Qt::AlignCenter);
        m_emptyLabel->setStyleSheet(
            "color:#555555;font-size:14px;background-color:#0a0a0a;padding:40px;");
        m_emptyLabel->setWordWrap(true);
        m_emptyLabel->setAttribute(Qt::WA_TransparentForMouseEvents, false);
    }
    m_emptyLabel->resize(m_ui->contentWidget->size());
    m_emptyLabel->move(0,0); m_emptyLabel->raise();
    if (m_chats.empty()) {
        QTimer::singleShot(0, this, [this](){ if(m_emptyLabel){
            m_emptyLabel->resize(m_ui->contentWidget->size());
            m_emptyLabel->raise(); m_emptyLabel->show(); } });
    } else {
        if (m_emptyLabel) m_emptyLabel->hide();
    }
}

void ChatView::loadChat(int index)
{
    const AppDataStore::Contact &chat = m_chats[index];
    const QString chatName = qtbridge::qstr(chat.name);
    m_ui->chatTitleLabel->setText(chatName);

    // Show online / last-seen for DM chats, group subtitle for groups
    if (!chat.isGroup) {
        const bool isOnline = m_memberOnline.value(qtbridge::qstr(chat.peerIdB64u), false);
        const QString statusText = isOnline
                                       ? "Online"
                                       : formatLastSeen(qtbridge::qdate(chat.lastActiveSecs));
        m_ui->chatSubLabel->setText("● " + statusText);
        m_ui->chatSubLabel->setStyleSheet(
            isOnline
                ? "color: #3a9e48; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
                : "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
    } else {
        // Show per-member presence summary for groups, but only after
        // at least one member's presence has been resolved — avoids a
        // misleading "0 of N online" flash before the first poll returns.
        const QString myKey = QString::fromStdString(m_controller->myIdB64u());
        int onlineCount = 0, totalMembers = 0;
        bool anyResolved = false;
        for (const std::string &k : chat.keys) {
            const QString trimmed = qtbridge::qstr(k).trimmed();
            if (trimmed.isEmpty() || trimmed == myKey) continue;
            ++totalMembers;
            if (m_memberOnline.contains(trimmed)) {
                anyResolved = true;
                if (m_memberOnline.value(trimmed))
                    ++onlineCount;
            }
        }
        if (!anyResolved || totalMembers == 0) {
            // No presence data yet — show the original subtitle
            m_ui->chatSubLabel->setText(qtbridge::qstr(chat.subtitle));
            m_ui->chatSubLabel->setStyleSheet(
                "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
        } else {
            m_ui->chatSubLabel->setText(
                QString("%1 of %2 members online").arg(onlineCount).arg(totalMembers));
            m_ui->chatSubLabel->setStyleSheet(
                onlineCount > 0
                    ? "color: #3a9e48; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
                    : "color: #888888; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;");
        }
    }

    if (!chat.avatarB64.empty()) {
        QPixmap px;
        px.loadFromData(QByteArray::fromBase64(QByteArray::fromStdString(chat.avatarB64)));
        if (!px.isNull()) {
            m_ui->chatAvatarLabel->setPixmap(makeCircularPixmap(px, 44));
            m_ui->chatAvatarLabel->setText("");
        }
    } else if (chat.isGroup) {
        const QString ch = chatName.isEmpty() ? "#" : QString(chatName[0]);
        m_ui->chatAvatarLabel->setPixmap(renderInitialsAvatar(ch, QColor(0x2e, 0x8b, 0x3a), 44));
        m_ui->chatAvatarLabel->setText("");
    } else {
        static const QList<QColor> kPalette = {
            QColor(0x2e, 0x8b, 0x3a), QColor(0x3a, 0x6b, 0xbf), QColor(0x7b, 0x3a, 0xbf),
            QColor(0xbf, 0x7b, 0x3a), QColor(0xbf, 0x3a, 0x3a), QColor(0x1a, 0x4a, 0x6a),
        };
        const QString ch = chatName.isEmpty() ? "?" : QString(chatName[0]);
        const QColor bg = avatarColorForName(chatName);
        m_ui->chatAvatarLabel->setPixmap(renderInitialsAvatar(ch, bg, 44));
        m_ui->chatAvatarLabel->setText("");
    }
    clearMessages();

    QDateTime lastShown;
    const auto &msgs = m_messagesByPeer[chat.peerIdB64u];
    for (const auto &msg : msgs) {
        const QDateTime msgTs = qtbridge::qdate(msg.timestampSecs);
        if (!lastShown.isValid() || lastShown.secsTo(msgTs) >= kDateSepSecs) {
            addDateSeparator(msgTs);
            lastShown = msgTs;
        }

        QString senderName;
        if (chat.isGroup && !msg.sent && !msg.senderName.empty()) {
            senderName = qtbridge::qstr(msg.senderName);
        }
        addMessageBubble(qtbridge::qstr(msg.text), msg.sent, senderName);
    }
    rebuildFilesTab();
}

void ChatView::promoteChatToTop(int index)
{
    // promoteChatToTop does NOT remap m_filesByKey because that map is keyed by
    // the stable peer ID — not by list index.  Only m_unread needs adjustment.
    if (index <= 0 || index >= static_cast<int>(m_chats.size())) return;

    AppDataStore::Contact promoted = std::move(m_chats[index]);
    m_chats.erase(m_chats.begin() + index);
    m_chats.insert(m_chats.begin(), std::move(promoted));

    ensureUnreadSize();
    int u = m_unread[index];
    m_unread.remove(index);
    m_unread.prepend(u);

    if (m_currentChat == index)              m_currentChat = 0;
    else if (m_currentChat >= 0 && m_currentChat < index) m_currentChat += 1;
}

void ChatView::clearMessages()
{
    QLayout *l = m_ui->scrollAreaWidgetContents->layout();
    if (!l) return;
    while (l->count() > 1) {
        QLayoutItem *it = l->takeAt(0);
        if (it->widget()) delete it->widget();
        delete it;
    }
}

void ChatView::addDateSeparator(const QDateTime &dt)
{
    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;
    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(28);
    auto *hl = new QHBoxLayout(row); hl->setContentsMargins(0,4,0,4); hl->setSpacing(0);
    auto *lbl = new QLabel(formatSepLabel(dt), row);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet("color:#666666;font-size:11px;background:transparent;");
    hl->addStretch(); hl->addWidget(lbl); hl->addStretch();
    layout->insertWidget(layout->count()-1, row);
}

void ChatView::addMessageBubble(const QString &text, bool sent, const QString &senderName)
{
    QFont f = QApplication::font(); f.setPixelSize(13);
    QFontMetrics fm(f);
    int vpW   = m_ui->messageScroll->viewport()->width();
    int maxW  = qMax(int(vpW * 0.65), 120);
    int hPad  = 28, vPad = 28, avail = maxW - hPad;
    QString disp  = processText(text, fm, avail);
    int     slw   = fm.horizontalAdvance(disp);
    bool    wrap  = (slw > avail) || disp.contains('\n');
    int     bw    = wrap ? maxW : qMin(slw + hPad + 4, maxW);
    int     bh;
    if (wrap) {
        int lines = 0;
        for (const QString &p : disp.split('\n')) {
            if (p.isEmpty()) { lines++; continue; }
            int lw = 0, pl = 1;
            for (const QString &w : p.split(' ')) {
                int ww = fm.horizontalAdvance(w + " ");
                if (lw+ww > avail && lw > 0) { pl++; lw = ww; } else lw += ww;
            }
            lines += pl;
        }
        bh = fm.height()*lines + vPad + (lines-1)*fm.leading() + 1;
    } else {
        bh = fm.height() + vPad + 1;
    }

    // ── Outer widget holds optional name label + bubble row ───────────────────
    const bool showName = !sent && !senderName.isEmpty();
    const int nameHeight = showName ? 16 : 0;

    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    row->setFixedHeight(bh + nameHeight + 4);

    auto *outerLayout = new QVBoxLayout(row);
    outerLayout->setContentsMargins(0, 2, 0, 2);
    outerLayout->setSpacing(2);

    // ── Sender name — group received messages only ────────────────────────────
    if (showName) {
        auto *nameRow = new QHBoxLayout;
        nameRow->setContentsMargins(0, 0, 0, 0);
        auto *nameLbl = new QLabel(senderName, row);
        nameLbl->setProperty("p2pRole", "senderName");
        nameLbl->setStyleSheet(
            "color: #5dd868; font-size: 11px; background: transparent; padding-left: 4px;"
            );
        nameRow->addWidget(nameLbl);
        nameRow->addStretch();
        outerLayout->addLayout(nameRow);
    }

    // ── Bubble row ────────────────────────────────────────────────────────────
    auto *rl = new QHBoxLayout;
    rl->setContentsMargins(0, 0, 0, 0);
    rl->setSpacing(0);

    auto *bubble = new QLabel(disp, row);
    bubble->setFont(f); bubble->setFixedSize(bw, bh);
    bubble->setWordWrap(wrap);
    bubble->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    bubble->setTextInteractionFlags(Qt::TextSelectableByMouse);

    // Tag BEFORE setting the stylesheet so the theme classifier can
    // find this bubble again on every flip — classifier prefers the
    // p2pRole property over stylesheet-content matching, which only
    // works the first pass (once we rewrite the sheet, the original
    // #222222 / #2e8b3a literal is gone and substring match fails).
    bubble->setProperty("p2pRole", sent ? "bubbleSelf" : "bubbleOther");
    if (sent) {
        bubble->setStyleSheet("background-color:#2e8b3a;color:#ffffff;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addStretch(); rl->addWidget(bubble);
    } else {
        bubble->setStyleSheet("background-color:#222222;color:#eeeeee;"
                              "border-radius:14px;padding:10px 14px;font-size:13px;");
        rl->addWidget(bubble); rl->addStretch();
    }
    // Re-classify just the new row so a bubble added in light mode
    // doesn't briefly flash dark before the next themeChanged.
    themeStyles::reapplyForChildren(row, ThemeManager::instance().current());
    outerLayout->addLayout(rl);

    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;
    layout->insertWidget(layout->count()-1, row);
    QTimer::singleShot(5, this, [this](){
        m_ui->messageScroll->verticalScrollBar()->setValue(
            m_ui->messageScroll->verticalScrollBar()->maximum());
    });
}

// ── Clickable file bubble ─────────────────────────────────────────────────────

void ChatView::addFileBubble(const QString &fileName, qint64 fileSize, bool sent)
{
    auto *layout = qobject_cast<QVBoxLayout*>(m_ui->scrollAreaWidgetContents->layout());
    if (!layout) return;

    auto *row = new QWidget(m_ui->scrollAreaWidgetContents);
    row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    auto *rl = new QHBoxLayout(row);
    rl->setContentsMargins(0, 2, 0, 2);
    rl->setSpacing(0);

    const QString label = QString("📎  %1  ·  %2\nTap to view files")
                              .arg(fileName, formatFileSize(fileSize));

    auto *btn = new QPushButton(label, row);
    btn->setFont([]{ QFont f = QApplication::font(); f.setPixelSize(13); return f; }());
    btn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    btn->setMinimumHeight(52);
    btn->setMaximumWidth(int(m_ui->messageScroll->viewport()->width() * 0.65));
    btn->setCursor(Qt::PointingHandCursor);
    btn->setFlat(true);

    const QString bgColor = sent ? "#2e8b3a" : "#222222";
    btn->setStyleSheet(
        QString("QPushButton { background-color:%1; color:#ffffff;"
                " border-radius:14px; padding:10px 14px; font-size:13px;"
                " text-align:left; }"
                "QPushButton:hover { background-color:%2; }"
                "QPushButton:pressed { background-color:%3; }")
            .arg(bgColor,
                 sent ? "#36a344" : "#2a2a2a",
                 sent ? "#256e30" : "#1a1a1a"));

    QObject::connect(btn, &QPushButton::clicked, this, [this]{
        m_ui->mainTabs->setCurrentIndex(1);
    });

    if (sent) {
        rl->addStretch();
        rl->addWidget(btn);
    } else {
        rl->addWidget(btn);
        rl->addStretch();
    }

    layout->insertWidget(layout->count() - 1, row);
    QTimer::singleShot(5, this, [this]{
        m_ui->messageScroll->verticalScrollBar()->setValue(
            m_ui->messageScroll->verticalScrollBar()->maximum());
    });
}

// ── Files tab ─────────────────────────────────────────────────────────────────
//
// Layout strategy: we fully replace the contents of filesScrollContents' layout
// each rebuild so we can switch between an empty placeholder, an in-progress
// placeholder, and a 3-column QGridLayout of cards without fighting the static
// QHBoxLayout / spacer that the .ui file placed there at design time.

void ChatView::rebuildFilesTab()
{
    QLayout *outerRaw = m_ui->filesScrollContents->layout();
    if (!outerRaw) return;

    // ── Clear everything currently in the scroll area ─────────────────────────
    // We need to remove widgets AND sub-layouts recursively.
    auto clearLayout = [](QLayout *l) {
        while (l->count() > 0) {
            QLayoutItem *it = l->takeAt(0);
            if (it->widget()) {
                it->widget()->hide();
                delete it->widget();
            } else if (it->layout()) {
                // Clear the sub-layout's own children first
                QLayout *sub = it->layout();
                while (sub->count() > 0) {
                    QLayoutItem *s = sub->takeAt(0);
                    if (s->widget()) { s->widget()->hide(); delete s->widget(); }
                    delete s;
                }
            }
            delete it;
        }
    };
    clearLayout(outerRaw);

    auto *outer = qobject_cast<QVBoxLayout*>(outerRaw);
    if (!outer) return;

    if (m_currentChat < 0) return;

    const QString key     = chatKey(m_chats[m_currentChat]);
    const auto   &records = m_filesByKey.value(key);

    // ── Filter records by search query if active ───────────────────────────
    std::vector<AppDataStore::FileRecord> filtered;
    if (!m_searchQuery.isEmpty()) {
        for (const auto &r : records)
            if (qtbridge::qstr(r.fileName).toLower().contains(m_searchQuery) ||
                qtbridge::qstr(r.peerName).toLower().contains(m_searchQuery))
                filtered.push_back(r);
    } else {
        filtered = records;
    }

    if (filtered.empty()) {
        // ── Empty state ───────────────────────────────────────────────────────
        auto *ph = new QLabel(m_ui->filesScrollContents);
        if (!m_searchQuery.isEmpty())
            ph->setText("🔍\n\nNo files matching \"" + m_searchQuery + "\"");
        else
            ph->setText("📎\n\nNo files shared yet\n\nClick the  ⬆  button below to send a file");
        ph->setAlignment(Qt::AlignCenter);
        ph->setWordWrap(true);
        ph->setStyleSheet(
            "color:#444444;font-size:13px;background:transparent;border:none;");
        outer->addStretch();
        outer->addWidget(ph);
        outer->addStretch();
        return;
    }

    // ── Grid of cards (3 per row) ─────────────────────────────────────────────
    auto *gridWidget = new QWidget(m_ui->filesScrollContents);
    gridWidget->setStyleSheet("background:transparent;");
    auto *grid = new QGridLayout(gridWidget);
    grid->setSpacing(16);
    grid->setContentsMargins(0, 0, 0, 0);

    static constexpr int kCols = 3;
    for (int i = 0; i < static_cast<int>(filtered.size()); ++i)
        grid->addWidget(buildFileCard(filtered[i], gridWidget), i / kCols, i % kCols);

    // Equal-width columns so cards fill the available space
    for (int c = 0; c < kCols; ++c)
        grid->setColumnStretch(c, 1);

    outer->addWidget(gridWidget);
    outer->addStretch();
}

QFrame *ChatView::buildFileCard(const AppDataStore::FileRecord &rec, QWidget *parent)
{
    const auto recStatus = static_cast<FileTransferStatus>(rec.status);
    const bool inFlight = (recStatus == FileTransferStatus::Sending ||
                           recStatus == FileTransferStatus::Receiving);
    const QString recFileName  = qtbridge::qstr(rec.fileName);
    const QString recSavedPath = qtbridge::qstr(rec.savedPath);
    const QString recTransferId = qtbridge::qstr(rec.transferId);

    // ── Card shell ────────────────────────────────────────────────────────────
    auto *card = new QFrame(parent);
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    card->setStyleSheet(
        "QFrame#fileCard{"
        "  background-color:#1a1a1a;"
        "  border:1px solid #2a2a2a;"
        "  border-radius:12px;"
        "}"
        );
    card->setObjectName("fileCard");

    auto *vl = new QVBoxLayout(card);
    vl->setContentsMargins(0, 0, 0, 16);
    vl->setSpacing(0);

    // ── Thumbnail / icon area ─────────────────────────────────────────────────
    const FilePreviewType previewType = filePreviewType(recFileName);
    const bool hasFile = (recStatus == FileTransferStatus::Complete && !recSavedPath.isEmpty());
    const bool isImage = (previewType == FilePreviewType::Image && hasFile);
    const bool isText  = (previewType == FilePreviewType::Text  && hasFile);

    // For images use QPushButton so the whole thumb area is clickable
    QWidget    *thumbWidget = nullptr;
    QPushButton *thumbBtn   = nullptr;
    if (isImage) {
        thumbBtn = new QPushButton(card);
        thumbBtn->setFlat(true);
        thumbBtn->setFixedHeight(220);
        thumbBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        thumbBtn->setCursor(Qt::PointingHandCursor);
        thumbBtn->setStyleSheet(
            "QPushButton{background-color:#242424;border-radius:10px 10px 0 0;border:none;}"
            "QPushButton:hover{background-color:#2d2d2d;}");
        thumbWidget = thumbBtn;
    } else {
        thumbWidget = new QWidget(card);
        thumbWidget->setMinimumHeight(220);
        thumbWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        thumbWidget->setStyleSheet("background-color:#242424;border-radius:10px 10px 0 0;");
    }

    auto *thumbLayout = new QVBoxLayout(thumbWidget);
    thumbLayout->setContentsMargins(0, 0, 0, 0);
    thumbLayout->setSpacing(0);

    // ── Delete button (✕) — right-aligned at top of thumbnail area ───────────
    auto *delBtn = new QPushButton("\u2715", thumbWidget);  // ✕
    delBtn->setFixedSize(28, 28);
    delBtn->setCursor(Qt::PointingHandCursor);
    delBtn->setToolTip("Delete file");
    delBtn->setStyleSheet(
        "QPushButton{"
        "  background-color:rgba(60,60,60,200);"
        "  color:#cccccc;"
        "  border:none;"
        "  border-radius:14px;"
        "  font-size:14px;"
        "  font-weight:bold;"
        "}"
        "QPushButton:hover{ background-color:rgba(180,50,50,220); color:#ffffff; }"
        "QPushButton:pressed{ background-color:rgba(140,30,30,255); }"
        );
    {
        auto *delRow = new QHBoxLayout;
        delRow->setContentsMargins(0, 6, 6, 0);
        delRow->addStretch();
        delRow->addWidget(delBtn);
        thumbLayout->addLayout(delRow);
    }

    const QString delTransferId = recTransferId;
    const QString delSavedPath  = recSavedPath;
    QObject::connect(delBtn, &QPushButton::clicked, [this, delTransferId, delSavedPath]() {
        auto reply = QMessageBox::question(
            m_ui->centralwidget, "Delete File",
            "Remove this file from your file list?\n\n"
            "The file will remain on your disk.",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (reply != QMessageBox::Yes) return;

        // 1. Delete from database
        if (m_store) m_store->deleteFileRecord(delTransferId.toStdString());

        // 3. Remove from in-memory map
        if (m_currentChat >= 0 && m_currentChat < static_cast<int>(m_chats.size())) {
            const QString ck = chatKey(m_chats[m_currentChat]);
            const std::string delIdStd = delTransferId.toStdString();
            auto &files = m_filesByKey[ck];
            files.erase(std::remove_if(files.begin(), files.end(),
                [&](const AppDataStore::FileRecord &r){ return r.transferId == delIdStd; }),
                files.end());
        }

        // 4. Rebuild the files tab
        rebuildFilesTab();
    });

    if (isImage) {
        QPixmap px(recSavedPath);
        auto *imgLbl = new QLabel(thumbWidget);
        imgLbl->setAlignment(Qt::AlignCenter);
        imgLbl->setStyleSheet("background:transparent;border:none;");
        if (!px.isNull()) {
            imgLbl->setPixmap(
                px.scaled(QSize(400, 200), Qt::KeepAspectRatio, Qt::SmoothTransformation));
        } else {
            imgLbl->setText(fileIcon(recFileName));
            imgLbl->setStyleSheet("background:transparent;color:#555555;font-size:64px;border:none;");
        }
        thumbLayout->addStretch();
        thumbLayout->addWidget(imgLbl);
        thumbLayout->addStretch();

        const QString savedPath = recSavedPath;
        const QString imgName   = recFileName;
        QObject::connect(thumbBtn, &QPushButton::clicked, [=] {
            auto *dlg = new QDialog(m_ui->centralwidget);
            dlg->setAttribute(Qt::WA_DeleteOnClose);
            dlg->setWindowTitle(imgName);
            dlg->resize(900, 650);
            auto *scroll = new QScrollArea(dlg);
            scroll->setAlignment(Qt::AlignCenter);
            scroll->setWidgetResizable(false);
            auto *imgLabel = new QLabel;
            imgLabel->setAlignment(Qt::AlignCenter);
            QPixmap fullPx(savedPath);
            imgLabel->setPixmap(fullPx);
            imgLabel->resize(fullPx.size());
            scroll->setWidget(imgLabel);
            auto *dl = new QVBoxLayout(dlg);
            dl->setContentsMargins(0, 0, 0, 0);
            dl->addWidget(scroll);
            dlg->show();
        });

    } else if (isText) {
        auto *iconLbl = new QLabel(fileIcon(recFileName), thumbWidget);
        iconLbl->setAlignment(Qt::AlignCenter);
        iconLbl->setStyleSheet("background:transparent;color:#555555;font-size:40px;border:none;");

        QString preview;
        QFile tf(recSavedPath);
        if (tf.open(QIODevice::ReadOnly | QIODevice::Text)) {
            for (int i = 0; i < 3 && !tf.atEnd(); ++i)
                preview += QString::fromUtf8(tf.readLine());
            tf.close();
            preview = preview.trimmed();
        }
        auto *previewLbl = new QLabel(preview.isEmpty() ? "(empty)" : preview, thumbWidget);
        previewLbl->setWordWrap(true);
        previewLbl->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        previewLbl->setStyleSheet(
            "background:transparent;color:#888888;font-size:11px;"
            "font-family:monospace;border:none;padding:0 12px;");

        thumbLayout->addStretch();
        thumbLayout->addWidget(iconLbl);
        thumbLayout->addWidget(previewLbl);
        thumbLayout->addStretch();

    } else {
        auto *iconLbl = new QLabel(fileIcon(recFileName), thumbWidget);
        iconLbl->setAlignment(Qt::AlignCenter);
        iconLbl->setStyleSheet("background:transparent;color:#555555;font-size:64px;border:none;");
        thumbLayout->addStretch();
        thumbLayout->addWidget(iconLbl);
        thumbLayout->addStretch();
    }

    // Progress bar at bottom of thumb area (in-flight only)
    if (inFlight && rec.chunksTotal > 0) {
        auto *pb = new QProgressBar(thumbWidget);
        pb->setRange(0, rec.chunksTotal);
        pb->setValue(rec.chunksComplete);
        pb->setFixedHeight(4);
        pb->setTextVisible(false);
        pb->setStyleSheet(
            "QProgressBar{background-color:#333333;border-radius:0;border:none;margin:0;}"
            "QProgressBar::chunk{background-color:#3a9e48;border-radius:0;}");
        thumbLayout->addWidget(pb);
    }

    vl->addWidget(thumbWidget);

    // ── Text block ────────────────────────────────────────────────────────────
    auto *textWidget = new QWidget(card);
    textWidget->setStyleSheet("background:transparent;");
    auto *tl = new QVBoxLayout(textWidget);
    tl->setContentsMargins(14, 12, 14, 0);
    tl->setSpacing(3);

    // Filename (elided to one line)
    auto *nameLbl = new QLabel(textWidget);
    {
        QFont nf = nameLbl->font();
        nf.setBold(true);
        nf.setPixelSize(13);
        nameLbl->setFont(nf);
    }
    nameLbl->setStyleSheet("color:#eeeeee;background:transparent;border:none;");
    nameLbl->setToolTip(recFileName);
    // Elide done after card is painted; use a sizePolicy hint for now
    nameLbl->setText(recFileName);
    nameLbl->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Size label
    auto *sizeLbl = new QLabel(formatFileSize(rec.fileSize), textWidget);
    sizeLbl->setStyleSheet("color:#888888;font-size:12px;background:transparent;border:none;");

    // Direction / status label
    QString dirText;
    if (inFlight) {
        dirText = QString("%1 / %2 chunks…")
                      .arg(rec.chunksComplete).arg(rec.chunksTotal);
    } else {
        dirText = rec.sent ? "You sent this" : "From other";
    }
    auto *dirLbl = new QLabel(dirText, textWidget);
    dirLbl->setStyleSheet(
        inFlight ? "color:#5dd868;font-size:12px;background:transparent;border:none;"
                 : "color:#666666;font-size:12px;background:transparent;border:none;");

    tl->addWidget(nameLbl);
    tl->addWidget(sizeLbl);
    tl->addWidget(dirLbl);
    vl->addWidget(textWidget);

    // ── Download button (complete state only) ─────────────────────────────────
    if (recStatus == FileTransferStatus::Complete && !recSavedPath.isEmpty()) {
        auto *btnContainer = new QWidget(card);
        btnContainer->setStyleSheet("background:transparent;");
        auto *bl = new QVBoxLayout(btnContainer);
        bl->setContentsMargins(14, 10, 14, 0);

        auto *dlBtn = new QPushButton("↓   Download", btnContainer);
        dlBtn->setFixedHeight(42);
        dlBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        dlBtn->setStyleSheet(
            "QPushButton{"
            "  background-color:#2e8b3a;"
            "  color:#ffffff;"
            "  border:none;"
            "  border-radius:8px;"
            "  font-size:13px;"
            "  font-weight:bold;"
            "}"
            "QPushButton:hover{ background-color:#38a844; }"
            "QPushButton:pressed{ background-color:#226228; }"
            );

        const QString savedPath = recSavedPath;
        const QString fileName  = recFileName;
        const bool    isSent    = rec.sent;

        QObject::connect(dlBtn, &QPushButton::clicked, [=]() {
            if (isSent) {
                // Sent file: the savedPath IS the original file — just open its folder
                if (QFile::exists(savedPath)) {
                    QDesktopServices::openUrl(
                        QUrl::fromLocalFile(QFileInfo(savedPath).absolutePath()));
                } else {
                    QMessageBox::warning(m_ui->centralwidget, "File Not Found",
                                         "The original file could not be found at:\n" + savedPath);
                }
                return;
            }

            // Received file: offer Save As into a location the user chooses
            const QString defaultDest =
                QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
                + "/" + fileName;
            const QString dest = QFileDialog::getSaveFileName(
                m_ui->centralwidget, "Save File", defaultDest);
            if (dest.isEmpty()) return;

            if (!QFile::exists(savedPath)) {
                QMessageBox::warning(m_ui->centralwidget, "File Not Found",
                                     "The auto-saved copy could not be found:\n" + savedPath);
                return;
            }
            if (QFile::exists(dest)) QFile::remove(dest);
            if (QFile::copy(savedPath, dest)) {
                QMessageBox::information(m_ui->centralwidget, "Saved",
                                         "File saved to:\n" + dest);
            } else {
                QMessageBox::warning(m_ui->centralwidget, "Copy Failed",
                                     "Could not copy file to:\n" + dest);
            }
        });

        bl->addWidget(dlBtn);
        vl->addWidget(btnContainer);
    }

    // ── Cancel button (in-flight only) ───────────────────────────────────────
    if (inFlight) {
        auto *btnContainer = new QWidget(card);
        btnContainer->setStyleSheet("background:transparent;");
        auto *bl = new QVBoxLayout(btnContainer);
        bl->setContentsMargins(14, 10, 14, 0);

        auto *cancelFileBtn = new QPushButton("✕   Cancel transfer", btnContainer);
        cancelFileBtn->setFixedHeight(34);
        cancelFileBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        cancelFileBtn->setStyleSheet(
            "QPushButton{"
            "  background-color:#2e1a1a;"
            "  color:#cc5555;"
            "  border:1px solid #5e2e2e;"
            "  border-radius:8px;"
            "  font-size:12px;"
            "}"
            "QPushButton:hover{ background-color:#3a2020; }"
            );

        const QString transferId = recTransferId;
        QObject::connect(cancelFileBtn, &QPushButton::clicked, [this, transferId]() {
            m_controller->cancelFileTransfer(transferId.toStdString());
        });

        bl->addWidget(cancelFileBtn);
        vl->addWidget(btnContainer);
    }

    return card;
}

void ChatView::ensureUnreadSize()
{
    if (m_unread.size() < m_chats.size())
        m_unread.resize(m_chats.size());
}

int ChatView::totalUnread() const
{
    int s = 0; for (int n : m_unread) s += n; return s;
}

void ChatView::showToast(const QString &message)
{
    if (!m_toastLabel) {
        m_toastLabel = new QLabel(m_ui->centralwidget);
        m_toastLabel->setAlignment(Qt::AlignCenter);
        m_toastLabel->setStyleSheet(
            "background-color:#1a2e1c;"
            "color:#5dd868;"
            "font-size:12px;"
            "padding:8px 16px;"
            "border-radius:8px;"
            "border:1px solid #2e5e30;");
        m_toastLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
    }
    m_toastLabel->setText(message);
    m_toastLabel->adjustSize();
    // Position at bottom-center of centralwidget
    const QSize ws = m_ui->centralwidget->size();
    m_toastLabel->move((ws.width() - m_toastLabel->width()) / 2,
                        ws.height() - m_toastLabel->height() - 24);
    m_toastLabel->raise();
    m_toastLabel->show();
    QTimer::singleShot(3000, m_toastLabel, &QLabel::hide);
}

// ── Phase 2: file transfer consent + cancel ──────────────────────────────────

void ChatView::onFileAcceptRequested(const QString &fromPeerIdB64u,
                                      const QString &transferId,
                                      const QString &fileName,
                                      qint64 fileSize)
{
    // Verified-contacts gate: when SettingsPanel's "Only accept from
    // verified contacts" toggle is on AND the sender's safety number
    // hasn't been confirmed, silently decline.  Same semantic as the
    // iOS-side filter — the core has already accepted the envelope;
    // we just refuse without bothering the user.
    if (m_requireVerifiedFiles && m_controller) {
        const auto trust = m_controller->peerTrust(fromPeerIdB64u.toStdString());
        if (trust != ChatController::PeerTrust::Verified) {
            m_controller->declineFileTransfer(transferId.toStdString());
            return;
        }
    }

    // Figure out which contact/chat this is so we can show a friendly name.
    QString senderName = fromPeerIdB64u.left(8) + "...";
    const std::string fromStd = fromPeerIdB64u.toStdString();
    for (const auto &c : m_chats) {
        if (std::find(c.keys.begin(), c.keys.end(), fromStd) != c.keys.end()) {
            senderName = qtbridge::qstr(c.name);
            break;
        }
    }

    QMessageBox box(m_ui->centralwidget);
    box.setWindowTitle("Incoming File");
    box.setText(QString("<b>%1</b> wants to send you a file:<br><br>"
                        "<b>%2</b><br>"
                        "<span style='color:#888'>%3</span>")
                    .arg(senderName, fileName, formatFileSize(fileSize)));
    box.setIcon(QMessageBox::Question);

    QPushButton *acceptBtn  = box.addButton("Accept",  QMessageBox::AcceptRole);
    QPushButton *declineBtn = box.addButton("Decline", QMessageBox::RejectRole);
    box.setDefaultButton(acceptBtn);

    box.exec();
    if (box.clickedButton() == acceptBtn) {
        // Respect the user's global "require P2P" setting — ChatController
        // will OR it with our per-call flag.
        m_controller->acceptFileTransfer(transferId.toStdString(), /*requireP2P=*/false);
    } else {
        m_controller->declineFileTransfer(transferId.toStdString());
    }
    Q_UNUSED(declineBtn);
}

void ChatView::onFileTransferCanceled(const QString &transferId, bool byReceiver)
{
    const std::string transferStd = transferId.toStdString();
    // Walk every chat's file records and mark the matching transfer as failed.
    for (auto it = m_filesByKey.begin(); it != m_filesByKey.end(); ++it) {
        auto &records = it.value();
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            if (static_cast<FileTransferStatus>(rec.status) == FileTransferStatus::Complete) return; // too late
            rec.status = static_cast<int>(FileTransferStatus::Failed);
            if (m_store) m_store->saveFileRecord(it.key().toStdString(), rec);
            rebuildFilesTab();
            break;
        }
    }

    const QString msg = byReceiver
        ? "File transfer was declined or canceled by the recipient."
        : "File transfer canceled by sender.";
    showToast(msg);
}

void ChatView::onFileTransferDelivered(const QString &transferId)
{
    const std::string transferStd = transferId.toStdString();
    // Sender-side: flip the record's status to Complete with a confirmation.
    for (auto it = m_filesByKey.begin(); it != m_filesByKey.end(); ++it) {
        auto &records = it.value();
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            if (!rec.sent) return; // only meaningful on sender side
            // Transfer landed + hash verified. Keep status Complete but reflect delivery.
            rec.chunksComplete = rec.chunksTotal;
            rec.status         = static_cast<int>(FileTransferStatus::Complete);
            if (m_store) m_store->saveFileRecord(it.key().toStdString(), rec);
            rebuildFilesTab();
            showToast(QString("Delivered: %1").arg(qtbridge::qstr(rec.fileName)));
            return;
        }
    }
}

void ChatView::onFileTransferBlocked(const QString &transferId, bool byReceiver)
{
    const std::string transferStd = transferId.toStdString();
    // Mark as failed + toast explanation.
    for (auto it = m_filesByKey.begin(); it != m_filesByKey.end(); ++it) {
        auto &records = it.value();
        for (auto &rec : records) {
            if (rec.transferId != transferStd) continue;
            rec.status = static_cast<int>(FileTransferStatus::Failed);
            if (m_store) m_store->saveFileRecord(it.key().toStdString(), rec);
            rebuildFilesTab();
            break;
        }
    }

    const QString msg = byReceiver
        ? "Recipient requires a direct connection for files. Transfer aborted."
        : "Your privacy settings block relay fallback for files. Transfer aborted.";
    showToast(msg);
}
