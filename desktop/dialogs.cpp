#include "dialogs.h"

#include "ChatController.hpp"
#include "QrImage.hpp"
#include "filetransfer.h"
#include "qt_str_helpers.hpp"
#include "theme.h"
#include "theme_styles.h"

#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QColorDialog>
#include <QDesktopServices>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QProgressBar>
#include <QPushButton>
#include <QRect>
#include <QScrollArea>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>

namespace dialogs {

// ── Shared avatar + style helpers ────────────────────────────────────────────

QPixmap renderInitialsAvatar(const QString &initial, const QColor &bg, int size)
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

QPixmap makeCircularPixmap(const QPixmap &src, int size)
{
    if (size <= 0 || src.isNull()) return QPixmap();
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);

    QPainterPath path;
    path.addEllipse(0, 0, size, size);
    p.setClipPath(path);
    const QPixmap scaled = src.scaled(size, size, Qt::KeepAspectRatioByExpanding,
                                        Qt::SmoothTransformation);
    p.drawPixmap((size - scaled.width()) / 2, (size - scaled.height()) / 2, scaled);
    p.end();
    return pm;
}

void applyStyle(QWidget *dlg)
{
    dlg->setProperty("p2pRole", QLatin1String("dialog"));
    dlg->setStyleSheet(themeStyles::dialogCss(
        ThemeManager::instance().current()));
}

// ── Contact editor ───────────────────────────────────────────────────────────

ContactEditorResult openContactEditor(
    QWidget *parent,
    const QString &title,
    QString &nameInOut,
    QStringList &keysInOut,
    bool showDestructiveActions,
    bool isBlocked,
    bool isGroup,
    const std::vector<AppDataStore::Contact> *allContacts,
    std::function<void(const AppDataStore::Contact&)> onNewContact,
    QString *avatarInOut,
    ChatController *controller)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    applyStyle(&dlg);
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
            applyStyle(&picker);
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
                                    : "Remove this contact from your address book?\n\n"
                                      "Messages and file records stay — right-click "
                                      "the chat and pick \"Delete Conversation\" to "
                                      "wipe the transcript separately.";
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

// ── Profile editor ───────────────────────────────────────────────────────────

bool openProfileEditor(QWidget *parent, const ProfileInput &in, ProfileOutput &out)
{
    // ── Avatar state (shared between main dialog and photo popup) ─────────────
    bool usingPhoto = false;
    QPixmap uploadedPhoto;
    QColor avatarColor(0x2e, 0x8b, 0x3a);

    if (!in.currentAvatarB64.isEmpty()) {
        QPixmap px;
        px.loadFromData(QByteArray::fromBase64(in.currentAvatarB64.toUtf8()));
        if (!px.isNull()) { usingPhoto = true; uploadedPhoto = px; }
    }

    // ── Main profile dialog ───────────────────────────────────────────────────
    QDialog dlg(parent);
    dlg.setWindowTitle("Edit Profile");
    applyStyle(&dlg);
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

    // Captured by reference below — names the field lambdas use for the
    // initial character so swapping the display name live (in the name
    // edit) refreshes the preview.
    QString currentName = in.currentName;

    auto refreshThumb = [&]() {
        QPixmap px;
        if (usingPhoto && !uploadedPhoto.isNull())
            px = makeCircularPixmap(uploadedPhoto, 56);
        else {
            const QString nm = currentName;
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
    auto *nameEdit = new QLineEdit(in.currentName, &dlg);
    root->addWidget(nameEdit);

    // ── Your Public Key (read-only) ─────────────────────────────────────────
    root->addWidget(new QLabel("Your Public Key", &dlg));

    auto *keyRow = new QHBoxLayout;
    keyRow->setSpacing(8);

    auto *keyDisplay = new QLineEdit(in.myKey, &dlg);
    keyDisplay->setReadOnly(true);
    themeStyles::applyRole(keyDisplay, "keyDisplay",
        themeStyles::keyDisplayCss(ThemeManager::instance().current()));
    keyRow->addWidget(keyDisplay, 1);

    auto *copyBtn = new QPushButton("Copy", &dlg);
    copyBtn->setAutoDefault(false);
    themeStyles::applyRole(copyBtn, "dialogAccentBtn",
        themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
    const QString myKeyCopy = in.myKey;
    QObject::connect(copyBtn, &QPushButton::clicked, [myKeyCopy, copyBtn]() {
        QApplication::clipboard()->setText(myKeyCopy);
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
    QImage qrImg = QrImage::encodeText(in.myKey, /*pixelsPerModule=*/4);
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

    // Keep the initials preview in sync with the name field while editing
    QObject::connect(nameEdit, &QLineEdit::textChanged, [&](const QString &t) {
        currentName = t;
        refreshThumb();
    });

    // ── "Change Photo" toggles inline photo options ───────────────────────────
    QObject::connect(changePhotoBtn, &QPushButton::clicked, [&, photoOptionsWidget]() {
        const bool nowVisible = !photoOptionsWidget->isVisible();
        photoOptionsWidget->setVisible(nowVisible);
        changePhotoBtn->setText(nowVisible ? "Done" : "Change Photo");
        dlg.adjustSize();
    });

    if (dlg.exec() != QDialog::Accepted) return false;

    // ── Commit ────────────────────────────────────────────────────────────────
    out.newName = nameEdit->text().trimmed();
    out.usingPhoto = usingPhoto;

    QPixmap finalPx;
    if (usingPhoto && !uploadedPhoto.isNull()) {
        finalPx = makeCircularPixmap(uploadedPhoto, 200);
    } else {
        const QString ch = out.newName.isEmpty() ? "?" : QString(out.newName[0]);
        finalPx = renderInitialsAvatar(ch, avatarColor, 200);
    }
    out.thumb200 = finalPx;

    QByteArray bytes;
    QBuffer buf(&bytes);
    buf.open(QIODevice::WriteOnly);
    finalPx.save(&buf, "PNG");
    out.newAvatarB64 = QString::fromLatin1(bytes.toBase64());

    return true;
}

// ── File card ────────────────────────────────────────────────────────────────

FileCard::FileCard(const AppDataStore::FileRecord &rec, QWidget *parent)
    : QFrame(parent)
{
    const auto recStatus = static_cast<FileTransferStatus>(rec.status);
    const bool inFlight = (recStatus == FileTransferStatus::Sending ||
                           recStatus == FileTransferStatus::Receiving);
    const QString recFileName  = qtbridge::qstr(rec.fileName);
    const QString recSavedPath = qtbridge::qstr(rec.savedPath);
    const QString recTransferId = qtbridge::qstr(rec.transferId);

    // ── Card shell ────────────────────────────────────────────────────────────
    QFrame *card = this;
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
    QObject::connect(delBtn, &QPushButton::clicked, this, [this, delTransferId]() {
        auto reply = QMessageBox::question(
            this, "Delete File",
            "Remove this file from your file list?\n\n"
            "The file will remain on your disk.",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (reply != QMessageBox::Yes) return;
        emit deleteRequested(delTransferId);
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
        QObject::connect(thumbBtn, &QPushButton::clicked, this, [this, savedPath, imgName] {
            auto *dlg = new QDialog(this);
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

        QObject::connect(dlBtn, &QPushButton::clicked, this, [this, savedPath, fileName, isSent]() {
            if (isSent) {
                // Sent file: the savedPath IS the original file — just open its folder
                if (QFile::exists(savedPath)) {
                    QDesktopServices::openUrl(
                        QUrl::fromLocalFile(QFileInfo(savedPath).absolutePath()));
                } else {
                    QMessageBox::warning(this, "File Not Found",
                                         "The original file could not be found at:\n" + savedPath);
                }
                return;
            }

            // Received file: offer Save As into a location the user chooses
            const QString defaultDest =
                QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
                + "/" + fileName;
            const QString dest = QFileDialog::getSaveFileName(
                this, "Save File", defaultDest);
            if (dest.isEmpty()) return;

            if (!QFile::exists(savedPath)) {
                QMessageBox::warning(this, "File Not Found",
                                     "The auto-saved copy could not be found:\n" + savedPath);
                return;
            }
            if (QFile::exists(dest)) QFile::remove(dest);
            if (QFile::copy(savedPath, dest)) {
                QMessageBox::information(this, "Saved",
                                         "File saved to:\n" + dest);
            } else {
                QMessageBox::warning(this, "Copy Failed",
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
        QObject::connect(cancelFileBtn, &QPushButton::clicked, this, [this, transferId]() {
            emit cancelRequested(transferId);
        });

        bl->addWidget(cancelFileBtn);
        vl->addWidget(btnContainer);
    }
}

// ── Contacts picker ──────────────────────────────────────────────────────────

QString openContactsPicker(QWidget *parent,
                           const std::vector<AppDataStore::Contact> &contacts,
                           const QString &myPeerId)
{
    QDialog dlg(parent);
    dlg.setWindowTitle("Contacts");
    applyStyle(&dlg);
    dlg.setMinimumWidth(380);
    dlg.setMinimumHeight(480);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(12);
    root->setContentsMargins(24, 24, 24, 24);

    auto *title = new QLabel("Contacts", &dlg);
    title->setObjectName("dlgTitle");
    root->addWidget(title);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    auto *list = new QListWidget(&dlg);
    for (const auto &c : contacts) {
        if (c.isGroup) continue;
        if (!c.inAddressBook) continue;
        if (!myPeerId.isEmpty() && c.peerIdB64u == myPeerId.toStdString()) continue;
        const QString label = c.name.empty()
            ? qtbridge::qstr(c.peerIdB64u).left(8) + "…"
            : qtbridge::qstr(c.name);
        auto *item = new QListWidgetItem(label, list);
        item->setData(Qt::UserRole, qtbridge::qstr(c.peerIdB64u));
        item->setToolTip(qtbridge::qstr(c.peerIdB64u));
    }
    root->addWidget(list, /*stretch=*/1);

    QString selected;
    // Double-click or Open button picks the highlighted contact.
    QObject::connect(list, &QListWidget::itemDoubleClicked,
        [&](QListWidgetItem *item) {
            if (item) {
                selected = item->data(Qt::UserRole).toString();
                dlg.accept();
            }
        });

    auto *btnRow = new QHBoxLayout;
    auto *closeBtn = new QPushButton("Close", &dlg);
    auto *openBtn  = new QPushButton("View Info", &dlg);
    closeBtn->setObjectName("cancelBtn");
    openBtn->setObjectName("saveBtn");
    openBtn->setDefault(true);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    btnRow->addWidget(openBtn);
    root->addLayout(btnRow);

    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    QObject::connect(openBtn, &QPushButton::clicked, [&]() {
        if (auto *item = list->currentItem()) {
            selected = item->data(Qt::UserRole).toString();
            dlg.accept();
        }
    });

    dlg.exec();
    return selected;
}

}  // namespace dialogs
