#include "dialogs.h"

#include "ChatController.hpp"
#include "QrImage.hpp"
#include "filetransfer.h"
#include "qt_str_helpers.hpp"
#include "theme.h"
#include "theme_styles.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBuffer>
#include <QCheckBox>
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

void appendSafetyNumberBlock(QVBoxLayout *root,
                              QWidget *parent,
                              ChatController *controller,
                              const QString &peerIdB64u)
{
    if (!controller || peerIdB64u.size() != 43) return;
    const std::string peerIdStd = peerIdB64u.toStdString();

    auto *sn = new QFrame(parent);
    sn->setFrameShape(QFrame::HLine);
    sn->setStyleSheet("color: #2a2a2a;");
    root->addWidget(sn);

    auto *lbl = new QLabel("Safety Number", parent);
    lbl->setStyleSheet("color:#d0d0d0;font-size:13px;background:transparent;");
    root->addWidget(lbl);

    const QString number = QString::fromStdString(
        controller->safetyNumber(peerIdStd));
    auto *numLbl = new QLabel(number, parent);
    numLbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    themeStyles::applyRole(numLbl, "safetyNumber",
        themeStyles::safetyNumberCss(ThemeManager::instance().current()));
    numLbl->setWordWrap(true);
    root->addWidget(numLbl);

    auto *statusLbl = new QLabel(parent);
    auto *verifyBtn = new QPushButton(parent);
    verifyBtn->setAutoDefault(false);

    auto refresh = [controller, peerIdStd, statusLbl, verifyBtn]() {
        const Theme &th = ThemeManager::instance().current();
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

// ── Mute toggle helper (shared by both editors) ─────────────────────────────
//
// Builds the "Hide Alerts" row.  Both editors render an identical
// section so the in-out wiring is centralised.

static QCheckBox* buildMuteRow(QVBoxLayout *root, QDialog *dlg, bool initial)
{
    auto *muteSep = new QFrame(dlg);
    muteSep->setFrameShape(QFrame::HLine);
    muteSep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(muteSep);

    auto *muteCheck = new QCheckBox("Hide Alerts", dlg);
    muteCheck->setChecked(initial);
    muteCheck->setToolTip("Messages still arrive — only desktop notifications are silenced.");
    muteCheck->setStyleSheet("color:#d0d0d0;font-size:13px;");
    root->addWidget(muteCheck);
    return muteCheck;
}

// ── Avatar editor block (shared) ────────────────────────────────────────────
//
// Renders the avatar thumb + Change Photo button + inline upload/reset
// row that both the contact and group editors use.  `localAvatarRaw`
// is set when the user uploads a new image; the caller serializes it
// to PNG/base64 only on Save.  Initials fallback is rendered with
// `initial` (single character) on a green disc so the editor matches
// the chat-list avatar style.

static void buildAvatarBlock(QVBoxLayout *root, QDialog *dlg,
                             QString &localAvatar, QPixmap &localAvatarRaw,
                             const QString &initial,
                             std::function<QString()> currentInitial)
{
    auto *avatarRow = new QHBoxLayout;
    avatarRow->setSpacing(14);

    auto *avatarThumb = new QLabel(dlg);
    avatarThumb->setFixedSize(56, 56);
    avatarThumb->setAlignment(Qt::AlignCenter);

    auto refresh = [&localAvatar, &localAvatarRaw, avatarThumb,
                    initial, currentInitial]() mutable {
        QPixmap px;
        if (!localAvatarRaw.isNull()) {
            px = makeCircularPixmap(localAvatarRaw, 56);
        } else if (!localAvatar.isEmpty()) {
            QPixmap src;
            src.loadFromData(QByteArray::fromBase64(localAvatar.toUtf8()));
            if (!src.isNull()) px = makeCircularPixmap(src, 56);
        }
        if (px.isNull()) {
            QString ch = currentInitial ? currentInitial() : initial;
            if (ch.isEmpty()) ch = "?";
            px = renderInitialsAvatar(ch, QColor(0x2e, 0x8b, 0x3a), 56);
        }
        avatarThumb->setPixmap(px);
    };
    refresh();

    auto *changePhotoBtn = new QPushButton("Change Photo", dlg);
    changePhotoBtn->setAutoDefault(false);
    themeStyles::applyRole(changePhotoBtn, "dialogNeutralBtn",
        themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));

    auto *photoOptionsGroup = new QWidget(dlg);
    photoOptionsGroup->setVisible(false);
    auto *poLayout = new QVBoxLayout(photoOptionsGroup);
    poLayout->setContentsMargins(0, 4, 0, 4);
    poLayout->setSpacing(8);

    auto *pUpload = new QPushButton("Upload Photo", photoOptionsGroup);
    pUpload->setAutoDefault(false);
    themeStyles::applyRole(pUpload, "dialogNeutralBtn",
        themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
    QObject::connect(pUpload, &QPushButton::clicked, dlg,
        [dlg, &localAvatarRaw, refresh]() mutable {
            const QString path = QFileDialog::getOpenFileName(
                dlg, "Choose Photo", QString(),
                "Images (*.png *.jpg *.jpeg *.bmp)");
            if (path.isEmpty()) return;
            QPixmap px(path);
            if (px.isNull()) return;
            localAvatarRaw = px;
            refresh();
        });
    poLayout->addWidget(pUpload);

    auto *pReset = new QPushButton("Reset to Default", photoOptionsGroup);
    pReset->setAutoDefault(false);
    pReset->setObjectName("cancelBtn");
    QObject::connect(pReset, &QPushButton::clicked, dlg,
        [&localAvatar, &localAvatarRaw, refresh]() mutable {
            localAvatarRaw = QPixmap();
            localAvatar.clear();
            refresh();
        });
    poLayout->addWidget(pReset);

    QObject::connect(changePhotoBtn, &QPushButton::clicked, dlg,
        [dlg, photoOptionsGroup, changePhotoBtn]() {
            const bool v = !photoOptionsGroup->isVisible();
            photoOptionsGroup->setVisible(v);
            changePhotoBtn->setText(v ? "Done" : "Change Photo");
            dlg->adjustSize();
        });

    avatarRow->addWidget(avatarThumb);
    avatarRow->addWidget(changePhotoBtn);
    avatarRow->addStretch();
    root->addLayout(avatarRow);
    root->addWidget(photoOptionsGroup);
}

// Encode the user's pixmap upload into a PNG/base64 string.  Empty raw
// pixmap = no upload happened, leave the caller's existing string alone.
static void commitAvatarUpload(QString &localAvatar, const QPixmap &localAvatarRaw)
{
    if (localAvatarRaw.isNull()) return;
    QPixmap circ = makeCircularPixmap(localAvatarRaw, 200);
    QByteArray bytes; QBuffer buf(&bytes);
    buf.open(QIODevice::WriteOnly);
    circ.save(&buf, "PNG");
    localAvatar = QString::fromLatin1(bytes.toBase64());
}

// ── Contact editor (address-book row) ────────────────────────────────────────
//
// Strictly mutates `contact` (a row in the contacts table).  No
// thread-level fields here — those live in `openConversationEditor`.

ContactEditorResult openContactEditor(
    QWidget *parent,
    AppDataStore::Contact &contact,
    bool &isBlockedInOut,
    ChatController *controller,
    bool showDestructiveActions)
{
    const QString keyForVerification = qtbridge::qstr(contact.peerIdB64u);
    const QString initialName        = qtbridge::qstr(contact.name);
    const QString initialSubtitle    = qtbridge::qstr(contact.subtitle);

    QDialog dlg(parent);
    dlg.setWindowTitle("Edit Contact");
    applyStyle(&dlg);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    auto *titleLbl = new QLabel("Edit Contact", &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    // ── Avatar editor ────────────────────────────────────────────────────────
    QString localAvatar = qtbridge::qstr(contact.avatarB64);
    QPixmap localAvatarRaw;
    auto *nameEdit = new QLineEdit(initialName, &dlg);
    buildAvatarBlock(root, &dlg, localAvatar, localAvatarRaw,
                     initialName.isEmpty() ? QString("?") : QString(initialName[0]),
                     [nameEdit]() {
                         const QString t = nameEdit->text().trimmed();
                         return t.isEmpty() ? QString("?") : QString(t[0]);
                     });

    // ── Display Name ─────────────────────────────────────────────────────────
    root->addWidget(new QLabel("Display Name", &dlg));
    root->addWidget(nameEdit);

    // ── Subtitle ─────────────────────────────────────────────────────────────
    root->addWidget(new QLabel("Subtitle", &dlg));
    auto *subtitleEdit = new QLineEdit(initialSubtitle, &dlg);
    root->addWidget(subtitleEdit);

    // ── Public Key (read-only — peer ID is fixed in v3) ──────────────────────
    if (!keyForVerification.isEmpty()) {
        root->addWidget(new QLabel("Public Key", &dlg));
        auto *keyDisplay = new QLineEdit(keyForVerification, &dlg);
        keyDisplay->setReadOnly(true);
        themeStyles::applyRole(keyDisplay, "keyDisplay",
            themeStyles::keyDisplayCss(ThemeManager::instance().current()));
        root->addWidget(keyDisplay);
    }

    // ── Safety number block — extracted to dialogs::appendSafetyNumberBlock
    // so openConversationEditor's stranger branch can show the same UI.
    appendSafetyNumberBlock(root, &dlg, controller, keyForVerification);

    // ── Mute this person across all chats ────────────────────────────────────
    auto *muteSep = new QFrame(&dlg);
    muteSep->setFrameShape(QFrame::HLine);
    muteSep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(muteSep);

    auto *muteCheck = new QCheckBox("Mute this person across all chats", &dlg);
    muteCheck->setChecked(contact.muted);
    muteCheck->setToolTip("Silences notifications for direct messages and any "
                          "groups this contact participates in.");
    muteCheck->setStyleSheet("color:#d0d0d0;font-size:13px;");
    root->addWidget(muteCheck);

    root->addStretch();
    ContactEditorResult result = ContactEditorResult::Cancelled;

    // ── Destructive actions ──────────────────────────────────────────────────
    if (showDestructiveActions) {
        auto *actionSep = new QFrame(&dlg);
        actionSep->setFrameShape(QFrame::HLine);
        actionSep->setStyleSheet("color: #2a2a2a;");
        root->addWidget(actionSep);

        auto *actionRow = new QHBoxLayout;
        const QString destructiveStyle =
            themeStyles::destructiveBtnCss(ThemeManager::instance().current());
        const bool isBlocked = isBlockedInOut;

        auto *blockBtn = new QPushButton(isBlocked ? "Unblock Contact" : "Block Contact", &dlg);
        themeStyles::applyRole(blockBtn, "destructiveBtn", destructiveStyle);
        actionRow->addWidget(blockBtn);
        QObject::connect(blockBtn, &QPushButton::clicked, [&, isBlocked]() {
            const QString msg = isBlocked
                                    ? "Unblock this contact?"
                                    : "Block this contact? They won't be able to send you messages.";
            if (QMessageBox::question(&dlg, isBlocked ? "Unblock Contact" : "Block Contact",
                                      msg, QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                result = ContactEditorResult::Blocked;
                dlg.accept();
            }
        });

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

        auto *removeBtn = new QPushButton("Remove from Address Book", &dlg);
        themeStyles::applyRole(removeBtn, "destructiveBtn", destructiveStyle);
        actionRow->addWidget(removeBtn);
        actionRow->addStretch();
        root->addLayout(actionRow);

        QObject::connect(removeBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Remove from Address Book",
                    "Remove this contact from your address book?\n\n"
                    "Your chat history with this person stays intact — "
                    "use \"Delete Chat\" on the conversation if you want "
                    "to wipe the transcript separately.",
                    QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                result = ContactEditorResult::Removed;
                dlg.accept();
            }
        });
    }

    // ── Save / Cancel ────────────────────────────────────────────────────────
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

    // Save / Blocked / SessionReset / Removed all surface the latest
    // edits to the caller; Cancel leaves `contact` untouched.
    if (result == ContactEditorResult::Saved
        || result == ContactEditorResult::Blocked
        || result == ContactEditorResult::SessionReset) {
        contact.name      = nameEdit->text().trimmed().toStdString();
        contact.subtitle  = subtitleEdit->text().trimmed().toStdString();
        commitAvatarUpload(localAvatar, localAvatarRaw);
        contact.avatarB64 = localAvatar.toStdString();
        contact.muted     = muteCheck->isChecked();
        if (result == ContactEditorResult::Blocked) {
            isBlockedInOut = !isBlockedInOut;
        }
    }
    return result;
}

// ── Conversation editor (1:1 thread) ─────────────────────────────────────────
//
// Edits the `conversations` row for a 1:1 chat.  Read-only header
// renders the peer's display name + key prefix; mutable fields are
// strictly thread-level.

ConversationEditorResult openConversationEditor(
    QWidget *parent,
    AppDataStore::Conversation &conv,
    const AppDataStore::Contact *contactIfAny,
    ChatController *controller,
    std::function<void(const QString &peerIdB64u)> onViewContactRequested,
    std::function<void(const QString &peerIdB64u)> onAddContactRequested)
{
    const QString peerId = qtbridge::qstr(conv.directPeerId);
    const QString peerName = contactIfAny && !contactIfAny->name.empty()
        ? qtbridge::qstr(contactIfAny->name)
        : (peerId.isEmpty() ? QString("Unknown peer")
                            : peerId.left(8) + QStringLiteral("…"));

    QDialog dlg(parent);
    dlg.setWindowTitle("Conversation");
    applyStyle(&dlg);
    dlg.setMinimumWidth(420);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(14);
    root->setContentsMargins(24, 24, 24, 24);

    auto *titleLbl = new QLabel("Conversation", &dlg);
    titleLbl->setObjectName("dlgTitle");
    root->addWidget(titleLbl);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    // ── Read-only peer header ───────────────────────────────────────────────
    // The header just identifies who the chat is with — no editable
    // contact fields.  Tapping View Contact / Add Contact below opens
    // the dedicated contact editor for the peer.
    auto *peerHeader = new QLabel(peerName, &dlg);
    peerHeader->setStyleSheet("color:#eeeeee;font-size:15px;font-weight:bold;"
                              "background:transparent;");
    root->addWidget(peerHeader);

    if (!peerId.isEmpty()) {
        auto *keyDisplay = new QLineEdit(peerId, &dlg);
        keyDisplay->setReadOnly(true);
        themeStyles::applyRole(keyDisplay, "keyDisplay",
            themeStyles::keyDisplayCss(ThemeManager::instance().current()));
        root->addWidget(keyDisplay);
    }

    // ── Hide Alerts (per-thread) ────────────────────────────────────────────
    QCheckBox *muteCheck = buildMuteRow(root, &dlg, conv.muted);

    // ── Archive (in-chat-list toggle) ───────────────────────────────────────
    auto *archiveCheck = new QCheckBox("Archive (hide from chat list)", &dlg);
    archiveCheck->setChecked(!conv.inChatList);
    archiveCheck->setToolTip("Removes this chat from the list while preserving "
                             "messages and files.  Toggle off to bring it back.");
    archiveCheck->setStyleSheet("color:#d0d0d0;font-size:13px;");
    root->addWidget(archiveCheck);

    // ── View Contact / Add Contact drill-in ─────────────────────────────────
    // Only renders when we have a peer id to act on; otherwise the
    // button has no target.  When the address book already has the
    // peer the button reads "View Contact"; when not, "Add Contact"
    // is shown so the caller can route to the add-contact flow with
    // the peer prefilled.
    if (!peerId.isEmpty()) {
        auto *contactBtn = new QPushButton(
            contactIfAny ? "View Contact" : "Add Contact", &dlg);
        contactBtn->setAutoDefault(false);
        themeStyles::applyRole(contactBtn, "dialogNeutralBtn",
            themeStyles::dialogNeutralBtnCss(ThemeManager::instance().current()));
        QObject::connect(contactBtn, &QPushButton::clicked, &dlg,
            [peerId, hasContact = (contactIfAny != nullptr),
             onViewContactRequested, onAddContactRequested]() {
                // Modal-on-modal: the parent dialog stays open while
                // the child runs.  Qt handles the event loop nesting;
                // we just hand control to the caller's handler.
                if (hasContact && onViewContactRequested) {
                    onViewContactRequested(peerId);
                } else if (!hasContact && onAddContactRequested) {
                    onAddContactRequested(peerId);
                }
            });
        auto *contactRow = new QHBoxLayout;
        contactRow->addWidget(contactBtn);
        contactRow->addStretch();
        root->addLayout(contactRow);
    }

    // ── Safety number (stranger only) ───────────────────────────────────────
    // Per-peer security primitives surface here only when the peer
    // isn't in the address book yet — once they are, the same UI lives
    // in openContactEditor (reached via the View Contact button above).
    // Same reasoning as `verified_peers` being a separate table from
    // `contacts`: verification is keyed on the peer's identity key,
    // not on whether they're in your address book.
    if (!contactIfAny && !peerId.isEmpty()) {
        appendSafetyNumberBlock(root, &dlg, controller, peerId);
    }

    root->addStretch();
    ConversationEditorResult result = ConversationEditorResult::Cancelled;

    // ── Destructive: Delete Chat ────────────────────────────────────────────
    auto *actionSep = new QFrame(&dlg);
    actionSep->setFrameShape(QFrame::HLine);
    actionSep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(actionSep);

    auto *actionRow = new QHBoxLayout;
    const QString destructiveStyle =
        themeStyles::destructiveBtnCss(ThemeManager::instance().current());

    // Reset Session lives here only for STRANGER peers (no address-book
    // row).  Once the user adds the contact, the button moves to
    // openContactEditor — that's the canonical home for per-peer
    // security operations alongside fingerprint verification.
    if (!contactIfAny && !peerId.isEmpty()) {
        auto *resetBtn = new QPushButton("Reset Session", &dlg);
        actionRow->addWidget(resetBtn);
        QObject::connect(resetBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Reset Session",
                    "Wipe the encrypted session with this peer and force a "
                    "fresh handshake on the next message.  Use this if you "
                    "suspect compromise — the verified safety number will "
                    "change after reset.",
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) == QMessageBox::Yes) {
                result = ConversationEditorResult::SessionReset;
                dlg.accept();
            }
        });
    }

    auto *deleteBtn = new QPushButton("Delete Chat", &dlg);
    themeStyles::applyRole(deleteBtn, "destructiveBtn", destructiveStyle);
    actionRow->addWidget(deleteBtn);
    actionRow->addStretch();
    root->addLayout(actionRow);

    QObject::connect(deleteBtn, &QPushButton::clicked, [&]() {
        if (QMessageBox::question(&dlg, "Delete Chat",
                "This will permanently delete the message history with "
                "this person.  Their address-book entry stays intact.",
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) == QMessageBox::Yes) {
            result = ConversationEditorResult::Deleted;
            dlg.accept();
        }
    });

    // ── Save / Cancel ────────────────────────────────────────────────────────
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
        result = ConversationEditorResult::Saved;
        dlg.accept();
    });

    dlg.exec();

    if (result == ConversationEditorResult::Saved) {
        conv.muted      = muteCheck->isChecked();
        conv.inChatList = !archiveCheck->isChecked();
    }
    return result;
}

// ── Group editor ─────────────────────────────────────────────────────────────

GroupEditorResult openGroupEditor(
    QWidget *parent,
    const QString &title,
    QString &nameInOut,
    QString &avatarInOut,
    bool &mutedInOut,
    QStringList &memberPeerIdsInOut,
    const std::vector<GroupAddressBookEntry> &addressBook,
    bool showDestructiveActions,
    std::function<void(const QString &peerIdB64u)> onMemberActivated)
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

    // ── Avatar editor — group always shows # initial fallback ────────────────
    QString localAvatar = avatarInOut;
    QPixmap localAvatarRaw;
    auto *nameEdit = new QLineEdit(nameInOut, &dlg);
    buildAvatarBlock(root, &dlg, localAvatar, localAvatarRaw,
                     QString("#"),
                     [nameEdit]() {
                         const QString t = nameEdit->text().trimmed();
                         return t.isEmpty() ? QString("#") : QString(t[0]);
                     });

    // ── Display Name ─────────────────────────────────────────────────────────
    root->addWidget(new QLabel("Group Name", &dlg));
    root->addWidget(nameEdit);

    // ── Members ──────────────────────────────────────────────────────────────
    // Lookup helper: peerId → display name (empty when unknown).
    auto lookupName = [&addressBook](const QString &peerId) -> QString {
        for (const auto &e : addressBook) {
            if (e.peerId == peerId) return e.displayName;
        }
        return QString();
    };

    root->addWidget(new QLabel("Members", &dlg));

    auto *memberList = new QListWidget(&dlg);
    memberList->setFixedHeight(160);

    auto addMemberRow = [&lookupName, memberList](const QString &peerId) {
        const QString name = lookupName(peerId);
        const QString label = name.isEmpty()
            ? (peerId.left(8) + QStringLiteral("…"))
            : name;
        auto *item = new QListWidgetItem(label, memberList);
        item->setData(Qt::UserRole, peerId);
        item->setToolTip(peerId);
    };

    for (const QString &peerId : memberPeerIdsInOut) {
        addMemberRow(peerId);
    }
    root->addWidget(memberList);

    // Double-click drills into the per-member contact editor.  Single
    // click still selects (so "Remove Selected" keeps working); the
    // double-click gesture mirrors the chat-list double-click-to-open
    // pattern users already know.
    if (onMemberActivated) {
        QObject::connect(memberList, &QListWidget::itemDoubleClicked,
            [onMemberActivated](QListWidgetItem *item) {
                if (!item) return;
                const QString peerId = item->data(Qt::UserRole).toString();
                if (!peerId.isEmpty()) onMemberActivated(peerId);
            });
    }

    auto *addRow = new QHBoxLayout;
    auto *addMemberBtn = new QPushButton("Add Member", &dlg);
    auto *removeMemberBtn = new QPushButton("Remove Selected", &dlg);
    removeMemberBtn->setObjectName("cancelBtn");
    addRow->addStretch();
    addRow->addWidget(removeMemberBtn);
    addRow->addWidget(addMemberBtn);
    root->addLayout(addRow);

    QObject::connect(removeMemberBtn, &QPushButton::clicked, &dlg, [memberList]() {
        // Drop the highlighted row; idempotent when nothing is selected.
        QListWidgetItem *cur = memberList->currentItem();
        if (cur) delete cur;
    });

    QObject::connect(addMemberBtn, &QPushButton::clicked, &dlg,
        [&dlg, &addressBook, memberList, addMemberRow]() {
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
            for (const auto &e : addressBook) {
                if (e.peerId.isEmpty()) continue;
                // Filter out members already present in this group.
                bool alreadyIn = false;
                for (int i = 0; i < memberList->count(); ++i) {
                    if (memberList->item(i)->data(Qt::UserRole).toString() == e.peerId) {
                        alreadyIn = true;
                        break;
                    }
                }
                if (alreadyIn) continue;
                const QString label = e.displayName.isEmpty()
                    ? (e.peerId.left(8) + QStringLiteral("…"))
                    : e.displayName;
                auto *item = new QListWidgetItem(label, pList);
                item->setData(Qt::UserRole, e.peerId);
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
            const QString picked = pList->currentItem()->data(Qt::UserRole).toString();
            if (!picked.isEmpty()) addMemberRow(picked);
        });

    // ── Hide Alerts ──────────────────────────────────────────────────────────
    QCheckBox *muteCheck = buildMuteRow(root, &dlg, mutedInOut);

    root->addStretch();
    GroupEditorResult result = GroupEditorResult::Cancelled;

    // ── Destructive actions ──────────────────────────────────────────────────
    if (showDestructiveActions) {
        auto *actionSep = new QFrame(&dlg);
        actionSep->setFrameShape(QFrame::HLine);
        actionSep->setStyleSheet("color: #2a2a2a;");
        root->addWidget(actionSep);

        auto *actionRow = new QHBoxLayout;
        const QString destructiveStyle =
            themeStyles::destructiveBtnCss(ThemeManager::instance().current());

        auto *resetBtn = new QPushButton("Reset Sessions", &dlg);
        actionRow->addWidget(resetBtn);
        QObject::connect(resetBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Reset Sessions",
                    "Wipe the encrypted session with every member of "
                    "this group and force a fresh handshake on the next "
                    "message from each.  Use this if you suspect the "
                    "group has been compromised.  Members' verified "
                    "safety numbers will change after reset.",
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) == QMessageBox::Yes) {
                result = GroupEditorResult::SessionsReset;
                dlg.accept();
            }
        });

        auto *leaveBtn = new QPushButton("Leave Group", &dlg);
        themeStyles::applyRole(leaveBtn, "destructiveBtn", destructiveStyle);
        actionRow->addWidget(leaveBtn);
        QObject::connect(leaveBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Leave Group",
                    "Broadcast a leave notification to other members. "
                    "Your local message history is kept — to wipe it, "
                    "use Delete Group instead.",
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) == QMessageBox::Yes) {
                result = GroupEditorResult::Left;
                dlg.accept();
            }
        });

        auto *removeBtn = new QPushButton("Delete Group", &dlg);
        themeStyles::applyRole(removeBtn, "destructiveBtn", destructiveStyle);
        actionRow->addWidget(removeBtn);
        actionRow->addStretch();
        root->addLayout(actionRow);

        QObject::connect(removeBtn, &QPushButton::clicked, [&]() {
            if (QMessageBox::question(&dlg, "Delete Group",
                    "Permanently delete this group's chat view, files, "
                    "and local message history on this device.  Other "
                    "members aren't notified — use Leave Group first if "
                    "you want them to drop you from their rosters.",
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) == QMessageBox::Yes) {
                result = GroupEditorResult::Removed;
                dlg.accept();
            }
        });
    }

    // ── Save / Cancel ────────────────────────────────────────────────────────
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
        result = GroupEditorResult::Saved;
        dlg.accept();
    });

    dlg.exec();

    if (result == GroupEditorResult::Saved) {
        nameInOut   = nameEdit->text().trimmed();
        commitAvatarUpload(localAvatar, localAvatarRaw);
        avatarInOut = localAvatar;
        memberPeerIdsInOut.clear();
        for (int i = 0; i < memberList->count(); ++i)
            memberPeerIdsInOut << memberList->item(i)->data(Qt::UserRole).toString();
        if (muteCheck) mutedInOut = muteCheck->isChecked();
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
        // v3 contacts table = address-book only; no in-address-book / is-group
        // filter needed.  Skip self though.
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

// ── Archived chats dialog ────────────────────────────────────────────────────
//
// Modal recovery surface listing every conversation row where
// `inChatList == false`.  The rebuild helper repopulates the QListWidget
// from the store on each call so Restore / Delete actions can refresh
// the view without re-opening.  Display names mirror the chat list:
// 1:1 rows resolve to `contactsByPeer[directPeerId].name` when present
// (falls back to a key-prefix label), groups use `groupName`.

void openArchivedChatsDialog(
    QWidget *parent,
    AppDataStore *store,
    const std::unordered_map<std::string, AppDataStore::Contact> &contactsByPeer,
    std::function<void(const ArchivedChatEvent &)> onAction)
{
    if (!store) return;

    QDialog dlg(parent);
    dlg.setWindowTitle("Archived Chats");
    applyStyle(&dlg);
    dlg.setMinimumWidth(440);
    dlg.setMinimumHeight(520);
    dlg.setModal(true);

    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(12);
    root->setContentsMargins(24, 24, 24, 24);

    auto *title = new QLabel("Archived Chats", &dlg);
    title->setObjectName("dlgTitle");
    root->addWidget(title);

    auto *sep = new QFrame(&dlg);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#2a2a2a;");
    root->addWidget(sep);

    // Subtitle / hint — explains what the user is looking at.
    auto *hint = new QLabel(
        "Conversations you hid from your chat list. Restore brings a "
        "chat back; messages and files were preserved while it was "
        "archived.", &dlg);
    hint->setWordWrap(true);
    hint->setStyleSheet("color:#888888;font-size:12px;background:transparent;");
    root->addWidget(hint);

    // ── Stack: list of archived rows OR centered empty-state label ──────────
    auto *stack = new QFrame(&dlg);
    stack->setStyleSheet("background:transparent;border:none;");
    auto *stackLayout = new QVBoxLayout(stack);
    stackLayout->setContentsMargins(0, 0, 0, 0);
    stackLayout->setSpacing(0);

    auto *list = new QListWidget(&dlg);
    list->setSelectionMode(QAbstractItemView::NoSelection);
    list->setFocusPolicy(Qt::NoFocus);
    list->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    stackLayout->addWidget(list, /*stretch=*/1);

    auto *emptyLbl = new QLabel("No archived chats", &dlg);
    emptyLbl->setAlignment(Qt::AlignCenter);
    emptyLbl->setStyleSheet(
        "color:#777777;font-size:14px;background:transparent;border:none;"
        "padding:40px 0;");
    emptyLbl->setVisible(false);
    stackLayout->addWidget(emptyLbl, /*stretch=*/1);

    root->addWidget(stack, /*stretch=*/1);

    // ── Resolve a Conversation → display name (mirrors ChatView::displayNameFor)
    auto displayNameFor = [&contactsByPeer](
        const AppDataStore::Conversation &c) -> QString {
        if (c.kind == AppDataStore::ConversationKind::Group)
            return qtbridge::qstr(c.groupName);
        auto it = contactsByPeer.find(c.directPeerId);
        if (it != contactsByPeer.end() && !it->second.name.empty())
            return qtbridge::qstr(it->second.name);
        if (!c.directPeerId.empty())
            return qtbridge::qstr(c.directPeerId).left(8) + QStringLiteral("…");
        return QString("Unnamed conversation");
    };

    // ── Subtitle for a row ──────────────────────────────────────────────────
    // Direct: "Hidden 1:1 chat".  Group: "Group · N members" so the user
    // can tell at a glance which kind they're restoring, and how big it is.
    auto subtitleFor = [store](
        const AppDataStore::Conversation &c) -> QString {
        if (c.kind == AppDataStore::ConversationKind::Direct)
            return QStringLiteral("Hidden 1:1 chat");
        int memberCount = 0;
        store->loadConversationMembers(c.id,
            [&memberCount](const std::string &) { ++memberCount; });
        if (memberCount == 0) return QStringLiteral("Group");
        return QStringLiteral("Group · %1 member%2")
            .arg(memberCount).arg(memberCount == 1 ? "" : "s");
    };

    // Snapshot the "hidden" rows on each rebuild — sorted by last_active
    // DESC (loadAllConversations already orders this way).
    auto loadArchived = [store]() -> std::vector<AppDataStore::Conversation> {
        std::vector<AppDataStore::Conversation> out;
        store->loadAllConversations(
            [&out](const AppDataStore::Conversation &c) {
                if (!c.inChatList) out.push_back(c);
            });
        return out;
    };

    const QString destructiveStyle =
        themeStyles::destructiveBtnCss(ThemeManager::instance().current());

    // Forward-declare the rebuild lambda so per-row buttons can recurse
    // (Restore / Delete each remove a row and trigger a refresh).
    std::function<void()> rebuild;
    rebuild = [&]() {
        list->clear();
        const auto rows = loadArchived();
        const bool empty = rows.empty();
        list->setVisible(!empty);
        emptyLbl->setVisible(empty);
        if (empty) return;

        for (const auto &c : rows) {
            const QString convId = qtbridge::qstr(c.id);
            const QString name = displayNameFor(c);
            const QString sub  = subtitleFor(c);
            const bool isGroup = (c.kind == AppDataStore::ConversationKind::Group);

            auto *item = new QListWidgetItem(list);
            item->setSizeHint(QSize(0, 64));

            auto *row = new QWidget;
            row->setStyleSheet("background:transparent;");
            auto *hl = new QHBoxLayout(row);
            hl->setContentsMargins(12, 8, 12, 8);
            hl->setSpacing(10);

            // Kind glyph — # for group, ◉ for 1:1.  ASCII fallback so
            // the dialog stays readable on systems without emoji fonts.
            auto *glyph = new QLabel(isGroup ? QStringLiteral("#")
                                              : QStringLiteral("◉"), row);
            glyph->setFixedSize(28, 28);
            glyph->setAlignment(Qt::AlignCenter);
            glyph->setStyleSheet(
                "color:#5dd868;font-size:16px;font-weight:bold;"
                "background:#1a2e1c;border:1px solid #2e5e30;border-radius:14px;");
            hl->addWidget(glyph);

            // Name + subtitle — stacked vertically on the left.
            auto *textCol = new QVBoxLayout;
            textCol->setContentsMargins(0, 0, 0, 0);
            textCol->setSpacing(2);
            auto *nameLbl = new QLabel(name.isEmpty()
                ? QStringLiteral("Unnamed conversation") : name, row);
            nameLbl->setStyleSheet(
                "color:#d0d0d0;font-size:13px;font-weight:bold;"
                "background:transparent;");
            auto *subLbl = new QLabel(sub, row);
            subLbl->setStyleSheet(
                "color:#888888;font-size:11px;background:transparent;");
            textCol->addWidget(nameLbl);
            textCol->addWidget(subLbl);
            hl->addLayout(textCol, /*stretch=*/1);

            // Restore + Delete Permanently buttons.  Restore is the
            // primary affordance (accent pill); Delete is destructive
            // (red).  Both fire the onAction callback so the parent
            // ChatView can re-sync.
            auto *restoreBtn = new QPushButton("Restore", row);
            restoreBtn->setAutoDefault(false);
            themeStyles::applyRole(restoreBtn, "dialogAccentBtn",
                themeStyles::dialogAccentBtnCss(ThemeManager::instance().current()));
            QObject::connect(restoreBtn, &QPushButton::clicked, &dlg,
                [&dlg, &rebuild, store, onAction, convId]() {
                    if (!store->setConversationInChatList(
                            convId.toStdString(), /*inList=*/true)) {
                        QMessageBox::warning(&dlg, "Restore Failed",
                            "Could not restore this chat. The database may "
                            "be locked; try again in a moment.");
                        return;
                    }
                    if (onAction) onAction({convId.toStdString(),
                                            ArchivedChatAction::Restored});
                    rebuild();
                });
            hl->addWidget(restoreBtn);

            auto *deleteBtn = new QPushButton("Delete", row);
            deleteBtn->setAutoDefault(false);
            themeStyles::applyRole(deleteBtn, "destructiveBtn", destructiveStyle);
            QObject::connect(deleteBtn, &QPushButton::clicked, &dlg,
                [&dlg, &rebuild, store, onAction, convId, name, isGroup]() {
                    const QString prompt = isGroup
                        ? QStringLiteral("Permanently delete the group \"%1\" "
                                         "and all of its messages and files? "
                                         "This cannot be undone.").arg(name)
                        : QStringLiteral("Permanently delete the conversation "
                                         "with \"%1\" and all of its messages "
                                         "and files? This cannot be undone.")
                                         .arg(name);
                    if (QMessageBox::question(&dlg, "Delete Permanently",
                            prompt,
                            QMessageBox::Yes | QMessageBox::No,
                            QMessageBox::No) != QMessageBox::Yes)
                        return;
                    if (!store->deleteConversation(convId.toStdString())) {
                        QMessageBox::warning(&dlg, "Delete Failed",
                            "Could not delete this chat. The database may "
                            "be locked; try again in a moment.");
                        return;
                    }
                    if (onAction) onAction({convId.toStdString(),
                                            ArchivedChatAction::Deleted});
                    rebuild();
                });
            hl->addWidget(deleteBtn);

            list->setItemWidget(item, row);
        }
    };

    rebuild();

    // ── Close button ────────────────────────────────────────────────────────
    auto *btnRow = new QHBoxLayout;
    auto *closeBtn = new QPushButton("Close", &dlg);
    closeBtn->setObjectName("cancelBtn");
    closeBtn->setDefault(true);
    btnRow->addStretch();
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);

    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
}

}  // namespace dialogs
