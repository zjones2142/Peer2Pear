#pragma once

// Single home for the modal dialogs and avatar/style helpers used by
// chatview.cpp.  Lifted out of chatview.cpp's anonymous namespace so
// future dialog additions (profile editor, file card) can sit beside
// each other instead of growing chatview.cpp past 3K lines, and so all
// three dialogs share the same avatar / style helpers without copying.

#include <QColor>
#include <QFrame>
#include <QPixmap>
#include <QString>
#include <QStringList>

#include <functional>
#include <vector>

#include "AppDataStore.hpp"

class QWidget;
class ChatController;

namespace dialogs {

// ── Shared avatar + style helpers ────────────────────────────────────────────

// Render a circular avatar with a single-letter initial centered on a
// solid-colored disc.  Used for contact rows + profile previews.
QPixmap renderInitialsAvatar(const QString &initial, const QColor &bg, int size);

// Crop an arbitrary pixmap into a circular thumbnail of `size` px.
// Maintains aspect by KeepAspectRatioByExpanding then center-clips.
QPixmap makeCircularPixmap(const QPixmap &src, int size);

// Apply the theme-aware dialog stylesheet + tag the widget so the theme
// classifier picks it up on a live theme flip while the dialog is open.
void applyStyle(QWidget *dlg);

// ── Contact editor ───────────────────────────────────────────────────────────
//
// Modal dialog for both 1:1 contacts and groups.  Result tells the
// caller which terminal action the user took; only `Saved` populates
// nameInOut/keysInOut/avatarInOut.

enum class ContactEditorResult { Cancelled, Saved, Blocked, Removed, Left, SessionReset };

ContactEditorResult openContactEditor(
    QWidget *parent,
    const QString &title,
    QString &nameInOut,
    QStringList &keysInOut,
    bool showDestructiveActions = true,
    bool isBlocked = false,
    bool isGroup = false,
    const std::vector<AppDataStore::Contact> *allContacts = nullptr,
    std::function<void(const AppDataStore::Contact&)> onNewContact = nullptr,
    QString *avatarInOut = nullptr,
    ChatController *controller = nullptr,
    bool *isMutedInOut = nullptr);

// ── Profile editor ───────────────────────────────────────────────────────────
//
// Display-name + avatar editor used by the "Edit Profile" menu action.
// Splits the Qt dialog building out of ChatView; the caller still owns
// persistence (saveSetting) and the broadcast-to-contacts side-effect.

struct ProfileInput {
    QString currentName;
    QString currentAvatarB64;   // base64 PNG of saved avatar, or empty
    QString myKey;              // 43-char b64url public key shown as read-only
};

struct ProfileOutput {
    QString newName;            // trimmed; may be empty (caller picks default)
    QString newAvatarB64;       // base64 PNG of new avatar (initials or photo)
    QPixmap thumb200;           // 200px circular avatar, ready to downscale
    bool    usingPhoto = false; // true when user picked a photo, false for initials
};

// Returns true when the user accepted (Save); out is populated only then.
bool openProfileEditor(QWidget *parent, const ProfileInput &in, ProfileOutput &out);

// ── Contacts picker ──────────────────────────────────────────────────────────
//
// Modal list of explicit address-book contacts (in_address_book=1,
// not a group, not self).  Mirrors iOS's ContactsListView: a place
// to surface fresh peers that haven't yet produced a chat, and to
// reopen chats hidden by Delete Conversation.  The caller passes in
// the already-loaded contact snapshot so the dialog doesn't need
// database access.
//
// Returns the peerIdB64u of the chosen contact, or an empty string if
// the user cancelled.

QString openContactsPicker(QWidget *parent,
                           const std::vector<AppDataStore::Contact> &contacts,
                           const QString &myPeerId);

// ── File card ────────────────────────────────────────────────────────────────
//
// Grid tile for a single transferred file.  Emits deleteRequested /
// cancelRequested so callers can update their own in-memory state and
// rebuild the tab; the card itself only handles its render and the
// Download / open-preview interactions, which are self-contained.

class FileCard : public QFrame {
    Q_OBJECT
public:
    FileCard(const AppDataStore::FileRecord &rec, QWidget *parent = nullptr);

signals:
    void deleteRequested(const QString &transferId);
    void cancelRequested(const QString &transferId);
};

}  // namespace dialogs
