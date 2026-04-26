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
#include <string>
#include <unordered_map>
#include <vector>

#include "AppDataStore.hpp"

class QWidget;
class QVBoxLayout;
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

// Append a "Safety Number" block to the given vertical layout: the
// 60-digit number, a status line (Verified / Mismatch / Unverified),
// and a Verify / Unverify / Re-verify button that flips the trust
// state via `controller`.  No-op when `controller` is null or
// `peerIdB64u` isn't a valid 43-char key.
//
// Both `openContactEditor` and `openConversationEditor`'s stranger
// branch use this — same primitive for two contexts because
// verification is keyed on the peer's identity key, not on
// whether they're in the address book.
void appendSafetyNumberBlock(QVBoxLayout *layout,
                              QWidget *parent,
                              ChatController *controller,
                              const QString &peerIdB64u);

// ── Contact editor (address-book row) ────────────────────────────────────────
//
// Edits a single row of the `contacts` table — i.e. an entry in the
// address book.  Strictly person-level: nickname, subtitle, avatar,
// person-mute, block, fingerprint / safety-number verification.
// Nothing here touches a `conversations` row; thread-mute and chat
// deletion live in `openConversationEditor`.
//
// Reachable from:
//   • Contacts picker (address-book list)
//   • "View Contact" drill-in from `openConversationEditor` (1:1 thread)
//   • Tap on a member row in `openGroupEditor`
//
// Mutates `contact` in place on Saved / Blocked.  Removed signals the
// caller should drop the address-book row (chat history is preserved).
// SessionReset asks the caller to wipe ratchet state for the peer.

enum class ContactEditorResult { Cancelled, Saved, Blocked, Removed, SessionReset };

/// Edit a contact row.  `isBlockedInOut` is round-tripped separately
/// from `contact` because block lives in its own `blocked_keys` table
/// (Phase 3h) and is keyed on the peer's identity, not on the
/// contact-row content.  When the user toggles the Block / Unblock
/// button the dialog flips this in-out flag and returns
/// ContactEditorResult::Blocked; the caller is responsible for
/// persisting via addBlockedKey / removeBlockedKey.
ContactEditorResult openContactEditor(
    QWidget *parent,
    AppDataStore::Contact &contact,
    bool &isBlockedInOut,
    ChatController *controller = nullptr,
    bool showDestructiveActions = true);

// ── Conversation editor (1:1 thread) ─────────────────────────────────────────
//
// Edits the `conversations` row for a 1:1 chat.  Read-only header
// shows the peer's display name (resolved via `contactIfAny` when an
// address-book entry exists, key-prefix fallback otherwise) — there
// are NO editable contact fields here.  Mutable fields are strictly
// thread-level: per-thread mute and the in-chat-list / archive flag.
//
// "View Contact" drills into `openContactEditor` for the conversation's
// `directPeerId`.  When no `Contact` row exists yet the button reads
// "Add Contact" instead — the caller-supplied `onAddContactRequested`
// hook handles routing to the existing add-contact flow with the peer
// prefilled.  `onViewContactRequested` is invoked when an entry is
// already present; the caller is responsible for pushing a nested
// modal `openContactEditor`.

enum class ConversationEditorResult {
    Cancelled, Saved, Deleted, SessionReset
};

ConversationEditorResult openConversationEditor(
    QWidget *parent,
    AppDataStore::Conversation &conv,
    const AppDataStore::Contact *contactIfAny,
    ChatController *controller = nullptr,
    std::function<void(const QString &peerIdB64u)> onViewContactRequested = {},
    std::function<void(const QString &peerIdB64u)> onAddContactRequested  = {});

// ── Group editor ─────────────────────────────────────────────────────────────
//
// Mutates a group's display name, avatar, and member list.  Members
// are passed as peer IDs; the dialog renders them by looking up each
// id in `addressBook` (a snapshot keyed by peerIdB64u → display name).
// "Add Member" picks from the same snapshot.  Self is excluded by the
// caller before the dialog opens.
//
// `onMemberActivated` is invoked when the user clicks a member row.
// The caller pushes a nested modal `openContactEditor` (or the
// add-contact flow for unknown peers); the group editor stays alive
// underneath so the user can drill in and back out without losing
// edits.

enum class GroupEditorResult {
    Cancelled, Saved, Removed, Left, SessionsReset
};

struct GroupAddressBookEntry {
    QString peerId;       // 43-char public key
    QString displayName;  // empty when peer is not yet in the address book
};

GroupEditorResult openGroupEditor(
    QWidget *parent,
    const QString &title,
    QString &nameInOut,
    QString &avatarInOut,
    bool &mutedInOut,
    QStringList &memberPeerIdsInOut,
    const std::vector<GroupAddressBookEntry> &addressBook,
    bool showDestructiveActions = true,
    std::function<void(const QString &peerIdB64u)> onMemberActivated = {});

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
// Modal list of address-book contacts.  Mirrors iOS's ContactsListView:
// a place to surface fresh peers that haven't yet produced a chat, and
// to reopen chats hidden by Delete Conversation.  The caller passes in
// the already-loaded contact snapshot so the dialog doesn't need
// database access.
//
// Returns the peerIdB64u of the chosen contact, or an empty string if
// the user cancelled.

QString openContactsPicker(QWidget *parent,
                           const std::vector<AppDataStore::Contact> &contacts,
                           const QString &myPeerId);

// ── Archived chats dialog ────────────────────────────────────────────────────
//
// Recovery surface for conversations the user hid via the editor's
// "Archive (hide from chat list)" toggle.  Lists every row in the
// `conversations` table where `in_chat_list = 0`, sorted by
// last_active DESC.  Each row offers a Restore action (flips the
// in-chat-list bit back on) and a Delete Permanently action
// (CASCADE-deletes the conversation, mirroring Delete Chat / Delete
// Group from the editors).
//
// The dialog reads its data lazily from the store so the caller
// doesn't have to keep an "archived" mirror in memory; the address-
// book snapshot is passed in so 1:1 rows can resolve to their
// contact's display name.  The `onAction` callback fires per action
// so the parent (ChatView via MainWindow) can update its own
// in-memory state to match — `Restored` means a previously-hidden
// conversation is back in the chat list and should reappear; the
// simplest correct response is to call `ChatView::initChats()`.

enum class ArchivedChatAction { Restored, Deleted };

struct ArchivedChatEvent {
    std::string         conversationId;
    ArchivedChatAction  action;
};

void openArchivedChatsDialog(
    QWidget *parent,
    AppDataStore *store,
    const std::unordered_map<std::string, AppDataStore::Contact> &contactsByPeer,
    std::function<void(const ArchivedChatEvent &)> onAction);

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
