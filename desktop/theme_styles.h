#pragma once
//
// theme_styles — shared CSS-string builders + auto-classifier.
//
// SettingsPanel and ChatView both want the same kinds of widgets
// (cards, headings, key/value labels, dividers) to flip dark/light
// in lockstep.  Rather than duplicate per-section helpers in each
// translation unit, the helpers live here and read from the active
// `Theme`.
//
// The classifier (`themeStyles::reapplyForChildren`) walks a parent
// widget's findChildren and pattern-matches each child's existing
// stylesheet to one of the known roles.  This works because every
// section maker emits stylesheets in a small number of stable shapes;
// the matcher rewrites them with theme-aware versions on flip.  Brittle
// in theory (a freehand `border-radius: 10px` typo would silently break
// classification), but in practice the patterns are isolated to the
// few helpers in this file + chatview.cpp / settingspanel.cpp section
// builders, so drift is contained.

#include "theme.h"

#include <QFrame>
#include <QLabel>
#include <QString>
#include <QStringLiteral>
#include <QWidget>

namespace themeStyles {

// ── Shared CSS builders ────────────────────────────────────────────────────

inline QString cardCss(const Theme& t) {
    return QStringLiteral(
        "background-color: %1;"
        "border: 1px solid %2;"
        "border-radius: 10px;"
    ).arg(t.card.name(), t.border.name());
}

inline QString headingCss(const Theme& t) {
    return QStringLiteral(
        "color: %1;"
        "font-size: 11px;"
        "font-weight: bold;"
        "padding: 12px 16px 6px 16px;"
        "background: transparent;"
        "border: none;"
    ).arg(t.accent.name());
}

inline QString keyCss(const Theme& t, int fontSize = 13) {
    return QStringLiteral(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(t.textPrimary.name()).arg(fontSize);
}

inline QString valueCss(const Theme& t, int fontSize = 13, bool monospace = false) {
    return QStringLiteral(
        "color: %1; font-size: %2px;%3"
        "background: transparent; border: none;"
    ).arg(t.textMuted.name())
     .arg(fontSize)
     .arg(monospace ? " font-family: monospace;" : "");
}

inline QString dividerCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; background-color: %1;"
        "border: none; max-height: 1px;"
    ).arg(t.divider.name());
}

// ── ChatView-specific bubble + roster styles ──────────────────────────────
// The own-bubble color tracks the brand accent so the sender's bubbles
// always look "us"-colored regardless of theme.  The other-bubble bg
// uses the alt surface (slightly lifted from the window bg) so bubbles
// are visible against the chat scroll bg.

inline QString bubbleSelfCss(const Theme& t) {
    return QStringLiteral(
        "background-color: %1; color: #ffffff;"
        "border-radius: 14px; padding: 10px 14px; font-size: 13px;"
    ).arg(t.accent.name());
}

inline QString bubbleOtherCss(const Theme& t) {
    // Uses `surface` not `bgAlt` so bubbles have visible contrast
    // against the chat scroll bg (which paints at `bg` via qApp's
    // global stylesheet).  bgAlt sits at the same level as card and
    // would blend into the bg on dark mode.
    return QStringLiteral(
        "background-color: %1; color: %2;"
        "border-radius: 14px; padding: 10px 14px; font-size: 13px;"
    ).arg(t.surface.name(), t.textPrimary.name());
}

inline QString senderNameCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 11px;"
        "background: transparent; padding-left: 4px;"
    ).arg(t.accent.name());
}

// Sidebar chat-name label.
inline QString chatNameCss(const Theme& t, int fontSize = 13) {
    return QStringLiteral(
        "color: %1; font-size: %2px; background: transparent;"
    ).arg(t.textPrimary.name()).arg(fontSize);
}

// Caption / metadata label (timestamps, file sizes, etc.).
inline QString captionCss(const Theme& t, int fontSize = 11) {
    return QStringLiteral(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(t.textSecondary.name()).arg(fontSize);
}

// File thumbnail surface — top half of a file bubble, square top corners.
inline QString fileThumbCss(const Theme& t) {
    return QStringLiteral(
        "background-color: %1;"
        "border-radius: 10px 10px 0 0;"
        "border: none;"
    ).arg(t.bgAlt.name());
}

// File-card shell — the whole bubble holding thumbnail + metadata.
// Distinct from the 10px Settings card because file cards carry a
// slightly lighter surface + 12px radius per the chat design.
inline QString fileCardCss(const Theme& t) {
    return QStringLiteral(
        "QFrame#fileCard{"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 12px;"
        "}"
    ).arg(t.card.name(), t.border.name());
}

// Vertical separator in dialogs (the `color` attr drives the QFrame line).
inline QString separatorLineCss(const Theme& t) {
    return QStringLiteral("color: %1;").arg(t.divider.name());
}

// Unread / online dot — accent-colored small disc.
inline QString unreadDotCss(const Theme& t) {
    return QStringLiteral(
        "QLabel{background-color: %1; border-radius: 4px;}"
    ).arg(t.accent.name());
}

// ── MainWindow chrome (from the .ui file) ─────────────────────────────────
//
// The widgets below have their stylesheets set in mainwindow.ui, which
// Qt Designer bakes into the generated code.  We can't edit those sheets
// at runtime through the .ui mechanism, so MainWindow calls
// `applyChromeStyles(ui)` after setupUi — it tags each named widget with
// a p2pRole property + writes a theme-aware stylesheet that overrides
// the baked-in dark one.

// Full MainWindow shell stylesheet — port of the ~40-selector dark
// stylesheet baked into mainwindow.ui:22.  The .ui sheet is set on
// the QMainWindow itself so overwriting it requires reproducing
// EVERY selector; dropping any means that slice of the UI falls
// back to the Fusion-palette global and drifts visually from the
// intended chat design.
//
// Kept in one function so the color mapping is auditable in one
// place; selectors ordered to match the original .ui so future
// diffs stay small.
inline QString windowShellCss(const Theme& t) {
    const QString bg          = t.bg.name();
    const QString card        = t.card.name();
    const QString surface     = t.surface.name();
    const QString bgAlt       = t.bgAlt.name();
    const QString border      = t.border.name();
    const QString divider     = t.divider.name();
    const QString textPrimary = t.textPrimary.name();
    const QString textMuted   = t.textMuted.name();
    const QString textSec     = t.textSecondary.name();
    const QString accent      = t.accent.name();
    const QString accentSoft  = t.accentSoft.name();
    const QString accentLit   = t.accent.lighter(115).name();
    const QString accentDrk   = t.accent.darker(115).name();

    return QStringLiteral(
        // Base
        "QMainWindow, QWidget#centralwidget, QWidget#appWidget {"
        "  background-color: %1; color: %2;"
        "  font-family: \"Segoe UI\", \"SF Pro Text\", Arial, sans-serif;"
        "}"
        // Top header
        "QWidget#topHeader {"
        "  background-color: %3; border-bottom: 1px solid %5;"
        "}"
        "QLabel#logoLabel { color: %2; font-size: 18px; font-weight: bold; padding-left: 8px; }"
        // Search bar
        "QLineEdit#searchEdit_12 {"
        "  background-color: %4; color: %2; border: 1px solid %5;"
        "  border-radius: 18px; padding: 7px 16px; font-size: 13px;"
        "  selection-background-color: %11;"
        "}"
        "QLineEdit#searchEdit_12:focus { border: 1px solid %11; color: %2; }"
        "QLineEdit#searchEdit_12::placeholder { color: %8; }"
        // Settings button in header
        "QToolButton#settingsBtn_12 {"
        "  background-color: transparent; border: none;"
        "  color: %7; font-size: 18px; padding: 4px; border-radius: 6px;"
        "}"
        "QToolButton#settingsBtn_12:hover {"
        "  color: %11; background-color: %12;"
        "}"
        // Sidebar
        "QWidget#sidebarWidget {"
        "  background-color: %3; border-right: 1px solid %5;"
        "}"
        "QWidget#profileWidget {"
        "  background-color: %3; border-bottom: 1px solid %5;"
        "}"
        // Profile avatar + name
        "QLabel#profileAvatarLabel {"
        "  background-color: transparent; color: %2;"
        "  font-size: 15px; font-weight: bold; border-radius: 20px;"
        "  min-width: 40px; max-width: 40px; min-height: 40px; max-height: 40px;"
        "}"
        "QLabel#profileNameLabel { color: %2; font-size: 13px; font-weight: bold; }"
        "QLabel#profileHandleLabel { color: %8; font-size: 11px; }"
        // New-chat button
        "QPushButton#newChatBtn {"
        "  background-color: %12; color: %11; border: 1px solid %11;"
        "  border-radius: 8px; font-size: 12px; font-weight: bold;"
        "  padding: 6px 12px;"
        "}"
        "QPushButton#newChatBtn:hover {"
        "  background-color: %12; border-color: %13; color: %13;"
        "}"
        // Chat list
        "QListWidget#chatList {"
        "  background-color: %3; border: none; outline: none;"
        "  font-size: 14px; color: %7;"
        "}"
        "QListWidget#chatList::item {"
        "  padding: 14px 16px; border-bottom: 1px solid %5;"
        "  min-height: 20px;"
        "}"
        "QListWidget#chatList::item:selected {"
        "  background-color: %12; color: %2;"
        "  border-left: 3px solid %11; padding-left: 13px;"
        "}"
        "QListWidget#chatList::item:hover:!selected {"
        "  background-color: %4;"
        "}"
        // Scrollbars
        "QScrollBar:vertical { background-color: transparent; width: 6px; margin: 0; }"
        "QScrollBar::handle:vertical {"
        "  background-color: %5; border-radius: 3px; min-height: 30px;"
        "}"
        "QScrollBar::handle:vertical:hover { background-color: %11; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QScrollBar:horizontal { height: 0; }"
        // Content area
        "QWidget#contentWidget { background-color: %1; }"
        "QWidget#chatHeader { background-color: %3; border-bottom: 1px solid %5; }"
        "QLabel#chatTitleLabel { color: %2; font-size: 16px; font-weight: bold; letter-spacing: 0.2px; }"
        "QLabel#chatSubLabel { color: %11; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }"
        "QWidget#contentContainer { background-color: %1; }"
        // Tabs.  QTabBar itself needs an explicit bg + border:none —
        // without this, Qt's native style paints a slightly-different
        // shade behind the tab strip (visible as a darker box around
        // the selected tab) instead of inheriting from chatHeader.
        // The :selected and :hover states also need background-color
        // re-asserted as transparent so the tab text stays clean.
        "QTabWidget#mainTabs { background-color: %1; }"
        "QTabWidget#mainTabs::pane { border: none; background-color: %1; }"
        "QTabBar { background-color: %1; border: none; }"
        // QTabBar::tab — `transparent` background isn't enough because
        // Fusion style paints a button-fill behind subcontrols anyway.
        // Setting bg explicitly to %1 (pane color) makes the tab cells
        // visually disappear into the strip, leaving only the green
        // underline as the selected indicator.  margin pinned at 0 to
        // stop Fusion from shifting the selected tab up into the
        // chatHeader border-bottom line above.
        "QTabBar::tab {"
        "  background-color: %1; color: %8;"
        "  font-size: 13px; padding: 10px 20px; border: none;"
        "  border-bottom: 2px solid %1;"
        "  margin: 0 2px 0 0;"
        "  font-weight: 500;"
        "}"
        "QTabBar::tab:selected {"
        "  background-color: %1; color: %11;"
        "  border-bottom: 2px solid %11;"
        "  margin: 0 2px 0 0;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "  background-color: %1; color: %7;"
        "  margin: 0 2px 0 0;"
        "}"
        // Message scroll
        "QScrollArea#messageScroll { background-color: %1; border: none; }"
        "QWidget#scrollAreaWidgetContents { background-color: %1; }"
        // Files tab
        "QScrollArea#filesScroll { background-color: %1; border: none; }"
        "QWidget#filesScrollContents { background-color: %1; }"
        "QFrame#fileCard1, QFrame#fileCard2, QFrame#fileCard3 {"
        "  background-color: %6; border: 1px solid %5; border-radius: 12px;"
        "}"
        "QLabel#fileThumb1, QLabel#fileThumb2, QLabel#fileThumb3 {"
        "  background-color: %4; color: %8;"
        "  font-size: 36px; border-radius: 8px; min-height: 140px;"
        "}"
        "QLabel#fileName1, QLabel#fileName2, QLabel#fileName3 {"
        "  color: %2; font-size: 13px; font-weight: bold;"
        "}"
        "QLabel#fileSize1, QLabel#fileSize2, QLabel#fileSize3 {"
        "  color: %7; font-size: 11px;"
        "}"
        "QLabel#fileSender1, QLabel#fileSender2, QLabel#fileSender3 {"
        "  color: %8; font-size: 11px;"
        "}"
        "QPushButton#dlBtn1, QPushButton#dlBtn2, QPushButton#dlBtn3 {"
        "  background-color: %12; color: %11; border: 1px solid %11;"
        "  border-radius: 8px; font-size: 13px; font-weight: bold;"
        "  padding: 8px; min-height: 36px;"
        "}"
        "QPushButton#dlBtn1:hover, QPushButton#dlBtn2:hover, QPushButton#dlBtn3:hover {"
        "  background-color: %11; color: #ffffff;"
        "}"
        // Input bar
        "QWidget#inputBar { background-color: %3; border-top: 1px solid %5; }"
        "QToolButton#attachBtn {"
        "  background-color: transparent; border: 1px solid %5;"
        "  border-radius: 20px; color: %7; font-size: 16px;"
        "  min-width: 40px; max-width: 40px; min-height: 40px; max-height: 40px;"
        "}"
        "QToolButton#attachBtn:hover {"
        "  background-color: %4; border-color: %11; color: %2;"
        "}"
        "QLineEdit#messageInput {"
        "  background-color: %4; color: %2; border: 1px solid %5;"
        "  border-radius: 22px; padding: 11px 20px; font-size: 14px;"
        "  selection-background-color: %11;"
        "}"
        "QLineEdit#messageInput:focus { border: 1px solid %11; background-color: %6; }"
        "QPushButton#sendBtn {"
        "  background-color: %11; color: #ffffff; border: none;"
        "  border-radius: 20px; font-size: 14px; font-weight: bold;"
        "  min-width: 80px; max-width: 80px;"
        "  min-height: 40px; max-height: 40px; letter-spacing: 0.3px;"
        "}"
        "QPushButton#sendBtn:hover { background-color: %13; }"
        "QPushButton#sendBtn:pressed { background-color: %14; }"
        // QMainWindow's auto-created QStatusBar — used as a footer
        // strip even though we never push messages into it.  Without
        // an explicit rule it inherits macOS native style which
        // paints a gradient that doesn't match the rest of the chrome.
        // %6 (surface) gives a uniformly-lighter footer; visible but
        // subtle, no gradient.
        "QStatusBar { background-color: %6; border: none; color: %2; }"
        "QStatusBar::item { border: none; }"
        // Edit / Add icon buttons
        "QToolButton#editProfileBtn, QToolButton#editItemBtn {"
        "  background-color: transparent; border: none;"
        "  color: %7; font-size: 16px; border-radius: 6px;"
        "}"
        "QToolButton#editProfileBtn:hover, QToolButton#editItemBtn:hover {"
        "  color: %11; background-color: %12;"
        "}"
    )
    // 12 args for placeholders %1-%8 + %11-%14.  The template has no
    // %9 or %10, so we DO NOT call .arg() for them — QString::arg
    // always fills the lowest-numbered remaining placeholder, and an
    // unmatched dummy arg would shift every subsequent value into the
    // wrong slot (accent→border, accentSoft→accent, etc.).
    .arg(bg)            // %1  window bg
    .arg(textPrimary)   // %2  primary text
    .arg(card)          // %3  card / elevated surface
    .arg(bgAlt)         // %4  input bg
    .arg(border)        // %5  border / divider
    .arg(surface)       // %6  raised surface (file cards)
    .arg(textSec)       // %7  secondary text
    .arg(textMuted)     // %8  muted / placeholder
    .arg(accent)        // %11 accent / focus
    .arg(accentSoft)    // %12 accent-soft / selected
    .arg(accentLit)     // %13 accent-lighter (hover)
    .arg(accentDrk);    // %14 accent-darker (pressed)
}

// Sidebar footer strip holding the + button — matches mainwindow.ui:433.
inline QString sidebarFooterCss(const Theme& t) {
    return QStringLiteral(
        "background-color: %1; border-top: 1px solid %2;"
    ).arg(t.card.name(), t.border.name());
}

// Chat-header avatar label — green circle with the first letter of the
// contact's name.  Matches mainwindow.ui:540.
inline QString chatAvatarCss(const Theme& t) {
    return QStringLiteral(
        "background-color: transparent; color: %1;"
        "font-size: 15px; font-weight: bold;"
        "border-radius: 20px;"
        "min-width: 44px; max-width: 44px;"
        "min-height: 44px; max-height: 44px;"
    ).arg(t.accent.name());
}

// Neutral toolbar icon button — transparent base, accent on hover.
// Used by editProfileBtn (mainwindow.ui:378).
inline QString toolIconBtnCss(const Theme& t) {
    return QStringLiteral(
        "QToolButton {"
        "  background-color: transparent; border: none;"
        "  color: %1; font-size: 16px; border-radius: 6px;"
        "}"
        "QToolButton:hover {"
        "  color: %2; background-color: %3;"
        "}"
    ).arg(t.textMuted.name(), t.accent.name(), t.accentSoft.name());
}

// Accent round-button — the + addContact button (mainwindow.ui:479).
inline QString accentRoundBtnCss(const Theme& t) {
    return QStringLiteral(
        "QToolButton {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  color: %2;"
        "  font-size: 22px; border-radius: 18px;"
        "}"
        "QToolButton:hover {"
        "  background-color: %3;"
        "  border-color: %4;"
        "  color: %4;"
        "}"
    ).arg(t.accentSoft.name(),
          t.accent.name(),
          t.accentSoft.lighter(115).name(),
          t.accent.lighter(110).name());
}

// Segmented-picker button — used by both the Privacy level picker
// (Standard / Enhanced / Maximum) and the Appearance picker
// (Dark / Light / System).  Three visual states: normal / hover /
// checked.  Checked state uses accent-soft bg + accent text + border.
inline QString segmentButtonCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 6px;"
        "  padding: 8px 14px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover { background-color: %4; color: %5; }"
        "QPushButton:checked {"
        "  background-color: %6;"
        "  color: %7;"
        "  border: 1px solid %7;"
        "  font-weight: bold;"
        "}"
    ).arg(t.bgAlt.name(),        // %1 normal bg
          t.textSecondary.name(),// %2 normal text
          t.border.name(),       // %3 normal border
          t.bgAlt.lighter(115).name(), // %4 hover bg
          t.textPrimary.name(),  // %5 hover text
          t.accentSoft.name(),   // %6 checked bg
          t.accent.name());      // %7 checked text + border
}

// ── SettingsPanel toggle buttons + status labels ───────────────────────────
// Every on/off toggle in SettingsPanel uses the same 2-state shape:
// when active the button sits in danger colors (red "Disable") so
// clicking it looks like a warning action; when inactive it sits in
// accent colors (green "Enable") inviting activation.  Status labels
// alongside read "Enabled"/"On" in accent or "Disabled"/"Off" in muted.

inline QString toggleDangerCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: %4; }"
    ).arg(t.dangerBg.name(), t.dangerText.name(),
          t.dangerText.darker(130).name(),
          t.dangerBg.lighter(115).name());
}

inline QString toggleAccentCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; font-size: 12px;"
        "}"
        "QPushButton:hover { background-color: %4; }"
    ).arg(t.accentSoft.name(), t.accent.name(), t.accent.name(),
          t.accentSoft.lighter(115).name());
}

inline QString statusAccentCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 13px; background: transparent; border: none;"
    ).arg(t.accent.name());
}

inline QString statusMutedCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 13px; background: transparent; border: none;"
    ).arg(t.textMuted.name());
}

// Online / offline presence label in the chat header.  11px bold with
// letter-spacing — used by chatSubLabel in the .ui-defined chat header.
// Falls outside the QLabel#chatSubLabel rule in windowShellCss because
// we need a distinct color for the online vs offline states.
inline QString onlineStatusCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
    ).arg(t.accent.name());
}

inline QString offlineStatusCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 11px; font-weight: bold; letter-spacing: 0.5px;"
    ).arg(t.textMuted.name());
}

// Safety-number dialog status labels.  All 12px on transparent bg.
// Three variants: verified (accent), mismatch (warning), unverified
// (muted).  Mismatch uses the new Theme.warningText token so the
// orange attention-needed read-back flips from a light orange (dark
// mode) to a rusty brown (light mode) instead of staying bright
// orange in both.
inline QString statusVerifiedCss(const Theme& t) {
    return QStringLiteral(
        "QLabel{color: %1; font-size: 12px; background: transparent;}"
    ).arg(t.accent.name());
}

inline QString statusWarningCss(const Theme& t) {
    return QStringLiteral(
        "QLabel{color: %1; font-size: 12px; background: transparent;}"
    ).arg(t.warningText.name());
}

inline QString statusUnverifiedCss(const Theme& t) {
    return QStringLiteral(
        "QLabel{color: %1; font-size: 12px; background: transparent;}"
    ).arg(t.textSecondary.name());
}

// ── Dialog-internal buttons ────────────────────────────────────────────────
// These live INSIDE dialogs whose chrome is already themed via
// `dialogCss`, but they override QDialog's generic QPushButton rule
// with widget-level stylesheets.  We provide explicit helpers so
// those overrides stay theme-aware.

// Neutral dialog button — used for Change Photo / Upload Photo /
// Verify / other non-destructive actions.  Gray on dark, tint on
// light so it stands out from QDialog bg without competing with
// the accent-colored primary actions.
inline QString dialogNeutralBtnCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background: %1; color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 8px; padding: 8px 14px; font-size: 13px;"
        "}"
        "QPushButton:hover { background: %4; border: 1px solid %5; }"
    ).arg(t.bgAlt.name(),
          t.textPrimary.name(),
          t.border.name(),
          t.bgAlt.lighter(115).name(),
          t.accent.name());
}

// Accent pill button — used by Copy (in Edit Profile), Paste (Add
// Contact), the group-create button, and similar "positive action"
// buttons inside dialogs that the accent round-button doesn't cover.
inline QString dialogAccentBtnCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background: %1; color: %2;"
        "  border: 1px solid %2;"
        "  border-radius: 8px; padding: 8px 14px; font-size: 12px;"
        "}"
        "QPushButton:hover { background: %3; }"
    ).arg(t.accentSoft.name(),
          t.accent.name(),
          t.accentSoft.lighter(115).name());
}

// 60-digit safety-number display — monospace QLabel with card surface,
// primary text, border.  Used inside the safety-number verification
// dialog; distinct from keyDisplayCss because it sits in a QLabel
// (not QLineEdit) with 13px font + letter-spacing for legibility of
// the digit groups.
inline QString safetyNumberCss(const Theme& t) {
    return QStringLiteral(
        "QLabel {"
        "  color: %1; background: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 10px 14px;"
        "  font-family: 'Menlo','Monaco',monospace; font-size: 13px;"
        "  letter-spacing: 0.5px;"
        "}"
    ).arg(t.textPrimary.name(), t.card.name(), t.border.name());
}

// Larger destructive button — used in Contact Edit for "Block",
// "Reset Session", "Remove Contact".  Same color semantic as
// toggleDangerCss but bigger (8px radius + 8px 16px padding) to
// match the row of action buttons in the contact editor footer.
inline QString destructiveBtnCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 8px;"
        "  padding: 8px 16px;"
        "}"
        "QPushButton:hover { background-color: %4; }"
    ).arg(t.dangerBg.name(), t.dangerText.name(),
          t.dangerText.darker(130).name(),
          t.dangerBg.lighter(115).name());
}

// Themed QLineEdit — used by SettingsPanel's relay URL field.  Same
// shape as the global QLineEdit rule but exposed as a helper so the
// classifier can stamp + reapply on theme flips.
inline QString lineEditCss(const Theme& t, int fontSize = 13) {
    return QStringLiteral(
        "QLineEdit {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; padding: 5px 8px; font-size: %4px;"
        "}"
        "QLineEdit:focus { border: 1px solid %5; }"
    ).arg(t.bgAlt.name(), t.textPrimary.name(), t.border.name())
     .arg(fontSize)
     .arg(t.accent.name());
}

// "Apply" / similar gated-action button — three states: enabled
// (subtle accent tint), hover (stronger accent), disabled (muted).
// Distinct from dialogAccentBtnCss because it stays neutral until
// the form actually has a pending change.
inline QString applyBtnCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; padding: 5px 12px; font-size: 12px;"
        "}"
        "QPushButton:hover:enabled { background-color: %4; color: %5; }"
        "QPushButton:disabled {"
        "  background-color: %6; color: %7; border-color: %3;"
        "}"
    ).arg(t.accentSoft.name(),    // %1 enabled bg
          t.textPrimary.name(),   // %2 enabled text
          t.border.name(),        // %3 border
          t.accentSoft.lighter(115).name(), // %4 hover bg
          t.accent.name(),        // %5 hover text
          t.bg.name(),            // %6 disabled bg
          t.textMuted.name());    // %7 disabled text
}

// Themed QComboBox + QSpinBox — the global stylesheet covers these
// generically, but several SettingsPanel sites set widget-level
// stylesheets that override the global with hardcoded dark colors.
// Use these helpers to set the per-widget sheet from the active theme.
inline QString comboCss(const Theme& t, int fontSize = 12) {
    return QStringLiteral(
        "QComboBox {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; padding: 4px 8px; font-size: %4px;"
        "}"
        "QComboBox:hover { border-color: %5; }"
    ).arg(t.bgAlt.name(), t.textPrimary.name(), t.border.name())
     .arg(fontSize)
     .arg(t.accent.name());
}

inline QString spinBoxCss(const Theme& t, int fontSize = 13) {
    return QStringLiteral(
        "QSpinBox {"
        "  background-color: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 6px; padding: 3px 6px; font-size: %4px;"
        "}"
    ).arg(t.bgAlt.name(), t.textPrimary.name(), t.border.name())
     .arg(fontSize);
}

// Read-only key readout — shows the 43-char base64url peer ID as a
// monospace-text QLineEdit.  Distinct from the QLineEdit rule in
// dialogCss (which targets editable inputs) — read-only gets a
// muted foreground so copy-paste targeting is obvious.
inline QString keyDisplayCss(const Theme& t) {
    return QStringLiteral(
        "QLineEdit {"
        "  background: %1; color: %2; border: 1px solid %3;"
        "  border-radius: 8px; padding: 8px 12px;"
        "  font-size: 12px; font-family: monospace;"
        "}"
    ).arg(t.card.name(), t.textSecondary.name(), t.border.name());
}

// Settings header title label — bold 16px in primary text color.
inline QString headerTitleCss(const Theme& t) {
    return QStringLiteral(
        "color: %1; font-size: 16px; font-weight: bold;"
    ).arg(t.textPrimary.name());
}

// SettingsPanel's back button — transparent base with secondary-text
// color, hover flips to primary.
inline QString backBtnCss(const Theme& t) {
    return QStringLiteral(
        "QPushButton#settingsBackBtn {"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 8px;"
        "  font-size: 13px;"
        "  padding: 4px 10px;"
        "}"
        "QPushButton#settingsBackBtn:hover {"
        "  color: %3; border-color: %4;"
        "}"
    ).arg(t.textSecondary.name(), t.border.name(),
          t.textPrimary.name(), t.accent.name());
}

// Thin messageScroll scrollbar (mainwindow.ui:650).
inline QString thinScrollBarCss(const Theme& t) {
    return QStringLiteral(
        "QScrollBar:vertical { background-color: %1; width: 6px; margin: 0; }"
    ).arg(t.bgAlt.name());
}

// Shared QDialog stylesheet — covers the common widgets that show up
// across Edit Profile / Add Contact / group editor dialogs.  Before
// this lived as a single `static const char* kDlgStyle` hardcoded to
// dark; themed variant rebuilds the whole selector-set from the active
// Theme so dialogs match the user's chosen appearance.
inline QString dialogCss(const Theme& t) {
    // Button hover variants — shade the base color slightly so the
    // state transition is legible without falling off the palette.
    const QString btnHoverBg = t.accent.lighter(115).name();
    const QString cancelBg   = t.card.name();
    const QString cancelHov  = t.bgAlt.name();
    return QStringLiteral(
        "QDialog { background-color: %1; color: %2; }"
        "QLabel { color: %3; font-size: 12px; }"
        "QLabel#dlgTitle { color: %2; font-size: 15px; font-weight: bold; }"
        "QLineEdit { background-color: %4; color: %2; border: 1px solid %5;"
        "  border-radius: 8px; padding: 8px 12px; font-size: 13px; }"
        "QLineEdit:focus { border: 1px solid %6; }"
        "QListWidget { background-color: %4; color: %2; border: 1px solid %5;"
        "  border-radius: 8px; font-size: 13px; }"
        "QListWidget::item { padding: 6px 10px; border-bottom: 1px solid %5; }"
        "QListWidget::item:selected { background-color: %7; color: %2; }"
        "QPushButton { background-color: %7; color: %6; border: 1px solid %6;"
        "  border-radius: 8px; font-size: 13px; padding: 8px 16px; }"
        "QPushButton:hover { background-color: %7; border-color: %6; }"
        "QPushButton#saveBtn   { background-color: %6; color: #ffffff; border: none; }"
        "QPushButton#saveBtn:hover { background-color: %8; }"
        "QPushButton#cancelBtn { background-color: %9; color: %3; border: 1px solid %5; }"
        "QPushButton#cancelBtn:hover { background-color: %10; color: %2; }"
        "QPushButton#removeKeyBtn { background-color: %11; color: %12; border: 1px solid %5; }"
        "QPushButton#removeKeyBtn:hover { background-color: %11; }"
    )
    .arg(t.card.name())          // %1 dialog bg
    .arg(t.textPrimary.name())   // %2 primary text
    .arg(t.textSecondary.name()) // %3 muted text
    .arg(t.bgAlt.name())         // %4 input bg
    .arg(t.border.name())        // %5 border
    .arg(t.accent.name())        // %6 accent / focus
    .arg(t.accentSoft.name())    // %7 accent-soft / selected row
    .arg(btnHoverBg)             // %8 save hover
    .arg(cancelBg)               // %9 cancel bg
    .arg(cancelHov)              // %10 cancel hover
    .arg(t.dangerBg.name())      // %11 danger bg
    .arg(t.dangerText.name());   // %12 danger text
}

// ── Auto-classifier ────────────────────────────────────────────────────────
// Walks every child widget under `parent` and, for each one whose
// stylesheet matches a known shape, rewrites it with a theme-driven
// equivalent.  Idempotent + safe to call repeatedly (e.g. on every
// themeChanged emission).

// Applies the stylesheet for a known role and stamps the widget with
// `p2pRole` so later calls can skip CSS-content matching.  CSS matching
// only works the FIRST time — after we rewrite the sheet the original
// dark literals (#cccccc, #111111, …) are gone and we'd miss the next
// theme flip.  The property tag is the stable handle.
inline void applyRole(QWidget* w, const char* role, const QString& css) {
    w->setProperty("p2pRole", QLatin1String(role));
    w->setStyleSheet(css);
}

// Tag the MainWindow chrome widgets by objectName so the classifier
// picks them up on every theme flip.  Designer-baked stylesheets are
// immediately overwritten with theme-driven equivalents.  Safe to call
// once after setupUi — properties stick even if a widget gets re-
// parented; subsequent theme flips hit the fast-path.
inline void tagChromeWidgets(QWidget* root, const Theme& t) {
    auto tagIf = [&](const char* objName, const char* role,
                      const QString& css) {
        if (auto* w = root->findChild<QWidget*>(QLatin1String(objName))) {
            applyRole(w, role, css);
        }
    };
    // QMainWindow itself owns the shell sheet (not reachable via
    // findChild because the main window is the root, not a child).
    applyRole(root, "windowShell", windowShellCss(t));
    tagIf("sidebarFooter",   "sidebarFooter",   sidebarFooterCss(t));
    tagIf("chatAvatarLabel", "chatAvatar",      chatAvatarCss(t));
    tagIf("editProfileBtn",  "toolIconBtn",     toolIconBtnCss(t));
    tagIf("addContactBtn",   "accentRoundBtn",  accentRoundBtnCss(t));
    tagIf("messageScroll",   "thinScrollBar",   thinScrollBarCss(t));
}

inline void reapplyForChildren(QWidget* parent, const Theme& t) {
    for (auto* w : parent->findChildren<QWidget*>()) {
        // Fast path — widget has been tagged (either at construction
        // for bubbles / sender names, or by a prior CSS-match pass
        // for SettingsPanel surfaces).  Dispatch by role + move on.
        const QString role = w->property("p2pRole").toString();
        if (!role.isEmpty()) {
            auto* lbl   = qobject_cast<QLabel*>(w);
            auto* frame = qobject_cast<QFrame*>(w);
            const QString sheet = w->styleSheet();
            const bool mono = sheet.contains(QLatin1String("font-family: monospace"));
            if      (role == QLatin1String("card"))        w->setStyleSheet(cardCss(t));
            else if (role == QLatin1String("heading"))     w->setStyleSheet(headingCss(t));
            else if (role == QLatin1String("key13"))       w->setStyleSheet(keyCss(t, 13));
            else if (role == QLatin1String("value13"))     w->setStyleSheet(valueCss(t, 13, mono));
            else if (role == QLatin1String("value12"))     w->setStyleSheet(valueCss(t, 12, mono));
            else if (role == QLatin1String("divider") && frame) w->setStyleSheet(dividerCss(t));
            else if (role == QLatin1String("bubbleSelf"))  w->setStyleSheet(bubbleSelfCss(t));
            else if (role == QLatin1String("bubbleOther")) w->setStyleSheet(bubbleOtherCss(t));
            else if (role == QLatin1String("senderName"))  w->setStyleSheet(senderNameCss(t));
            else if (role == QLatin1String("chatName13"))  w->setStyleSheet(chatNameCss(t, 13));
            else if (role == QLatin1String("chatName14"))  w->setStyleSheet(chatNameCss(t, 14));
            else if (role == QLatin1String("caption11"))   w->setStyleSheet(captionCss(t, 11));
            else if (role == QLatin1String("caption12"))   w->setStyleSheet(captionCss(t, 12));
            else if (role == QLatin1String("unreadDot"))   w->setStyleSheet(unreadDotCss(t));
            else if (role == QLatin1String("fileThumb"))   w->setStyleSheet(fileThumbCss(t));
            else if (role == QLatin1String("fileCard"))    w->setStyleSheet(fileCardCss(t));
            else if (role == QLatin1String("separator"))   w->setStyleSheet(separatorLineCss(t));
            else if (role == QLatin1String("dialog"))      w->setStyleSheet(dialogCss(t));
            else if (role == QLatin1String("windowShell"))   w->setStyleSheet(windowShellCss(t));
            else if (role == QLatin1String("sidebarFooter")) w->setStyleSheet(sidebarFooterCss(t));
            else if (role == QLatin1String("chatAvatar"))    w->setStyleSheet(chatAvatarCss(t));
            else if (role == QLatin1String("toolIconBtn"))   w->setStyleSheet(toolIconBtnCss(t));
            else if (role == QLatin1String("accentRoundBtn")) w->setStyleSheet(accentRoundBtnCss(t));
            else if (role == QLatin1String("thinScrollBar")) w->setStyleSheet(thinScrollBarCss(t));
            else if (role == QLatin1String("segmentBtn"))    w->setStyleSheet(segmentButtonCss(t));
            else if (role == QLatin1String("onlineStatus"))  w->setStyleSheet(onlineStatusCss(t));
            else if (role == QLatin1String("offlineStatus")) w->setStyleSheet(offlineStatusCss(t));
            else if (role == QLatin1String("backBtn"))       w->setStyleSheet(backBtnCss(t));
            else if (role == QLatin1String("headerTitle"))   w->setStyleSheet(headerTitleCss(t));
            else if (role == QLatin1String("dialogNeutralBtn")) w->setStyleSheet(dialogNeutralBtnCss(t));
            else if (role == QLatin1String("dialogAccentBtn"))  w->setStyleSheet(dialogAccentBtnCss(t));
            else if (role == QLatin1String("keyDisplay"))    w->setStyleSheet(keyDisplayCss(t));
            else if (role == QLatin1String("statusVerified"))   w->setStyleSheet(statusVerifiedCss(t));
            else if (role == QLatin1String("statusWarning"))    w->setStyleSheet(statusWarningCss(t));
            else if (role == QLatin1String("statusUnverified")) w->setStyleSheet(statusUnverifiedCss(t));
            else if (role == QLatin1String("safetyNumber"))  w->setStyleSheet(safetyNumberCss(t));
            else if (role == QLatin1String("themedCombo"))   w->setStyleSheet(comboCss(t, 12));
            else if (role == QLatin1String("themedSpin"))    w->setStyleSheet(spinBoxCss(t, 13));
            else if (role == QLatin1String("themedLineEdit")) w->setStyleSheet(lineEditCss(t, 13));
            else if (role == QLatin1String("applyBtn"))      w->setStyleSheet(applyBtnCss(t));
            else if (role == QLatin1String("destructiveBtn")) w->setStyleSheet(destructiveBtnCss(t));
            (void)lbl;
            continue;
        }

        const QString css = w->styleSheet();
        if (css.isEmpty()) continue;

        // First pass — pattern-match the original dark stylesheet the
        // section makers emit, apply the theme-aware version, and
        // stamp `p2pRole` so subsequent passes take the fast path above.

        // Card surface — bg #111 + 10px radius.
        if (css.contains(QLatin1String("border-radius: 10px"))
            && css.contains(QLatin1String("background-color: #111111"))) {
            applyRole(w, "card", cardCss(t));
            continue;
        }

        if (auto* lbl = qobject_cast<QLabel*>(w)) {
            // Section heading — green text + bold + 11px.
            if (css.contains(QLatin1String("color: #4caf50"))
                && css.contains(QLatin1String("font-size: 11px"))
                && css.contains(QLatin1String("font-weight: bold"))) {
                applyRole(lbl, "heading", headingCss(t));
                continue;
            }
            // Key label — primary text + 13px on transparent bg.
            if (css.contains(QLatin1String("color: #cccccc; font-size: 13px"))
                && css.contains(QLatin1String("background: transparent"))) {
                applyRole(lbl, "key13", keyCss(t));
                continue;
            }
            // Value label — muted text at 13px or 12px (some are mono).
            if (css.contains(QLatin1String("color: #555555; font-size: 13px"))
                && css.contains(QLatin1String("background: transparent"))) {
                const bool mono = css.contains(QLatin1String("font-family: monospace"));
                applyRole(lbl, "value13", valueCss(t, 13, mono));
                continue;
            }
            if (css.contains(QLatin1String("color: #555555; font-size: 12px"))
                && css.contains(QLatin1String("background: transparent"))) {
                const bool mono = css.contains(QLatin1String("font-family: monospace"));
                applyRole(lbl, "value12", valueCss(t, 12, mono));
                continue;
            }
            // Group sender-name label — accent green at 11px.
            if (css.contains(QLatin1String("color: #5dd868"))
                && css.contains(QLatin1String("font-size: 11px"))
                && css.contains(QLatin1String("padding-left: 4px"))) {
                applyRole(lbl, "senderName", senderNameCss(t));
                continue;
            }
            // Own message bubble — green bg + white text + 14px radius.
            if (css.contains(QLatin1String("background-color:#2e8b3a"))
                && css.contains(QLatin1String("border-radius:14px"))) {
                applyRole(lbl, "bubbleSelf", bubbleSelfCss(t));
                continue;
            }
            // Other-party bubble — dark gray bg + light text + 14px radius.
            if (css.contains(QLatin1String("background-color:#222222"))
                && css.contains(QLatin1String("border-radius:14px"))) {
                applyRole(lbl, "bubbleOther", bubbleOtherCss(t));
                continue;
            }
            // Sidebar chat-name label (#d0d0d0, 13/14px, transparent).
            if (css.contains(QLatin1String("color:#d0d0d0; font-size:13px"))
                || css.contains(QLatin1String("color:#d0d0d0;font-size:13px"))) {
                applyRole(lbl, "chatName13", chatNameCss(t, 13));
                continue;
            }
            if (css.contains(QLatin1String("color:#d0d0d0; font-size:14px"))
                || css.contains(QLatin1String("color:#d0d0d0;font-size:14px"))) {
                applyRole(lbl, "chatName14", chatNameCss(t, 14));
                continue;
            }
            // Bright-text label (#eeeeee on transparent).
            if (css.contains(QLatin1String("color:#eeeeee"))
                && css.contains(QLatin1String("background:transparent"))) {
                applyRole(lbl, "chatName13", chatNameCss(t, 13));
                continue;
            }
            // Caption labels at 11px — varied shades.
            if ((css.contains(QLatin1String("color:#888888"))
                 || css.contains(QLatin1String("color:#666666"))
                 || css.contains(QLatin1String("color:#555;")))
                && css.contains(QLatin1String("font-size:11px"))) {
                applyRole(lbl, "caption11", captionCss(t, 11));
                continue;
            }
            if (css.contains(QLatin1String("color:#888888"))
                && css.contains(QLatin1String("font-size:12px"))) {
                applyRole(lbl, "caption12", captionCss(t, 12));
                continue;
            }
        }

        // Unread / accent dot — distinct rounded green pill on a label.
        if (qobject_cast<QLabel*>(w)
            && css.contains(QLatin1String("background-color:#5dd868"))
            && css.contains(QLatin1String("border-radius:4px"))) {
            applyRole(w, "unreadDot", unreadDotCss(t));
            continue;
        }

        // File-thumbnail frame — gray bg, top corners rounded.
        if (css.contains(QLatin1String("background-color:#242424"))
            && css.contains(QLatin1String("border-radius:10px 10px 0 0"))) {
            applyRole(w, "fileThumb", fileThumbCss(t));
            continue;
        }

        // File-card shell — matches on the object-name selector the
        // card maker emits; the 12px radius distinguishes it from
        // Settings cards (10px) that use a plain selector.
        if (qobject_cast<QFrame*>(w)
            && w->objectName() == QLatin1String("fileCard")
            && css.contains(QLatin1String("QFrame#fileCard"))) {
            applyRole(w, "fileCard", fileCardCss(t));
            continue;
        }

        // Dialog vertical/horizontal separator — QFrame with a
        // `color: #2a2a2a` rule (whitespace varies between call sites).
        // Match on either spacing so all dialog separators get themed.
        if (qobject_cast<QFrame*>(w)
            && (css.startsWith(QLatin1String("color:#2a2a2a"))
                || css.startsWith(QLatin1String("color: #2a2a2a")))) {
            applyRole(w, "separator", separatorLineCss(t));
            continue;
        }

        // Horizontal-rule frame — 1px height marker.
        if (qobject_cast<QFrame*>(w)
            && css.contains(QLatin1String("max-height: 1px"))) {
            applyRole(w, "divider", dividerCss(t));
            continue;
        }
    }
}

}  // namespace themeStyles
