#pragma once

#include <QColor>
#include <QObject>
#include <QString>

// Theme — single source of truth for the desktop palette.
//
// Colors are named semantically (bg, card, textPrimary, accent, ...)
// so callers say what they mean.  Two palettes are defined below: the
// original hardcoded dark and a complementary light set.  A third
// "System" mode follows the OS dark/light signal by choosing between
// the two at startup.
//
// Callers fetch the active palette via ThemeManager::instance().current().
// When the user flips the Appearance picker in SettingsPanel, ThemeManager
// emits `themeChanged` — widgets that own their own stylesheets re-apply
// them in response.  Widgets that have NO per-widget stylesheet are
// painted by the application-wide stylesheet installed on qApp, which
// is rebuilt on every theme change.
//
// Scope note: not every widget has been migrated yet.  ChatView and
// several SettingsPanel subsections still set hardcoded dark stylesheets
// on themselves; they'll stay dark in "Light" mode until those sheets
// get converted to read from the Theme struct.  The caption in
// SettingsPanel's Appearance card flags this to the user.

struct Theme {
    QColor bg;             // window / top-level background
    QColor bgAlt;          // secondary background (scroll areas, list rows)
    QColor card;           // card surface sitting on bg
    QColor border;         // thin separators / card outlines
    QColor divider;        // horizontal rules inside cards
    QColor textPrimary;    // body text, titles
    QColor textSecondary;  // de-emphasized labels, captions
    QColor textMuted;      // placeholder, disabled
    QColor accent;         // green brand accent — same in both themes
    QColor accentSoft;     // checked-state background tint for the accent
    QColor dangerText;     // warnings / destructive button text
    QColor dangerBg;       // warnings / destructive button background
};

namespace Themes {

// Hardcoded dark palette — values chosen so the dark-mode rendering
// matches what the inline stylesheets in settingspanel.cpp /
// chatview.cpp produce today.  textPrimary is #cccccc (not #ffffff)
// because that's what the row-key labels everywhere use; pure white is
// only for one-off prominent titles which keep a hardcoded sheet.
inline Theme dark() {
    Theme t;
    t.bg             = QColor("#0d0d0d");
    t.bgAlt          = QColor("#111111");
    t.card           = QColor("#111111");
    t.border         = QColor("#1e1e1e");
    t.divider        = QColor("#1e1e1e");
    t.textPrimary    = QColor("#cccccc");
    t.textSecondary  = QColor("#999999");
    t.textMuted      = QColor("#555555");
    t.accent         = QColor("#4caf50");
    t.accentSoft     = QColor("#1f2e1f");
    t.dangerText     = QColor("#cc5555");
    t.dangerBg       = QColor("#2e1a1a");
    return t;
}

// Light palette — complementary to dark.  Accent color stays green so
// brand recognition doesn't shift; everything else inverts roughly.
// textPrimary kept slightly off-black so card surfaces don't feel too
// hard against #ffffff card backgrounds.
inline Theme light() {
    Theme t;
    t.bg             = QColor("#f4f4f5");
    t.bgAlt          = QColor("#ffffff");
    t.card           = QColor("#ffffff");
    t.border         = QColor("#dcdcdc");
    t.divider        = QColor("#e5e5e5");
    t.textPrimary    = QColor("#222222");
    t.textSecondary  = QColor("#555555");
    t.textMuted      = QColor("#9a9a9a");
    t.accent         = QColor("#2e7d32");
    t.accentSoft     = QColor("#e8f5e9");
    t.dangerText     = QColor("#b00020");
    t.dangerBg       = QColor("#fde3e3");
    return t;
}

}  // namespace Themes

class ThemeManager : public QObject {
    Q_OBJECT
public:
    enum class Preference {
        Dark   = 0,
        Light  = 1,
        System = 2
    };
    Q_ENUM(Preference)

    static ThemeManager& instance();

    Preference preference() const { return m_pref; }
    const Theme& current() const { return m_current; }

    // Update preference + re-apply the app-wide stylesheet.  Emits
    // themeChanged with the resolved Theme (System collapses to dark
    // or light based on the OS appearance).
    void setPreference(Preference pref);

signals:
    void themeChanged(const Theme& theme);

private:
    explicit ThemeManager(QObject* parent = nullptr);
    void reapply();
    Theme resolve() const;
    QString buildGlobalStyleSheet(const Theme& t) const;

    Preference m_pref    = Preference::Dark;
    Theme      m_current = Themes::dark();
    bool       m_applied = false;   // false until first setPreference()
};
