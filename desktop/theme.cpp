#include "theme.h"

#include <QApplication>
#include <QPalette>
#include <QStyleHints>

ThemeManager& ThemeManager::instance() {
    static ThemeManager s;
    return s;
}

ThemeManager::ThemeManager(QObject* parent) : QObject(parent) {
    // Constructor leaves the default dark palette active — MainWindow
    // calls setPreference() at startup with whatever's in the DB, which
    // triggers a reapply() and emits themeChanged for subscribers.
}

void ThemeManager::setPreference(Preference pref) {
    if (pref == m_pref && m_applied) return;
    m_pref = pref;
    m_applied = true;
    reapply();
}

void ThemeManager::reapply() {
    m_current = resolve();

    // Apply the palette via Fusion style so subordinate widgets that
    // don't set their own stylesheet pick it up.  Fusion obeys QPalette
    // across platforms; the native macOS style largely ignores palette.
    qApp->setStyle("Fusion");

    QPalette pal;
    pal.setColor(QPalette::Window,          m_current.bg);
    pal.setColor(QPalette::WindowText,      m_current.textPrimary);
    pal.setColor(QPalette::Base,            m_current.card);
    pal.setColor(QPalette::AlternateBase,   m_current.bgAlt);
    pal.setColor(QPalette::ToolTipBase,     m_current.card);
    pal.setColor(QPalette::ToolTipText,     m_current.textPrimary);
    pal.setColor(QPalette::Text,            m_current.textPrimary);
    pal.setColor(QPalette::PlaceholderText, m_current.textMuted);
    pal.setColor(QPalette::Button,          m_current.card);
    pal.setColor(QPalette::ButtonText,      m_current.textPrimary);
    pal.setColor(QPalette::Link,            m_current.accent);
    pal.setColor(QPalette::Highlight,       m_current.accent);
    pal.setColor(QPalette::HighlightedText, Qt::white);
    qApp->setPalette(pal);

    // Install an app-wide stylesheet covering the common widget types.
    // Widgets that set their own stylesheet still win for THAT widget,
    // but their CHILDREN without explicit sheets fall through to this
    // global.  Over time we migrate more widgets off per-widget
    // stylesheets so the global takes over more surface area.
    qApp->setStyleSheet(buildGlobalStyleSheet(m_current));

    emit themeChanged(m_current);
}

Theme ThemeManager::resolve() const {
    if (m_pref == Preference::Dark)  return Themes::dark();
    if (m_pref == Preference::Light) return Themes::light();

    // System — follow the OS appearance at resolve time.  If the user
    // flips the OS dark/light mode while the app is running, this
    // doesn't live-update (no hook wired up); they'd need to toggle
    // the preference off+on.  Acceptable for a "System" preset that
    // most users set once and forget.
    const auto scheme = qApp->styleHints()->colorScheme();
    return (scheme == Qt::ColorScheme::Light) ? Themes::light()
                                               : Themes::dark();
}

QString ThemeManager::buildGlobalStyleSheet(const Theme& t) const {

    // Selectors target widget types, not object names — the idea is
    // to establish a sensible default for any unstyled widget in the
    // app.  Per-widget stylesheets still override these where they
    // exist (e.g., ChatView bubbles, which remain dark for now).
    return QString(
        "QWidget { background-color: %1; color: %2; }"
        "QMainWindow { background-color: %1; }"
        "QScrollArea { background-color: %1; border: none; }"
        "QLabel { background: transparent; color: %2; }"
        "QLineEdit {"
        "  background-color: %3;"
        "  color: %2;"
        "  border: 1px solid %4;"
        "  border-radius: 6px;"
        "  padding: 6px 8px;"
        "}"
        "QLineEdit:focus { border-color: %5; }"
        "QComboBox {"
        "  background-color: %3;"
        "  color: %2;"
        "  border: 1px solid %4;"
        "  border-radius: 6px;"
        "  padding: 4px 8px;"
        "}"
        "QSpinBox {"
        "  background-color: %3;"
        "  color: %2;"
        "  border: 1px solid %4;"
        "  border-radius: 6px;"
        "  padding: 4px 8px;"
        "}"
        "QPushButton {"
        "  background-color: %3;"
        "  color: %2;"
        "  border: 1px solid %4;"
        "  border-radius: 6px;"
        "  padding: 6px 12px;"
        "}"
        "QPushButton:hover { border-color: %5; }"
        "QToolTip {"
        "  background-color: %3;"
        "  color: %2;"
        "  border: 1px solid %4;"
        "}"
    )
    .arg(t.bg.name())          // %1
    .arg(t.textPrimary.name()) // %2
    .arg(t.card.name())        // %3
    .arg(t.border.name())      // %4
    .arg(t.accent.name());     // %5
}
