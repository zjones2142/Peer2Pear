#include "lockoverlay.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

LockOverlay::LockOverlay(QWidget *parent)
    : QWidget(parent)
{
    // Capture every input so a click / keystroke that lands on
    // the overlay doesn't bleed through to the chat area
    // underneath.  Without WA_NoMousePropagation a click inside
    // the overlay's empty regions still selects items in the
    // ChatList sitting behind it.
    setAttribute(Qt::WA_NoMousePropagation, true);
    setFocusPolicy(Qt::StrongFocus);

    buildUi();
}

void LockOverlay::buildUi()
{
    // Opaque dark fill so the locked chat list / message area
    // underneath isn't visible.  Same colour as the rest of the
    // dark theme; LockOverlay always renders in the same palette
    // regardless of the user's theme preference, since the
    // alternative (theme-aware) is more code for a screen that
    // displays for seconds at most.
    setStyleSheet(
        "LockOverlay { background-color: #0a0a0a; }"
        "QLabel#brand { color: #ffffff; font-size: 26px; "
        "  font-weight: bold; }"
        "QLabel#tag { color: #888888; font-size: 13px; }"
        "QLabel#error { color: #d05050; font-size: 12px; }"
        "QLineEdit { background-color: #1a1a1a; color: #f0f0f0; "
        "  border: 1px solid #2a2a2a; border-radius: 8px; "
        "  padding: 8px 12px; font-size: 14px; }"
        "QLineEdit:focus { border-color: #3a9e48; }"
        "QPushButton { background-color: #2e8b3a; color: #ffffff; "
        "  border: none; border-radius: 8px; padding: 10px 16px; "
        "  font-size: 14px; font-weight: bold; }"
        "QPushButton:hover:enabled { background-color: #38a844; }"
        "QPushButton:disabled { background-color: #1a3a1f; "
        "  color: #666666; }");

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addStretch(1);

    auto *card = new QWidget(this);
    card->setFixedWidth(380);
    auto *cardLayout = new QVBoxLayout(card);
    cardLayout->setSpacing(14);

    // Brand mark — bubble emoji is a deliberately neutral
    // placeholder until we ship a real lock-screen icon asset.
    auto *brandIcon = new QLabel(QStringLiteral("\xF0\x9F\x94\x92"), card);  // 🔒
    brandIcon->setAlignment(Qt::AlignCenter);
    brandIcon->setStyleSheet("font-size: 56px;");
    cardLayout->addWidget(brandIcon);

    auto *brand = new QLabel("Peer2Pear is locked", card);
    brand->setObjectName("brand");
    brand->setAlignment(Qt::AlignCenter);
    cardLayout->addWidget(brand);

    auto *tag = new QLabel("Enter your passphrase to unlock.", card);
    tag->setObjectName("tag");
    tag->setAlignment(Qt::AlignCenter);
    cardLayout->addWidget(tag);

    cardLayout->addSpacing(8);

    m_passField = new QLineEdit(card);
    m_passField->setEchoMode(QLineEdit::Password);
    m_passField->setPlaceholderText("Passphrase");
    connect(m_passField, &QLineEdit::textEdited,
            this, &LockOverlay::onTextEdited);
    connect(m_passField, &QLineEdit::returnPressed,
            this, &LockOverlay::onSubmit);
    cardLayout->addWidget(m_passField);

    m_errorLabel = new QLabel(QString(), card);
    m_errorLabel->setObjectName("error");
    m_errorLabel->setAlignment(Qt::AlignCenter);
    m_errorLabel->setVisible(false);
    cardLayout->addWidget(m_errorLabel);

    m_submitButton = new QPushButton("Unlock", card);
    m_submitButton->setMinimumHeight(40);
    m_submitButton->setDefault(true);
    m_submitButton->setEnabled(false);
    connect(m_submitButton, &QPushButton::clicked,
            this, &LockOverlay::onSubmit);
    cardLayout->addWidget(m_submitButton);

    auto *centerRow = new QHBoxLayout();
    centerRow->addStretch(1);
    centerRow->addWidget(card);
    centerRow->addStretch(1);
    outer->addLayout(centerRow);
    outer->addStretch(1);
}

void LockOverlay::prepareForShow()
{
    if (m_passField)  m_passField->clear();
    if (m_errorLabel) {
        m_errorLabel->clear();
        m_errorLabel->setVisible(false);
    }
    if (m_submitButton) m_submitButton->setEnabled(false);
    if (m_passField)  m_passField->setFocus();
}

void LockOverlay::showWrongPassphrase()
{
    if (m_errorLabel) {
        m_errorLabel->setText("Wrong passphrase.");
        m_errorLabel->setVisible(true);
    }
    if (m_passField) {
        m_passField->clear();
        m_passField->setFocus();
    }
    if (m_submitButton) m_submitButton->setEnabled(false);
}

void LockOverlay::onTextEdited()
{
    const bool hasInput = !m_passField->text().isEmpty();
    m_submitButton->setEnabled(hasInput);
    // Clear the wrong-passphrase error as soon as the user starts
    // re-typing so the prompt feels responsive.
    if (hasInput && m_errorLabel && m_errorLabel->isVisible()) {
        m_errorLabel->clear();
        m_errorLabel->setVisible(false);
    }
}

void LockOverlay::onSubmit()
{
    const QString pass = m_passField->text();
    if (pass.isEmpty()) return;
    emit unlockRequested(pass);
    // Don't clear here — MainWindow drives the next state via
    // either showWrongPassphrase() (clears + re-focuses) or by
    // hiding the overlay outright (next prepareForShow clears).
}
