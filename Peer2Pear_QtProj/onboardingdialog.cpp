#include "onboardingdialog.h"

#include <utility>
#include <QStackedWidget>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QColorDialog>
#include <QFileDialog>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QBuffer>
#include <QByteArray>

// ── Helpers ───────────────────────────────────────────────────────────────────

QPixmap OnboardingDialog::renderInitialsAvatar(const QString &initial, const QColor &bg, int size)
{
    QPixmap pm(size, size);
    pm.setDevicePixelRatio(1.0);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);

    // Filled circle
    p.setBrush(bg);
    p.setPen(Qt::NoPen);
    p.drawEllipse(0, 0, size, size);

    // Initial letter
    QFont font = p.font();
    font.setBold(true);
    font.setPixelSize(size / 2);
    p.setFont(font);
    p.setPen(Qt::white);
    p.drawText(QRect(0, 0, size, size), Qt::AlignCenter, initial.toUpper());

    p.end();
    return pm;
}

QPixmap OnboardingDialog::makeCircularPixmap(const QPixmap &src, int size)
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

// ── Constructor ───────────────────────────────────────────────────────────────

OnboardingDialog::OnboardingDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Welcome to Peer2Pear");
    setModal(true);
    setFixedWidth(400);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);

    setStyleSheet("QDialog { background: #0d0d0d; }");

    m_stack = new QStackedWidget(this);

    QVBoxLayout *rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->addWidget(m_stack);

    buildStep1();

    // Step 2 page is a placeholder widget until onNextClicked populates it
    m_stack->addWidget(new QWidget(this)); // index 1 placeholder
}

// ── Step 1 ────────────────────────────────────────────────────────────────────

void OnboardingDialog::buildStep1()
{
    QWidget *page = new QWidget(this);
    page->setStyleSheet("background: #0d0d0d;");

    QVBoxLayout *lay = new QVBoxLayout(page);
    lay->setContentsMargins(40, 48, 40, 48);
    lay->setSpacing(0);

    // App name heading
    QLabel *heading = new QLabel("Peer2Pear", page);
    heading->setAlignment(Qt::AlignCenter);
    heading->setStyleSheet("color: #4caf50; font-size: 28px; font-weight: bold; background: transparent;");
    lay->addWidget(heading);

    lay->addSpacing(12);

    // Subtitle
    QLabel *subtitle = new QLabel("Choose a display name to get started", page);
    subtitle->setAlignment(Qt::AlignCenter);
    subtitle->setWordWrap(true);
    subtitle->setStyleSheet("color: #555555; font-size: 13px; background: transparent;");
    lay->addWidget(subtitle);

    lay->addSpacing(32);

    // Name input
    m_nameEdit = new QLineEdit(page);
    m_nameEdit->setPlaceholderText("Display name");
    m_nameEdit->setStyleSheet(
        "QLineEdit {"
        "  background: #1a1a1a;"
        "  border: 1px solid #333;"
        "  color: #f0f0f0;"
        "  padding: 10px;"
        "  border-radius: 8px;"
        "  font-size: 13px;"
        "}"
        "QLineEdit:focus {"
        "  border: 1px solid #4caf50;"
        "}"
    );
    lay->addWidget(m_nameEdit);

    lay->addSpacing(20);

    // Next button
    m_nextBtn = new QPushButton("Next", page);
    m_nextBtn->setEnabled(false);
    m_nextBtn->setStyleSheet(
        "QPushButton {"
        "  background: #4caf50;"
        "  color: #f0f0f0;"
        "  border: none;"
        "  border-radius: 8px;"
        "  padding: 10px;"
        "  font-size: 13px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:disabled {"
        "  background: #2a3a2a;"
        "  color: #555555;"
        "}"
        "QPushButton:hover:!disabled {"
        "  background: #43a047;"
        "}"
    );
    lay->addWidget(m_nextBtn);

    lay->addStretch();

    m_stack->addWidget(page); // index 0

    // Wire signals
    connect(m_nameEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_nextBtn->setEnabled(!text.trimmed().isEmpty());
    });
    connect(m_nextBtn, &QPushButton::clicked, this, &OnboardingDialog::onNextClicked);
}

// ── Step 2 ────────────────────────────────────────────────────────────────────

void OnboardingDialog::buildStep2()
{
    // Remove old placeholder at index 1
    QWidget *old = m_stack->widget(1);
    m_stack->removeWidget(old);
    delete old;

    QWidget *page = new QWidget(this);
    page->setStyleSheet("background: #0d0d0d;");

    QVBoxLayout *lay = new QVBoxLayout(page);
    lay->setContentsMargins(40, 40, 40, 40);
    lay->setSpacing(0);

    // Heading
    QLabel *heading = new QLabel("Set your profile picture", page);
    heading->setAlignment(Qt::AlignCenter);
    heading->setStyleSheet("color: #f0f0f0; font-size: 16px; font-weight: bold; background: transparent;");
    lay->addWidget(heading);

    lay->addSpacing(8);

    // Subtitle
    QLabel *subtitle = new QLabel("This is how others will see you", page);
    subtitle->setAlignment(Qt::AlignCenter);
    subtitle->setStyleSheet("color: #555555; font-size: 13px; background: transparent;");
    lay->addWidget(subtitle);

    lay->addSpacing(28);

    // Avatar preview (100x100 circle)
    m_avatarPreview = new QLabel(page);
    m_avatarPreview->setFixedSize(100, 100);
    m_avatarPreview->setAlignment(Qt::AlignCenter);
    m_avatarPreview->setStyleSheet(
        "QLabel {"
        "  border-radius: 50px;"
        "  background: transparent;"
        "}"
    );

    QHBoxLayout *previewRow = new QHBoxLayout();
    previewRow->addStretch();
    previewRow->addWidget(m_avatarPreview);
    previewRow->addStretch();
    lay->addLayout(previewRow);

    lay->addSpacing(24);

    // "Background color" label
    QLabel *colorLabel = new QLabel("Background color", page);
    colorLabel->setAlignment(Qt::AlignCenter);
    colorLabel->setStyleSheet("color: #f0f0f0; font-size: 11px; background: transparent;");
    lay->addWidget(colorLabel);

    lay->addSpacing(10);

    // Swatch row
    QHBoxLayout *swatchRow = new QHBoxLayout();
    swatchRow->setSpacing(8);
    swatchRow->addStretch();

    const QList<QColor> presets = {
        QColor(0x2e, 0x8b, 0x3a),
        QColor(0x3a, 0x6b, 0xbf),
        QColor(0x7b, 0x3a, 0xbf),
        QColor(0xbf, 0x7b, 0x3a),
        QColor(0xbf, 0x3a, 0x3a),
    };

    m_swatchBtns.clear();

    auto makeSwatchStyle = [](const QColor &col, bool selected) -> QString {
        QString hex = col.name();
        if (selected) {
            return QString(
                "QPushButton {"
                "  background: %1;"
                "  border: 2px solid white;"
                "  border-radius: 14px;"
                "}"
            ).arg(hex);
        } else {
            return QString(
                "QPushButton {"
                "  background: %1;"
                "  border: none;"
                "  border-radius: 14px;"
                "}"
                "QPushButton:hover {"
                "  border: 2px solid #888;"
                "  border-radius: 14px;"
                "}"
            ).arg(hex);
        }
    };

    for (const QColor &col : presets) {
        QPushButton *btn = new QPushButton(page);
        btn->setFixedSize(28, 28);
        btn->setStyleSheet(makeSwatchStyle(col, col == m_avatarColor));
        if (col == m_avatarColor) {
            m_selectedSwatch = btn;
        }
        m_swatchBtns.append(btn);

        connect(btn, &QPushButton::clicked, this, [this, btn, col, makeSwatchStyle]() {
            // Deselect previous
            if (m_selectedSwatch && m_selectedSwatch != btn) {
                // find its color
                for (int i = 0; i < m_swatchBtns.size(); ++i) {
                    if (m_swatchBtns[i] == m_selectedSwatch) {
                        // we need the color — stored in closure capture below
                        break;
                    }
                }
            }
            // Update all swatch styles
            for (int i = 0; i < m_swatchBtns.size(); ++i) {
                // re-derive color from stylesheet is not clean; use stored list
            }
            m_selectedSwatch = btn;
            onPickColor(col);
        });

        swatchRow->addWidget(btn);
    }

    // Custom color "+" button
    QPushButton *customBtn = new QPushButton("+", page);
    customBtn->setFixedSize(28, 28);
    customBtn->setStyleSheet(
        "QPushButton {"
        "  background: #1e1e1e;"
        "  border: 1px solid #555;"
        "  border-radius: 14px;"
        "  color: #f0f0f0;"
        "  font-size: 16px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background: #2a2a2a;"
        "}"
    );
    connect(customBtn, &QPushButton::clicked, this, &OnboardingDialog::onPickCustomColor);
    swatchRow->addWidget(customBtn);

    swatchRow->addStretch();
    lay->addLayout(swatchRow);

    lay->addSpacing(20);

    // Upload photo button
    QPushButton *uploadBtn = new QPushButton("Upload Photo", page);
    uploadBtn->setStyleSheet(
        "QPushButton {"
        "  background: #111111;"
        "  border: 1px solid #1e1e1e;"
        "  color: #f0f0f0;"
        "  border-radius: 8px;"
        "  padding: 10px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background: #1a1a1a;"
        "  border: 1px solid #333;"
        "}"
    );
    connect(uploadBtn, &QPushButton::clicked, this, &OnboardingDialog::onUploadPhoto);
    lay->addWidget(uploadBtn);

    lay->addSpacing(24);

    // Bottom row: Back + Get Started
    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->setSpacing(12);

    QPushButton *backBtn = new QPushButton("Back", page);
    backBtn->setStyleSheet(
        "QPushButton {"
        "  background: transparent;"
        "  border: 1px solid #333;"
        "  color: #f0f0f0;"
        "  border-radius: 8px;"
        "  padding: 10px 20px;"
        "  font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "  background: #1a1a1a;"
        "}"
    );
    connect(backBtn, &QPushButton::clicked, this, &OnboardingDialog::onBackClicked);

    m_getStartedBtn = new QPushButton("Get Started", page);
    m_getStartedBtn->setStyleSheet(
        "QPushButton {"
        "  background: #4caf50;"
        "  color: #f0f0f0;"
        "  border: none;"
        "  border-radius: 8px;"
        "  padding: 10px 20px;"
        "  font-size: 13px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background: #43a047;"
        "}"
    );
    connect(m_getStartedBtn, &QPushButton::clicked, this, [this]() {
        // Render final avatar at 200x200
        QPixmap finalPx;
        if (m_usingPhoto) {
            finalPx = makeCircularPixmap(m_uploadedPhoto, 200);
        } else {
            QString initial = m_displayName.isEmpty() ? "?" : QString(m_displayName[0]).toUpper();
            finalPx = renderInitialsAvatar(initial, m_avatarColor, 200);
        }

        // Convert to base64 PNG
        QByteArray bytes;
        QBuffer buf(&bytes);
        buf.open(QIODevice::WriteOnly);
        finalPx.save(&buf, "PNG");
        m_avatarData = QString::fromLatin1(bytes.toBase64());

        accept();
    });

    bottomRow->addWidget(backBtn);
    bottomRow->addWidget(m_getStartedBtn, 1);
    lay->addLayout(bottomRow);

    m_stack->insertWidget(1, page);

    // Now fix swatch styles — rebuild with proper color tracking
    // The lambda above has a deficiency; patch it now with correct approach
    // by reconnecting with full preset list reference.
    // We'll use a dedicated refresh lambda.
    auto refreshSwatches = [this, makeSwatchStyle, presets]() {
        for (int i = 0; i < m_swatchBtns.size() && i < presets.size(); ++i) {
            m_swatchBtns[i]->setStyleSheet(makeSwatchStyle(presets[i], m_swatchBtns[i] == m_selectedSwatch));
        }
    };

    // Reconnect swatch buttons with full context
    for (int i = 0; i < m_swatchBtns.size(); ++i) {
        QPushButton *btn = m_swatchBtns[i];
        QColor col = presets[i];
        // Disconnect previous connection (lambda connected above)
        btn->disconnect(SIGNAL(clicked()));
        connect(btn, &QPushButton::clicked, this, [this, btn, col, refreshSwatches]() {
            m_selectedSwatch = btn;
            onPickColor(col);
            refreshSwatches();
        });
    }

    // Initial preview
    updateAvatarPreview();
}

// ── Slots ─────────────────────────────────────────────────────────────────────

void OnboardingDialog::onNextClicked()
{
    m_displayName = m_nameEdit->text().trimmed();
    buildStep2();
    m_stack->setCurrentIndex(1);
}

void OnboardingDialog::onBackClicked()
{
    m_stack->setCurrentIndex(0);
}

void OnboardingDialog::onPickColor(const QColor &color)
{
    m_avatarColor = color;
    m_usingPhoto  = false;
    updateAvatarPreview();
}

void OnboardingDialog::onPickCustomColor()
{
    QColor col = QColorDialog::getColor(m_avatarColor, this, "Choose a color");
    if (col.isValid()) {
        m_selectedSwatch = nullptr; // no swatch selected for custom
        // Deselect all swatches visually
        for (QPushButton *btn : std::as_const(m_swatchBtns)) {
            // Extract background color from existing style and rebuild without selection
            // Simpler: just remove white border
            QString s = btn->styleSheet();
            s.replace("border: 2px solid white;", "border: none;");
            btn->setStyleSheet(s);
        }
        onPickColor(col);
    }
}

void OnboardingDialog::onUploadPhoto()
{
    const QString path = QFileDialog::getOpenFileName(
        this,
        "Choose a photo",
        QString(),
        "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
    );
    if (path.isEmpty()) return;

    QPixmap px(path);
    if (px.isNull()) return;

    m_uploadedPhoto = px;
    m_usingPhoto    = true;
    updateAvatarPreview();
}

void OnboardingDialog::updateAvatarPreview()
{
    if (!m_avatarPreview) return;

    QPixmap pm;
    if (m_usingPhoto) {
        pm = makeCircularPixmap(m_uploadedPhoto, 100);
    } else {
        QString initial = m_displayName.isEmpty() ? "?" : QString(m_displayName[0]).toUpper();
        pm = renderInitialsAvatar(initial, m_avatarColor, 100);
    }
    m_avatarPreview->setPixmap(pm);
    m_avatarPreview->setText("");
}

// ── Accessors ─────────────────────────────────────────────────────────────────

QString OnboardingDialog::displayName()  const { return m_displayName; }
QString OnboardingDialog::avatarData()   const { return m_avatarData;  }
bool    OnboardingDialog::isPhotoAvatar() const { return m_usingPhoto;  }
