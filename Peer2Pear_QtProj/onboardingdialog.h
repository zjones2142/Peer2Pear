#pragma once
#include <QDialog>
#include <QString>
#include <QColor>

class QLineEdit;
class QLabel;
class QPushButton;
class QStackedWidget;

class OnboardingDialog : public QDialog
{
    Q_OBJECT
public:
    explicit OnboardingDialog(QWidget *parent = nullptr);
    QString displayName() const;
    QString avatarData() const; // base64-encoded PNG, may be empty if using initials

private slots:
    void onNextClicked();
    void onBackClicked();
    void onPickColor(const QColor &color);
    void onPickCustomColor();
    void onUploadPhoto();

private:
    void buildStep1();
    void buildStep2();
    void updateAvatarPreview();
    QPixmap renderInitialsAvatar(const QString &initial, const QColor &bg, int size);
    QPixmap makeCircularPixmap(const QPixmap &src, int size);

    QStackedWidget *m_stack         = nullptr;
    QLineEdit      *m_nameEdit      = nullptr;
    QPushButton    *m_nextBtn       = nullptr;
    QLabel         *m_avatarPreview = nullptr;
    QPushButton    *m_getStartedBtn = nullptr;

    QString  m_displayName;
    QString  m_avatarData;   // base64 PNG — set when user uploads photo
    QColor   m_avatarColor   { "#2e8b3a" };
    bool     m_usingPhoto    = false;
    QPixmap  m_uploadedPhoto;

    // Track selected swatch button for border highlight
    QPushButton *m_selectedSwatch = nullptr;
    QList<QPushButton*> m_swatchBtns;
};
