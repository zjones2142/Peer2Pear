#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QWidget>
#include <QVector>
#include <QResizeEvent>
#include <QStackedWidget>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

struct ChatData {
    QString name;
    QString subtitle;
    QVector<QPair<bool, QString>> messages;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onChatSelected(int index);
    void onSendMessage();
    void onSearchChanged(const QString &text);
    void onSettingsClicked();//slot for settings button click
    void onSettingsBackClicked();//slot for settings back button click

private:
    Ui::MainWindow *ui;

    QVector<ChatData> m_chats;
    int m_currentChat = -1;

    void initChats();
    void loadChat(int index);
    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);
    void buildSettingsPanel();//builds settings panel and assigns it to m_settingsPanel

    QStackedWidget *m_mainStack   = nullptr;
    QWidget        *m_settingsPanel = nullptr;
};

#endif // MAINWINDOW_H
