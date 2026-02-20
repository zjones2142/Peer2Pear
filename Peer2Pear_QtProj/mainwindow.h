#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QWidget>
#include <QVector>

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

private slots:
    void onChatSelected(int index);
    void onSendMessage();
    void onSearchChanged(const QString &text);

private:
    Ui::MainWindow *ui;

    QVector<ChatData> m_chats;
    int m_currentChat = -1;

    void initChats();
    void loadChat(int index);
    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);
};

#endif // MAINWINDOW_H
