#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QWidget>
#include <QVector>
#include <QResizeEvent>
#include "ChatController.hpp"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

struct ChatData {
    QString name;
    QString subtitle;
    QString peerIdB64u;                 // NEW: peer identity key (base64url)
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

    void onIncomingMessage(const QString& fromPeerIdB64u, const QString& text); // NEW
    void onStatus(const QString& s);

private:
    Ui::MainWindow *ui;

    QVector<ChatData> m_chats;
    int m_currentChat = -1;

    void initChats();
    void loadChat(int index);
    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);

    ChatController m_controller; // NEW
};

#endif // MAINWINDOW_H


