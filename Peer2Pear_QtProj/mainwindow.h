#pragma once

#include <QMainWindow>
#include <QLabel>
#include <QWidget>
#include <QVector>
#include <QPair>
#include <QString>
#include <QStringList>

#include <QResizeEvent>
#include <QStackedWidget>

class QListWidgetItem;
class QStackedWidget;

#include "ChatController.hpp"
#include "settingspanel.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

struct ChatData {
    QString name;
    QString subtitle;
    QString peerIdB64u;                 // NEW: peer identity key (base64url)
    QStringList keys;                   // public keys for this contact
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

    void onEditProfile();
    void onEditContact(int index);
    void onAddContact();

    //void onOpenSettings();//delete function later ? Unused currently
    void onSettingsClicked();//slot for settings button click
    void onSettingsBackClicked();//slot for settings back button click

    void onIncomingMessage(const QString& fromPeerIdB64u, const QString& text); // NEW
    void onStatus(const QString& s);

private:
    void initChats();
    void rebuildChatList();
    void loadChat(int index);

    void clearMessages();
    void addMessageBubble(const QString &text, bool sent);

private:
    Ui::MainWindow *ui;

    ChatController m_controller;

    QVector<ChatData> m_chats;
    int m_currentChat = -1;

    QStackedWidget *m_mainStack = nullptr;
    SettingsPanel  *m_settingsPanel = nullptr;
};
