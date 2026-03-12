#pragma once
#include "ChatController.hpp"
#include <QMainWindow>

#include <QResizeEvent>
#include <QStackedWidget>

class QListWidgetItem;
class QStackedWidget;

#include "settingspanel.h"
#include "chatview.h"
#include "ChatNotifier.h"
#include "databasemanager.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onSettingsClicked();//slot for settings button click
    void onSettingsBackClicked();//slot for settings back button click

private:
    Ui::MainWindow *ui;

    DatabaseManager m_db;

    ChatController m_controller;

    ChatView *m_chatView = nullptr;
    ChatNotifier   *m_notifier    = nullptr;

    QStackedWidget *m_mainStack = nullptr;
    SettingsPanel  *m_settingsPanel = nullptr;
};
