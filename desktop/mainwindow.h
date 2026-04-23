#pragma once
#include "ChatController.hpp"
#include "QtWebSocket.hpp"
#include "QtHttpClient.hpp"
#include "QtTimer.hpp"
#include <QMainWindow>
#include <QResizeEvent>
#include <QStackedWidget>
#include <QTimer>

#include "settingspanel.h"
#include "chatview.h"
#include "ChatNotifier.h"
#include "AppDataStoreQt.hpp"
#include "AppDataStore.hpp"
#include "SqlCipherDb.hpp"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
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
    void onSettingsClicked();
    void onSettingsBackClicked();
    void onExportContacts();
    void onImportContacts();

private:
    Ui::MainWindow  *ui;
    // App-data layer.  m_db is the raw SQLCipher handle (page-level
    // encryption); m_store is the table-level CRUD that lives on top
    // and adds per-field XChaCha20-Poly1305.  Both replace the old
    // legacy Qt facade — chatview/settingspanel hit m_store via the
    // free-function helpers in AppDataStoreQt.hpp.
    SqlCipherDb      m_db;
    AppDataStore     m_store;
    QtWebSocket      m_webSocket;
    QtHttpClient     m_httpClient;
    QtTimerFactory   m_timerFactory;
    ChatController   m_controller;
    ChatView        *m_chatView      = nullptr;
    ChatNotifier    *m_notifier      = nullptr;
    QStackedWidget  *m_mainStack     = nullptr;
    SettingsPanel   *m_settingsPanel = nullptr;

    // Debounce: only reload bubbles after resize activity stops
    QTimer m_resizeDebounce;
};
