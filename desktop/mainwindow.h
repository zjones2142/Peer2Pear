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
#include "qt_str_helpers.hpp"
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
    // and adds per-field XChaCha20-Poly1305.  chatview / settingspanel
    // call m_store directly with AppDataStore types; Qt↔std conversion
    // happens at render/save sites via qt_str_helpers.hpp.
    SqlCipherDb        m_db;
    AppDataStore       m_store;
    // Factory replaces the previous single QtWebSocket member: it
    // creates fresh QtWebSocket instances per RelayClient subscribe
    // (one for the primary, one per addSubscribeRelay()).  Each
    // QtWebSocket is parented to MainWindow for thread affinity.
    QtWebSocketFactory m_wsFactory;
    QtHttpClient       m_httpClient;
    QtTimerFactory     m_timerFactory;
    ChatController     m_controller;
    ChatView        *m_chatView      = nullptr;
    ChatNotifier    *m_notifier      = nullptr;
    QStackedWidget  *m_mainStack     = nullptr;
    SettingsPanel   *m_settingsPanel = nullptr;

    // Debounce: only reload bubbles after resize activity stops
    QTimer m_resizeDebounce;

    // Top-bar relay-status indicator.  Mirrors the iOS connectivity
    // popover (wifi icon → tap → card showing "Connected" / "Offline"
    // + relay URL + backup relays).  Tracks live state via the
    // RelayClient's onConnected / onDisconnected callbacks; click
    // the 📡 button to see the popover.
    bool m_relayConnected = false;
    void updateConnectivityIndicator();
    void showConnectivityPopover();
};
