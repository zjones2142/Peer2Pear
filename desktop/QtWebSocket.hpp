#pragma once

#include "IWebSocket.hpp"
#include "qt_thread_hop.hpp"
#include <QWebSocket>
#include <QUrl>
#include <QString>

#include <memory>

/*
 * QtWebSocket — IWebSocket implementation using Qt WebSockets.
 *
 * Thin wrapper that forwards QWebSocket signals to the std-typed
 * IWebSocket callback interface. Converts Qt ↔ std at the adapter
 * boundary.
 *
 * QWebSocket is owner-thread-pinned (same as QNetworkAccessManager);
 * mutating entry points hop via runOnOwnerThread before touching m_ws.
 */
class QtWebSocket : public QObject, public IWebSocket {
    Q_OBJECT
public:
    explicit QtWebSocket(QObject* parent = nullptr)
        : QObject(parent)
    {
        connect(&m_ws, &QWebSocket::connected, this, [this]() {
            if (onConnected) onConnected();
        });
        connect(&m_ws, &QWebSocket::disconnected, this, [this]() {
            if (onDisconnected) onDisconnected();
        });
        connect(&m_ws, &QWebSocket::binaryMessageReceived,
                this, [this](const QByteArray& data) {
            if (!onBinaryMessage) return;
            Bytes b(reinterpret_cast<const uint8_t*>(data.constData()),
                    reinterpret_cast<const uint8_t*>(data.constData()) + data.size());
            onBinaryMessage(b);
        });
        connect(&m_ws, &QWebSocket::textMessageReceived,
                this, [this](const QString& msg) {
            if (onTextMessage) onTextMessage(msg.toStdString());
        });
    }

    void open(const std::string& url) override {
        p2p::runOnOwnerThread(this, [this, url]() {
            m_ws.open(QUrl(QString::fromStdString(url)));
        });
    }

    void close() override {
        p2p::runOnOwnerThread(this, [this]() { m_ws.close(); });
    }

    // QWebSocket::state() is safe from any thread — atomic snapshot.
    bool isConnected() const override {
        return m_ws.state() == QAbstractSocket::ConnectedState;
    }

    bool isIdle() const override {
        return m_ws.state() == QAbstractSocket::UnconnectedState;
    }

    void sendTextMessage(const std::string& message) override {
        p2p::runOnOwnerThread(this, [this, message]() {
            m_ws.sendTextMessage(QString::fromStdString(message));
        });
    }

private:
    QWebSocket m_ws;
};

// QtWebSocketFactory — produces fresh QtWebSocket instances on demand.
//
// Each create() allocates a new QtWebSocket parented to `m_parent`
// for proper Qt object-tree ownership (parent dictates thread
// affinity + dictates teardown when the parent QObject is destroyed
// in case unique_ptr release is missed).
//
// Real multi-WS support comes for free here because each QWebSocket
// is independent at the Qt layer — pair this factory with
// RelayClient::addSubscribeRelay() and the desktop receives on every
// configured relay simultaneously.
class QtWebSocketFactory : public IWebSocketFactory {
public:
    explicit QtWebSocketFactory(QObject* parent = nullptr)
        : m_parent(parent) {}

    std::unique_ptr<IWebSocket> create() override {
        return std::make_unique<QtWebSocket>(m_parent);
    }

private:
    QObject* m_parent = nullptr;
};
