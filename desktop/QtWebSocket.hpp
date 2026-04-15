#pragma once

#include "IWebSocket.hpp"
#include <QWebSocket>

/*
 * QtWebSocket — IWebSocket implementation using Qt WebSockets.
 *
 * Thin wrapper (~60 lines) that forwards QWebSocket signals to the
 * IWebSocket callback interface. This is the desktop platform adapter.
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
            if (onBinaryMessage) onBinaryMessage(data);
        });
        connect(&m_ws, &QWebSocket::textMessageReceived,
                this, [this](const QString& msg) {
            if (onTextMessage) onTextMessage(msg);
        });
    }

    void open(const QUrl& url) override { m_ws.open(url); }
    void close() override { m_ws.close(); }

    bool isConnected() const override {
        return m_ws.state() == QAbstractSocket::ConnectedState;
    }

    bool isIdle() const override {
        return m_ws.state() == QAbstractSocket::UnconnectedState;
    }

    void sendTextMessage(const QString& message) override {
        m_ws.sendTextMessage(message);
    }

private:
    QWebSocket m_ws;
};
