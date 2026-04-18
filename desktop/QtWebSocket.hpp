#pragma once

#include "IWebSocket.hpp"
#include <QWebSocket>
#include <QUrl>
#include <QString>

/*
 * QtWebSocket — IWebSocket implementation using Qt WebSockets.
 *
 * Thin wrapper that forwards QWebSocket signals to the std-typed
 * IWebSocket callback interface. Converts Qt ↔ std at the adapter
 * boundary.
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
        m_ws.open(QUrl(QString::fromStdString(url)));
    }
    void close() override { m_ws.close(); }

    bool isConnected() const override {
        return m_ws.state() == QAbstractSocket::ConnectedState;
    }

    bool isIdle() const override {
        return m_ws.state() == QAbstractSocket::UnconnectedState;
    }

    void sendTextMessage(const std::string& message) override {
        m_ws.sendTextMessage(QString::fromStdString(message));
    }

private:
    QWebSocket m_ws;
};
