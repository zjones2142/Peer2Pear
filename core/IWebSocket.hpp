#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>
#include <functional>

/*
 * IWebSocket — platform abstraction for WebSocket transport.
 *
 * The single interface that platform code must implement:
 *   Desktop (Qt):   QtWebSocket wrapping QWebSocket
 *   iOS:            URLSessionWebSocket wrapping URLSessionWebSocketTask
 *   Android:        OkHttpWebSocket wrapping OkHttpClient.newWebSocket()
 *
 * RelayClient depends only on this interface — no QWebSocket, no platform
 * networking headers. Each platform provides ~50-80 lines of glue.
 */
class IWebSocket {
public:
    virtual ~IWebSocket() = default;

    /// Open a WebSocket connection to the given URL.
    virtual void open(const QUrl& url) = 0;

    /// Close the connection gracefully.
    virtual void close() = 0;

    /// True if the WebSocket is in the connected state.
    virtual bool isConnected() const = 0;

    /// True if the WebSocket is idle (not connected, not connecting).
    virtual bool isIdle() const = 0;

    /// Send a UTF-8 text frame (used for auth and presence JSON messages).
    virtual void sendTextMessage(const QString& message) = 0;

    // ── Callbacks (set by RelayClient before open()) ────────────────────────

    /// Called when the WebSocket connection is established.
    std::function<void()> onConnected;

    /// Called when the WebSocket connection is closed or lost.
    std::function<void()> onDisconnected;

    /// Called for each binary frame received (sealed envelopes).
    std::function<void(const QByteArray&)> onBinaryMessage;

    /// Called for each text frame received (auth response, presence updates).
    std::function<void(const QString&)> onTextMessage;
};
