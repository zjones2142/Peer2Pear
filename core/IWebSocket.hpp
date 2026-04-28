#pragma once

#include "types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

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
 *
 * Types: std::string for text/URLs (UTF-8), std::vector<uint8_t> for binary
 * frames.
 */
class IWebSocket {
public:

    virtual ~IWebSocket() = default;

    /// Open a WebSocket connection to the given URL.
    virtual void open(const std::string& url) = 0;

    /// Close the connection gracefully.
    virtual void close() = 0;

    /// True if the WebSocket is in the connected state.
    virtual bool isConnected() const = 0;

    /// True if the WebSocket is idle (not connected, not connecting).
    virtual bool isIdle() const = 0;

    /// Send a UTF-8 text frame (used for auth and presence JSON messages).
    virtual void sendTextMessage(const std::string& message) = 0;

    // ── Callbacks (set by RelayClient before open()) ────────────────────────

    /// Called when the WebSocket connection is established.
    std::function<void()> onConnected;

    /// Called when the WebSocket connection is closed or lost.
    std::function<void()> onDisconnected;

    /// Called for each binary frame received (sealed envelopes).
    std::function<void(const Bytes&)> onBinaryMessage;

    /// Called for each text frame received (auth response, presence updates).
    std::function<void(const std::string&)> onTextMessage;
};

/*
 * IWebSocketFactory — creates additional IWebSocket instances on demand.
 *
 * Used by RelayClient's multi-relay subscribe feature: when a recipient
 * is configured to listen on N relays simultaneously, RelayClient asks
 * the factory for N-1 additional IWebSocket instances (the "primary"
 * IWebSocket passed to the constructor counts as the first one).
 *
 * Each returned IWebSocket is owned by RelayClient via unique_ptr —
 * the factory transfers ownership.  Implementations typically wrap a
 * fresh QWebSocket / URLSessionWebSocketTask / OkHttp WebSocket each
 * call so the platform-side connection state is independent.
 *
 * Mirrors ITimerFactory — same lifetime + ownership semantics.  Tests
 * can ship a SimpleWebSocketFactory that hands back deterministic
 * mock instances; production wires through to platform networking.
 */
class IWebSocketFactory {
public:
    virtual ~IWebSocketFactory() = default;

    /// Create a fresh IWebSocket instance.  The returned object is
    /// idle (not connected) and has no callbacks wired — the caller
    /// installs onConnected / onBinaryMessage / etc. before calling
    /// open().  Returning nullptr signals that the factory cannot
    /// create more instances right now (e.g. resource cap hit);
    /// RelayClient treats that as "skip this subscribe URL."
    virtual std::unique_ptr<IWebSocket> create() = 0;
};
