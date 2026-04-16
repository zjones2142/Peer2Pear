#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>
#include <QMap>
#include <functional>

/*
 * IHttpClient — platform abstraction for HTTP requests.
 *
 * Used by RelayClient for anonymous envelope sends (POST /v1/send).
 * Each platform provides a thin implementation:
 *   Desktop (Qt):   QtHttpClient wrapping QNetworkAccessManager
 *   iOS:            URLSessionHttpClient wrapping URLSession
 *   Android:        OkHttpHttpClient wrapping OkHttpClient
 */
class IHttpClient {
public:
    virtual ~IHttpClient() = default;

    struct Response {
        int        status = 0;   // HTTP status code (200, 413, 429, etc.)
        QByteArray body;         // response body
        QString    error;        // non-empty on network failure
    };

    using Callback = std::function<void(const Response&)>;

    /// POST binary data to a URL. Headers are optional (e.g., X-To for legacy).
    /// The callback is invoked when the request completes (success or failure).
    virtual void post(const QUrl& url,
                      const QByteArray& body,
                      const QMap<QString, QString>& headers,
                      Callback cb) = 0;

    /// GET a URL. Used by RelayClient to fetch /v1/relay_info (Fix #7 —
    /// onion routing needs the relay's X25519 pubkey).
    virtual void get(const QUrl& url,
                     const QMap<QString, QString>& headers,
                     Callback cb) = 0;
};
