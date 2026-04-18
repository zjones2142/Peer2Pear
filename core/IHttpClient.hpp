#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

/*
 * IHttpClient — platform abstraction for HTTP requests.
 *
 * Used by RelayClient for anonymous envelope sends (POST /v1/send).
 * Each platform provides a thin implementation:
 *   Desktop (Qt):   QtHttpClient wrapping QNetworkAccessManager
 *   iOS:            URLSessionHttpClient wrapping URLSession
 *   Android:        OkHttpHttpClient wrapping OkHttpClient
 *
 * Types: std::string for URLs/headers/errors, std::vector<uint8_t> for bytes.
 * Migrated off Qt 2026-04.
 */
class IHttpClient {
public:
    using Bytes = std::vector<uint8_t>;
    using Headers = std::map<std::string, std::string>;

    virtual ~IHttpClient() = default;

    struct Response {
        int         status = 0;   // HTTP status code (200, 413, 429, etc.)
        Bytes       body;         // response body
        std::string error;        // non-empty on network failure
    };

    using Callback = std::function<void(const Response&)>;

    /// POST binary data to a URL. Headers are optional (e.g., X-To for legacy).
    /// The callback is invoked when the request completes (success or failure).
    virtual void post(const std::string& url,
                      const Bytes& body,
                      const Headers& headers,
                      Callback cb) = 0;

    /// GET a URL. Used by RelayClient to fetch /v1/relay_info (Fix #7 —
    /// onion routing needs the relay's X25519 pubkey).
    virtual void get(const std::string& url,
                     const Headers& headers,
                     Callback cb) = 0;
};
