#pragma once

#include "IWebSocket.hpp"
#include "IHttpClient.hpp"
#include <QObject>
#include <QUrl>
#include <QTimer>
#include <QMap>
#include <QSet>
#include <QVector>

class CryptoEngine;

/*
 * RelayClient — unified relay transport
 *
 * Replaces MailboxClient + RendezvousClient with a single class that:
 *   - Sends envelopes anonymously via HTTP POST /v1/send (no sender identity)
 *   - Receives envelopes via authenticated WebSocket /v1/receive (push-based)
 *   - Handles presence via WS messages (subscribe + push, no polling)
 *   - Supports retry queue for failed sends
 *   - Delivers stored mailbox envelopes immediately on WS connect
 *
 * The relay never sees plaintext. It reads only the 'to' field
 * (bytes 1-32 of the envelope) for routing.
 *
 * Takes an IWebSocket& for platform portability — desktop provides
 * QtWebSocket, iOS provides URLSessionWebSocket, Android provides
 * OkHttpWebSocket. Each is ~50-80 lines of glue code.
 */
class RelayClient : public QObject {
    Q_OBJECT
public:
    explicit RelayClient(IWebSocket& ws, IHttpClient& http, CryptoEngine* crypto, QObject* parent = nullptr);
    ~RelayClient() override;

    // Set the relay server URL (e.g., "wss://relay.peer2pear.org:8443")
    void setRelayUrl(const QUrl& url);

    // Connect the WebSocket receive channel (authenticates with Ed25519 sig)
    void connectToRelay();
    void disconnectFromRelay();
    bool isConnected() const;

    // Send a sealed envelope anonymously via HTTP POST /v1/send.
    // The recipient is parsed from the envelope header (bytes 1-32).
    void sendEnvelope(const QByteArray& sealedEnvelope);

    // Send with explicit recipient (for legacy envelope format that doesn't
    // have the recipient embedded in the binary header).
    void sendEnvelopeTo(const QString& recipientIdB64u,
                        const QByteArray& envelopeBytes);

    // Presence: subscribe to online/offline updates for a set of peers.
    // Results are pushed via presenceChanged signal.
    void subscribePresence(const QStringList& peerIds);

    // One-shot presence query (results via presenceChanged signal).
    void queryPresence(const QStringList& peerIds);

signals:
    void connected();
    void disconnected();
    void status(const QString& s);

    // Emitted for each envelope received (real-time push or stored mailbox delivery)
    void envelopeReceived(const QByteArray& envelope);

    // Presence updates
    void presenceChanged(const QString& peerIdB64u, bool online);

private slots:
    void onWsConnected();
    void onWsDisconnected();
    void onWsBinaryMessage(const QByteArray& data);
    void onWsTextMessage(const QString& message);

private:
    void authenticate();
    void scheduleReconnect();
    void processRetryQueue();

    CryptoEngine*         m_crypto = nullptr;
    IWebSocket&           m_ws;
    IHttpClient&          m_http;
    QUrl                  m_relayUrl;     // base URL (https/wss)
    bool                  m_authenticated = false;
    bool                  m_intentionalDisconnect = false;

    // Reconnect with exponential backoff
    QTimer m_reconnectTimer;
    int    m_reconnectAttempt = 0;
    static constexpr int kMaxReconnectDelaySec = 60;

    // Retry queue for failed sends
    static constexpr int kMaxRetries = 5;
    static constexpr int kMaxRetryQueue = 100; // M1 fix: prevent OOM
    struct PendingEnvelope {
        QByteArray data;
        int        retryCount = 0;
    };
    QVector<PendingEnvelope> m_retryQueue;
    QTimer                   m_retryTimer;
    bool                     m_retryInFlight = false;
    void scheduleRetry();
};
