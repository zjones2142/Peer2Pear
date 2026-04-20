#pragma once

#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

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
 * Types: std::string URL + peer IDs, Bytes envelopes.
 * Async: ITimer for scheduling, std::function callbacks for events.
 * No Qt — core/ is Qt-free.
 */
class RelayClient {
public:
    using Bytes = std::vector<uint8_t>;

    RelayClient(IWebSocket& ws, IHttpClient& http,
                ITimerFactory& timers, CryptoEngine* crypto);
    ~RelayClient();

    RelayClient(const RelayClient&)            = delete;
    RelayClient& operator=(const RelayClient&) = delete;

    // Set the relay server URL (e.g., "wss://relay.peer2pear.org:8443")
    void setRelayUrl(const std::string& url);

    // Connect the WebSocket receive channel (authenticates with Ed25519 sig)
    void connectToRelay();
    void disconnectFromRelay();
    bool isConnected() const;

    // Send a sealed envelope anonymously via HTTP POST /v1/send.
    // The recipient is parsed from the envelope header (bytes 1-32).
    void sendEnvelope(const Bytes& sealedEnvelope);

    // Presence: subscribe to online/offline updates for a set of peers.
    void subscribePresence(const std::vector<std::string>& peerIds);

    // One-shot presence query.
    void queryPresence(const std::vector<std::string>& peerIds);

    // ── DAITA: client-side traffic analysis defense ─────────────────────────
    void setJitterRange(int minMs, int maxMs);
    void setCoverTrafficInterval(int seconds);
    void setKnownPeers(const std::vector<std::string>& peerIds);

    // ── Multi-relay routing ─────────────────────────────────────────────────
    void addSendRelay(const std::string& url);
    void setMultiHopEnabled(bool enabled);
    void refreshRelayInfo();

    /// Set the privacy level:
    ///   0 = Standard:  padding only (default)
    ///   1 = Enhanced:  + jitter (50-300ms) + cover traffic (30s) + multi-relay rotation
    ///   2 = Maximum:   + multi-hop forwarding + high-frequency cover traffic (10s)
    void setPrivacyLevel(int level);

    // ── Event callbacks — set from outside before connecting ─────────────
    //
    // onConnected:        fires after WS authenticates successfully.
    // onDisconnected:     fires on WS close (intentional or lost).
    // onStatus:           human-readable status string; UI hook.
    // onEnvelopeReceived: binary envelope received (real-time or stored).
    // onPresenceChanged:  presence push from relay.
    std::function<void()>                          onConnected;
    std::function<void()>                          onDisconnected;
    std::function<void(const std::string&)>        onStatus;
    std::function<void(const Bytes&)>              onEnvelopeReceived;
    std::function<void(const std::string&, bool)>  onPresenceChanged;

private:
    void onWsConnected();
    void onWsDisconnected();
    void onWsBinaryMessage(const Bytes& data);
    void onWsTextMessage(const std::string& message);

    void authenticate();
    void scheduleReconnect();
    void processRetryQueue();

    void sendCoverEnvelope();
    void scheduleCoverTimer();
    void onRealActivity();

    std::string pickSendRelay();
    int         pickJitterMs() const;
    void postEnvelope(const std::string& relayUrl, const Bytes& envelope,
                      IHttpClient::Callback cb);
    void forwardEnvelope(const std::string& viaRelay, const std::string& toRelay,
                         const Bytes& envelope,
                         IHttpClient::Callback cb);

    void scheduleRetry();

    void emitStatus(const std::string& s) { if (onStatus) onStatus(s); }

    CryptoEngine*   m_crypto   = nullptr;
    IWebSocket&     m_ws;
    IHttpClient&    m_http;
    ITimerFactory&  m_timers;
    std::string     m_relayUrl;
    bool            m_authenticated         = false;
    bool            m_intentionalDisconnect = false;

    // Reconnect with exponential backoff
    std::unique_ptr<ITimer> m_reconnectTimer;
    int    m_reconnectAttempt = 0;
    static constexpr int kMaxReconnectDelaySec = 60;

    // Retry queue for failed sends
    static constexpr int kMaxRetries    = 5;
    static constexpr int kMaxRetryQueue = 100;
    struct PendingEnvelope {
        Bytes data;
        int   retryCount = 0;
    };
    std::vector<PendingEnvelope> m_retryQueue;
    std::unique_ptr<ITimer>      m_retryTimer;
    bool                         m_retryInFlight = false;

    // DAITA: client-side traffic defense
    static constexpr uint8_t kDummyVersion = 0x00;
    int                     m_jitterMinMs      = 0;
    int                     m_jitterMaxMs      = 0;
    std::unique_ptr<ITimer> m_coverTimer;
    int                     m_coverIntervalSec = 0;
    int                     m_burstRemaining   = 0;

    std::vector<std::string> m_knownPeers;
    std::set<std::string>    m_onlinePeers;

    // Multi-relay routing
    std::vector<std::string> m_sendRelays;
    size_t                   m_sendRelayIdx = 0;
    bool                     m_multiHop     = false;

    std::map<std::string, Bytes> m_relayX25519Pubs;
};
