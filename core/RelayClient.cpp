#include "RelayClient.hpp"
#include "CryptoEngine.hpp"
#include "OnionWrap.hpp"
#include "SealedEnvelope.hpp"
#include <sodium.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <utility>

// Qt usage is confined to the .cpp — URL manipulation only, via three tiny
// helpers.  Phase 7 leaves this in place; a pure-std URL helper can replace
// it later without touching any caller.
#include <QUrl>
#include <QDebug>
#include <QString>

using json = nlohmann::json;

namespace {

std::string urlWithPath(const std::string& baseUrl, const std::string& path) {
    QUrl u(QString::fromStdString(baseUrl));
    u.setPath(QString::fromStdString(path));
    return u.toString().toStdString();
}

std::string baseOf(const std::string& url) {
    QUrl u(QString::fromStdString(url));
    return u.toString(QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment)
        .toStdString();
}

std::string wsUrl(const std::string& baseUrl, const std::string& path) {
    QUrl u(QString::fromStdString(baseUrl));
    if      (u.scheme() == "https") u.setScheme("wss");
    else if (u.scheme() == "http")  u.setScheme("ws");
    u.setPath(QString::fromStdString(path));
    return u.toString().toStdString();
}

std::string hostPort(const std::string& url) {
    QUrl u(QString::fromStdString(url));
    const QString host = u.host();
    if (u.port() > 0)
        return (host + ":" + QString::number(u.port())).toStdString();
    return host.toStdString();
}

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

QString peerPrefix(const std::string& id) {
    const size_t n = std::min<size_t>(8, id.size());
    return QString::fromStdString(id.substr(0, n)) + "…";
}

}  // anonymous namespace

RelayClient::RelayClient(IWebSocket& ws, IHttpClient& http,
                          ITimerFactory& timers, CryptoEngine* crypto)
    : m_crypto(crypto), m_ws(ws), m_http(http), m_timers(timers)
{
    m_ws.onConnected     = [this]()                           { onWsConnected(); };
    m_ws.onDisconnected  = [this]()                           { onWsDisconnected(); };
    m_ws.onBinaryMessage = [this](const IWebSocket::Bytes& d) { onWsBinaryMessage(d); };
    m_ws.onTextMessage   = [this](const std::string& m)       { onWsTextMessage(m); };

    m_reconnectTimer = m_timers.create();
    m_retryTimer     = m_timers.create();
    m_coverTimer     = m_timers.create();
}

RelayClient::~RelayClient()
{
    m_intentionalDisconnect = true;
    m_ws.close();
}

void RelayClient::setRelayUrl(const std::string& url) { m_relayUrl = url; }

bool RelayClient::isConnected() const
{
    return m_ws.isConnected() && m_authenticated;
}

// ── WebSocket receive channel ────────────────────────────────────────────────

void RelayClient::connectToRelay()
{
    if (!m_ws.isIdle()) return;

    m_intentionalDisconnect = false;
    m_authenticated = false;

    const std::string wsU = wsUrl(m_relayUrl, "/v1/receive");
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] Connecting to" << QString::fromStdString(wsU);
#endif
    m_ws.open(wsU);
}

void RelayClient::disconnectFromRelay()
{
    m_intentionalDisconnect = true;
    m_reconnectTimer->stop();
    m_ws.close();
}

void RelayClient::onWsConnected()
{
#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] WebSocket connected, authenticating...";
#endif
    m_reconnectAttempt = 0;
    authenticate();
}

void RelayClient::authenticate()
{
    if (!m_crypto) return;

    const std::string peerId  = CryptoEngine::toBase64Url(m_crypto->identityPub());
    const int64_t     ts      = nowMs();
    const std::string message = "RELAY1|" + peerId + "|" + std::to_string(ts);
    const Bytes       msgBytes(message.begin(), message.end());
    const std::string sig     = m_crypto->signB64u(msgBytes);

    json auth;
    auth["peer_id"] = peerId;
    auth["ts"]      = ts;
    auth["sig"]     = sig;

    m_ws.sendTextMessage(auth.dump());
}

void RelayClient::onWsDisconnected()
{
    m_authenticated = false;
    m_coverTimer->stop();
    m_onlinePeers.clear();

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] WebSocket disconnected";
#endif

    if (onDisconnected) onDisconnected();

    if (!m_intentionalDisconnect)
        scheduleReconnect();
}

void RelayClient::scheduleReconnect()
{
    const int delaySec = std::min(1 << m_reconnectAttempt, kMaxReconnectDelaySec);
    m_reconnectAttempt++;

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] Reconnecting in" << delaySec << "seconds...";
#endif
    m_reconnectTimer->startSingleShot(delaySec * 1000,
                                       [this] { connectToRelay(); });
}

// ── Incoming messages ────────────────────────────────────────────────────────

void RelayClient::onWsBinaryMessage(const Bytes& data)
{
    if (!data.empty() && data[0] == kDummyVersion)
        return;

    onRealActivity();

    if (onEnvelopeReceived) onEnvelopeReceived(data);
}

void RelayClient::onWsTextMessage(const std::string& message)
{
    json obj;
    try { obj = json::parse(message); } catch (...) { return; }
    if (!obj.is_object()) return;
    const std::string type = obj.value("type", "");

    if (type == "auth_ok") {
        m_authenticated = true;
#ifndef QT_NO_DEBUG_OUTPUT
        const std::string authedAs = obj.value("peer_id", "");
        qDebug() << "[Relay] Authenticated as" << peerPrefix(authedAs);
#endif
        if (m_coverIntervalSec > 0) scheduleCoverTimer();
        refreshRelayInfo();
        if (onConnected) onConnected();
        return;
    }

    if (type == "presence" || type == "presence_result") {
        if (obj.contains("peer_id")) {
            const std::string pid = obj.value("peer_id", "");
            const bool online     = obj.value("online", false);
            if (online) m_onlinePeers.insert(pid);
            else        m_onlinePeers.erase(pid);
            if (onPresenceChanged) onPresenceChanged(pid, online);
            return;
        }

        if (obj.contains("peers") && obj["peers"].is_object()) {
            for (auto it = obj["peers"].begin(); it != obj["peers"].end(); ++it) {
                const bool online = it.value().get<bool>();
                if (online) m_onlinePeers.insert(it.key());
                else        m_onlinePeers.erase(it.key());
                if (onPresenceChanged) onPresenceChanged(it.key(), online);
            }
            return;
        }
    }

    if (type == "pong") return;
}

// ── Sending envelopes ────────────────────────────────────────────────────────

void RelayClient::sendEnvelope(const Bytes& sealedEnvelope)
{
    if (m_coverIntervalSec > 0 && m_burstRemaining <= 0 && isConnected()) {
        const int precover = 1 + int(randombytes_uniform(2));
        for (int i = 0; i < precover; i++)
            sendCoverEnvelope();
    }
    onRealActivity();

    const std::string relay = pickSendRelay();

    auto retryCb = [this, sealedEnvelope](const IHttpClient::Response& r) {
        if (r.error.empty()) return;

        if (r.status == 413) {
            emitStatus("Envelope too large for relay — rejected.");
            return;
        }

        if (static_cast<int>(m_retryQueue.size()) < kMaxRetryQueue)
            m_retryQueue.push_back({ sealedEnvelope, 0 });
        if (!m_retryTimer->isActive())
            scheduleRetry();

        if (r.status != 429)
            emitStatus("relay send error: " + r.error + " — will retry");
    };

    if (m_multiHop && m_sendRelays.size() >= 2) {
        const std::string via = pickSendRelay();
        std::string to        = pickSendRelay();
        if (to == via) to = m_relayUrl;
        forwardEnvelope(via, to, sealedEnvelope, std::move(retryCb));
    } else {
        postEnvelope(relay, sealedEnvelope, std::move(retryCb));
    }
}

// ── Presence ─────────────────────────────────────────────────────────────────

void RelayClient::subscribePresence(const std::vector<std::string>& peerIds)
{
    m_knownPeers = peerIds;
    if (!isConnected()) return;

    json ids = json::array();
    for (const std::string& id : peerIds) {
        const auto first = id.find_first_not_of(" \t\r\n");
        const auto last  = id.find_last_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        ids.push_back(id.substr(first, last - first + 1));
    }

    json msg;
    msg["type"]     = "presence_subscribe";
    msg["peer_ids"] = std::move(ids);
    m_ws.sendTextMessage(msg.dump());
}

void RelayClient::queryPresence(const std::vector<std::string>& peerIds)
{
    if (!isConnected()) return;

    json ids = json::array();
    for (const std::string& id : peerIds) {
        const auto first = id.find_first_not_of(" \t\r\n");
        const auto last  = id.find_last_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        ids.push_back(id.substr(first, last - first + 1));
    }

    json msg;
    msg["type"]     = "presence_query";
    msg["peer_ids"] = std::move(ids);
    m_ws.sendTextMessage(msg.dump());
}

// ── Retry queue ──────────────────────────────────────────────────────────────

void RelayClient::scheduleRetry()
{
    if (m_retryQueue.empty()) return;
    const int attempt = m_retryQueue.front().retryCount;
    const int delaySec = std::min(1 << attempt, 60);
    m_retryTimer->startSingleShot(delaySec * 1000,
                                   [this] { processRetryQueue(); });
}

void RelayClient::processRetryQueue()
{
    if (m_retryQueue.empty() || m_retryInFlight) return;
    m_retryInFlight = true;

    PendingEnvelope pe = std::move(m_retryQueue.front());
    m_retryQueue.erase(m_retryQueue.begin());

    const std::string sendUrl = urlWithPath(m_relayUrl, "/v1/send");

    m_http.post(sendUrl, pe.data, {},
                [this, pe](const IHttpClient::Response& r) {
        m_retryInFlight = false;

        if (r.error.empty()) {
            if (!m_retryQueue.empty()) scheduleRetry();
            return;
        }

        if (r.status == 413) {
            if (!m_retryQueue.empty()) scheduleRetry();
            return;
        }

        PendingEnvelope next = pe;
        next.retryCount++;
        if (next.retryCount < kMaxRetries) {
            m_retryQueue.insert(m_retryQueue.begin(), std::move(next));
            scheduleRetry();
        } else {
            emitStatus("Gave up delivering envelope after max retries.");
        }
    });
}

// ── DAITA ────────────────────────────────────────────────────────────────────

void RelayClient::setJitterRange(int minMs, int maxMs)
{
    m_jitterMinMs = std::max(0, minMs);
    m_jitterMaxMs = std::max(m_jitterMinMs, maxMs);
}

void RelayClient::setCoverTrafficInterval(int seconds)
{
    m_coverIntervalSec = std::max(0, seconds);
    m_coverTimer->stop();
    m_burstRemaining = 0;
    if (m_coverIntervalSec > 0 && isConnected())
        scheduleCoverTimer();
}

void RelayClient::onRealActivity()
{
    if (m_coverIntervalSec <= 0) return;

    if (m_burstRemaining > 0) {
        --m_burstRemaining;
    } else {
        m_burstRemaining = 2 + int(randombytes_uniform(3));
    }

    m_coverTimer->stop();
    scheduleCoverTimer();
}

void RelayClient::scheduleCoverTimer()
{
    if (m_coverIntervalSec <= 0) return;

    if (m_burstRemaining > 0) {
        const int delayMs = 1000 + int(randombytes_uniform(4000));
        m_coverTimer->startSingleShot(delayMs, [this] { sendCoverEnvelope(); });
    } else {
        const int idleMs = m_coverIntervalSec * 1000
            + int(randombytes_uniform(uint32_t(m_coverIntervalSec * 4000)));
        m_coverTimer->startSingleShot(idleMs, [this] { sendCoverEnvelope(); });
        m_burstRemaining = 2 + int(randombytes_uniform(5));
    }
}

void RelayClient::setKnownPeers(const std::vector<std::string>& peerIds)
{
    m_knownPeers = peerIds;
}

void RelayClient::sendCoverEnvelope()
{
    if (!isConnected()) return;

    std::vector<std::string> onlinePool;
    onlinePool.reserve(m_knownPeers.size());
    for (const std::string& pid : m_knownPeers)
        if (m_onlinePeers.count(pid)) onlinePool.push_back(pid);
    if (onlinePool.empty()) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }
    const std::string& peerId = onlinePool[randombytes_uniform(uint32_t(onlinePool.size()))];
    Bytes recipientPub = CryptoEngine::fromBase64Url(peerId);
    if (recipientPub.size() != 32) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }

    const bool hybrid = randombytes_uniform(10) == 0;
    const int baseMin = hybrid
        ? (1 + 32 + 1088 + 24 + 16)
        : (1 + 32 + 24 + 16);

    size_t innerSize;
    if (randombytes_uniform(20) == 0) {
        innerSize = baseMin + 244000 + size_t(randombytes_uniform(8000));
    } else {
        innerSize = baseMin + size_t(randombytes_uniform(1400));
    }
    Bytes body(innerSize);
    randombytes_buf(body.data(), innerSize);
    body[0] = hybrid ? uint8_t(0x03) : uint8_t(0x02);

    Bytes env = SealedEnvelope::wrapForRelay(recipientPub, body);
    if (env.empty()) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }

    auto noop = [](const IHttpClient::Response&) {};
    if (m_multiHop && m_sendRelays.size() >= 2) {
        const std::string via = pickSendRelay();
        std::string to        = pickSendRelay();
        if (to == via) to = m_relayUrl;
        forwardEnvelope(via, to, env, noop);
    } else {
        postEnvelope(pickSendRelay(), env, noop);
    }

    if (m_burstRemaining > 0) --m_burstRemaining;
    scheduleCoverTimer();
}

// ── Multi-relay routing ─────────────────────────────────────────────────────

void RelayClient::addSendRelay(const std::string& url)
{
    if (url.empty()) return;
    if (std::find(m_sendRelays.begin(), m_sendRelays.end(), url) == m_sendRelays.end())
        m_sendRelays.push_back(url);
}

void RelayClient::setMultiHopEnabled(bool enabled) { m_multiHop = enabled; }

std::string RelayClient::pickSendRelay()
{
    if (m_sendRelays.empty()) return m_relayUrl;
    m_sendRelayIdx = (m_sendRelayIdx + 1) % m_sendRelays.size();
    return m_sendRelays[m_sendRelayIdx];
}

int RelayClient::pickJitterMs() const
{
    if (m_jitterMaxMs <= 0) return 0;
    const int span = m_jitterMaxMs - m_jitterMinMs;
    if (span <= 0) return m_jitterMinMs;
    return m_jitterMinMs + int(randombytes_uniform(uint32_t(span + 1)));
}

void RelayClient::postEnvelope(const std::string& relayUrl, const Bytes& envelope,
                                IHttpClient::Callback cb)
{
    const std::string sendUrl = urlWithPath(relayUrl, "/v1/send");

    const int jitterMs = pickJitterMs();
    if (jitterMs <= 0) {
        m_http.post(sendUrl, envelope, {}, std::move(cb));
        return;
    }

    m_timers.singleShot(jitterMs,
        [this, sendUrl, envelope, cb = std::move(cb)]() mutable {
            m_http.post(sendUrl, envelope, {}, std::move(cb));
        });
}

void RelayClient::forwardEnvelope(const std::string& viaRelay, const std::string& toRelay,
                                   const Bytes& envelope,
                                   IHttpClient::Callback cb)
{
    const std::string relayKey = baseOf(viaRelay);
    const auto pubIt = m_relayX25519Pubs.find(relayKey);
    const bool havePub = (pubIt != m_relayX25519Pubs.end() && pubIt->second.size() == 32);

    if (havePub) {
        const std::string nextHop = urlWithPath(toRelay, "/v1/send");
        const Bytes onion = OnionWrap::wrap(pubIt->second, nextHop, envelope);

        if (!onion.empty()) {
            const std::string fwdUrl = urlWithPath(viaRelay, "/v1/forward-onion");

            const int jitterMs = pickJitterMs();
            if (jitterMs <= 0) {
                m_http.post(fwdUrl, onion, {}, std::move(cb));
            } else {
                m_timers.singleShot(jitterMs,
                    [this, fwdUrl, onion, cb = std::move(cb)]() mutable {
                        m_http.post(fwdUrl, onion, {}, std::move(cb));
                    });
            }
            return;
        }
    }

    // Legacy path
    const std::string fwdUrl = urlWithPath(viaRelay, "/v1/forward");
    IHttpClient::Headers headers;
    headers["X-Forward-To"] = hostPort(toRelay);

    const int jitterMs = pickJitterMs();
    if (jitterMs <= 0) {
        m_http.post(fwdUrl, envelope, headers, std::move(cb));
    } else {
        m_timers.singleShot(jitterMs,
            [this, fwdUrl, envelope, headers, cb = std::move(cb)]() mutable {
                m_http.post(fwdUrl, envelope, headers, std::move(cb));
            });
    }
    const_cast<RelayClient*>(this)->refreshRelayInfo();
}

void RelayClient::refreshRelayInfo()
{
    auto fetchOne = [this](const std::string& base) {
        const std::string infoUrl  = urlWithPath(base, "/v1/relay_info");
        const std::string cacheKey = baseOf(base);
        m_http.get(infoUrl, {},
                   [this, cacheKey](const IHttpClient::Response& r) {
            if (!r.error.empty() || r.status != 200) return;
            json doc;
            try {
                doc = json::parse(std::string(r.body.begin(), r.body.end()));
            } catch (...) { return; }
            if (!doc.is_object()) return;
            const std::string pubB64u = doc.value("x25519_pub", "");
            const Bytes pub = CryptoEngine::fromBase64Url(pubB64u);
            if (pub.size() != 32) return;
            m_relayX25519Pubs[cacheKey] = pub;
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[Relay] cached X25519 pub for onion routing:"
                     << QString::fromStdString(cacheKey);
#endif
        });
    };
    if (!m_relayUrl.empty()) fetchOne(m_relayUrl);
    for (const std::string& url : m_sendRelays) fetchOne(url);
}

void RelayClient::setPrivacyLevel(int level)
{
    switch (level) {
    case 0:
        setJitterRange(0, 0);
        setCoverTrafficInterval(0);
        m_sendRelays.clear();
        setMultiHopEnabled(false);
        break;
    case 1:
        setJitterRange(50, 300);
        setCoverTrafficInterval(30);
        setMultiHopEnabled(false);
        break;
    case 2:
        setJitterRange(100, 500);
        setCoverTrafficInterval(10);
        setMultiHopEnabled(true);
        break;
    }
}
