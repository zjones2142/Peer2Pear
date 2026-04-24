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

#include "log.hpp"

using json = nlohmann::json;

namespace {

// Tiny URL parser — handles `scheme://host[:port][/path][?query][#fragment]`.
// We only support http(s)/ws(s) URLs in well-formed shape.  Path/query/fragment
// are intentionally discarded by every helper that constructs a new URL — the
// callers pass in the path they want.
struct ParsedUrl {
    std::string scheme;       // "https", "wss", …
    std::string host;
    int         port = -1;    // -1 if not specified
};

ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl out;
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return out;
    out.scheme = url.substr(0, schemeEnd);
    auto rest = url.substr(schemeEnd + 3);
    // Strip path/query/fragment — first '/' '?' '#' wins
    auto cut = rest.find_first_of("/?#");
    std::string authority = (cut == std::string::npos) ? rest : rest.substr(0, cut);
    // Split host[:port]
    auto colon = authority.find(':');
    if (colon == std::string::npos) {
        out.host = authority;
    } else {
        out.host = authority.substr(0, colon);
        try { out.port = std::stoi(authority.substr(colon + 1)); }
        catch (...) { out.port = -1; }
    }
    return out;
}

std::string buildUrl(const std::string& scheme, const std::string& host,
                     int port, const std::string& path) {
    std::string out = scheme + "://" + host;
    if (port > 0) out += ":" + std::to_string(port);
    if (!path.empty()) {
        if (path[0] != '/') out += '/';
        out += path;
    }
    return out;
}

std::string urlWithPath(const std::string& baseUrl, const std::string& path) {
    auto p = parseUrl(baseUrl);
    return buildUrl(p.scheme, p.host, p.port, path);
}

std::string baseOf(const std::string& url) {
    auto p = parseUrl(url);
    return buildUrl(p.scheme, p.host, p.port, {});
}

std::string wsUrl(const std::string& baseUrl, const std::string& path) {
    auto p = parseUrl(baseUrl);
    if      (p.scheme == "https") p.scheme = "wss";
    else if (p.scheme == "http")  p.scheme = "ws";
    return buildUrl(p.scheme, p.host, p.port, path);
}

std::string hostPort(const std::string& url) {
    auto p = parseUrl(url);
    if (p.port > 0) return p.host + ":" + std::to_string(p.port);
    return p.host;
}

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string peerPrefix(const std::string& id) {
    const size_t n = std::min<size_t>(8, id.size());
    return id.substr(0, n) + "…";
}

}  // anonymous namespace

RelayClient::RelayClient(IWebSocket& ws, IHttpClient& http,
                          ITimerFactory& timers, CryptoEngine* crypto)
    : m_crypto(crypto), m_ws(ws), m_http(http), m_timers(timers)
{
    m_ws.onConnected     = [this]()                           { onWsConnected(); };
    m_ws.onDisconnected  = [this]()                           { onWsDisconnected(); };
    m_ws.onBinaryMessage = [this](const Bytes& d) { onWsBinaryMessage(d); };
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

void RelayClient::setRelayUrl(const std::string& url) {
    // Refuse non-TLS relay URLs.  An http:// / ws:// URL would silently
    // downgrade the WebSocket and HTTP paths to cleartext, exposing auth
    // signatures and envelope ciphertexts in-flight.  The only exceptions
    // are the empty string (used by tests + the reset pattern) and
    // localhost for dev, which we accept with a loud log.
    auto parsed = parseUrl(url);
    const std::string& s = parsed.scheme;
    const bool isTls = (s == "https" || s == "wss");
    const bool isDev = (s == "http" || s == "ws") &&
                       (parsed.host == "localhost" ||
                        parsed.host == "127.0.0.1" ||
                        parsed.host == "::1");
    if (!url.empty() && !isTls && !isDev) {
        emitStatus("relay URL rejected — only https:// / wss:// are allowed");
        P2P_WARN("[Relay] setRelayUrl rejected non-TLS url: " << url);
        return;
    }
    if (!url.empty() && !isTls) {
        P2P_WARN("[Relay] allowing non-TLS localhost url for dev: " << url);
    }
    m_relayUrl = url;
}

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
    P2P_LOG("[Relay] Connecting to " << wsU);
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
    P2P_LOG("[Relay] WebSocket connected, authenticating...");
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

    // Queue a push-token replay if we had one registered — the relay
    // may have lost per-connection state, and the next reconnect
    // should re-establish us as reachable via push.
    if (!m_pushPlatform.empty()) m_pushPending = true;

    P2P_LOG("[Relay] WebSocket disconnected");

    if (onDisconnected) onDisconnected();

    if (!m_intentionalDisconnect)
        scheduleReconnect();
}

void RelayClient::scheduleReconnect()
{
    const int delaySec = std::min(1 << m_reconnectAttempt, kMaxReconnectDelaySec);
    m_reconnectAttempt++;

    P2P_LOG("[Relay] Reconnecting in " << delaySec << " seconds...");
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
        P2P_LOG("[Relay] Authenticated as " << peerPrefix(obj.value("peer_id", std::string())));
        if (m_coverIntervalSec > 0) scheduleCoverTimer();
        refreshRelayInfo();

        // Replay any pending push-token registration on this fresh
        // authenticated WS.  The cached (platform, token) pair is
        // whatever the app last told us — includes the "unregister"
        // case (empty token) so the relay drops stale rows if the
        // user signed out offline.
        if (m_pushPending && !m_pushPlatform.empty()) {
            json msg;
            msg["type"]     = "push_register";
            msg["platform"] = m_pushPlatform;
            msg["token"]    = m_pushToken;
            m_ws.sendTextMessage(msg.dump());
            m_pushPending = false;
        }

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

void RelayClient::registerPushToken(const std::string& platform,
                                       const std::string& token)
{
    // Cache so we can replay on reconnect.  The WS auth already
    // identifies which peer_id this is for, so the relay stores
    // under (connected_peer_id, platform).  Token may be empty to
    // signal "unregister" — the relay treats that as a delete.
    m_pushPlatform = platform;
    m_pushToken    = token;
    m_pushPending  = true;

    if (!isConnected()) return;

    json msg;
    msg["type"]     = "push_register";
    msg["platform"] = platform;
    msg["token"]    = token;
    m_ws.sendTextMessage(msg.dump());
    m_pushPending = false;
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

    // When no contacts are online (or the user has no contacts yet), fall
    // back to a self-addressed cover envelope instead of going silent.
    // Otherwise a relay operator observing a steady cover-traffic rate
    // suddenly drop to zero could infer "all this user's contacts just
    // went offline," and cover↔silence transitions themselves would leak
    // online-state changes.  Routing the packet to our own mailbox keeps
    // the outbound profile constant regardless of peer presence; the
    // envelope lands back in our own inbox, fails unseal (random body),
    // and is discarded.
    Bytes recipientPub;
    if (!onlinePool.empty()) {
        const std::string& peerId =
            onlinePool[randombytes_uniform(uint32_t(onlinePool.size()))];
        recipientPub = CryptoEngine::fromBase64Url(peerId);
    } else if (m_crypto) {
        recipientPub = m_crypto->identityPub();
    }
    if (recipientPub.size() != 32) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }

    const bool hybrid = randombytes_uniform(10) == 0;
    const int baseMin = hybrid
        ? (1 + 32 + 1088 + 24 + 16)
        : (1 + 32 + 24 + 16);

    // Arch-review #9: pick a padding bucket first, then fill the
    // inner body so it lands *inside* that bucket after wrapForRelay
    // pads it up.  SealedEnvelope buckets are {2 KiB, 16 KiB, 256
    // KiB}; the 37-byte routing header means the raw inner max per
    // bucket is (bucket - 37).
    //
    //   BandwidthBiased : 60 / 30 / 10  — covers the medium bucket
    //                     (previously 0%) so text-only users can't be
    //                     fingerprinted by "never sends a 16 KB body."
    //
    //   UniformBuckets  : 34 / 33 / 33 — every user's cover histogram
    //                     is identical regardless of real-send shape.
    //                     Roughly 3x the bandwidth of the biased mode.
    constexpr size_t kSmallMax  =   2 * 1024 - 37;  //  2011
    constexpr size_t kMediumMax =  16 * 1024 - 37;  // 16347
    constexpr size_t kLargeMax  = 256 * 1024 - 37;  // 262107

    const uint32_t roll = randombytes_uniform(100);
    uint32_t bucketProb[3];  // small / medium / large cutpoints in 0..99
    if (m_coverSizeMode == CoverSizeMode::UniformBuckets) {
        bucketProb[0] = 34;  // 0..33  → small
        bucketProb[1] = 67;  // 34..66 → medium
        bucketProb[2] = 100; // 67..99 → large
    } else {
        bucketProb[0] = 60;  // 0..59  → small
        bucketProb[1] = 90;  // 60..89 → medium
        bucketProb[2] = 100; // 90..99 → large
    }

    size_t innerSize;
    if (roll < bucketProb[0]) {
        const size_t span = (kSmallMax > size_t(baseMin))
            ? kSmallMax - size_t(baseMin) : 0;
        innerSize = size_t(baseMin) +
                    (span ? size_t(randombytes_uniform(uint32_t(span))) : 0);
    } else if (roll < bucketProb[1]) {
        // Span: (2 KiB .. 16 KiB) — skip the small bucket entirely.
        const size_t lo   = kSmallMax + 1;
        const size_t span = kMediumMax - lo;
        innerSize = lo + size_t(randombytes_uniform(uint32_t(span)));
    } else {
        // Span: (16 KiB .. 256 KiB).  Bounded below kLargeMax so the
        // envelope doesn't exceed the large bucket.
        const size_t lo   = kMediumMax + 1;
        const size_t span = kLargeMax - lo;
        innerSize = lo + size_t(randombytes_uniform(uint32_t(span)));
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
    // Pick uniformly at random rather than strict round-robin.
    // Deterministic rotation lets a traffic analyst observing multiple
    // relays fingerprint a single client by matching the N-step pattern.
    // Uniform random sampling over the configured relays removes that
    // signal; the expected per-relay load is the same as round-robin,
    // just without the identifying cadence.
    //
    // Uses randombytes_uniform from libsodium — crypto-grade RNG (not
    // math/rand) so observers can't predict future picks from past ones.
    if (m_sendRelays.empty()) return m_relayUrl;
    const uint32_t idx = randombytes_uniform(
        static_cast<uint32_t>(m_sendRelays.size()));
    m_sendRelayIdx = idx;  // kept for diagnostics / compat; no longer load-bearing
    return m_sendRelays[idx];
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

    // Refuse the /v1/forward fallback: it hands the full routing envelope
    // (including the plaintext recipientPub) to the entry relay via
    // X-Forward-To, defeating multi-hop privacy.  Trigger a pubkey
    // refresh and surface the situation to the caller.  The envelope
    // stays in the retry queue pending the refresh — the next send will
    // onion-wrap properly.
    emitStatus("multi-hop send deferred — entry relay X25519 pubkey not cached yet");
    P2P_WARN("[Relay] refusing /v1/forward fallback for " << baseOf(viaRelay)
              << " — pubkey not cached");
    if (cb) {
        IHttpClient::Response r;
        r.status = 0;
        r.error  = "entry relay pubkey not cached; retry after refreshRelayInfo";
        cb(r);
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
            P2P_LOG("[Relay] cached X25519 pub for onion routing: " << cacheKey);
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
        m_coverSizeMode = CoverSizeMode::BandwidthBiased;
        break;
    case 1:
        setJitterRange(50, 300);
        setCoverTrafficInterval(30);
        setMultiHopEnabled(false);
        m_coverSizeMode = CoverSizeMode::BandwidthBiased;
        break;
    case 2:
        setJitterRange(100, 500);
        setCoverTrafficInterval(10);
        setMultiHopEnabled(true);
        // Arch-review #9: Maximum privacy pays the ~3x bandwidth cost
        // for uniform cover distribution so the relay can't correlate
        // the user's observed bucket histogram with their actual sends.
        m_coverSizeMode = CoverSizeMode::UniformBuckets;
        break;
    }
}
