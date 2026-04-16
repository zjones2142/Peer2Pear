#include "RelayClient.hpp"
#include "CryptoEngine.hpp"
#include "SealedEnvelope.hpp"  // Fix #13: cover traffic uses real wrap-for-relay framing
#include "OnionWrap.hpp"       // Fix #7: onion layer for multi-hop forwarding
#include <sodium.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QRandomGenerator>
#include <QDebug>

RelayClient::RelayClient(IWebSocket& ws, IHttpClient& http, CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto), m_ws(ws), m_http(http)
{
    // IWebSocket callbacks
    m_ws.onConnected     = [this]()                    { onWsConnected(); };
    m_ws.onDisconnected  = [this]()                    { onWsDisconnected(); };
    m_ws.onBinaryMessage = [this](const QByteArray& d) { onWsBinaryMessage(d); };
    m_ws.onTextMessage   = [this](const QString& m)    { onWsTextMessage(m); };

    // Reconnect timer
    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout, this, &RelayClient::connectToRelay);

    // Retry timer for failed sends
    m_retryTimer.setSingleShot(true);
    connect(&m_retryTimer, &QTimer::timeout, this, &RelayClient::processRetryQueue);

    // DAITA: cover traffic timer (disabled by default)
    connect(&m_coverTimer, &QTimer::timeout, this, &RelayClient::sendCoverEnvelope);
}

RelayClient::~RelayClient()
{
    m_intentionalDisconnect = true;
    m_ws.close();
}

void RelayClient::setRelayUrl(const QUrl& url)
{
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

    // Build the WebSocket URL: wss://host:port/v1/receive
    QUrl wsUrl = m_relayUrl;
    if (wsUrl.scheme() == "https") wsUrl.setScheme("wss");
    else if (wsUrl.scheme() == "http") wsUrl.setScheme("ws");
    wsUrl.setPath("/v1/receive");

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] Connecting to" << wsUrl.toString();
#endif

    m_ws.open(wsUrl);
}

void RelayClient::disconnectFromRelay()
{
    m_intentionalDisconnect = true;
    m_reconnectTimer.stop();
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

    const QString peerId = CryptoEngine::toBase64Url(m_crypto->identityPub());
    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    const QString message = QString("RELAY1|%1|%2").arg(peerId).arg(ts);
    const QString sig = m_crypto->signB64u(message.toUtf8());

    QJsonObject auth;
    auth["peer_id"] = peerId;
    auth["ts"]      = ts;
    auth["sig"]     = sig;

    m_ws.sendTextMessage(
        QString::fromUtf8(QJsonDocument(auth).toJson(QJsonDocument::Compact)));
}

void RelayClient::onWsDisconnected()
{
    m_authenticated = false;
    m_coverTimer.stop();  // DAITA: stop cover traffic on disconnect
    // Fix #14: online-peer set is ws-session-scoped; clear so we don't use
    // stale presence after a reconnect lands fresh subscriptions.
    m_onlinePeers.clear();

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] WebSocket disconnected";
#endif

    emit disconnected();

    if (!m_intentionalDisconnect)
        scheduleReconnect();
}

void RelayClient::scheduleReconnect()
{
    // Exponential backoff: 1s, 2s, 4s, 8s, ... capped at 60s
    int delaySec = qMin(1 << m_reconnectAttempt, kMaxReconnectDelaySec);
    m_reconnectAttempt++;

#ifndef QT_NO_DEBUG_OUTPUT
    qDebug() << "[Relay] Reconnecting in" << delaySec << "seconds...";
#endif

    m_reconnectTimer.start(delaySec * 1000);
}

// ── Incoming messages ────────────────────────────────────────────────────────

void RelayClient::onWsBinaryMessage(const QByteArray& data)
{
    // DAITA: discard relay cover traffic (dummy envelopes with version 0x00)
    if (!data.isEmpty() && static_cast<quint8>(data.at(0)) == kDummyVersion)
        return;

    // DAITA: real receive resets cover traffic timer — mimics reading + replying
    onRealActivity();

    // Binary messages are sealed envelopes pushed by the relay
    emit envelopeReceived(data);
}

void RelayClient::onWsTextMessage(const QString& message)
{
    const QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8());
    if (!doc.isObject()) return;
    const QJsonObject obj = doc.object();
    const QString type = obj.value("type").toString();

    if (type == "auth_ok") {
        m_authenticated = true;
#ifndef QT_NO_DEBUG_OUTPUT
        qDebug() << "[Relay] Authenticated as" << obj.value("peer_id").toString().left(8) + "…";
#endif
        // DAITA: start cover traffic if configured
        if (m_coverIntervalSec > 0)
            scheduleCoverTimer();
        // Fix #7: fetch relay X25519 pubkeys so multi-hop forwards upgrade
        // from single-layer /v1/forward to proper onion /v1/forward-onion.
        refreshRelayInfo();
        emit connected();
        return;
    }

    if (type == "presence" || type == "presence_result") {
        // Single peer presence push: { "type": "presence", "peer_id": "...", "online": true }
        if (obj.contains("peer_id")) {
            const QString pid = obj.value("peer_id").toString();
            const bool online = obj.value("online").toBool();
            // Fix #14: track online state so cover traffic can target only
            // currently-connected contacts.  Filling an offline contact's
            // mailbox with cover not only wastes their quota but also lets
            // the relay distinguish cover (goes to offline peers too) from
            // real traffic (almost never offline peers).
            if (online) m_onlinePeers.insert(pid);
            else        m_onlinePeers.remove(pid);
            emit presenceChanged(pid, online);
            return;
        }

        // Batch presence result: { "type": "presence_result", "peers": { "id": true, ... } }
        if (obj.contains("peers")) {
            const QJsonObject peers = obj.value("peers").toObject();
            for (auto it = peers.begin(); it != peers.end(); ++it) {
                const bool online = it.value().toBool();
                if (online) m_onlinePeers.insert(it.key());
                else        m_onlinePeers.remove(it.key());
                emit presenceChanged(it.key(), online);
            }
            return;
        }
    }

    if (type == "pong") {
        // Keepalive response — nothing to do
        return;
    }
}

// ── Sending envelopes ────────────────────────────────────────────────────────
//
// Sends are always anonymous HTTP POST to /v1/send — no authentication,
// no sender identity. The relay reads the recipient from envelope bytes 1-32.

void RelayClient::sendEnvelope(const QByteArray& sealedEnvelope)
{
    // DAITA: if cover traffic is active, send 1-2 cover envelopes BEFORE the real
    // one so the real message isn't always the first after idle. An open-source
    // attacker reading this code still can't tell which envelope is real — they're
    // all version 0x01, same size, to real contacts, random ciphertext.
    if (m_coverIntervalSec > 0 && m_burstRemaining <= 0 && isConnected()) {
        const int precover = 1 + QRandomGenerator::global()->bounded(2); // 1-2
        for (int i = 0; i < precover; i++)
            sendCoverEnvelope();
    }
    onRealActivity();

    // Pick which relay to send through (round-robin if multi-relay configured)
    const QUrl relay = pickSendRelay();

    auto retryCb = [this, sealedEnvelope](const IHttpClient::Response& r) {
        if (r.error.isEmpty()) return;  // success

        // Permanent failure — don't retry
        if (r.status == 413) {
            emit status("Envelope too large for relay — rejected.");
            return;
        }

        // Transient failure — queue for retry
        if (m_retryQueue.size() < kMaxRetryQueue)
            m_retryQueue.append({ sealedEnvelope, 0 });
        if (!m_retryTimer.isActive())
            scheduleRetry();

        if (r.status != 429)
            emit status(QString("relay send error: %1 — will retry").arg(r.error));
    };

    // Route: multi-hop sends through an intermediate relay, single-hop sends direct
    if (m_multiHop && m_sendRelays.size() >= 2) {
        // Pick two different relays: send to first, forward to second (which delivers)
        const QUrl via = pickSendRelay();
        QUrl to = pickSendRelay();
        if (to == via) to = m_relayUrl; // fallback to main relay if pool is small
        forwardEnvelope(via, to, sealedEnvelope, std::move(retryCb));
    } else {
        postEnvelope(relay, sealedEnvelope, std::move(retryCb));
    }
}

// ── Presence ─────────────────────────────────────────────────────────────────

void RelayClient::subscribePresence(const QStringList& peerIds)
{
    // DAITA: update known peers for realistic cover traffic targeting
    m_knownPeers = peerIds;

    if (!isConnected()) return;

    QJsonArray ids;
    for (const QString& id : peerIds)
        if (!id.trimmed().isEmpty()) ids.append(id.trimmed());

    QJsonObject msg;
    msg["type"]     = "presence_subscribe";
    msg["peer_ids"] = ids;

    m_ws.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));
}

void RelayClient::queryPresence(const QStringList& peerIds)
{
    if (!isConnected()) return;

    QJsonArray ids;
    for (const QString& id : peerIds)
        if (!id.trimmed().isEmpty()) ids.append(id.trimmed());

    QJsonObject msg;
    msg["type"]     = "presence_query";
    msg["peer_ids"] = ids;

    m_ws.sendTextMessage(
        QString::fromUtf8(QJsonDocument(msg).toJson(QJsonDocument::Compact)));
}

// ── Retry queue ──────────────────────────────────────────────────────────────

void RelayClient::scheduleRetry()
{
    if (m_retryQueue.isEmpty()) return;
    const int attempt = m_retryQueue.first().retryCount;
    const int delaySec = qMin(1 << attempt, 60);
    m_retryTimer.start(delaySec * 1000);
}

void RelayClient::processRetryQueue()
{
    if (m_retryQueue.isEmpty() || m_retryInFlight) return;
    m_retryInFlight = true;

    PendingEnvelope pe = m_retryQueue.takeFirst();

    QUrl sendUrl = m_relayUrl;
    sendUrl.setPath("/v1/send");

    m_http.post(sendUrl, pe.data, {}, [this, pe](const IHttpClient::Response& r) {
        m_retryInFlight = false;

        if (r.error.isEmpty()) {
            if (!m_retryQueue.isEmpty()) scheduleRetry();
            return;
        }

        if (r.status == 413) {
            if (!m_retryQueue.isEmpty()) scheduleRetry();
            return;
        }

        PendingEnvelope next = pe;
        next.retryCount++;
        if (next.retryCount < kMaxRetries) {
            m_retryQueue.prepend(next);
            scheduleRetry();
        } else {
            emit status("Gave up delivering envelope after max retries.");
        }
    });
}

// ── DAITA: client-side traffic analysis defense ─────────────────────────────

void RelayClient::setJitterRange(int minMs, int maxMs)
{
    m_jitterMinMs = qMax(0, minMs);
    m_jitterMaxMs = qMax(m_jitterMinMs, maxMs);
}

void RelayClient::setCoverTrafficInterval(int seconds)
{
    m_coverIntervalSec = qMax(0, seconds);
    m_coverTimer.stop();
    m_burstRemaining = 0;
    if (m_coverIntervalSec > 0 && isConnected())
        scheduleCoverTimer();
}

void RelayClient::onRealActivity()
{
    // A real message was sent or received — blend it into the cover pattern.
    //
    // If we're mid-burst: the real message counts as one of the burst messages.
    // Reset the timer so the next cover envelope comes at natural conversation pace.
    //
    // If we're idle: real activity starts a new burst — the user is now "in a
    // conversation" and cover traffic should match that pace.
    if (m_coverIntervalSec <= 0) return;

    if (m_burstRemaining > 0) {
        // Real message counts as part of the burst
        --m_burstRemaining;
    } else {
        // Real activity during idle → start a new burst (2-4 more cover messages)
        m_burstRemaining = 2 + QRandomGenerator::global()->bounded(3);
    }

    // Reset timer — next cover envelope comes at burst pace (1-5s)
    m_coverTimer.stop();
    scheduleCoverTimer();
}

void RelayClient::scheduleCoverTimer()
{
    if (m_coverIntervalSec <= 0) return;

    // Bursty timing: mimic real conversation patterns.
    // Real chats = rapid burst of 3-8 messages (1-5s apart), then idle (1-5 min).
    if (m_burstRemaining > 0) {
        // Mid-burst: next envelope in 1-5 seconds (mimics typing + sending)
        const int delayMs = 1000 + QRandomGenerator::global()->bounded(4000);
        m_coverTimer.start(delayMs);
    } else {
        // Between bursts: idle for 1-5x the configured interval
        const int idleMs = m_coverIntervalSec * 1000
            + QRandomGenerator::global()->bounded(m_coverIntervalSec * 4000);
        m_coverTimer.start(idleMs);
        // Next timer fire starts a new burst of 2-6 envelopes
        m_burstRemaining = 2 + QRandomGenerator::global()->bounded(5);
    }
}

void RelayClient::setKnownPeers(const QStringList& peerIds)
{
    m_knownPeers = peerIds;
}

void RelayClient::sendCoverEnvelope()
{
    if (!isConnected()) return;

    // Cover traffic must be INDISTINGUISHABLE from real envelopes on the wire.
    //
    // Fix #13: previously cover envelopes were formatted as
    //   [0x01][recipientPub(32)][random bytes...]
    // but real envelopes use the wrap-for-relay framing:
    //   [0x01][recipientPub(32)][innerLen(4 BE)][sealedBytes][random pad]
    // where innerLen is a BE uint32 well below 256 KiB (typically 200–60000).
    // Bytes 33–36 of a real envelope are a small number; cover envelopes had
    // uniform random there. A relay operator could filter cover with 3 lines
    // of Python. This rewrite generates cover using the SAME wrap-for-relay
    // path and a plausible inner sealed body.
    //
    // Fix #14: recipients are chosen from currently-online contacts only.
    // Sending cover to offline peers filled their mailbox quotas AND let the
    // relay distinguish cover (often goes to offline peers) from real
    // traffic (rarely goes to offline peers, since you'd ratchet-encrypt
    // for them only after an accept). Online-only targets match real
    // messaging distribution. The relay already learns our online-contact
    // set via the presence subscription, so this doesn't leak new info.

    // Build the candidate list: known peers ∩ currently online.
    QStringList onlinePool;
    onlinePool.reserve(m_knownPeers.size());
    for (const QString& pid : m_knownPeers) {
        if (m_onlinePeers.contains(pid)) onlinePool << pid;
    }
    if (onlinePool.isEmpty()) {
        // No online contacts — skip this tick rather than send cover to an
        // offline peer.  Reschedule so timing remains bursty.
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }
    const QString& peerId = onlinePool[int(randombytes_uniform(quint32(onlinePool.size())))];
    QByteArray recipientPub = CryptoEngine::fromBase64Url(peerId);
    if (recipientPub.size() != 32) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }

    // Synthesize a sealed-envelope body that passes structural checks:
    //   [version 0x02 or 0x03][ephPub(32)][optional kemCt(1088)][AEAD blob]
    // Then wrap it with the routing layer so bytes 33–36 carry a plausible
    // innerLen BE uint32.
    const bool hybrid = randombytes_uniform(10) == 0;  // ~10% hybrid
    const int baseMin = hybrid
        ? (1 + 32 + 1088 + 24 + 16)   // version + ephPub + kemCt + nonce + tag
        : (1 + 32 + 24 + 16);         // version + ephPub + nonce + tag

    // Size distribution: mostly short message envelopes (200–1500B after min),
    // occasionally file-chunk-sized to match real file-transfer traffic.
    int innerSize;
    if (randombytes_uniform(20) == 0) {
        // ~5% file-chunk-sized (240KB chunks produce ~245KB sealed envelopes)
        innerSize = baseMin + 244000 + int(randombytes_uniform(8000));
    } else {
        innerSize = baseMin + int(randombytes_uniform(1400));
    }
    QByteArray body(innerSize, Qt::Uninitialized);
    randombytes_buf(reinterpret_cast<unsigned char*>(body.data()),
                    static_cast<size_t>(innerSize));
    body[0] = hybrid ? char(0x03) : char(0x02);  // version byte matches real sealed v2

    QByteArray env = SealedEnvelope::wrapForRelay(recipientPub, body);
    if (env.isEmpty()) {
        if (m_burstRemaining > 0) --m_burstRemaining;
        scheduleCoverTimer();
        return;
    }

    // Route cover traffic the same way as real traffic — indistinguishable.
    auto noop = [](const IHttpClient::Response&) {};
    if (m_multiHop && m_sendRelays.size() >= 2) {
        const QUrl via = pickSendRelay();
        QUrl to = pickSendRelay();
        if (to == via) to = m_relayUrl;
        forwardEnvelope(via, to, env, noop);
    } else {
        postEnvelope(pickSendRelay(), env, noop);
    }

    if (m_burstRemaining > 0) --m_burstRemaining;
    scheduleCoverTimer();
}

// ── Multi-relay routing ─────────────────────────────────────────────────────

void RelayClient::addSendRelay(const QUrl& url)
{
    if (!url.isEmpty() && !m_sendRelays.contains(url))
        m_sendRelays.append(url);
}

void RelayClient::setMultiHopEnabled(bool enabled)
{
    m_multiHop = enabled;
}

QUrl RelayClient::pickSendRelay()
{
    if (m_sendRelays.isEmpty()) return m_relayUrl;
    m_sendRelayIdx = (m_sendRelayIdx + 1) % m_sendRelays.size();
    return m_sendRelays[m_sendRelayIdx];
}

// Fix #9: honor the jitter range set by setPrivacyLevel.  Previously
// m_jitterMinMs/m_jitterMaxMs were stored but never read — every send went
// out the instant the caller invoked it, turning "Enhanced/Maximum privacy"
// timing protection into a no-op that a relay operator could trivially
// correlate to user typing.
//
// Random jitter ∈ [m_jitterMinMs, m_jitterMaxMs] is scheduled per-send via
// QTimer::singleShot.  When both bounds are 0 (Privacy Level 0), we skip
// the timer and post synchronously to preserve ordering invariants.
int RelayClient::pickJitterMs() const
{
    if (m_jitterMaxMs <= 0) return 0;
    const int span = m_jitterMaxMs - m_jitterMinMs;
    if (span <= 0) return m_jitterMinMs;
    // Fix #25: jitter is a timing-correlation defense; use a cryptographic
    // source so an observer who watches many samples can't build a
    // statistical predictor for the next delay.  randombytes_uniform is
    // unbiased and CSPRNG-backed from libsodium.
    return m_jitterMinMs + int(randombytes_uniform(quint32(span + 1)));
}

void RelayClient::postEnvelope(const QUrl& relayUrl, const QByteArray& envelope,
                                IHttpClient::Callback cb)
{
    QUrl sendUrl = relayUrl;
    sendUrl.setPath("/v1/send");

    const int jitterMs = pickJitterMs();
    if (jitterMs <= 0) {
        m_http.post(sendUrl, envelope, {}, std::move(cb));
        return;
    }

    QTimer::singleShot(jitterMs, this,
        [this, sendUrl, envelope, cb = std::move(cb)]() mutable {
            m_http.post(sendUrl, envelope, {}, std::move(cb));
        });
}

void RelayClient::forwardEnvelope(const QUrl& viaRelay, const QUrl& toRelay,
                                   const QByteArray& envelope,
                                   IHttpClient::Callback cb)
{
    // Fix #7: if we have the entry-hop's X25519 pubkey cached, wrap the
    // envelope as an onion layer.  The entry hop sees only
    //   (ephPub, opaque ciphertext with authenticated nextHopUrl inside)
    // and posts the inner blob to the next hop's /v1/send.  Crucially, the
    // entry hop does NOT learn the final recipient pubkey that sits inside
    // the inner wrap-for-relay header.  Only the exit hop does.
    const QString relayKey = viaRelay.toString(
        QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);
    const QByteArray viaPub = m_relayX25519Pubs.value(relayKey);

    if (viaPub.size() == 32) {
        // Target URL the entry hop forwards TO — the exit relay's /v1/send.
        QUrl exitUrl = toRelay;
        exitUrl.setPath("/v1/send");
        const QString nextHop = exitUrl.toString();

        const QByteArray onion = OnionWrap::wrap(viaPub, nextHop, envelope);
        if (!onion.isEmpty()) {
            QUrl fwdUrl = viaRelay;
            fwdUrl.setPath("/v1/forward-onion");

            const int jitterMs = pickJitterMs();
            if (jitterMs <= 0) {
                m_http.post(fwdUrl, onion, {}, std::move(cb));
            } else {
                QTimer::singleShot(jitterMs, this,
                    [this, fwdUrl, onion, cb = std::move(cb)]() mutable {
                        m_http.post(fwdUrl, onion, {}, std::move(cb));
                    });
            }
            return;
        }
        // wrap failed (shouldn't happen) — fall through to legacy path.
    }

    // Legacy path (no cached pubkey yet — entry hop sees final recipient).
    // Triggers refreshRelayInfo() so the next send upgrades to onion.
    QUrl fwdUrl = viaRelay;
    fwdUrl.setPath("/v1/forward");
    QMap<QString, QString> headers;
    headers["X-Forward-To"] = toRelay.host()
        + (toRelay.port() > 0 ? ":" + QString::number(toRelay.port()) : "");

    const int jitterMs = pickJitterMs();
    if (jitterMs <= 0) {
        m_http.post(fwdUrl, envelope, headers, std::move(cb));
    } else {
        QTimer::singleShot(jitterMs, this,
            [this, fwdUrl, envelope, headers, cb = std::move(cb)]() mutable {
                m_http.post(fwdUrl, envelope, headers, std::move(cb));
            });
    }
    // Async: fetch the pubkey so next send onions properly.
    const_cast<RelayClient*>(this)->refreshRelayInfo();
}

void RelayClient::refreshRelayInfo()
{
    // Fetch /v1/relay_info from every configured relay and cache the X25519
    // pubkey so forwardEnvelope() can use onion layering.  Idempotent — a
    // relay that already has a cached key is re-fetched (in case it rolled).
    auto fetchOne = [this](const QUrl& base) {
        QUrl infoUrl = base;
        infoUrl.setPath("/v1/relay_info");
        const QString cacheKey = base.toString(
            QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);
        m_http.get(infoUrl, {}, [this, cacheKey](const IHttpClient::Response& r) {
            if (!r.error.isEmpty() || r.status != 200) return;
            QJsonParseError pe{};
            const QJsonDocument doc = QJsonDocument::fromJson(r.body, &pe);
            if (pe.error != QJsonParseError::NoError) return;
            const QString pubB64u = doc.object().value("x25519_pub").toString();
            const QByteArray pub = CryptoEngine::fromBase64Url(pubB64u);
            if (pub.size() != 32) return;
            m_relayX25519Pubs[cacheKey] = pub;
#ifndef QT_NO_DEBUG_OUTPUT
            qDebug() << "[Relay] cached X25519 pub for onion routing:" << cacheKey;
#endif
        });
    };
    if (!m_relayUrl.isEmpty()) fetchOne(m_relayUrl);
    for (const QUrl& url : m_sendRelays) fetchOne(url);
}

void RelayClient::setPrivacyLevel(int level)
{
    switch (level) {
    case 0: // Standard: padding only (already always on)
        setJitterRange(0, 0);
        setCoverTrafficInterval(0);
        m_sendRelays.clear();
        setMultiHopEnabled(false);
        break;
    case 1: // Enhanced: + jitter + cover + multi-relay rotation
        setJitterRange(50, 300);
        setCoverTrafficInterval(30);
        setMultiHopEnabled(false);
        break;
    case 2: // Maximum: + multi-hop + high-frequency cover
        setJitterRange(100, 500);
        setCoverTrafficInterval(10);
        setMultiHopEnabled(true);
        break;
    }
}
