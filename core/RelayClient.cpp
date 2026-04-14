#include "RelayClient.hpp"
#include "CryptoEngine.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDebug>

RelayClient::RelayClient(CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto)
{
    // WebSocket signals
    connect(&m_ws, &QWebSocket::connected, this, &RelayClient::onWsConnected);
    connect(&m_ws, &QWebSocket::disconnected, this, &RelayClient::onWsDisconnected);
    connect(&m_ws, &QWebSocket::binaryMessageReceived, this, &RelayClient::onWsBinaryMessage);
    connect(&m_ws, &QWebSocket::textMessageReceived, this, &RelayClient::onWsTextMessage);

    // Reconnect timer
    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout, this, &RelayClient::connectToRelay);

    // Retry timer for failed sends
    m_retryTimer.setSingleShot(true);
    connect(&m_retryTimer, &QTimer::timeout, this, &RelayClient::processRetryQueue);
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
    return m_ws.state() == QAbstractSocket::ConnectedState && m_authenticated;
}

// ── WebSocket receive channel ────────────────────────────────────────────────

void RelayClient::connectToRelay()
{
    if (m_ws.state() != QAbstractSocket::UnconnectedState) return;

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
        emit connected();
        return;
    }

    if (type == "presence" || type == "presence_result") {
        // Single peer presence push: { "type": "presence", "peer_id": "...", "online": true }
        if (obj.contains("peer_id")) {
            emit presenceChanged(
                obj.value("peer_id").toString(),
                obj.value("online").toBool());
            return;
        }

        // Batch presence result: { "type": "presence_result", "peers": { "id": true, ... } }
        if (obj.contains("peers")) {
            const QJsonObject peers = obj.value("peers").toObject();
            for (auto it = peers.begin(); it != peers.end(); ++it) {
                emit presenceChanged(it.key(), it.value().toBool());
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
    QUrl sendUrl = m_relayUrl;
    sendUrl.setPath("/v1/send");

    QNetworkRequest req(sendUrl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    auto* reply = m_nam.post(req, sealedEnvelope);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, sealedEnvelope]() {
        const int http = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (reply->error() == QNetworkReply::NoError) {
            reply->deleteLater();
            return;
        }

        // Permanent failure — don't retry
        if (http == 413) {
            emit status("Envelope too large for relay — rejected.");
            reply->deleteLater();
            return;
        }

        // Transient failure — queue for retry
        m_retryQueue.append({ sealedEnvelope, 0 });
        if (!m_retryTimer.isActive())
            scheduleRetry();

        if (http != 429)
            emit status(QString("relay send error: %1 — will retry").arg(reply->errorString()));

        reply->deleteLater();
    });
}

void RelayClient::sendEnvelopeTo(const QString& recipientIdB64u,
                                  const QByteArray& envelopeBytes)
{
    // Legacy path: the envelope doesn't have the recipient in its binary header,
    // so we fall back to the old /mbox/enqueue endpoint with X-To header.
    QUrl sendUrl = m_relayUrl;
    sendUrl.setPath("/mbox/enqueue");

    QNetworkRequest req(sendUrl);
    req.setRawHeader("X-To", recipientIdB64u.toUtf8());
    req.setRawHeader("X-TtlMs", QByteArray::number(7LL * 24 * 60 * 60 * 1000));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    auto* reply = m_nam.post(req, envelopeBytes);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, envelopeBytes]() {
        if (reply->error() == QNetworkReply::NoError) {
            reply->deleteLater();
            return;
        }

        const int http = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (http == 413) {
            emit status("Envelope too large — rejected.");
            reply->deleteLater();
            return;
        }

        m_retryQueue.append({ envelopeBytes, 0 });
        if (!m_retryTimer.isActive())
            scheduleRetry();

        reply->deleteLater();
    });
}

// ── Presence ─────────────────────────────────────────────────────────────────

void RelayClient::subscribePresence(const QStringList& peerIds)
{
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

    QNetworkRequest req(sendUrl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    auto* reply = m_nam.post(req, pe.data);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, pe]() {
        m_retryInFlight = false;
        const int http = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (reply->error() == QNetworkReply::NoError) {
            reply->deleteLater();
            if (!m_retryQueue.isEmpty()) scheduleRetry();
            return;
        }

        if (http == 413) {
            reply->deleteLater();
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

        reply->deleteLater();
    });
}
