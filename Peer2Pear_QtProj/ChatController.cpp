#include "ChatController.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QTimeZone>

ChatController::ChatController(QObject* parent)
    : QObject(parent),
    m_rvz(&m_crypto, this),
    m_mbox(&m_crypto, this)
{
    // IMPORTANT: Do not call ensureIdentity() here.
    // Identity is unlocked/created after setPassphrase() is called.

    connect(&m_mbox, &MailboxClient::status, this, &ChatController::status);
    connect(&m_rvz,  &RendezvousClient::status, this, &ChatController::status);
    connect(&m_mbox, &MailboxClient::envelopeReceived, this, &ChatController::onEnvelope);
    connect(&m_pollTimer, &QTimer::timeout, this, &ChatController::pollOnce);
}

void ChatController::setPassphrase(const QString& pass)
{
    // CryptoEngine::ensureIdentity() should be strict and may throw.
    m_crypto.setPassphrase(pass);
    m_crypto.ensureIdentity();
}

void ChatController::setServerBaseUrl(const QUrl& base) {
    m_rvz.setBaseUrl(base);
    m_mbox.setBaseUrl(base);
}

QString ChatController::myIdB64u() const {
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
}

void ChatController::sendSignalingMessage(const QString& peerIdB64u, const QJsonObject& payload) {
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray key32 = m_crypto.deriveSharedKey32(peerPub);
    if (key32.size() != 32) return;

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray ct = m_crypto.aeadEncrypt(key32, pt);
    const QByteArray env = QByteArray("FROM:") + myIdB64u().toUtf8() + "\n" + ct;

    m_mbox.enqueue(peerIdB64u, env, 7LL * 24 * 60 * 60 * 1000);
}

void ChatController::initiateP2PConnection(const QString& peerIdB64u) {
    if (m_p2pConnections.contains(peerIdB64u)) return;

    NiceConnection* conn = new NiceConnection(this);
    m_p2pConnections[peerIdB64u] = conn;

    connect(conn, &NiceConnection::localSdpReady, this, [this, peerIdB64u](const QString& sdp) {
        QJsonObject payload;
        payload["type"] = "ice_offer";
        payload["from"] = myIdB64u();
        payload["sdp"] = sdp;
        sendSignalingMessage(peerIdB64u, payload);
    });

    connect(conn, &NiceConnection::stateChanged, this, [this, peerIdB64u](int state) {
        if (state == NICE_COMPONENT_STATE_READY) {
            emit status("P2P Direct Connection Ready with " + peerIdB64u);
        } else if (state == NICE_COMPONENT_STATE_FAILED) {
            emit status("P2P Connection Failed for " + peerIdB64u);
        }
    });

    connect(conn, &NiceConnection::dataReceived, this, [this, peerIdB64u](const QByteArray& ct) {
        onP2PDataReceived(peerIdB64u, ct);
    });

    emit status("Initiating direct P2P connection to " + peerIdB64u);
    conn->initIce(true); // Offer side is controlling
}

void ChatController::sendText(const QString& peerIdB64u, const QString& text) {
    QJsonObject payload;
    payload["from"] = myIdB64u();
    payload["type"] = "text";
    payload["text"] = text;
    payload["ts"]   = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray ct = m_crypto.aeadEncrypt(m_crypto.deriveSharedKey32(peerPub), pt);

    if (m_p2pConnections.contains(peerIdB64u) && m_p2pConnections[peerIdB64u]->isReady()) {
        // Send directly over UDP/ICE
        m_p2pConnections[peerIdB64u]->sendData(ct);
    } else {
        // Fallback to Mailbox and trigger a connection attempt for next time
        sendSignalingMessage(peerIdB64u, payload);
        initiateP2PConnection(peerIdB64u);
    }
}

void ChatController::onP2PDataReceived(const QString& peerIdB64u, const QByteArray& ct) {
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray pt = m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), ct);
    if (pt.isEmpty()) return;

    const auto o = QJsonDocument::fromJson(pt).object();
    if (o.value("type").toString() == "text") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsSecs > 0 ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime() : QDateTime::currentDateTime();
        emit messageReceived(peerIdB64u, o.value("text").toString(), ts);
    }
}

void ChatController::startPolling(int intervalMs) {
    if (!m_pollTimer.isActive()) m_pollTimer.start(intervalMs);
}

void ChatController::stopPolling()
{
    m_pollTimer.stop();
}

void ChatController::pollOnce() {
    m_mbox.fetch(myIdB64u());
    for (const QString &key : m_selfKeys) {
        if (!key.trimmed().isEmpty() && key.trimmed() != myIdB64u())
            m_mbox.fetch(key.trimmed());
    }
}

void ChatController::setSelfKeys(const QStringList& keys) {
    m_selfKeys = keys;
}

void ChatController::onEnvelope(const QByteArray& body, const QString& envId) {
    Q_UNUSED(envId);

    const int nl = body.indexOf('\n');
    if (nl <= 5) return;

    const QByteArray header = body.left(nl);
    if (!header.startsWith("FROM:")) return;
    const QString fromId = QString::fromUtf8(header.mid(5)).trimmed();

    const QByteArray ct = body.mid(nl + 1);
    const QByteArray peerPub = CryptoEngine::fromBase64Url(fromId);
    const QByteArray pt = m_crypto.aeadDecrypt(m_crypto.deriveSharedKey32(peerPub), ct);

    if (pt.isEmpty()) return;

    const auto o = QJsonDocument::fromJson(pt).object();
    const QString type = o.value("type").toString();

    if (type == "text") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsSecs > 0 ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime() : QDateTime::currentDateTime();
        emit messageReceived(fromId, o.value("text").toString(), ts);

    } else if (type == "ice_offer") {
        if (!m_p2pConnections.contains(fromId)) {
            NiceConnection* conn = new NiceConnection(this);
            m_p2pConnections[fromId] = conn;

            connect(conn, &NiceConnection::localSdpReady, this, [this, fromId](const QString& sdp) {
                QJsonObject payload;
                payload["type"] = "ice_answer";
                payload["from"] = myIdB64u();
                payload["sdp"] = sdp;
                sendSignalingMessage(fromId, payload);
            });

            connect(conn, &NiceConnection::stateChanged, this, [this, fromId](int state) {
                if (state == NICE_COMPONENT_STATE_READY) {
                    emit status("P2P Direct Connection Ready with " + fromId);
                }
            });

            connect(conn, &NiceConnection::dataReceived, this, [this, fromId](const QByteArray& data) {
                onP2PDataReceived(fromId, data);
            });

            conn->initIce(false); // Answer side is controlled
        }
        m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());

    } else if (type == "ice_answer") {
        if (m_p2pConnections.contains(fromId)) {
            m_p2pConnections[fromId]->setRemoteSdp(o.value("sdp").toString());
        }
    }
}
