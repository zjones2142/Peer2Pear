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

    connect(&m_mbox,   &MailboxClient::status,        this, &ChatController::status);
    connect(&m_rvz,    &RendezvousClient::status,     this, &ChatController::status);
    connect(&m_direct, &DirectPeerLink::status,       this, &ChatController::status);

    // Both transport layers feed the same envelope handler.
    connect(&m_mbox,   &MailboxClient::envelopeReceived,   this, &ChatController::onEnvelope);
    connect(&m_direct, &DirectPeerLink::envelopeReceived,  this, &ChatController::onEnvelope);

    // Rendezvous lookup result wired here.
    connect(&m_rvz, &RendezvousClient::lookupResult, this, &ChatController::onLookupResult);

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

void ChatController::publishMyAddress(const QString& host, quint16 port)
{
    const quint16 actual = m_direct.startListening(port);
    if (actual == 0) {
        emit status("direct: could not start listener — falling back to mailbox only");
        return;
    }

    // TTL: 30 minutes. The app should call this periodically or on startup.
    const qint64 ttlMs = 30LL * 60 * 1000;
    m_rvz.publish(host, actual, ttlMs);
    emit status(QString("direct: published address %1:%2 to rendezvous").arg(host).arg(actual));
}

// Primary entry point called by ChatView.
// Strategy:
//   1. If we already know the peer's address → send direct.
//   2. Otherwise ask the rendezvous server (async) → onLookupResult.
//   3. If rendezvous says peer is offline → fall back to mailbox.
void ChatController::sendText(const QString& peerIdB64u, const QString& text)
{
    if (m_peerAddressCache.contains(peerIdB64u)) {
        const auto [host, port] = m_peerAddressCache[peerIdB64u];
        m_direct.sendDirect(host, port, buildEnvelope(peerIdB64u, text));
        return;
    }

    // Store intent, then fire async lookup.
    m_pendingPeer = peerIdB64u;
    m_pendingText = text;
    m_rvz.lookup(peerIdB64u);
}

void ChatController::onLookupResult(const QString& host, int port)
{
    if (host.isEmpty() || port <= 0) {
        // Peer not registered / offline — use mailbox as fallback.
        emit status("direct: peer not found in rendezvous, falling back to mailbox");
        sendTextViaMailbox(m_pendingPeer, m_pendingText);
        return;
    }

    const quint16 p = static_cast<quint16>(port);
    m_peerAddressCache[m_pendingPeer] = {host, p};
    m_direct.sendDirect(host, p, buildEnvelope(m_pendingPeer, m_pendingText));
}

void ChatController::sendTextViaMailbox(const QString& peerIdB64u, const QString& text)
{
    const qint64 ttlMs = 7LL * 24 * 60 * 60 * 1000; // 7 days
    m_mbox.enqueue(peerIdB64u, buildEnvelope(peerIdB64u, text), ttlMs);
}

// Shared envelope builder — produces the same binary format used by both paths.
QByteArray ChatController::buildEnvelope(const QString& peerIdB64u, const QString& text)
{
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
    if (key32.size() != 32) {
        emit status("crypto: cannot derive shared key (bad peer id?)");
        return {};
    }

    QJsonObject payload;
    payload["from"] = myIdB64u();
    payload["type"] = "text";
    payload["text"] = text;
    payload["ts"]   = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray ct  = m_crypto.aeadEncrypt(key32, pt);

    // Envelope format: "FROM:<b64u>\n" + ciphertext
    return QByteArray("FROM:") + myIdB64u().toUtf8() + "\n" + ct;
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
    const QByteArray ct     = body.mid(nl + 1);

    if (!header.startsWith("FROM:")) return;
    const QString fromId = QString::fromUtf8(header.mid(5)).trimmed();

    const QByteArray fromPub = CryptoEngine::fromBase64Url(fromId);
    const QByteArray key32   = m_crypto.deriveSharedKey32(fromPub);
    if (key32.size() != 32) return;

    const QByteArray pt = m_crypto.aeadDecrypt(key32, ct);
    if (pt.isEmpty()) return;

    const auto doc = QJsonDocument::fromJson(pt);
    if (!doc.isObject()) return;
    const auto o = doc.object();

    if (o.value("type").toString() == "text") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts  = tsSecs > 0
                                 ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime()
                                 : QDateTime::currentDateTime();

        emit messageReceived(fromId, o.value("text").toString(), ts);
    }
}
