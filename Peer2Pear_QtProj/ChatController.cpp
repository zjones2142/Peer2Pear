#include "ChatController.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QTimeZone>
#include <QUuid>

ChatController::ChatController(QObject* parent)
    : QObject(parent),
    m_rvz(&m_crypto, this),
    m_mbox(&m_crypto, this)
{
    // IMPORTANT: Do not call ensureIdentity() here.
    // Identity is unlocked/created after setPassphrase() is called.

    connect(&m_mbox,   &MailboxClient::status,        this, &ChatController::status);
    connect(&m_rvz,    &RendezvousClient::status,     this, &ChatController::status);
    connect(&m_punch, &HolePuncher::status,           this, &ChatController::status);

    // Both transport layers feed the same envelope handler.
    connect(&m_mbox,   &MailboxClient::envelopeReceived,   this, &ChatController::onEnvelope);
    connect(&m_punch, &HolePuncher::envelopeReceived,   this, &ChatController::onEnvelope);

    connect(&m_rvz,   &RendezvousClient::lookupResult,  this, &ChatController::onLookupResult);
    connect(&m_punch, &HolePuncher::punchSuccess,       this, &ChatController::onPunchSuccess);
    connect(&m_punch, &HolePuncher::punchFailed,        this, &ChatController::onPunchFailed);
    connect(&m_stun,  &StunClient::publicAddressDiscovered,
            this, &ChatController::onPublicAddressDiscovered);
    connect(&m_stun,  &StunClient::failed, this, &ChatController::onStunFailed);

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

void ChatController::discoverAndPublish()
{
    // Step 1: bind the UDP punch socket on any free port
    const quint16 boundPort = m_punch.bind(0);
    if (boundPort == 0) {
        emit status("punch: failed to bind — P2P unavailable, mailbox only");
        return;
    }
    // Step 2: ask a STUN server what our public IP:port looks like
    // The SAME port must be used for STUN and for hole-punching —
    // that's what makes the NAT mapping stable.
    m_stun.discover("stun.l.google.com", 19302);
}

void ChatController::onPublicAddressDiscovered(const QString& host, quint16 port)
{
    m_myPublicHost = host;
    m_myPublicPort = port;
    emit status(QString("stun: public address is %1:%2").arg(host).arg(port));

    // Step 3: advertise to the rendezvous server so peers can find us
    const qint64 ttlMs = 30LL * 60 * 1000; // 30 min
    m_rvz.publish(host, port, ttlMs);
}

void ChatController::onStunFailed(const QString& reason)
{
    emit status(QString("stun failed: %1 — P2P will not work across NAT").arg(reason));
    // The app still functions via the mailbox fallback.
}

void ChatController::sendText(const QString& peerIdB64u, const QString& text)
{
    // 1. Cache hit — we already know where this peer is
    if (m_peerAddressCache.contains(peerIdB64u)) {
        const auto [host, port] = m_peerAddressCache[peerIdB64u];
        m_punch.sendTo(host, port, buildEnvelope(peerIdB64u, text));
        return;
    }

    // 2. Ask the rendezvous server (async) — result in onLookupResult
    m_pendingPeer = peerIdB64u;
    m_pendingText = text;
    m_rvz.lookup(peerIdB64u);
}

void ChatController::onLookupResult(const QString& host, int port)
{
    if (host.isEmpty() || port <= 0) {
        emit status("direct: peer offline, using mailbox fallback");
        sendTextViaMailbox(m_pendingPeer, m_pendingText);
        return;
    }

    const quint16 p = static_cast<quint16>(port);

    // 3. We have the peer's public address — punch through both NATs
    const QString punchId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_pendingPunches[punchId] = {m_pendingPeer, m_pendingText};
    m_punch.punchAndSend(punchId, host, p, buildEnvelope(m_pendingPeer, m_pendingText));
}

void ChatController::onPunchSuccess(const QString& punchId,
                                    const QString& host, quint16 port)
{
    if (!m_pendingPunches.contains(punchId)) return;
    const auto [peerId, _] = m_pendingPunches.take(punchId);

    // Cache the address for future sends
    m_peerAddressCache[peerId] = {host, port};
    emit status(QString("punch: hole open to %1:%2 — P2P active").arg(host).arg(port));
}

void ChatController::onPunchFailed(const QString& punchId)
{
    if (!m_pendingPunches.contains(punchId)) return;
    const auto [peerId, text] = m_pendingPunches.take(punchId);

    emit status("punch: hole-punch failed, falling back to mailbox");
    sendTextViaMailbox(peerId, text);
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

void ChatController::onEnvelope(const QByteArray& body, const QString& envId)
{
    Q_UNUSED(envId);

    const int nl = body.indexOf('\n');
    if (nl <= 5) return;

    const QByteArray header = body.left(nl);
    const QByteArray ct     = body.mid(nl + 1);
    if (!header.startsWith("FROM:")) return;

    const QString fromId     = QString::fromUtf8(header.mid(5)).trimmed();
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
