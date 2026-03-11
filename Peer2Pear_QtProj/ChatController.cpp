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
// Public
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

void ChatController::sendTextViaMailbox(const QString& peerIdB64u, const QString& text) {
    // Derive shared key
    const QByteArray peerPub = CryptoEngine::fromBase64Url(peerIdB64u);
    const QByteArray key32 = m_crypto.deriveSharedKey32(peerPub);
    if (key32.size() != 32) {
        emit status("crypto: cannot derive shared key (bad peer id?)");
        return;
    }

    // Ciphertext is JSON payload encrypted
    QJsonObject payload;
    payload["from"] = myIdB64u();
    payload["type"] = "text";
    payload["text"] = text;
    payload["ts"]   = QDateTime::currentSecsSinceEpoch();

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray ct = m_crypto.aeadEncrypt(key32, pt);

    // Envelope format (MVP): "FROM:<b64u>\n" + ct
    // This leaks sender id to mailbox; sealed sender can replace this later.
    const QByteArray env = QByteArray("FROM:") + myIdB64u().toUtf8() + "\n" + ct;

    const qint64 ttlMs = 7LL * 24 * 60 * 60 * 1000; // 7 days
    m_mbox.enqueue(peerIdB64u, env, ttlMs);
}

void ChatController::startPolling(int intervalMs) {
    if (!m_pollTimer.isActive()) m_pollTimer.start(intervalMs);
}

void ChatController::stopPolling()
{
    m_pollTimer.stop();
}

void ChatController::setSelfKeys(const QStringList& keys) {
    m_selfKeys = keys;
}

void ChatController::sendGroupMessageViaMailbox(const QString& groupId,
                                                const QString& groupName,
                                                const QStringList& memberPeerIds,
                                                const QString& text)
{
    const QString myId = myIdB64u();
    const qint64 ts = QDateTime::currentSecsSinceEpoch();

    for (const QString& peerId : memberPeerIds) {
        if (peerId.trimmed().isEmpty()) continue;
        if (peerId.trimmed() == myId) continue; // don't send to yourself

        const QByteArray peerPub = CryptoEngine::fromBase64Url(peerId);
        const QByteArray key32   = m_crypto.deriveSharedKey32(peerPub);
        if (key32.size() != 32) continue;

        QJsonObject payload;
        payload["from"]      = myId;
        payload["type"]      = "group_msg";
        payload["groupId"]   = groupId;
        payload["groupName"] = groupName;
        payload["text"]      = text;
        payload["ts"]        = ts;

        const QByteArray pt  = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        const QByteArray ct  = m_crypto.aeadEncrypt(key32, pt);
        const QByteArray env = QByteArray("FROM:") + myId.toUtf8() + "\n" + ct;

        m_mbox.enqueue(peerId, env, 7LL * 24 * 60 * 60 * 1000);
    }
}

// Private
void ChatController::pollOnce() {
    m_mbox.fetch(myIdB64u());
    for (const QString &key : m_selfKeys) {
        if (!key.trimmed().isEmpty() && key.trimmed() != myIdB64u())
            m_mbox.fetch(key.trimmed());
    }
}

void ChatController::onEnvelope(const QByteArray& body, const QString& envId) {
    Q_UNUSED(envId);

    // Parse "FROM:<id>\n"
    const int nl = body.indexOf('\n');
    if (nl <= 5) return;

    const QByteArray header = body.left(nl);
    const QByteArray ct = body.mid(nl + 1);

    if (!header.startsWith("FROM:")) return;
    const QString fromId = QString::fromUtf8(header.mid(5)).trimmed();

    const QByteArray fromPub = CryptoEngine::fromBase64Url(fromId);
    const QByteArray key32 = m_crypto.deriveSharedKey32(fromPub);
    if (key32.size() != 32) return;

    const QByteArray pt = m_crypto.aeadDecrypt(key32, ct);
    if (pt.isEmpty()) return;

    const auto doc = QJsonDocument::fromJson(pt);
    if (!doc.isObject()) return;
    const auto o = doc.object();

    if (o.value("type").toString() == "text") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsSecs > 0
                                 ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime()
                                 : QDateTime::currentDateTime();

        emit messageReceived(fromId, o.value("text").toString(), ts);
    }
    else if (o.value("type").toString() == "group_msg") {
        const qint64 tsSecs = o.value("ts").toVariant().toLongLong();
        const QDateTime ts = tsSecs > 0
                                 ? QDateTime::fromSecsSinceEpoch(tsSecs, QTimeZone::utc()).toLocalTime()
                                 : QDateTime::currentDateTime();
        emit groupMessageReceived(
            fromId,
            o.value("groupId").toString(),
            o.value("groupName").toString(),
            o.value("text").toString(),
            ts
            );
    }
}
