#include "ChatController.hpp"
#include <QJsonDocument>
#include <QJsonObject>

ChatController::ChatController(QObject* parent)
    : QObject(parent),
    m_rvz(&m_crypto, this),
    m_mbox(&m_crypto, this) {

    m_crypto.ensureIdentity();

    connect(&m_mbox, &MailboxClient::status, this, &ChatController::status);
    connect(&m_rvz, &RendezvousClient::status, this, &ChatController::status);
    connect(&m_mbox, &MailboxClient::envelopeReceived, this, &ChatController::onEnvelope);
    connect(&m_pollTimer, &QTimer::timeout, this, &ChatController::pollOnce);
}

void ChatController::setServerBaseUrl(const QUrl& base) {
    m_rvz.setBaseUrl(base);
    m_mbox.setBaseUrl(base);
}

QString ChatController::myIdB64u() const {
    return CryptoEngine::toBase64Url(m_crypto.identityPub());
}

void ChatController::startPolling(int intervalMs) {
    if (!m_pollTimer.isActive()) m_pollTimer.start(intervalMs);
}

void ChatController::pollOnce() {
    m_mbox.fetch(myIdB64u());
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

    const QByteArray pt = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    const QByteArray ct = m_crypto.aeadEncrypt(key32, pt);

    // Envelope format (MVP): "FROM:<b64u>\n" + ct
    // This leaks sender id to mailbox; sealed sender can replace this later.
    const QByteArray env = QByteArray("FROM:") + myIdB64u().toUtf8() + "\n" + ct;

    const qint64 ttlMs = 7LL * 24 * 60 * 60 * 1000; // 7 days
    m_mbox.enqueue(peerIdB64u, env, ttlMs);
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
        emit messageReceived(fromId, o.value("text").toString());
    }
}
