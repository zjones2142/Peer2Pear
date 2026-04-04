#include "MailboxClient.hpp"
#include "CryptoEngine.hpp"
#include <QDebug>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDateTime>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>

MailboxClient::MailboxClient(CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto)
{
    m_retryTimer.setSingleShot(true);
    connect(&m_retryTimer, &QTimer::timeout, this, &MailboxClient::processRetryQueue);
}

void MailboxClient::setBaseUrl(const QUrl& u) { m_base = u; }

// ── enqueue ───────────────────────────────────────────────────────────────────

void MailboxClient::enqueue(const QString& toIdB64u,
                            const QByteArray& envelopeBytes,
                            qint64 ttlMs)
{
    QNetworkRequest req(m_base.resolved(QUrl("/mbox/enqueue")));
    req.setRawHeader("X-To",    toIdB64u.toUtf8());
    req.setRawHeader("X-TtlMs", QByteArray::number(ttlMs));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    qDebug() << "[Mailbox] Enqueue to" << toIdB64u.left(8) + "..."
             << "| size:" << envelopeBytes.size() << "B | ttl:" << ttlMs << "ms";

    auto* rep = m_nam.post(req, envelopeBytes);
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, toIdB64u, envelopeBytes, ttlMs]()
    {
        const int http = rep->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (rep->error() == QNetworkReply::NoError) {
            qDebug() << "[Mailbox] Enqueue OK to" << toIdB64u.left(8) + "...";
            rep->deleteLater();
            return;   // success — nothing to do
        }
        qWarning() << "[Mailbox] Enqueue failed to" << toIdB64u.left(8) + "..."
                   << "| HTTP" << http << "|" << rep->errorString();

        // ── Permanent failures — don't retry ────────────────────────────────
        if (http == 413) {
            emit status("Envelope too large for server — chunk rejected.");
            rep->deleteLater();
            return;
        }
        if (http == 429) {
            emit status(QString("Recipient mailbox full — some chunks may be delayed."));
            // Still retry — recipient may fetch and free space
        }

        // ── Transient failure — queue for retry ─────────────────────────────
        m_retryQueue.append({ toIdB64u, envelopeBytes, ttlMs, 0 });
        if (!m_retryTimer.isActive())
            scheduleRetry();

        if (http != 429)   // 429 already logged above
            emit status(QString("mbox enqueue error: %1 — will retry").arg(rep->errorString()));

        rep->deleteLater();
    });
}

// ── Retry queue with exponential backoff ─────────────────────────────────────

void MailboxClient::scheduleRetry()
{
    if (m_retryQueue.isEmpty()) return;
    // Backoff: 2^retry seconds, capped at 60 s
    const int attempt = m_retryQueue.first().retryCount;
    const int delaySec = qMin(1 << attempt, 60);
    m_retryTimer.start(delaySec * 1000);
}

void MailboxClient::processRetryQueue()
{
    if (m_retryQueue.isEmpty() || m_retryInFlight) return;
    m_retryInFlight = true;

    PendingEnvelope pe = m_retryQueue.takeFirst();

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/enqueue")));
    req.setRawHeader("X-To",    pe.toIdB64u.toUtf8());
    req.setRawHeader("X-TtlMs", QByteArray::number(pe.ttlMs));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    auto* rep = m_nam.post(req, pe.envelopeBytes);
    connect(rep, &QNetworkReply::finished, this, [this, rep, pe]()
    {
        m_retryInFlight = false;
        const int http = rep->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (rep->error() == QNetworkReply::NoError) {
            // Success — continue draining the queue
            rep->deleteLater();
            if (!m_retryQueue.isEmpty()) scheduleRetry();
            return;
        }

        // Permanent: 413 — give up
        if (http == 413) {
            emit status("Retry failed: envelope too large (413). Giving up.");
            rep->deleteLater();
            if (!m_retryQueue.isEmpty()) scheduleRetry();
            return;
        }

        // Still failing — re-queue if under max retries
        PendingEnvelope next = pe;
        next.retryCount++;
        if (next.retryCount < kMaxRetries) {
            m_retryQueue.prepend(next);
            scheduleRetry();
        } else {
            emit status(QString("Gave up delivering chunk to %1 after %2 retries.")
                            .arg(pe.toIdB64u.left(8) + "…")
                            .arg(kMaxRetries));
        }

        rep->deleteLater();
    });
}

// ── fetch (single — with drain loop) ─────────────────────────────────────────
//
// The server's /mbox/fetch pops and returns ONE envelope per call.
// After receiving an envelope we immediately schedule another fetch via
// QTimer::singleShot(0, ...) so the full queue drains as fast as the network
// allows, without waiting for the 2-second poll timer to tick again.
//
// The m_fetchInFlight guard ensures we never stack multiple concurrent
// requests for the same identity — important when a deep file-chunk queue
// triggers many rapid completions.

void MailboxClient::fetch(const QString& myIdB64u)
{
    // If a request for this identity is already in-flight, skip — the
    // completion handler will schedule the next one automatically.
    if (m_fetchInFlight.value(myIdB64u, false)) return;
    m_fetchInFlight[myIdB64u] = true;

    const qint64   ts    = QDateTime::currentMSecsSinceEpoch();
    const quint64  nonce = QRandomGenerator::global()->generate64();
    const QString  msg   = QString("MBX1|%1|%2|%3|fetch|")
                            .arg(myIdB64u).arg(ts).arg(nonce);
    const QString  sig   = m_crypto->signB64u(msg.toUtf8());

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/fetch")));
    req.setRawHeader("X-To",    myIdB64u.toUtf8());
    req.setRawHeader("X-Ts",    QByteArray::number(ts));
    req.setRawHeader("X-Nonce", QByteArray::number(nonce));
    req.setRawHeader("X-Sig",   sig.toUtf8());

    auto* rep = m_nam.get(req);
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, myIdB64u]()
            {
                m_fetchInFlight[myIdB64u] = false; // release the guard

                const int http = rep->attribute(
                                        QNetworkRequest::HttpStatusCodeAttribute).toInt();

                if (rep->error() != QNetworkReply::NoError) {
                    emit status(QString("mbox fetch error: %1").arg(rep->errorString()));
                    rep->deleteLater();
                    return;
                }

                if (http == 204) {
                    // Queue empty — nothing to do; poll timer will try again later
                    rep->deleteLater();
                    return;
                }

                // ── Envelope received ─────────────────────────────────────────────────
                const QByteArray body  = rep->readAll();
                const QString    envId = QString::fromUtf8(rep->rawHeader("X-EnvId"));
                rep->deleteLater();

                qDebug() << "[Mailbox] Fetched envelope | size:" << body.size() << "B | envId:" << envId.left(8);
                emit envelopeReceived(body, envId);

                // Drain: immediately fetch the next envelope without waiting for the
                // poll timer.  QTimer::singleShot(0) defers until the current event-
                // loop iteration finishes (so envelopeReceived slots run first), then
                // fires the next fetch synchronously.
                QTimer::singleShot(0, this, [this, myIdB64u]() {
                    fetch(myIdB64u);
                });
            });
}

// ── fetchAll (batch — uses /mbox/fetch_all) ───────────────────────────────────
//
// Retrieves all pending envelopes in one signed HTTP request.
// Server returns a JSON array: [ {"env_id": "...", "payload_b64": "..."}, ... ]
// Falls back to single fetch() if the server returns 404 or 405 (not yet deployed).

void MailboxClient::fetchAll(const QString& myIdB64u)
{
    const qint64   ts    = QDateTime::currentMSecsSinceEpoch();
    const quint64  nonce = QRandomGenerator::global()->generate64();
    const QString  msg   = QString("MBX1|%1|%2|%3|fetch_all|")
                            .arg(myIdB64u).arg(ts).arg(nonce);
    const QString  sig   = m_crypto->signB64u(msg.toUtf8());

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/fetch_all")));
    req.setRawHeader("X-To",    myIdB64u.toUtf8());
    req.setRawHeader("X-Ts",    QByteArray::number(ts));
    req.setRawHeader("X-Nonce", QByteArray::number(nonce));
    req.setRawHeader("X-Sig",   sig.toUtf8());

    auto* rep = m_nam.get(req);
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, myIdB64u]()
            {
                const int http = rep->attribute(
                                        QNetworkRequest::HttpStatusCodeAttribute).toInt();

                if (rep->error() != QNetworkReply::NoError) {
                    // Network error — fall back to single fetch
                    emit status(QString("mbox fetch_all error: %1 — falling back")
                                    .arg(rep->errorString()));
                    rep->deleteLater();
                    fetch(myIdB64u);
                    return;
                }

                // Server doesn't support fetch_all yet — fall back gracefully
                if (http == 404 || http == 405) {
                    rep->deleteLater();
                    fetch(myIdB64u);
                    return;
                }

                if (http == 204) {
                    rep->deleteLater();
                    return;
                }

                // ── Parse batch response ──────────────────────────────────────────────
                // Server returns a JSON array directly:
                //   [ {"env_id": "...", "payload_b64": "..."}, ... ]
                const QByteArray    raw = rep->readAll();
                rep->deleteLater();

                const QJsonDocument doc = QJsonDocument::fromJson(raw);

                // If the response is not an array, fall back to single-fetch mode
                if (!doc.isArray()) {
                    emit status("fetchAll: unexpected response format, falling back");
                    fetch(myIdB64u);
                    return;
                }

                const QJsonArray arr = doc.array();
                for (const QJsonValue &v : arr) {
                    const QJsonObject entry = v.toObject();
                    const QString     envId = entry.value("env_id").toString();
                    const QString     b64   = entry.value("payload_b64").toString();

                    // G8 fix: use CryptoEngine helper instead of manual conversion
                    const QByteArray body = CryptoEngine::fromBase64Url(b64);

                    if (!body.isEmpty())
                        emit envelopeReceived(body, envId);
                }
            });
}

// ── ack ───────────────────────────────────────────────────────────────────────
// The server already pops on fetch; ack is a no-op kept for forward
// compatibility.  We keep the implementation so callers compile, but
// ChatController no longer calls it.

void MailboxClient::ack(const QString& myIdB64u, const QString& envId)
{
    const qint64   ts    = QDateTime::currentMSecsSinceEpoch();
    const quint64  nonce = QRandomGenerator::global()->generate64();
    const QString  msg   = QString("MBX1|%1|%2|%3|ack|%4")
                            .arg(myIdB64u).arg(ts).arg(nonce).arg(envId);
    const QString  sig   = m_crypto->signB64u(msg.toUtf8());

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/ack")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("X-To",    myIdB64u.toUtf8());
    req.setRawHeader("X-Ts",    QByteArray::number(ts));
    req.setRawHeader("X-Nonce", QByteArray::number(nonce));
    req.setRawHeader("X-Sig",   sig.toUtf8());

    QJsonObject j;
    j["env_id"] = envId;
    auto* rep = m_nam.post(req, QJsonDocument(j).toJson(QJsonDocument::Compact));
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        if (rep->error() != QNetworkReply::NoError)
            emit status(QString("mbox ack error: %1").arg(rep->errorString()));
        rep->deleteLater();
    });
}
