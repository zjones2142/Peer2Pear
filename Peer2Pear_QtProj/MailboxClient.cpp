#include "MailboxClient.hpp"
#include "CryptoEngine.hpp"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDateTime>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>

MailboxClient::MailboxClient(CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto) {}

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

    auto* rep = m_nam.post(req, envelopeBytes);
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        if (rep->error() != QNetworkReply::NoError)
            emit status(QString("mbox enqueue error: %1").arg(rep->errorString()));
        // No need to log success noise for every chunk
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
// Server returns:  { "envelopes": [ {"env_id": "...", "payload_b64": "..."}, ... ] }
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
                const QByteArray     raw = rep->readAll();
                rep->deleteLater();

                const QJsonDocument  doc = QJsonDocument::fromJson(raw);
                if (!doc.isObject()) return;

                const QJsonArray envelopes = doc.object().value("envelopes").toArray();
                for (const QJsonValue &v : envelopes) {
                    const QJsonObject entry  = v.toObject();
                    const QString     envId  = entry.value("env_id").toString();
                    const QString     b64u   = entry.value("payload_b64").toString();

                    // Decode base64url payload
                    QByteArray padded = b64u.toUtf8();
                    // Add padding if missing
                    while (padded.size() % 4) padded.append('=');
                    // Replace URL-safe chars back to standard base64 for Qt's decoder
                    padded.replace('-', '+');
                    padded.replace('_', '/');
                    const QByteArray body = QByteArray::fromBase64(padded);

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
