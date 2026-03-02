#include "MailboxClient.hpp"
#include "CryptoEngine.hpp"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDateTime>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <QJsonObject>

MailboxClient::MailboxClient(CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto) {}

void MailboxClient::setBaseUrl(const QUrl& u) { m_base = u; }

void MailboxClient::enqueue(const QString& toIdB64u, const QByteArray& envelopeBytes, qint64 ttlMs) {
    QNetworkRequest req(m_base.resolved(QUrl("/mbox/enqueue")));
    req.setRawHeader("X-To", toIdB64u.toUtf8());
    req.setRawHeader("X-TtlMs", QByteArray::number(ttlMs));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");

    auto* rep = m_nam.post(req, envelopeBytes);
    connect(rep, &QNetworkReply::finished, this, [this, rep](){
        if (rep->error() != QNetworkReply::NoError) {
            emit status(QString("mbox enqueue error: %1").arg(rep->errorString()));
        } else {
            emit status(QString("mbox enqueue ok env=%1").arg(QString::fromUtf8(rep->readAll())));
        }
        rep->deleteLater();
    });
}

void MailboxClient::fetch(const QString& myIdB64u) {
    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    const quint64 nonce = QRandomGenerator::global()->generate64();

    const QString msg = QString("MBX1|%1|%2|%3|fetch|")
                            .arg(myIdB64u)
                            .arg(ts)
                            .arg(nonce);

    const QString sig = m_crypto->signB64u(msg.toUtf8());

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/fetch")));
    req.setRawHeader("X-To", myIdB64u.toUtf8());
    req.setRawHeader("X-Ts", QByteArray::number(ts));
    req.setRawHeader("X-Nonce", QByteArray::number(nonce));
    req.setRawHeader("X-Sig", sig.toUtf8());

    auto* rep = m_nam.get(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep](){
        const int http = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (rep->error() != QNetworkReply::NoError) {
            emit status(QString("mbox fetch error: %1").arg(rep->errorString()));
        } else if (http == 204) {
            // no mail
        } else {
            const QByteArray body = rep->readAll();
            const QString envId = QString::fromUtf8(rep->rawHeader("X-EnvId"));
            emit envelopeReceived(body, envId);
        }
        rep->deleteLater();
    });
}

void MailboxClient::ack(const QString& myIdB64u, const QString& envId) {
    const qint64 ts = QDateTime::currentMSecsSinceEpoch();
    const quint64 nonce = QRandomGenerator::global()->generate64();

    const QString msg = QString("MBX1|%1|%2|%3|ack|%4")
                            .arg(myIdB64u)
                            .arg(ts)
                            .arg(nonce)
                            .arg(envId);

    const QString sig = m_crypto->signB64u(msg.toUtf8());

    QNetworkRequest req(m_base.resolved(QUrl("/mbox/ack")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("X-To", myIdB64u.toUtf8());
    req.setRawHeader("X-Ts", QByteArray::number(ts));
    req.setRawHeader("X-Nonce", QByteArray::number(nonce));
    req.setRawHeader("X-Sig", sig.toUtf8());

    QJsonObject j;
    j["env_id"] = envId;
    auto* rep = m_nam.post(req, QJsonDocument(j).toJson(QJsonDocument::Compact));
    connect(rep, &QNetworkReply::finished, this, [this, rep](){
        if (rep->error() != QNetworkReply::NoError)
            emit status(QString("mbox ack error: %1").arg(rep->errorString()));
        rep->deleteLater();
    });
}
