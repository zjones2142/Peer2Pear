#include "RendezvousClient.hpp"
#include "CryptoEngine.hpp"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>

RendezvousClient::RendezvousClient(CryptoEngine* crypto, QObject* parent)
    : QObject(parent), m_crypto(crypto) {}

void RendezvousClient::setBaseUrl(const QUrl& u) { m_base = u; }

void RendezvousClient::publish(const QString& host, int port, qint64 expiresMs) {
    const QString id = CryptoEngine::toBase64Url(m_crypto->identityPub());
    const QString msg = QString("RVZ1|%1|%2|%3|%4").arg(id, host).arg(port).arg(expiresMs);
    const QString sig = m_crypto->signB64u(msg.toUtf8());

    QJsonObject j;
    j["id"] = id;
    j["host"] = host;
    j["port"] = port;
    j["expires_ms"] = expiresMs;
    j["sig"] = sig;

    QNetworkRequest req(m_base.resolved(QUrl("/rvz/publish")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    auto* rep = m_nam.post(req, QJsonDocument(j).toJson(QJsonDocument::Compact));
    connect(rep, &QNetworkReply::finished, this, [this, rep](){
        if (rep->error() != QNetworkReply::NoError)
            emit status(QString("rvz publish error: %1").arg(rep->errorString()));
        rep->deleteLater();
    });
}

void RendezvousClient::lookup(const QString& peerIdB64u) {
    QJsonObject j;
    j["id"] = peerIdB64u;

    QNetworkRequest req(m_base.resolved(QUrl("/rvz/lookup")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    auto* rep = m_nam.post(req, QJsonDocument(j).toJson(QJsonDocument::Compact));
    connect(rep, &QNetworkReply::finished, this, [this, rep](){
        if (rep->error() != QNetworkReply::NoError) {
            emit status(QString("rvz lookup error: %1").arg(rep->errorString()));
        } else {
            const auto doc = QJsonDocument::fromJson(rep->readAll());
            const auto o = doc.object();
            emit lookupResult(o["host"].toString(), o["port"].toInt());
        }
        rep->deleteLater();
    });
}
