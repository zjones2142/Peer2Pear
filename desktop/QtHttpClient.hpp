#pragma once

#include "IHttpClient.hpp"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QString>
#include <QByteArray>

/*
 * QtHttpClient — IHttpClient implementation using QNetworkAccessManager.
 *
 * Thin wrapper that translates QNetworkReply signals into std-typed
 * IHttpClient callbacks.
 */
class QtHttpClient : public QObject, public IHttpClient {
    Q_OBJECT
public:
    explicit QtHttpClient(QObject* parent = nullptr)
        : QObject(parent) {}

    void post(const std::string& url,
              const Bytes& body,
              const Headers& headers,
              Callback cb) override
    {
        QNetworkRequest req((QUrl(QString::fromStdString(url))));
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
        for (const auto& [k, v] : headers)
            req.setRawHeader(QByteArray::fromStdString(k), QByteArray::fromStdString(v));

        const QByteArray qBody(reinterpret_cast<const char*>(body.data()),
                               static_cast<int>(body.size()));
        auto* reply = m_nam.post(req, qBody);
        connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
            Response resp;
            resp.status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray b = reply->readAll();
            resp.body.assign(reinterpret_cast<const uint8_t*>(b.constData()),
                             reinterpret_cast<const uint8_t*>(b.constData()) + b.size());
            if (reply->error() != QNetworkReply::NoError)
                resp.error = reply->errorString().toStdString();
            reply->deleteLater();
            if (cb) cb(resp);
        });
    }

    void get(const std::string& url,
             const Headers& headers,
             Callback cb) override
    {
        QNetworkRequest req((QUrl(QString::fromStdString(url))));
        for (const auto& [k, v] : headers)
            req.setRawHeader(QByteArray::fromStdString(k), QByteArray::fromStdString(v));

        auto* reply = m_nam.get(req);
        connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
            Response resp;
            resp.status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray b = reply->readAll();
            resp.body.assign(reinterpret_cast<const uint8_t*>(b.constData()),
                             reinterpret_cast<const uint8_t*>(b.constData()) + b.size());
            if (reply->error() != QNetworkReply::NoError)
                resp.error = reply->errorString().toStdString();
            reply->deleteLater();
            if (cb) cb(resp);
        });
    }

private:
    QNetworkAccessManager m_nam;
};
