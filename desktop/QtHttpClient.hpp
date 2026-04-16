#pragma once

#include "IHttpClient.hpp"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>

/*
 * QtHttpClient — IHttpClient implementation using QNetworkAccessManager.
 *
 * Thin wrapper that translates QNetworkReply signals into IHttpClient
 * callbacks. This is the desktop platform adapter for HTTP sends.
 */
class QtHttpClient : public QObject, public IHttpClient {
    Q_OBJECT
public:
    explicit QtHttpClient(QObject* parent = nullptr)
        : QObject(parent) {}

    void post(const QUrl& url,
              const QByteArray& body,
              const QMap<QString, QString>& headers,
              Callback cb) override
    {
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
        for (auto it = headers.cbegin(); it != headers.cend(); ++it)
            req.setRawHeader(it.key().toUtf8(), it.value().toUtf8());

        auto* reply = m_nam.post(req, body);
        connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
            Response resp;
            resp.status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            resp.body = reply->readAll();
            if (reply->error() != QNetworkReply::NoError)
                resp.error = reply->errorString();
            reply->deleteLater();
            if (cb) cb(resp);
        });
    }

    void get(const QUrl& url,
             const QMap<QString, QString>& headers,
             Callback cb) override
    {
        QNetworkRequest req(url);
        for (auto it = headers.cbegin(); it != headers.cend(); ++it)
            req.setRawHeader(it.key().toUtf8(), it.value().toUtf8());

        auto* reply = m_nam.get(req);
        connect(reply, &QNetworkReply::finished, this, [reply, cb]() {
            Response resp;
            resp.status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            resp.body = reply->readAll();
            if (reply->error() != QNetworkReply::NoError)
                resp.error = reply->errorString();
            reply->deleteLater();
            if (cb) cb(resp);
        });
    }

private:
    QNetworkAccessManager m_nam;
};
