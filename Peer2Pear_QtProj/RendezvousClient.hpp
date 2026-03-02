#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QUrl>

class CryptoEngine;

class RendezvousClient : public QObject {
    Q_OBJECT
public:
    explicit RendezvousClient(CryptoEngine* crypto, QObject* parent=nullptr);
    void setBaseUrl(const QUrl& u);

    void publish(const QString& host, int port, qint64 expiresMs);
    void lookup(const QString& peerIdB64u);

signals:
    void status(const QString& s);
    void lookupResult(const QString& host, int port);

private:
    CryptoEngine* m_crypto = nullptr;
    QNetworkAccessManager m_nam;
    QUrl m_base;
};
