#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QUrl>

class CryptoEngine;

class MailboxClient : public QObject {
    Q_OBJECT
public:
    explicit MailboxClient(CryptoEngine* crypto, QObject* parent=nullptr);

    void setBaseUrl(const QUrl& u);

    void enqueue(const QString& toIdB64u, const QByteArray& envelopeBytes, qint64 ttlMs);
    void fetch(const QString& myIdB64u);
    void ack(const QString& myIdB64u, const QString& envId);

signals:
    void status(const QString& s);
    void envelopeReceived(const QByteArray& body, const QString& envId);

private:
    CryptoEngine* m_crypto = nullptr;
    QNetworkAccessManager m_nam;
    QUrl m_base;
};
