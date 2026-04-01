#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QMap>
#include <QVector>
#include <QTimer>

class CryptoEngine;

class MailboxClient : public QObject {
    Q_OBJECT
public:
    explicit MailboxClient(CryptoEngine* crypto, QObject* parent = nullptr);

    void setBaseUrl(const QUrl& u);

    void enqueue(const QString& toIdB64u, const QByteArray& envelopeBytes, qint64 ttlMs);

    // Fetch one envelope.  On a non-204 response the envelope is emitted AND
    // another fetch is immediately scheduled so the queue drains without
    // waiting for the next poll-timer tick.  Only one request per identity
    // is in-flight at a time to avoid stacking requests.
    void fetch(const QString& myIdB64u);

    // Fetch ALL pending envelopes in one authenticated request via
    // /mbox/fetch_all.  Each envelope in the JSON array is emitted in order.
    // Falls back to single fetch() if the server returns 404/405.
    void fetchAll(const QString& myIdB64u);

    void ack(const QString& myIdB64u, const QString& envId);

signals:
    void status(const QString& s);
    void envelopeReceived(const QByteArray& body, const QString& envId);

private:
    CryptoEngine*         m_crypto = nullptr;
    QNetworkAccessManager m_nam;
    QUrl                  m_base;

    // One in-flight fetch per identity — prevents request stacking on a
    // deep queue.  fetch() is re-issued only after the previous one completes.
    QMap<QString, bool>   m_fetchInFlight;

    // ── Retry queue for failed enqueues ──────────────────────────────────────
    static constexpr int kMaxRetries = 5;

    struct PendingEnvelope {
        QString    toIdB64u;
        QByteArray envelopeBytes;
        qint64     ttlMs;
        int        retryCount = 0;
    };

    QVector<PendingEnvelope> m_retryQueue;
    QTimer                   m_retryTimer;
    bool                     m_retryInFlight = false;

    void scheduleRetry();
    void processRetryQueue();
};
