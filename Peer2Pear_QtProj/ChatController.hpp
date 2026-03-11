#pragma once
#include <QObject>
#include <QTimer>
#include <QMap>
#include <QPair>
#include <QQueue>

#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include "RendezvousClient.hpp"
#include "HolePuncher.hpp"
#include "StunClient.hpp"

class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(QObject* parent=nullptr);

    void setPassphrase(const QString& pass);
    void setServerBaseUrl(const QUrl& base);

    QString myIdB64u() const;

    // Primary send method: tries direct TCP first, falls back to mailbox.
    void sendText(const QString& peerIdB64u, const QString& text);

    // Send encrypted text to peer via mailbox
    void sendTextViaMailbox(const QString& peerIdB64u, const QString& text);//for offline fallback

    void discoverAndPublish();
    // Start periodic mailbox fetch
    void startPolling(int intervalMs = 2000);
    void stopPolling();

    // How the app knows which keys are yours
    void setSelfKeys(const QStringList& keys);

signals:
    void status(const QString& s);
    void messageReceived(const QString& fromPeerIdB64u, const QString& text, const QDateTime& timestamp);

private slots:
    void pollOnce();
    void onEnvelope(const QByteArray& body, const QString& envId);

    void onLookupResult(const QString& host, int port);
    void onPublicAddressDiscovered(const QString& host, quint16 port);
    void onStunFailed(const QString& reason);
    void onPunchSuccess(const QString& punchId, const QString& host, quint16 port);
    void onPunchFailed(const QString& punchId);

private:
    QByteArray buildEnvelope(const QString& peerIdB64u, const QString& text);

    CryptoEngine m_crypto;
    RendezvousClient m_rvz;
    MailboxClient m_mbox;
    HolePuncher m_punch;
    StunClient m_stun;

    QTimer m_pollTimer;
    QStringList m_selfKeys;

    QMap<QString, QPair<QString, quint16>> m_peerAddressCache;

    QQueue<QPair<QString, QString>> m_pendingQueue;

    static constexpr int kMaxRvzRetries = 2;
    int m_rvzLookupRetries = 0;

    QMap<QString, QPair<QString, QString>> m_pendingPunches;
    QString  m_myPublicHost;
    quint16  m_myPublicPort = 0;
};
