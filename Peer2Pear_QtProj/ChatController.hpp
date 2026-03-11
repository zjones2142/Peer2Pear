#pragma once
#include <QObject>
#include <QTimer>
#include <QMap>
#include <QPair>

#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include "RendezvousClient.hpp"
#include "DirectPeerLink.hpp"

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

    void publishMyAddress(const QString& host, quint16 port);

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

private:
    QByteArray buildEnvelope(const QString& peerIdB64u, const QString& text);

    CryptoEngine m_crypto;
    RendezvousClient m_rvz;
    MailboxClient m_mbox;
    DirectPeerLink m_direct;

    QTimer m_pollTimer;
    QStringList m_selfKeys;

    QMap<QString, QPair<QString, quint16>> m_peerAddressCache;

    // Carry the intent through the async rendezvous lookup.
    QString m_pendingPeer;
    QString m_pendingText;
};
