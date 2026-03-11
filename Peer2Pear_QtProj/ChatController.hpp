#pragma once
#include <QObject>
#include <QTimer>

#include "CryptoEngine.hpp"
#include "MailboxClient.hpp"
#include "RendezvousClient.hpp"

class ChatController : public QObject {
    Q_OBJECT
public:
    explicit ChatController(QObject* parent=nullptr);

    void setPassphrase(const QString& pass);        // NEW
    void setServerBaseUrl(const QUrl& base);

    QString myIdB64u() const;

    // Send encrypted text to peer via mailbox
    void sendTextViaMailbox(const QString& peerIdB64u, const QString& text);

    // Start periodic mailbox fetch
    void startPolling(int intervalMs = 2000);
    void stopPolling();

    // How the app knows which keys are yours
    void setSelfKeys(const QStringList& keys);

    // Send messages in groupchats
    void sendGroupMessageViaMailbox(const QString& groupId,
                                    const QString& groupName,
                                    const QStringList& memberPeerIds,
                                    const QString& text);

signals:
    void status(const QString& s);
    void messageReceived(const QString& fromPeerIdB64u, const QString& text, const QDateTime& timestamp);
    // Signals for groupchats
    void groupMessageReceived(const QString& fromPeerIdB64u,
                              const QString& groupId,
                              const QString& groupName,
                              const QStringList& memberKeys,
                              const QString& text,
                              const QDateTime& ts);

private slots:
    void pollOnce();
    void onEnvelope(const QByteArray& body, const QString& envId);

private:
    CryptoEngine m_crypto;
    RendezvousClient m_rvz;
    MailboxClient m_mbox;

    QTimer m_pollTimer;
    QStringList m_selfKeys;
};
