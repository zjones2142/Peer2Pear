#pragma once
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QByteArray>
#include <QString>
#include <QMap>

// DirectPeerLink
// - Listens for incoming TCP connections from peers
// - Sends raw envelopes directly to a peer's IP:port
// - Emits envelopeReceived(...) with the same signature as MailboxClient,
//   so ChatController::onEnvelope can handle both without changes.

class DirectPeerLink : public QObject
{
    Q_OBJECT
public:
    explicit DirectPeerLink(QObject* parent = nullptr);

    // Start listening on the given port (0 = let OS pick one).
    // Returns the actual port bound, or 0 on failure.
    quint16 startListening(quint16 port = 0);

    // Stop listening and close all open connections.
    void stopListening();

    // Returns the port currently listening on (0 if not listening).
    quint16 listeningPort() const;

    // Send a raw envelope (already encrypted, same format as mailbox)
    // directly to host:port.  Fires-and-forgets — result is reported via
    // status() signal.
    void sendDirect(const QString& host, quint16 port, const QByteArray& envelope);

signals:
    // Fired for every complete envelope received from a direct connection.
    // envId is synthesised locally (not from a server).
    void envelopeReceived(const QByteArray& body, const QString& envId);

    // Informational / error messages.
    void status(const QString& s);

private slots:
    void onNewConnection();
    void onClientReadyRead();
    void onClientDisconnected();

private:
    QTcpServer  m_server;

    // Each incoming socket accumulates data here until a full envelope
    // (prefixed with a 4-byte big-endian length) has arrived.
    QMap<QTcpSocket*, QByteArray> m_incoming;
};