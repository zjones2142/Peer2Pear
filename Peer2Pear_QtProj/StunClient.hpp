#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QTimer>

// StunClient
// Can either use its own internal socket (for simple IP discovery)
// OR operate on an externally-provided socket (required for hole-punching
// so that STUN and hole-punch traffic share the same NAT mapping/port).

class StunClient : public QObject
{
    Q_OBJECT
public:
    explicit StunClient(QObject* parent = nullptr);

    // Use internal socket — simple IP discovery only, NOT for hole-punching.
    void discover(const QString& stunHost = "stun.l.google.com",
                  quint16 stunPort        = 19302);

    // Use an external, already-bound socket — REQUIRED for hole-punching.
    // The socket must already be bound before calling this.
    void discoverOnSocket(QUdpSocket* sharedSocket,
                          const QString& stunHost = "stun.l.google.com",
                          quint16 stunPort        = 19302);

    // Called by HolePuncher when it receives a datagram that might be a STUN reply.
    // Returns true if the datagram was consumed as a STUN response.
    bool tryHandleDatagram(const QByteArray& buf);

signals:
    void publicAddressDiscovered(const QString& publicHost, quint16 publicPort);
    void failed(const QString& reason);

private slots:
    void onReadyRead(); // used only with internal socket
    void onTimeout();

private:
    void sendRequest(QUdpSocket* sock, const QHostAddress& addr, quint16 port);
    bool parseResponse(const QByteArray& buf);

    QUdpSocket  m_ownSocket;   // used when no shared socket is given
    QUdpSocket* m_socket = nullptr; // points to whichever socket is active
    QTimer      m_timeout;
    QByteArray  m_txId;
};
