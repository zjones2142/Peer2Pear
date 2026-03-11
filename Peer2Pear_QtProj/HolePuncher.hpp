#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QTimer>
#include <QHostAddress>
#include <QMap>

// HolePuncher
// Uses a single shared UDP socket for both sending and receiving.
// Hole-punching: sends several probe packets to open the NAT hole,
// then uses the same socket for the actual data exchange.
//
// Wire protocol (same framing as DirectPeerLink TCP):
//   [4-byte big-endian length][payload]
// Control probe packets use length=0 (no payload) so they're ignored
// by the envelope handler.

class HolePuncher : public QObject
{
    Q_OBJECT
public:
    explicit HolePuncher(QObject* parent = nullptr);

    // Bind on the given port (same port used for STUN — critical for NAT mapping).
    // Returns actual port, or 0 on failure.
    quint16 bind(quint16 port = 0);

    quint16 boundPort() const;

    // Start hole-punching to peerHost:peerPort, then send envelope once open.
    // punchId lets the caller correlate the punchSuccess/punchFailed signals.
    void punchAndSend(const QString& punchId,
                      const QString& peerHost, quint16 peerPort,
                      const QByteArray& envelope);

    // Send directly (use only when hole is already known open).
    void sendTo(const QString& host, quint16 port, const QByteArray& envelope);

signals:
    void envelopeReceived(const QByteArray& body, const QString& envId);
    void punchSuccess(const QString& punchId, const QString& host, quint16 port);
    void punchFailed(const QString& punchId);
    void status(const QString& s);

private slots:
    void onReadyRead();

private:
    struct PunchAttempt {
        QString    punchId;
        QHostAddress host;
        quint16    port    = 0;
        QByteArray envelope;
        int        probes  = 0;
        QTimer*    timer   = nullptr;
    };

    void sendProbe(const QHostAddress& host, quint16 port);

    QUdpSocket m_socket;
    QMap<QString, PunchAttempt*> m_attempts; // punchId → attempt
    QMap<QString, QByteArray>    m_rxBufs;   // "host:port" → partial buffer
};