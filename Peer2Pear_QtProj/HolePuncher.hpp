#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QTimer>
#include <QHostAddress>
#include <QMap>

class StunClient;

class HolePuncher : public QObject
{
    Q_OBJECT
public:
    explicit HolePuncher(QObject* parent = nullptr);

    // Bind the shared UDP socket. Returns actual port or 0 on failure.
    // discoverAndPublish() in ChatController calls this first, then passes
    // the socket to StunClient so both share the same NAT mapping.
    quint16 bind(quint16 port = 0);
    quint16 boundPort() const;

    // Expose the socket so StunClient can share it.
    QUdpSocket* socket() { return &m_socket; }

    // Start hole-punch + send envelope once open.
    void punchAndSend(const QString& punchId,
                      const QString& peerHost, quint16 peerPort,
                      const QByteArray& envelope);

    // Send directly (hole already known open).
    void sendTo(const QString& host, quint16 port, const QByteArray& envelope);

    // Feed a datagram to StunClient if it looks like a STUN response.
    // Called from onReadyRead so STUN replies on the shared socket are handled.
    void setStunClient(StunClient* stun) { m_stun = stun; }

signals:
    void envelopeReceived(const QByteArray& body, const QString& envId);
    void punchSuccess(const QString& punchId, const QString& host, quint16 port);
    void punchFailed(const QString& punchId);
    void status(const QString& s);

private slots:
    void onReadyRead();

private:
    struct PunchAttempt {
        QString      punchId;
        QHostAddress host;
        quint16      port     = 0;
        QByteArray   envelope;
        int          probes   = 0;
        QTimer*      probeTimer   = nullptr;
        QTimer*      timeoutTimer = nullptr;
    };

    void sendProbe(const QHostAddress& host, quint16 port);
    void cleanupAttempt(const QString& punchId);
    // Normalize to IPv4 string for consistent comparison
    static QString normalizeAddress(const QHostAddress& addr);

    QUdpSocket  m_socket;
    StunClient* m_stun = nullptr;

    QMap<QString, PunchAttempt*> m_attempts;
    QMap<QString, QByteArray>    m_rxBufs;
};
