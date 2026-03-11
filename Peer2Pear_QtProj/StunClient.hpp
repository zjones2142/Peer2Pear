#pragma once
#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QTimer>

// StunClient
// Sends a STUN Binding Request to a STUN server and emits
// publicAddressDiscovered(host, port) with our external IP:port.
// Uses the simple STUN RFC 5389 binding request — no authentication.

class StunClient : public QObject
{
    Q_OBJECT
public:
    explicit StunClient(QObject* parent = nullptr);

    // Query the given STUN server. Result fires publicAddressDiscovered().
    void discover(const QString& stunHost = "stun.l.google.com",
                  quint16 stunPort       = 19302);

signals:
    void publicAddressDiscovered(const QString& publicHost, quint16 publicPort);
    void failed(const QString& reason);

private slots:
    void onReadyRead();
    void onTimeout();

private:
    QUdpSocket m_socket;
    QTimer     m_timeout;
    QByteArray m_txId; // 12-byte transaction ID
};