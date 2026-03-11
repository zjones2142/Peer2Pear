#include "StunClient.hpp"
#include <QHostInfo>
#include <QDebug>
#include <QRandomGenerator>

// Minimal STUN Binding Request (RFC 5389)
// Header: 20 bytes
//   [2] Message Type  = 0x0001 (Binding Request)
//   [2] Message Length = 0x0000 (no attributes)
//   [4] Magic Cookie  = 0x2112A442
//   [12] Transaction ID (random)

static QByteArray buildBindingRequest(QByteArray& txIdOut)
{
    txIdOut.resize(12);
    for (int i = 0; i < 12; ++i)
        txIdOut[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));

    QByteArray msg(20, '\0');
    // Message Type: Binding Request
    msg[0] = 0x00; msg[1] = 0x01;
    // Message Length: 0
    msg[2] = 0x00; msg[3] = 0x00;
    // Magic Cookie
    msg[4] = 0x21; msg[5] = 0x12; msg[6] = 0xA4; msg[7] = 0x42;
    // Transaction ID
    msg.replace(8, 12, txIdOut);
    return msg;
}

StunClient::StunClient(QObject* parent) : QObject(parent)
{
    connect(&m_socket, &QUdpSocket::readyRead, this, &StunClient::onReadyRead);
    m_timeout.setSingleShot(true);
    connect(&m_timeout, &QTimer::timeout, this, &StunClient::onTimeout);
}

void StunClient::discover(const QString& stunHost, quint16 stunPort)
{
    m_socket.bind(QHostAddress::Any, 0);

    // Resolve hostname then send
    QHostInfo::lookupHost(stunHost, this, [this, stunPort](const QHostInfo& info) {
        if (info.addresses().isEmpty()) {
            emit failed("STUN: DNS lookup failed");
            return;
        }
        const QByteArray req = buildBindingRequest(m_txId);
        m_socket.writeDatagram(req, info.addresses().first(), stunPort);
        m_timeout.start(5000); // 5 second timeout
    });
}

void StunClient::onReadyRead()
{
    QByteArray buf;
    QHostAddress sender;
    quint16 senderPort;

    buf.resize(512);
    qint64 n = m_socket.readDatagram(buf.data(), buf.size(), &sender, &senderPort);
    if (n < 20) return;
    buf.resize(static_cast<int>(n));

    // Verify magic cookie
    if ((quint8)buf[4] != 0x21 || (quint8)buf[5] != 0x12 ||
        (quint8)buf[6] != 0xA4 || (quint8)buf[7] != 0x42)
        return;

    // Verify transaction ID
    if (buf.mid(8, 12) != m_txId) return;

    m_timeout.stop();

    // Parse attributes to find XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    int offset = 20;
    while (offset + 4 <= buf.size()) {
        const quint16 attrType   = ((quint8)buf[offset] << 8) | (quint8)buf[offset+1];
        const quint16 attrLen    = ((quint8)buf[offset+2] << 8) | (quint8)buf[offset+3];
        offset += 4;

        if (attrType == 0x0020 && attrLen >= 8) { // XOR-MAPPED-ADDRESS (IPv4)
            // Family byte at offset+1 should be 0x01 for IPv4
            const quint16 xPort = (((quint8)buf[offset+2] << 8) | (quint8)buf[offset+3]) ^ 0x2112;
            const quint32 xIp   =
                (((quint8)buf[offset+4] << 24) | ((quint8)buf[offset+5] << 16) |
                 ((quint8)buf[offset+6] << 8)  |  (quint8)buf[offset+7])
                ^ 0x2112A442u;

            const QString ip = QString("%1.%2.%3.%4")
                .arg((xIp >> 24) & 0xFF).arg((xIp >> 16) & 0xFF)
                .arg((xIp >> 8)  & 0xFF).arg(xIp & 0xFF);

            emit publicAddressDiscovered(ip, xPort);
            return;
        }
        offset += attrLen;
        if (attrLen % 4) offset += 4 - (attrLen % 4); // 4-byte padding
    }

    emit failed("STUN: no MAPPED-ADDRESS found in response");
}

void StunClient::onTimeout()
{
    emit failed("STUN: timed out waiting for response");
}
