#include "StunClient.hpp"
#include <QHostInfo>
#include <QRandomGenerator>
#include <QDataStream>
#include <QDebug>

static QByteArray buildBindingRequest(QByteArray& txIdOut)
{
    txIdOut.resize(12);
    for (int i = 0; i < 12; ++i)
        txIdOut[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));

    QByteArray msg(20, '\0');
    msg[0] = 0x00; msg[1] = 0x01; // Binding Request
    msg[2] = 0x00; msg[3] = 0x00; // Length = 0
    msg[4] = 0x21; msg[5] = 0x12; msg[6] = 0xA4; msg[7] = 0x42; // Magic cookie
    msg.replace(8, 12, txIdOut);
    return msg;
}

StunClient::StunClient(QObject* parent) : QObject(parent)
{
    connect(&m_ownSocket, &QUdpSocket::readyRead, this, &StunClient::onReadyRead);
    m_timeout.setSingleShot(true);
    connect(&m_timeout, &QTimer::timeout, this, &StunClient::onTimeout);
}

// ── Internal socket path (simple IP discovery) ────────────────────────────────

void StunClient::discover(const QString& stunHost, quint16 stunPort)
{
    m_socket    = &m_ownSocket;
    m_retriesLeft = kMaxRetries;
    m_stunHost  = stunHost;
    m_stunPort  = stunPort;
    m_ownSocket.bind(QHostAddress::Any, 0);

    QHostInfo::lookupHost(stunHost, this, [this, stunPort](const QHostInfo& info) {
        if (info.addresses().isEmpty()) { emit failed("STUN: DNS lookup failed"); return; }
        m_stunAddr = info.addresses().first();
        sendRequest(m_socket, m_stunAddr, stunPort);
    });
}

// ── Shared socket path (REQUIRED for hole-punching) ──────────────────────────

void StunClient::discoverOnSocket(QUdpSocket* sharedSocket,
                                  const QString& stunHost, quint16 stunPort)
{
    m_socket      = sharedSocket;
    m_retriesLeft = kMaxRetries;
    m_stunHost    = stunHost;
    m_stunPort    = stunPort;

    QHostInfo::lookupHost(stunHost, this, [this, stunPort](const QHostInfo& info) {
        if (info.addresses().isEmpty()) { emit failed("STUN: DNS lookup failed"); return; }
        m_stunAddr = info.addresses().first();
        sendRequest(m_socket, m_stunAddr, stunPort);
    });
}

void StunClient::sendRequest(QUdpSocket* sock, const QHostAddress& addr, quint16 port)
{
    const QByteArray req = buildBindingRequest(m_txId);
    sock->writeDatagram(req, addr, port);
    m_timeout.start(5000);
}

// ── Response handling ─────────────────────────────────────────────────────────

void StunClient::onReadyRead()
{
    // Only used when m_ownSocket is active (internal path)
    QByteArray buf(512, '\0');
    QHostAddress sender; quint16 senderPort;
    qint64 n = m_ownSocket.readDatagram(buf.data(), buf.size(), &sender, &senderPort);
    if (n < 20) return;
    buf.resize(static_cast<int>(n));
    parseResponse(buf);
}

bool StunClient::tryHandleDatagram(const QByteArray& buf)
{
    // Returns true if this looks like a STUN response and we handled it
    if (buf.size() < 20) return false;
    // Check magic cookie
    if ((quint8)buf[4] != 0x21 || (quint8)buf[5] != 0x12 ||
        (quint8)buf[6] != 0xA4 || (quint8)buf[7] != 0x42) return false;
    // Check it's a Binding Response (0x0101) or Success (0x0101)
    const quint16 msgType = ((quint8)buf[0] << 8) | (quint8)buf[1];
    if (msgType != 0x0101 && msgType != 0x0111) return false;
    // Check transaction ID matches
    if (buf.mid(8, 12) != m_txId) return false;

    return parseResponse(buf);
}

bool StunClient::parseResponse(const QByteArray& buf)
{
    if (buf.size() < 20) return false;
    if (buf.mid(8, 12) != m_txId) return false;

    m_timeout.stop();
    m_retriesLeft = 0; // success — no more retries needed

    int offset = 20;
    while (offset + 4 <= buf.size()) {
        const quint16 attrType = ((quint8)buf[offset] << 8) | (quint8)buf[offset+1];
        const quint16 attrLen  = ((quint8)buf[offset+2] << 8) | (quint8)buf[offset+3];
        offset += 4;

        if (attrType == 0x0020 && attrLen >= 8) { // XOR-MAPPED-ADDRESS
            const quint16 xPort = (((quint8)buf[offset+2] << 8) | (quint8)buf[offset+3]) ^ 0x2112;
            const quint32 xIp   =
                (((quint8)buf[offset+4] << 24) | ((quint8)buf[offset+5] << 16) |
                 ((quint8)buf[offset+6] << 8)  |  (quint8)buf[offset+7]) ^ 0x2112A442u;

            const QString ip = QString("%1.%2.%3.%4")
                                   .arg((xIp >> 24) & 0xFF).arg((xIp >> 16) & 0xFF)
                                   .arg((xIp >> 8) & 0xFF).arg(xIp & 0xFF);

            emit publicAddressDiscovered(ip, xPort);
            return true;
        }
        offset += attrLen;
        if (attrLen % 4) offset += 4 - (attrLen % 4);
    }

    emit failed("STUN: no XOR-MAPPED-ADDRESS in response");
    return false;
}

void StunClient::onTimeout()
{
    if (m_retriesLeft > 0 && m_socket && !m_stunAddr.isNull()) {
        --m_retriesLeft;
        qDebug() << "[STUN] timeout — retrying, attempts left:" << m_retriesLeft;
        sendRequest(m_socket, m_stunAddr, m_stunPort);
        return;
    }
    emit failed("STUN: timed out");
}
