#include "DirectPeerLink.hpp"
#include <QDataStream>
#include <QUuid>
#include <QDebug>

// Wire protocol (simple framing):
//   [4-byte big-endian uint32 length][payload bytes]
// Both sides use this to know when a complete envelope has arrived.

static constexpr int kHeaderSize = 4; // bytes for the length prefix

DirectPeerLink::DirectPeerLink(QObject* parent)
    : QObject(parent)
{
    connect(&m_server, &QTcpServer::newConnection,
            this,      &DirectPeerLink::onNewConnection);
}

quint16 DirectPeerLink::startListening(quint16 port)
{
    if (m_server.isListening())
        return m_server.serverPort();

    if (!m_server.listen(QHostAddress::Any, port)) {
        emit status(QString("direct: listen failed on port %1: %2")
                        .arg(port).arg(m_server.errorString()));
        return 0;
    }

    emit status(QString("direct: listening on port %1").arg(m_server.serverPort()));
    return m_server.serverPort();
}

void DirectPeerLink::stopListening()
{
    m_server.close();
    for (QTcpSocket* s : m_incoming.keys()) {
        s->disconnectFromHost();
        s->deleteLater();
    }
    m_incoming.clear();
}

quint16 DirectPeerLink::listeningPort() const
{
    return m_server.isListening() ? m_server.serverPort() : 0;
}

void DirectPeerLink::sendDirect(const QString& host, quint16 port, const QByteArray& envelope)
{
    // Each send gets its own short-lived socket.
    QTcpSocket* sock = new QTcpSocket(this);

    connect(sock, &QTcpSocket::connected, this, [sock, envelope, this]() {
        // Write length-prefixed envelope
        QByteArray frame;
        QDataStream ds(&frame, QIODevice::WriteOnly);
        ds.setByteOrder(QDataStream::BigEndian);
        ds << static_cast<quint32>(envelope.size());
        frame.append(envelope);
        sock->write(frame);
        sock->flush();
        sock->disconnectFromHost();
        emit status(QString("direct: sent %1 bytes").arg(envelope.size()));
    });

    connect(sock, &QTcpSocket::disconnected, sock, &QTcpSocket::deleteLater);

    connect(sock, &QAbstractSocket::errorOccurred, this,
            [sock, host, port, this](QAbstractSocket::SocketError err) {
        Q_UNUSED(err);
        emit status(QString("direct: send to %1:%2 failed: %3")
                        .arg(host).arg(port).arg(sock->errorString()));
        sock->deleteLater();
    });

    sock->connectToHost(host, port);
}

// ── Incoming connection handling ─────────────────────────────────────────────

void DirectPeerLink::onNewConnection()
{
    while (m_server.hasPendingConnections()) {
        QTcpSocket* client = m_server.nextPendingConnection();
        m_incoming[client] = QByteArray();

        connect(client, &QTcpSocket::readyRead,
                this,   &DirectPeerLink::onClientReadyRead);
        connect(client, &QTcpSocket::disconnected,
                this,   &DirectPeerLink::onClientDisconnected);

        emit status(QString("direct: peer connected from %1:%2")
                        .arg(client->peerAddress().toString())
                        .arg(client->peerPort()));
    }
}

void DirectPeerLink::onClientReadyRead()
{
    QTcpSocket* client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    m_incoming[client].append(client->readAll());

    QByteArray& buf = m_incoming[client];

    // Process as many complete frames as are buffered
    while (buf.size() >= kHeaderSize) {
        // Peek at the length prefix
        quint32 payloadLen = 0;
        {
            QDataStream ds(buf.left(kHeaderSize));
            ds.setByteOrder(QDataStream::BigEndian);
            ds >> payloadLen;
        }

        if (payloadLen == 0 || payloadLen > 10 * 1024 * 1024) {
            // Sanity check — reject absurdly large or zero-length frames
            emit status("direct: invalid frame length, dropping connection");
            client->disconnectFromHost();
            return;
        }

        const int totalNeeded = kHeaderSize + static_cast<int>(payloadLen);
        if (buf.size() < totalNeeded)
            break; // wait for more data

        // Extract complete payload
        const QByteArray payload = buf.mid(kHeaderSize, static_cast<int>(payloadLen));
        buf.remove(0, totalNeeded);

        // Give it a synthetic envId so the signature matches MailboxClient
        const QString envId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        emit envelopeReceived(payload, envId);
    }
}

void DirectPeerLink::onClientDisconnected()
{
    QTcpSocket* client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    m_incoming.remove(client);
    client->deleteLater();
}