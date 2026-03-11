#include "HolePuncher.hpp"
#include <QDataStream>
#include <QUuid>
#include <QHostInfo>
#include <QDebug>

static constexpr int kHeaderSize   = 4;
static constexpr int kMaxProbes    = 10;
static constexpr int kProbeIntervalMs = 200;
static constexpr int kPunchTimeoutMs  = 5000;

HolePuncher::HolePuncher(QObject* parent) : QObject(parent)
{
    connect(&m_socket, &QUdpSocket::readyRead, this, &HolePuncher::onReadyRead);
}

quint16 HolePuncher::bind(quint16 port)
{
    if (m_socket.state() == QAbstractSocket::BoundState)
        return m_socket.localPort();

    if (!m_socket.bind(QHostAddress::Any, port)) {
        emit status(QString("punch: bind failed: %1").arg(m_socket.errorString()));
        return 0;
    }
    emit status(QString("punch: bound on port %1").arg(m_socket.localPort()));
    return m_socket.localPort();
}

quint16 HolePuncher::boundPort() const
{
    return (m_socket.state() == QAbstractSocket::BoundState) ? m_socket.localPort() : 0;
}

void HolePuncher::punchAndSend(const QString& punchId,
                                const QString& peerHost, quint16 peerPort,
                                const QByteArray& envelope)
{
    // Resolve the host first, then punch
    QHostInfo::lookupHost(peerHost, this, [=](const QHostInfo& info) {
        if (info.addresses().isEmpty()) {
            emit punchFailed(punchId);
            return;
        }

        const QHostAddress addr = info.addresses().first();
        auto* attempt           = new PunchAttempt;
        attempt->punchId        = punchId;
        attempt->host           = addr;
        attempt->port           = peerPort;
        attempt->envelope       = envelope;
        attempt->probes         = 0;

        m_attempts[punchId] = attempt;

        // Fire probes on a timer
        attempt->timer = new QTimer(this);
        attempt->timer->setInterval(kProbeIntervalMs);

        connect(attempt->timer, &QTimer::timeout, this, [this, punchId]() {
            auto* a = m_attempts.value(punchId);
            if (!a) return;

            sendProbe(a->host, a->port);
            a->probes++;

            if (a->probes >= kMaxProbes) {
                a->timer->stop();
                // One last try: send the actual envelope anyway.
                // If the hole isn't open yet this will be dropped, but
                // some NATs open on the first real packet.
                sendTo(a->host.toString(), a->port, a->envelope);
                emit punchFailed(punchId);
                a->timer->deleteLater();
                delete m_attempts.take(punchId);
            }
        });

        attempt->timer->start();
        emit status(QString("punch: starting hole-punch to %1:%2")
                        .arg(addr.toString()).arg(peerPort));
    });
}

void HolePuncher::sendTo(const QString& host, quint16 port, const QByteArray& envelope)
{
    QByteArray frame;
    QDataStream ds(&frame, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::BigEndian);
    ds << static_cast<quint32>(envelope.size());
    frame.append(envelope);
    m_socket.writeDatagram(frame, QHostAddress(host), port);
}

void HolePuncher::sendProbe(const QHostAddress& host, quint16 port)
{
    // Probe = just the 4-byte header with length=0, no payload.
    // This opens our NAT mapping without confusing the receiver.
    QByteArray probe(kHeaderSize, '\0'); // length field = 0
    m_socket.writeDatagram(probe, host, port);
}

void HolePuncher::onReadyRead()
{
    while (m_socket.hasPendingDatagrams()) {
        QByteArray buf;
        QHostAddress sender;
        quint16 senderPort;

        buf.resize(static_cast<int>(m_socket.pendingDatagramSize()));
        m_socket.readDatagram(buf.data(), buf.size(), &sender, &senderPort);

        const QString key = sender.toString() + ":" + QString::number(senderPort);

        // If length=0, it's a punch probe — mark hole open and flush pending sends
        if (buf.size() == kHeaderSize) {
            quint32 len = 0;
            QDataStream ds(buf);
            ds.setByteOrder(QDataStream::BigEndian);
            ds >> len;
            if (len == 0) {
                // Find a matching punch attempt and mark success
                for (auto it = m_attempts.begin(); it != m_attempts.end(); ++it) {
                    auto* a = it.value();
                    if (a->host == sender && a->port == senderPort) {
                        a->timer->stop();
                        sendTo(sender.toString(), senderPort, a->envelope);
                        emit punchSuccess(a->punchId, sender.toString(), senderPort);
                        a->timer->deleteLater();
                        delete m_attempts.take(it.key());
                        break;
                    }
                }
                continue;
            }
        }

        // Accumulate real data
        m_rxBufs[key].append(buf);
        QByteArray& accum = m_rxBufs[key];

        while (accum.size() >= kHeaderSize) {
            quint32 payloadLen = 0;
            {
                QDataStream ds(accum.left(kHeaderSize));
                ds.setByteOrder(QDataStream::BigEndian);
                ds >> payloadLen;
            }

            if (payloadLen == 0) { accum.remove(0, kHeaderSize); continue; }
            if (payloadLen > 10 * 1024 * 1024) {
                emit status("punch: oversized frame, dropping");
                accum.clear();
                break;
            }

            const int needed = kHeaderSize + static_cast<int>(payloadLen);
            if (accum.size() < needed) break;

            const QByteArray payload = accum.mid(kHeaderSize, static_cast<int>(payloadLen));
            accum.remove(0, needed);

            const QString envId = QUuid::createUuid().toString(QUuid::WithoutBraces);
            emit envelopeReceived(payload, envId);
        }
    }
}