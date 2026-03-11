#include "HolePuncher.hpp"
#include "StunClient.hpp"
#include <QDataStream>
#include <QUuid>
#include <QHostInfo>
#include <QDebug>

static constexpr int kHeaderSize      = 4;
static constexpr int kMaxProbes       = 20;  // was 10 — give NAT more time
static constexpr int kProbeIntervalMs = 200;
static constexpr int kPunchTimeoutMs  = 6000; // now actually used

HolePuncher::HolePuncher(QObject* parent) : QObject(parent)
{
    connect(&m_socket, &QUdpSocket::readyRead, this, &HolePuncher::onReadyRead);
}

quint16 HolePuncher::bind(quint16 port)
{
    if (m_socket.state() == QAbstractSocket::BoundState)
        return m_socket.localPort();

    if (!m_socket.bind(QHostAddress::Any, port,
                       QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint)) {
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

// ── Normalize address to plain IPv4 string ────────────────────────────────────
// Fixes Bug 3: QHostAddress can represent the same IPv4 address in multiple
// formats (e.g. "1.2.3.4" vs "::ffff:1.2.3.4"). Always compare as IPv4.
QString HolePuncher::normalizeAddress(const QHostAddress& addr)
{
    // If it's an IPv4-mapped IPv6 address, extract the IPv4 part
    bool ok = false;
    QHostAddress v4(addr.toIPv4Address(&ok));
    return ok ? v4.toString() : addr.toString();
}

// ── Punch + send ──────────────────────────────────────────────────────────────

void HolePuncher::punchAndSend(const QString& punchId,
                               const QString& peerHost, quint16 peerPort,
                               const QByteArray& envelope)
{
    QHostInfo::lookupHost(peerHost, this, [=](const QHostInfo& info) {
        if (info.addresses().isEmpty()) {
            emit status(QString("punch: DNS failed for %1").arg(peerHost));
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

        // ── Probe timer: fires every 200ms to send a punch probe ─────────────
        attempt->probeTimer = new QTimer(this);
        attempt->probeTimer->setInterval(kProbeIntervalMs);
        connect(attempt->probeTimer, &QTimer::timeout, this, [this, punchId]() {
            auto* a = m_attempts.value(punchId);
            if (!a) return;
            sendProbe(a->host, a->port);
            a->probes++;
            // No hard cutoff here — the timeout timer handles giving up
        });

        // ── Timeout timer: give up after kPunchTimeoutMs ─────────────────────
        // Bug 4 fix: this timer was previously never started
        attempt->timeoutTimer = new QTimer(this);
        attempt->timeoutTimer->setSingleShot(true);
        attempt->timeoutTimer->setInterval(kPunchTimeoutMs);
        connect(attempt->timeoutTimer, &QTimer::timeout, this, [this, punchId]() {
            if (!m_attempts.contains(punchId)) return;
            emit status(QString("punch: timeout after %1ms, giving up").arg(kPunchTimeoutMs));
            cleanupAttempt(punchId);
            emit punchFailed(punchId);
        });

        attempt->probeTimer->start();
        attempt->timeoutTimer->start();

        // Send first probe immediately (don't wait for first timer tick)
        sendProbe(addr, peerPort);

        emit status(QString("punch: probing %1:%2 (punchId=%3)")
                        .arg(normalizeAddress(addr)).arg(peerPort).arg(punchId));
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
    QByteArray probe(kHeaderSize, '\0'); // length = 0 means "probe, not data"
    m_socket.writeDatagram(probe, host, port);
}

void HolePuncher::cleanupAttempt(const QString& punchId)
{
    auto* a = m_attempts.take(punchId);
    if (!a) return;
    if (a->probeTimer)   { a->probeTimer->stop();   a->probeTimer->deleteLater(); }
    if (a->timeoutTimer) { a->timeoutTimer->stop();  a->timeoutTimer->deleteLater(); }
    delete a;
}

// ── Incoming datagrams ────────────────────────────────────────────────────────

void HolePuncher::onReadyRead()
{
    while (m_socket.hasPendingDatagrams()) {
        QByteArray buf;
        QHostAddress sender;
        quint16 senderPort;

        buf.resize(static_cast<int>(m_socket.pendingDatagramSize()));
        m_socket.readDatagram(buf.data(), buf.size(), &sender, &senderPort);

        // ── Let StunClient inspect it first (shared socket, Bug 1 fix) ───────
        if (m_stun && m_stun->tryHandleDatagram(buf))
            continue; // consumed as STUN response

        // ── Probe packet: length prefix = 0 ──────────────────────────────────
        if (buf.size() == kHeaderSize) {
            quint32 len = 0;
            QDataStream ds(buf);
            ds.setByteOrder(QDataStream::BigEndian);
            ds >> len;

            if (len == 0) {
                // Bug 3 fix: normalize both addresses before comparing
                const QString senderNorm = normalizeAddress(sender);

                for (auto it = m_attempts.begin(); it != m_attempts.end(); ++it) {
                    auto* a = it.value();
                    const QString attemptNorm = normalizeAddress(a->host);

                    if (attemptNorm == senderNorm && a->port == senderPort) {
                        emit status(QString("punch: hole open! peer probe received from %1:%2")
                                        .arg(senderNorm).arg(senderPort));
                        const QString pid = a->punchId;
                        sendTo(senderNorm, senderPort, a->envelope);
                        emit punchSuccess(pid, senderNorm, senderPort);
                        cleanupAttempt(pid);
                        break;
                    }
                }
                continue;
            }
        }

        // ── Real data frame ───────────────────────────────────────────────────
        const QString key = normalizeAddress(sender) + ":" + QString::number(senderPort);
        m_rxBufs[key].append(buf);
        QByteArray& accum = m_rxBufs[key];

        while (accum.size() >= kHeaderSize) {
            quint32 payloadLen = 0;
            {
                QDataStream ds(accum.left(kHeaderSize));
                ds.setByteOrder(QDataStream::BigEndian);
                ds >> payloadLen;
            }

            if (payloadLen == 0)               { accum.remove(0, kHeaderSize); continue; }
            if (payloadLen > 10 * 1024 * 1024) { emit status("punch: oversized frame, dropping"); accum.clear(); break; }

            const int needed = kHeaderSize + static_cast<int>(payloadLen);
            if (accum.size() < needed) break;

            const QByteArray payload = accum.mid(kHeaderSize, static_cast<int>(payloadLen));
            accum.remove(0, needed);

            emit envelopeReceived(payload, QUuid::createUuid().toString(QUuid::WithoutBraces));
        }
    }
}
