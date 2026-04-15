#pragma once

#include "NiceConnection.hpp"
#include <QObject>
#include <QByteArray>
#include <QHostAddress>
#include <QTimer>
#include <functional>
#include <atomic>

#include <msquic.h>

/*
 * QuicConnection — QUIC transport layered over ICE/libnice.
 *
 * Wraps NiceConnection (composition) for NAT traversal, then upgrades
 * to a QUIC connection for reliable, framed, multiplexed P2P transport.
 *
 * Two QUIC streams:
 *   - Message stream (bidirectional, stream 0): text messages, signaling
 *   - File stream (bidirectional, stream 4): bulk file transfers
 *
 * Falls back to raw ICE (NiceConnection passthrough) when:
 *   - Peer doesn't support QUIC (no "quic" field in ice_offer/answer)
 *   - ICE selected a TURN relay candidate (QUIC can't tunnel through TURN)
 *   - QUIC handshake times out (3 seconds)
 *
 * Wire framing on QUIC streams: [4 bytes BE length][payload]
 */

class QuicConnection : public QObject {
    Q_OBJECT
public:
    explicit QuicConnection(QObject* parent = nullptr);
    ~QuicConnection();

    // Same interface as NiceConnection for ChatController compatibility
    void initIce(bool controlling);
    void setTurnServer(const QString& host, int port,
                       const QString& user, const QString& pass);
    void setRemoteSdp(const QString& sdp);

    // Send data on the message stream (framed, reliable)
    void sendData(const QByteArray& data);

    // Send data on the file stream (framed, reliable, bulk).
    // Returns true if sent via QUIC, false if not available (caller should use mailbox).
    bool sendFileData(const QByteArray& data);

    bool isReady() const;

    // QUIC capability negotiation
    void setPeerSupportsQuic(bool supports, const QString& fingerprint = {});
    bool quicActive() const { return m_quicActive; }
    QString localQuicFingerprint() const { return m_localFingerprint; }

    // Public statics for atexit cleanup (S5 fix)
    static const QUIC_API_TABLE* s_msquic;
    static HQUIC s_registration;

Q_SIGNALS:  // Q_SIGNALS avoids conflict with GLib's gio 'signals' struct member
    void localSdpReady(const QString& sdp);
    void stateChanged(int state);
    void dataReceived(const QByteArray& data);       // message stream
    void fileDataReceived(const QByteArray& data);    // file stream

private slots:
    void onIceStateChanged(int state);
    void onIceDataReceived(const QByteArray& data);
    void onQuicHandshakeTimeout();

private:
    // ICE layer (composition)
    NiceConnection* m_ice = nullptr;

    // QUIC state
    static bool s_initialized;
    static void initQuicGlobal();

    HQUIC m_configuration = nullptr;
    HQUIC m_connection = nullptr;
    HQUIC m_listener = nullptr;
    HQUIC m_msgStream = nullptr;
    HQUIC m_fileStream = nullptr;

    // Framing buffers (length-prefix reassembly)
    QByteArray m_msgRecvBuf;
    QByteArray m_fileRecvBuf;
    void processFramedStream(QByteArray& buf, const uint8_t* data, uint32_t len,
                             void (QuicConnection::*signal)(const QByteArray&));

    // TLS / fingerprint
    QString m_localFingerprint;
    QString m_peerFingerprint;
    bool m_peerSupportsQuic = false;

    // State
    bool m_controlling = false;
    bool m_quicActive = false;
    bool m_rawIceMode = false;
    QTimer m_handshakeTimer;

    // QUIC bootstrap over ICE: exchange ports before switching
    quint16 m_localQuicPort = 0;
    quint16 m_peerQuicPort = 0;
    QHostAddress m_peerAddress;

    void startQuicClient();
    void startQuicServer();
    void openStreams();
    void sendFramed(HQUIC stream, const QByteArray& data);
    void fallbackToRawIce();

    // msquic callbacks (static, dispatch via context pointer)
    static QUIC_STATUS QUIC_API connectionCallback(HQUIC conn, void* ctx, QUIC_CONNECTION_EVENT* ev);
    static QUIC_STATUS QUIC_API streamCallback(HQUIC stream, void* ctx, QUIC_STREAM_EVENT* ev);
    static QUIC_STATUS QUIC_API listenerCallback(HQUIC listener, void* ctx, QUIC_LISTENER_EVENT* ev);
};
