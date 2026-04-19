#pragma once
//
// QuicConnection — QUIC transport layered over ICE/libnice.
//
// Plain C++ class.  No Qt inheritance, no Qt types — the Phase 7d Qt strip
// (2026-04-18) replaced the former QObject base + signals with a
// std::function callbacks pattern, matching NiceConnection.
//
// Wraps NiceConnection (composition) for NAT traversal, then upgrades to a
// QUIC connection for reliable, framed, multiplexed P2P transport.
//
// Two QUIC streams:
//   - Message stream (bidirectional, stream 0): text messages, signaling
//   - File stream (bidirectional, stream 4): bulk file transfers
//
// Falls back to raw ICE (NiceConnection passthrough) when:
//   - Peer doesn't support QUIC (no "quic" field in ice_offer/answer)
//   - ICE selected a TURN relay candidate (QUIC can't tunnel through TURN)
//   - QUIC handshake times out (3 seconds)
//
// Wire framing on QUIC streams: [4 bytes BE length][payload]
//
// **Threading:** all callbacks fire on whatever thread libnice/msquic
// happen to be running on (the GLib main loop thread for ICE events,
// msquic's worker pool for QUIC events).  ChatController's callbacks are
// thread-safe by design.  No Qt thread marshaling is used.
//

#include "ITimer.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <msquic.h>

class NiceConnection;

class QuicConnection {
public:
    using Bytes = std::vector<uint8_t>;

    explicit QuicConnection(ITimerFactory& timers);
    ~QuicConnection();

    QuicConnection(const QuicConnection&) = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    // Same interface as NiceConnection for ChatController compatibility.
    void initIce(bool controlling);
    void setTurnServer(const std::string& host, int port,
                       const std::string& user, const std::string& pass);
    void setRemoteSdp(const std::string& sdp);

    // Send data on the message stream (framed, reliable).
    void sendData(const Bytes& data);

    // Send data on the file stream (framed, reliable, bulk).
    // Returns true if sent via QUIC, false if not available (caller should use mailbox).
    bool sendFileData(const Bytes& data);

    bool isReady() const;

    // QUIC capability negotiation.
    void setPeerSupportsQuic(bool supports, const std::string& fingerprint = {});
    bool quicActive() const { return m_quicActive; }
    std::string localQuicFingerprint() const { return m_localFingerprint; }

    // ── Event callbacks (assign before / shortly after initIce). ──────────
    std::function<void(const std::string& sdp)>     onLocalSdpReady;
    std::function<void(int niceComponentState)>     onStateChanged;
    std::function<void(const Bytes& data)>          onDataReceived;     // message stream
    std::function<void(const Bytes& data)>          onFileDataReceived; // file stream

    // Public statics for atexit cleanup (S5 fix).
    static const QUIC_API_TABLE* s_msquic;
    static HQUIC s_registration;

private:
    // ICE event handlers (assigned to NiceConnection's callback slots).
    void onIceStateChanged(int state);
    void onIceDataReceived(const Bytes& data);
    void onQuicHandshakeTimeout();

    // QUIC global init.
    static bool s_initialized;
    static void initQuicGlobal();

    // ICE layer (composition).  unique_ptr because NiceConnection is
    // non-copyable and we own its lifetime.
    std::unique_ptr<NiceConnection> m_ice;

    // QUIC state.
    HQUIC m_configuration = nullptr;
    HQUIC m_connection    = nullptr;
    HQUIC m_listener      = nullptr;
    HQUIC m_msgStream     = nullptr;
    HQUIC m_fileStream    = nullptr;

    // Framing buffers (length-prefix reassembly).
    Bytes m_msgRecvBuf;
    Bytes m_fileRecvBuf;
    void processFramedStream(Bytes& buf, const uint8_t* data, uint32_t len,
                             std::function<void(const Bytes&)>& cb);

    // TLS / fingerprint.
    std::string m_localFingerprint;
    std::string m_peerFingerprint;
    bool m_peerSupportsQuic = false;

    // State.
    bool m_controlling = false;
    bool m_quicActive  = false;
    bool m_rawIceMode  = false;

    // Handshake timer (replaces QTimer).
    ITimerFactory*          m_timerFactory = nullptr;
    std::unique_ptr<ITimer> m_handshakeTimer;

    // QUIC bootstrap over ICE: exchange ports before switching.
    uint16_t    m_localQuicPort = 0;
    uint16_t    m_peerQuicPort  = 0;
    std::string m_peerAddress;   // dotted-quad / IPv6 string; empty until ICE ready

    void startQuicClient();
    void startQuicServer();
    void openStreams();
    void sendFramed(HQUIC stream, const Bytes& data);
    void fallbackToRawIce();

    // msquic callbacks (static, dispatch via context pointer).
    static QUIC_STATUS QUIC_API connectionCallback(HQUIC conn, void* ctx, QUIC_CONNECTION_EVENT* ev);
    static QUIC_STATUS QUIC_API streamCallback(HQUIC stream, void* ctx, QUIC_STREAM_EVENT* ev);
    static QUIC_STATUS QUIC_API listenerCallback(HQUIC listener, void* ctx, QUIC_LISTENER_EVENT* ev);
};
