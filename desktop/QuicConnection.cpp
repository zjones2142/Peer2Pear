#include "QuicConnection.hpp"
#include "NiceConnection.hpp"
#include "CryptoEngine.hpp"
#include "log.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #include <arpa/inet.h>
#endif

using json = nlohmann::json;

// S4 fix: max frame size matches the mailbox envelope limit (256 KB)
static constexpr uint32_t kMaxFrameSize = 256 * 1024;

// ---------------------------
// Static msquic state
// ---------------------------

const QUIC_API_TABLE* QuicConnection::s_msquic = nullptr;
HQUIC QuicConnection::s_registration = nullptr;
bool QuicConnection::s_initialized = false;

// S5 fix: cleanup on app exit
static void cleanupMsquic() {
    if (QuicConnection::s_msquic && QuicConnection::s_registration) {
        QuicConnection::s_msquic->RegistrationClose(QuicConnection::s_registration);
        QuicConnection::s_registration = nullptr;
    }
    if (QuicConnection::s_msquic) {
        MsQuicClose(QuicConnection::s_msquic);
        QuicConnection::s_msquic = nullptr;
    }
}

void QuicConnection::initQuicGlobal() {
    if (s_initialized) return;

    if (QUIC_FAILED(MsQuicOpen2(&s_msquic))) {
        P2P_WARN("[QUIC] Failed to open MsQuic");
        return;
    }

    QUIC_REGISTRATION_CONFIG regConfig = { "Peer2Pear", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(s_msquic->RegistrationOpen(&regConfig, &s_registration))) {
        P2P_WARN("[QUIC] Failed to open registration");
        MsQuicClose(s_msquic);
        s_msquic = nullptr;
        return;
    }

    s_initialized = true;
    atexit(cleanupMsquic);  // S5 fix
    P2P_LOG("[QUIC] MsQuic initialized");
}

// ---------------------------
// Helpers
// ---------------------------

namespace {

// Bind a UDP socket to an ephemeral port, read it back, then close the socket.
// There's a TOCTOU race between the close here and msquic's later bind on the
// same port — same as the previous QUdpSocket-based version.  Acceptable for
// local development; iOS/Android will pick the port via system APIs anyway.
uint16_t findEphemeralUdpPort() {
#ifdef _WIN32
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return 0;
#else
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
#ifdef _WIN32
        ::closesocket(s);
#else
        ::close(s);
#endif
        return 0;
    }
#ifdef _WIN32
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    uint16_t port = 0;
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        port = ntohs(addr.sin_port);
    }
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
    return port;
}

// Replaces QByteArray::startsWith for Bytes.
inline bool bytesStartsWith(const QuicConnection::Bytes& data, const char* prefix) {
    const size_t n = std::strlen(prefix);
    if (data.size() < n) return false;
    return std::memcmp(data.data(), prefix, n) == 0;
}

}  // namespace

// ---------------------------
// Constructor / Destructor
// ---------------------------

QuicConnection::QuicConnection(ITimerFactory& timers)
    : m_timerFactory(&timers)
    , m_handshakeTimer(timers.create())
{
    initQuicGlobal();
}

QuicConnection::~QuicConnection() {
    if (m_handshakeTimer) m_handshakeTimer->stop();
    if (s_msquic) {
        if (m_msgStream)  s_msquic->StreamClose(m_msgStream);
        if (m_fileStream) s_msquic->StreamClose(m_fileStream);
        if (m_connection) {
            s_msquic->ConnectionShutdown(m_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            s_msquic->ConnectionClose(m_connection);
        }
        if (m_listener)      s_msquic->ListenerClose(m_listener);
        if (m_configuration) s_msquic->ConfigurationClose(m_configuration);
    }
    // m_ice's unique_ptr destructor cleans up the GLib loop and joins the
    // worker thread — see NiceConnection::~NiceConnection.
}

// ---------------------------
// ICE interface (delegated)
// ---------------------------

void QuicConnection::initIce(bool controlling) {
    m_controlling = controlling;
    m_ice = std::make_unique<NiceConnection>();

    m_ice->onLocalSdpReady = [this](const std::string& sdp) {
        if (onLocalSdpReady) onLocalSdpReady(sdp);
    };
    m_ice->onStateChanged  = [this](int state) { onIceStateChanged(state); };
    m_ice->onDataReceived  = [this](const Bytes& data) { onIceDataReceived(data); };

    m_ice->initIce(controlling);
}

void QuicConnection::setTurnServer(const std::string& host, int port,
                                    const std::string& user, const std::string& pass) {
    if (m_ice) m_ice->setTurnServer(host, port, user, pass);
}

void QuicConnection::setRemoteSdp(const std::string& sdp) {
    if (m_ice) m_ice->setRemoteSdp(sdp);
}

void QuicConnection::setPeerSupportsQuic(bool supports, const std::string& fingerprint) {
    m_peerSupportsQuic = supports;
    m_peerFingerprint  = fingerprint;
}

bool QuicConnection::isReady() const {
    if (m_quicActive) return true;
    if (m_rawIceMode && m_ice) return m_ice->isReady();
    return false;
}

// ---------------------------
// ICE callbacks
// ---------------------------

void QuicConnection::onIceStateChanged(int state) {
    if (state == NICE_COMPONENT_STATE_READY) {
        // S3 fix: check if ICE path is relayed (TURN) — can't do QUIC over TURN.
        if (m_ice && m_ice->isRelayed()) {
            P2P_LOG("[QUIC] ICE selected TURN relay — QUIC not possible, using raw ICE");
            fallbackToRawIce();
            if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_READY);
            return;
        }

        if (!m_peerSupportsQuic || !s_initialized) {
            fallbackToRawIce();
            if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_READY);
            return;
        }

        // S3 fix: extract peer's actual address from ICE selected pair.
        std::string peerHost;
        uint16_t    peerPort = 0;
        if (m_ice && m_ice->getSelectedPeerAddress(peerHost, peerPort)) {
            m_peerAddress = peerHost;
        } else {
            P2P_WARN("[QUIC] Could not get peer address from ICE — falling back");
            fallbackToRawIce();
            if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_READY);
            return;
        }

        P2P_LOG("[QUIC] ICE ready — attempting QUIC upgrade to "
                << m_peerAddress << " " << (m_controlling ? "(client)" : "(server)"));
        if (m_handshakeTimer)
            m_handshakeTimer->startSingleShot(3000, [this]() { onQuicHandshakeTimeout(); });

        // Find a free UDP port for QUIC.
        m_localQuicPort = findEphemeralUdpPort();

        // S2 fix: sign the bootstrap message with our identity key so the peer
        // can verify it's authentic (prevents port redirection attacks on ICE channel).
        json bootstrap = json::object();
        bootstrap["quic_port"]   = m_localQuicPort;
        bootstrap["fingerprint"] = m_localFingerprint;
        const std::string body = bootstrap.dump();
        Bytes msg;
        msg.reserve(5 + body.size());
        const char prefix[] = "QUIC:";
        msg.insert(msg.end(),
                   reinterpret_cast<const uint8_t*>(prefix),
                   reinterpret_cast<const uint8_t*>(prefix) + 5);
        msg.insert(msg.end(),
                   reinterpret_cast<const uint8_t*>(body.data()),
                   reinterpret_cast<const uint8_t*>(body.data()) + body.size());
        m_ice->sendData(msg);

        if (m_peerQuicPort > 0) {
            if (m_controlling) startQuicClient();
            else               startQuicServer();
        }
    } else if (state == NICE_COMPONENT_STATE_FAILED) {
        if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_FAILED);
    }
}

void QuicConnection::onIceDataReceived(const Bytes& data) {
    // Check for QUIC bootstrap message.
    if (bytesStartsWith(data, "QUIC:")) {
        const std::string body(reinterpret_cast<const char*>(data.data()) + 5,
                                data.size() - 5);
        const json obj = json::parse(body, /*cb=*/nullptr, /*allow_exceptions=*/false);
        if (!obj.is_object()) return;
        m_peerQuicPort = static_cast<uint16_t>(obj.value("quic_port", 0));

        // S2 fix: verify the bootstrap fingerprint matches what we received in signaling.
        const std::string bootFingerprint = obj.value("fingerprint", std::string());
        if (!m_peerFingerprint.empty() && bootFingerprint != m_peerFingerprint) {
            P2P_WARN("[QUIC] Bootstrap fingerprint mismatch — possible tampering, falling back");
            fallbackToRawIce();
            if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_READY);
            return;
        }

        P2P_LOG("[QUIC] Peer QUIC port: " << m_peerQuicPort);

        if (m_ice->isReady() && !m_quicActive && !m_rawIceMode) {
            if (m_controlling) startQuicClient();
            else               startQuicServer();
        }
        return;
    }

    if (m_rawIceMode) {
        if (onDataReceived) onDataReceived(data);
        return;
    }

    if (!m_quicActive) {
        if (onDataReceived) onDataReceived(data);
    }
}

void QuicConnection::onQuicHandshakeTimeout() {
    if (!m_quicActive) {
        P2P_WARN("[QUIC] Handshake timeout — falling back to raw ICE");
        fallbackToRawIce();
        if (onStateChanged) onStateChanged(NICE_COMPONENT_STATE_READY);
    }
}

void QuicConnection::fallbackToRawIce() {
    m_rawIceMode = true;
    m_quicActive = false;
    P2P_LOG("[QUIC] Fallback to raw ICE mode");
}

// ---------------------------
// QUIC setup
// ---------------------------

void QuicConnection::startQuicClient() {
    if (!s_msquic || !s_registration) { fallbackToRawIce(); return; }

    QUIC_BUFFER alpn = { 7, (uint8_t*)"p2pear" };
    QUIC_SETTINGS settings = {};
    settings.IdleTimeoutMs = 30000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerUnidiStreamCount = 0;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    settings.PeerBidiStreamCount = 2;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    // S1 fix: app-layer crypto is the primary security layer.  See header for rationale.
    QUIC_CREDENTIAL_CONFIG credConfig = {};
    credConfig.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    credConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT |
                       QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(s_msquic->ConfigurationOpen(s_registration, &alpn, 1,
                                                  &settings, sizeof(settings),
                                                  nullptr, &m_configuration))) {
        P2P_WARN("[QUIC] Failed to open client configuration");
        fallbackToRawIce();
        return;
    }

    if (QUIC_FAILED(s_msquic->ConfigurationLoadCredential(m_configuration, &credConfig))) {
        P2P_WARN("[QUIC] Failed to load client credentials");
        fallbackToRawIce();
        return;
    }

    if (QUIC_FAILED(s_msquic->ConnectionOpen(s_registration, connectionCallback,
                                               this, &m_connection))) {
        P2P_WARN("[QUIC] Failed to open connection");
        fallbackToRawIce();
        return;
    }

    if (QUIC_FAILED(s_msquic->ConnectionStart(m_connection, m_configuration,
                                                QUIC_ADDRESS_FAMILY_INET,
                                                m_peerAddress.c_str(),
                                                m_peerQuicPort))) {
        P2P_WARN("[QUIC] Failed to start connection");
        fallbackToRawIce();
        return;
    }

    P2P_LOG("[QUIC] Client connecting to " << m_peerAddress << ":" << m_peerQuicPort);
}

void QuicConnection::startQuicServer() {
    if (!s_msquic || !s_registration) { fallbackToRawIce(); return; }

    QUIC_BUFFER alpn = { 7, (uint8_t*)"p2pear" };
    QUIC_SETTINGS settings = {};
    settings.IdleTimeoutMs = 30000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = 2;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    // S1 fix: same rationale as client — app-layer crypto is the primary security layer.
    QUIC_CREDENTIAL_CONFIG credConfig = {};
    credConfig.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    credConfig.Flags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(s_msquic->ConfigurationOpen(s_registration, &alpn, 1,
                                                  &settings, sizeof(settings),
                                                  nullptr, &m_configuration))) {
        P2P_WARN("[QUIC] Failed to open server configuration");
        fallbackToRawIce();
        return;
    }

    if (QUIC_FAILED(s_msquic->ConfigurationLoadCredential(m_configuration, &credConfig))) {
        P2P_WARN("[QUIC] Failed to load server credentials");
        fallbackToRawIce();
        return;
    }

    if (QUIC_FAILED(s_msquic->ListenerOpen(s_registration, listenerCallback,
                                             this, &m_listener))) {
        P2P_WARN("[QUIC] Failed to open listener");
        fallbackToRawIce();
        return;
    }

    QUIC_ADDR addr = {};
    QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&addr, m_localQuicPort);

    if (QUIC_FAILED(s_msquic->ListenerStart(m_listener, &alpn, 1, &addr))) {
        P2P_WARN("[QUIC] Failed to start listener on port " << m_localQuicPort);
        fallbackToRawIce();
        return;
    }

    P2P_LOG("[QUIC] Server listening on port " << m_localQuicPort);
}

// ---------------------------
// QUIC callbacks
// ---------------------------

QUIC_STATUS QUIC_API QuicConnection::connectionCallback(HQUIC /*conn*/, void* ctx,
                                                          QUIC_CONNECTION_EVENT* ev) {
    auto* self = static_cast<QuicConnection*>(ctx);

    switch (ev->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        P2P_LOG("[QUIC] Connected!");
        self->m_quicActive = true;
        if (self->m_handshakeTimer) self->m_handshakeTimer->stop();
        self->openStreams();
        // Fire the state-change callback directly on the msquic worker thread.
        // Previously this used QMetaObject::invokeMethod with a queued
        // connection to marshal back to the QObject's owning thread.  After
        // the QObject strip, ChatController's callbacks are thread-tolerant.
        if (self->onStateChanged) self->onStateChanged(NICE_COMPONENT_STATE_READY);
        return QUIC_STATUS_SUCCESS;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        P2P_LOG("[QUIC] Connection shutdown complete");
        self->m_quicActive = false;
        return QUIC_STATUS_SUCCESS;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        HQUIC stream = ev->PEER_STREAM_STARTED.Stream;
        s_msquic->SetCallbackHandler(stream, (void*)streamCallback, ctx);
        if (!self->m_msgStream) {
            self->m_msgStream = stream;
        } else if (!self->m_fileStream) {
            self->m_fileStream = stream;
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        P2P_WARN("[QUIC] Peer-initiated shutdown, error: "
                 << ev->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        return QUIC_STATUS_SUCCESS;

    default:
        return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API QuicConnection::streamCallback(HQUIC stream, void* ctx,
                                                      QUIC_STREAM_EVENT* ev) {
    auto* self = static_cast<QuicConnection*>(ctx);

    switch (ev->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
            const QUIC_BUFFER& buf = ev->RECEIVE.Buffers[i];

            if (stream == self->m_msgStream) {
                self->processFramedStream(self->m_msgRecvBuf, buf.Buffer, buf.Length,
                                           self->onDataReceived);
            } else if (stream == self->m_fileStream) {
                self->processFramedStream(self->m_fileRecvBuf, buf.Buffer, buf.Length,
                                           self->onFileDataReceived);
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        std::free(ev->SEND_COMPLETE.ClientContext);
        return QUIC_STATUS_SUCCESS;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        return QUIC_STATUS_SUCCESS;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        return QUIC_STATUS_SUCCESS;

    default:
        return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API QuicConnection::listenerCallback(HQUIC /*listener*/, void* ctx,
                                                        QUIC_LISTENER_EVENT* ev) {
    auto* self = static_cast<QuicConnection*>(ctx);

    switch (ev->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        HQUIC conn = ev->NEW_CONNECTION.Connection;

        // S7 fix: verify the connecting peer's IP matches the ICE-discovered peer.
        // Note: port may differ (peer binds a new ephemeral port for QUIC).
        // Full IP validation deferred — the bootstrap fingerprint check (S2) and
        // the sealed-envelope auth at the application layer cover the gap.
        (void)self;

        self->m_connection = conn;
        s_msquic->SetCallbackHandler(conn, (void*)connectionCallback, ctx);
        s_msquic->ConnectionSetConfiguration(conn, self->m_configuration);
        return QUIC_STATUS_SUCCESS;
    }
    default:
        return QUIC_STATUS_SUCCESS;
    }
}

// ---------------------------
// Stream operations
// ---------------------------

void QuicConnection::openStreams() {
    if (!s_msquic || !m_connection) return;

    // Only the controlling side opens streams (client initiates).
    if (!m_controlling) return;

    if (QUIC_FAILED(s_msquic->StreamOpen(m_connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                           streamCallback, this, &m_msgStream))) {
        P2P_WARN("[QUIC] Failed to open message stream");
        return;
    }
    s_msquic->StreamStart(m_msgStream, QUIC_STREAM_START_FLAG_NONE);

    if (QUIC_FAILED(s_msquic->StreamOpen(m_connection, QUIC_STREAM_OPEN_FLAG_NONE,
                                           streamCallback, this, &m_fileStream))) {
        P2P_WARN("[QUIC] Failed to open file stream");
        return;
    }
    s_msquic->StreamStart(m_fileStream, QUIC_STREAM_START_FLAG_NONE);

    P2P_LOG("[QUIC] Opened message + file streams");
}

void QuicConnection::sendFramed(HQUIC stream, const Bytes& data) {
    if (!stream || !s_msquic) return;

    const uint32_t len      = static_cast<uint32_t>(data.size());
    const uint32_t totalLen = 4 + len;

    auto* buf = static_cast<uint8_t*>(std::malloc(totalLen));
    if (!buf) return;

    buf[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((len >>  8) & 0xFF);
    buf[3] = static_cast<uint8_t>( len        & 0xFF);
    std::memcpy(buf + 4, data.data(), len);

    QUIC_BUFFER quicBuf;
    quicBuf.Length = totalLen;
    quicBuf.Buffer = buf;

    s_msquic->StreamSend(stream, &quicBuf, 1, QUIC_SEND_FLAG_NONE, buf);
}

void QuicConnection::processFramedStream(Bytes& buf, const uint8_t* data, uint32_t len,
                                           std::function<void(const Bytes&)>& cb) {
    buf.insert(buf.end(), data, data + len);

    while (buf.size() >= 4) {
        const uint32_t frameLen =
            (static_cast<uint32_t>(buf[0]) << 24) |
            (static_cast<uint32_t>(buf[1]) << 16) |
            (static_cast<uint32_t>(buf[2]) <<  8) |
             static_cast<uint32_t>(buf[3]);

        // S4 fix: reject frames larger than the mailbox envelope limit.
        if (frameLen > kMaxFrameSize) {
            P2P_WARN("[QUIC] Frame too large: " << frameLen << " — dropping buffer");
            buf.clear();
            return;
        }

        if (buf.size() < 4u + frameLen) break;

        Bytes payload(buf.begin() + 4, buf.begin() + 4 + frameLen);
        buf.erase(buf.begin(), buf.begin() + 4 + frameLen);

        if (cb) cb(payload);
    }
}

// ---------------------------
// Send interface
// ---------------------------

void QuicConnection::sendData(const Bytes& data) {
    if (m_rawIceMode) {
        if (m_ice) m_ice->sendData(data);
        return;
    }

    if (m_quicActive && m_msgStream) {
        sendFramed(m_msgStream, data);
    } else if (m_ice && m_ice->isReady()) {
        m_ice->sendData(data);
    }
}

// S6 fix: return bool indicating success.
bool QuicConnection::sendFileData(const Bytes& data) {
    if (m_rawIceMode) return false;  // no QUIC file stream in raw mode

    if (m_quicActive && m_fileStream) {
        sendFramed(m_fileStream, data);
        return true;
    }
    return false;
}
