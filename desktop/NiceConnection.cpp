#include "NiceConnection.hpp"
#include "log.hpp"
#include <sodium.h>
#include <cstring>

NiceConnection::NiceConnection()
    : m_state(NICE_COMPONENT_STATE_DISCONNECTED) {}

NiceConnection::~NiceConnection() {
    if (m_agent) {
        nice_agent_close_async(m_agent, nullptr, nullptr);
    }
    if (m_loop) {
        g_main_loop_quit(m_loop);
        if (m_thread.joinable()) m_thread.join();
        g_main_loop_unref(m_loop);
        g_main_context_unref(m_context);
    }
    if (m_agent) g_object_unref(m_agent);
    // Zero TURN credentials in memory.
    if (!m_turnUser.empty()) {
        sodium_memzero(m_turnUser.data(), m_turnUser.size());
        m_turnUser.clear();
    }
    if (!m_turnPass.empty()) {
        sodium_memzero(m_turnPass.data(), m_turnPass.size());
        m_turnPass.clear();
    }
}

void NiceConnection::setTurnServer(const std::string& host, int port,
                                    const std::string& username, const std::string& password) {
    m_turnHost = host;
    m_turnPort = port;
    m_turnUser = username;
    m_turnPass = password;
}

void NiceConnection::initIce(bool controlling) {
    m_context = g_main_context_new();
    m_loop = g_main_loop_new(m_context, FALSE);

    m_agent = nice_agent_new(m_context, NICE_COMPATIBILITY_RFC5245);
    g_object_set(G_OBJECT(m_agent), "controlling-mode", controlling ? TRUE : FALSE, NULL);

    // Add a public STUN server for NAT traversal.
    g_object_set(G_OBJECT(m_agent), "stun-server", "stun.l.google.com", NULL);
    g_object_set(G_OBJECT(m_agent), "stun-server-port", 19302, NULL);

    m_streamId = nice_agent_add_stream(m_agent, 1);

    // Add TURN relay server if configured (required for symmetric NAT).
    if (!m_turnHost.empty() && m_turnPort > 0) {
        nice_agent_set_relay_info(m_agent, m_streamId, 1,
            m_turnHost.c_str(), m_turnPort,
            m_turnUser.c_str(), m_turnPass.c_str(),
            NICE_RELAY_TYPE_TURN_UDP);
        P2P_LOG("[ICE] TURN relay configured: " << m_turnHost << ":" << m_turnPort);
    }

    g_signal_connect(G_OBJECT(m_agent), "candidate-gathering-done", G_CALLBACK(cbCandidateGatheringDone), this);
    g_signal_connect(G_OBJECT(m_agent), "component-state-changed", G_CALLBACK(cbComponentStateChanged), this);

    nice_agent_attach_recv(m_agent, m_streamId, 1, m_context, cbRecv, this);

    // Run the GLib main loop on a worker thread; libnice callbacks fire there.
    m_thread = std::thread([this]() { runMainLoop(); });
    nice_agent_gather_candidates(m_agent, m_streamId);
}

void NiceConnection::setRemoteSdp(const std::string& sdp) {
    if (m_agent) {
        int parsed = nice_agent_parse_remote_sdp(m_agent, sdp.c_str());
        P2P_LOG("[ICE] setRemoteSdp: parsed " << parsed << " candidates"
                << " | sdp length: " << sdp.size());
    } else {
        P2P_WARN("[ICE] setRemoteSdp: agent is null!");
    }
}

void NiceConnection::sendData(const Bytes& data) {
    if (m_agent && isReady()) {
        nice_agent_send(m_agent, m_streamId, 1,
                        static_cast<guint>(data.size()),
                        reinterpret_cast<const gchar*>(data.data()));
    }
}

bool NiceConnection::isReady() const {
    return m_state == NICE_COMPONENT_STATE_READY;
}

bool NiceConnection::getSelectedPeerAddress(std::string& host, uint16_t& port) const {
    if (!m_agent || !isReady()) return false;

    NiceCandidate* local = nullptr;
    NiceCandidate* remote = nullptr;
    if (!nice_agent_get_selected_pair(m_agent, m_streamId, 1, &local, &remote))
        return false;

    if (!remote) return false;

    gchar addrStr[NICE_ADDRESS_STRING_LEN];
    nice_address_to_string(&remote->addr, addrStr);
    host = addrStr;
    port = static_cast<uint16_t>(nice_address_get_port(&remote->addr));
    return true;
}

bool NiceConnection::isRelayed() const {
    if (!m_agent || !isReady()) return false;

    NiceCandidate* local = nullptr;
    NiceCandidate* remote = nullptr;
    if (!nice_agent_get_selected_pair(m_agent, m_streamId, 1, &local, &remote))
        return false;

    // If either candidate is RELAYED, we're going through TURN.
    return (local && local->type == NICE_CANDIDATE_TYPE_RELAYED) ||
           (remote && remote->type == NICE_CANDIDATE_TYPE_RELAYED);
}

void NiceConnection::runMainLoop() {
    g_main_loop_run(m_loop);
}

void NiceConnection::cbCandidateGatheringDone(NiceAgent* agent, guint /*stream_id*/, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    gchar* sdp = nice_agent_generate_local_sdp(agent);
    std::string sdpStr = sdp ? sdp : "";
    P2P_LOG("[ICE] Candidate gathering done | sdp length: " << sdpStr.size());
    if (self->onLocalSdpReady) self->onLocalSdpReady(sdpStr);
    g_free(sdp);
}

void NiceConnection::cbComponentStateChanged(NiceAgent* /*agent*/, guint /*stream_id*/, guint /*component_id*/, guint state, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    self->m_state = state;

    static const char* stateNames[] = {
        "DISCONNECTED", "GATHERING", "CONNECTING",
        "CONNECTED", "READY", "FAILED", "LAST"
    };
    const char* name = (state < 7) ? stateNames[state] : "UNKNOWN";
    P2P_LOG("[ICE] State changed: " << name << " (" << state << ")");

    if (self->onStateChanged) self->onStateChanged(static_cast<int>(state));
}

void NiceConnection::cbRecv(NiceAgent* /*agent*/, guint /*stream_id*/, guint /*component_id*/, guint len, gchar* buf, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    if (self->onDataReceived) {
        Bytes payload(reinterpret_cast<const uint8_t*>(buf),
                      reinterpret_cast<const uint8_t*>(buf) + len);
        self->onDataReceived(payload);
    }
}
