#include "NiceConnection.hpp"
#include <QDebug>

NiceConnection::NiceConnection(QObject* parent)
    : QThread(parent), m_state(NICE_COMPONENT_STATE_DISCONNECTED) {}

NiceConnection::~NiceConnection() {
    if (m_agent) {
        nice_agent_close_async(m_agent, nullptr, nullptr);
    }
    if (m_loop) {
        g_main_loop_quit(m_loop);
        wait(); // Wait for thread to exit
        g_main_loop_unref(m_loop);
        g_main_context_unref(m_context);
    }
    if (m_agent) g_object_unref(m_agent);
}

void NiceConnection::setTurnServer(const QString& host, int port,
                                    const QString& username, const QString& password) {
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

    // Add a public STUN server for NAT traversal
    g_object_set(G_OBJECT(m_agent), "stun-server", "stun.l.google.com", NULL);
    g_object_set(G_OBJECT(m_agent), "stun-server-port", 19302, NULL);

    m_streamId = nice_agent_add_stream(m_agent, 1);

    // Add TURN relay server if configured (required for symmetric NAT)
    if (!m_turnHost.isEmpty() && m_turnPort > 0) {
        nice_agent_set_relay_info(m_agent, m_streamId, 1,
            m_turnHost.toUtf8().constData(), m_turnPort,
            m_turnUser.toUtf8().constData(), m_turnPass.toUtf8().constData(),
            NICE_RELAY_TYPE_TURN_UDP);
        qDebug() << "[ICE] TURN relay configured:" << m_turnHost << ":" << m_turnPort;
    }

    g_signal_connect(G_OBJECT(m_agent), "candidate-gathering-done", G_CALLBACK(cbCandidateGatheringDone), this);
    g_signal_connect(G_OBJECT(m_agent), "component-state-changed", G_CALLBACK(cbComponentStateChanged), this);

    nice_agent_attach_recv(m_agent, m_streamId, 1, m_context, cbRecv, this);

    start(); // Start the GMainLoop inside QThread
    nice_agent_gather_candidates(m_agent, m_streamId);
}

void NiceConnection::setRemoteSdp(const QString& sdp) {
    if (m_agent) {
        int parsed = nice_agent_parse_remote_sdp(m_agent, sdp.toUtf8().constData());
        qDebug() << "[ICE] setRemoteSdp: parsed" << parsed << "candidates"
                 << "| sdp length:" << sdp.size();
    } else {
        qDebug() << "[ICE] setRemoteSdp: agent is null!";
    }
}

void NiceConnection::sendData(const QByteArray& data) {
    if (m_agent && isReady()) {
        nice_agent_send(m_agent, m_streamId, 1, data.size(), data.constData());
    }
}

bool NiceConnection::isReady() const {
    return m_state == NICE_COMPONENT_STATE_READY;
}

void NiceConnection::run() {
    g_main_loop_run(m_loop);
}

void NiceConnection::cbCandidateGatheringDone(NiceAgent* agent, guint stream_id, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    gchar* sdp = nice_agent_generate_local_sdp(agent);
    QString sdpStr = QString::fromUtf8(sdp);
    qDebug() << "[ICE] Candidate gathering done | sdp length:" << sdpStr.size();
    emit self->localSdpReady(sdpStr);
    g_free(sdp);
}

void NiceConnection::cbComponentStateChanged(NiceAgent* agent, guint stream_id, guint component_id, guint state, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    self->m_state = state;

    static const char* stateNames[] = {
        "DISCONNECTED", "GATHERING", "CONNECTING",
        "CONNECTED", "READY", "FAILED", "LAST"
    };
    const char* name = (state < 7) ? stateNames[state] : "UNKNOWN";
    qDebug() << "[ICE] State changed:" << name << "(" << state << ")";

    emit self->stateChanged(state);
}

void NiceConnection::cbRecv(NiceAgent* agent, guint stream_id, guint component_id, guint len, gchar* buf, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    QByteArray payload(buf, len);
    emit self->dataReceived(payload);
}
