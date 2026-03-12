#include "NiceConnection.hpp"

NiceConnection::NiceConnection(QObject* parent)
    : QThread(parent), m_state(NICE_COMPONENT_STATE_DISCONNECTED) {}

NiceConnection::~NiceConnection() {
    if (m_loop) {
        g_main_loop_quit(m_loop);
        wait(); // Wait for thread to exit
        g_main_loop_unref(m_loop);
        g_main_context_unref(m_context);
    }
    if (m_agent) g_object_unref(m_agent);
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

    g_signal_connect(G_OBJECT(m_agent), "candidate-gathering-done", G_CALLBACK(cbCandidateGatheringDone), this);
    g_signal_connect(G_OBJECT(m_agent), "component-state-changed", G_CALLBACK(cbComponentStateChanged), this);

    nice_agent_attach_recv(m_agent, m_streamId, 1, m_context, cbRecv, this);

    start(); // Start the GMainLoop inside QThread
    nice_agent_gather_candidates(m_agent, m_streamId);
}

void NiceConnection::setRemoteSdp(const QString& sdp) {
    if (m_agent) {
        nice_agent_parse_remote_sdp(m_agent, sdp.toUtf8().constData());
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
    emit self->localSdpReady(QString::fromUtf8(sdp));
    g_free(sdp);
}

void NiceConnection::cbComponentStateChanged(NiceAgent* agent, guint stream_id, guint component_id, guint state, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    self->m_state = state;
    emit self->stateChanged(state);
}

void NiceConnection::cbRecv(NiceAgent* agent, guint stream_id, guint component_id, guint len, gchar* buf, gpointer data) {
    NiceConnection* self = static_cast<NiceConnection*>(data);
    QByteArray payload(buf, len);
    emit self->dataReceived(payload);
}
