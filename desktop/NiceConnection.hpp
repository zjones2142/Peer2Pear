#pragma once
//
// NiceConnection — ICE NAT-traversal layer (libnice + GLib).
//
// Plain C++ class.  No Qt inheritance, no Qt types — the Phase 7d Qt strip
// (2026-04-18) replaced the former QThread base + QObject signals with a
// `std::thread` + `std::function` callbacks pattern.  This keeps the door
// open for cross-platform P2P; libnice itself is C-only.
//
// **Threading model:** initIce() spawns a worker thread that runs the GLib
// main loop.  All libnice callbacks (and therefore all of the on* callbacks
// below) fire on that worker thread.  Callers must marshal back to their
// own thread if they need it (desktop's QuicConnection runs on the GLib
// thread by design — no marshaling needed there).

// nice/agent.h pulls in GLib's gio headers which use a struct member named
// 'signals' — this clashes with Qt5's 'signals' macro when this header is
// transitively included from a translation unit that also pulls in Qt.
// Disable it for GLib here.
#undef signals
#include <nice/agent.h>
#define signals Q_SIGNALS

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

class NiceConnection {
public:
    using Bytes = std::vector<uint8_t>;

    NiceConnection();
    ~NiceConnection();

    NiceConnection(const NiceConnection&) = delete;
    NiceConnection& operator=(const NiceConnection&) = delete;

    // Initialize the ICE agent.  One side must be 'controlling' (the offerer).
    // Optionally provide TURN relay credentials for symmetric-NAT fallback.
    void initIce(bool controlling);
    void setTurnServer(const std::string& host, int port,
                       const std::string& username, const std::string& password);

    // Parse the SDP string received from the peer via the mailbox.
    void setRemoteSdp(const std::string& sdp);

    // Send data directly over the P2P connection.
    void sendData(const Bytes& data);

    // Check if the ICE connection is established.
    bool isReady() const;

    // Get the selected peer's transport address after ICE completes.
    // Returns true and populates host/port.  Returns false if not ready.
    bool getSelectedPeerAddress(std::string& host, uint16_t& port) const;

    // Check if the selected candidate pair uses a TURN relay.
    bool isRelayed() const;

    // ── Event callbacks (assign before / shortly after initIce). ──────────
    // All fire on the GLib worker thread; see threading note above.
    std::function<void(const std::string& sdp)>      onLocalSdpReady;
    std::function<void(int niceComponentState)>      onStateChanged;
    std::function<void(const Bytes& payload)>        onDataReceived;

private:
    static void cbCandidateGatheringDone(NiceAgent* agent, guint stream_id, gpointer data);
    static void cbComponentStateChanged(NiceAgent* agent, guint stream_id, guint component_id, guint state, gpointer data);
    static void cbRecv(NiceAgent* agent, guint stream_id, guint component_id, guint len, gchar* buf, gpointer data);

    void runMainLoop();   // body of the worker thread

    NiceAgent*       m_agent   = nullptr;
    GMainContext*    m_context = nullptr;
    GMainLoop*       m_loop    = nullptr;
    guint            m_streamId = 0;
    std::atomic<int> m_state;
    std::thread      m_thread;

    // TURN relay config (set before initIce).
    std::string m_turnHost;
    int         m_turnPort = 0;
    std::string m_turnUser;
    std::string m_turnPass;
};
