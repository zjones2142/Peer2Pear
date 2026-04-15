#pragma once
// nice/agent.h pulls in GLib's gio headers which use a struct member named
// 'signals' — this clashes with Qt5's 'signals' macro. Disable it for GLib.
#undef signals
#include <nice/agent.h>
#define signals Q_SIGNALS

#include <QObject>
#include <QThread>
#include <QString>
#include <QByteArray>
#include <atomic>

class NiceConnection : public QThread {
    Q_OBJECT
public:
    explicit NiceConnection(QObject* parent = nullptr);
    ~NiceConnection();

    // Initialize the ICE agent. One side must be 'controlling' (the offerer).
    // Optionally provide TURN relay credentials for symmetric-NAT fallback.
    void initIce(bool controlling);
    void setTurnServer(const QString& host, int port,
                       const QString& username, const QString& password);

    // Parse the SDP string received from the peer via the mailbox
    void setRemoteSdp(const QString& sdp);

    // Send data directly over the P2P connection
    void sendData(const QByteArray& data);

    // Check if the ICE connection is established
    bool isReady() const;

    // Get the selected peer's transport address after ICE completes.
    // Returns true and populates host/port. Returns false if not ready.
    bool getSelectedPeerAddress(QString& host, quint16& port) const;

    // Check if the selected candidate pair uses a TURN relay.
    bool isRelayed() const;

Q_SIGNALS:  // Q_SIGNALS avoids conflict with GLib's gio 'signals' struct member
    void localSdpReady(const QString& sdp);
    void stateChanged(int state); // Emits NiceComponentState
    void dataReceived(const QByteArray& data);

protected:
    void run() override;

private:
    static void cbCandidateGatheringDone(NiceAgent* agent, guint stream_id, gpointer data);
    static void cbComponentStateChanged(NiceAgent* agent, guint stream_id, guint component_id, guint state, gpointer data);
    static void cbRecv(NiceAgent* agent, guint stream_id, guint component_id, guint len, gchar* buf, gpointer data);

    NiceAgent* m_agent = nullptr;
    GMainContext* m_context = nullptr;
    GMainLoop* m_loop = nullptr;
    guint m_streamId = 0;
    std::atomic<int> m_state;

    // TURN relay config (set before initIce)
    QString m_turnHost;
    int     m_turnPort = 0;
    QString m_turnUser;
    QString m_turnPass;
};
