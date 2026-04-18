/*
 * peer2pear_api.cpp — C API implementation
 *
 * Bridges the C FFI boundary to the C++ core. Contains:
 *   - CWebSocket:   IWebSocket impl that delegates to C function pointers
 *   - CHttpClient:  IHttpClient impl that delegates to C function pointers
 *   - p2p_context:  opaque struct owning ChatController + crypto + DB
 *   - All p2p_* function implementations
 */

#include "peer2pear.h"
#include "IWebSocket.hpp"
#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "ChatController.hpp"
#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"
#include "SessionStore.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QUrl>
#include <QMap>
#include <QDateTime>
#include <QStringList>
#include <QTimer>

#include <string>
#include <map>
#include <functional>
#include <mutex>

// ── CWebSocket: IWebSocket backed by C function pointers ────────────────────

class CWebSocket : public IWebSocket {
public:
    explicit CWebSocket(p2p_platform platform) : m_p(platform) {}

    void open(const std::string& url) override {
        if (m_p.ws_open)
            m_p.ws_open(url.c_str(), m_p.platform_ctx);
    }

    void close() override {
        if (m_p.ws_close)
            m_p.ws_close(m_p.platform_ctx);
    }

    bool isConnected() const override {
        return m_p.ws_is_connected
            ? m_p.ws_is_connected(m_p.platform_ctx) != 0
            : false;
    }

    bool isIdle() const override {
        return m_p.ws_is_idle
            ? m_p.ws_is_idle(m_p.platform_ctx) != 0
            : true;
    }

    void sendTextMessage(const std::string& message) override {
        if (m_p.ws_send_text)
            m_p.ws_send_text(message.c_str(), m_p.platform_ctx);
    }

private:
    p2p_platform m_p;
};

// ── CHttpClient: IHttpClient backed by C function pointers ──────────────────

class CHttpClient : public IHttpClient {
public:
    explicit CHttpClient(p2p_platform platform) : m_p(platform) {}

    void post(const std::string& url,
              const Bytes& body,
              const Headers& headers,
              Callback cb) override
    {
        if (!m_p.http_post) {
            if (cb) cb({ 0, {}, "http_post not implemented" });
            return;
        }

        // Convert headers to C arrays (copies live in keyStore/valStore)
        std::vector<const char*> keys, vals;
        keys.reserve(headers.size());
        vals.reserve(headers.size());
        for (const auto& [k, v] : headers) {
            keys.push_back(k.c_str());
            vals.push_back(v.c_str());
        }

        int reqId = m_p.http_post(
            url.c_str(),
            body.empty() ? nullptr : body.data(),
            static_cast<int>(body.size()),
            keys.empty() ? nullptr : keys.data(),
            vals.empty() ? nullptr : vals.data(),
            static_cast<int>(keys.size()),
            m_p.platform_ctx);

        // Store callback keyed by request ID
        std::lock_guard<std::mutex> lock(m_mu);
        m_pending[reqId] = std::move(cb);
    }

    void get(const std::string& url,
             const Headers& headers,
             Callback cb) override
    {
        // Mobile FFI doesn't carry a dedicated http_get function pointer yet.
        // Reuse http_post with an empty body + X-HTTP-Method: GET header so
        // the platform adapter can distinguish GET from POST without new
        // FFI surface.
        if (!m_p.http_post) {
            if (cb) cb({ 0, {}, "http_get not implemented" });
            return;
        }

        Headers hdrs = headers;
        hdrs["X-HTTP-Method"] = "GET";

        std::vector<const char*> keys, vals;
        keys.reserve(hdrs.size());
        vals.reserve(hdrs.size());
        for (const auto& [k, v] : hdrs) {
            keys.push_back(k.c_str());
            vals.push_back(v.c_str());
        }

        int reqId = m_p.http_post(
            url.c_str(),
            nullptr, 0,  // empty body + X-HTTP-Method header signals GET
            keys.empty() ? nullptr : keys.data(),
            vals.empty() ? nullptr : vals.data(),
            static_cast<int>(keys.size()),
            m_p.platform_ctx);

        std::lock_guard<std::mutex> lock(m_mu);
        m_pending[reqId] = std::move(cb);
    }

    // Called by p2p_http_response() when platform delivers the result
    void onResponse(int requestId, int status,
                    const uint8_t* body, int bodyLen,
                    const char* error)
    {
        Callback cb;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            auto it = m_pending.find(requestId);
            if (it == m_pending.end()) return;
            cb = std::move(it->second);
            m_pending.erase(it);
        }

        Response resp;
        resp.status = status;
        if (body && bodyLen > 0)
            resp.body.assign(body, body + bodyLen);
        if (error)
            resp.error = error;
        if (cb) cb(resp);
    }

private:
    p2p_platform m_p;
    std::mutex m_mu;
    std::map<int, Callback> m_pending;
};

// ── Timer factory: Qt-based for now; Phase 8 routes through platform cbs. ──
//
// peer2pear_api currently links Qt::Core (core/CMakeLists still depends on
// it).  When that drops and iOS builds start, this factory is replaced by
// a CTimerFactory that calls platform-provided scheduling functions via
// p2p_platform.  Kept inline here so there's exactly one place to swap.

class QtApiTimer : public ITimer {
public:
    QtApiTimer() {
        m_t.setSingleShot(true);
        QObject::connect(&m_t, &QTimer::timeout, &m_t, [this]() {
            if (m_cb) m_cb();
        });
    }
    void startSingleShot(int delayMs, std::function<void()> cb) override {
        m_cb = std::move(cb);
        m_t.start(delayMs);
    }
    void stop() override { m_t.stop(); m_cb = {}; }
    bool isActive() const override { return m_t.isActive(); }
private:
    QTimer m_t;
    std::function<void()> m_cb;
};

class QtApiTimerFactory : public ITimerFactory {
public:
    std::unique_ptr<ITimer> create() override { return std::make_unique<QtApiTimer>(); }
    void singleShot(int delayMs, std::function<void()> cb) override {
        QTimer::singleShot(delayMs, [cb = std::move(cb)]() { if (cb) cb(); });
    }
};

// ── p2p_context: the opaque handle ──────────────────────────────────────────

struct p2p_context {
    CWebSocket        ws;
    CHttpClient       http;
    QtApiTimerFactory timers;
    ChatController    controller;

    // Scratch buffer for returning strings (valid until next call)
    std::string  scratch;

    // Event callbacks + user data
    struct {
        void (*on_status)(const char*, void*) = nullptr;
        void* status_ud = nullptr;

        void (*on_connected)(void*) = nullptr;
        void* connected_ud = nullptr;

        void (*on_message)(const char*, const char*, int64_t, const char*, void*) = nullptr;
        void* message_ud = nullptr;

        void (*on_group_message)(const char*, const char*, const char*,
                                 const char**, const char*, int64_t, const char*, void*) = nullptr;
        void* group_message_ud = nullptr;

        void (*on_presence)(const char*, int, void*) = nullptr;
        void* presence_ud = nullptr;

        void (*on_file_progress)(const char*, const char*, const char*,
                                 int64_t, int, int, const char*, int64_t, void*) = nullptr;
        void* file_progress_ud = nullptr;

        void (*on_avatar)(const char*, const char*, const char*, void*) = nullptr;
        void* avatar_ud = nullptr;

        // Phase 2
        void (*on_file_request)(const char*, const char*, const char*, int64_t, void*) = nullptr;
        void* file_request_ud = nullptr;

        void (*on_file_canceled)(const char*, int, void*) = nullptr;
        void* file_canceled_ud = nullptr;

        // Phase 3
        void (*on_file_delivered)(const char*, void*) = nullptr;
        void* file_delivered_ud = nullptr;

        void (*on_file_blocked)(const char*, int, void*) = nullptr;
        void* file_blocked_ud = nullptr;
    } cb;

    QString dataDir;

    p2p_context(p2p_platform platform)
        : ws(platform)
        , http(platform)
        , controller(ws, http, timers)
    {}
};

// ── Helper: assign ChatController callbacks → C FFI callbacks ──────────────
//
// ChatController is a plain class now (Phase 7b); direct assignment replaces
// QObject::connect.  The callback signatures are still Qt-typed at this
// layer (QString/QDateTime); the Qt-free conversion happens when
// ChatController's signatures migrate to std types in a future pass.

static void wire_signals(p2p_context* ctx)
{
    auto& c = ctx->controller;

    c.onStatus = [ctx](const QString& s) {
        if (ctx->cb.on_status) {
            const QByteArray u = s.toUtf8();
            ctx->cb.on_status(u.constData(), ctx->cb.status_ud);
        }
    };

    c.onRelayConnected = [ctx]() {
        if (ctx->cb.on_connected) ctx->cb.on_connected(ctx->cb.connected_ud);
    };

    c.onPresenceChanged = [ctx](const QString& peerId, bool online) {
        if (ctx->cb.on_presence) {
            const QByteArray id = peerId.toUtf8();
            ctx->cb.on_presence(id.constData(), online ? 1 : 0, ctx->cb.presence_ud);
        }
    };

    c.onMessageReceived = [ctx](const QString& from, const QString& text,
                                 const QDateTime& ts, const QString& msgId) {
        if (ctx->cb.on_message) {
            const QByteArray f = from.toUtf8();
            const QByteArray t = text.toUtf8();
            const QByteArray m = msgId.toUtf8();
            ctx->cb.on_message(f.constData(), t.constData(),
                               ts.toSecsSinceEpoch(), m.constData(),
                               ctx->cb.message_ud);
        }
    };

    c.onGroupMessageReceived = [ctx](const QString& from, const QString& groupId,
                                      const QString& groupName,
                                      const QStringList& memberKeys,
                                      const QString& text, const QDateTime& ts,
                                      const QString& msgId) {
        if (ctx->cb.on_group_message) {
            const QByteArray f = from.toUtf8();
            const QByteArray gid = groupId.toUtf8();
            const QByteArray gn = groupName.toUtf8();
            const QByteArray t = text.toUtf8();
            const QByteArray m = msgId.toUtf8();

            std::vector<QByteArray> memberBufs;
            std::vector<const char*> memberPtrs;
            for (const QString& k : memberKeys) {
                memberBufs.push_back(k.toUtf8());
                memberPtrs.push_back(memberBufs.back().constData());
            }
            memberPtrs.push_back(nullptr);

            ctx->cb.on_group_message(
                f.constData(), gid.constData(), gn.constData(),
                memberPtrs.data(), t.constData(),
                ts.toSecsSinceEpoch(), m.constData(),
                ctx->cb.group_message_ud);
        }
    };

    c.onFileChunkReceived = [ctx](const QString& from, const QString& transferId,
                                   const QString& fileName, qint64 fileSize,
                                   int chunksRcvd, int chunksTotal,
                                   const QString& savedPath, const QDateTime& ts,
                                   const QString&, const QString&) {
        if (ctx->cb.on_file_progress) {
            const QByteArray f = from.toUtf8();
            const QByteArray tid = transferId.toUtf8();
            const QByteArray fn = fileName.toUtf8();
            const QByteArray sp = savedPath.toUtf8();
            ctx->cb.on_file_progress(
                f.constData(), tid.constData(), fn.constData(),
                fileSize, chunksRcvd, chunksTotal,
                savedPath.isEmpty() ? nullptr : sp.constData(),
                ts.toSecsSinceEpoch(),
                ctx->cb.file_progress_ud);
        }
    };

    c.onAvatarReceived = [ctx](const QString& peerId, const QString& name,
                                const QString& b64) {
        if (ctx->cb.on_avatar) {
            const QByteArray p = peerId.toUtf8();
            const QByteArray n = name.toUtf8();
            const QByteArray a = b64.toUtf8();
            ctx->cb.on_avatar(p.constData(), n.constData(), a.constData(),
                              ctx->cb.avatar_ud);
        }
    };

    c.onFileAcceptRequested = [ctx](const QString& from, const QString& tid,
                                     const QString& fileName, qint64 fileSize) {
        if (ctx->cb.on_file_request) {
            const QByteArray f  = from.toUtf8();
            const QByteArray t  = tid.toUtf8();
            const QByteArray fn = fileName.toUtf8();
            ctx->cb.on_file_request(f.constData(), t.constData(), fn.constData(),
                                    fileSize, ctx->cb.file_request_ud);
        }
    };

    c.onFileTransferCanceled = [ctx](const QString& tid, bool byReceiver) {
        if (ctx->cb.on_file_canceled) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_canceled(t.constData(), byReceiver ? 1 : 0,
                                     ctx->cb.file_canceled_ud);
        }
    };

    c.onFileTransferDelivered = [ctx](const QString& tid) {
        if (ctx->cb.on_file_delivered) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_delivered(t.constData(), ctx->cb.file_delivered_ud);
        }
    };

    c.onFileTransferBlocked = [ctx](const QString& tid, bool byReceiver) {
        if (ctx->cb.on_file_blocked) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_blocked(t.constData(), byReceiver ? 1 : 0,
                                    ctx->cb.file_blocked_ud);
        }
    };
}

// ── C API implementation ────────────────────────────────────────────────────

p2p_context* p2p_create(const char* data_dir, p2p_platform platform)
{
    auto* ctx = new p2p_context(platform);
    ctx->dataDir = QString::fromUtf8(data_dir);
    // Route identity.json and salt files to the host-provided directory.
    // Without this, iOS/Android would try to read/write to a non-existent
    // QStandardPaths::AppDataLocation path.
    if (!ctx->dataDir.isEmpty())
        ctx->controller.setDataDir(ctx->dataDir);
    wire_signals(ctx);
    return ctx;
}

void p2p_destroy(p2p_context* ctx)
{
    if (ctx) {
        ctx->controller.disconnectFromRelay();
        delete ctx;
    }
}

void p2p_set_passphrase(p2p_context* ctx, const char* passphrase)
{
    if (!ctx) return;
    ctx->controller.setPassphrase(QString::fromUtf8(passphrase));
}

const char* p2p_my_id(p2p_context* ctx)
{
    if (!ctx) return "";
    ctx->scratch = ctx->controller.myIdB64u().toStdString();
    return ctx->scratch.c_str();
}

void p2p_set_relay_url(p2p_context* ctx, const char* url)
{
    if (!ctx) return;
    ctx->controller.setRelayUrl(QUrl(QString::fromUtf8(url)));
}

void p2p_connect(p2p_context* ctx)
{
    if (ctx) ctx->controller.connectToRelay();
}

void p2p_disconnect(p2p_context* ctx)
{
    if (ctx) ctx->controller.disconnectFromRelay();
}

int p2p_send_text(p2p_context* ctx, const char* peer_id, const char* text)
{
    if (!ctx || !peer_id || !text) return -1;
    ctx->controller.sendText(QString::fromUtf8(peer_id), QString::fromUtf8(text));
    return 0;
}

int p2p_send_group_text(p2p_context* ctx,
                        const char* group_id,
                        const char* group_name,
                        const char** member_ids,
                        const char* text)
{
    if (!ctx || !group_id || !text || !member_ids) return -1;
    QStringList members;
    for (const char** p = member_ids; *p; ++p)
        members << QString::fromUtf8(*p);
    ctx->controller.sendGroupMessageViaMailbox(
        QString::fromUtf8(group_id),
        QString::fromUtf8(group_name ? group_name : ""),
        members, QString::fromUtf8(text));
    return 0;
}

const char* p2p_send_file(p2p_context* ctx,
                          const char* peer_id,
                          const char* file_name,
                          const char* file_path)
{
    if (!ctx || !peer_id || !file_name || !file_path) return nullptr;
    QString tid = ctx->controller.sendFile(
        QString::fromUtf8(peer_id),
        QString::fromUtf8(file_name),
        QString::fromUtf8(file_path));
    if (tid.isEmpty()) return nullptr;
    ctx->scratch = tid.toStdString();
    return ctx->scratch.c_str();
}

// ── Phase 2: file consent + cancel ──────────────────────────────────────────

void p2p_respond_file_request(p2p_context* ctx,
                              const char* transfer_id,
                              int accept,
                              int require_p2p)
{
    if (!ctx || !transfer_id) return;
    const QString tid = QString::fromUtf8(transfer_id);
    if (accept) {
        ctx->controller.acceptFileTransfer(tid, require_p2p != 0);
    } else {
        ctx->controller.declineFileTransfer(tid);
    }
}

void p2p_cancel_transfer(p2p_context* ctx, const char* transfer_id)
{
    if (!ctx || !transfer_id) return;
    ctx->controller.cancelFileTransfer(QString::fromUtf8(transfer_id));
}

void p2p_set_file_auto_accept_mb(p2p_context* ctx, int mb)
{
    if (ctx) ctx->controller.setFileAutoAcceptMaxMB(mb);
}

void p2p_set_file_hard_max_mb(p2p_context* ctx, int mb)
{
    if (ctx) ctx->controller.setFileHardMaxMB(mb);
}

void p2p_set_file_require_p2p(p2p_context* ctx, int enabled)
{
    if (ctx) ctx->controller.setFileRequireP2P(enabled != 0);
}

void p2p_check_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    QStringList ids;
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids << QString::fromUtf8(peer_ids[i]);
    ctx->controller.checkPresence(ids);
}

void p2p_subscribe_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    QStringList ids;
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids << QString::fromUtf8(peer_ids[i]);
    ctx->controller.subscribePresence(ids);
}

void p2p_add_send_relay(p2p_context* ctx, const char* url)
{
    if (!ctx || !url) return;
    ctx->controller.relay().addSendRelay(url ? std::string(url) : std::string());
}

void p2p_set_privacy_level(p2p_context* ctx, int level)
{
    if (!ctx) return;
    ctx->controller.relay().setPrivacyLevel(level);
}

// ── Platform → Core events ──────────────────────────────────────────────────

void p2p_ws_on_connected(p2p_context* ctx)
{
    if (ctx && ctx->ws.onConnected) ctx->ws.onConnected();
}

void p2p_ws_on_disconnected(p2p_context* ctx)
{
    if (ctx && ctx->ws.onDisconnected) ctx->ws.onDisconnected();
}

void p2p_ws_on_binary(p2p_context* ctx, const uint8_t* data, int len)
{
    if (ctx && ctx->ws.onBinaryMessage) {
        IWebSocket::Bytes buf(data, data + len);
        ctx->ws.onBinaryMessage(buf);
    }
}

void p2p_ws_on_text(p2p_context* ctx, const char* message)
{
    if (ctx && ctx->ws.onTextMessage)
        ctx->ws.onTextMessage(message ? std::string(message) : std::string());
}

void p2p_http_response(p2p_context* ctx, int request_id,
                       int status, const uint8_t* body, int body_len,
                       const char* error)
{
    if (ctx)
        ctx->http.onResponse(request_id, status, body, body_len, error);
}

// ── Event callback setters ──────────────────────────────────────────────────

void p2p_set_on_status(p2p_context* ctx,
    void (*cb)(const char*, void*), void* ud)
{
    if (!ctx) return;
    ctx->cb.on_status = cb;
    ctx->cb.status_ud = ud;
}

void p2p_set_on_connected(p2p_context* ctx,
    void (*cb)(void*), void* ud)
{
    if (!ctx) return;
    ctx->cb.on_connected = cb;
    ctx->cb.connected_ud = ud;
}

void p2p_set_on_message(p2p_context* ctx,
    void (*cb)(const char*, const char*, int64_t, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_message = cb;
    ctx->cb.message_ud = ud;
}

void p2p_set_on_group_message(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               const char**, const char*, int64_t, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_group_message = cb;
    ctx->cb.group_message_ud = ud;
}

void p2p_set_on_presence(p2p_context* ctx,
    void (*cb)(const char*, int, void*), void* ud)
{
    if (!ctx) return;
    ctx->cb.on_presence = cb;
    ctx->cb.presence_ud = ud;
}

void p2p_set_on_file_progress(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               int64_t, int, int, const char*, int64_t, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_file_progress = cb;
    ctx->cb.file_progress_ud = ud;
}

void p2p_set_on_avatar(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_avatar = cb;
    ctx->cb.avatar_ud = ud;
}

void p2p_set_on_file_request(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*, int64_t, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_file_request    = cb;
    ctx->cb.file_request_ud    = ud;
}

void p2p_set_on_file_canceled(p2p_context* ctx,
    void (*cb)(const char*, int, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_file_canceled    = cb;
    ctx->cb.file_canceled_ud    = ud;
}

void p2p_set_on_file_delivered(p2p_context* ctx,
    void (*cb)(const char*, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_file_delivered    = cb;
    ctx->cb.file_delivered_ud    = ud;
}

void p2p_set_on_file_blocked(p2p_context* ctx,
    void (*cb)(const char*, int, void*),
    void* ud)
{
    if (!ctx) return;
    ctx->cb.on_file_blocked    = cb;
    ctx->cb.file_blocked_ud    = ud;
}
