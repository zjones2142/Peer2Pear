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

#include <string>
#include <map>
#include <functional>
#include <mutex>

// ── CWebSocket: IWebSocket backed by C function pointers ────────────────────

class CWebSocket : public IWebSocket {
public:
    explicit CWebSocket(p2p_platform platform) : m_p(platform) {}

    void open(const QUrl& url) override {
        if (m_p.ws_open)
            m_p.ws_open(url.toString().toUtf8().constData(), m_p.platform_ctx);
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

    void sendTextMessage(const QString& message) override {
        if (m_p.ws_send_text)
            m_p.ws_send_text(message.toUtf8().constData(), m_p.platform_ctx);
    }

private:
    p2p_platform m_p;
};

// ── CHttpClient: IHttpClient backed by C function pointers ──────────────────

class CHttpClient : public IHttpClient {
public:
    explicit CHttpClient(p2p_platform platform) : m_p(platform) {}

    void post(const QUrl& url,
              const QByteArray& body,
              const QMap<QString, QString>& headers,
              Callback cb) override
    {
        if (!m_p.http_post) {
            if (cb) cb({ 0, {}, "http_post not implemented" });
            return;
        }

        // Convert headers to C arrays
        std::vector<std::string> keyStore, valStore;
        std::vector<const char*> keys, vals;
        for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
            keyStore.push_back(it.key().toStdString());
            valStore.push_back(it.value().toStdString());
            keys.push_back(keyStore.back().c_str());
            vals.push_back(valStore.back().c_str());
        }

        int reqId = m_p.http_post(
            url.toString().toUtf8().constData(),
            reinterpret_cast<const uint8_t*>(body.constData()), body.size(),
            keys.empty() ? nullptr : keys.data(),
            vals.empty() ? nullptr : vals.data(),
            static_cast<int>(keys.size()),
            m_p.platform_ctx);

        // Store callback keyed by request ID
        std::lock_guard<std::mutex> lock(m_mu);
        m_pending[reqId] = std::move(cb);
    }

    void get(const QUrl& url,
             const QMap<QString, QString>& headers,
             Callback cb) override
    {
        // Mobile FFI doesn't carry a dedicated http_get function pointer yet.
        // Reuse http_post with an empty body — the platform adapter on the
        // other side can issue a GET when body size is 0, or explicitly handle
        // "GET" via a header the onion code sets.  For now, if the platform
        // sets http_post, we route the GET through it; otherwise fail.
        if (!m_p.http_post) {
            if (cb) cb({ 0, {}, "http_get not implemented" });
            return;
        }

        // Convert headers and add a X-HTTP-Method override so the platform
        // adapter can distinguish GET from POST without new FFI surface.
        QMap<QString, QString> hdrs = headers;
        hdrs["X-HTTP-Method"] = "GET";

        std::vector<std::string> keyStore, valStore;
        std::vector<const char*> keys, vals;
        for (auto it = hdrs.cbegin(); it != hdrs.cend(); ++it) {
            keyStore.push_back(it.key().toStdString());
            valStore.push_back(it.value().toStdString());
            keys.push_back(keyStore.back().c_str());
            vals.push_back(valStore.back().c_str());
        }

        int reqId = m_p.http_post(
            url.toString().toUtf8().constData(),
            nullptr, 0,  // empty body signals GET (in combination with X-HTTP-Method)
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
            resp.body = QByteArray(reinterpret_cast<const char*>(body), bodyLen);
        if (error)
            resp.error = QString::fromUtf8(error);
        if (cb) cb(resp);
    }

private:
    p2p_platform m_p;
    std::mutex m_mu;
    std::map<int, Callback> m_pending;
};

// ── p2p_context: the opaque handle ──────────────────────────────────────────

struct p2p_context {
    CWebSocket   ws;
    CHttpClient  http;
    ChatController controller;

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
        , controller(ws, http)
    {}
};

// ── Helper: connect Qt signals to C callbacks ───────────────────────────────

static void wire_signals(p2p_context* ctx)
{
    auto* c = &ctx->controller;

    QObject::connect(c, &ChatController::status, [ctx](const QString& s) {
        if (ctx->cb.on_status) {
            const QByteArray u = s.toUtf8();
            ctx->cb.on_status(u.constData(), ctx->cb.status_ud);
        }
    });

    QObject::connect(c, &ChatController::relayConnected, [ctx]() {
        if (ctx->cb.on_connected)
            ctx->cb.on_connected(ctx->cb.connected_ud);
    });

    QObject::connect(c, &ChatController::presenceChanged,
        [ctx](const QString& peerId, bool online) {
        if (ctx->cb.on_presence) {
            const QByteArray id = peerId.toUtf8();
            ctx->cb.on_presence(id.constData(), online ? 1 : 0, ctx->cb.presence_ud);
        }
    });

    QObject::connect(c, &ChatController::messageReceived,
        [ctx](const QString& from, const QString& text,
              const QDateTime& ts, const QString& msgId) {
        if (ctx->cb.on_message) {
            const QByteArray f = from.toUtf8();
            const QByteArray t = text.toUtf8();
            const QByteArray m = msgId.toUtf8();
            ctx->cb.on_message(f.constData(), t.constData(),
                               ts.toSecsSinceEpoch(), m.constData(),
                               ctx->cb.message_ud);
        }
    });

    QObject::connect(c, &ChatController::groupMessageReceived,
        [ctx](const QString& from, const QString& groupId, const QString& groupName,
              const QStringList& memberKeys, const QString& text,
              const QDateTime& ts, const QString& msgId) {
        if (ctx->cb.on_group_message) {
            const QByteArray f = from.toUtf8();
            const QByteArray gid = groupId.toUtf8();
            const QByteArray gn = groupName.toUtf8();
            const QByteArray t = text.toUtf8();
            const QByteArray m = msgId.toUtf8();

            // Build NULL-terminated member ID array
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
    });

    QObject::connect(c, &ChatController::fileChunkReceived,
        [ctx](const QString& from, const QString& transferId,
              const QString& fileName, qint64 fileSize,
              int chunksRcvd, int chunksTotal, const QString& savedPath,
              const QDateTime& ts, const QString& /*groupId*/,
              const QString& /*groupName*/) {
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
    });

    QObject::connect(c, &ChatController::avatarReceived,
        [ctx](const QString& peerId, const QString& name, const QString& b64) {
        if (ctx->cb.on_avatar) {
            const QByteArray p = peerId.toUtf8();
            const QByteArray n = name.toUtf8();
            const QByteArray a = b64.toUtf8();
            ctx->cb.on_avatar(p.constData(), n.constData(), a.constData(),
                              ctx->cb.avatar_ud);
        }
    });

    // Phase 2: file-consent prompt.
    QObject::connect(c, &ChatController::fileAcceptRequested,
        [ctx](const QString& from, const QString& tid,
              const QString& fileName, qint64 fileSize) {
        if (ctx->cb.on_file_request) {
            const QByteArray f  = from.toUtf8();
            const QByteArray t  = tid.toUtf8();
            const QByteArray fn = fileName.toUtf8();
            ctx->cb.on_file_request(f.constData(), t.constData(), fn.constData(),
                                    fileSize, ctx->cb.file_request_ud);
        }
    });

    // Phase 2: transfer canceled/declined either direction.
    QObject::connect(c, &ChatController::fileTransferCanceled,
        [ctx](const QString& tid, bool byReceiver) {
        if (ctx->cb.on_file_canceled) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_canceled(t.constData(), byReceiver ? 1 : 0,
                                     ctx->cb.file_canceled_ud);
        }
    });

    // Phase 3: delivery confirmation.
    QObject::connect(c, &ChatController::fileTransferDelivered,
        [ctx](const QString& tid) {
        if (ctx->cb.on_file_delivered) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_delivered(t.constData(), ctx->cb.file_delivered_ud);
        }
    });

    // Phase 3: transport-policy blocked.
    QObject::connect(c, &ChatController::fileTransferBlocked,
        [ctx](const QString& tid, bool byReceiver) {
        if (ctx->cb.on_file_blocked) {
            const QByteArray t = tid.toUtf8();
            ctx->cb.on_file_blocked(t.constData(), byReceiver ? 1 : 0,
                                    ctx->cb.file_blocked_ud);
        }
    });
}

// ── C API implementation ────────────────────────────────────────────────────

p2p_context* p2p_create(const char* data_dir, p2p_platform platform)
{
    auto* ctx = new p2p_context(platform);
    ctx->dataDir = QString::fromUtf8(data_dir);
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
    ctx->controller.relay().addSendRelay(QUrl(QString::fromUtf8(url)));
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
    if (ctx && ctx->ws.onBinaryMessage)
        ctx->ws.onBinaryMessage(QByteArray(reinterpret_cast<const char*>(data), len));
}

void p2p_ws_on_text(p2p_context* ctx, const char* message)
{
    if (ctx && ctx->ws.onTextMessage)
        ctx->ws.onTextMessage(QString::fromUtf8(message));
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
