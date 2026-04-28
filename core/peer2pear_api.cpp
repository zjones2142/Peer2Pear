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
#include "StdTimer.hpp"
#include "ChatController.hpp"
#include "CryptoEngine.hpp"
#include "SqlCipherDb.hpp"
#include "SessionStore.hpp"
#include "AppDataStore.hpp"
#include "MigrationCrypto.hpp"
#include "log.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_set>

// ── CWebSocket: IWebSocket backed by C function pointers ────────────────────

class SingleWebSocketFactory;  // fwd

class CWebSocket : public IWebSocket {
public:
    explicit CWebSocket(p2p_platform platform,
                        SingleWebSocketFactory* factory = nullptr)
        : m_p(platform), m_factory(factory) {}
    ~CWebSocket() override;  // notifies factory (defined below)

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
    p2p_platform            m_p;
    SingleWebSocketFactory* m_factory = nullptr;  // non-owning
};

// SingleWebSocketFactory — adapter that satisfies IWebSocketFactory's
// contract on top of today's single-WS-per-platform FFI.  The first
// create() returns a CWebSocket bound to the platform; subsequent
// calls return nullptr (because the FFI doesn't yet support multiple
// independent connections per platform_ctx).
//
// `active()` returns a non-owning pointer to the currently live
// CWebSocket so the p2p_ws_on_* platform callbacks can dispatch
// callbacks (onConnected / onBinaryMessage / etc.) without going
// through the controller.  The pointer is automatically cleared in
// CWebSocket's destructor — so a stale call after the controller is
// torn down is a safe no-op rather than a use-after-free.
//
// RelayClient::addSubscribeRelay handles a nullptr create() by logging
// and skipping — no crash, just "multi-WS subscribe not available
// here yet."  When the platform layer ships multi-connection support,
// replace this adapter with a real factory that creates fresh CWebSocket
// instances each call (each tied to its own per-connection platform_ctx).
class SingleWebSocketFactory : public IWebSocketFactory {
public:
    explicit SingleWebSocketFactory(p2p_platform platform) : m_p(platform) {}

    std::unique_ptr<IWebSocket> create() override {
        if (m_consumed) {
            P2P_WARN("[CWS] SingleWebSocketFactory::create() called "
                     "more than once — platform shim does not yet "
                     "support multiple WS connections; returning null");
            return nullptr;
        }
        m_consumed = true;
        auto ws = std::make_unique<CWebSocket>(m_p, this);
        m_active = ws.get();
        return ws;  // ownership transfers to RelayClient
    }

    // Pointer to the WS this factory created on its single-shot call.
    // Valid while RelayClient (and therefore the unique_ptr) is alive;
    // the CWebSocket destructor clears it back to nullptr.  Used by
    // the p2p_ws_on_* platform callbacks to find the IWebSocket whose
    // onConnected / onBinaryMessage / onTextMessage / onDisconnected
    // they should dispatch.
    CWebSocket* active() const { return m_active; }

    void clearActive(CWebSocket* ws) {
        if (m_active == ws) m_active = nullptr;
    }

private:
    p2p_platform m_p;
    bool         m_consumed = false;
    CWebSocket*  m_active   = nullptr;
};

inline CWebSocket::~CWebSocket() {
    if (m_factory) m_factory->clearActive(this);
}

// ── Multi-connection variants (v2 FFI) ──────────────────────────────────────

class MultiCWebSocketFactory;  // fwd

// MultiCWebSocket — IWebSocket bound to a per-connection opaque handle
// supplied by the platform layer's ws_alloc_connection callback.  The
// factory owns the platform `conn_handle` and frees it via
// ws_free_connection on this object's destruction.
//
// Registers itself in the factory's `byHandle` map so the v2 platform
// callbacks (p2p_ws_on_connected_v2 etc.) can locate it without a
// linear scan.
class MultiCWebSocket : public IWebSocket {
public:
    MultiCWebSocket(p2p_platform platform,
                    void* connHandle,
                    MultiCWebSocketFactory* factory);
    ~MultiCWebSocket() override;

    void open(const std::string& url) override {
        if (m_p.ws_open_v2)
            m_p.ws_open_v2(m_connHandle, url.c_str(), m_p.platform_ctx);
    }
    void close() override {
        if (m_p.ws_close_v2) m_p.ws_close_v2(m_connHandle, m_p.platform_ctx);
    }
    bool isConnected() const override {
        return m_p.ws_is_connected_v2
            ? m_p.ws_is_connected_v2(m_connHandle, m_p.platform_ctx) != 0
            : false;
    }
    bool isIdle() const override {
        return m_p.ws_is_idle_v2
            ? m_p.ws_is_idle_v2(m_connHandle, m_p.platform_ctx) != 0
            : true;
    }
    void sendTextMessage(const std::string& message) override {
        if (m_p.ws_send_text_v2)
            m_p.ws_send_text_v2(m_connHandle, message.c_str(), m_p.platform_ctx);
    }

    void* connHandle() const { return m_connHandle; }

private:
    p2p_platform               m_p;
    void*                      m_connHandle = nullptr;
    MultiCWebSocketFactory*    m_factory    = nullptr;
};

// Factory that allocates a fresh per-connection handle from the
// platform on every create().  Tracks live MultiCWebSockets by their
// handle so the v2 platform callbacks can dispatch back to them.
//
// Lifecycle:
//   create() → ws_alloc_connection → MultiCWebSocket{handle} → registered
//   ~MultiCWebSocket() → unregistered → ws_free_connection
class MultiCWebSocketFactory : public IWebSocketFactory {
public:
    explicit MultiCWebSocketFactory(p2p_platform platform) : m_p(platform) {}

    std::unique_ptr<IWebSocket> create() override {
        if (!m_p.ws_alloc_connection || !m_p.ws_free_connection) {
            P2P_WARN("[CWS-v2] ws_alloc_connection / ws_free_connection "
                     "missing — multi-WS unavailable");
            return nullptr;
        }
        void* handle = m_p.ws_alloc_connection(m_p.platform_ctx);
        if (!handle) {
            P2P_WARN("[CWS-v2] ws_alloc_connection returned null");
            return nullptr;
        }
        auto ws = std::make_unique<MultiCWebSocket>(m_p, handle, this);
        m_byHandle[handle] = ws.get();
        return ws;
    }

    // Looked up by p2p_ws_on_*_v2 callbacks to dispatch to the right
    // IWebSocket.  Returns nullptr for an unknown handle (e.g., a
    // late-arriving event for a connection we already freed).
    MultiCWebSocket* find(void* connHandle) const {
        auto it = m_byHandle.find(connHandle);
        return (it == m_byHandle.end()) ? nullptr : it->second;
    }

    void unregister(MultiCWebSocket* ws) {
        if (!ws) return;
        m_byHandle.erase(ws->connHandle());
    }

    p2p_platform platform() const { return m_p; }

private:
    p2p_platform                                  m_p;
    std::map<void*, MultiCWebSocket*>             m_byHandle;
};

inline MultiCWebSocket::MultiCWebSocket(p2p_platform platform,
                                          void* connHandle,
                                          MultiCWebSocketFactory* factory)
    : m_p(platform), m_connHandle(connHandle), m_factory(factory) {}

inline MultiCWebSocket::~MultiCWebSocket() {
    if (m_factory) m_factory->unregister(this);
    if (m_p.ws_free_connection && m_connHandle)
        m_p.ws_free_connection(m_connHandle, m_p.platform_ctx);
}

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


// ── p2p_context: the opaque handle ──────────────────────────────────────────

struct p2p_context {
    // Every p2p_* entry point (and every timer callback) takes this
    // mutex before touching controller / ws / http / cb.  This
    // serializes the maintenance timer against the host's WS/HTTP
    // callbacks — otherwise they race on ChatController state (fields
    // like m_envelopeCount, m_fileKeys, m_pendingIncomingFiles,
    // m_sessionStore) because the timer fires on its own worker thread.
    //
    // Mutex MUST be declared before timers/controller so it outlives any
    // callback thread they spawn: C++ destroys members in reverse order,
    // so the timers / controller tear down first and their worker threads
    // join while ctrlMu is still alive.
    std::mutex        ctrlMu;

    // The factory adapter is the WS provider for the C++ core.  When
    // the platform provides ws_alloc_connection (v2 FFI), we use a
    // MultiCWebSocketFactory that allocates a fresh per-connection
    // handle on every create().  Otherwise we fall back to
    // SingleWebSocketFactory which honors only the first create()
    // (legacy single-connection FFI).
    //
    // Polymorphic via unique_ptr so the choice is made at construction
    // time and the rest of the core sees IWebSocketFactory uniformly.
    std::unique_ptr<IWebSocketFactory> wsFactory;
    CHttpClient            http;
    StdTimerFactory        timers;

    // Arch-review #7: db / appData / controller used to be value
    // members with carefully-ordered declarations.  The controller's
    // submembers (SessionStore, SessionSealer, FileTransferManager,
    // AppDataStore) hold non-owning raw SqlCipherDb* pointers into
    // `db` — if anyone reordered these three declarations, reverse-
    // declaration-order destruction would run ~SqlCipherDb BEFORE
    // the consumers' dtors, triggering use-after-free on the key +
    // sqlite3 handle.  Wrapping them in unique_ptr + explicit
    // reset() sequencing in ~p2p_context makes teardown order
    // independent of declaration order.  Primary ownership stays
    // here; no shared_ptr lifetime-extension risk (a consumer that
    // captured shared_ptr into a long-lived callback would keep the
    // DB key in memory past p2p_destroy — with unique_ptr that's
    // impossible because no one else owns it).
    std::unique_ptr<SqlCipherDb>    db;
    std::unique_ptr<AppDataStore>   appData;
    std::unique_ptr<ChatController> controller;

    ~p2p_context()
    {
        // Explicit teardown order (Arch-review #7).  Consumers that
        // hold raw views into *db MUST be destroyed first so their
        // destructors don't observe a freed handle.  Member-
        // declaration order no longer affects correctness.
        controller.reset();
        appData.reset();
        db.reset();
    }

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

        // Group member-left / rename / avatar (all fire from inbound
        // control messages — see ChatController::onGroupMemberLeft /
        // onGroupRenamed / onGroupAvatarReceived).
        void (*on_group_member_left)(const char*, const char*, const char*,
                                     const char**, int64_t, const char*, void*) = nullptr;
        void* group_member_left_ud = nullptr;
        void (*on_group_renamed)(const char*, const char*, void*) = nullptr;
        void* group_renamed_ud = nullptr;
        void (*on_group_avatar)(const char*, const char*, void*) = nullptr;
        void* group_avatar_ud = nullptr;

        // pv=2 (Causally-Linked Pairwise) UX events — fire from
        // ChatController's dispatchGroupMessageV2 path when the
        // receiver hits a gap or surfaces lost messages on a
        // session reset.
        void (*on_group_stream_blocked)(const char*, const char*,
                                          int64_t, int64_t, void*) = nullptr;
        void* group_stream_blocked_ud = nullptr;
        void (*on_group_messages_lost)(const char*, const char*,
                                          int64_t, void*) = nullptr;
        void* group_messages_lost_ud = nullptr;

        void (*on_presence)(const char*, int, void*) = nullptr;
        void* presence_ud = nullptr;

        void (*on_file_progress)(const char*, const char*, const char*,
                                 int64_t, int, int, const char*, int64_t, void*) = nullptr;
        void* file_progress_ud = nullptr;

        void (*on_file_sent_progress)(const char*, const char*, const char*,
                                       int64_t, int, int, int64_t, void*) = nullptr;
        void* file_sent_progress_ud = nullptr;

        void (*on_avatar)(const char*, const char*, const char*, void*) = nullptr;
        void* avatar_ud = nullptr;

        // File consent / cancel.
        void (*on_file_request)(const char*, const char*, const char*, int64_t, void*) = nullptr;
        void* file_request_ud = nullptr;

        void (*on_file_canceled)(const char*, int, void*) = nullptr;
        void* file_canceled_ud = nullptr;

        // File delivery.
        void (*on_file_delivered)(const char*, void*) = nullptr;
        void* file_delivered_ud = nullptr;

        void (*on_file_blocked)(const char*, int, void*) = nullptr;
        void* file_blocked_ud = nullptr;

        // Safety numbers
        void (*on_peer_key_changed)(const char*,
                                    const uint8_t*, int,
                                    const uint8_t*, int,
                                    void*) = nullptr;
        void* peer_key_changed_ud = nullptr;

        // Per-bubble delivery failure (post retry-exhaustion).
        void (*on_send_failed)(const char* msg_id, void* ud) = nullptr;
        void* send_failed_ud = nullptr;
    } cb;

    std::string dataDir;

    p2p_context(p2p_platform platform)
        : wsFactory(makeWsFactory(platform))
        , http(platform)
        , timers(&ctrlMu)
        , db(std::make_unique<SqlCipherDb>())
        , appData(std::make_unique<AppDataStore>())
        , controller(std::make_unique<ChatController>(*wsFactory, http, timers))
    {}

private:
    // Pick the right factory at construction.  Single-connection
    // platforms get the legacy SingleWebSocketFactory (returns one
    // CWebSocket then nullptr); platforms that wired the v2 callbacks
    // get the MultiCWebSocketFactory which scales out properly.
    static std::unique_ptr<IWebSocketFactory>
    makeWsFactory(const p2p_platform& platform) {
        if (platform.ws_alloc_connection &&
            platform.ws_free_connection &&
            platform.ws_open_v2) {
            return std::make_unique<MultiCWebSocketFactory>(platform);
        }
        return std::make_unique<SingleWebSocketFactory>(platform);
    }

public:
};

// Scope guard: serializes every public p2p_* entry point.
// Recursive is overkill (we never re-enter), plain lock_guard suffices.
#define P2P_CTX_GUARD(ctx) std::lock_guard<std::mutex> _p2p_lock((ctx)->ctrlMu)

// ── Helper: assign ChatController callbacks → C FFI callbacks ──────────────
//
// Each lambda just forwards arguments to the matching C function pointer.

// Helper: build a NULL-terminated vector<const char*> from a vector of
// strings, lifetimed to the caller's scope.  Shared by every C callback
// bridge lambda that hands a member list across the FFI boundary.
static std::vector<const char*> cPtrArrayFromStrings(
    const std::vector<std::string>& src)
{
    std::vector<const char*> out;
    out.reserve(src.size() + 1);
    for (const std::string& s : src) out.push_back(s.c_str());
    out.push_back(nullptr);
    return out;
}

static void wire_signals(p2p_context* ctx)
{
    auto& c = *ctx->controller;

    c.onStatus = [ctx](const std::string& s) {
        if (ctx->cb.on_status)
            ctx->cb.on_status(s.c_str(), ctx->cb.status_ud);
    };

    c.onRelayConnected = [ctx]() {
        if (ctx->cb.on_connected) ctx->cb.on_connected(ctx->cb.connected_ud);
    };

    c.onPresenceChanged = [ctx](const std::string& peerId, bool online) {
        if (ctx->cb.on_presence)
            ctx->cb.on_presence(peerId.c_str(), online ? 1 : 0, ctx->cb.presence_ud);
    };

    c.onMessageReceived = [ctx](const std::string& from, const std::string& text,
                                 int64_t tsSecs, const std::string& msgId) {
        if (ctx->cb.on_message)
            ctx->cb.on_message(from.c_str(), text.c_str(),
                               tsSecs, msgId.c_str(),
                               ctx->cb.message_ud);
    };

    c.onGroupMessageReceived = [ctx](const std::string& from, const std::string& groupId,
                                      const std::string& groupName,
                                      const std::vector<std::string>& memberKeys,
                                      const std::string& text, int64_t tsSecs,
                                      const std::string& msgId) {
        if (ctx->cb.on_group_message) {
            auto memberPtrs = cPtrArrayFromStrings(memberKeys);
            ctx->cb.on_group_message(
                from.c_str(), groupId.c_str(), groupName.c_str(),
                memberPtrs.data(), text.c_str(),
                tsSecs, msgId.c_str(),
                ctx->cb.group_message_ud);
        }
    };

    c.onGroupMemberLeft = [ctx](const std::string& from,
                                 const std::string& groupId,
                                 const std::string& groupName,
                                 const std::vector<std::string>& memberKeys,
                                 int64_t tsSecs,
                                 const std::string& msgId) {
        if (ctx->cb.on_group_member_left) {
            auto memberPtrs = cPtrArrayFromStrings(memberKeys);
            ctx->cb.on_group_member_left(
                from.c_str(), groupId.c_str(), groupName.c_str(),
                memberPtrs.data(), tsSecs, msgId.c_str(),
                ctx->cb.group_member_left_ud);
        }
    };

    c.onGroupRenamed = [ctx](const std::string& groupId, const std::string& newName) {
        if (ctx->cb.on_group_renamed) {
            ctx->cb.on_group_renamed(
                groupId.c_str(), newName.c_str(), ctx->cb.group_renamed_ud);
        }
    };

    c.onGroupAvatarReceived = [ctx](const std::string& groupId, const std::string& avatarB64) {
        if (ctx->cb.on_group_avatar) {
            ctx->cb.on_group_avatar(
                groupId.c_str(), avatarB64.c_str(), ctx->cb.group_avatar_ud);
        }
    };

    c.onGroupStreamBlocked = [ctx](const std::string& groupId,
                                     const std::string& senderPeerId,
                                     int64_t fromCtr, int64_t toCtr) {
        if (ctx->cb.on_group_stream_blocked) {
            ctx->cb.on_group_stream_blocked(
                groupId.c_str(), senderPeerId.c_str(),
                fromCtr, toCtr,
                ctx->cb.group_stream_blocked_ud);
        }
    };

    c.onGroupMessagesLost = [ctx](const std::string& groupId,
                                     const std::string& senderPeerId,
                                     int64_t count) {
        if (ctx->cb.on_group_messages_lost) {
            ctx->cb.on_group_messages_lost(
                groupId.c_str(), senderPeerId.c_str(), count,
                ctx->cb.group_messages_lost_ud);
        }
    };

    c.onFileChunkReceived = [ctx](const std::string& from, const std::string& transferId,
                                   const std::string& fileName, int64_t fileSize,
                                   int chunksRcvd, int chunksTotal,
                                   const std::string& savedPath, int64_t tsSecs,
                                   const std::string&, const std::string&) {
        if (ctx->cb.on_file_progress) {
            ctx->cb.on_file_progress(
                from.c_str(), transferId.c_str(), fileName.c_str(),
                fileSize, chunksRcvd, chunksTotal,
                savedPath.empty() ? nullptr : savedPath.c_str(),
                tsSecs,
                ctx->cb.file_progress_ud);
        }
    };

    c.onFileChunkSent = [ctx](const std::string& to, const std::string& transferId,
                               const std::string& fileName, int64_t fileSize,
                               int chunksSent, int chunksTotal, int64_t tsSecs,
                               const std::string&, const std::string&) {
        if (ctx->cb.on_file_sent_progress) {
            ctx->cb.on_file_sent_progress(
                to.c_str(), transferId.c_str(), fileName.c_str(),
                fileSize, chunksSent, chunksTotal, tsSecs,
                ctx->cb.file_sent_progress_ud);
        }
    };

    c.onAvatarReceived = [ctx](const std::string& peerId, const std::string& name,
                                const std::string& b64) {
        if (ctx->cb.on_avatar)
            ctx->cb.on_avatar(peerId.c_str(), name.c_str(), b64.c_str(),
                              ctx->cb.avatar_ud);
    };

    c.onFileAcceptRequested = [ctx](const std::string& from, const std::string& tid,
                                     const std::string& fileName, int64_t fileSize) {
        if (ctx->cb.on_file_request)
            ctx->cb.on_file_request(from.c_str(), tid.c_str(), fileName.c_str(),
                                    fileSize, ctx->cb.file_request_ud);
    };

    c.onFileTransferCanceled = [ctx](const std::string& tid, bool byReceiver) {
        if (ctx->cb.on_file_canceled)
            ctx->cb.on_file_canceled(tid.c_str(), byReceiver ? 1 : 0,
                                     ctx->cb.file_canceled_ud);
    };

    c.onFileTransferDelivered = [ctx](const std::string& tid) {
        if (ctx->cb.on_file_delivered)
            ctx->cb.on_file_delivered(tid.c_str(), ctx->cb.file_delivered_ud);
    };

    c.onFileTransferBlocked = [ctx](const std::string& tid, bool byReceiver) {
        if (ctx->cb.on_file_blocked)
            ctx->cb.on_file_blocked(tid.c_str(), byReceiver ? 1 : 0,
                                    ctx->cb.file_blocked_ud);
    };

    c.onPeerKeyChanged = [ctx](const std::string& peerId,
                                const Bytes& oldFp, const Bytes& newFp) {
        if (!ctx->cb.on_peer_key_changed) return;
        ctx->cb.on_peer_key_changed(
            peerId.c_str(),
            oldFp.empty() ? nullptr : oldFp.data(),
            static_cast<int>(oldFp.size()),
            newFp.empty() ? nullptr : newFp.data(),
            static_cast<int>(newFp.size()),
            ctx->cb.peer_key_changed_ud);
    };

    c.onMessageSendFailed = [ctx](const std::string& msgId) {
        if (!ctx->cb.on_send_failed) return;
        ctx->cb.on_send_failed(msgId.c_str(), ctx->cb.send_failed_ud);
    };
}

// ── C API implementation ────────────────────────────────────────────────────

p2p_context* p2p_create(const char* data_dir, p2p_platform platform)
{
    auto* ctx = new p2p_context(platform);
    ctx->dataDir = data_dir ? data_dir : "";
    // Route identity.json and salt files to the host-provided directory.
    // Without this, iOS/Android would try to read/write to a non-existent
    // AppDataLocation path.
    if (!ctx->dataDir.empty())
        ctx->controller->setDataDir(ctx->dataDir);
    wire_signals(ctx);
    return ctx;
}

void p2p_destroy(p2p_context* ctx)
{
    if (!ctx) return;
    // Drain timer worker threads *before* any other teardown.  A still-
    // running singleShot cb holds captured references into
    // ChatController; destroying it first would UAF.  Everything below
    // runs under the ctrlMu so we serialize with any host-driven p2p_*
    // entry points that might still be in flight.
    ctx->timers.shutdown();
    {
        std::lock_guard<std::mutex> lk(ctx->ctrlMu);
        ctx->controller->disconnectFromRelay();
    }
    delete ctx;
}

void p2p_set_passphrase(p2p_context* ctx, const char* passphrase)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    // Keep the passphrase copy in a named local so we can zero it on the
    // way out.  An implicit std::string temporary would be destructed
    // with the passphrase bytes still in its buffer.  The caller's own
    // `passphrase` C string is out of our control — the header documents
    // that they must zero it.
    std::string pass = passphrase ? passphrase : "";
    ctx->controller->setPassphrase(pass);
    CryptoEngine::secureZero(pass);
}

int p2p_set_passphrase_v2(p2p_context* ctx, const char* passphrase)
{
    if (!ctx || !passphrase || passphrase[0] == '\0') return -1;
    // Enforce the library-side strength floor.  Platform UIs should
    // reject weak passphrases long before they reach this entry, but a
    // byte-length check here keeps the core from ever accepting a
    // 1-char passphrase via a misconfigured FFI caller.
    if (std::strlen(passphrase) < P2P_MIN_PASSPHRASE_BYTES) return -1;
    if (ctx->dataDir.empty()) return -1;
    P2P_CTX_GUARD(ctx);

    namespace fs = std::filesystem;
    const std::string keysDir = ctx->dataDir + "/keys";
    std::error_code ec;
    fs::create_directories(keysDir, ec);  // no-op if already there

    const std::string saltPath = keysDir + "/db_salt.bin";
    Bytes salt = CryptoEngine::loadOrCreateSalt(saltPath);
    if (salt.size() != 16) return -1;

    // Route the passphrase through one named local we can zero on every
    // exit path, so no intermediate std::string holds it after this
    // function returns.
    std::string pass = passphrase;

    Bytes masterKey = CryptoEngine::deriveMasterKey(pass, salt);
    if (masterKey.size() != 32) {
        CryptoEngine::secureZero(pass);
        return -1;
    }

    // HKDF info labels.  Must stay byte-identical to what the desktop
    // onboarding flow uses (mainwindow.cpp:115 / :117) so v4→v5 migration
    // succeeds across frontends.
    auto labelBytes = [](const char* s, size_t n) {
        return Bytes(reinterpret_cast<const uint8_t*>(s),
                      reinterpret_cast<const uint8_t*>(s) + n);
    };
    static const char kIdentityInfo[] = "identity-unlock";
    static const char kDbInfo[]       = "sqlcipher-db-key";

    // Derive both subkeys from one master before zeroing it — Argon2id
    // at MODERATE is ~150-300 ms, so running it twice on unlock is a
    // real user-visible stall (and a memory spike under iOS jetsam
    // pressure).  The master lives microseconds longer than it would if
    // we zeroed between derivations — drastically shorter than the
    // passphrase buffer itself, which we hold until the end.
    Bytes identityKey = CryptoEngine::deriveSubkey(
        masterKey, labelBytes(kIdentityInfo, sizeof(kIdentityInfo) - 1));
    Bytes dbKey       = CryptoEngine::deriveSubkey(
        masterKey, labelBytes(kDbInfo,       sizeof(kDbInfo) - 1));
    CryptoEngine::secureZero(masterKey);
    if (identityKey.size() != 32 || dbKey.size() != 32) {
        CryptoEngine::secureZero(identityKey);
        CryptoEngine::secureZero(dbKey);
        CryptoEngine::secureZero(pass);
        return -1;
    }

    int rc = 0;
    try {
        ctx->controller->setPassphrase(pass, identityKey);
    } catch (...) {
        rc = -1;  // wrong passphrase or corrupted identity.json
    }
    CryptoEngine::secureZero(identityKey);

    // SQLCipher session store — mirrors desktop mainwindow.cpp's flow.
    // Without this, `ctx->controller->m_sessionMgr` stays null and every
    // outbound send fails with "cannot seal" (mobile FFI regression
    // discovered during test_c_api_e2e round-trip writeup).
    if (rc == 0) {
        const std::string dbPath = ctx->dataDir + "/peer2pear.db";
        if (ctx->db->open(dbPath, dbKey)) {
            ctx->controller->setDatabase(*ctx->db);
            // Bind the app-data layer to the same SQLCipher handle and
            // give it the same key for per-field XChaCha20-Poly1305.
            // Page-level (SQLCipher) + field-level (libsodium) gives
            // defense-in-depth: a memory dump that captures the page
            // key still doesn't yield message bodies until the field
            // key is also recovered.
            ctx->appData->bind(*ctx->db);
            ctx->appData->setEncryptionKey(dbKey);
            // Hand the appData pointer to ChatController so the v2
            // group sender path can persist its monotonic counter +
            // sealed-envelope replay cache.
            ctx->controller->setAppDataStore(ctx->appData.get());
        } else {
            rc = -1;
        }
    }
    CryptoEngine::secureZero(dbKey);

    CryptoEngine::secureZero(pass);
    return rc;
}

const char* p2p_my_id(p2p_context* ctx)
{
    if (!ctx) return "";
    P2P_CTX_GUARD(ctx);
    ctx->scratch = ctx->controller->myIdB64u();
    return ctx->scratch.c_str();
}

const char* p2p_safety_number(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return "";
    P2P_CTX_GUARD(ctx);
    ctx->scratch = ctx->controller->safetyNumber(peer_id);
    return ctx->scratch.c_str();
}

int p2p_peer_trust(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return P2P_PEER_UNVERIFIED;
    P2P_CTX_GUARD(ctx);
    switch (ctx->controller->peerTrust(peer_id)) {
        case ChatController::PeerTrust::Unverified: return P2P_PEER_UNVERIFIED;
        case ChatController::PeerTrust::Verified:   return P2P_PEER_VERIFIED;
        case ChatController::PeerTrust::Mismatch:   return P2P_PEER_MISMATCH;
    }
    return P2P_PEER_UNVERIFIED;
}

int p2p_mark_peer_verified(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->controller->markPeerVerified(peer_id) ? 0 : -1;
}

void p2p_unverify_peer(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->unverifyPeer(peer_id);
}

void p2p_set_hard_block_on_key_change(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setHardBlockOnKeyChange(enabled != 0);
}

void p2p_reset_session(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->resetSession(peer_id);
}

void p2p_set_relay_url(p2p_context* ctx, const char* url)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setRelayUrl(url ? url : "");
}

void p2p_connect(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->connectToRelay();
}

void p2p_disconnect(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->disconnectFromRelay();
}

int p2p_send_text(p2p_context* ctx, const char* peer_id, const char* text)
{
    if (!ctx || !peer_id || !text) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendText(peer_id, text);
    return 0;
}

int p2p_send_text_v2(p2p_context* ctx, const char* peer_id,
                       const char* text, const char* msg_id)
{
    if (!ctx || !peer_id || !text) return -1;
    P2P_CTX_GUARD(ctx);
    // NULL or empty msg_id falls back to v1 semantics (core mints
    // its own UUID).  A non-empty value is what makes the
    // on_send_failed correlation work — the platform passes the
    // same id its UI bubble carries.
    ctx->controller->sendText(peer_id, text, msg_id ? msg_id : "");
    return 0;
}

// Helper: materialize a NULL-terminated C array into a std::vector.  Used
// by every group action that takes a member list.
static std::vector<std::string> cStringArrayToVector(const char** arr) {
    std::vector<std::string> out;
    if (!arr) return out;
    for (const char** p = arr; *p; ++p) out.emplace_back(*p);
    return out;
}

int p2p_send_group_text(p2p_context* ctx,
                        const char* group_id,
                        const char* group_name,
                        const char** member_ids,
                        const char* text)
{
    if (!ctx || !group_id || !text || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupMessageViaMailbox(
        group_id,
        group_name ? group_name : "",
        cStringArrayToVector(member_ids), text);
    return 0;
}

int p2p_send_group_text_v2(p2p_context* ctx,
                            const char* group_id,
                            const char* group_name,
                            const char** member_ids,
                            const char* text,
                            const char* msg_id)
{
    if (!ctx || !group_id || !text || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupMessageViaMailbox(
        group_id,
        group_name ? group_name : "",
        cStringArrayToVector(member_ids), text,
        msg_id ? msg_id : "");
    return 0;
}

const char* p2p_send_group_file(p2p_context* ctx,
                                const char* group_id,
                                const char* group_name,
                                const char** member_ids,
                                const char* file_name,
                                const char* file_path)
{
    if (!ctx || !group_id || !member_ids || !file_name || !file_path) return nullptr;
    P2P_CTX_GUARD(ctx);
    std::string tid = ctx->controller->sendGroupFile(
        group_id, group_name ? group_name : "",
        cStringArrayToVector(member_ids),
        file_name, file_path);
    if (tid.empty()) return nullptr;
    ctx->scratch = std::move(tid);
    return ctx->scratch.c_str();
}

int p2p_rename_group(p2p_context* ctx,
                     const char* group_id,
                     const char* new_name,
                     const char** member_ids)
{
    if (!ctx || !group_id || !new_name || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupRename(
        group_id, new_name, cStringArrayToVector(member_ids));
    return 0;
}

int p2p_leave_group(p2p_context* ctx,
                    const char* group_id,
                    const char* group_name,
                    const char** member_ids)
{
    if (!ctx || !group_id || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupLeaveNotification(
        group_id, group_name ? group_name : "",
        cStringArrayToVector(member_ids));
    return 0;
}

int p2p_send_group_avatar(p2p_context* ctx,
                          const char* group_id,
                          const char* avatar_b64,
                          const char** member_ids)
{
    if (!ctx || !group_id || !avatar_b64 || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupAvatar(
        group_id, avatar_b64, cStringArrayToVector(member_ids));
    return 0;
}

int p2p_update_group_members(p2p_context* ctx,
                             const char* group_id,
                             const char* group_name,
                             const char** member_ids)
{
    if (!ctx || !group_id || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller->sendGroupMemberUpdate(
        group_id, group_name ? group_name : "",
        cStringArrayToVector(member_ids));
    return 0;
}

void p2p_set_known_group_members(p2p_context* ctx,
                                  const char* group_id,
                                  const char** member_ids)
{
    if (!ctx || !group_id || !member_ids) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setKnownGroupMembers(
        group_id, cStringArrayToVector(member_ids));
}

const char* p2p_send_file(p2p_context* ctx,
                          const char* peer_id,
                          const char* file_name,
                          const char* file_path)
{
    if (!ctx || !peer_id || !file_name || !file_path) return nullptr;
    P2P_CTX_GUARD(ctx);
    std::string tid = ctx->controller->sendFile(peer_id, file_name, file_path);
    if (tid.empty()) return nullptr;
    ctx->scratch = std::move(tid);
    return ctx->scratch.c_str();
}

// ── File consent + cancel ───────────────────────────────────────────────────

void p2p_respond_file_request(p2p_context* ctx,
                              const char* transfer_id,
                              int accept,
                              int require_p2p)
{
    if (!ctx || !transfer_id) return;
    P2P_CTX_GUARD(ctx);
    const std::string tid = transfer_id;
    if (accept) {
        ctx->controller->acceptFileTransfer(tid, require_p2p != 0);
    } else {
        ctx->controller->declineFileTransfer(tid);
    }
}

void p2p_cancel_transfer(p2p_context* ctx, const char* transfer_id)
{
    if (!ctx || !transfer_id) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->cancelFileTransfer(transfer_id);
}

void p2p_set_file_auto_accept_mb(p2p_context* ctx, int mb)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setFileAutoAcceptMaxMB(mb);
}

void p2p_set_file_hard_max_mb(p2p_context* ctx, int mb)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setFileHardMaxMB(mb);
}

void p2p_set_file_require_p2p(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->setFileRequireP2P(enabled != 0);
}

void p2p_check_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    // A buggy caller could pass count<0, which would underflow the
    // reserve(size_t) and allocate SIZE_MAX bytes.  Silent no-op
    // matches the defensive posture of the p2p_ws_on_binary
    // null/length guard.
    if (count <= 0) return;
    P2P_CTX_GUARD(ctx);
    std::vector<std::string> ids;
    ids.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids.emplace_back(peer_ids[i]);
    ctx->controller->checkPresence(ids);
}

void p2p_subscribe_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    if (count <= 0) return;  // see p2p_check_presence — same guard
    P2P_CTX_GUARD(ctx);
    std::vector<std::string> ids;
    ids.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids.emplace_back(peer_ids[i]);
    ctx->controller->subscribePresence(ids);
}

void p2p_add_send_relay(p2p_context* ctx, const char* url)
{
    if (!ctx || !url) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().addSendRelay(url ? std::string(url) : std::string());
}

void p2p_add_subscribe_relay(p2p_context* ctx, const char* url)
{
    if (!ctx || !url) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().addSubscribeRelay(std::string(url));
}

void p2p_clear_subscribe_relays(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().clearSubscribeRelays();
}

void p2p_set_parallel_fan_out(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().setParallelFanOut(enabled != 0);
}

void p2p_set_parallel_fan_out_k(p2p_context* ctx, int k)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().setParallelFanOutK(k);
}

void p2p_set_multi_hop_enabled(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().setMultiHopEnabled(enabled != 0);
}

void p2p_set_privacy_level(p2p_context* ctx, int level)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller->relay().setPrivacyLevel(level);
}

void p2p_set_push_token(p2p_context* ctx,
                         const char* token,
                         const char* platform)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    const std::string tok = token    ? std::string(token)    : std::string();
    const std::string plt = platform ? std::string(platform) : std::string();
    ctx->controller->relay().registerPushToken(plt, tok);
}

void p2p_wake_for_push(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    // Most relays deliver queued envelopes automatically on
    // (re)authentication, so the simple + robust response is to
    // ensure the relay WS is up.  If already connected, this is a
    // no-op; if disconnected, nudge a (re)connect which drains the
    // mailbox as part of normal auth flow.
    if (!ctx->controller->relay().isConnected())
        ctx->controller->relay().connectToRelay();
}

// ── Platform → Core events ──────────────────────────────────────────────────

namespace {

// Find the IWebSocket the legacy v1 callbacks should dispatch to.
// Only meaningful when ctx is using the SingleWebSocketFactory; the
// multi-WS path uses p2p_ws_on_*_v2 with explicit conn_handle.
inline IWebSocket* primaryWsForLegacyCallback(p2p_context* ctx) {
    if (!ctx || !ctx->wsFactory) return nullptr;
    auto* single = dynamic_cast<SingleWebSocketFactory*>(ctx->wsFactory.get());
    return single ? static_cast<IWebSocket*>(single->active()) : nullptr;
}

// Find the IWebSocket for a v2 callback by conn_handle.  Returns null
// for unknown handles (defensive: a free + late event race shouldn't
// crash).  Only meaningful when ctx is using the MultiCWebSocketFactory.
inline IWebSocket* wsByHandle(p2p_context* ctx, void* connHandle) {
    if (!ctx || !ctx->wsFactory || !connHandle) return nullptr;
    auto* multi = dynamic_cast<MultiCWebSocketFactory*>(ctx->wsFactory.get());
    return multi ? static_cast<IWebSocket*>(multi->find(connHandle)) : nullptr;
}

}  // namespace

void p2p_ws_on_connected(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = primaryWsForLegacyCallback(ctx); ws && ws->onConnected) {
        ws->onConnected();
    }
}

void p2p_ws_on_disconnected(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = primaryWsForLegacyCallback(ctx); ws && ws->onDisconnected) {
        ws->onDisconnected();
    }
}

void p2p_ws_on_binary(p2p_context* ctx, const uint8_t* data, int len)
{
    if (!ctx) return;
    // FFI hardening: a buggy or hostile platform adapter could pass
    // (NULL, anything) or (anything, negative).  Constructing
    // Bytes(data, data + len) under those conditions is UB — even
    // (nullptr, 0) is technically UB per [expr.add]/4 since pointer
    // arithmetic on null is undefined.  Treat malformed inputs as
    // "drop the frame" rather than crash.
    if (len < 0) return;
    if (!data && len > 0) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = primaryWsForLegacyCallback(ctx); ws && ws->onBinaryMessage) {
        Bytes buf;
        if (data && len > 0) buf.assign(data, data + len);
        ws->onBinaryMessage(buf);
    }
}

void p2p_ws_on_text(p2p_context* ctx, const char* message)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = primaryWsForLegacyCallback(ctx); ws && ws->onTextMessage) {
        ws->onTextMessage(message ? std::string(message) : std::string());
    }
}

// ── v2 multi-connection event callbacks ─────────────────────────────────────

void p2p_ws_on_connected_v2(p2p_context* ctx, void* conn_handle)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = wsByHandle(ctx, conn_handle); ws && ws->onConnected) {
        ws->onConnected();
    }
}

void p2p_ws_on_disconnected_v2(p2p_context* ctx, void* conn_handle)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = wsByHandle(ctx, conn_handle); ws && ws->onDisconnected) {
        ws->onDisconnected();
    }
}

void p2p_ws_on_binary_v2(p2p_context* ctx, void* conn_handle,
                          const uint8_t* data, int len)
{
    if (!ctx) return;
    if (len < 0) return;
    if (!data && len > 0) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = wsByHandle(ctx, conn_handle); ws && ws->onBinaryMessage) {
        Bytes buf;
        if (data && len > 0) buf.assign(data, data + len);
        ws->onBinaryMessage(buf);
    }
}

void p2p_ws_on_text_v2(p2p_context* ctx, void* conn_handle, const char* message)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (auto* ws = wsByHandle(ctx, conn_handle); ws && ws->onTextMessage) {
        ws->onTextMessage(message ? std::string(message) : std::string());
    }
}

void p2p_http_response(p2p_context* ctx, int request_id,
                       int status, const uint8_t* body, int body_len,
                       const char* error)
{
    if (!ctx) return;
    // FFI hardening: same null/length contract as p2p_ws_on_binary
    // above.  CHttpClient::onResponse already guards its assign() with
    // `body && bodyLen > 0`, but enforcing here too means any future
    // consumer of (body, body_len) downstream gets sane inputs without
    // re-checking.
    if (body_len < 0) return;
    if (!body && body_len > 0) return;
    P2P_CTX_GUARD(ctx);
    ctx->http.onResponse(request_id, status, body, body_len, error);
}

// ── Event callback setters ──────────────────────────────────────────────────

void p2p_set_on_status(p2p_context* ctx,
    void (*cb)(const char*, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_status = cb;
    ctx->cb.status_ud = ud;
}

void p2p_set_on_connected(p2p_context* ctx,
    void (*cb)(void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_connected = cb;
    ctx->cb.connected_ud = ud;
}

void p2p_set_on_message(p2p_context* ctx,
    void (*cb)(const char*, const char*, int64_t, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_message = cb;
    ctx->cb.message_ud = ud;
}

void p2p_set_on_group_message(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               const char**, const char*, int64_t, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_message = cb;
    ctx->cb.group_message_ud = ud;
}

void p2p_set_on_presence(p2p_context* ctx,
    void (*cb)(const char*, int, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_presence = cb;
    ctx->cb.presence_ud = ud;
}

void p2p_set_on_group_member_left(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               const char**, int64_t, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_member_left = cb;
    ctx->cb.group_member_left_ud = ud;
}

void p2p_set_on_group_renamed(p2p_context* ctx,
    void (*cb)(const char*, const char*, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_renamed = cb;
    ctx->cb.group_renamed_ud = ud;
}

void p2p_set_on_group_avatar(p2p_context* ctx,
    void (*cb)(const char*, const char*, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_avatar = cb;
    ctx->cb.group_avatar_ud = ud;
}

void p2p_set_on_group_stream_blocked(p2p_context* ctx,
    void (*cb)(const char*, const char*, int64_t, int64_t, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_stream_blocked = cb;
    ctx->cb.group_stream_blocked_ud = ud;
}

void p2p_set_on_group_messages_lost(p2p_context* ctx,
    void (*cb)(const char*, const char*, int64_t, void*), void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_group_messages_lost = cb;
    ctx->cb.group_messages_lost_ud = ud;
}

void p2p_set_on_file_progress(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               int64_t, int, int, const char*, int64_t, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_progress = cb;
    ctx->cb.file_progress_ud = ud;
}

void p2p_set_on_file_sent_progress(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*,
               int64_t, int, int, int64_t, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_sent_progress = cb;
    ctx->cb.file_sent_progress_ud = ud;
}

void p2p_set_on_avatar(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_avatar = cb;
    ctx->cb.avatar_ud = ud;
}

void p2p_set_on_file_request(p2p_context* ctx,
    void (*cb)(const char*, const char*, const char*, int64_t, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_request    = cb;
    ctx->cb.file_request_ud    = ud;
}

void p2p_set_on_file_canceled(p2p_context* ctx,
    void (*cb)(const char*, int, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_canceled    = cb;
    ctx->cb.file_canceled_ud    = ud;
}

void p2p_set_on_file_delivered(p2p_context* ctx,
    void (*cb)(const char*, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_delivered    = cb;
    ctx->cb.file_delivered_ud    = ud;
}

void p2p_set_on_file_blocked(p2p_context* ctx,
    void (*cb)(const char*, int, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_file_blocked    = cb;
    ctx->cb.file_blocked_ud    = ud;
}

void p2p_set_on_peer_key_changed(p2p_context* ctx,
    void (*cb)(const char*, const uint8_t*, int, const uint8_t*, int, void*),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_peer_key_changed = cb;
    ctx->cb.peer_key_changed_ud = ud;
}

void p2p_set_on_send_failed(p2p_context* ctx,
    void (*cb)(const char* msg_id, void* ud),
    void* ud)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->cb.on_send_failed = cb;
    ctx->cb.send_failed_ud = ud;
}

// ── App-data store (contacts / messages / settings / file_transfers) ──────
//
// All entry points guard ctx + p2p_context::ctrlMu so a callback that
// races with shutdown sees a coherent appData (mirrors the rest of
// the API).  load_* callbacks invoke `cb` while holding the mutex —
// the consumer's callback must NOT call back into p2p_app_* synchronously
// (it would deadlock).  The Swift wrappers buffer rows into an array
// before returning to user code, which sidesteps this entirely.

namespace {
// Convert std::vector<std::string> ↔ NULL-terminated C-string array.
// Used to bridge contacts.keys across the FFI without copying the
// underlying string data twice.
std::vector<const char*> toCArray(const std::vector<std::string>& v,
                                   std::vector<const char*>& storage)
{
    storage.clear();
    storage.reserve(v.size() + 1);
    for (const auto& s : v) storage.push_back(s.c_str());
    storage.push_back(nullptr);
    return storage;
}

std::vector<std::string> fromCArray(const char* const* arr)
{
    std::vector<std::string> out;
    if (!arr) return out;
    for (const char* const* p = arr; *p; ++p) out.emplace_back(*p);
    return out;
}
} // namespace

int p2p_app_save_contact(p2p_context* ctx,
                          const char* peer_id,
                          const char* name,
                          const char* subtitle,
                          const char* avatar_b64,
                          int muted,
                          int64_t last_active_secs)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::Contact c;
    c.peerIdB64u     = peer_id;
    c.name           = name       ? name       : "";
    c.subtitle       = subtitle   ? subtitle   : "";
    c.avatarB64      = avatar_b64 ? avatar_b64 : "";
    c.muted          = muted != 0;
    c.lastActiveSecs = last_active_secs;
    return ctx->appData->saveContact(c) ? 0 : -1;
}

int p2p_app_delete_contact(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteContact(peer_id) ? 0 : -1;
}

int p2p_app_set_contact_muted(p2p_context* ctx, const char* peer_id, int muted)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->setContactMuted(peer_id, muted != 0) ? 0 : -1;
}

// ── Blocked keys ────────────────────────────────────────────────────────────

int p2p_app_add_blocked_key(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    const int64_t now = static_cast<int64_t>(time(nullptr));
    return ctx->appData->addBlockedKey(peer_id, now) ? 0 : -1;
}

int p2p_app_remove_blocked_key(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->removeBlockedKey(peer_id) ? 0 : -1;
}

int p2p_app_is_blocked_key(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->isBlockedKey(peer_id) ? 1 : 0;
}

void p2p_app_load_blocked_keys(p2p_context* ctx,
                                p2p_blocked_key_cb cb, void* ud)
{
    if (!ctx || !cb) return;
    // Same lock-discipline pattern as load_contacts: snapshot under
    // the guard, then fire callbacks unguarded so the consumer can
    // re-enter the API safely.
    std::vector<std::pair<std::string, int64_t>> snapshot;
    {
        P2P_CTX_GUARD(ctx);
        ctx->appData->loadAllBlockedKeys(
            [&](const std::string& p, int64_t t) {
                snapshot.emplace_back(p, t);
            });
    }
    for (const auto& row : snapshot) cb(row.first.c_str(), row.second, ud);
}

void p2p_app_load_contacts(p2p_context* ctx, p2p_contact_cb cb, void* ud)
{
    if (!ctx || !cb) return;

    // Do NOT hold ctrlMu across the callback.  std::mutex is
    // non-recursive, so a caller whose callback re-enters any
    // p2p_app_* function (commonly seen on iOS, which layers a
    // SwiftUI update inside the loop) would deadlock.  Snapshot the
    // rows under the lock, then release before firing callbacks.
    std::vector<AppDataStore::Contact> snapshot;
    {
        P2P_CTX_GUARD(ctx);
        ctx->appData->loadAllContacts([&](const AppDataStore::Contact& c) {
            snapshot.push_back(c);
        });
    }

    for (const auto& c : snapshot) {
        cb(c.peerIdB64u.c_str(),
           c.name.c_str(),
           c.subtitle.c_str(),
           c.avatarB64.c_str(),
           c.muted ? 1 : 0,
           c.lastActiveSecs,
           ud);
    }
}

int p2p_app_save_contact_avatar(p2p_context* ctx,
                                 const char* peer_id,
                                 const char* avatar_b64)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->saveContactAvatar(peer_id,
                                           avatar_b64 ? avatar_b64 : "")
        ? 0 : -1;
}

int p2p_app_save_message(p2p_context* ctx,
                          const char* conversation_id,
                          int sent,
                          const char* text,
                          int64_t timestamp_secs,
                          const char* msg_id,
                          const char* sender_id,
                          const char* sender_name,
                          int send_failed)
{
    if (!ctx || !conversation_id) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::Message m;
    m.sent          = sent != 0;
    m.text          = text        ? text        : "";
    m.timestampSecs = timestamp_secs;
    m.msgId         = msg_id      ? msg_id      : "";
    m.senderId      = sender_id   ? sender_id   : "";
    m.senderName    = sender_name ? sender_name : "";
    m.sendFailed    = send_failed != 0;
    return ctx->appData->saveMessage(conversation_id, m) ? 0 : -1;
}

void p2p_app_load_messages(p2p_context* ctx, const char* conversation_id,
                            p2p_message_cb cb, void* ud)
{
    if (!ctx || !conversation_id || !cb) return;
    P2P_CTX_GUARD(ctx);
    ctx->appData->loadMessages(conversation_id, [&](const AppDataStore::Message& m) {
        cb(m.sent ? 1 : 0,
           m.text.c_str(),
           m.timestampSecs,
           m.msgId.c_str(),
           m.senderId.c_str(),
           m.senderName.c_str(),
           m.sendFailed ? 1 : 0,
           ud);
    });
}

int p2p_app_delete_messages(p2p_context* ctx, const char* conversation_id)
{
    if (!ctx || !conversation_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteMessages(conversation_id) ? 0 : -1;
}

int p2p_app_delete_message(p2p_context* ctx, const char* conversation_id, const char* msg_id)
{
    if (!ctx || !conversation_id || !msg_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteMessage(conversation_id, msg_id) ? 0 : -1;
}

int p2p_app_set_message_send_failed(p2p_context* ctx,
                                       const char* conversation_id,
                                       const char* msg_id,
                                       int failed)
{
    if (!ctx || !conversation_id || !msg_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->setMessageSendFailed(conversation_id, msg_id, failed != 0)
        ? 0 : -1;
}

// ── Conversations ───────────────────────────────────────────────────────────

int p2p_app_save_conversation(p2p_context* ctx,
                                const char* id,
                                const char* kind,
                                const char* direct_peer_id,
                                const char* group_name,
                                const char* group_avatar_b64,
                                int muted,
                                int64_t last_active_secs,
                                int in_chat_list)
{
    if (!ctx || !id || !kind) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::Conversation c;
    c.id              = id;
    c.kind            = std::string(kind) == "group"
                            ? AppDataStore::ConversationKind::Group
                            : AppDataStore::ConversationKind::Direct;
    c.directPeerId    = direct_peer_id   ? direct_peer_id   : "";
    c.groupName       = group_name       ? group_name       : "";
    c.groupAvatarB64  = group_avatar_b64 ? group_avatar_b64 : "";
    c.muted           = muted != 0;
    c.lastActiveSecs  = last_active_secs;
    c.inChatList      = in_chat_list != 0;
    return ctx->appData->saveConversation(c) ? 0 : -1;
}

int p2p_app_find_or_create_direct_conversation(p2p_context* ctx,
                                                  const char* peer_id,
                                                  char* out_id,
                                                  size_t out_id_cap)
{
    if (!ctx || !peer_id || !out_id || out_id_cap == 0) return -1;
    P2P_CTX_GUARD(ctx);
    const std::string id = ctx->appData->findOrCreateDirectConversation(peer_id);
    if (id.empty() || id.size() + 1 > out_id_cap) return -1;
    std::memcpy(out_id, id.data(), id.size());
    out_id[id.size()] = '\0';
    return 0;
}

int p2p_app_delete_conversation(p2p_context* ctx, const char* id)
{
    if (!ctx || !id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteConversation(id) ? 0 : -1;
}

int p2p_app_set_conversation_muted(p2p_context* ctx, const char* id, int muted)
{
    if (!ctx || !id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->setConversationMuted(id, muted != 0) ? 0 : -1;
}

int p2p_app_set_conversation_in_chat_list(p2p_context* ctx, const char* id, int in_list)
{
    if (!ctx || !id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->setConversationInChatList(id, in_list != 0) ? 0 : -1;
}

void p2p_app_load_conversations(p2p_context* ctx,
                                  p2p_conversation_cb cb,
                                  void* ud)
{
    if (!ctx || !cb) return;
    // Snapshot before firing callbacks — same lock-discipline reason
    // as p2p_app_load_contacts (callbacks may re-enter the API).
    std::vector<AppDataStore::Conversation> snapshot;
    {
        P2P_CTX_GUARD(ctx);
        ctx->appData->loadAllConversations(
            [&](const AppDataStore::Conversation& c) {
                snapshot.push_back(c);
            });
    }
    for (const auto& c : snapshot) {
        const char* kind = c.kind == AppDataStore::ConversationKind::Group
                               ? "group" : "direct";
        cb(c.id.c_str(),
           kind,
           c.directPeerId.c_str(),
           c.groupName.c_str(),
           c.groupAvatarB64.c_str(),
           c.muted ? 1 : 0,
           c.lastActiveSecs,
           c.inChatList ? 1 : 0,
           ud);
    }
}

int p2p_app_set_conversation_members(p2p_context* ctx,
                                        const char* conversation_id,
                                        const char* const* peer_ids)
{
    if (!ctx || !conversation_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->setConversationMembers(conversation_id,
                                                  fromCArray(peer_ids))
        ? 0 : -1;
}

void p2p_app_load_conversation_members(p2p_context* ctx,
                                          const char* conversation_id,
                                          p2p_conversation_member_cb cb,
                                          void* ud)
{
    if (!ctx || !conversation_id || !cb) return;
    std::vector<std::string> snapshot;
    {
        P2P_CTX_GUARD(ctx);
        ctx->appData->loadConversationMembers(
            conversation_id,
            [&](const std::string& pid) { snapshot.push_back(pid); });
    }
    for (const auto& pid : snapshot) cb(pid.c_str(), ud);
}

int p2p_app_save_setting(p2p_context* ctx, const char* key, const char* value)
{
    if (!ctx || !key) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->saveSetting(key, value ? value : "") ? 0 : -1;
}

const char* p2p_app_load_setting(p2p_context* ctx, const char* key,
                                  const char* default_value)
{
    if (!ctx || !key) return default_value ? default_value : "";
    P2P_CTX_GUARD(ctx);
    ctx->scratch = ctx->appData->loadSetting(key, default_value ? default_value : "");
    return ctx->scratch.c_str();
}

// Tier 1 PQ — identity-bundle plumbing exposed to platform code.

int p2p_maybe_publish_identity_bundle(p2p_context* ctx)
{
    if (!ctx) return -1;
    P2P_CTX_GUARD(ctx);
    if (!ctx->controller) return -1;
    return ctx->controller->maybePublishIdentityBundle() ? 1 : 0;
}

void p2p_request_identity_bundle_fetch(p2p_context* ctx,
                                          const char* peer_id_b64u)
{
    if (!ctx || !peer_id_b64u || !*peer_id_b64u) return;
    P2P_CTX_GUARD(ctx);
    if (!ctx->controller) return;
    ctx->controller->requestIdentityBundleFetch(peer_id_b64u);
}

int p2p_app_save_file_record(p2p_context* ctx,
                              const char* transfer_id,
                              const char* chat_key,
                              const char* file_name,
                              int64_t file_size,
                              const char* peer_id,
                              const char* peer_name,
                              int64_t timestamp_secs,
                              int sent,
                              int status,
                              int chunks_total,
                              int chunks_complete,
                              const char* saved_path)
{
    if (!ctx || !transfer_id || !chat_key) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::FileRecord r;
    r.transferId      = transfer_id;
    r.chatKey         = chat_key;
    r.fileName        = file_name  ? file_name  : "";
    r.fileSize        = file_size;
    r.peerIdB64u      = peer_id    ? peer_id    : "";
    r.peerName        = peer_name  ? peer_name  : "";
    r.timestampSecs   = timestamp_secs;
    r.sent            = sent != 0;
    r.status          = status;
    r.chunksTotal     = chunks_total;
    r.chunksComplete  = chunks_complete;
    r.savedPath       = saved_path ? saved_path : "";
    return ctx->appData->saveFileRecord(chat_key, r) ? 0 : -1;
}

int p2p_app_delete_file_record(p2p_context* ctx, const char* transfer_id)
{
    if (!ctx || !transfer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteFileRecord(transfer_id) ? 0 : -1;
}

int p2p_app_delete_file_records_for_chat(p2p_context* ctx, const char* chat_key)
{
    if (!ctx || !chat_key) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteFileRecordsForChat(chat_key) ? 0 : -1;
}

void p2p_app_load_file_records(p2p_context* ctx, const char* chat_key,
                                p2p_file_record_cb cb, void* ud)
{
    if (!ctx || !chat_key || !cb) return;
    P2P_CTX_GUARD(ctx);
    ctx->appData->loadFileRecords(chat_key, [&](const AppDataStore::FileRecord& r) {
        cb(r.transferId.c_str(),
           r.fileName.c_str(),
           r.fileSize,
           r.peerIdB64u.c_str(),
           r.peerName.c_str(),
           r.timestampSecs,
           r.sent ? 1 : 0,
           r.status,
           r.chunksTotal,
           r.chunksComplete,
           r.savedPath.c_str(),
           ud);
    });
}

// ── Stateless validators ───────────────────────────────────────────────────

int p2p_is_valid_peer_id(const char* key)
{
    if (!key) return 0;
    // Peer IDs are Ed25519 public keys base64url-encoded without padding:
    // 32 bytes → exactly 43 characters from [A-Z a-z 0-9 _ -].
    const size_t n = std::strlen(key);
    if (n != 43) return 0;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(key[i]);
        const bool ok = (c >= 'A' && c <= 'Z')
                     || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9')
                     || c == '_' || c == '-';
        if (!ok) return 0;
    }
    return 1;
}

// ── Contacts import/export (JSON wire format) ─────────────────────────────

int p2p_export_contacts_json(p2p_context* ctx, char** out_json)
{
    if (!ctx || !out_json) return -1;
    std::string s;
    {
        P2P_CTX_GUARD(ctx);
        s = ctx->appData->exportContactsJson();
    }
    char* buf = static_cast<char*>(std::malloc(s.size() + 1));
    if (!buf) return -1;
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    *out_json = buf;
    return 0;
}

int p2p_import_contacts_json(p2p_context* ctx, const char* json)
{
    if (!ctx || !json) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->importContactsJson(json);
}

// ── Migration (device-to-device account transfer) ───────────────────────────
//
// Stateless thin wrappers around MigrationCrypto::*.  No p2p_context
// guard — these don't touch any session / DB / relay state, they're
// pure crypto operations using libsodium + liboqs.  Threading-wise
// the underlying libs are reentrant so multiple migration flows
// in flight don't conflict (not that there will be — exactly one
// migration ever runs at a time per device pair).

int p2p_migration_keypair(uint8_t* x25519_pub,
                           uint8_t* x25519_priv,
                           uint8_t* mlkem_pub,
                           uint8_t* mlkem_priv)
{
    if (!x25519_pub || !x25519_priv || !mlkem_pub || !mlkem_priv) return -1;

    auto k = MigrationCrypto::generateKeypairs();
    if (k.x25519Pub.size()  != MigrationCrypto::kX25519PubLen)  return -1;
    if (k.x25519Priv.size() != MigrationCrypto::kX25519PrivLen) return -1;
    if (k.mlkemPub.size()   != MigrationCrypto::kMlkemPubLen)   return -1;
    if (k.mlkemPriv.size()  != MigrationCrypto::kMlkemPrivLen)  return -1;

    std::memcpy(x25519_pub,  k.x25519Pub.data(),  k.x25519Pub.size());
    std::memcpy(x25519_priv, k.x25519Priv.data(), k.x25519Priv.size());
    std::memcpy(mlkem_pub,   k.mlkemPub.data(),   k.mlkemPub.size());
    std::memcpy(mlkem_priv,  k.mlkemPriv.data(),  k.mlkemPriv.size());

    // Wipe the temporaries inside the Keypairs struct — caller's
    // copies are now in their own buffers.
    CryptoEngine::secureZero(k.x25519Priv);
    CryptoEngine::secureZero(k.mlkemPriv);
    return 0;
}

int p2p_migration_fingerprint(const uint8_t* x25519_pub,
                               const uint8_t* mlkem_pub,
                               uint8_t* fingerprint_out)
{
    if (!x25519_pub || !mlkem_pub || !fingerprint_out) return -1;

    Bytes xPub(x25519_pub, x25519_pub + MigrationCrypto::kX25519PubLen);
    Bytes mPub(mlkem_pub,  mlkem_pub  + MigrationCrypto::kMlkemPubLen);
    Bytes fp = MigrationCrypto::fingerprint(xPub, mPub);
    if (fp.size() != MigrationCrypto::kFingerprintLen) return -1;

    std::memcpy(fingerprint_out, fp.data(), fp.size());
    return 0;
}

int p2p_migration_seal(const uint8_t* payload, int payload_len,
                        const uint8_t* receiver_x25519_pub,
                        const uint8_t* receiver_mlkem_pub,
                        const uint8_t* handshake_nonce,
                        uint8_t* envelope_out, int envelope_cap)
{
    if (!payload || payload_len <= 0)        return -1;
    if (!receiver_x25519_pub)                return -1;
    if (!receiver_mlkem_pub)                 return -1;
    if (!handshake_nonce)                    return -1;
    if (!envelope_out || envelope_cap <= 0)  return -1;

    Bytes pl(payload, payload + payload_len);
    Bytes rxPub(receiver_x25519_pub,
                 receiver_x25519_pub + MigrationCrypto::kX25519PubLen);
    Bytes rmPub(receiver_mlkem_pub,
                 receiver_mlkem_pub + MigrationCrypto::kMlkemPubLen);
    Bytes nonce(handshake_nonce,
                 handshake_nonce + MigrationCrypto::kHandshakeNonceLen);

    Bytes env = MigrationCrypto::seal(pl, rxPub, rmPub, nonce);
    if (env.empty()) return -1;
    if (static_cast<int>(env.size()) > envelope_cap) return -1;

    std::memcpy(envelope_out, env.data(), env.size());
    return static_cast<int>(env.size());
}

int p2p_migration_open(const uint8_t* envelope, int envelope_len,
                        const uint8_t* receiver_x25519_pub,
                        const uint8_t* receiver_x25519_priv,
                        const uint8_t* receiver_mlkem_pub,
                        const uint8_t* receiver_mlkem_priv,
                        const uint8_t* handshake_nonce,
                        uint8_t* payload_out, int payload_cap)
{
    if (!envelope || envelope_len <= 0)      return -1;
    if (!receiver_x25519_pub)                return -1;
    if (!receiver_x25519_priv)               return -1;
    if (!receiver_mlkem_pub)                 return -1;
    if (!receiver_mlkem_priv)                return -1;
    if (!handshake_nonce)                    return -1;
    if (!payload_out || payload_cap <= 0)    return -1;

    Bytes env(envelope, envelope + envelope_len);
    Bytes rxPub(receiver_x25519_pub,
                 receiver_x25519_pub + MigrationCrypto::kX25519PubLen);
    Bytes rxPriv(receiver_x25519_priv,
                  receiver_x25519_priv + MigrationCrypto::kX25519PrivLen);
    Bytes rmPub(receiver_mlkem_pub,
                 receiver_mlkem_pub + MigrationCrypto::kMlkemPubLen);
    Bytes rmPriv(receiver_mlkem_priv,
                  receiver_mlkem_priv + MigrationCrypto::kMlkemPrivLen);
    Bytes nonce(handshake_nonce,
                 handshake_nonce + MigrationCrypto::kHandshakeNonceLen);

    Bytes pl = MigrationCrypto::open(env, rxPub, rxPriv,
                                       rmPub, rmPriv, nonce);
    // Wipe secret material we just copied into stack temporaries.
    CryptoEngine::secureZero(rxPriv);
    CryptoEngine::secureZero(rmPriv);
    if (pl.empty()) return -1;
    if (static_cast<int>(pl.size()) > payload_cap) return -1;

    std::memcpy(payload_out, pl.data(), pl.size());
    return static_cast<int>(pl.size());
}
