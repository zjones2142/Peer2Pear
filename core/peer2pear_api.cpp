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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

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

// ── StdTimer / StdTimerFactory: thread-based, no Qt dependency. ────────────
//
// The C API hosts (iOS, Android, generic) don't have a Qt event loop.  These
// timers spawn a worker thread per timer that sleeps until the deadline (or
// a cancellation signal arrives) and then fires the callback.
//
// C2 audit-#2 fix: every p2p_* entry point and every timer callback
// serializes on p2p_context::ctrlMu (see p2p_guard below), so the host's
// WS/HTTP callbacks and the maintenance timer can't race on ChatController
// state.  The factory threads themselves still run in parallel — they just
// take the lock before invoking the user's lambda, which is where the data
// race lived.

class StdTimer : public ITimer {
public:
    // ctrlMu must outlive every callback we fire.  In practice the
    // p2p_context owns both this timer and the mutex, destroyed together.
    explicit StdTimer(std::mutex* ctrlMu) : m_ctrlMu(ctrlMu) {}
    ~StdTimer() override { cancelAndJoin(); }

    StdTimer(const StdTimer&) = delete;
    StdTimer& operator=(const StdTimer&) = delete;

    void startSingleShot(int delayMs, std::function<void()> cb) override {
        cancelAndJoin();
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_canceled = false;
            m_active = true;
        }
        auto* ctrlMu = m_ctrlMu;
        m_thread = std::thread([this, delayMs, ctrlMu, cb = std::move(cb)]() {
            std::unique_lock<std::mutex> lk(m_mu);
            const bool gotCancel = m_cv.wait_for(
                lk, std::chrono::milliseconds(delayMs),
                [this] { return m_canceled; });
            const bool fire = !gotCancel;
            m_active = false;
            lk.unlock();
            if (fire && cb) {
                // Serialize with p2p_* entry points (C2 audit fix).
                if (ctrlMu) {
                    std::lock_guard<std::mutex> cg(*ctrlMu);
                    cb();
                } else {
                    cb();
                }
            }
        });
    }

    void stop() override { cancelAndJoin(); }

    bool isActive() const override {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_active;
    }

private:
    void cancelAndJoin() {
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_canceled = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }

    mutable std::mutex      m_mu;
    std::condition_variable m_cv;
    bool                    m_canceled = false;
    bool                    m_active   = false;
    std::thread             m_thread;
    std::mutex*             m_ctrlMu   = nullptr;
};

class StdTimerFactory : public ITimerFactory {
public:
    explicit StdTimerFactory(std::mutex* ctrlMu) : m_ctrlMu(ctrlMu) {}

    ~StdTimerFactory() override { shutdown(); }

    // Drain any still-pending singleShot worker threads.  MUST be called
    // by p2p_destroy BEFORE tearing down the ChatController — otherwise a
    // cb mid-execution can dereference the already-destroyed controller
    // (the cb captured references to it).  Idempotent.
    void shutdown() {
        std::vector<std::thread> pending;
        {
            std::lock_guard<std::mutex> lk(m_bagMu);
            if (m_shuttingDown) return;
            m_shuttingDown = true;
            pending.swap(m_bag);
        }
        for (auto& t : pending) {
            if (t.joinable()) t.join();
        }
    }

    std::unique_ptr<ITimer> create() override {
        return std::make_unique<StdTimer>(m_ctrlMu);
    }

    void singleShot(int delayMs, std::function<void()> cb) override {
        auto* ctrlMu = m_ctrlMu;
        auto* self = this;
        std::thread t([self, delayMs, ctrlMu, cb = std::move(cb)]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            if (!cb) return;
            // If the factory is being torn down by now, the p2p_context
            // is mid-destruction — skip the callback; the shutdown path
            // will join this thread.
            {
                std::lock_guard<std::mutex> lk(self->m_bagMu);
                if (self->m_shuttingDown) return;
            }
            if (ctrlMu) {
                std::lock_guard<std::mutex> cg(*ctrlMu);
                cb();
            } else {
                cb();
            }
        });
        // Stash the handle so the dtor can join it.  The bag grows for
        // the session lifetime (bounded by call count — jitter timers
        // etc.); process teardown drains it.  A more aggressive GC could
        // track "done" flags per thread, but the simplest-correct shape
        // is to just keep handles until shutdown.
        std::lock_guard<std::mutex> lk(m_bagMu);
        if (m_shuttingDown) {
            // Racing with destruction — detach and let the thread's own
            // m_shuttingDown re-check skip the cb.
            t.detach();
        } else {
            m_bag.push_back(std::move(t));
        }
    }

private:
    std::mutex*              m_ctrlMu = nullptr;
    std::mutex               m_bagMu;
    std::vector<std::thread> m_bag;
    bool                     m_shuttingDown = false;
};

// ── p2p_context: the opaque handle ──────────────────────────────────────────

struct p2p_context {
    // C2 audit-#2 fix: every p2p_* entry point (and every timer callback)
    // takes this mutex before touching controller / ws / http / cb.  This
    // serializes the maintenance timer against the host's WS/HTTP
    // callbacks — they used to race on ChatController state (fields like
    // m_envelopeCount, m_fileKeys, m_pendingIncomingFiles, m_sessionStore)
    // because the timer fired on its own worker thread.
    //
    // Mutex MUST be declared before timers/controller so it outlives any
    // callback thread they spawn: C++ destroys members in reverse order,
    // so the timers / controller tear down first and their worker threads
    // join while ctrlMu is still alive.
    std::mutex        ctrlMu;

    CWebSocket        ws;
    CHttpClient       http;
    StdTimerFactory   timers;
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

        // Safety numbers
        void (*on_peer_key_changed)(const char*,
                                    const uint8_t*, int,
                                    const uint8_t*, int,
                                    void*) = nullptr;
        void* peer_key_changed_ud = nullptr;
    } cb;

    std::string dataDir;

    p2p_context(p2p_platform platform)
        : ws(platform)
        , http(platform)
        , timers(&ctrlMu)
        , controller(ws, http, timers)
    {}
};

// Scope guard for C2: serializes every public p2p_* entry point.
// Recursive is overkill (we never re-enter), plain lock_guard suffices.
#define P2P_CTX_GUARD(ctx) std::lock_guard<std::mutex> _p2p_lock((ctx)->ctrlMu)

// ── Helper: assign ChatController callbacks → C FFI callbacks ──────────────
//
// ChatController is a plain class with std-typed callbacks (Phase 7c).
// Each lambda just forwards arguments to the matching C function pointer.

static void wire_signals(p2p_context* ctx)
{
    auto& c = ctx->controller;

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
            std::vector<const char*> memberPtrs;
            memberPtrs.reserve(memberKeys.size() + 1);
            for (const std::string& k : memberKeys) memberPtrs.push_back(k.c_str());
            memberPtrs.push_back(nullptr);

            ctx->cb.on_group_message(
                from.c_str(), groupId.c_str(), groupName.c_str(),
                memberPtrs.data(), text.c_str(),
                tsSecs, msgId.c_str(),
                ctx->cb.group_message_ud);
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
        ctx->controller.setDataDir(ctx->dataDir);
    wire_signals(ctx);
    return ctx;
}

void p2p_destroy(p2p_context* ctx)
{
    if (!ctx) return;
    // C2 audit-#2 fix: drain timer worker threads *before* any other
    // teardown.  A still-running singleShot cb holds captured references
    // into ChatController; destroying it first would UAF.  Everything
    // below runs under the ctrlMu so we serialize with any host-driven
    // p2p_* entry points that might still be in flight.
    ctx->timers.shutdown();
    {
        std::lock_guard<std::mutex> lk(ctx->ctrlMu);
        ctx->controller.disconnectFromRelay();
    }
    delete ctx;
}

void p2p_set_passphrase(p2p_context* ctx, const char* passphrase)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    // M2 audit fix (2026-04-19): keep the passphrase copy in a named local
    // so we can zero it on the way out.  Previously an implicit std::string
    // temporary was created on-the-fly and destructed with the passphrase
    // bytes still in its buffer.  The caller's own `passphrase` C string is
    // out of our control — the header documents that they must zero it.
    std::string pass = passphrase ? passphrase : "";
    ctx->controller.setPassphrase(pass);
    CryptoEngine::secureZero(pass);
}

int p2p_set_passphrase_v2(p2p_context* ctx, const char* passphrase)
{
    if (!ctx || !passphrase || passphrase[0] == '\0') return -1;
    // M3 audit fix: enforce the library-side strength floor.  Platform UIs
    // should reject weak passphrases long before they reach this entry,
    // but a byte-length check here keeps the core from ever accepting a
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

    // M2 fix: route the passphrase through one named local we can zero
    // on every exit path, so no intermediate std::string holds it after
    // this function returns.
    std::string pass = passphrase;

    Bytes masterKey = CryptoEngine::deriveMasterKey(pass, salt);
    if (masterKey.size() != 32) {
        CryptoEngine::secureZero(pass);
        return -1;
    }

    // HKDF info label must stay byte-identical to what the desktop
    // onboarding flow uses (mainwindow.cpp:115) so v4→v5 migration
    // succeeds across frontends.
    static const char kIdentityInfo[] = "identity-unlock";
    Bytes info(
        reinterpret_cast<const uint8_t*>(kIdentityInfo),
        reinterpret_cast<const uint8_t*>(kIdentityInfo)
            + sizeof(kIdentityInfo) - 1);

    Bytes identityKey = CryptoEngine::deriveSubkey(masterKey, info);
    CryptoEngine::secureZero(masterKey);
    if (identityKey.size() != 32) {
        CryptoEngine::secureZero(pass);
        return -1;
    }

    int rc = 0;
    try {
        ctx->controller.setPassphrase(pass, identityKey);
    } catch (...) {
        rc = -1;  // wrong passphrase or corrupted identity.json
    }
    CryptoEngine::secureZero(identityKey);
    CryptoEngine::secureZero(pass);
    return rc;
}

const char* p2p_my_id(p2p_context* ctx)
{
    if (!ctx) return "";
    P2P_CTX_GUARD(ctx);
    ctx->scratch = ctx->controller.myIdB64u();
    return ctx->scratch.c_str();
}

const char* p2p_safety_number(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return "";
    P2P_CTX_GUARD(ctx);
    ctx->scratch = ctx->controller.safetyNumber(peer_id);
    return ctx->scratch.c_str();
}

int p2p_peer_trust(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return P2P_PEER_UNVERIFIED;
    P2P_CTX_GUARD(ctx);
    switch (ctx->controller.peerTrust(peer_id)) {
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
    return ctx->controller.markPeerVerified(peer_id) ? 0 : -1;
}

void p2p_unverify_peer(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.unverifyPeer(peer_id);
}

void p2p_set_hard_block_on_key_change(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.setHardBlockOnKeyChange(enabled != 0);
}

void p2p_set_relay_url(p2p_context* ctx, const char* url)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.setRelayUrl(url ? url : "");
}

void p2p_connect(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.connectToRelay();
}

void p2p_disconnect(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.disconnectFromRelay();
}

int p2p_send_text(p2p_context* ctx, const char* peer_id, const char* text)
{
    if (!ctx || !peer_id || !text) return -1;
    P2P_CTX_GUARD(ctx);
    ctx->controller.sendText(peer_id, text);
    return 0;
}

int p2p_send_group_text(p2p_context* ctx,
                        const char* group_id,
                        const char* group_name,
                        const char** member_ids,
                        const char* text)
{
    if (!ctx || !group_id || !text || !member_ids) return -1;
    P2P_CTX_GUARD(ctx);
    std::vector<std::string> members;
    for (const char** p = member_ids; *p; ++p)
        members.emplace_back(*p);
    ctx->controller.sendGroupMessageViaMailbox(
        group_id,
        group_name ? group_name : "",
        members, text);
    return 0;
}

const char* p2p_send_file(p2p_context* ctx,
                          const char* peer_id,
                          const char* file_name,
                          const char* file_path)
{
    if (!ctx || !peer_id || !file_name || !file_path) return nullptr;
    P2P_CTX_GUARD(ctx);
    std::string tid = ctx->controller.sendFile(peer_id, file_name, file_path);
    if (tid.empty()) return nullptr;
    ctx->scratch = std::move(tid);
    return ctx->scratch.c_str();
}

// ── Phase 2: file consent + cancel ──────────────────────────────────────────

void p2p_respond_file_request(p2p_context* ctx,
                              const char* transfer_id,
                              int accept,
                              int require_p2p)
{
    if (!ctx || !transfer_id) return;
    P2P_CTX_GUARD(ctx);
    const std::string tid = transfer_id;
    if (accept) {
        ctx->controller.acceptFileTransfer(tid, require_p2p != 0);
    } else {
        ctx->controller.declineFileTransfer(tid);
    }
}

void p2p_cancel_transfer(p2p_context* ctx, const char* transfer_id)
{
    if (!ctx || !transfer_id) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.cancelFileTransfer(transfer_id);
}

void p2p_set_file_auto_accept_mb(p2p_context* ctx, int mb)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.setFileAutoAcceptMaxMB(mb);
}

void p2p_set_file_hard_max_mb(p2p_context* ctx, int mb)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.setFileHardMaxMB(mb);
}

void p2p_set_file_require_p2p(p2p_context* ctx, int enabled)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.setFileRequireP2P(enabled != 0);
}

void p2p_check_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    P2P_CTX_GUARD(ctx);
    std::vector<std::string> ids;
    ids.reserve(count);
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids.emplace_back(peer_ids[i]);
    ctx->controller.checkPresence(ids);
}

void p2p_subscribe_presence(p2p_context* ctx, const char** peer_ids, int count)
{
    if (!ctx || !peer_ids) return;
    P2P_CTX_GUARD(ctx);
    std::vector<std::string> ids;
    ids.reserve(count);
    for (int i = 0; i < count; i++)
        if (peer_ids[i]) ids.emplace_back(peer_ids[i]);
    ctx->controller.subscribePresence(ids);
}

void p2p_add_send_relay(p2p_context* ctx, const char* url)
{
    if (!ctx || !url) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.relay().addSendRelay(url ? std::string(url) : std::string());
}

void p2p_set_privacy_level(p2p_context* ctx, int level)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    ctx->controller.relay().setPrivacyLevel(level);
}

// ── Platform → Core events ──────────────────────────────────────────────────

void p2p_ws_on_connected(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (ctx->ws.onConnected) ctx->ws.onConnected();
}

void p2p_ws_on_disconnected(p2p_context* ctx)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (ctx->ws.onDisconnected) ctx->ws.onDisconnected();
}

void p2p_ws_on_binary(p2p_context* ctx, const uint8_t* data, int len)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (ctx->ws.onBinaryMessage) {
        IWebSocket::Bytes buf(data, data + len);
        ctx->ws.onBinaryMessage(buf);
    }
}

void p2p_ws_on_text(p2p_context* ctx, const char* message)
{
    if (!ctx) return;
    P2P_CTX_GUARD(ctx);
    if (ctx->ws.onTextMessage)
        ctx->ws.onTextMessage(message ? std::string(message) : std::string());
}

void p2p_http_response(p2p_context* ctx, int request_id,
                       int status, const uint8_t* body, int body_len,
                       const char* error)
{
    if (!ctx) return;
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
