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

    CWebSocket        ws;
    CHttpClient       http;
    StdTimerFactory   timers;

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
    } cb;

    std::string dataDir;

    p2p_context(p2p_platform platform)
        : ws(platform)
        , http(platform)
        , timers(&ctrlMu)
        , db(std::make_unique<SqlCipherDb>())
        , appData(std::make_unique<AppDataStore>())
        , controller(std::make_unique<ChatController>(ws, http, timers))
    {}
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
    // FFI hardening: a buggy or hostile platform adapter could pass
    // (NULL, anything) or (anything, negative).  Constructing
    // Bytes(data, data + len) under those conditions is UB — even
    // (nullptr, 0) is technically UB per [expr.add]/4 since pointer
    // arithmetic on null is undefined.  Treat malformed inputs as
    // "drop the frame" rather than crash.
    if (len < 0) return;
    if (!data && len > 0) return;
    P2P_CTX_GUARD(ctx);
    if (ctx->ws.onBinaryMessage) {
        Bytes buf;
        if (data && len > 0) buf.assign(data, data + len);
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
                          const char* const* keys,
                          int is_blocked,
                          int is_group,
                          const char* group_id,
                          const char* avatar_b64,
                          int64_t last_active_secs,
                          int in_address_book)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::Contact c;
    c.peerIdB64u     = peer_id;
    c.name           = name      ? name     : "";
    c.subtitle       = subtitle  ? subtitle : "";
    c.keys           = fromCArray(keys);
    c.isBlocked      = is_blocked != 0;
    c.isGroup        = is_group   != 0;
    c.groupId        = group_id   ? group_id   : "";
    c.avatarB64      = avatar_b64 ? avatar_b64 : "";
    c.lastActiveSecs = last_active_secs;
    c.inAddressBook  = in_address_book != 0;
    return ctx->appData->saveContact(c) ? 0 : -1;
}

int p2p_app_delete_contact(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteContact(peer_id) ? 0 : -1;
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

    std::vector<const char*> keysStorage;
    for (const auto& c : snapshot) {
        toCArray(c.keys, keysStorage);
        cb(c.peerIdB64u.c_str(),
           c.name.c_str(),
           c.subtitle.c_str(),
           keysStorage.data(),
           c.isBlocked ? 1 : 0,
           c.isGroup   ? 1 : 0,
           c.groupId.c_str(),
           c.avatarB64.c_str(),
           c.lastActiveSecs,
           c.inAddressBook ? 1 : 0,
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
                          const char* peer_id,
                          int sent,
                          const char* text,
                          int64_t timestamp_secs,
                          const char* msg_id,
                          const char* sender_name)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    AppDataStore::Message m;
    m.sent          = sent != 0;
    m.text          = text        ? text        : "";
    m.timestampSecs = timestamp_secs;
    m.msgId         = msg_id      ? msg_id      : "";
    m.senderName    = sender_name ? sender_name : "";
    return ctx->appData->saveMessage(peer_id, m) ? 0 : -1;
}

void p2p_app_load_messages(p2p_context* ctx, const char* peer_id,
                            p2p_message_cb cb, void* ud)
{
    if (!ctx || !peer_id || !cb) return;
    P2P_CTX_GUARD(ctx);
    ctx->appData->loadMessages(peer_id, [&](const AppDataStore::Message& m) {
        cb(m.sent ? 1 : 0,
           m.text.c_str(),
           m.timestampSecs,
           m.msgId.c_str(),
           m.senderName.c_str(),
           ud);
    });
}

int p2p_app_delete_messages(p2p_context* ctx, const char* peer_id)
{
    if (!ctx || !peer_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteMessages(peer_id) ? 0 : -1;
}

int p2p_app_delete_message(p2p_context* ctx, const char* peer_id, const char* msg_id)
{
    if (!ctx || !peer_id || !msg_id) return -1;
    P2P_CTX_GUARD(ctx);
    return ctx->appData->deleteMessage(peer_id, msg_id) ? 0 : -1;
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
