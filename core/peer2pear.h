/*
 * peer2pear.h — C API for the Peer2Pear messaging protocol
 *
 * This is the FFI boundary for mobile clients (iOS Swift, Android Kotlin/JNI).
 * All types are plain C — no C++, no Qt, no exceptions.
 *
 * Usage:
 *   1. Fill p2p_platform with your platform's WebSocket + HTTP implementations
 *   2. Call p2p_create() to get a context handle
 *   3. Set event callbacks (p2p_set_on_message, etc.)
 *   4. Call p2p_set_passphrase() + p2p_set_relay_url() + p2p_connect()
 *   5. Send messages with p2p_send_text(), receive via callbacks
 *   6. Call p2p_destroy() on shutdown
 *
 * Thread safety:
 *   All p2p_* calls must be made from the same thread (or serialized).
 *   Event callbacks fire on the same thread that processes platform events.
 *   The platform is responsible for dispatching to the UI thread if needed.
 */

#ifndef PEER2PEAR_H
#define PEER2PEAR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque context ─────────────────────────────────────────────────────── */

typedef struct p2p_context p2p_context;

/* ── Platform transport callbacks ───────────────────────────────────────
 *
 * The core library issues commands to the platform via these function
 * pointers. The platform responds asynchronously by calling the
 * corresponding p2p_ws_* / p2p_http_response functions below.
 *
 * `platform_ctx` is an opaque pointer owned by the platform — the core
 * library passes it through unchanged. Use it to reach your ObjC/Java/
 * Swift object from the C callback.
 */

typedef struct {
    /* WebSocket commands */
    void (*ws_open)(const char* url, void* platform_ctx);
    void (*ws_close)(void* platform_ctx);
    void (*ws_send_text)(const char* message, void* platform_ctx);
    int  (*ws_is_connected)(void* platform_ctx);
    int  (*ws_is_idle)(void* platform_ctx);

    /* HTTP commands — returns a request_id that the platform passes
     * back to p2p_http_response() when the request completes. */
    int  (*http_post)(const char* url,
                      const uint8_t* body, int body_len,
                      const char** header_keys,
                      const char** header_values,
                      int header_count,
                      void* platform_ctx);

    void* platform_ctx;
} p2p_platform;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/**
 * Create a new Peer2Pear context.
 * @param data_dir  Writable directory for identity keys and session DB.
 *                  iOS: NSDocumentDirectory. Android: Context.getFilesDir().
 * @param platform  Transport callbacks (WebSocket + HTTP). Copied internally.
 * @return Opaque context, or NULL on failure. Free with p2p_destroy().
 */
p2p_context* p2p_create(const char* data_dir, p2p_platform platform);

/** Destroy a context and free all resources. */
void p2p_destroy(p2p_context* ctx);

/* ── Identity ──────────────────────────────────────────────────────────── */

/**
 * Set the passphrase and derive/load the identity keypair.
 * Must be called before p2p_connect().
 */
void p2p_set_passphrase(p2p_context* ctx, const char* passphrase);

/**
 * Get this device's peer ID (base64url-encoded Ed25519 public key).
 * Returns a pointer valid until the next p2p_* call. Do not free.
 */
const char* p2p_my_id(p2p_context* ctx);

/* ── Relay ─────────────────────────────────────────────────────────────── */

/** Set the relay server URL (e.g., "https://relay.peer2pear.org:8443"). */
void p2p_set_relay_url(p2p_context* ctx, const char* url);

/** Connect to the relay (authenticate via WebSocket). */
void p2p_connect(p2p_context* ctx);

/** Disconnect from the relay. */
void p2p_disconnect(p2p_context* ctx);

/** Add a relay to the send pool (for multi-relay rotation). */
void p2p_add_send_relay(p2p_context* ctx, const char* url);

/**
 * Set privacy level:
 *   0 = Standard:  envelope padding only (default)
 *   1 = Enhanced:  + send jitter + cover traffic + multi-relay rotation
 *   2 = Maximum:   + multi-hop forwarding + high-frequency cover traffic
 */
void p2p_set_privacy_level(p2p_context* ctx, int level);

/* ── Messaging ─────────────────────────────────────────────────────────── */

/**
 * Send an encrypted text message to a peer.
 * @return 0 on success, -1 on failure (no session, seal failed, etc.)
 */
int p2p_send_text(p2p_context* ctx, const char* peer_id, const char* text);

/**
 * Send an encrypted text message to a group.
 * @param member_ids  NULL-terminated array of peer ID strings.
 */
int p2p_send_group_text(p2p_context* ctx,
                        const char* group_id,
                        const char* group_name,
                        const char** member_ids,
                        const char* text);

/* ── File transfer ─────────────────────────────────────────────────────── */

/**
 * Send an encrypted file to a peer. Path-based — the file is streamed from
 * disk and never fully loaded into RAM. The caller owns the file on disk.
 *
 * The receiver evaluates consent on arrival: auto-accept, auto-decline, or
 * prompt their user. Chunks are not streamed until a file_accept arrives.
 *
 * @param peer_id    base64url recipient public key
 * @param file_name  display name shown to the receiver (basename)
 * @param file_path  absolute path to the source file
 * @return Transfer ID string (valid until next call), or NULL on failure.
 */
const char* p2p_send_file(p2p_context* ctx,
                          const char* peer_id,
                          const char* file_name,
                          const char* file_path);

/**
 * Respond to a pending incoming file transfer (Phase 2 consent).
 * Called from the app after the user taps Accept or Decline in response to
 * an on_file_request callback.
 *
 * @param accept       1 = accept, 0 = decline
 * @param require_p2p  only meaningful when accept==1. If 1, the sender is
 *                     told to abort rather than fall back to relay.
 */
void p2p_respond_file_request(p2p_context* ctx,
                              const char* transfer_id,
                              int accept,
                              int require_p2p);

/**
 * Cancel an in-flight transfer. Works for both outbound (sender canceling
 * their own send) and inbound (receiver canceling mid-stream). Sends
 * file_cancel to the peer and cleans up local state.
 */
void p2p_cancel_transfer(p2p_context* ctx, const char* transfer_id);

/* ── File-transfer consent settings ───────────────────────────────────── */

/**
 * Phase 2 consent settings. Files ≤ auto_accept_mb auto-accept.
 * Files > hard_max_mb auto-decline. Between the two prompts the user.
 * If require_p2p is true, file_accept responses tell the sender to abort
 * unless a direct P2P connection is available.
 */
void p2p_set_file_auto_accept_mb(p2p_context* ctx, int mb);
void p2p_set_file_hard_max_mb(p2p_context* ctx, int mb);
void p2p_set_file_require_p2p(p2p_context* ctx, int enabled);

/* ── Presence ──────────────────────────────────────────────────────────── */

/** Check if peers are online (results via on_presence callback). */
void p2p_check_presence(p2p_context* ctx, const char** peer_ids, int count);

/** Subscribe to presence updates for peers (pushed via on_presence). */
void p2p_subscribe_presence(p2p_context* ctx, const char** peer_ids, int count);

/* ── Platform → Core events ────────────────────────────────────────────
 *
 * The platform calls these when transport events occur.
 * These must be called from the same thread as other p2p_* calls.
 */

/** Platform: WebSocket connected successfully. */
void p2p_ws_on_connected(p2p_context* ctx);

/** Platform: WebSocket disconnected or connection lost. */
void p2p_ws_on_disconnected(p2p_context* ctx);

/** Platform: Binary frame received on WebSocket. */
void p2p_ws_on_binary(p2p_context* ctx, const uint8_t* data, int len);

/** Platform: Text frame received on WebSocket. */
void p2p_ws_on_text(p2p_context* ctx, const char* message);

/**
 * Platform: HTTP POST completed.
 * @param request_id  The ID returned by the platform's http_post() callback.
 * @param status      HTTP status code (0 on network failure).
 * @param body        Response body (may be NULL).
 * @param body_len    Response body length.
 * @param error       Error string (NULL on success).
 */
void p2p_http_response(p2p_context* ctx, int request_id,
                       int status, const uint8_t* body, int body_len,
                       const char* error);

/* ── Event callbacks (Core → App) ──────────────────────────────────────
 *
 * Set these to receive events from the protocol engine.
 * All callbacks include a `void* ud` (user data) that you provide.
 * Callbacks fire on the core thread — dispatch to UI thread if needed.
 */

void p2p_set_on_status(p2p_context* ctx,
    void (*cb)(const char* message, void* ud), void* ud);

void p2p_set_on_connected(p2p_context* ctx,
    void (*cb)(void* ud), void* ud);

void p2p_set_on_message(p2p_context* ctx,
    void (*cb)(const char* from_peer_id,
               const char* text,
               int64_t timestamp_sec,
               const char* msg_id,
               void* ud),
    void* ud);

void p2p_set_on_group_message(p2p_context* ctx,
    void (*cb)(const char* from_peer_id,
               const char* group_id,
               const char* group_name,
               const char** member_ids,    /* NULL-terminated */
               const char* text,
               int64_t timestamp_sec,
               const char* msg_id,
               void* ud),
    void* ud);

void p2p_set_on_presence(p2p_context* ctx,
    void (*cb)(const char* peer_id, int online, void* ud), void* ud);

/**
 * File transfer progress callback.
 * saved_path is the on-disk location of the received file, non-NULL only
 * when chunks_received == chunks_total (transfer complete). Files are
 * streamed directly to disk — no full-file buffer is ever passed to the app.
 */
void p2p_set_on_file_progress(p2p_context* ctx,
    void (*cb)(const char* from_peer_id,
               const char* transfer_id,
               const char* file_name,
               int64_t file_size,
               int chunks_received,
               int chunks_total,
               const char* saved_path,   /* non-NULL only when complete */
               int64_t timestamp_sec,
               void* ud),
    void* ud);

void p2p_set_on_avatar(p2p_context* ctx,
    void (*cb)(const char* peer_id,
               const char* display_name,
               const char* avatar_b64,
               void* ud),
    void* ud);

/**
 * Phase 2: an incoming file transfer needs the user's consent.
 * The app should display a prompt with sender + filename + size and then
 * call p2p_respond_file_request() with the user's choice.
 */
void p2p_set_on_file_request(p2p_context* ctx,
    void (*cb)(const char* from_peer_id,
               const char* transfer_id,
               const char* file_name,
               int64_t file_size,
               void* ud),
    void* ud);

/**
 * Phase 2: a transfer was canceled, declined, or abandoned.
 * by_receiver == 1 → receiver declined or canceled
 * by_receiver == 0 → sender canceled or the outbound-pending timer expired
 */
void p2p_set_on_file_canceled(p2p_context* ctx,
    void (*cb)(const char* transfer_id, int by_receiver, void* ud),
    void* ud);

/**
 * Phase 3: sender-side — receiver confirmed the full file landed + hash ok.
 */
void p2p_set_on_file_delivered(p2p_context* ctx,
    void (*cb)(const char* transfer_id, void* ud),
    void* ud);

/**
 * Phase 3: transport policy blocked the transfer (P2P required, P2P failed).
 * by_receiver == 1 → recipient's requireP2P refused relay fallback
 * by_receiver == 0 → our own require_p2p setting refused relay fallback
 */
void p2p_set_on_file_blocked(p2p_context* ctx,
    void (*cb)(const char* transfer_id, int by_receiver, void* ud),
    void* ud);

#ifdef __cplusplus
}
#endif

#endif /* PEER2PEAR_H */
