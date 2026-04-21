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
 * Minimum accepted passphrase length at the v2 FFI entry (M3 audit).
 * Measured in UTF-8 bytes — 8 ASCII chars minimum, or any UTF-8 string
 * whose encoded form is ≥ 8 bytes.  Platforms should enforce stronger
 * requirements in their onboarding UI (entropy, common-passwords list,
 * etc.); this is a library-side floor, not a policy.
 */
#define P2P_MIN_PASSPHRASE_BYTES 8

/**
 * Set the passphrase and derive/load the identity keypair.
 * Must be called before p2p_connect().
 *
 * DEPRECATED — new callers should use p2p_set_passphrase_v2().  This
 * function routes to the legacy per-key Argon2 derivation path which
 * runs Argon2id three times (once per private key) and can't be
 * migrated to v5 identity storage.
 *
 * Memory hygiene (M2 audit): the library zeros its own copies of the
 * passphrase after using them, but the caller's `passphrase` buffer is
 * out of its control.  Zero it yourself as soon as this function
 * returns if you want the bytes gone from process memory.
 */
void p2p_set_passphrase(p2p_context* ctx, const char* passphrase);

/**
 * Set the passphrase via the v5 unified key-derivation path (audit H4).
 *
 * Runs Argon2id MODERATE once over (passphrase, salt) → 32-byte master
 * key, then HKDFs `identity-unlock` → 32-byte identity key and installs
 * it on the controller.  Existing v4 identity files are migrated to v5
 * on first load.  The salt file lives at <data_dir>/keys/db_salt.bin
 * and is created on first use; data_dir is the one supplied to
 * p2p_create().
 *
 * Prefer this over p2p_set_passphrase(): mobile callers that use the
 * legacy function pay ~3x the Argon2 cost and are pinned to the older
 * on-disk layout.
 *
 * Memory hygiene (M2 audit): same contract as p2p_set_passphrase —
 * every intermediate copy the library makes is zeroed on return, but
 * the caller's `passphrase` buffer is not.  Wipe it yourself.
 *
 * Strength floor (M3 audit): passphrases shorter than
 * P2P_MIN_PASSPHRASE_BYTES (8) are rejected outright.  This is a
 * defense-in-depth check — platform UIs should enforce a stronger
 * policy before calling.
 *
 * @return 0 on success, non-zero on failure (null args, empty or too-
 *         short passphrase, p2p_create() was called without a
 *         data_dir, the salt file is corrupt, Argon2 failed, or the
 *         supplied passphrase can't decrypt an existing identity).
 */
int p2p_set_passphrase_v2(p2p_context* ctx, const char* passphrase);

/**
 * Get this device's peer ID (base64url-encoded Ed25519 public key).
 * Returns a pointer valid until the next p2p_* call. Do not free.
 */
const char* p2p_my_id(p2p_context* ctx);

/* ── Safety numbers / out-of-band key verification ───────────────────── */

/**
 * Return the 60-digit safety-number display string for the (self, peer)
 * pair — 12 groups of 5 digits separated by spaces.  Users compare the
 * string out-of-band to confirm the peerId wasn't MITM'd on contact
 * exchange.  Returns a pointer valid until the next p2p_* call; empty
 * string on any error (null ctx, bad peerId).
 */
const char* p2p_safety_number(p2p_context* ctx, const char* peer_id);

/**
 * Trust state for a peer, returned by p2p_peer_trust().
 *   0 = Unverified (no record; first contact; messaging allowed)
 *   1 = Verified   (stored fingerprint matches current)
 *   2 = Mismatch   (stored fingerprint no longer matches — usually means
 *                   local identity was regenerated; fires on_peer_key_changed
 *                   and is blocked when p2p_set_hard_block_on_key_change(1))
 */
#define P2P_PEER_UNVERIFIED 0
#define P2P_PEER_VERIFIED   1
#define P2P_PEER_MISMATCH   2
int p2p_peer_trust(p2p_context* ctx, const char* peer_id);

/**
 * Mark the current (self, peer) fingerprint as user-verified.  Call
 * after the user has compared the p2p_safety_number() display with the
 * peer out-of-band.  Returns 0 on success, -1 on invalid args.
 */
int p2p_mark_peer_verified(p2p_context* ctx, const char* peer_id);

/**
 * Forget any prior verification for peer_id — returns them to Unverified.
 */
void p2p_unverify_peer(p2p_context* ctx, const char* peer_id);

/**
 * Policy: when enabled, messages to/from a Mismatch peer are refused at
 * the core level.  Default is off (soft warn via on_peer_key_changed;
 * UI decides).  Enable to hard-block.
 */
void p2p_set_hard_block_on_key_change(p2p_context* ctx, int enabled);

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

/**
 * Register a push-notification token with the relay.  Called by
 * mobile clients after they receive a device token from APNs (iOS)
 * or FCM (Android).  The relay stores (peer_id, platform, token) so
 * it can fire a silent wake-up push when a new envelope arrives for
 * an offline recipient.
 *
 * `platform` is a short identifier like "ios" or "android".  Pass an
 * empty token to unregister (e.g., on sign-out).
 *
 * Safe to call any time after p2p_connect — the call is forwarded
 * to the relay over the authenticated WebSocket.
 */
void p2p_set_push_token(p2p_context* ctx,
                         const char* token,
                         const char* platform);

/**
 * Wake-up hook for background push arrivals.  Mobile silent-push
 * handlers invoke this from their background-task entry point;
 * internally it nudges the relay connection to drain any queued
 * envelopes that were waiting on this device.  Returns immediately;
 * completion signalling is via the usual on_message / on_group_message
 * callbacks.
 */
void p2p_wake_for_push(p2p_context* ctx);

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

/**
 * Send an encrypted file to every member of a group.
 * Same semantics as p2p_send_file; chunks stream to each recipient once
 * their file_accept arrives (Phase 2 consent).
 *
 * @return Transfer ID string (valid until next call), or NULL on failure.
 */
const char* p2p_send_group_file(p2p_context* ctx,
                                const char* group_id,
                                const char* group_name,
                                const char** member_ids,  /* NULL-terminated */
                                const char* file_name,
                                const char* file_path);

/**
 * Rename a group.  A `group_rename` control message is sent to every
 * member; they must surface it via on_group_renamed.
 * @return 0 on success, -1 on bad args.
 */
int p2p_rename_group(p2p_context* ctx,
                     const char* group_id,
                     const char* new_name,
                     const char** member_ids);

/**
 * Leave a group.  Sends a `group_leave` notification; peers receive it
 * via on_group_member_left and should remove us from their roster.
 * No local state is deleted here — the app decides whether to drop
 * the group from its own UI after the send completes.
 * @return 0 on success, -1 on bad args.
 */
int p2p_leave_group(p2p_context* ctx,
                    const char* group_id,
                    const char* group_name,
                    const char** member_ids);

/**
 * Publish a new group avatar to every member.  `avatar_b64` is the same
 * base64 PNG/JPEG payload the 1:1 avatar API uses.
 * @return 0 on success, -1 on bad args.
 */
int p2p_send_group_avatar(p2p_context* ctx,
                          const char* group_id,
                          const char* avatar_b64,
                          const char** member_ids);

/**
 * Broadcast the current member roster to every member (including new
 * ones being added or the full group in cases of removal).  Peers apply
 * the update on their side via on_group_member_left (for removals)
 * and on_group_message (for the member-list field, which carries the
 * updated roster).
 * @return 0 on success, -1 on bad args.
 */
int p2p_update_group_members(p2p_context* ctx,
                             const char* group_id,
                             const char* group_name,
                             const char** member_ids);

/**
 * Seed the core's in-memory group roster for `group_id` with `member_ids`.
 * Apps should call this on startup for every group the user is a member
 * of, using their own persisted roster.
 *
 * Without this call the core uses a cold-start bootstrap (H2 audit fix):
 * the first inbound group_msg is accepted only if the sender included
 * themselves in the message's declared member list.  sendGroupText on
 * the sender side strips self from that list (so the list reflects
 * recipients), meaning peers that don't already have a roster for this
 * group will drop subsequent control messages (rename / avatar / leave)
 * as "from non-member".
 *
 * Call this once per known group after p2p_set_passphrase_v2 succeeds.
 */
void p2p_set_known_group_members(p2p_context* ctx,
                                  const char* group_id,
                                  const char** member_ids);

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
 * A peer left (or was removed from) a group.  `member_ids` is the NEW
 * roster (post-departure) as the sender observed it.  Clients should
 * replace their stored roster with this list.
 */
void p2p_set_on_group_member_left(p2p_context* ctx,
    void (*cb)(const char* from,
               const char* group_id,
               const char* group_name,
               const char** member_ids,   /* NULL-terminated */
               int64_t timestamp_sec,
               const char* msg_id,
               void* ud),
    void* ud);

/**
 * A peer renamed the group.  Clients should update their stored name.
 */
void p2p_set_on_group_renamed(p2p_context* ctx,
    void (*cb)(const char* group_id, const char* new_name, void* ud),
    void* ud);

/**
 * A peer published a new group avatar.  `avatar_b64` is the raw
 * base64 payload (typically PNG/JPEG).
 */
void p2p_set_on_group_avatar(p2p_context* ctx,
    void (*cb)(const char* group_id, const char* avatar_b64, void* ud),
    void* ud);

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

/**
 * Sender-side per-chunk progress.  Fires after each outbound chunk
 * dispatches (relay or P2P).  Terminal events (delivered / canceled /
 * blocked) come via their own callbacks; this one is the running count
 * so UIs can draw progress bars for outbound transfers.
 *
 * When chunks_sent == chunks_total, the sender has dispatched the last
 * chunk — delivery confirmation still arrives separately via
 * p2p_set_on_file_delivered.
 */
void p2p_set_on_file_sent_progress(p2p_context* ctx,
    void (*cb)(const char* to_peer_id,
               const char* transfer_id,
               const char* file_name,
               int64_t file_size,
               int chunks_sent,
               int chunks_total,
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

/**
 * Safety numbers: fires once per session when a previously-verified
 * peer's fingerprint no longer matches the current (self, peer) pair.
 * The UI should surface a banner and invite the user to re-verify.
 * `old_fingerprint` / `new_fingerprint` are the raw 32-byte BLAKE2b
 * values (for display or QR encoding); lengths are always 32.
 */
void p2p_set_on_peer_key_changed(p2p_context* ctx,
    void (*cb)(const char* peer_id,
               const uint8_t* old_fingerprint, int old_len,
               const uint8_t* new_fingerprint, int new_len,
               void* ud),
    void* ud);

#ifdef __cplusplus
}
#endif

#endif /* PEER2PEAR_H */
