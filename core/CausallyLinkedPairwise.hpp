#pragma once

/*
 * core/CausallyLinkedPairwise.hpp — wire-format spec for Phase 1
 *                                    group messaging.
 *
 * Header-only documentation: defines the JSON shape that GroupProtocol
 * v2 emits and consumes, the protocol version byte, and the
 * per-(sender, group, recipient) state machine that backs it.  No
 * runtime types here — implementations live in GroupProtocol.cpp,
 * ChatController.cpp, and AppDataStore.{hpp,cpp}.
 *
 * Background: prior group messaging used SenderChain (per-sender
 * symmetric chain w/ epoch+idx).  Receiver state loss after a device
 * wipe broke decryption permanently because the sender never
 * re-announced.  Causally-Linked Pairwise drops SenderChain entirely;
 * each group_msg is a regular pairwise DR envelope with three new
 * fields inside the sealed payload that the receiver uses to detect
 * and recover from gaps.
 *
 * The protocol is documented in the design discussion
 * (PR #X / commit Y) and elaborated below.
 *
 * ── Protocol version ─────────────────────────────────────────────────
 *
 * The outer envelope's `pv` field selects the path:
 *   pv = 1   → legacy SenderChain (deprecated; removed after dual-stack window)
 *   pv = 2   → Causally-Linked Pairwise (this spec)
 *
 * Default for new sends is pv = 2.  Receivers MUST honour both during
 * the dual-stack window; the SenderChain path is wholly deleted from
 * a later release once telemetry confirms the long tail of
 * pre-upgrade peers has cleared.
 *
 * ── Inner payload (pv = 2) ───────────────────────────────────────────
 *
 *   {
 *     "type":      "group_msg",
 *     "from":      "<sender peerId>",
 *     "groupId":   "<group uuid>",
 *     "groupName": "<encrypted-by-DR display name>",
 *     "members":   [ "<peerId>", ... ],     // group roster snapshot
 *     "session":   "<8B base64url>",        // session_id, see below
 *     "ctr":       <integer>,               // sender's counter, see below
 *     "prev":      "<16B base64url>",       // prev_hash, see below
 *     "text":      "<user message body>",
 *     "ts":        <unix-secs>,
 *     "msgId":     "<uuid>"
 *   }
 *
 * The whole payload is sealed pairwise via SessionSealer::sealForPeer
 * (existing mechanism) — there is no second symmetric encryption
 * layer.  DR provides forward secrecy + post-compromise security per
 * message; replay protection comes from `ctr` monotonicity + the DR
 * skipped-key guard.
 *
 * ── Field semantics ──────────────────────────────────────────────────
 *
 *   session_id:
 *     8 bytes derived from the DR session's INITIAL root key
 *     (see RatchetSession::sessionId()).  Both sender and receiver
 *     compute identical bytes from the Noise-derived rootKey at
 *     handshake time, so no over-the-wire negotiation is needed.  A
 *     fresh handshake (session reset) produces a fresh session_id;
 *     receivers detect the change and reset expectedNext to 1, surfacing
 *     any buffered messages from the prior session as a "K messages
 *     lost during reconnection" UI event.
 *
 *   counter (ctr):
 *     u32 monotonic counter the sender maintains per
 *     (recipient peerId, groupId, session_id).  Starts at 1 for each
 *     fresh session and increments on every successful enqueue.
 *     Rolls into the prev_hash chain so insertions / deletions /
 *     reorderings within a sender's stream are detectable.
 *
 *   prev_hash (prev):
 *     16 bytes (truncated BLAKE2b of the previous sealed envelope's
 *     bytes for this (recipient, group, session) tuple).  All-zero
 *     for the first message of a session (counter == 1).  The hash
 *     is over the sealed envelope, NOT the plaintext, so a receiver
 *     can verify the chain without holding plaintext history.
 *
 * ── Replay cache (sender side) ──────────────────────────────────────
 *
 * After successfully sealing each envelope, the sender stores the
 * sealed bytes in `group_replay_cache` keyed by
 * (peer_id, group_id, session_id, counter).  When a later
 * `gap_request` arrives, the sender replays byte-identical envelopes
 * (no re-encryption, no DR step that would shift the chain past the
 * receiver's expected counter).
 *
 * Cache TTL: 7 days (kReplayCacheMaxAgeSecs).  The relay mailbox TTL
 * is 14 days, so the relay-served path covers the wider window;
 * replay cache fills the narrower edge-cases (post-fetch state loss,
 * mid-session crash, etc.).
 *
 * ── Chain state (receiver side) ─────────────────────────────────────
 *
 * Per (group_id, sender_peer_id) the receiver tracks:
 *   session_id   = current session for this sender
 *   expected_next = the counter we'll deliver next (starts at 1)
 *   last_hash    = prev_hash check value (16B of the most recently
 *                  delivered envelope)
 *   blocked_since, gap_from, gap_to, last_retry_at, retry_count =
 *                  bookkeeping for in-progress gap_request fan-out
 *
 * Out-of-order arrivals (counter > expected_next) are buffered in
 * `group_msg_buffer` (DR-decrypted, field-encrypted at rest) and a
 * `gap_request` is fired to the sender.  The stream is "blocked" —
 * subsequent messages buffer, none deliver — until the gap fills or
 * the user explicitly skips after a 24h timeout.
 *
 * ── gap_request control message ─────────────────────────────────────
 *
 *   {
 *     "type":      "group_gap_request",
 *     "from":      "<requestor>",
 *     "groupId":   "<group uuid>",
 *     "session":   "<8B base64url>",
 *     "from_ctr":  <integer>,           // inclusive
 *     "to_ctr":    <integer>            // inclusive
 *   }
 *
 * Sender response: replay every matching `group_replay_cache` row in
 * counter-ascending order using the sender's normal sealed-envelope
 * path (each replay is byte-identical to the original send).
 *
 * Receivers cap retry attempts (exponential backoff: immediate, 30s,
 * 5min, 1h) and after a 24h ceiling surface a UI prompt to skip the
 * gap (advances expected_next past the missing counters; releases the
 * buffered messages).
 *
 * ── Session reset ────────────────────────────────────────────────────
 *
 * When the sender's session_id changes, it means the DR session was
 * re-established (e.g., one side device-wiped + re-handshook).
 * Receiver behaviour:
 *   1. Stash any buffered messages for the OLD session as "K lost
 *      messages during reconnection" — surfaced once via UI callback.
 *   2. Update chain_state.session_id to the new value, expected_next
 *      to the incoming counter (typically 1).
 *   3. Drain `group_msg_buffer` for the old session via
 *      AppDataStore::dropBufferForSession.
 *   4. Continue normally on the new session.
 *
 * Senders never reuse a session_id — each fresh handshake derives a
 * new initial root key and therefore a new session_id deterministically.
 */
