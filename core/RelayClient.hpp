#pragma once

#include "types.hpp"

#include "IHttpClient.hpp"
#include "ITimer.hpp"
#include "IWebSocket.hpp"

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

class CryptoEngine;

/*
 * RelayClient — unified relay transport
 *
 * Replaces MailboxClient + RendezvousClient with a single class that:
 *   - Sends envelopes anonymously via HTTP POST /v1/send (no sender identity)
 *   - Receives envelopes via authenticated WebSocket /v1/receive (push-based)
 *   - Handles presence via WS messages (subscribe + push, no polling)
 *   - Supports retry queue for failed sends
 *   - Delivers stored mailbox envelopes immediately on WS connect
 *
 * Types: std::string URL + peer IDs, Bytes envelopes.
 * Async: ITimer for scheduling, std::function callbacks for events.
 * No Qt — core/ is Qt-free.
 */
class RelayClient {
public:

    // Constructed with an IWebSocketFactory: the primary subscribe
    // connection is created via wsFactory.create() at construction
    // time, and additional subscribe relays (added via
    // addSubscribeRelay) come from the same factory.  This unifies WS
    // ownership in the C++ core — platform layers provide a factory
    // implementation instead of a single IWebSocket reference.
    RelayClient(IWebSocketFactory& wsFactory, IHttpClient& http,
                ITimerFactory& timers, CryptoEngine* crypto);
    ~RelayClient();

    RelayClient(const RelayClient&)            = delete;
    RelayClient& operator=(const RelayClient&) = delete;

    // Set the relay server URL (e.g., "wss://relay.peer2pear.org:8443")
    void setRelayUrl(const std::string& url);

    // Connect the WebSocket receive channel (authenticates with Ed25519 sig)
    void connectToRelay();
    void disconnectFromRelay();
    bool isConnected() const;

    // Tags an envelope's logical payload class so the transport can
    // apply per-class policy.  Today only parallel fan-out cares about
    // this — file chunks are large enough that broadcasting each one
    // to multiple relays burns bandwidth disproportionate to the
    // redundancy gain, so chunks stay on the single-relay path even
    // when fan-out is enabled for messages.
    enum class TrafficClass { Message, FileChunk };

    // Send a sealed envelope anonymously via HTTP POST /v1/send.
    // The recipient is parsed from the envelope header (bytes 1-32).
    // `cls` selects per-class transport policy; defaults to Message.
    // `messageId` (optional) tags the envelope so the retry-give-up
    // path can fire `onSendFailed(messageId)` to mark the
    // corresponding bubble in the UI as undelivered.  Empty string
    // means "don't track" — used for cover traffic, presence
    // refreshes, control envelopes that have no user-visible
    // bubble.
    void sendEnvelope(const Bytes& sealedEnvelope,
                      TrafficClass cls = TrafficClass::Message,
                      const std::string& messageId = "");

    // Presence: subscribe to online/offline updates for a set of peers.
    void subscribePresence(const std::vector<std::string>& peerIds);

    // One-shot presence query.
    void queryPresence(const std::vector<std::string>& peerIds);

    // Tell the relay which push token / platform to wake us on when
    // an envelope arrives while we're disconnected.  Pass an empty
    // token to unregister (e.g., sign-out).  Safe to call repeatedly;
    // the relay upserts by (peer_id, platform).  If the WS is down
    // at call time, the latest (platform, token) pair is replayed
    // after the next successful reconnect.
    void registerPushToken(const std::string& platform,
                             const std::string& token);

    // ── Identity-bundle endpoints (Tier 1 of project_pq_messaging.md) ───────
    //
    // Publish own (ed25519_id, kem_pub, ts_day, sig) tuple so peers
    // can fetch it pre-msg1 + run hybrid PQ Noise IK from byte one.
    //
    // `cb` is invoked with `true` on 200 from the relay, `false`
    // otherwise.  Async over IHttpClient.post — callback fires on
    // whatever thread the HTTP backend uses (URLSession delegate
    // queue / Qt main loop).
    using PublishIdentityCallback = std::function<void(bool ok)>;
    void publishIdentityBundle(const std::string& ed25519IdB64u,
                                 const Bytes& kemPub,
                                 uint64_t tsDay,
                                 const Bytes& sig,
                                 PublishIdentityCallback cb);

    // Fetch a peer's bundle.  On success the callback delivers the
    // 1184-byte ML-KEM-768 pub (caller stores in `contacts.kem_pub`
    // for sub­sequent hybrid sealing).  On any failure (404,
    // network error, signature verification fails, response
    // ed25519_id doesn't match the requested one) the callback
    // receives an empty Bytes — caller's existing `kem_pub.empty()`
    // → classical-msg1 fallback path stays intact.
    using FetchIdentityCallback = std::function<void(const Bytes& kemPub)>;
    void fetchIdentityBundle(const std::string& ed25519IdB64u,
                               FetchIdentityCallback cb);

    // ── DAITA: client-side traffic analysis defense ─────────────────────────
    void setJitterRange(int minMs, int maxMs);
    void setCoverTrafficInterval(int seconds);
    void setKnownPeers(const std::vector<std::string>& peerIds);

    // ── Multi-relay routing ─────────────────────────────────────────────────
    void addSendRelay(const std::string& url);
    void setMultiHopEnabled(bool enabled);
    void refreshRelayInfo();

    // ── Multi-relay subscribe (Phase 0a Milestone 2 — receive-side redundancy)
    //
    // Wire a factory before the first connectToRelay() call so RelayClient
    // can spawn additional WS instances ("slaves") that each subscribe to
    // a different relay URL.  Together with parallel send fan-out, this
    // delivers true redundancy: a sender can post to N relays, and a
    // receiver can listen on those same N relays — one being down doesn't
    // drop delivery.
    //
    // The primary IWebSocket passed to the constructor handles m_relayUrl
    // (existing behavior).  Slaves handle every URL added via
    // addSubscribeRelay().  All inbound binary frames flow through the
    // same dedup-filtered onWsBinaryMessage path, so duplicate envelopes
    // delivered through multiple relays are dropped before reaching UI.
    //
    // Slaves are created via the same IWebSocketFactory that produced
    // the primary.  When the factory's create() returns nullptr (e.g.,
    // a platform shim that doesn't yet support multi-WS), addSubscribeRelay
    // logs a warn and returns — keeps platform layers that haven't
    // shipped multi-WS support yet from silently breaking.
    void addSubscribeRelay(const std::string& url);
    void clearSubscribeRelays();

    // ── Parallel fan-out (redundancy, NOT anonymity) ────────────────────────
    //
    // Distinct from `setMultiHopEnabled` (which onion-routes one envelope
    // through a chain of relays for unlinkability).  Parallel fan-out
    // posts the SAME sealed envelope to multiple configured relays
    // simultaneously so a recipient's mailbox is replicated across them
    // and one relay being unreachable / blocked doesn't drop the message.
    //
    // Per-class policy: file chunks (TrafficClass::FileChunk) skip the
    // fan-out branch even when enabled — at 240 KB/chunk × hundreds of
    // chunks per file, the bandwidth multiplier defeats the redundancy
    // benefit.  Messages and control envelopes pay the small N× cost.
    //
    // Receive-side dedup (BLAKE2b-128 of the sealed bytes) drops
    // duplicates that arrive when the recipient subscribes to multiple
    // of the same relays — guards against double-delivery to UI
    // regardless of which side configured the redundancy.
    void setParallelFanOut(bool enabled);

    // K = 0 means "all configured send relays" (full broadcast).
    // K > 0 picks K random relays uniformly without replacement;
    // values >= m_sendRelays.size() collapse to "all".
    void setParallelFanOutK(int k);

    /// Set the privacy level (preset matrix over the four orthogonal
    /// dials: jitter, cover traffic, parallel fan-out, multi-hop).
    ///   0 = Standard:  padding only — no jitter, no cover, no multi-relay
    ///   1 = Enhanced:  jitter (50-300ms) + cover (30s) + parallel fan-out (all configured)
    ///   2 = Maximum:   jitter (100-500ms) + cover (10s) + parallel fan-out + multi-hop
    /// Parallel fan-out and multi-hop are independent in spec but
    /// multi-hop wins in the send dispatcher when both are enabled
    /// (see sendEnvelope).
    void setPrivacyLevel(int level);

    // ── Event callbacks — set from outside before connecting ─────────────
    //
    // onConnected:        fires after WS authenticates successfully.
    // onDisconnected:     fires on WS close (intentional or lost).
    // onStatus:           human-readable status string; UI hook.
    // onEnvelopeReceived: binary envelope received (real-time or stored).
    // onPresenceChanged:  presence push from relay.
    std::function<void()>                          onConnected;
    std::function<void()>                          onDisconnected;
    std::function<void(const std::string&)>        onStatus;
    std::function<void(const Bytes&)>              onEnvelopeReceived;
    std::function<void(const std::string&, bool)>  onPresenceChanged;

    // Fires from processRetryQueue's give-up branch with the
    // messageId that was tagged on sendEnvelope, IF non-empty.
    // Lets the platform layer surface a per-bubble "failed to
    // deliver" indicator next to the specific message that
    // ran out of retries — separate from the broader
    // onStatus toast.  Empty messageIds (cover traffic etc.)
    // never trigger this callback.
    std::function<void(const std::string&)>        onSendFailed;

private:
    void onWsConnected();
    void onWsDisconnected();
    void onWsBinaryMessage(const Bytes& data);
    void onWsTextMessage(const std::string& message);

    void authenticate();
    void scheduleReconnect();
    void processRetryQueue();

    // ── Slave subscribe state ──────────────────────────────────────────────
    // A Slave is a secondary WS subscribe connection separate from the
    // primary m_ws.  Same auth lifecycle, same reconnect-with-backoff,
    // but binary frames feed into onWsBinaryMessage so dedup catches
    // any duplicates delivered through multiple relays.
    struct Slave {
        std::string             url;
        std::unique_ptr<IWebSocket> ws;
        std::unique_ptr<ITimer> reconnectTimer;
        bool                    authenticated         = false;
        bool                    intentionalDisconnect = false;
        int                     reconnectAttempt      = 0;
    };

    void connectSlave(Slave& s);
    void onSlaveConnected(Slave& s);
    void onSlaveDisconnected(Slave& s);
    void onSlaveTextMessage(Slave& s, const std::string& message);
    void scheduleSlaveReconnect(Slave& s);
    void authenticateOnSlave(Slave& s);

    void sendCoverEnvelope();
    void scheduleCoverTimer();
    void onRealActivity();

    std::string pickSendRelay();

    // Pick K relays from m_sendRelays without replacement.  K==0 or
    // K >= size() returns the full list.  Used by parallel fan-out.
    std::vector<std::string> pickKSendRelays(int k) const;

    // BLAKE2b-128 of the sealed envelope bytes.  Stable across relays
    // (content hash, not relay-assigned ID), so a single envelope
    // posted to multiple relays + delivered through multiple WS
    // subscriptions hashes identically and the second delivery is
    // dropped before reaching onEnvelopeReceived.  Returns true iff
    // the hash was already in the LRU; inserts otherwise.
    bool isDuplicateEnvelope(const Bytes& sealed);

    int         pickJitterMs() const;
    void postEnvelope(const std::string& relayUrl, const Bytes& envelope,
                      IHttpClient::Callback cb);
    void forwardEnvelope(const std::string& viaRelay, const std::string& toRelay,
                         const Bytes& envelope,
                         IHttpClient::Callback cb);

    void scheduleRetry();

    void emitStatus(const std::string& s) { if (onStatus) onStatus(s); }

    CryptoEngine*       m_crypto   = nullptr;
    IWebSocketFactory&  m_wsFactory;
    // Primary subscribe WS, created by factory at construction.  May
    // be null if the factory rejected the request — RelayClient
    // continues to function for sends but cannot receive; logged as
    // critical at construction.
    std::unique_ptr<IWebSocket> m_ws;
    IHttpClient&        m_http;
    ITimerFactory&      m_timers;
    std::string     m_relayUrl;
    bool            m_authenticated         = false;
    bool            m_intentionalDisconnect = false;

    // Reconnect with exponential backoff
    std::unique_ptr<ITimer> m_reconnectTimer;
    int    m_reconnectAttempt = 0;
    static constexpr int kMaxReconnectDelaySec = 60;

    // Retry queue for failed sends
    static constexpr int kMaxRetries    = 5;
    static constexpr int kMaxRetryQueue = 100;
    struct PendingEnvelope {
        Bytes data;
        int   retryCount = 0;
        // Tagged at sendEnvelope-time so the give-up branch can
        // fire onSendFailed(messageId) and the platform can mark
        // the corresponding bubble as undelivered.  Empty for
        // cover traffic / control envelopes.
        std::string messageId;
    };
    std::vector<PendingEnvelope> m_retryQueue;
    std::unique_ptr<ITimer>      m_retryTimer;
    bool                         m_retryInFlight = false;

    // DAITA: client-side traffic defense
    static constexpr uint8_t kDummyVersion = 0x00;
    int                     m_jitterMinMs      = 0;
    int                     m_jitterMaxMs      = 0;
    std::unique_ptr<ITimer> m_coverTimer;
    int                     m_coverIntervalSec = 0;
    int                     m_burstRemaining   = 0;

    // Cover-traffic size distribution.  The inner body of a cover
    // envelope picks a padding bucket first, then fills to land
    // inside it, so the relay's view of cover bucket frequencies is
    // independent of the user's real-traffic shape.  Without bucket
    // shuffling a text-only user would show a distinctive histogram
    // (near-zero large-bucket rate), making them trivially separable
    // from users who send files.  The two modes trade bandwidth
    // against indistinguishability:
    //
    //   BandwidthBiased  — 60% small / 30% medium / 10% large.  Covers
    //                      every bucket at least some of the time so
    //                      a text-only user can't be identified by
    //                      bucket-histogram analysis, but still biased
    //                      toward the most common real-traffic sizes.
    //                      Used at privacy level 1.
    //
    //   UniformBuckets   — 1/3 / 1/3 / 1/3.  Every user's cover
    //                      distribution looks the same regardless of
    //                      their real sends.  Costs ~3x bandwidth vs
    //                      the biased mode.  Used at privacy level 2.
    enum class CoverSizeMode { BandwidthBiased, UniformBuckets };
    CoverSizeMode           m_coverSizeMode    = CoverSizeMode::BandwidthBiased;

    std::vector<std::string> m_knownPeers;
    std::set<std::string>    m_onlinePeers;

    // Multi-relay routing
    std::vector<std::string> m_sendRelays;
    size_t                   m_sendRelayIdx = 0;
    bool                     m_multiHop     = false;

    // Parallel fan-out.  See setParallelFanOut() for semantics.
    bool                     m_parallelFanOut  = false;
    int                      m_parallelFanOutK = 0;  // 0 = all

    // Receive-side dedup.  std::array hashes can't be the
    // unordered_set key directly without a custom hasher, so we key by
    // string-of-bytes + keep an order-preserving deque for LRU eviction.
    static constexpr size_t kDedupLruMax = 10000;
    using EnvHash = std::array<uint8_t, 16>;
    std::deque<EnvHash>            m_seenEnvOrder;
    std::unordered_set<std::string> m_seenEnvSet;

    std::map<std::string, Bytes> m_relayX25519Pubs;

    // Slave subscribers (multi-relay receive).  Created via
    // m_wsFactory; managed wholly by RelayClient.
    std::vector<std::unique_ptr<Slave>> m_slaves;

    // Push-token registration state.  Stored after the first
    // registerPushToken call so we can replay on reconnect.  Empty
    // token means "unregister on next reconnect" — relays handle
    // absent/empty tokens by removing any existing row.
    std::string m_pushPlatform;
    std::string m_pushToken;
    bool        m_pushPending = false;   // have we replayed to this WS yet?
};
