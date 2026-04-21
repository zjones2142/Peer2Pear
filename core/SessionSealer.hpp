#pragma once

#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

class CryptoEngine;
class SessionManager;
class SqlCipherDb;

/*
 * SessionSealer — the single choke point for outbound sealing +
 * safety-number enforcement.
 *
 * Every user-initiated send (sendText, sendAvatar, sendFile,
 * sendGroupText, sendGroupFile, all group control messages) flows
 * through `sealForPeer`.  That method is where:
 *
 *   1. The once-per-session `onPeerKeyChanged` callback fires for any
 *      peer whose stored safety-number fingerprint no longer matches
 *      the one derived from their current public key.
 *   2. The `hardBlockOnKeyChange` policy, if on, returns empty so the
 *      caller surfaces "seal failed" to the user.
 *   3. The peer's ML-KEM-768 public key (if we've seen one) is mixed
 *      into the Noise handshake for hybrid PQ sealing.
 *
 * Noise handshake-response and file-chunk seals call a different
 * path (the `setSendResponseFn` / `setSealFn` callbacks wired by
 * ChatController) because they're infrastructure traffic that
 * must not be gated on the user-facing trust state.
 *
 * Storage:
 *   - `verified_peers` table holds the stored fingerprint (bytes).
 *     Written only by markPeerVerified / unverifyPeer.
 *   - An in-memory cache (`PeerKeyCacheEntry`) memoizes both the
 *     stored-from-DB bytes AND the freshly-computed BLAKE2b(me, peer)
 *     so per-send safety checks don't re-hit SQLCipher or redo the
 *     crypto.  Writes invalidate the cache entry.
 *   - A per-peer `m_peerKemPubs` cache + `contacts.kem_pub` column
 *     hold peer ML-KEM-768 pub keys seen via kem_pub_announce.
 *
 * Thread model:
 *   Called only from ChatController entry points, which are serialized
 *   by the C API's p2p_context::ctrlMu (or the desktop Qt event loop).
 *   The cache is therefore not lock-guarded — it's `mutable` so const
 *   methods (peerTrust) can populate it, not so it can race.
 *
 * Identity-rotation note:
 *   `m_peerKeyCache[peer].current` depends on `m_crypto.identityPub()`,
 *   which is set once during startup and does not change for the
 *   lifetime of this SessionSealer.  If identity rotation is ever
 *   added, the entire cache must be cleared.
 */
class SessionSealer {
public:
    using Bytes = std::vector<uint8_t>;

    enum class PeerTrust { Unverified, Verified, Mismatch };

    SessionSealer(CryptoEngine& crypto);

    // Late-binding wiring — set after ChatController has opened the DB
    // and constructed its SessionManager.
    void setSessionManager(SessionManager* mgr) { m_sessionMgr = mgr; }
    void setDatabase(SqlCipherDb* db);   // also calls ensureVerifiedPeersTable

    // ── The choke point ───────────────────────────────────────────────
    // Returns a fully relay-wrapped sealed envelope, or empty on
    // failure.  Failure modes:
    //   - no SessionManager wired yet
    //   - hard-block is on and peer is Mismatch
    //   - session encrypt failed (no handshake established)
    //   - peer id did not decode as Ed25519
    //   - SealedEnvelope::seal failed
    Bytes sealForPeer(const std::string& peerIdB64u, const Bytes& plaintext);

    // ── Safety numbers ────────────────────────────────────────────────
    // 60-digit display string for out-of-band verification, or empty
    // if `peerIdB64u` is not a valid Ed25519 pub.
    std::string safetyNumber(const std::string& peerIdB64u) const;
    PeerTrust peerTrust(const std::string& peerIdB64u) const;
    bool markPeerVerified(const std::string& peerIdB64u);
    void unverifyPeer(const std::string& peerIdB64u);

    // Hard-block refuses sends + drops inbound messages from any
    // peer whose safety number has changed since they were verified.
    // Off by default; the UI exposes it as a settings toggle.
    void setHardBlockOnKeyChange(bool on) { m_hardBlockOnKeyChange = on; }
    bool hardBlockOnKeyChange() const     { return m_hardBlockOnKeyChange; }

    // Explicit key-change check — fires `onPeerKeyChanged` at most
    // once per session per peer.  Exposed separately from sealForPeer
    // so the inbound dispatch path can gate delivery on mismatch too.
    bool detectKeyChange(const std::string& peerIdB64u);

    // Wipe the in-memory fingerprint cache.  Production callers
    // shouldn't need this — the cache invalidates itself whenever
    // `verified_peers` is written through saveVerifiedFingerprint /
    // deleteVerifiedPeer.  Exposed for (a) test fixtures that mutate
    // the DB directly to simulate tampering / restart, and (b) future
    // migration / admin tooling that might write verified_peers out
    // of band.
    void clearPeerKeyCache() const { m_peerKeyCache.clear(); }

    // Fires once per session when a previously-verified peer's
    // fingerprint no longer matches.  `oldFingerprint` is the stored
    // 32-byte BLAKE2b, `newFingerprint` is the freshly-computed one.
    std::function<void(const std::string& peerId,
                       const Bytes& oldFingerprint,
                       const Bytes& newFingerprint)> onPeerKeyChanged;

    // ── KEM pub store ─────────────────────────────────────────────────
    // Look up the peer's ML-KEM-768 pub.  Returns empty if we've never
    // seen one for this peer — sealForPeer will then fall back to
    // classical Noise IK.  Also used by ChatController's raw sealing
    // paths (handshake response, file chunks).
    Bytes lookupPeerKemPub(const std::string& peerIdB64u);

    // Record a peer's ML-KEM-768 pub (from kem_pub_announce).
    // Persists to `contacts.kem_pub` + the in-memory cache.
    void saveKemPub(const std::string& peerIdB64u, const Bytes& kemPub);

    // Announce-once guard: ChatController asks whether we've already
    // sent our KEM pub to this peer this session, and marks as sent
    // after dispatching the announce envelope.
    bool hasAnnouncedKemPubTo(const std::string& peerIdB64u) const;
    void markKemPubAnnouncedTo(const std::string& peerIdB64u);

private:
    // ── DB-backed helpers ─────────────────────────────────────────────
    void ensureVerifiedPeersTable();
    Bytes loadVerifiedFingerprint(const std::string& peerIdB64u) const;
    void  saveVerifiedFingerprint(const std::string& peerIdB64u,
                                   const Bytes& fingerprint);
    void  deleteVerifiedPeer(const std::string& peerIdB64u);

    // ── Fingerprint cache ─────────────────────────────────────────────
    struct PeerKeyCacheEntry {
        Bytes stored;   // verified_peers row (32 B); empty = not verified
        Bytes current;  // BLAKE2b(me, peer) (32 B); empty if peerId was invalid
    };
    // All trust checks go through this; never read the DB directly.
    const PeerKeyCacheEntry& fingerprintsFor(const std::string& peerIdB64u) const;
    void invalidatePeerKeyCache(const std::string& peerIdB64u) const;

    CryptoEngine&    m_crypto;
    SessionManager*  m_sessionMgr = nullptr;
    SqlCipherDb*     m_dbPtr      = nullptr;

    // Cache invariant note — see class header comment.
    mutable std::unordered_map<std::string, PeerKeyCacheEntry> m_peerKeyCache;

    // Once-per-session onPeerKeyChanged guard.
    std::set<std::string> m_keyChangeWarned;

    bool m_hardBlockOnKeyChange = false;

    // Peer ML-KEM-768 public keys: peerIdB64u -> 1184-byte KEM pub.
    // Populated by kem_pub_announce messages, used by sealForPeer
    // for hybrid envelopes.
    std::unordered_map<std::string, Bytes> m_peerKemPubs;
    // Peers we've already announced our own KEM pub to this session.
    std::set<std::string> m_kemPubAnnounced;
};
