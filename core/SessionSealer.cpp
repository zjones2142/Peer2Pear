#include "SessionSealer.hpp"

#include "CryptoEngine.hpp"
#include "SessionManager.hpp"
#include "SealedEnvelope.hpp"
#include "SqlCipherDb.hpp"
#include "log.hpp"

#include <sodium.h>

#include <chrono>
#include <cstring>

using Bytes = SessionSealer::Bytes;

namespace {

// Sealed-envelope inner-wire prefix.  Duplicated in ChatController.cpp
// for the handshake-response + file-chunk sealing paths that don't go
// through sealForPeer.  Keeping them in sync is a wire-compat
// requirement — do not change without coordinating.
const char kSealedPrefix[] = "SEALED:";

int64_t nowSecs() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

}  // namespace

SessionSealer::SessionSealer(CryptoEngine& crypto) : m_crypto(crypto) {}

void SessionSealer::setDatabase(SqlCipherDb* db)
{
    m_dbPtr = db;
    ensureVerifiedPeersTable();
}

// ── The choke point ─────────────────────────────────────────────────────────

Bytes SessionSealer::sealForPeer(const std::string& peerIdB64u,
                                  const Bytes& plaintext)
{
    if (!m_sessionMgr) return {};

    // detectKeyChange fires onPeerKeyChanged once per session per peer.
    // When the hard-block toggle is on, a Mismatch returns empty here
    // and the caller sees "seal failed" → surfaces as a status message.
    if (detectKeyChange(peerIdB64u) && m_hardBlockOnKeyChange) {
        P2P_WARN("[SEND] BLOCKED — peer's safety number changed for "
                 << peerIdB64u.substr(0, 8) << "... (hard-block on)");
        return {};
    }

    // Pass peer's KEM pub so SessionManager can do hybrid Noise handshake if available.
    Bytes peerKemPub = lookupPeerKemPub(peerIdB64u);
    Bytes sessionBlob = m_sessionMgr->encryptForPeer(peerIdB64u, plaintext, peerKemPub);
    if (sessionBlob.empty()) return {};

    Bytes peerEdPub = CryptoEngine::fromBase64Url(peerIdB64u);
    unsigned char peerCurvePub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(peerCurvePub, peerEdPub.data()) != 0)
        return {};

    Bytes recipientCurvePub(peerCurvePub, peerCurvePub + 32);
    sodium_memzero(peerCurvePub, sizeof(peerCurvePub));

    // Use hybrid seal if we know the peer's ML-KEM-768 public key.
    // Include ML-DSA-65 signature if we have DSA keys.
    Bytes sealed = SealedEnvelope::seal(
        recipientCurvePub, peerEdPub,
        m_crypto.identityPub(), m_crypto.identityPriv(),
        sessionBlob, peerKemPub,
        m_crypto.dsaPub(), m_crypto.dsaPriv());
    if (sealed.empty()) return {};

    // Inner wire: kSealedPrefix + "\n" + sealed
    Bytes inner;
    const size_t prefixLen = std::strlen(kSealedPrefix);
    inner.reserve(prefixLen + 1 + sealed.size());
    inner.insert(inner.end(),
                 reinterpret_cast<const uint8_t*>(kSealedPrefix),
                 reinterpret_cast<const uint8_t*>(kSealedPrefix) + prefixLen);
    inner.push_back('\n');
    inner.insert(inner.end(), sealed.begin(), sealed.end());

    // Wrap with relay routing header so /v1/send can route anonymously.
    return SealedEnvelope::wrapForRelay(peerEdPub, inner);
}

// ── Safety numbers ─────────────────────────────────────────────────────────

std::string SessionSealer::safetyNumber(const std::string& peerIdB64u) const
{
    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() != 32) return {};
    return CryptoEngine::safetyNumber(m_crypto.identityPub(), peerEd);
}

SessionSealer::PeerTrust
SessionSealer::peerTrust(const std::string& peerIdB64u) const
{
    const auto& c = fingerprintsFor(peerIdB64u);
    if (c.stored.size() != 32)  return PeerTrust::Unverified;
    if (c.current.size() != 32) return PeerTrust::Unverified;  // invalid peerId
    return (c.current == c.stored) ? PeerTrust::Verified : PeerTrust::Mismatch;
}

bool SessionSealer::markPeerVerified(const std::string& peerIdB64u)
{
    const auto& c = fingerprintsFor(peerIdB64u);
    if (c.current.size() != 32) return false;
    // saveVerifiedFingerprint invalidates the cache on write, so the
    // next read repopulates with stored == current.
    saveVerifiedFingerprint(peerIdB64u, c.current);
    // A fresh mark clears the once-per-session warning so if the user
    // re-verifies and we later detect ANOTHER change they'll see it.
    m_keyChangeWarned.erase(peerIdB64u);
    return true;
}

void SessionSealer::unverifyPeer(const std::string& peerIdB64u)
{
    deleteVerifiedPeer(peerIdB64u);
    m_keyChangeWarned.erase(peerIdB64u);
}

bool SessionSealer::detectKeyChange(const std::string& peerIdB64u)
{
    const auto& c = fingerprintsFor(peerIdB64u);
    if (c.stored.size() != 32)  return false;  // Unverified — not a mismatch
    if (c.current.size() != 32) return false;  // peerId didn't decode
    if (c.current == c.stored)  return false;

    // Mismatch.  Fire the callback at most once per session per peer.
    if (m_keyChangeWarned.insert(peerIdB64u).second) {
        if (onPeerKeyChanged) onPeerKeyChanged(peerIdB64u, c.stored, c.current);
        P2P_WARN("[SAFETY] key-change detected for " << peerIdB64u.substr(0, 8)
                 << "... (hardBlock=" << (m_hardBlockOnKeyChange ? "on" : "off") << ")");
    }
    return true;
}

// ── DB-backed fingerprint helpers ─────────────────────────────────────────

void SessionSealer::ensureVerifiedPeersTable()
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    q.exec(
        "CREATE TABLE IF NOT EXISTS verified_peers ("
        "  peer_id              TEXT PRIMARY KEY,"
        "  verified_at          INTEGER NOT NULL,"
        "  verified_fingerprint BLOB NOT NULL"
        ");"
    );
}

Bytes SessionSealer::loadVerifiedFingerprint(const std::string& peerIdB64u) const
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return {};
    SqlCipherQuery q(m_dbPtr->handle());
    if (!q.prepare("SELECT verified_fingerprint FROM verified_peers WHERE peer_id=:pid;"))
        return {};
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) return q.valueBlob(0);
    return {};
}

void SessionSealer::saveVerifiedFingerprint(const std::string& peerIdB64u,
                                             const Bytes& fingerprint)
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    if (!q.prepare(
            "INSERT INTO verified_peers (peer_id, verified_at, verified_fingerprint)"
            " VALUES (:pid, :at, :fp)"
            " ON CONFLICT(peer_id) DO UPDATE SET"
            "   verified_at=excluded.verified_at,"
            "   verified_fingerprint=excluded.verified_fingerprint;"))
        return;
    q.bindValue(":pid", peerIdB64u);
    q.bindValue(":at",  nowSecs());
    q.bindValue(":fp",  fingerprint);
    q.exec();

    // Drop the cached entry so the next trust check picks up the new
    // stored fingerprint from disk.  Doing this inside the low-level
    // DB helper (rather than only at the markPeerVerified call site)
    // means any future caller that writes through here is automatically
    // safe.
    invalidatePeerKeyCache(peerIdB64u);
}

void SessionSealer::deleteVerifiedPeer(const std::string& peerIdB64u)
{
    if (!m_dbPtr || !m_dbPtr->isOpen()) return;
    SqlCipherQuery q(*m_dbPtr);
    if (!q.prepare("DELETE FROM verified_peers WHERE peer_id=:pid;"))
        return;
    q.bindValue(":pid", peerIdB64u);
    q.exec();

    // Same reasoning as saveVerifiedFingerprint: belt-and-braces
    // invalidation at the DB-write layer so no caller can forget.
    // A stale "stored" entry here would silently report a now-unverified
    // peer as Verified — the one direction that IS a security regression.
    invalidatePeerKeyCache(peerIdB64u);
}

// ── Fingerprint cache ─────────────────────────────────────────────────────

const SessionSealer::PeerKeyCacheEntry&
SessionSealer::fingerprintsFor(const std::string& peerIdB64u) const
{
    auto it = m_peerKeyCache.find(peerIdB64u);
    if (it != m_peerKeyCache.end()) return it->second;

    PeerKeyCacheEntry e;
    const Bytes peerEd = CryptoEngine::fromBase64Url(peerIdB64u);
    if (peerEd.size() == 32) {
        // `current` is stable for the lifetime of this SessionSealer:
        // it depends only on identityPub() (set once in setPassphrase)
        // and the peerIdB64u key we're indexed on.
        e.current = CryptoEngine::safetyFingerprint(m_crypto.identityPub(), peerEd);
    }
    e.stored = loadVerifiedFingerprint(peerIdB64u);
    auto [ins, _] = m_peerKeyCache.emplace(peerIdB64u, std::move(e));
    return ins->second;
}

void SessionSealer::invalidatePeerKeyCache(const std::string& peerIdB64u) const
{
    m_peerKeyCache.erase(peerIdB64u);
}

// ── KEM pub store ─────────────────────────────────────────────────────────

Bytes SessionSealer::lookupPeerKemPub(const std::string& peerIdB64u)
{
    auto it = m_peerKemPubs.find(peerIdB64u);
    if (it != m_peerKemPubs.end()) return it->second;

    // Load from DB.
    if (!m_dbPtr || !m_dbPtr->isOpen()) return {};
    SqlCipherQuery q(m_dbPtr->handle());
    q.prepare("SELECT kem_pub FROM contacts WHERE peer_id=:pid;");
    q.bindValue(":pid", peerIdB64u);
    if (q.exec() && q.next()) {
        Bytes pub = q.valueBlob(0);
        if (!pub.empty()) {
            m_peerKemPubs[peerIdB64u] = pub;
            return pub;
        }
    }
    return {};
}

void SessionSealer::saveKemPub(const std::string& peerIdB64u, const Bytes& kemPub)
{
    if (kemPub.size() != 1184) return;  // ML-KEM-768 pub size
    m_peerKemPubs[peerIdB64u] = kemPub;
    if (m_dbPtr && m_dbPtr->isOpen()) {
        SqlCipherQuery q(*m_dbPtr);
        q.prepare("UPDATE contacts SET kem_pub=:kp WHERE peer_id=:pid;");
        q.bindValue(":kp",  kemPub);
        q.bindValue(":pid", peerIdB64u);
        q.exec();
    }
}

bool SessionSealer::hasAnnouncedKemPubTo(const std::string& peerIdB64u) const
{
    return m_kemPubAnnounced.count(peerIdB64u) != 0;
}

void SessionSealer::markKemPubAnnouncedTo(const std::string& peerIdB64u)
{
    m_kemPubAnnounced.insert(peerIdB64u);
}
