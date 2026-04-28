import Foundation

// QR-displayed handshake from the RECEIVER (new device) to the
// SENDER (old device).  Carries the FINGERPRINT of the receiver's
// hybrid pubkey pair (X25519 + ML-KEM-768), not the pubkeys
// themselves — ML-KEM-768 pubkeys are 1184 bytes, too large to
// QR-encode reliably alongside the X25519 metadata.
//
// Pairing flow:
//   1. Receiver generates fresh keypairs via MigrationCryptoBridge
//      (C side: libsodium X25519 + liboqs ML-KEM-768).
//   2. Receiver computes fingerprint = SHA-256(x25519_pub || mlkem_pub)[0..16].
//   3. Receiver renders {version, fingerprint, nonce} as a QR.
//   4. Sender scans QR.
//   5. Both devices spin up MultipeerConnectivity (B.3).
//   6. Receiver sends full pubkeys over the MPC channel.
//   7. Sender re-hashes received pubkeys + verifies match against
//      QR fingerprint.  Mismatch = MITM = abort.
//   8. Sender seals + ships the envelope; receiver opens.
//
// QR payload size at v1: version(1) + fingerprint(16) + nonce(16)
// = 33 bytes raw → ~50 base64url chars after JSON-and-base64url
// encoding.  Trivially fits any QR error-correction level.

struct MigrationHandshake: Codable {
    /// Handshake-format version.  Senders that don't recognize this
    /// refuse the QR with a "your other device needs to be updated"
    /// message; degrading silently would be worse.
    let version: Int

    /// 16-byte fingerprint = SHA-256(x25519_pub || mlkem_pub)[0..16].
    /// 64 bits of collision resistance — attacker would need ~2^64
    /// KEM keypair generations to find a colliding fingerprint, well
    /// above any practical attack budget for a one-shot pairing.
    let fingerprint: Data

    /// Random 16-byte nonce.  Mixed into the AEAD KDF salt by
    /// MigrationCrypto so a stale QR can't be reused verbatim across
    /// migration sessions — each fresh QR derives different keys
    /// even from the same pubkey hash.
    let nonce: Data

    /// LAN IPv4 address the receiver is listening on (v2+).  When
    /// present the sender connects directly via TCP — no Bonjour /
    /// MultipeerConnectivity discovery, no relay.  v1 handshakes
    /// from older receivers omit the field; senders fall back to
    /// platform-native discovery (iOS MPC).
    let addr: String?

    /// TCP port the receiver's listener bound (v2+).  Paired with
    /// `addr`; either both are present (v2 cross-platform path) or
    /// both absent (v1 iOS-MPC-only path).
    let port: Int?
}

extension MigrationHandshake {
    /// Wire-format versions the decoder accepts.  v1 (no addr/port)
    /// is the legacy MPC-era handshake, kept for backward decode
    /// only — modern receivers always emit v2 once their TCP
    /// listener is up and they know their addr+port.
    static let supportedVersions: Set<Int> = [1, 2]

    /// Build an INTERNAL v1 placeholder for a freshly-generated
    /// keypair.  Receiver sessions create this at construction time
    /// (when the keypair fingerprint + nonce are known) and replace
    /// it with a v2 handshake (with addr + port) once the
    /// `NWListener` transitions to .ready.  The placeholder is
    /// never emitted on the wire — `MigrationReceiveSession.start`
    /// only flips phase to `.advertising` after the v2 upgrade, and
    /// the QR-rendering view watches phase before reading the
    /// handshake.
    static func make(fingerprint: Data) -> MigrationHandshake {
        precondition(fingerprint.count == 16,
                      "fingerprint must be 16 bytes")
        var nonce = Data(count: 16)
        nonce.withUnsafeMutableBytes { ptr in
            // SecRandom — SecRandomCopyBytes is the standard
            // iOS RNG.  16 bytes is well under any limits.
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        return MigrationHandshake(
            version:     1,
            fingerprint: fingerprint,
            nonce:       nonce,
            addr:        nil,
            port:        nil)
    }

    /// Encode for QR display.  Base64url-of-JSON keeps the payload
    /// URL-safe (no '+' / '/' / '=' to URL-escape) and avoids edge
    /// cases pure-JSON-in-QR would hit with control characters.
    /// Deterministic key ordering so the same struct produces the
    /// same encoding on both platforms.
    func encodeForQR() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let json = (try? enc.encode(self)) ?? Data()
        return json.base64URLEncodedString()
    }

    /// Decode a handshake string.  Used for BOTH the QR-scan path
    /// (image → string → decode) AND the manual-paste fallback
    /// (clipboard → string → decode).  The string format is the
    /// same in either case — base64url-of-JSON, ~50 chars at v1
    /// — so a user who can't or won't use the camera can read
    /// the receiver's handshake on screen, AirDrop / message it
    /// to themselves, paste into the sender's "Paste handshake"
    /// field.
    ///
    /// Returns nil for malformed payloads, unsupported versions,
    /// or wrong-shaped fingerprint bytes — the caller surfaces a
    /// clear "that doesn't look like a Peer2Pear handshake" error
    /// rather than crashing on bad input.
    static func decode(_ encoded: String) -> MigrationHandshake? {
        // Tolerate the user pasting whitespace / newlines around
        // the encoded string (clipboard edge cases on iOS sometimes
        // include trailing newlines).
        let trimmed = encoded.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64URLEncoded: trimmed) else { return nil }
        guard let h = try? JSONDecoder().decode(
                MigrationHandshake.self, from: data) else {
            return nil
        }
        guard supportedVersions.contains(h.version) else { return nil }
        guard h.fingerprint.count == 16             else { return nil }
        guard h.nonce.count == 16                   else { return nil }
        // v2 sanity: if either of addr/port is present, both must
        // be — a half-populated handshake means a sender produced
        // a malformed payload.  v1 senders omit both, which is
        // also valid.
        if (h.addr != nil) != (h.port != nil)       { return nil }
        if let p = h.port, p <= 0 || p > 65535      { return nil }
        return h
    }

    /// Back-compat alias — older call sites referring to the
    /// QR-specific name still work.  Both paths (camera QR scan
    /// and manual paste) decode the same string format.
    static func decodeFromQR(_ qr: String) -> MigrationHandshake? {
        decode(qr)
    }
}

// base64url helpers — used by the QR encoding above.  Standard
// base64 has '+' / '/' which trigger URL escaping, and '=' padding
// that's noisy in QR codes; the URL variant fixes both.
extension Data {
    func base64URLEncodedString() -> String {
        let s = base64EncodedString()
        return s.replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded s: String) {
        var b64 = s.replacingOccurrences(of: "-", with: "+")
                   .replacingOccurrences(of: "_", with: "/")
        // Re-pad to a multiple of 4 chars — base64 decoder is
        // strict about padding even though the URL variant elides it.
        while b64.count % 4 != 0 { b64.append("=") }
        guard let d = Data(base64Encoded: b64) else { return nil }
        self = d
    }
}
