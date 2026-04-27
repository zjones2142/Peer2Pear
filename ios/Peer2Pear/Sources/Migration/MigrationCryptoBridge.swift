import Foundation

// Thin Swift wrapper over the C-side migration-crypto API.
//
// All cryptographic work — X25519 + ML-KEM-768 hybrid AEAD seal,
// pubkey fingerprinting, AAD construction — lives in
// core/MigrationCrypto.{hpp,cpp} where libsodium + liboqs are
// already wired (matches the rest of the protocol's hybrid-PQ
// posture: NoiseState, RatchetSession, SealedEnvelope).  This
// file's job is byte-array marshalling between Swift `Data` and
// the C `uint8_t*` surface, plus letting Swift call the four
// migration entry points without dropping into UnsafePointer
// boilerplate at every call site.
//
// Cross-platform: when desktop migration lands, Qt code calls
// the same C++ `MigrationCrypto::*` namespace directly — no
// re-implementation of the crypto needed.

/// Receiver's keypair quartet — both X25519 + ML-KEM-768 pairs.
/// Generated on the receiver via `generateKeypairs()`, fingerprint
/// goes in the QR, full pubkeys cross over MPC after pairing,
/// privates stay in receiver process memory until use + then
/// should be zeroed.
///
/// `Data` is value-typed but the underlying buffer is COW-shared
/// — wiping it doesn't reliably zero RAM across copies.  Treated
/// as a known limitation here (same trade-off the unlock
/// passphrase has elsewhere); strict zeroing would need a
/// custom `[UInt8]` wrapper threaded through the C bridge.
struct MigrationKeypairs {
    let x25519Pub:  Data   // 32 bytes
    let x25519Priv: Data   // 32 bytes
    let mlkemPub:   Data   // 1184 bytes
    let mlkemPriv:  Data   // 2400 bytes
}

enum MigrationCryptoBridge {

    /// Generate fresh ephemeral keypairs.  Returns nil on any
    /// libsodium / liboqs error from the C side.
    static func generateKeypairs() -> MigrationKeypairs? {
        var xPub  = Data(count: Int(P2P_MIGRATION_X25519_PUB_LEN))
        var xPriv = Data(count: Int(P2P_MIGRATION_X25519_PRIV_LEN))
        var mPub  = Data(count: Int(P2P_MIGRATION_MLKEM_PUB_LEN))
        var mPriv = Data(count: Int(P2P_MIGRATION_MLKEM_PRIV_LEN))

        let rc = xPub.withUnsafeMutableBytes { xp in
            xPriv.withUnsafeMutableBytes { xv in
                mPub.withUnsafeMutableBytes { mp in
                    mPriv.withUnsafeMutableBytes { mv in
                        p2p_migration_keypair(
                            xp.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            xv.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            mp.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            mv.baseAddress!.assumingMemoryBound(to: UInt8.self))
                    }
                }
            }
        }
        guard rc == 0 else { return nil }

        return MigrationKeypairs(
            x25519Pub:  xPub,
            x25519Priv: xPriv,
            mlkemPub:   mPub,
            mlkemPriv:  mPriv)
    }

    /// Compute the QR fingerprint for a pubkey pair.
    /// Format: SHA-256(x25519_pub || mlkem_pub)[0..16].
    /// Returns nil on malformed (wrong-sized) input.
    static func fingerprint(x25519Pub: Data, mlkemPub: Data) -> Data? {
        guard x25519Pub.count == Int(P2P_MIGRATION_X25519_PUB_LEN),
              mlkemPub.count  == Int(P2P_MIGRATION_MLKEM_PUB_LEN) else {
            return nil
        }
        var fp = Data(count: Int(P2P_MIGRATION_FINGERPRINT_LEN))
        let rc = x25519Pub.withUnsafeBytes { xp in
            mlkemPub.withUnsafeBytes { mp in
                fp.withUnsafeMutableBytes { fpw in
                    p2p_migration_fingerprint(
                        xp.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        mp.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        fpw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        return rc == 0 ? fp : nil
    }

    /// Seal a payload for transit.  `payload` is typically a
    /// JSON-encoded MigrationPayload.  Returns the wire envelope
    /// bytes ready to ship over MultipeerConnectivity, or nil on
    /// any encrypt error.
    static func seal(payload: Data,
                       receiverX25519Pub: Data,
                       receiverMlkemPub: Data,
                       handshakeNonce: Data) -> Data?
    {
        guard receiverX25519Pub.count == Int(P2P_MIGRATION_X25519_PUB_LEN),
              receiverMlkemPub.count  == Int(P2P_MIGRATION_MLKEM_PUB_LEN),
              handshakeNonce.count    == Int(P2P_MIGRATION_NONCE_LEN),
              !payload.isEmpty else {
            return nil
        }

        // Cap the output buffer at payload + overhead; the C
        // function returns the actual byte count it wrote.
        let cap = payload.count + Int(P2P_MIGRATION_ENVELOPE_OVERHEAD)
        var out = Data(count: cap)

        let written: Int32 = payload.withUnsafeBytes { pl in
            receiverX25519Pub.withUnsafeBytes { rxPub in
                receiverMlkemPub.withUnsafeBytes { rmPub in
                    handshakeNonce.withUnsafeBytes { nonce in
                        out.withUnsafeMutableBytes { outBuf in
                            p2p_migration_seal(
                                pl.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                Int32(payload.count),
                                rxPub.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                rmPub.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                nonce.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                Int32(cap))
                        }
                    }
                }
            }
        }
        guard written > 0 else { return nil }
        out.removeSubrange(Int(written)..<out.count)
        return out
    }

    /// Open a sealed envelope.  Caller passes own pubs (for AAD
    /// reconstruction — must match what sender used) AND privs
    /// (for DH + decapsulation).  Returns the decrypted payload
    /// bytes, or nil on any failure.
    ///
    /// Failure modes are deliberately not distinguished — the
    /// underlying AEAD doesn't tell us "wrong key" vs "tampered
    /// ciphertext" by design (no oracle).  Callers surface a
    /// single "couldn't decrypt — wrong setup or tampered
    /// transfer" message to users.
    static func open(envelope: Data,
                       receiverX25519Pub: Data,
                       receiverX25519Priv: Data,
                       receiverMlkemPub: Data,
                       receiverMlkemPriv: Data,
                       handshakeNonce: Data) -> Data?
    {
        guard receiverX25519Pub.count  == Int(P2P_MIGRATION_X25519_PUB_LEN),
              receiverX25519Priv.count == Int(P2P_MIGRATION_X25519_PRIV_LEN),
              receiverMlkemPub.count   == Int(P2P_MIGRATION_MLKEM_PUB_LEN),
              receiverMlkemPriv.count  == Int(P2P_MIGRATION_MLKEM_PRIV_LEN),
              handshakeNonce.count     == Int(P2P_MIGRATION_NONCE_LEN),
              !envelope.isEmpty else {
            return nil
        }

        // Output buffer cap: envelope size minus overhead is the
        // upper bound on payload size; size the buffer to match.
        let cap = max(envelope.count, 0)
        var out = Data(count: cap)

        let written: Int32 = envelope.withUnsafeBytes { env in
            receiverX25519Pub.withUnsafeBytes { rxPub in
                receiverX25519Priv.withUnsafeBytes { rxPriv in
                    receiverMlkemPub.withUnsafeBytes { rmPub in
                        receiverMlkemPriv.withUnsafeBytes { rmPriv in
                            handshakeNonce.withUnsafeBytes { nonce in
                                out.withUnsafeMutableBytes { outBuf in
                                    p2p_migration_open(
                                        env.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        Int32(envelope.count),
                                        rxPub.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        rxPriv.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        rmPub.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        rmPriv.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        nonce.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        Int32(cap))
                                }
                            }
                        }
                    }
                }
            }
        }
        guard written > 0 else { return nil }
        out.removeSubrange(Int(written)..<out.count)
        return out
    }
}
