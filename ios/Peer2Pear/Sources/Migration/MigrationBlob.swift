import Foundation

// Inner payload of a migration transfer — what's encrypted inside
// the AEAD envelope.  The envelope itself is opaque bytes produced
// by the C-side MigrationCrypto::seal (which handles the X25519 +
// ML-KEM-768 hybrid + ChaChaPoly AEAD); Swift just packs / unpacks
// this payload struct + lets C handle the transit format.
//
// First slice (B.1) ships identity-only payloads.  Future chunks
// add optional fields (settings, SQLite snapshot, file metadata,
// saved-files trailer per project_backup_strategy.md's Tier 1/2
// inventory).  Adding optional fields is forward-compatible —
// older receivers ignore unknown JSON keys; required new fields
// bump `currentVersion`.
//
// JSON encoding via Codable keeps the payload format human-
// debuggable + cross-platform.  When desktop migration lands its
// matching Qt parser is a one-liner with QJsonDocument.

struct MigrationPayload: Codable {
    /// Payload-format version.  Distinct from the C-side envelope
    /// version (which gates wire-shape changes) so the two can
    /// evolve independently.
    ///   v1 — identity files only
    ///   v2 — adds appDataSnapshot (B.6.5)
    ///   v3 — adds userDefaults (B.6.6 — settings)
    /// Bumped on each incompatible payload change; senders set,
    /// receivers refuse non-matching values.  Pre-launch: no
    /// fielded v1/v2 to back-compat with, so clean breaks are
    /// fine.
    let version: Int

    /// Raw bytes of the source device's `identity.json`.  Already
    /// encrypted-at-rest under the user's passphrase on the source
    /// device; this transfer ships those exact bytes (no
    /// re-encryption beyond the AEAD transport layer).  Receiver
    /// must use the SAME passphrase as the source — that's the one
    /// piece of state that doesn't travel and can't be regenerated.
    let identityFile: Data

    /// Source device's salt file.  Argon2id parameters depend on
    /// the salt to derive deterministic keys from the passphrase;
    /// without it the receiver would re-derive different keys and
    /// fail to decrypt the migrated identity / DB.
    let saltFile: Data

    /// JSON-encoded MigrationAppDataSnapshot bytes — Tier 1
    /// migration content (contacts, conversations, members,
    /// messages, blocked_keys).  Empty for v2 senders that
    /// somehow couldn't build a snapshot; receivers tolerate
    /// empty (apply skipped, identity-only migration).
    let appDataSnapshot: Data

    /// Allowlisted UserDefaults snapshot from MigrationSettings.
    /// Each value is a plist-encoded `[String: Data]` entry
    /// keyed by UserDefaults key.  Plist preserves type info
    /// (Bool / Int / String / [String]) so receivers don't have
    /// to know each key's expected type at apply-time.
    /// Empty `[:]` is fine for senders with default settings;
    /// receivers skip apply for empty.
    let userDefaults: [String: Data]

    // Future fields:
    //   - fileRecords: [DBFileRecord]   // file-transfer METADATA only
    //                                    (saved files themselves don't
    //                                    transfer — that's a device-
    //                                    transfer problem, AirDrop's
    //                                    domain not ours)
}

extension MigrationPayload {
    /// Bumped on each incompatible payload change.  Senders set;
    /// receivers refuse non-matching values.
    static let currentVersion = 3
}
