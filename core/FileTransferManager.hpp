#pragma once

#include <cstdint>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

class CryptoEngine;
class SqlCipherDb;

/*
 * FileTransferManager — handles chunked, encrypted file transfers.
 *
 * Outbound: streams a file from disk in <= 240 KB chunks, encrypts each with
 *           a per-file ratchet-derived key, and dispatches via P2P or sealed
 *           relay. Includes BLAKE2b-256 integrity hash for verification.
 *           Never holds the full file in RAM.
 *
 * Inbound:  parses file-chunk envelopes, decrypts, writes each chunk directly
 *           to a disk-backed partial file at its correct offset, tracks
 *           received indices in a bitmap. On completion verifies integrity
 *           hash and renames the partial file to its final name. Never holds
 *           the full file in RAM.
 *
 * Supports both 1-to-1 and group file transfers.
 *
 * Types: std::string (UTF-8) for paths/IDs/names, std::vector<uint8_t>
 * (Bytes) for byte blobs, int64_t Unix seconds for timestamps.
 */
class FileTransferManager {
public:
    using Bytes = std::vector<uint8_t>;

    /// Return the sealed envelope to dispatch for a file chunk.  Empty = seal failed.
    using SealFn = std::function<Bytes(const std::string& peerIdB64u,
                                       const Bytes& payload)>;
    /// Dispatch a pre-sealed envelope to a peer (typically RelayClient::sendEnvelope).
    using SendFn = std::function<void(const std::string& peerIdB64u,
                                      const Bytes& env)>;
    /// Try to send a chunk over a P2P QUIC stream. Returns true on success.
    using SendFileP2PFn = std::function<bool(const std::string& peerIdB64u,
                                             const Bytes& chunk)>;

    explicit FileTransferManager(CryptoEngine& crypto);

    void setSendFn(SendFn fn)              { m_sendFn = std::move(fn); }
    void setSealFn(SealFn fn)              { m_sealFn = std::move(fn); }
    void setP2PFileSendFn(SendFileP2PFn fn){ m_p2pFileSendFn = std::move(fn); }

    /// Root directory for partial incoming files. Defaults to
    /// Downloads/Peer2Pear/.peer2pear-partial/ — can be overridden per platform.
    void setPartialFileDir(const std::string& dir);

    /// Attach a shared DB for persisting partial-transfer state.
    void setDatabase(SqlCipherDb* db);

    /// Restore in-flight incoming transfers from the DB on startup.
    void loadPersistedTransfers();

    /// Receiver-side resumption — list of incomplete transfers and their
    /// missing chunk indices.
    struct PendingResumption {
        std::string           transferId;
        std::string           peerId;
        std::vector<uint32_t> missingChunks;
    };
    std::vector<PendingResumption> pendingResumptions() const;

    /// Sender-side: re-read specific chunks from the original file and
    /// re-dispatch them.  Called when a file_request arrives.
    bool resendChunks(const std::string& transferId,
                      const std::vector<uint32_t>& chunkIndices);

    /// Sender records a transfer for later resumption.
    void registerSentTransfer(const std::string& senderIdB64u,
                               const std::string& peerIdB64u,
                               const std::string& transferId,
                               const std::string& fileName,
                               const std::string& filePath,
                               int64_t fileSize,
                               const Bytes& fileHash,
                               const Bytes& fileKey,
                               const std::string& groupId = {},
                               const std::string& groupName = {});

    /// Sender drops its record of a delivered transfer.
    void forgetSentTransfer(const std::string& transferId);

    /// Delete partial files older than kPartialFileMaxAgeSecs.
    void purgeStalePartialFiles();

    /// Toggle live sender-side privacy.
    void setSenderRequiresP2P(bool require);

    // ── Size knobs ──────────────────────────────────────────────────────────
    static constexpr int64_t kChunkBytes     = 240LL * 1024;
    static constexpr int64_t kMaxFileBytes   = 100LL * 1024 * 1024;
    static constexpr int64_t kLargeFileBytes = 5LL * 1024 * 1024;

    // ── Lifecycle timing ────────────────────────────────────────────────────
    static constexpr int     kP2PReadyWaitSecs           = 10;
    static constexpr int64_t kOutboundPendingTimeoutSecs = 10LL * 60;
    static constexpr int64_t kMaxTransferAgeSecs         = 30LL * 60;
    // At-rest file-key TTLs kept short so a device compromise exposes
    // fewer in-flight keys.  Receiver window (3 days) is long enough for
    // a weekend-away resumption; sender window (12 h) assumes senders
    // are typically active around the transfer.  Both values are the
    // DB-row TTL; the in-memory IncomingTransfer is still purged after
    // kMaxTransferAgeSecs (30 min) of inactivity.
    static constexpr int64_t kSentTransferMaxAgeSecs     = 12LL * 60 * 60;
    static constexpr int64_t kPartialFileMaxAgeSecs      = 3LL * 24 * 60 * 60;

    /// Send a file to a single peer using a pre-derived per-file ratchet key.
    std::string sendFileWithKey(const std::string& senderIdB64u,
                                 const std::string& peerIdB64u,
                                 const Bytes& fileKey,
                                 const std::string& transferId,
                                 const std::string& fileName,
                                 const std::string& filePath,
                                 int64_t fileSize,
                                 const Bytes& fileHash,
                                 const std::string& groupId = {},
                                 const std::string& groupName = {});

    // ── Outbound consent gate ───────────────────────────────────────────────
    void queueOutboundFile(const std::string& senderIdB64u,
                           const std::string& peerIdB64u,
                           const Bytes& fileKey,
                           const std::string& transferId,
                           const std::string& fileName,
                           const std::string& filePath,
                           int64_t fileSize,
                           const Bytes& fileHash,
                           const std::string& groupId = {},
                           const std::string& groupName = {});

    bool startOutboundStream(const std::string& transferId,
                             bool requireP2P,
                             bool senderRequiresP2P,
                             bool p2pReadyNow);

    std::vector<std::string> notifyP2PReady(const std::string& peerIdB64u);

    void abandonOutboundTransfer(const std::string& transferId);

    void cancelInboundTransfer(const std::string& transferId);

    std::string outboundPeerFor(const std::string& transferId) const;
    std::string inboundPeerFor(const std::string& transferId) const;

    void purgeStaleOutbound();

    bool announceIncoming(const std::string& fromId,
                           const std::string& transferId,
                           const std::string& fileName,
                           int64_t fileSize,
                           int totalChunks,
                           const Bytes& fileHash,
                           const Bytes& fileKey,
                           int64_t announcedTsSecs,
                           const std::string& groupId = {},
                           const std::string& groupName = {});

    bool handleFileEnvelope(const std::string& fromId,
                            const Bytes& payload,
                            std::function<bool(const std::string&)> markSeen,
                            const std::map<std::string, Bytes>& fileKeys = {});

    void purgeStaleTransfers();

    /// One-shot BLAKE2b-256 of a byte buffer (used for small data).
    static Bytes blake2b256(const Bytes& data);

    /// Streaming BLAKE2b-256 of a file on disk. One pass, constant RAM.
    static Bytes blake2b256File(const std::string& filePath);

    // ── Event callbacks — set from outside; fire on the main/event thread ──
    //
    // Callers assign directly:
    //   ftm.onStatus = [](const std::string& s) { ... };

    std::function<void(const std::string&)> onStatus;

    /// Fires after dispatching the first chunk so ChatController can
    /// bootstrap a P2P session for subsequent messages.
    std::function<void(const std::string& peerIdB64u)> onWantP2PConnection;

    /// Fires when a transfer completes (success, hash failure, or purge).
    std::function<void(const std::string& transferId)> onTransferCompleted;

    /// Fires when an outbound transfer is abandoned.
    std::function<void(const std::string& transferId,
                       const std::string& peerId)>     onOutboundAbandoned;

    /// Fires when an inbound transfer is canceled mid-stream.
    std::function<void(const std::string& transferId,
                       const std::string& peerId)>     onInboundCanceled;

    /// Outbound blocked by P2P-only policy.
    std::function<void(const std::string& transferId,
                       const std::string& peerId,
                       bool byReceiver)>               onOutboundBlockedByPolicy;

    /// Repopulate ChatController's m_fileKeys for resumed transfers.
    std::function<void(const std::string& fromPeerIdB64u,
                       const std::string& transferId,
                       const Bytes&       fileKey)>    onIncomingFileKeyRestored;

    /// Progress + completion callback.  savedPath is set when the transfer
    /// is complete; timestampSec is Unix epoch seconds (UTC).
    std::function<void(const std::string& fromPeerIdB64u,
                       const std::string& transferId,
                       const std::string& fileName,
                       int64_t            fileSize,
                       int                chunksReceived,
                       int                chunksTotal,
                       const std::string& savedPath,
                       int64_t            timestampSec,
                       const std::string& groupId,
                       const std::string& groupName)>  onFileChunkReceived;

    /// Sender-side progress.  Fires after each outbound chunk dispatches
    /// successfully (after dispatchChunk returns true).  Terminal events —
    /// completion, cancel, block — come via their own callbacks
    /// (onTransferCompleted / onOutboundAbandoned / onOutboundBlockedByPolicy);
    /// this one is purely the running count.
    ///
    /// chunksSent == chunksTotal is the last progress callback of a
    /// successful transfer; onTransferCompleted fires separately (and later,
    /// after the receiver's delivery confirmation).
    std::function<void(const std::string& toPeerIdB64u,
                       const std::string& transferId,
                       const std::string& fileName,
                       int64_t            fileSize,
                       int                chunksSent,
                       int                chunksTotal,
                       int64_t            timestampSec,
                       const std::string& groupId,
                       const std::string& groupName)>  onFileChunkSent;

private:
    /// Per-incoming-transfer state. Backed by a file on disk.
    struct IncomingTransfer {
        std::string fromId;
        std::string fileName;
        int64_t     fileSize    = 0;
        int         totalChunks = 0;
        int64_t     tsSecs      = 0;
        Bytes       fileHash;           // BLAKE2b-256 of original plaintext
        std::string groupId;
        std::string groupName;
        int64_t     createdSecs = 0;

        std::string partialPath;        // <partialDir>/<transferId>.partial
        std::string finalPath;          // destination after rename on completion
        std::unique_ptr<std::fstream> partialFile;
        std::vector<bool> receivedChunks;  // bitmap, size == totalChunks
        int               chunksReceivedCount = 0;

        IncomingTransfer() = default;
        IncomingTransfer(const IncomingTransfer&) = delete;
        IncomingTransfer& operator=(const IncomingTransfer&) = delete;
        IncomingTransfer(IncomingTransfer&&) = default;
        IncomingTransfer& operator=(IncomingTransfer&&) = default;
    };

    enum class RoutingMode {
        Auto,
        P2POnly,
    };

    void sendChunkEnvelopes(const std::string& senderIdB64u,
                            const std::string& peerIdB64u,
                            const Bytes& key32,
                            const std::string& filePath,
                            int64_t fileSize,
                            const std::string& transferId,
                            const std::string& fileName,
                            const std::string& fileHashB64u,
                            int64_t ts,
                            RoutingMode mode,
                            const std::string& groupId = {},
                            const std::string& groupName = {});

    bool dispatchChunk(const std::string& senderIdB64u,
                       const std::string& peerIdB64u,
                       const Bytes& innerPayload,
                       RoutingMode mode);

    std::string partialPathFor(const std::string& transferId);
    std::string finalPathFor(const std::string& fileName, const std::string& transferId);

    std::map<std::string, std::shared_ptr<IncomingTransfer>> m_incomingTransfers;
    static constexpr int kMaxConcurrentTransfers = 50;

    enum class OutboundStage {
        Queued,
        WaitingForP2P,
    };
    struct OutboundTransfer {
        std::string senderId;
        std::string peerId;
        Bytes       fileKey;        // 32 bytes — zero on drop
        std::string fileName;
        std::string filePath;
        int64_t     fileSize = 0;
        Bytes       fileHash;
        std::string groupId;
        std::string groupName;
        int64_t     queuedSecs = 0;

        OutboundStage stage = OutboundStage::Queued;
        bool    receiverRequiresP2P = false;
        bool    senderRequiresP2P   = false;
        int64_t waitStartedSecs     = 0;
    };
    std::map<std::string, OutboundTransfer> m_outboundPending;

    std::set<std::string> m_abortedTransfers;

    bool m_senderRequiresP2PLive = false;

    struct SentTransfer {
        std::string senderId;
        std::string peerId;
        std::string fileName;
        std::string filePath;
        int64_t     fileSize = 0;
        Bytes       fileHash;        // 32 bytes
        Bytes       fileKey;         // 32 bytes — zeroed on purge/completion
        std::string groupId;
        std::string groupName;
        int64_t     createdSecs = 0;
    };
    std::map<std::string, SentTransfer> m_sentTransfers;

    SqlCipherDb* m_dbPtr = nullptr;

    // ── DB helpers ──────────────────────────────────────────────────────────
    void ensurePhase4Tables();
    void persistIncomingFull(const std::string& transferId,
                              const IncomingTransfer& xfer,
                              const Bytes& fileKey) const;
    void deleteIncomingRow(const std::string& transferId) const;
    void deleteSentRow(const std::string& transferId) const;

    std::string m_partialDir;  // configurable via setPartialFileDir()

    CryptoEngine& m_crypto;
    SendFn        m_sendFn;
    SealFn        m_sealFn;
    SendFileP2PFn m_p2pFileSendFn;
};
