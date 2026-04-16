#pragma once

#include <QObject>
#include <QMap>
#include <QByteArray>
#include <QBitArray>
#include <QDateTime>
#include <QFile>
#include <functional>
#include <memory>

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
 *           received indices in a QBitArray. On completion verifies integrity
 *           hash and renames the partial file to its final name. Never holds
 *           the full file in RAM.
 *
 * Supports both 1-to-1 and group file transfers.
 */
class FileTransferManager : public QObject {
    Q_OBJECT
public:
    using SealFn = std::function<QByteArray(const QString& peerIdB64u, const QByteArray& payload)>;
    using SendFn = std::function<void(const QString&, const QByteArray&)>;
    using SendFileP2PFn = std::function<bool(const QString& peerIdB64u, const QByteArray& chunk)>;

    explicit FileTransferManager(CryptoEngine& crypto, QObject* parent = nullptr);

    void setSendFn(SendFn fn)              { m_sendFn = std::move(fn); }
    void setSealFn(SealFn fn)              { m_sealFn = std::move(fn); }
    void setP2PFileSendFn(SendFileP2PFn fn){ m_p2pFileSendFn = std::move(fn); }

    /// Root directory for partial incoming files. Defaults to
    /// Downloads/Peer2Pear/.peer2pear-partial/ — can be overridden per platform.
    void setPartialFileDir(const QString& dir);

    /// Phase 4: attach a shared DB for persisting partial-transfer state.
    /// When set, incoming transfer state survives app restarts; on next
    /// open the receiver can send file_request for missing chunks.
    /// Pass nullptr to clear. Does not take ownership.
    void setDatabase(SqlCipherDb* db);

    /// Phase 4: restore in-flight incoming transfers from the DB on startup.
    /// Rebuilds m_incomingTransfers from the file_transfers table, re-opening
    /// each partial file in R/W mode and computing the received-chunks bitmap
    /// from the DB bitmap blob. Call once after setDatabase().
    void loadPersistedTransfers();

    /// Phase 4: receiver-side resumption — return the list of transferIds
    /// with incomplete bitmaps, and for each the array of missing chunk indices.
    /// ChatController uses this on peer reconnect to send file_request.
    struct PendingResumption {
        QString        transferId;
        QString        peerId;
        QList<quint32> missingChunks;
    };
    QList<PendingResumption> pendingResumptions() const;

    /// Phase 4: sender-side — re-read specific chunks from the original file
    /// and re-dispatch them. Called when a file_request arrives.
    /// If the transferId isn't in our outbound-sent record, returns false.
    bool resendChunks(const QString& transferId,
                      const QList<quint32>& chunkIndices);

    /// Phase 4: sender records the file+key+path of transfers currently
    /// streaming so it can answer later file_request calls.
    /// Called internally at stream start; persisted to DB.
    void registerSentTransfer(const QString& senderIdB64u,
                               const QString& peerIdB64u,
                               const QString& transferId,
                               const QString& fileName,
                               const QString& filePath,
                               qint64 fileSize,
                               const QByteArray& fileHash,
                               const QByteArray& fileKey,
                               const QString& groupId = {},
                               const QString& groupName = {});

    /// Phase 4: sender drops its record of a delivered transfer. Called from
    /// ChatController when file_ack arrives or when the sender cancels mid-stream.
    /// Zeroes the stored fileKey and removes the DB row. No-op if unknown.
    void forgetSentTransfer(const QString& transferId);

    /// Phase 4: one-shot startup pass that deletes partial files older
    /// than kPartialFileMaxAgeSecs on disk (7 days). Also removes their DB rows.
    void purgeStalePartialFiles();

    // Chunk size (240 KB fits in 256 KiB relay envelope with overhead).
    static constexpr qint64 kChunkBytes  = 240LL * 1024;
    // 100 MB file limit. With streaming I/O we can raise this later.
    static constexpr qint64 kMaxFileBytes = 100LL * 1024 * 1024;

    // Phase 3: files above this size prefer P2P streaming.
    // Below this threshold, the existing "P2P if ready, sealed relay otherwise"
    // routing still applies (chunks dispatch immediately).
    static constexpr qint64 kLargeFileBytes = 5LL * 1024 * 1024;

    // Phase 3: after file_accept arrives, wait up to this long for P2P
    // to establish before either streaming via relay (if permitted) or
    // aborting the transfer.
    static constexpr int kP2PReadyWaitSecs = 10;

    /// Send a file to a single peer using a pre-derived per-file ratchet key.
    /// Streams from disk — the full file is NEVER loaded into RAM.
    /// The caller (ChatController) must have already announced the fileKey
    /// via the ratchet before calling this.
    ///
    /// @param filePath  absolute path to the source file on disk
    /// @param fileSize  file size in bytes (caller already stat'd it)
    /// @param fileHash  BLAKE2b-256 of the file (caller already computed it)
    /// @return transferId on success, empty QString on failure
    QString sendFileWithKey(const QString& senderIdB64u,
                            const QString& peerIdB64u,
                            const QByteArray& fileKey,
                            const QString& transferId,
                            const QString& fileName,
                            const QString& filePath,
                            qint64 fileSize,
                            const QByteArray& fileHash,
                            const QString& groupId = {},
                            const QString& groupName = {});

    // ── Phase 2: outbound consent gate ──────────────────────────────────────
    //
    // Phase 2 flow: sender dispatches the file_key announcement, then QUEUES
    // the file here — chunks are NOT sent until the receiver replies with
    // file_accept. If the receiver declines/cancels/times out, the queued
    // state is dropped and the fileKey zeroed.

    /// Stash outbound file state, awaiting a file_accept.
    /// Copies the fileKey internally; caller may zero its copy after return.
    void queueOutboundFile(const QString& senderIdB64u,
                           const QString& peerIdB64u,
                           const QByteArray& fileKey,
                           const QString& transferId,
                           const QString& fileName,
                           const QString& filePath,
                           qint64 fileSize,
                           const QByteArray& fileHash,
                           const QString& groupId = {},
                           const QString& groupName = {});

    /// Called when file_accept arrives. Begins streaming per Phase 3 rules:
    ///   - Small files (≤ kLargeFileBytes): stream immediately, current routing
    ///     (P2P if ready, sealed relay fallback per-chunk).
    ///   - Large files: if P2P is ready, stream via P2P; otherwise park in
    ///     waiting-for-P2P state for up to kP2PReadyWaitSecs. If the wait
    ///     expires, relay fallback only when both sides permit it.
    ///
    /// @param requireP2P      receiver refuses relay fallback
    /// @param senderRequiresP2P sender refuses relay fallback (e.g. Privacy Level 2)
    /// @param p2pReadyNow     true if QuicConnection with peer is already established
    /// Returns false if the transferId isn't pending.
    bool startOutboundStream(const QString& transferId,
                             bool requireP2P,
                             bool senderRequiresP2P,
                             bool p2pReadyNow);

    /// Called when a peer's P2P connection becomes ready. Flushes any
    /// outbound transfers that were parked waiting for P2P.
    /// Returns the list of transferIds that were flushed.
    QList<QString> notifyP2PReady(const QString& peerIdB64u);

    /// Called when file_decline / file_cancel arrives, or user cancels locally.
    /// Zeroes the fileKey and drops outbound state. No-op if unknown transferId.
    void abandonOutboundTransfer(const QString& transferId);

    /// Cancel an in-progress inbound transfer — close partial file, delete it,
    /// drop receiver state. Called on file_cancel from sender or local cancel.
    void cancelInboundTransfer(const QString& transferId);

    /// Look up peer IDs for control messages.
    /// Returns empty QString if the transferId isn't known in that direction.
    QString outboundPeerFor(const QString& transferId) const;
    QString inboundPeerFor(const QString& transferId) const;

    /// Purge outbound-pending entries older than kOutboundPendingTimeoutSecs.
    /// Called from the same maintenance tick as purgeStaleTransfers().
    void purgeStaleOutbound();

    /// Announce an incoming file transfer with locked metadata (Fix #3).
    /// Creates the IncomingTransfer record, opens the partial file, and
    /// persists to DB. Called after ChatController processes a `file_key`
    /// announcement and consent is granted (auto-accept or user Accept).
    ///
    /// Once announced, any arriving chunk whose metadata disagrees with the
    /// announced (fileSize, totalChunks, fileHash) is dropped — preventing
    /// a sender from announcing a small file and then streaming a large one.
    ///
    /// Returns true on success. Returns false if a transfer with this id is
    /// already registered (idempotent no-op with log), or if the partial
    /// file can't be opened.
    bool announceIncoming(const QString& fromId,
                           const QString& transferId,
                           const QString& fileName,
                           qint64 fileSize,
                           int totalChunks,
                           const QByteArray& fileHash,
                           const QByteArray& fileKey,
                           qint64 announcedTsSecs,
                           const QString& groupId = {},
                           const QString& groupName = {});

    /// Try to handle an envelope payload as a file chunk.
    /// Decrypted chunks are written directly to disk — the chunk buffer is
    /// the only in-RAM copy at any time.
    bool handleFileEnvelope(const QString& fromId,
                            const QByteArray& payload,
                            std::function<bool(const QString&)> markSeen,
                            const QMap<QString, QByteArray>& fileKeys = {});

    /// Purge incomplete transfers older than 30 minutes.
    /// Also closes and deletes their partial files.
    void purgeStaleTransfers();

    /// One-shot BLAKE2b-256 of a byte buffer (used for small data).
    static QByteArray blake2b256(const QByteArray& data);

    /// Streaming BLAKE2b-256 of a file on disk. One pass, constant RAM.
    /// Returns empty QByteArray on failure (file not found, read error, etc).
    static QByteArray blake2b256File(const QString& filePath);

signals:
    void status(const QString& s);

    /// Emitted after dispatching the first chunk so ChatController can
    /// bootstrap a P2P session for subsequent messages.
    void wantP2PConnection(const QString& peerIdB64u);

    /// Emitted when a transfer completes (success, hash failure, or purge).
    /// ChatController uses this to zero the ratchet-derived file key.
    void transferCompleted(const QString& transferId);

    /// Emitted when an outbound transfer is abandoned (declined, canceled,
    /// or timed out). ChatController updates its UI state; no chunks were sent.
    void outboundAbandoned(const QString& transferId, const QString& peerId);

    /// Emitted when an inbound transfer is canceled mid-stream — either by
    /// local user action or a file_cancel from the sender. Partial file is
    /// already deleted by the time this fires.
    void inboundCanceled(const QString& transferId, const QString& peerId);

    /// Phase 3: emitted when an outbound transfer cannot proceed because
    /// P2P is unavailable and one side requires no relay fallback. The
    /// transfer has already been abandoned by the time this fires.
    void outboundBlockedByPolicy(const QString& transferId,
                                  const QString& peerId,
                                  bool byReceiver);

    /// Phase 4/Fix #5: emitted from loadPersistedTransfers() for each inbound
    /// transfer whose fileKey was restored from the DB. ChatController hooks
    /// this to repopulate its in-memory m_fileKeys map so resumption chunks
    /// can decrypt after an app restart.
    void incomingFileKeyRestored(const QString& fromPeerIdB64u,
                                  const QString& transferId,
                                  const QByteArray& fileKey);

    /// Progress + completion signal.
    /// savedPath is set when the transfer is complete (the final file on disk).
    /// Historical note: previous versions emitted a full fileData QByteArray
    /// on completion. With streaming I/O the file lives only on disk, so
    /// we emit its path instead.
    void fileChunkReceived(const QString& fromPeerIdB64u,
                           const QString& transferId,
                           const QString& fileName,
                           qint64         fileSize,
                           int            chunksReceived,
                           int            chunksTotal,
                           const QString& savedPath,   // non-empty only when complete
                           const QDateTime& timestamp,
                           const QString& groupId = {},
                           const QString& groupName = {});

private:
    /// Per-incoming-transfer state. Backed by a file on disk — chunks are
    /// written directly as they arrive, never accumulated in memory.
    /// Copy-constructed is deleted (unique_ptr semantics); use references only.
    struct IncomingTransfer {
        QString     fromId;
        QString     fileName;
        qint64      fileSize    = 0;
        int         totalChunks = 0;
        QDateTime   ts;
        QByteArray  fileHash;           // BLAKE2b-256 of original plaintext
        QString     groupId;
        QString     groupName;
        qint64      createdSecs = 0;

        QString     partialPath;        // <partialDir>/<transferId>.partial
        QString     finalPath;          // destination after rename on completion
        std::unique_ptr<QFile> partialFile;
        QBitArray   receivedChunks;     // bitmap, size == totalChunks
        int         chunksReceivedCount = 0;

        // Move-only (unique_ptr<QFile>).
        IncomingTransfer() = default;
        IncomingTransfer(const IncomingTransfer&) = delete;
        IncomingTransfer& operator=(const IncomingTransfer&) = delete;
        IncomingTransfer(IncomingTransfer&&) = default;
        IncomingTransfer& operator=(IncomingTransfer&&) = default;
    };

    /// Chunk dispatch policy for a given transfer.
    enum class RoutingMode {
        Auto,        // try P2P first, fall back to sealed relay
        P2POnly,     // only P2P; drop chunk if P2P unavailable
    };

    /// Stream a file from disk, chunk-by-chunk, encrypting each and
    /// dispatching according to the given routing mode.
    void sendChunkEnvelopes(const QString& senderIdB64u,
                            const QString& peerIdB64u,
                            const QByteArray& key32,
                            const QString& filePath,
                            qint64 fileSize,
                            const QString& transferId,
                            const QString& fileName,
                            const QString& fileHashB64u,
                            qint64 ts,
                            RoutingMode mode,
                            const QString& groupId = {},
                            const QString& groupName = {});

    /// Send one encrypted chunk envelope per routing mode.
    /// Returns true if dispatched (P2P or relay); false if dropped (P2POnly + no P2P).
    bool dispatchChunk(const QString& senderIdB64u,
                       const QString& peerIdB64u,
                       const QByteArray& innerPayload,
                       RoutingMode mode);

    /// Resolve the partial-file path for a transferId (mkdir if needed).
    QString partialPathFor(const QString& transferId);

    /// Compute the final save path. Uses a safe filename derived from meta.
    QString finalPathFor(const QString& fileName, const QString& transferId);

    // Shared-pointer wrapping keeps QMap happy (it needs copyable values for
    // copy-on-write detach), while the struct itself remains move-only because
    // it owns a unique_ptr<QFile>.
    QMap<QString, std::shared_ptr<IncomingTransfer>> m_incomingTransfers;
    static constexpr int kMaxConcurrentTransfers = 50;

    /// Outbound state tracked per transferId. Lifecycle:
    ///   Queued  (awaiting file_accept) → Waiting (file_accept received,
    ///   waiting for P2P) → streaming (chunks flying) → dropped.
    enum class OutboundStage {
        Queued,          // before file_accept
        WaitingForP2P,   // after file_accept, large file, P2P not ready
    };
    struct OutboundTransfer {
        QString    senderId;
        QString    peerId;
        QByteArray fileKey;        // 32 bytes — zero on drop
        QString    fileName;
        QString    filePath;
        qint64     fileSize = 0;
        QByteArray fileHash;
        QString    groupId;
        QString    groupName;
        qint64     queuedSecs = 0;

        // Phase 3 transport policy (populated on file_accept).
        OutboundStage stage = OutboundStage::Queued;
        bool     receiverRequiresP2P = false;
        bool     senderRequiresP2P   = false;
        qint64   waitStartedSecs     = 0;   // when we entered WaitingForP2P
    };
    QMap<QString, OutboundTransfer> m_outboundPending;

    /// Sender gives up on a queued file if no accept/decline arrives within
    /// this window. User can re-initiate the send.
    static constexpr qint64 kOutboundPendingTimeoutSecs = 10 * 60;  // 10 minutes

    /// Phase 4: sender-side record of an in-flight / delivered transfer kept
    /// so we can answer file_request calls for resumption. Lives in DB.
    struct SentTransfer {
        QString    senderId;
        QString    peerId;
        QString    fileName;
        QString    filePath;
        qint64     fileSize = 0;
        QByteArray fileHash;        // 32 bytes
        QByteArray fileKey;         // 32 bytes — zeroed on purge/completion
        QString    groupId;
        QString    groupName;
        qint64     createdSecs = 0;
    };
    QMap<QString, SentTransfer> m_sentTransfers;

    /// Phase 4: max age of partial files / sent-transfer records before purge.
    static constexpr qint64 kPartialFileMaxAgeSecs = 7LL * 24 * 60 * 60;

    SqlCipherDb* m_dbPtr = nullptr;  // Phase 4: shared DB for persistence

    // ── Phase 4: DB helpers ─────────────────────────────────────────────────
    void ensurePhase4Tables();
    void persistIncomingFull(const QString& transferId,
                              const IncomingTransfer& xfer,
                              const QByteArray& fileKey) const;
    void deleteIncomingRow(const QString& transferId) const;
    void deleteSentRow(const QString& transferId) const;

    QString m_partialDir;  // configurable via setPartialFileDir()

    CryptoEngine& m_crypto;
    SendFn        m_sendFn;
    SealFn        m_sealFn;
    SendFileP2PFn m_p2pFileSendFn;
};
