#pragma once

#include <QObject>
#include <QMap>
#include <QByteArray>
#include <QDateTime>
#include <functional>

class CryptoEngine;

/*
 * FileTransferManager — handles chunked, encrypted file transfers.
 *
 * Outbound: splits a file into <= 240 KB chunks, encrypts each with
 *           a per-peer AEAD key, and enqueues via MailboxClient.
 *           Includes BLAKE2b-256 integrity hash for verification.
 *
 * Inbound:  parses file-chunk envelopes, decrypts, reassembles in order,
 *           verifies integrity hash, and emits fileChunkReceived on each
 *           chunk (progress) and on completion (with the full data).
 *
 * Supports both 1-to-1 and group file transfers.
 */
class FileTransferManager : public QObject {
    Q_OBJECT
public:
    // Callback for sealing envelopes (metadata privacy).
    // Takes (peerIdB64u, innerPayload) and returns sealed envelope bytes, or empty on failure.
    using SealFn = std::function<QByteArray(const QString& peerIdB64u, const QByteArray& payload)>;

    // SendFn: takes (recipientIdB64u, envelopeBytes) — sends via relay
    using SendFn = std::function<void(const QString&, const QByteArray&)>;

    explicit FileTransferManager(CryptoEngine& crypto, QObject* parent = nullptr);
    void setSendFn(SendFn fn) { m_sendFn = std::move(fn); }

    // Set the callback for sealing file chunk envelopes (M2 fix).
    void setSealFn(SealFn fn) { m_sealFn = std::move(fn); }

    // Callback for sending file chunks via P2P QUIC stream.
    // Returns true if sent successfully, false to fall back to mailbox.
    using SendFileP2PFn = std::function<bool(const QString& peerIdB64u, const QByteArray& chunk)>;
    void setP2PFileSendFn(SendFileP2PFn fn) { m_p2pFileSendFn = std::move(fn); }

    // The server enforces MAX_ENVELOPE_BYTES = 256 KB (262 144 bytes).
    //
    // Per-envelope overhead budget:
    //   "FROMFC:<43-char-key>\n"          =  51 bytes  (header)
    //   4-byte big-endian metaLen field   =   4 bytes
    //   encMeta (JSON ~250 B + AEAD 40 B) = ~290 bytes
    //   encChunk AEAD overhead            =  40 bytes
    //   ─────────────────────────────────────────────
    //   Total fixed overhead              = ~385 bytes
    //
    // Max plaintext chunk = 262 144 - 385 = ~261 759 bytes.
    // We use 240 KB = 245 760 bytes for a comfortable margin.
    // A 25 MB file therefore travels in at most ceil(25600 / 240) = 107 chunks.
    static constexpr qint64 kChunkBytes   = 240LL * 1024;   // 245 760 bytes
    static constexpr qint64 kMaxFileBytes  =  25LL * 1024 * 1024;

    // Send a file to a single peer using a ratchet-derived key.
    // The caller (ChatController) sends a file_key announcement through the
    // ratchet first, then passes the resulting key and transferId here.
    // Returns transferId or empty on failure.
    QString sendFileWithKey(const QString& senderIdB64u,
                            const QString& peerIdB64u,
                            const QByteArray& fileKey,
                            const QString& transferId,
                            const QString& fileName,
                            const QByteArray& fileData,
                            const QString& groupId = {},
                            const QString& groupName = {});

    // Try to handle an envelope payload as a file chunk.
    // markSeen is called for per-chunk dedup; returns false if already seen.
    // fileKeys: map of transferId -> 32-byte ratchet key from file_key announcements.
    //           If a matching key is found, it's used instead of ECDH.
    // Returns true if the envelope was a file chunk (handled), false otherwise.
    bool handleFileEnvelope(const QString& fromId,
                            const QByteArray& payload,
                            std::function<bool(const QString&)> markSeen,
                            const QMap<QString, QByteArray>& fileKeys = {});

    // Purge incomplete transfers older than 30 minutes to bound memory.
    void purgeStaleTransfers();

    // BLAKE2b-256 hash (used for file integrity checks).
    static QByteArray blake2b256(const QByteArray& data);

signals:
    void status(const QString& s);

    // Emitted when a P2P connection should be initiated for a peer
    // (as a side effect of sending file chunks via mailbox).
    void wantP2PConnection(const QString& peerIdB64u);

    // Emitted when a transfer completes (success or hash failure) or is purged.
    // ChatController uses this to remove the ratchet-derived key from m_fileKeys.
    void transferCompleted(const QString& transferId);

    void fileChunkReceived(const QString& fromPeerIdB64u,
                           const QString& transferId,
                           const QString& fileName,
                           qint64         fileSize,
                           int            chunksReceived,
                           int            chunksTotal,
                           const QByteArray& fileData,   // non-empty only when complete
                           const QDateTime& timestamp,
                           const QString& groupId = {},
                           const QString& groupName = {});

private:
    struct IncomingTransfer {
        QString   fromId;
        QString   fileName;
        qint64    fileSize    = 0;
        int       totalChunks = 0;
        QDateTime ts;
        QByteArray fileHash;   // BLAKE2b-256 of original plaintext
        QString   groupId;
        QString   groupName;
        qint64    createdSecs = 0;
        QMap<int, QByteArray> chunks;  // chunkIndex -> decrypted data
    };

    void sendChunkEnvelopes(const QString& senderIdB64u,
                            const QString& peerIdB64u,
                            const QByteArray& key32,
                            const QByteArray& fileData,
                            const QString& transferId,
                            const QString& fileName,
                            const QString& fileHashB64u,
                            qint64 ts,
                            const QString& groupId = {},
                            const QString& groupName = {});

    QMap<QString, IncomingTransfer> m_incomingTransfers; // transferId -> state
    static constexpr int kMaxConcurrentTransfers = 50;

    CryptoEngine& m_crypto;
    SendFn m_sendFn;
    SealFn m_sealFn;
    SendFileP2PFn m_p2pFileSendFn;
};
