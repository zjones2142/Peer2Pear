import Foundation
import Network

// MARK: - File transfer state machine + policy
//
// Owns the per-transfer upserts, user-consent responses, cancellation,
// and the SwiftUI-visible policy setters (auto-accept MB, hard max MB,
// require-P2P).  Also the NWPathMonitor that silently paves auto-accept
// to 0 when the device drops off Wi-Fi — see `onWifi` in the main file.
//
// Stored properties (transfers dict, pendingFileRequests, pathMonitor,
// etc.) still live in Peer2PearClient.swift since Swift extensions
// can't add stored members.

extension Peer2PearClient {

    // MARK: - Transfer state mutators (called from callbacks on the main queue)

    /// Upsert an in-progress transfer record.  Preserves existing
    /// terminal status (.completed / .delivered / .canceled / .blocked)
    /// — a late-arriving chunk event shouldn't flip a completed
    /// transfer back to .inFlight.
    func upsertTransfer(id: String, peerId: String,
                         fileName: String, fileSize: Int64,
                         direction: P2PTransferDirection,
                         chunksDone: Int, chunksTotal: Int,
                         savedPath: String?,
                         status: P2PTransferStatus,
                         timestamp: Date) {
        if var existing = transfers[id] {
            existing.chunksDone  = max(existing.chunksDone, chunksDone)
            existing.chunksTotal = chunksTotal > 0 ? chunksTotal : existing.chunksTotal
            if let savedPath { existing.savedPath = savedPath }
            if !existing.isTerminal {
                existing.status = status
            }
            existing.timestamp = max(existing.timestamp, timestamp)
            transfers[id] = existing
        } else {
            transfers[id] = P2PTransferRecord(
                id: id, peerId: peerId, fileName: fileName, fileSize: fileSize,
                direction: direction,
                chunksDone: chunksDone, chunksTotal: chunksTotal,
                savedPath: savedPath, status: status, timestamp: timestamp)
        }
        if let r = transfers[id] { persistTransfer(r) }
    }

    /// Flip the status on an existing record (delivered / canceled /
    /// blocked events).  No-op if the transferId is unknown — not
    /// every cancel / block necessarily has a prior progress event on
    /// record (e.g. the transfer was blocked before the first chunk).
    func markTransferStatus(id: String, status: P2PTransferStatus) {
        guard var existing = transfers[id] else { return }
        existing.status = status
        existing.timestamp = Date()
        transfers[id] = existing
        persistTransfer(existing)
    }

    /// Mirror a P2PTransferRecord into the file_transfers table so the
    /// row survives lock/unlock + relaunch.  Cheap UPSERT — every status
    /// change calls this; SQLite handles it in <1 ms.  The chat key is
    /// the counter-party's peer ID for 1:1 (groups TBD when iOS sends
    /// group files).
    func persistTransfer(_ r: P2PTransferRecord) {
        dbSaveFileRecord(DBFileRecord(
            transferId:     r.id,
            chatKey:        r.peerId,
            fileName:       r.fileName,
            fileSize:       r.fileSize,
            peerId:         r.peerId,
            peerName:       contactNicknames[r.peerId] ?? "",
            timestampSecs:  Int64(r.timestamp.timeIntervalSince1970),
            sent:           r.direction == .outbound,
            status:         Self.encodeStatus(r.status),
            chunksTotal:    r.chunksTotal,
            chunksComplete: r.chunksDone,
            savedPath:      r.savedPath ?? ""))
    }

    // MARK: - File transfer actions

    /// Start a file send.  Returns the transferId on success, nil otherwise.
    /// The receiver will get an `on_file_request` callback and must accept
    /// via `respondToFileRequest` before chunks flow.
    @discardableResult
    func sendFile(to peerId: String, fileName: String, filePath: String) -> String? {
        guard let ctx = rawContext else { return nil }
        if isBlocked(peerId: peerId) { return nil }
        guard let c = p2p_send_file(ctx, peerId, fileName, filePath) else { return nil }
        return String(cString: c)
    }

    /// Reply to an on_file_request prompt.  Accept=true installs the key
    /// and tells the sender to start streaming chunks; accept=false
    /// declines (zeroes the stashed key, no further state).
    func respondToFileRequest(transferId: String,
                              accept: Bool,
                              requireP2P: Bool = false) {
        guard let ctx = rawContext else { return }
        p2p_respond_file_request(ctx, transferId, accept ? 1 : 0, requireP2P ? 1 : 0)
        DispatchQueue.main.async { [weak self] in
            self?.pendingFileRequests.removeAll { $0.id == transferId }
        }
    }

    /// Cancel an in-flight transfer (inbound or outbound).
    func cancelTransfer(transferId: String) {
        guard let ctx = rawContext else { return }
        p2p_cancel_transfer(ctx, transferId)
    }

    /// Drop a terminal transfer record from the chat strip and the
    /// SQLCipher file_transfers table.  Mirrors desktop's "Remove this
    /// file from your file list" action — the saved file (if any) stays
    /// on disk untouched; only the bookkeeping row goes away.  No-op
    /// for in-flight transfers (use `cancelTransfer` for those).
    func removeTransferRecord(transferId: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.transfers.removeValue(forKey: transferId)
            self.dbDeleteFileRecord(transferId: transferId)
        }
    }

    // MARK: - Policy setters (thin C-API wrappers)

    func setFileAutoAcceptMB(_ mb: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_file_auto_accept_mb(ctx, Int32(mb))
    }
    func setFileHardMaxMB(_ mb: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_file_hard_max_mb(ctx, Int32(mb))
    }
    func setFileRequireP2P(_ on: Bool) {
        guard let ctx = rawContext else { return }
        p2p_set_file_require_p2p(ctx, on ? 1 : 0)
    }

    // MARK: - Network-path observer (wifi vs. cellular)

    /// Compute and push the effective auto-accept MB to the core based
    /// on the user's setting + current network type.  Called on every
    /// network change AND every time the user flips the toggle / changes
    /// the threshold, so the core's rule is always current.
    func applyEffectiveAutoAcceptThreshold() {
        let effective: Int = (fileAutoAcceptWifiOnly && !onWifi)
            ? 0
            : fileAutoAcceptMB
        setFileAutoAcceptMB(effective)
    }

    /// Start the NWPathMonitor that watches for Wi-Fi vs. cellular
    /// transitions.  Idempotent — safe to call on every start().
    func startNetworkMonitor() {
        guard pathMonitor == nil else { return }
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            // usesInterfaceType(.wifi) is true for both 802.11 and a
            // wired ethernet adapter.  Treat both as "not cellular".
            let onWifi = path.usesInterfaceType(.wifi)
                      || path.usesInterfaceType(.wiredEthernet)
            DispatchQueue.main.async {
                guard let self else { return }
                if self.onWifi != onWifi {
                    self.onWifi = onWifi
                    self.applyEffectiveAutoAcceptThreshold()
                }
            }
        }
        m.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = m
    }
}
