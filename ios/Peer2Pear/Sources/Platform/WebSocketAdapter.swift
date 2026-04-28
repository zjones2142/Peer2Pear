import Foundation

/// One WebSocket connection.  Owns a URLSessionWebSocketTask and a
/// receive loop.  Each instance is independent — the multi-WS pool
/// (see WebSocketPool) maintains many of these in parallel for the
/// receive-side multi-relay subscribe feature.
///
/// The C core invokes lifecycle methods (open / close / sendText) via
/// the v2 FFI (ws_open_v2 et al), passing the OpaquePointer that
/// identifies this connection.  The receive loop fires p2p_ws_on_*_v2
/// with that same pointer so the core can dispatch to the matching
/// IWebSocket on the C++ side.
final class WebSocketAdapter: NSObject, URLSessionWebSocketDelegate {
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private weak var context: Peer2PearClient?

    /// Identifier used by the C core's v2 callbacks.  Held as an
    /// OpaquePointer to the heap-allocated adapter — matches the
    /// pointer the pool returned from ws_alloc_connection.
    fileprivate var connHandle: UnsafeMutableRawPointer?

    var isConnected: Bool { task?.state == .running }
    var isIdle: Bool { task == nil || task?.state == .completed || task?.state == .canceling }

    init(client: Peer2PearClient) {
        self.context = client
        super.init()
        self.session = URLSession(configuration: .default, delegate: self, delegateQueue: .main)
    }

    func open(url: URL) {
        task?.cancel(with: .goingAway, reason: nil)
        task = session?.webSocketTask(with: url)
        task?.resume()
    }

    func close() {
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
    }

    func sendText(_ message: String) {
        task?.send(.string(message)) { error in
            if let error { print("[WS] send error: \(error)") }
        }
    }

    // MARK: - URLSessionWebSocketDelegate

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didOpenWithProtocol protocol: String?) {
        guard let ctx = context?.rawContext else { return }
        if let handle = connHandle {
            p2p_ws_on_connected_v2(ctx, handle)
        } else {
            p2p_ws_on_connected(ctx)
        }
        listenForMessages()
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        guard let ctx = context?.rawContext else { return }
        if let handle = connHandle {
            p2p_ws_on_disconnected_v2(ctx, handle)
        } else {
            p2p_ws_on_disconnected(ctx)
        }
    }

    // MARK: - Receive loop

    private func listenForMessages() {
        task?.receive { [weak self] result in
            guard let self, let ctx = self.context?.rawContext else { return }
            switch result {
            case .success(.data(let data)):
                data.withUnsafeBytes { ptr in
                    let raw = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    if let handle = self.connHandle {
                        p2p_ws_on_binary_v2(ctx, handle, raw, Int32(data.count))
                    } else {
                        p2p_ws_on_binary(ctx, raw, Int32(data.count))
                    }
                }
            case .success(.string(let text)):
                text.withCString { cstr in
                    if let handle = self.connHandle {
                        p2p_ws_on_text_v2(ctx, handle, cstr)
                    } else {
                        p2p_ws_on_text(ctx, cstr)
                    }
                }
            case .success:
                break
            case .failure:
                if let handle = self.connHandle, let ctx = self.context?.rawContext {
                    p2p_ws_on_disconnected_v2(ctx, handle)
                } else if let ctx = self.context?.rawContext {
                    p2p_ws_on_disconnected(ctx)
                }
                return // stop listening
            }
            self.listenForMessages() // continue receive loop
        }
    }
}

/// Pool of WebSocketAdapter instances keyed by a per-connection
/// OpaquePointer.  Backs the v2 multi-WS FFI: every
/// ws_alloc_connection allocates a fresh adapter and returns its
/// pointer; every ws_*_v2 looks it up; ws_free_connection drops it.
///
/// Adapters are owned by the pool's `connections` map (strong refs).
/// The OpaquePointer used as the key is the unmanaged-retain-from
/// reference, so it stays alive across the C boundary.  Free releases
/// the unmanaged reference, which causes the adapter to be dropped
/// when the pool's map removes its entry.
final class WebSocketPool {
    private weak var client: Peer2PearClient?
    private var connections: [UnsafeMutableRawPointer: WebSocketAdapter] = [:]

    init(client: Peer2PearClient) {
        self.client = client
    }

    func allocate() -> UnsafeMutableRawPointer? {
        guard let client = client else { return nil }
        let adapter = WebSocketAdapter(client: client)
        // Use the adapter's heap address as the handle.  Since we
        // store a strong reference in `connections` keyed by the same
        // pointer, the adapter outlives every C call until free().
        let handle = Unmanaged.passUnretained(adapter).toOpaque()
        adapter.connHandle = handle
        connections[handle] = adapter
        return handle
    }

    func free(_ handle: UnsafeMutableRawPointer) {
        guard let adapter = connections[handle] else { return }
        adapter.close()
        connections.removeValue(forKey: handle)
        // Strong ref count drops to zero here; adapter is deallocated.
    }

    func find(_ handle: UnsafeMutableRawPointer) -> WebSocketAdapter? {
        return connections[handle]
    }

    /// Drop every connection.  Called on Peer2PearClient teardown to
    /// release URL sessions promptly without waiting for ARC.
    func reset() {
        for (_, adapter) in connections {
            adapter.close()
        }
        connections.removeAll()
    }
}
