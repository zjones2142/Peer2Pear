import Foundation

/// iOS WebSocket implementation using URLSessionWebSocketTask.
/// Provides the ws_* callbacks for p2p_platform.
///
/// The C core calls ws_open/ws_close/ws_send_text/ws_is_connected/ws_is_idle
/// via function pointers. This class handles those calls and routes events
/// back to the core via p2p_ws_on_connected/disconnected/binary/text.
final class WebSocketAdapter: NSObject, URLSessionWebSocketDelegate {
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private weak var context: Peer2PearClient?

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
        p2p_ws_on_connected(ctx)
        listenForMessages()
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        guard let ctx = context?.rawContext else { return }
        p2p_ws_on_disconnected(ctx)
    }

    // MARK: - Receive loop

    private func listenForMessages() {
        task?.receive { [weak self] result in
            guard let self, let ctx = self.context?.rawContext else { return }
            switch result {
            case .success(.data(let data)):
                data.withUnsafeBytes { ptr in
                    p2p_ws_on_binary(ctx, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                     Int32(data.count))
                }
            case .success(.string(let text)):
                text.withCString { cstr in
                    p2p_ws_on_text(ctx, cstr)
                }
            case .success:
                break
            case .failure:
                p2p_ws_on_disconnected(ctx)
                return // stop listening
            }
            self.listenForMessages() // continue receive loop
        }
    }
}
