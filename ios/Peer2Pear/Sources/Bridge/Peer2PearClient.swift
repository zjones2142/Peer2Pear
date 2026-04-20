import Foundation
import Combine

/// Message received from a peer.
struct P2PMessage: Identifiable {
    let id: String       // msgId
    let from: String     // peer ID (base64url)
    let text: String
    let timestamp: Date
}

/// High-level Swift wrapper around the peer2pear C API.
/// Owns the p2p_context and bridges C callbacks → Combine publishers.
final class Peer2PearClient: ObservableObject {
    // MARK: - Published state (drives SwiftUI)

    @Published var isConnected = false
    @Published var myPeerId: String = ""
    @Published var messages: [P2PMessage] = []
    @Published var statusMessage: String = ""

    // MARK: - Internal

    /// Raw C context pointer — accessed by platform adapters
    private(set) var rawContext: OpaquePointer?

    private var ws: WebSocketAdapter!
    private var http: HttpAdapter!

    // MARK: - Lifecycle

    init() {
        ws = WebSocketAdapter(client: self)
        http = HttpAdapter(client: self)
    }

    /// Initialize the protocol engine with a data directory and passphrase.
    func start(dataDir: String, passphrase: String, relayUrl: String) {
        guard rawContext == nil else { return }

        // Build the platform callbacks struct
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        var platform = p2p_platform()
        platform.platform_ctx = selfPtr

        // WebSocket callbacks
        platform.ws_open = { urlCStr, ctx in
            guard let client = Peer2PearClient.from(ctx), let urlCStr,
                  let url = URL(string: String(cString: urlCStr)) else { return }
            client.ws.open(url: url)
        }
        platform.ws_close = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return }
            client.ws.close()
        }
        platform.ws_send_text = { msgCStr, ctx in
            guard let client = Peer2PearClient.from(ctx), let msgCStr else { return }
            client.ws.sendText(String(cString: msgCStr))
        }
        platform.ws_is_connected = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return 0 }
            return client.ws.isConnected ? 1 : 0
        }
        platform.ws_is_idle = { ctx in
            guard let client = Peer2PearClient.from(ctx) else { return 1 }
            return client.ws.isIdle ? 1 : 0
        }

        // HTTP callback
        platform.http_post = { urlCStr, body, bodyLen, hKeys, hVals, hCount, ctx in
            guard let client = Peer2PearClient.from(ctx), let urlCStr,
                  let url = URL(string: String(cString: urlCStr)) else { return -1 }
            let data = body != nil ? Data(bytes: body!, count: Int(bodyLen)) : Data()
            var headers: [(String, String)] = []
            for i in 0..<Int(hCount) {
                if let k = hKeys?[i], let v = hVals?[i] {
                    headers.append((String(cString: k), String(cString: v)))
                }
            }
            return client.http.post(url: url, body: data, headers: headers)
        }

        // Create core context
        rawContext = p2p_create(dataDir, platform)
        guard rawContext != nil else {
            statusMessage = "Failed to create Peer2Pear context"
            return
        }

        // Set event callbacks
        setupCallbacks()

        // Initialize identity (v5 unified Argon2id path — H4 fix).
        let rc = p2p_set_passphrase_v2(rawContext, passphrase)
        if rc != 0 {
            statusMessage = "Identity unlock failed (wrong passphrase?)"
            p2p_destroy(rawContext)
            rawContext = nil
            return
        }
        myPeerId = String(cString: p2p_my_id(rawContext))
        p2p_set_relay_url(rawContext, relayUrl)
        p2p_connect(rawContext)
    }

    func stop() {
        if let ctx = rawContext {
            p2p_destroy(ctx)
            rawContext = nil
        }
        isConnected = false
    }

    deinit { stop() }

    // MARK: - Actions

    func sendText(to peerId: String, text: String) {
        guard let ctx = rawContext else { return }
        p2p_send_text(ctx, peerId, text)
    }

    func setPrivacyLevel(_ level: Int) {
        guard let ctx = rawContext else { return }
        p2p_set_privacy_level(ctx, Int32(level))
    }

    // MARK: - Callback wiring

    private func setupCallbacks() {
        guard let ctx = rawContext else { return }
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()

        p2p_set_on_connected(ctx, { ud in
            guard let client = Peer2PearClient.from(ud) else { return }
            DispatchQueue.main.async { client.isConnected = true }
        }, selfPtr)

        p2p_set_on_status(ctx, { msg, ud in
            guard let client = Peer2PearClient.from(ud), let msg else { return }
            let str = String(cString: msg)
            DispatchQueue.main.async { client.statusMessage = str }
        }, selfPtr)

        p2p_set_on_message(ctx, { from, text, ts, msgId, ud in
            guard let client = Peer2PearClient.from(ud),
                  let from, let text, let msgId else { return }
            let msg = P2PMessage(
                id: String(cString: msgId),
                from: String(cString: from),
                text: String(cString: text),
                timestamp: Date(timeIntervalSince1970: TimeInterval(ts))
            )
            DispatchQueue.main.async { client.messages.append(msg) }
        }, selfPtr)

        p2p_set_on_presence(ctx, { peerId, online, ud in
            // TODO: update presence state
        }, selfPtr)
    }

    // MARK: - Helpers

    private static func from(_ ptr: UnsafeMutableRawPointer?) -> Peer2PearClient? {
        guard let ptr else { return nil }
        return Unmanaged<Peer2PearClient>.fromOpaque(ptr).takeUnretainedValue()
    }
}
