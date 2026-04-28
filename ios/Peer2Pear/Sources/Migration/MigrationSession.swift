import Foundation
import Network

// Device-to-device migration transport.  Pure LAN TCP via
// Network.framework — `NWListener` on the receiver, `NWConnection`
// on the sender.  Replaces the previous MultipeerConnectivity
// transport; same wire format on the socket as the desktop
// implementation so cross-platform pairs (iOS↔desktop in either
// direction, plus future Android) work over a single uniform
// protocol.  See project_backup_strategy.md "Cross-platform
// requirement / Transport decision (2026-04-28)" for the design
// trade-offs vs. MPC + relay alternatives.
//
// Two roles, both observable from SwiftUI via @Published `phase`:
//
//   * MigrationReceiveSession — new device, generates keypairs,
//     opens an `NWListener` on an OS-picked TCP port, picks the
//     primary RFC1918 IPv4, embeds both into a v2 handshake
//     (`addr` + `port`) the QR/paste exposes.  Accepts the first
//     incoming connection (rejects strays so a network scanner
//     can't disrupt an in-flight transfer), sends pubkeys,
//     receives envelope, decrypts, surfaces decrypted payload to
//     the caller for application.
//
//   * MigrationSendSession — old device, takes a parsed
//     MigrationHandshake (from QR scan / paste — both routes call
//     MigrationHandshake.decode), opens an `NWConnection` to the
//     handshake's `addr:port`, receives pubkeys, recomputes
//     SHA-256(pubkeys) constant-time-equals `handshake.fingerprint`
//     (catches a MITM redirecting the QR code's address), seals
//     the caller's payload, sends.
//
// Wire format on the socket: `[1 byte tag][4 byte BE length][body]`.
//   0x01 PubkeysOffer (JSON-encoded {x25519Pub, mlkemPub})
//   0x02 Envelope     (raw bytes from MigrationCryptoBridge.seal)
//
// Both classes are NOT @MainActor — `NWListener` / `NWConnection`
// callbacks fire on the queue we hand them; @Published mutations
// explicitly DispatchQueue.main.async around to keep SwiftUI
// reads on the main actor.

// MARK: - Wire framing

private enum WireMessageTag: UInt8 {
    case pubkeysOffer = 0x01
    case envelope     = 0x02
}

private struct PubkeysOffer: Codable {
    let x25519Pub: Data   // 32 bytes
    let mlkemPub:  Data   // 1184 bytes
}

/// Frame body cap (256 MB) — bounds memory for a malicious peer
/// that announces a multi-GB length on the wire.  Real-world
/// payloads (identity + salt + DB snapshot + saved files) cap
/// around 100 MB; 256 MB leaves headroom.  Matches the desktop
/// implementation's bound so neither end is the weakest link.
private let kMaxFrameBody: UInt32 = 256 * 1024 * 1024

private func framed(_ tag: WireMessageTag, _ body: Data) -> Data {
    let len = UInt32(body.count)
    var out = Data(capacity: 1 + 4 + body.count)
    out.append(tag.rawValue)
    out.append(UInt8((len >> 24) & 0xff))
    out.append(UInt8((len >> 16) & 0xff))
    out.append(UInt8((len >>  8) & 0xff))
    out.append(UInt8((len      ) & 0xff))
    out.append(body)
    return out
}

// MARK: - LAN IPv4 picker

/// True if `ip` is in one of the RFC1918 private ranges
/// (10/8, 172.16/12, 192.168/16).  Operates on the numeric IPv4
/// value rather than string prefixes — `"172.2"` would falsely
/// include 172.2.x.x and 172.250.x.x.  Mirrors the desktop
/// `migrationreceivedialog.cpp::isRFC1918`.
private func isRFC1918(_ a: UInt8, _ b: UInt8) -> Bool {
    if a == 10 { return true }                                  // 10.0.0.0/8
    if a == 192 && b == 168 { return true }                     // 192.168.0.0/16
    if a == 172 && (16...31).contains(b) { return true }        // 172.16.0.0/12
    return false
}

/// Walk every active non-loopback interface, pick the most-
/// likely-routable IPv4 address.  RFC1918 wins; public IPv4
/// only used as last resort (and a v2 handshake QR should
/// never be carrying a public IP across the internet — the
/// design is same-LAN).  Returns nil if no usable address.
private func pickLanIPv4() -> String? {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0 else { return nil }
    defer { freeifaddrs(ifaddr) }

    var publicCandidate: String?
    var ptr = ifaddr
    while let cur = ptr {
        defer { ptr = cur.pointee.ifa_next }
        let p = cur.pointee
        guard let sa = p.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else {
            continue
        }
        // Filter by ifa_flags — must be UP + RUNNING + not LOOPBACK.
        let flags = Int32(p.ifa_flags)
        if (flags & IFF_UP) == 0 || (flags & IFF_RUNNING) == 0 { continue }
        if (flags & IFF_LOOPBACK) != 0 { continue }

        var addrBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = getnameinfo(sa, socklen_t(sa.pointee.sa_len),
                              &addrBuf, socklen_t(addrBuf.count),
                              nil, 0, NI_NUMERICHOST)
        guard rc == 0 else { continue }
        let s = String(cString: addrBuf)

        // Skip link-local (169.254.x.x) — auto-assigned when no
        // DHCP, useless for cross-device pairing.
        if s.hasPrefix("169.254.") { continue }

        // Parse the four octets to test RFC1918 cleanly.
        let parts = s.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { continue }
        if isRFC1918(parts[0], parts[1]) {
            return s
        }
        if publicCandidate == nil {
            publicCandidate = s
        }
    }
    return publicCandidate
}

// MARK: - Frame reader

/// Buffered TCP reader that parses `[1 tag][4 BE length][body]`
/// frames out of a stream of `Data` chunks.  TCP delivers bytes,
/// not message boundaries, so callers feed bytes via `append`
/// and pull complete frames via `nextFrame`.
private final class FrameReader {
    private var buf = Data()

    func append(_ chunk: Data) { buf.append(chunk) }

    enum FrameError: Error {
        case oversized            // body length exceeds kMaxFrameBody
        case unknownTag(UInt8)
    }

    /// Try to consume a complete frame.  Returns nil if the
    /// buffer doesn't yet hold a full frame (caller should keep
    /// reading from the socket); throws on protocol errors.
    func nextFrame() throws -> (tag: WireMessageTag, body: Data)? {
        if buf.count < 5 { return nil }
        let tagByte = buf[0]
        let len = (UInt32(buf[1]) << 24)
                | (UInt32(buf[2]) << 16)
                | (UInt32(buf[3]) <<  8)
                |  UInt32(buf[4])
        if len > kMaxFrameBody { throw FrameError.oversized }
        if buf.count < 5 + Int(len) { return nil }
        guard let tag = WireMessageTag(rawValue: tagByte) else {
            throw FrameError.unknownTag(tagByte)
        }
        let body = buf.subdata(in: 5..<(5 + Int(len)))
        buf.removeSubrange(0..<(5 + Int(len)))
        return (tag, body)
    }
}

// MARK: - Receive session (new device)

final class MigrationReceiveSession: ObservableObject {

    enum Phase: Equatable {
        case idle                       // not started yet
        case advertising                // QR / paste-string visible, awaiting connect
        case paired                     // sender connected, sent pubkeys, awaiting envelope
        case applying                   // envelope decrypted, caller is now applying
        case success                    // payload delivered to caller successfully
        case error(String)              // anything went wrong, message for UI
    }

    @Published private(set) var phase: Phase = .idle

    /// Handshake the UI renders as a QR + displays as paste-able
    /// text.  Initially v1 (fingerprint + nonce only); start()
    /// upgrades to v2 (adds addr + port) once the listener is
    /// .ready.  The view watches phase — only renders the QR
    /// after .advertising — so the user never sees the v1
    /// placeholder.
    private(set) var handshake: MigrationHandshake

    /// Decrypted payload.  Only populated when phase moves to
    /// .applying / .success — UI/caller picks it up + applies.
    @Published private(set) var receivedPayload: Data?

    private let keypairs: MigrationKeypairs
    private let queue = DispatchQueue(label: "p2p.migration.receive")
    private var listener: NWListener?
    private var activeConnection: NWConnection?
    private let reader = FrameReader()

    /// Designated initializer.  Synchronous, populates the v1
    /// handshake from the keypair fingerprint + a fresh nonce.
    /// addr/port are filled in by start() once the listener is
    /// .ready.
    private init(keypairs: MigrationKeypairs,
                  handshake: MigrationHandshake)
    {
        self.keypairs  = keypairs
        self.handshake = handshake
    }

    /// Factory — returns nil if the C-side keypair generation
    /// fails (libsodium / liboqs error).  UI surfaces that as
    /// "couldn't prepare migration; restart and try again."
    static func make() -> MigrationReceiveSession? {
        guard let keys = MigrationCryptoBridge.generateKeypairs() else {
            return nil
        }
        guard let fp = MigrationCryptoBridge.fingerprint(
                x25519Pub: keys.x25519Pub,
                mlkemPub:  keys.mlkemPub) else {
            return nil
        }
        return MigrationReceiveSession(
            keypairs: keys,
            handshake: MigrationHandshake.make(fingerprint: fp))
    }

    /// Begin advertising on TCP.  Caller observes phase until it
    /// transitions to .advertising — at that point handshake has
    /// addr+port set and the view renders the QR.
    func start() {
        guard phase == .idle else { return }
        do {
            // OS picks an ephemeral port via `.any`.  We capture
            // the actual value once .stateUpdateHandler fires
            // .ready below.
            let l = try NWListener(using: .tcp)
            l.newConnectionHandler = { [weak self] conn in
                self?.acceptConnection(conn)
            }
            l.stateUpdateHandler = { [weak self] state in
                self?.onListenerStateChanged(state)
            }
            l.start(queue: queue)
            self.listener = l
        } catch {
            fail("Couldn't start migration listener: \(error.localizedDescription)")
        }
    }

    /// Cancel mid-flight.  Tears down the listener + any active
    /// connection.  UI pops the migration sheet on completion.
    func cancel() {
        listener?.cancel()
        listener = nil
        activeConnection?.cancel()
        activeConnection = nil
        DispatchQueue.main.async { [weak self] in
            // Don't overwrite a terminal state with .idle —
            // success / error stays so the UI can show the outcome.
            switch self?.phase {
            case .success, .error: break
            default:               self?.phase = .idle
            }
        }
    }

    // MARK: Listener state

    private func onListenerStateChanged(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener?.port?.rawValue else {
                fail("Listener reported ready without a port — internal error.")
                return
            }
            // pickLanIPv4 falls back to nil if no interface is up.
            // Surface that as an error rather than emitting a
            // useless v1 handshake the sender can't connect to.
            guard let addr = pickLanIPv4() else {
                fail("Couldn't find a LAN IP address for this device.  " +
                     "Connect to a Wi-Fi network and try again.")
                return
            }
            // Re-build the handshake with addr+port.  Same
            // fingerprint/nonce, just bumped to v2.
            self.handshake = MigrationHandshake(
                version:     2,
                fingerprint: self.handshake.fingerprint,
                nonce:       self.handshake.nonce,
                addr:        addr,
                port:        Int(port))
            DispatchQueue.main.async { [weak self] in
                self?.phase = .advertising
            }

        case .failed(let error):
            // Most likely cause: NSLocalNetworkUsageDescription
            // permission denied.  Surface honestly so the user
            // can re-enable it in Settings → Privacy & Security
            // → Local Network → Peer2Pear.
            fail("Couldn't start the migration listener (\(error)).  " +
                 "Check Settings → Privacy & Security → Local Network " +
                 "and make sure Peer2Pear is allowed.")

        default: break
        }
    }

    // MARK: Connection lifecycle

    private func acceptConnection(_ conn: NWConnection) {
        // Reject stray second-and-later connections — only one
        // migration session at a time.  A scanner / browser
        // hitting the listener mid-flow doesn't get to disrupt
        // the in-flight transfer.
        if activeConnection != nil {
            conn.cancel()
            return
        }
        self.activeConnection = conn
        conn.stateUpdateHandler = { [weak self] state in
            self?.onConnectionStateChanged(state)
        }
        conn.start(queue: queue)
    }

    private func onConnectionStateChanged(_ state: NWConnection.State) {
        switch state {
        case .ready:
            sendPubkeysOffer()
            scheduleRead()
        case .failed(let error):
            fail("Migration connection failed: \(error.localizedDescription)")
        case .cancelled:
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch self.phase {
                case .applying, .success, .error: break
                default: self.phase = .error("Other device disconnected before transfer completed.")
                }
            }
        default: break
        }
    }

    private func sendPubkeysOffer() {
        let offer = PubkeysOffer(x25519Pub: keypairs.x25519Pub,
                                  mlkemPub:  keypairs.mlkemPub)
        guard let body = try? JSONEncoder().encode(offer) else {
            fail("Couldn't encode pubkeys offer."); return
        }
        let frame = framed(.pubkeysOffer, body)
        activeConnection?.send(content: frame,
                                completion: .contentProcessed { [weak self] error in
            if let error {
                self?.fail("Couldn't send pubkeys: \(error.localizedDescription)")
                return
            }
            DispatchQueue.main.async { [weak self] in
                self?.phase = .paired
            }
        })
    }

    private func scheduleRead() {
        activeConnection?.receive(minimumIncompleteLength: 1,
                                    maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                self.fail("Read error: \(error.localizedDescription)")
                return
            }
            if let data, !data.isEmpty {
                self.reader.append(data)
                do {
                    while let frame = try self.reader.nextFrame() {
                        self.handleFrame(tag: frame.tag, body: frame.body)
                    }
                } catch {
                    self.fail("Malformed frame from sender: \(error).")
                    return
                }
            }
            if isComplete {
                // Sender closed the connection — fine if envelope
                // already arrived, otherwise surface as error.
                return
            }
            self.scheduleRead()
        }
    }

    private func handleFrame(tag: WireMessageTag, body: Data) {
        switch tag {
        case .envelope:
            openEnvelope(body)
        case .pubkeysOffer:
            // Receiver shouldn't see this — it's the message we
            // SEND, not receive.  Bug or attempted attack.
            fail("Unexpected pubkeys offer from other device.")
        }
    }

    private func openEnvelope(_ envelope: Data) {
        guard let plaintext = MigrationCryptoBridge.open(
                envelope:           envelope,
                receiverX25519Pub:  keypairs.x25519Pub,
                receiverX25519Priv: keypairs.x25519Priv,
                receiverMlkemPub:   keypairs.mlkemPub,
                receiverMlkemPriv:  keypairs.mlkemPriv,
                handshakeNonce:     handshake.nonce) else {
            fail("Couldn't decrypt the migration data — " +
                 "wrong setup or tampered transfer.")
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.receivedPayload = plaintext
            self?.phase           = .applying
        }
    }

    private func fail(_ message: String) {
        listener?.cancel()
        listener = nil
        activeConnection?.cancel()
        activeConnection = nil
        DispatchQueue.main.async { [weak self] in
            self?.phase = .error(message)
        }
    }
}

// MARK: - Send session (old device, unlocked, has identity)

final class MigrationSendSession: ObservableObject {

    enum Phase: Equatable {
        case idle                       // not started yet
        case browsing                   // dialed, awaiting connect
        case connecting                 // ↑ alias retained for UI back-compat
        case verifying                  // connected, awaiting pubkeys offer
        case sending                    // fingerprint verified, shipping envelope
        case success                    // envelope acknowledged
        case error(String)
    }

    @Published private(set) var phase: Phase = .idle

    private let handshake: MigrationHandshake
    private let payload: Data
    private let queue = DispatchQueue(label: "p2p.migration.send")
    private var connection: NWConnection?
    private let reader = FrameReader()
    private var didSendEnvelope = false

    /// Construct with the parsed handshake (from QR scan or manual
    /// paste — both routes call MigrationHandshake.decode and yield
    /// the same struct) and the payload to ship (typically a
    /// JSON-encoded MigrationPayload).
    init(handshake: MigrationHandshake, payload: Data) {
        self.handshake = handshake
        self.payload   = payload
    }

    func start() {
        guard phase == .idle else { return }
        // v1 handshakes don't carry addr/port — the receiver is on
        // an older Peer2Pear build that hasn't migrated to the LAN
        // TCP transport.  Refuse honestly rather than guessing.
        guard let addr = handshake.addr,
              let portInt = handshake.port,
              let port = NWEndpoint.Port(rawValue: UInt16(portInt)) else {
            fail("The other device's pairing code doesn't include " +
                 "connection details.  Both devices need to be on the " +
                 "latest version of Peer2Pear.")
            return
        }
        let host = NWEndpoint.Host(addr)
        let conn = NWConnection(host: host, port: port, using: .tcp)
        conn.stateUpdateHandler = { [weak self] state in
            self?.onConnectionStateChanged(state)
        }
        conn.start(queue: queue)
        self.connection = conn

        DispatchQueue.main.async { [weak self] in
            self?.phase = .browsing   // "dialing"; renamed in spirit, kept for view back-compat
        }
    }

    func cancel() {
        connection?.cancel()
        connection = nil
        DispatchQueue.main.async { [weak self] in
            switch self?.phase {
            case .success, .error: break
            default:               self?.phase = .idle
            }
        }
    }

    // MARK: Connection lifecycle

    private func onConnectionStateChanged(_ state: NWConnection.State) {
        switch state {
        case .ready:
            DispatchQueue.main.async { [weak self] in
                self?.phase = .verifying
            }
            scheduleRead()
        case .failed(let error):
            fail("Couldn't connect to the new device: \(error.localizedDescription).  " +
                 "Make sure both devices are on the same Wi-Fi or LAN.")
        case .cancelled:
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch self.phase {
                case .success, .error: break
                default: self.phase = .error("Disconnected before transfer completed.")
                }
            }
        default: break
        }
    }

    private func scheduleRead() {
        connection?.receive(minimumIncompleteLength: 1,
                              maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                self.fail("Read error: \(error.localizedDescription)")
                return
            }
            if let data, !data.isEmpty {
                self.reader.append(data)
                do {
                    while let frame = try self.reader.nextFrame() {
                        self.handleFrame(tag: frame.tag, body: frame.body)
                    }
                } catch {
                    self.fail("Malformed frame from receiver: \(error).")
                    return
                }
            }
            if isComplete { return }
            self.scheduleRead()
        }
    }

    private func handleFrame(tag: WireMessageTag, body: Data) {
        switch tag {
        case .pubkeysOffer:
            do {
                let offer = try JSONDecoder().decode(PubkeysOffer.self, from: body)
                verifyAndSend(offer: offer)
            } catch {
                fail("Other device sent unparseable pubkeys: \(error.localizedDescription)")
            }
        case .envelope:
            // Sender shouldn't see this — that's the message it
            // sends, not receives.
            fail("Unexpected envelope from other device.")
        }
    }

    private func verifyAndSend(offer: PubkeysOffer) {
        guard let recomputed = MigrationCryptoBridge.fingerprint(
                x25519Pub: offer.x25519Pub,
                mlkemPub:  offer.mlkemPub) else {
            fail("Couldn't compute fingerprint from received keys.")
            return
        }
        guard recomputed == handshake.fingerprint else {
            fail("Verification failed — the other device sent " +
                 "different keys than the QR / pasted handshake described.  " +
                 "Possible MITM; aborting.")
            return
        }
        guard let envelope = MigrationCryptoBridge.seal(
                payload:           payload,
                receiverX25519Pub: offer.x25519Pub,
                receiverMlkemPub:  offer.mlkemPub,
                handshakeNonce:    handshake.nonce) else {
            fail("Couldn't encrypt migration data.")
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.phase = .sending
        }
        let frame = framed(.envelope, envelope)
        didSendEnvelope = true
        connection?.send(content: frame,
                          completion: .contentProcessed { [weak self] error in
            if let error {
                self?.fail("Couldn't send envelope: \(error.localizedDescription)")
                return
            }
            DispatchQueue.main.async { [weak self] in
                self?.phase = .success
            }
        })
    }

    private func fail(_ message: String) {
        connection?.cancel()
        DispatchQueue.main.async { [weak self] in
            self?.phase = .error(message)
        }
    }
}
