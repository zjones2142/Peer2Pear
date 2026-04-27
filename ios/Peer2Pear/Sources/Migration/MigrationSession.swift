import Foundation
import MultipeerConnectivity

// Device-to-device migration transport.  MultipeerConnectivity is
// the right primitive for "two phones near each other" — Apple
// handles peer discovery (Bluetooth + AWDL + Wi-Fi), connection
// setup, and TLS-protected transit; we layer our own AEAD on top
// so plaintext never touches the MPC layer in case of bugs there.
//
// Two roles, both observable from SwiftUI via @Published `phase`:
//
//   * MigrationReceiveSession — new device, generates keypairs,
//     advertises on Bonjour with the fingerprint hex in
//     discoveryInfo (so multiple migration pairs on the same LAN
//     don't collide).  Accepts incoming invitations, sends
//     pubkeys, receives envelope, decrypts, surfaces decrypted
//     payload to the caller for application.
//
//   * MigrationSendSession — old device, takes a scanned-or-
//     pasted MigrationHandshake, browses, filters for the peer
//     whose advertised fingerprint matches.  After MPC connects,
//     receives pubkeys, verifies SHA-256(received) matches
//     handshake.fingerprint (catches a MITM that forged
//     discoveryInfo), seals the caller's payload, sends.
//
// Wire format over MPC: 1-byte type tag + payload.
//   0x01 PubkeysOffer (JSON-encoded {x25519Pub, mlkemPub})
//   0x02 Envelope     (raw bytes from MigrationCryptoBridge.seal)
//
// Both classes are NOT @MainActor — MCSession delegates fire on a
// session-private background queue + we explicitly DispatchQueue
// .main.async around @Published mutations.  Mixing @MainActor
// with framework callbacks that don't await is a recipe for
// subtle reentrancy bugs.

/// Bonjour service name.  MUST match the strings listed in
/// Info.plist's NSBonjourServices (project.yml builds them).
/// Bonjour limits service names to 15 chars + lowercase + dashes;
/// "p2p-migration" is 13.
let kMigrationServiceType = "p2p-migration"

private enum MpcMessageTag: UInt8 {
    case pubkeysOffer = 0x01
    case envelope     = 0x02
}

private struct PubkeysOffer: Codable {
    let x25519Pub: Data   // 32 bytes
    let mlkemPub:  Data   // 1184 bytes
}

// MARK: - Helpers

private extension Data {
    /// Lowercase hex-encoded representation.  Used for
    /// MPC discoveryInfo + safety-comparison logging.
    func hexEncoded() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private func tagged(_ tag: MpcMessageTag, _ body: Data) -> Data {
    var out = Data(count: 1 + body.count)
    out[0] = tag.rawValue
    out.replaceSubrange(1..<(1 + body.count), with: body)
    return out
}

private func untag(_ msg: Data) -> (MpcMessageTag, Data)? {
    guard let firstByte = msg.first,
          let tag = MpcMessageTag(rawValue: firstByte) else { return nil }
    return (tag, msg.dropFirst())
}

// MARK: - Receive session (new device)

final class MigrationReceiveSession: NSObject, ObservableObject {

    enum Phase: Equatable {
        case idle                       // not started yet
        case advertising                // QR / paste-string visible, awaiting invite
        case paired                     // MPC connected, sent pubkeys, awaiting envelope
        case applying                   // envelope decrypted, caller is now applying
        case success                    // payload delivered to caller successfully
        case error(String)              // anything went wrong, message for UI
    }

    @Published private(set) var phase: Phase = .idle

    /// Handshake the UI should render as a QR + display as
    /// paste-able text (`handshake.encodeForQR()`).
    let handshake: MigrationHandshake

    /// Decrypted payload.  Only populated when phase moves to
    /// .applying / .success — UI/caller picks it up + applies.
    @Published private(set) var receivedPayload: Data?

    private let keypairs: MigrationKeypairs
    private let peerID: MCPeerID
    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?

    /// Designated initializer — private, always populated by
    /// `make()`.  NSObject's init() is non-failable so we route
    /// the "C-side keypair generation failed" case through a
    /// static factory instead.
    private init(keypairs: MigrationKeypairs,
                  handshake: MigrationHandshake)
    {
        self.keypairs  = keypairs
        self.handshake = handshake
        // MPC peer-ID display name is shown in some UI surfaces;
        // a generic "Peer2Pear" string keeps it neutral.  The
        // routing happens via discoveryInfo + advertiser service
        // name, not the display name.
        self.peerID = MCPeerID(displayName: "Peer2Pear")
        super.init()
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

    /// Begin advertising on MPC.  Caller renders `handshake` as
    /// a QR + paste-string in the UI and waits for `phase` to
    /// transition to .applying.
    func start() {
        guard phase == .idle else { return }

        let s = MCSession(peer: peerID,
                          securityIdentity: nil,
                          encryptionPreference: .required)
        s.delegate = self
        self.session = s

        // discoveryInfo carries the fingerprint hex so the
        // sender's browser can filter matching peers without
        // inviting every Peer2Pear advertiser on the LAN.
        let info: [String: String] = [
            "fp": handshake.fingerprint.hexEncoded(),
            "v":  String(MigrationHandshake.currentVersion),
        ]
        let adv = MCNearbyServiceAdvertiser(peer: peerID,
                                             discoveryInfo: info,
                                             serviceType: kMigrationServiceType)
        adv.delegate = self
        adv.startAdvertisingPeer()
        self.advertiser = adv

        DispatchQueue.main.async { [weak self] in
            self?.phase = .advertising
        }
    }

    /// Cancel mid-flight.  Tears down MPC; UI should pop the
    /// migration sheet on completion of this call.
    func cancel() {
        advertiser?.stopAdvertisingPeer()
        advertiser = nil
        session?.disconnect()
        session = nil
        DispatchQueue.main.async { [weak self] in
            // Don't overwrite a terminal state with .idle —
            // success / error stays so the UI can show the
            // outcome.
            switch self?.phase {
            case .success, .error: break
            default:               self?.phase = .idle
            }
        }
    }

    // Send pubkeys to the just-connected sender.  Called from the
    // session-stateChanged delegate when the peer transitions to
    // .connected.
    private func sendPubkeysOffer(to peer: MCPeerID) {
        guard let s = session else { return }
        let offer = PubkeysOffer(x25519Pub: keypairs.x25519Pub,
                                  mlkemPub:  keypairs.mlkemPub)
        do {
            let body = try JSONEncoder().encode(offer)
            try s.send(tagged(.pubkeysOffer, body),
                       toPeers: [peer],
                       with: .reliable)
            DispatchQueue.main.async { [weak self] in
                self?.phase = .paired
            }
        } catch {
            fail("Couldn't send pubkeys to other device: \(error.localizedDescription)")
        }
    }

    // Decrypt a received envelope using own keypairs + the
    // handshake nonce we generated.  On success, surface the
    // payload via @Published so the caller (B.5 apply path) can
    // pick it up.
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
        advertiser?.stopAdvertisingPeer()
        session?.disconnect()
        DispatchQueue.main.async { [weak self] in
            self?.phase = .error(message)
        }
    }
}

// MARK: - Receive session — MPC delegates

extension MigrationReceiveSession: MCNearbyServiceAdvertiserDelegate {

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser,
                     didReceiveInvitationFromPeer peerID: MCPeerID,
                     withContext context: Data?,
                     invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        // Auto-accept — sender already filtered by our
        // advertised fingerprint.  Final security check happens
        // on the SENDER side post-pairing (re-hash received
        // pubkeys, compare to QR/paste fingerprint).
        invitationHandler(true, session)
    }

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser,
                     didNotStartAdvertisingPeer error: Error) {
        fail("Couldn't start migration advertiser: \(error.localizedDescription)")
    }
}

extension MigrationReceiveSession: MCSessionDelegate {

    func session(_ session: MCSession,
                  peer peerID: MCPeerID,
                  didChange state: MCSessionState) {
        switch state {
        case .connected:
            sendPubkeysOffer(to: peerID)
        case .notConnected:
            // If we hit notConnected before applying, the sender
            // disconnected unexpectedly — surface as error unless
            // we already finished.
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch self.phase {
                case .applying, .success, .error: break
                default:
                    self.phase = .error("Other device disconnected before transfer completed.")
                }
            }
        default: break
        }
    }

    func session(_ session: MCSession, didReceive data: Data,
                  fromPeer peerID: MCPeerID) {
        guard let (tag, body) = untag(data) else {
            fail("Received malformed migration message.")
            return
        }
        switch tag {
        case .envelope:
            openEnvelope(body)
        case .pubkeysOffer:
            // Receiver shouldn't see this — that's the message it
            // sends, not receives.  Bug or attempted attack;
            // either way, abort.
            fail("Unexpected pubkeys offer from other device.")
        }
    }

    // Streams + resources unused — we send everything as a single
    // .reliable Data chunk (the envelope is small enough; saved-
    // files trailer in B.6+ may switch to streams).
    func session(_ session: MCSession,
                  didReceive stream: InputStream,
                  withName streamName: String,
                  fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession,
                  didStartReceivingResourceWithName resourceName: String,
                  fromPeer peerID: MCPeerID,
                  with progress: Progress) {}
    func session(_ session: MCSession,
                  didFinishReceivingResourceWithName resourceName: String,
                  fromPeer peerID: MCPeerID,
                  at localURL: URL?,
                  withError error: Error?) {}
}

// MARK: - Send session (old device, unlocked, has identity)

final class MigrationSendSession: NSObject, ObservableObject {

    enum Phase: Equatable {
        case idle                       // not started yet
        case browsing                   // looking for the matching receiver
        case connecting                 // invited, waiting on connect
        case verifying                  // connected, awaiting pubkeys offer
        case sending                    // fingerprint verified, shipping envelope
        case success                    // envelope acknowledged at MPC layer
        case error(String)
    }

    @Published private(set) var phase: Phase = .idle

    private let handshake: MigrationHandshake
    private let payload: Data
    private let peerID: MCPeerID
    private var session: MCSession?
    private var browser: MCNearbyServiceBrowser?

    /// Construct with the parsed handshake (from QR scan or manual
    /// paste — both routes call MigrationHandshake.decode and yield
    /// the same struct) and the payload to ship (typically a
    /// JSON-encoded MigrationPayload).
    init(handshake: MigrationHandshake, payload: Data) {
        self.handshake = handshake
        self.payload   = payload
        self.peerID    = MCPeerID(displayName: "Peer2Pear")
        super.init()
    }

    func start() {
        guard phase == .idle else { return }

        let s = MCSession(peer: peerID,
                          securityIdentity: nil,
                          encryptionPreference: .required)
        s.delegate = self
        self.session = s

        let b = MCNearbyServiceBrowser(peer: peerID,
                                        serviceType: kMigrationServiceType)
        b.delegate = self
        b.startBrowsingForPeers()
        self.browser = b

        DispatchQueue.main.async { [weak self] in
            self?.phase = .browsing
        }
    }

    func cancel() {
        browser?.stopBrowsingForPeers()
        browser = nil
        session?.disconnect()
        session = nil
        DispatchQueue.main.async { [weak self] in
            switch self?.phase {
            case .success, .error: break
            default:               self?.phase = .idle
            }
        }
    }

    // After receiving the receiver's pubkeys, verify the
    // fingerprint matches what we have from the QR/paste, then
    // seal the payload and ship.
    private func verifyAndSend(offer: PubkeysOffer, to peer: MCPeerID) {
        // 1. Re-derive fingerprint from received pubkeys.
        guard let recomputed = MigrationCryptoBridge.fingerprint(
                x25519Pub: offer.x25519Pub,
                mlkemPub:  offer.mlkemPub) else {
            fail("Couldn't compute fingerprint from received keys.")
            return
        }

        // 2. Compare in constant-ish time (Data equality is
        //    typically constant-time on iOS, but this is a one-
        //    shot check on a 16-byte hash — even non-CT comparison
        //    leaks at most "match / no match" which is the signal
        //    we're going to surface anyway).
        guard recomputed == handshake.fingerprint else {
            fail("Verification failed — the other device sent " +
                 "different keys than the QR / pasted handshake described.  " +
                 "Possible MITM; aborting.")
            return
        }

        // 3. Seal payload + ship.
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

        do {
            try session?.send(tagged(.envelope, envelope),
                               toPeers: [peer],
                               with: .reliable)
            DispatchQueue.main.async { [weak self] in
                self?.phase = .success
            }
        } catch {
            fail("Couldn't send migration envelope: \(error.localizedDescription)")
        }
    }

    private func fail(_ message: String) {
        browser?.stopBrowsingForPeers()
        session?.disconnect()
        DispatchQueue.main.async { [weak self] in
            self?.phase = .error(message)
        }
    }
}

// MARK: - Send session — MPC delegates

extension MigrationSendSession: MCNearbyServiceBrowserDelegate {

    func browser(_ browser: MCNearbyServiceBrowser,
                  foundPeer peerID: MCPeerID,
                  withDiscoveryInfo info: [String: String]?) {
        // Filter by advertised fingerprint hex.  Same fingerprint
        // = same handshake = our intended receiver.  Mismatched
        // fingerprints from other migration pairs on the same LAN
        // are silently ignored.
        guard let advertisedFp = info?["fp"] else { return }
        let ourFp = handshake.fingerprint.hexEncoded()
        guard advertisedFp == ourFp else { return }

        // Only invite once — once we've moved past .browsing,
        // ignore further matching peers (could be a duplicate
        // from a re-advertising cycle).
        let shouldInvite: Bool = {
            switch phase {
            case .browsing: return true
            default:        return false
            }
        }()
        guard shouldInvite, let s = session else { return }

        DispatchQueue.main.async { [weak self] in
            self?.phase = .connecting
        }
        // 30s timeout — generous for slow Bluetooth pair-ups
        // before falling back to AWDL.
        browser.invitePeer(peerID, to: s, withContext: nil, timeout: 30)
    }

    func browser(_ browser: MCNearbyServiceBrowser,
                  lostPeer peerID: MCPeerID) {
        // The peer's advertiser stopped — fine, harmless.  Don't
        // surface as error unless we were already mid-handshake
        // with this specific peer.
    }

    func browser(_ browser: MCNearbyServiceBrowser,
                  didNotStartBrowsingForPeers error: Error) {
        fail("Couldn't start migration browser: \(error.localizedDescription)")
    }
}

extension MigrationSendSession: MCSessionDelegate {

    func session(_ session: MCSession,
                  peer peerID: MCPeerID,
                  didChange state: MCSessionState) {
        switch state {
        case .connected:
            DispatchQueue.main.async { [weak self] in
                self?.phase = .verifying
            }
        case .notConnected:
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch self.phase {
                case .success, .error: break
                default:
                    self.phase = .error("Other device disconnected before transfer completed.")
                }
            }
        default: break
        }
    }

    func session(_ session: MCSession, didReceive data: Data,
                  fromPeer peerID: MCPeerID) {
        guard let (tag, body) = untag(data) else {
            fail("Received malformed migration message.")
            return
        }
        switch tag {
        case .pubkeysOffer:
            do {
                let offer = try JSONDecoder().decode(PubkeysOffer.self, from: body)
                verifyAndSend(offer: offer, to: peerID)
            } catch {
                fail("Other device sent unparseable pubkeys: \(error.localizedDescription)")
            }
        case .envelope:
            // Sender shouldn't see this — that's the message it
            // sends, not receives.  Bug or attempted attack.
            fail("Unexpected envelope from other device.")
        }
    }

    func session(_ session: MCSession,
                  didReceive stream: InputStream,
                  withName streamName: String,
                  fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession,
                  didStartReceivingResourceWithName resourceName: String,
                  fromPeer peerID: MCPeerID,
                  with progress: Progress) {}
    func session(_ session: MCSession,
                  didFinishReceivingResourceWithName resourceName: String,
                  fromPeer peerID: MCPeerID,
                  at localURL: URL?,
                  withError error: Error?) {}
}
