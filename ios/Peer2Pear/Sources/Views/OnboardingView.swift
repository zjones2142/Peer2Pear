import SwiftUI

// Key used to persist the last-entered relay URL across launches.
// UserDefaults survives app launches and passcode unlock but is wiped
// on uninstall (iOS sandbox).  Cross-reinstall persistence would need
// iCloud Keychain or NSUbiquitousKeyValueStore, which adds an iCloud
// entitlement and user-dependent sync behaviour — not worth it for a
// URL the user typed once.
private let kDefaultsRelayUrlKey = "p2p.lastRelayUrl"
private let kDefaultRelayUrl = "https://relay.peer2pear.org:8443"

struct OnboardingView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var displayName = ""
    @State private var passphrase = ""
    @State private var relayUrl =
        UserDefaults.standard.string(forKey: kDefaultsRelayUrlKey)
        ?? kDefaultRelayUrl

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()

                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.green)

                Text("Peer2Pear")
                    .font(.largeTitle.bold())

                Text("Private messaging.\nNo phone number. No servers you don't control.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                VStack(spacing: 16) {
                    TextField("Display name", text: $displayName)
                        .textFieldStyle(.roundedBorder)

                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(.roundedBorder)

                    TextField("Relay URL", text: $relayUrl)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .keyboardType(.URL)
                }
                .padding(.horizontal, 32)

                Button("Get Started") {
                    let dataDir = FileManager.default
                        .urls(for: .documentDirectory, in: .userDomainMask)[0].path
                    // Remember what the user typed so subsequent
                    // first-runs (after logout / identity reset) do not
                    // have to re-enter the relay URL.
                    UserDefaults.standard.set(relayUrl, forKey: kDefaultsRelayUrlKey)
                    client.start(dataDir: dataDir, passphrase: passphrase, relayUrl: relayUrl)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(passphrase.isEmpty)

                Spacer()
            }
            .padding()
        }
    }
}
