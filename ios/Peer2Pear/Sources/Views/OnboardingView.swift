import SwiftUI

struct OnboardingView: View {
    @ObservedObject var client: Peer2PearClient
    @State private var displayName = ""
    @State private var passphrase = ""
    @State private var relayUrl = "https://relay.peer2pear.org:8443"

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
