import SwiftUI

@main
struct Peer2PearApp: App {
    @StateObject private var client = Peer2PearClient()

    var body: some Scene {
        WindowGroup {
            if client.myPeerId.isEmpty {
                OnboardingView(client: client)
            } else {
                ChatListView(client: client)
            }
        }
    }
}
