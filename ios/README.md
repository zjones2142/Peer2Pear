# Peer2Pear iOS

SwiftUI iOS client for the Peer2Pear messaging protocol.

## Architecture

```
┌──────────────────────────────────────────────┐
│              SwiftUI Views                   │
│  OnboardingView  ChatListView  Conversation  │
├──────────────────────────────────────────────┤
│           Peer2PearClient (Swift)             │
│  Owns p2p_context, publishes state via        │
│  Combine @Published properties               │
├──────────────────────────────────────────────┤
│           peer2pear.h (C API)                │
├──────────────────────────────────────────────┤
│        libpeer2pear-core.a (C++)              │
│  CryptoEngine, Noise IK, Double Ratchet,     │
│  Sealed Sender, RelayClient, FileTransfer    │
├──────────────────────────────────────────────┤
│        Platform Adapters (Swift)             │
│  WebSocketAdapter → URLSessionWebSocketTask  │
│  HttpAdapter → URLSession.dataTask           │
└──────────────────────────────────────────────┘
```

## Building

### Prerequisites

1. Xcode 15+
2. Cross-compiled `libpeer2pear-core.a` for iOS (arm64)
3. Cross-compiled dependencies: libsodium, liboqs, SQLCipher

### Cross-compile the core library

```bash
# From the repo root:
cmake -B build-ios \
  -DCMAKE_TOOLCHAIN_FILE=path/to/ios.toolchain.cmake \
  -DPLATFORM=OS64 \
  -DCMAKE_BUILD_TYPE=Release \
  core/

cmake --build build-ios
# Produces: build-ios/libpeer2pear-core.a
```

### Xcode setup

1. Open Xcode → Create new iOS App project in `ios/Peer2Pear/`
2. Add all `.swift` files from `Sources/`
3. Set Bridging Header: Build Settings → "Objective-C Bridging Header" → `Sources/Bridge/Peer2Pear-Bridging-Header.h`
4. Add `libpeer2pear-core.a` to Link Binary With Libraries
5. Add header search path: `../../core/` (so `peer2pear.h` is found)
6. Add library search path: `../../build-ios/`
7. Build & Run

## Files

```
ios/Peer2Pear/Sources/
  App/
    Peer2PearApp.swift          # @main entry point
  Views/
    OnboardingView.swift        # First-run: name, passphrase, relay URL
    ChatListView.swift          # Contact list with conversations
    ConversationView.swift      # Message bubbles, send bar
  Bridge/
    Peer2PearClient.swift       # Swift wrapper around C API
    Peer2Pear-Bridging-Header.h # Imports peer2pear.h for Swift
  Platform/
    WebSocketAdapter.swift      # URLSessionWebSocketTask → p2p_ws_* callbacks
    HttpAdapter.swift           # URLSession.dataTask → p2p_http_response
```
