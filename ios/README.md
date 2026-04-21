# Peer2Pear iOS

SwiftUI iOS client for the Peer2Pear messaging protocol.  Targets iOS 26.0+,
arm64 simulator and device.

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

No Qt anywhere — the core library is compiled with `WITH_QT_CORE=OFF` and
`PEER2PEAR_P2P=OFF` for iOS, and the vendored SQLCipher amalgamation
(`third_party/sqlcipher/`) drops the last C++-only dependency.

## Building

One-time setup:

```bash
# From the repo root:
./setup.sh                # bootstraps vcpkg, installs desktop-only prereqs
./build-ios.sh --both     # cross-compiles libpeer2pear-core.a for arm64
                          # simulator and arm64 device.  First run pulls
                          # libsodium / liboqs / openssl / sqlcipher via
                          # vcpkg — allow ~10 minutes.

cd ios
./generate.sh             # creates Peer2Pear.xcodeproj from project.yml
                          # (installs xcodegen via brew if missing)
```

Then open `ios/Peer2Pear.xcodeproj` in Xcode, or build from the command line:

```bash
xcodebuild -project Peer2Pear.xcodeproj -scheme Peer2Pear \
           -sdk iphonesimulator -arch arm64 -configuration Debug
```

## Files

```
ios/
  project.yml                                  # xcodegen input (COMMITTED)
  generate.sh                                  # creates .xcodeproj
  README.md                                    # this file
  Peer2Pear/
    Sources/
      App/Peer2PearApp.swift                   # @main entry point
      Views/
        OnboardingView.swift                   # first-run: passphrase + relay
        ChatListView.swift                     # contact list + conversations
        ConversationView.swift                 # message bubbles + send bar
      Bridge/
        Peer2PearClient.swift                  # Swift wrapper around C API
        Peer2Pear-Bridging-Header.h            # exposes peer2pear.h to Swift
      Platform/
        WebSocketAdapter.swift                 # URLSessionWebSocketTask wrap
        HttpAdapter.swift                      # URLSession.dataTask wrap
    Resources/                                 # Info.plist, assets (empty)
```

The `.xcodeproj` itself is NOT committed — everyone regenerates from
`project.yml` via `generate.sh`.  No `.pbxproj` merge conflicts.

## Why xcodegen (not a committed .xcodeproj)

`project.pbxproj` is an opaque, line-noise format that breaks on every
Git merge.  xcodegen lets us describe the project declaratively (~100
lines of YAML) and regenerate deterministically.  Adding a Swift file
means editing nothing if it lands in `Sources/`, and regenerating;
changing build settings means one line in YAML instead of hunting
through Xcode's UI.

## Status

What works today:
- Core library builds clean for iOS simulator + device (iOS 26.0 minimum).
- Xcode project links all static libs — `libpeer2pear-core.a`,
  `libsqlcipher.a`, `libsodium.a`, `liboqs.a`, `libssl.a`, `libcrypto.a`.
- Swift scaffolding (onboarding, chat list, conversation view) wires up
  a minimum subset of the C API: connected / status / message / presence.
- App boots, bridges Swift ↔ C, WebSocket adapter uses URLSessionWebSocketTask.

What's scaffolded but incomplete:
- `Peer2PearClient.setupCallbacks()` only wires 4 of the 12 C callbacks.
  Missing: group messages, avatars, group rename/avatar/member-update,
  file progress, file accept request, file canceled/delivered/blocked.
  Add them by mirroring the pattern used for `p2p_set_on_message`.
- Onboarding view does identity setup but doesn't persist the last
  relay URL yet.
- No contact QR code scanning / sharing — user manually pastes the 43-char
  peer ID.

What's deferred:
- **P2P transport on iOS.** `PEER2PEAR_P2P=OFF` because libnice / msquic /
  GLib haven't been ported to iOS in the repo.  iOS is relay-only for now;
  QuicConnection is Qt-free (Phase 7d) and could run on iOS in principle
  once the dependency chain is ported.
- **Code signing for device.** Simulator runs under "Sign to Run Locally";
  physical devices need an Apple Developer team to be added.

## Troubleshooting

**"library not found for -lpeer2pear-core"** — you haven't built the core
for iOS yet.  Run `./build-ios.sh --both` from the repo root.

**xcodegen: command not found** — `generate.sh` tries to install it via
Homebrew.  If you don't have brew, install it manually from the
[XcodeGen releases page](https://github.com/yonaskolb/XcodeGen/releases).

**Swift can't find peer2pear.h** — check `HEADER_SEARCH_PATHS` in the
generated project points at `../core/`.  If it doesn't, re-run
`generate.sh` (the setting is in `project.yml`).
