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

## Code signing (for device builds)

Simulator builds work out of the box — they don't need any code signing.
Running on a physical device or shipping to TestFlight requires an Apple
Developer Program membership ($99/year individual, $299/year organization).

**One-time setup:**

1. **Sign up for Apple Developer Program** at
   <https://developer.apple.com/programs/enroll/>.  The Personal Team
   tier (free) is enough for 7-day on-device testing if you're not ready
   to pay yet — for TestFlight or App Store distribution you need the
   paid tier.

2. **Sign in to Xcode** with your Apple ID:
   `Xcode → Settings → Accounts → +` → enter Apple ID → wait for the
   team list to populate.

3. **Find your Team ID** (10 characters, looks like `ABCD12345E`):
   - Apple Developer portal: <https://developer.apple.com/account> →
     Membership tab → "Team ID" field, OR
   - Xcode → Settings → Accounts → select your team → "Manage Certificates"
     sheet header.

4. **Wire the Team ID into the build:**
   ```bash
   cd ios/Peer2Pear/Configs
   cp Signing.local.xcconfig.template Signing.local.xcconfig
   # edit Signing.local.xcconfig, replace REPLACE_WITH_YOUR_10_CHAR_TEAM_ID
   # with your actual ID — file is gitignored, won't end up in the repo.
   ```

5. **Build for device:**
   - Open `ios/Peer2Pear.xcodeproj` in Xcode
   - Plug in your iPhone, unlock it, accept the "Trust" prompt
   - Select your device in the run-target dropdown
   - Hit ⌘R

   Xcode will auto-create a development provisioning profile for the
   `com.peer2pear.Peer2Pear` bundle ID under your team the first time
   you build for device.  No manual portal trips needed — that's the
   whole point of `CODE_SIGN_STYLE = Automatic` (set in
   `Configs/Signing.xcconfig`).

**Why xcconfig instead of editing project.yml directly?**
Different developers / CI runners use different Team IDs.  An xcconfig
keeps everyone's local Team ID out of the committed YAML, lets you
flip it without re-running `generate.sh`, and survives fresh repo
clones because the include is optional (`#include?`).

## Files

```
ios/
  project.yml                                  # xcodegen input (COMMITTED)
  generate.sh                                  # creates .xcodeproj
  README.md                                    # this file
  Peer2Pear/
    Configs/
      Signing.xcconfig                         # committed shell, optionally
                                               # includes Signing.local.xcconfig
      Signing.local.xcconfig.template          # copy to Signing.local.xcconfig
                                               # and add your Team ID
    Sources/
      App/Peer2PearApp.swift                   # @main entry point
      Views/
        OnboardingView.swift                   # first-run: passphrase + relay
        ChatListView.swift                     # contact list + conversations
        ConversationView.swift                 # message bubbles + send bar
        MyKeyView.swift                        # show own peer ID + QR + Copy
        QRScannerView.swift                    # AVFoundation-backed QR scanner
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
- Onboarding view does identity setup but doesn't persist the last
  relay URL yet.

What's deferred:
- **P2P transport on iOS.** `PEER2PEAR_P2P=OFF` because libnice / msquic /
  GLib haven't been ported to iOS in the repo.  iOS is relay-only for now;
  QuicConnection is Qt-free (Phase 7d) and could run on iOS in principle
  once the dependency chain is ported.

## Troubleshooting

**"library not found for -lpeer2pear-core"** — you haven't built the core
for iOS yet.  Run `./build-ios.sh --both` from the repo root.

**xcodegen: command not found** — `generate.sh` tries to install it via
Homebrew.  If you don't have brew, install it manually from the
[XcodeGen releases page](https://github.com/yonaskolb/XcodeGen/releases).

**Swift can't find peer2pear.h** — check `HEADER_SEARCH_PATHS` in the
generated project points at `../core/`.  If it doesn't, re-run
`generate.sh` (the setting is in `project.yml`).
