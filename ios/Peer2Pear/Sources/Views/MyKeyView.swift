import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

// MyKeyView — where the user sees + shares their own peer ID.
//
// Two exchange paths live side by side:
//   1. QR code rendered from `client.myPeerId` via CoreImage's built-in
//      qrCodeGenerator — scan from another phone for a zero-typing add.
//   2. The raw 43-char base64url string + a Copy button — the pre-existing
//      explicit path the user wants to keep.  The displayed string is
//      byte-for-byte what gets encoded into the QR, so the two methods
//      are interchangeable.
//
// Surfaced from ChatListView's toolbar (person.circle icon) as a sheet.
// Per-device preferences (appearance, biometric unlock, notification
// privacy, relay URL) live in SettingsView — they used to sit here
// but were confusing under the "My Key" title since they have
// nothing to do with identity-sharing.
struct MyKeyView: View {
    @ObservedObject var client: Peer2PearClient
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    Text("Share your key with someone to start a conversation. They can scan the QR or paste the text.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    QRCodeImage(payload: client.myPeerId, size: 240)
                        .frame(width: 240, height: 240)
                        .background(Color.white)
                        .cornerRadius(12)
                        .padding()
                        .accessibilityLabel("QR code of your peer ID")

                    VStack(spacing: 8) {
                        Text("Your Peer ID")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(client.myPeerId)
                            .font(.system(.footnote, design: .monospaced))
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .padding(10)
                            .background(Color(.secondarySystemBackground))
                            .cornerRadius(8)
                            .padding(.horizontal)
                    }

                    Button {
                        UIPasteboard.general.string = client.myPeerId
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                            copied = false
                        }
                    } label: {
                        Label(copied ? "Copied!" : "Copy",
                              systemImage: copied ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                    .padding(.horizontal)
                    .disabled(client.myPeerId.isEmpty)
                }
                .padding(.vertical)
            }
            .navigationTitle("My Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

// CoreImage-backed QR image.  The filter produces a tiny native-resolution
// image; we rasterize via CIContext + nearest-neighbor scaling so the
// modules stay crisp at display size rather than blurring through
// SwiftUI's default image-smoothing resampler.
struct QRCodeImage: View {
    let payload: String
    let size: CGFloat

    var body: some View {
        if let img = Self.render(payload: payload, size: size) {
            Image(uiImage: img)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            // Fallback — empty payload (myPeerId not ready yet) or filter failure.
            Rectangle()
                .fill(Color(.secondarySystemBackground))
                .overlay {
                    Image(systemName: "qrcode")
                        .foregroundStyle(.secondary)
                }
        }
    }

    private static func render(payload: String, size: CGFloat) -> UIImage? {
        guard !payload.isEmpty else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"      // ~15% tolerance — plenty for a clean screen-to-camera scan
        guard let ciImage = filter.outputImage else { return nil }

        // Scale up from the filter's native ~33×33 to the target pixel size
        // without anti-aliasing so each module stays a crisp square.
        let scale = (size * UIScreen.main.scale) / ciImage.extent.width
        let scaled = ciImage.transformed(by: .init(scaleX: scale, y: scale))

        let ctx = CIContext()
        guard let cg = ctx.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg, scale: UIScreen.main.scale, orientation: .up)
    }
}
