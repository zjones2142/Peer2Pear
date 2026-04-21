import AVFoundation
import SwiftUI
import UIKit

// QRScannerView — a UIKit-backed full-screen camera view that returns the
// first scanned QR string to the caller via the `onScan` closure.
//
// Design intent:
//   - Returns the decoded string verbatim.  It's the caller's job to
//     validate (e.g. 43-char base64url) and handle rejection UX.
//   - Fires `onScan` exactly once per presentation — after first success
//     we stop the session so a second QR sliding into frame doesn't
//     double-dispatch.
//   - `onCancel` wraps the "user tapped Cancel" path.  The caller is
//     responsible for dismissing the sheet in both closures.
//
// NSCameraUsageDescription must be set in Info.plist or iOS will abort
// the capture-session start.
struct QRScannerView: UIViewControllerRepresentable {
    var onScan: (String) -> Void
    var onCancel: () -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.onScan   = onScan
        vc.onCancel = onCancel
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController,
                                  context: Context) {}
}

final class QRScannerViewController: UIViewController,
                                      AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    var onCancel: (() -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasDelivered = false

    private lazy var statusLabel: UILabel = {
        let lbl = UILabel()
        lbl.translatesAutoresizingMaskIntoConstraints = false
        lbl.textColor = .white
        lbl.font = .preferredFont(forTextStyle: .headline)
        lbl.textAlignment = .center
        lbl.numberOfLines = 0
        lbl.text = "Point the camera at a Peer2Pear QR code"
        return lbl
    }()

    private lazy var cancelButton: UIButton = {
        var cfg = UIButton.Configuration.filled()
        cfg.title = "Cancel"
        cfg.baseBackgroundColor = UIColor.black.withAlphaComponent(0.6)
        cfg.baseForegroundColor = .white
        cfg.cornerStyle = .capsule
        let b = UIButton(configuration: cfg)
        b.translatesAutoresizingMaskIntoConstraints = false
        b.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        return b
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureSessionOrShowError()
        layoutOverlay()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    // MARK: - Session setup

    private func configureSessionOrShowError() {
        // Permission check.  If the user denied camera access, surface a
        // clear message rather than a black screen.
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.startSession() }
                    else       { self?.showDeniedLabel() }
                }
            }
        case .denied, .restricted:
            showDeniedLabel()
        @unknown default:
            showDeniedLabel()
        }
    }

    private func startSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input  = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            showDeniedLabel(); return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { showDeniedLabel(); return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0)
        previewLayer = preview

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    private func showDeniedLabel() {
        statusLabel.text = """
            Camera access is needed to scan QR codes.

            Enable it in Settings → Privacy → Camera, or paste the key manually.
            """
    }

    // MARK: - Overlay

    private func layoutOverlay() {
        view.addSubview(statusLabel)
        view.addSubview(cancelButton)
        NSLayoutConstraint.activate([
            statusLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor,
                                               constant: 24),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),

            cancelButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor,
                                                   constant: -24),
            cancelButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
        ])
    }

    // MARK: - Delegate

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                         didOutput metadataObjects: [AVMetadataObject],
                         from connection: AVCaptureConnection) {
        guard !hasDelivered,
              let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              obj.type == .qr,
              let raw = obj.stringValue else { return }

        hasDelivered = true
        // Stop the session so the preview freezes + no second object fires.
        session.stopRunning()
        // Haptic tick — matches iOS's system scanner feel.
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onScan?(raw)
    }

    @objc private func cancelTapped() { onCancel?() }
}
