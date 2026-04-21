import Foundation

/// iOS HTTP implementation using URLSession.
/// Provides the http_post callback for p2p_platform.
///
/// The C core calls http_post with URL, body, and headers.
/// When the request completes, we call p2p_http_response() with the result.
final class HttpAdapter {
    private let session = URLSession.shared
    private var nextRequestId: Int32 = 1
    private weak var context: Peer2PearClient?

    init(client: Peer2PearClient) {
        self.context = client
    }

    func post(url: URL, body: Data, headers: [(String, String)]) -> Int32 {
        let requestId = nextRequestId
        nextRequestId += 1

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        session.dataTask(with: request) { [weak self] data, response, error in
            guard let ctx = self?.context?.rawContext else { return }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0

            if let error {
                let msg = error.localizedDescription
                msg.withCString { cstr in
                    p2p_http_response(ctx, requestId, Int32(status), nil, 0, cstr)
                }
            } else if let data {
                data.withUnsafeBytes { ptr in
                    p2p_http_response(ctx, requestId, Int32(status),
                                      ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                      Int32(data.count), nil)
                }
            } else {
                p2p_http_response(ctx, requestId, Int32(status), nil, 0, nil)
            }
        }.resume()

        return requestId
    }
}
