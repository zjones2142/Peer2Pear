#pragma once

#include <QImage>
#include <QString>

// QrImage — wraps Nayuki's qrcodegen to produce a QImage of a QR code
// for a given text payload (typically a 43-char base64url peer ID).
//
// Returns a square 1-bit-style QImage (Format_RGB32) with `pixelsPerModule`
// pixels per QR module on a side, plus a 4-module quiet zone matching the
// QR spec.  Returns a null QImage on failure (empty payload, encoder
// rejection, etc.) — callers should fall back to a placeholder.
//
// The desktop Edit Profile dialog uses this to render a small QR next to
// the existing Copy button, so users with a phone can scan their
// counterpart's screen instead of typing 43 characters.
class QrImage {
public:
    static QImage encodeText(const QString& text, int pixelsPerModule = 6);
};
