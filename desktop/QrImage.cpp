#include "QrImage.hpp"

#include <qrcodegen.hpp>

#include <QPainter>

#include <exception>

QImage QrImage::encodeText(const QString& text, int pixelsPerModule)
{
    if (text.isEmpty() || pixelsPerModule <= 0) return {};

    // qrcodegen operates on UTF-8 bytes; peer IDs are base64url ASCII so the
    // conversion is lossless either way.  We request ECC=Medium (~15 %
    // recovery) — matches the iOS side and comfortably survives a camera
    // scan from a few feet away without bloating the grid size.
    //
    // QrCode has no default constructor (it owns the bit grid), so the
    // encode + render must live in one scope.  encodeText throws
    // length_error for payloads past the largest QR version's capacity —
    // a 43-char id never trips this, but the catch keeps us from crashing
    // if a caller passes garbage.
    try {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
            text.toUtf8().constData(),
            qrcodegen::QrCode::Ecc::MEDIUM);

        // 4-module quiet zone on every side is what the QR spec recommends
        // for reliable scanning; dropping below 2 modules makes some readers
        // (older Android especially) miss the finder pattern.
        const int border  = 4;
        const int modules = qr.getSize();
        const int sidePx  = (modules + 2 * border) * pixelsPerModule;

        QImage img(sidePx, sidePx, QImage::Format_RGB32);
        img.fill(Qt::white);

        QPainter p(&img);
        p.setPen(Qt::NoPen);
        p.setBrush(Qt::black);
        for (int y = 0; y < modules; ++y) {
            for (int x = 0; x < modules; ++x) {
                if (!qr.getModule(x, y)) continue;
                p.drawRect((x + border) * pixelsPerModule,
                            (y + border) * pixelsPerModule,
                            pixelsPerModule,
                            pixelsPerModule);
            }
        }
        return img;
    } catch (const std::exception&) {
        return {};
    }
}
