// ════════════════════════════════════════════════════════════════════════════
// Peer2Pear — FileTransfer & Helper Unit Tests
// ════════════════════════════════════════════════════════════════════════════

#include <glib.h>
#include <gio/gio.h>
#undef signals

#include <QtTest/QtTest>
#include <sodium.h>

#include "../filetransfer.h"
#include "../FileTransferManager.hpp"

class TestFileTransfer : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();

    // ── FileTransferRecord defaults ──────────────────────────────────────────
    void recordDefaultsAreCorrect();
    void recordHoldsAllFields();

    // ── formatFileSize ───────────────────────────────────────────────────────
    void formatFileSizeBytes();
    void formatFileSizeKB();
    void formatFileSizeMB();
    void formatFileSizeGB();
    void formatFileSizeZero();

    // ── fileIcon ─────────────────────────────────────────────────────────────
    void fileIconPdf();
    void fileIconImage();
    void fileIconVideo();
    void fileIconAudio();
    void fileIconArchive();
    void fileIconCode();
    void fileIconText();
    void fileIconUnknown();

    // ── filePreviewType ──────────────────────────────────────────────────────
    void previewTypeImage();
    void previewTypeVideo();
    void previewTypeAudio();
    void previewTypeText();
    void previewTypeGeneric();

    // ── FileTransferManager constants ────────────────────────────────────────
    void chunkSizeIs240KB();
    void maxFileSizeIs25MB();

    // ── BLAKE2b hash ─────────────────────────────────────────────────────────
    void blake2b256ProducesCorrectLength();
    void blake2b256IsDeterministic();
    void blake2b256DifferentInputsDifferentHash();
    void blake2b256EmptyInput();
};

void TestFileTransfer::initTestCase()
{
    QVERIFY2(sodium_init() >= 0, "libsodium must initialize");
}

// ═══════════════════════════════════════════════════════════════════════════
// FileTransferRecord
// ═════════════════════════════════��═════════════════════════════════════════

void TestFileTransfer::recordDefaultsAreCorrect()
{
    FileTransferRecord rec;
    QCOMPARE(rec.fileSize, qint64(0));
    QCOMPARE(rec.sent, false);
    QCOMPARE(rec.status, FileTransferStatus::Sending);
    QCOMPARE(rec.chunksTotal, 0);
    QCOMPARE(rec.chunksComplete, 0);
    QVERIFY(rec.transferId.isEmpty());
    QVERIFY(rec.fileName.isEmpty());
    QVERIFY(rec.savedPath.isEmpty());
}

void TestFileTransfer::recordHoldsAllFields()
{
    FileTransferRecord rec;
    rec.transferId = "xfer-test";
    rec.fileName = "doc.pdf";
    rec.fileSize = 5 * 1024 * 1024;
    rec.peerIdB64u = "peer123";
    rec.peerName = "Alice";
    rec.timestamp = QDateTime::currentDateTimeUtc();
    rec.sent = true;
    rec.status = FileTransferStatus::Complete;
    rec.chunksTotal = 22;
    rec.chunksComplete = 22;
    rec.savedPath = "/downloads/doc.pdf";

    QCOMPARE(rec.transferId, QString("xfer-test"));
    QCOMPARE(rec.fileName, QString("doc.pdf"));
    QCOMPARE(rec.fileSize, qint64(5 * 1024 * 1024));
    QCOMPARE(rec.status, FileTransferStatus::Complete);
    QCOMPARE(rec.chunksTotal, 22);
}

// ═══════════════════════════════════════════════════════════════════════════
// formatFileSize
// ════════════════════════��══════════════════════════════════════════════════

void TestFileTransfer::formatFileSizeBytes()
{
    QCOMPARE(formatFileSize(512), QString("512 B"));
    QCOMPARE(formatFileSize(0), QString("0 B"));
    QCOMPARE(formatFileSize(1023), QString("1023 B"));
}

void TestFileTransfer::formatFileSizeKB()
{
    QCOMPARE(formatFileSize(1024), QString("1 KB"));
    QCOMPARE(formatFileSize(2048), QString("2 KB"));
    QCOMPARE(formatFileSize(500 * 1024), QString("500 KB"));
}

void TestFileTransfer::formatFileSizeMB()
{
    QString result = formatFileSize(5 * 1024 * 1024);
    QVERIFY2(result.contains("MB"), qPrintable(QString("Expected MB, got: %1").arg(result)));
}

void TestFileTransfer::formatFileSizeGB()
{
    QString result = formatFileSize(2LL * 1024 * 1024 * 1024);
    QVERIFY2(result.contains("GB"), qPrintable(QString("Expected GB, got: %1").arg(result)));
}

void TestFileTransfer::formatFileSizeZero()
{
    QCOMPARE(formatFileSize(0), QString("0 B"));
}

// ═══════════════════════════════════════════════════════════════════════════
// fileIcon
// ═══════════════════════════════════════════════════════════════════════════

void TestFileTransfer::fileIconPdf()    { QCOMPARE(fileIcon("doc.pdf"), QString("📄")); }
void TestFileTransfer::fileIconImage()  { QCOMPARE(fileIcon("photo.png"), QString("🖼")); }
void TestFileTransfer::fileIconVideo()  { QCOMPARE(fileIcon("movie.mp4"), QString("🎬")); }
void TestFileTransfer::fileIconAudio()  { QCOMPARE(fileIcon("song.mp3"), QString("🎵")); }
void TestFileTransfer::fileIconArchive(){ QCOMPARE(fileIcon("backup.zip"), QString("🗜")); }
void TestFileTransfer::fileIconCode()   { QCOMPARE(fileIcon("main.cpp"), QString("💻")); }
void TestFileTransfer::fileIconText()   { QCOMPARE(fileIcon("readme.txt"), QString("📝")); }
void TestFileTransfer::fileIconUnknown(){ QCOMPARE(fileIcon("data.xyz"), QString("📁")); }

// ═══════════════════════════════════════════════════════════════════════════
// filePreviewType
// ═══════════════════════════════════════════════════════════════════════════

void TestFileTransfer::previewTypeImage()   { QCOMPARE(filePreviewType("pic.jpg"), FilePreviewType::Image); }
void TestFileTransfer::previewTypeVideo()   { QCOMPARE(filePreviewType("vid.mp4"), FilePreviewType::Video); }
void TestFileTransfer::previewTypeAudio()   { QCOMPARE(filePreviewType("aud.wav"), FilePreviewType::Audio); }
void TestFileTransfer::previewTypeText()    { QCOMPARE(filePreviewType("code.py"), FilePreviewType::Text); }
void TestFileTransfer::previewTypeGeneric() { QCOMPARE(filePreviewType("f.unknown"), FilePreviewType::Generic); }

// ═══════════════════════════════════════════════════════════════════════════
// FileTransferManager constants
// ═══════════════════════════════════════════════════════════════════════════

void TestFileTransfer::chunkSizeIs240KB()
{
    QCOMPARE(FileTransferManager::kChunkBytes, qint64(240 * 1024));
}

void TestFileTransfer::maxFileSizeIs25MB()
{
    QCOMPARE(FileTransferManager::kMaxFileBytes, qint64(25 * 1024 * 1024));
}

// ═══════════════════════════════════════════════════════════════════════════
// BLAKE2b
// ═══════════════════════════════════════════════════════════════════════════

void TestFileTransfer::blake2b256ProducesCorrectLength()
{
    QByteArray hash = FileTransferManager::blake2b256("test data");
    QCOMPARE(hash.size(), 32);
}

void TestFileTransfer::blake2b256IsDeterministic()
{
    QByteArray h1 = FileTransferManager::blake2b256("hello");
    QByteArray h2 = FileTransferManager::blake2b256("hello");
    QCOMPARE(h1, h2);
}

void TestFileTransfer::blake2b256DifferentInputsDifferentHash()
{
    QByteArray h1 = FileTransferManager::blake2b256("input-a");
    QByteArray h2 = FileTransferManager::blake2b256("input-b");
    QVERIFY2(h1 != h2, "Different inputs must produce different BLAKE2b hashes");
}

void TestFileTransfer::blake2b256EmptyInput()
{
    QByteArray hash = FileTransferManager::blake2b256({});
    QCOMPARE(hash.size(), 32);
}

QTEST_MAIN(TestFileTransfer)
#include "tst_filetransfer.moc"