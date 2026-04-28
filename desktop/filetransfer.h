#pragma once

// File-transfer UI helpers — pure presentation utilities shared by
// ChatView's render path.  The actual file-record struct lives on
// AppDataStore::FileRecord now; this header keeps just the switch-
// friendly status enum + icon / size / preview-type formatters.

#include <QString>

// ── FileTransferStatus ────────────────────────────────────────────────────────
// Mirrors the integer stored in AppDataStore::FileRecord::status.
// Kept as an enum here so switch statements and guards in the UI
// layer read naturally; cast via static_cast<int>(...) at the DB edge.
enum class FileTransferStatus {
    Sending,    // outgoing: chunks are being queued
    Receiving,  // incoming: partial — waiting for more chunks
    Complete,   // all chunks delivered; file accessible on disk
    Failed
};

// ── Helpers ───────────────────────────────────────────────────────────────────
inline QString formatFileSize(qint64 bytes)
{
    if (bytes < 1024LL)
        return QString("%1 B").arg(bytes);
    if (bytes < 1024LL * 1024)
        return QString("%1 KB").arg(bytes / 1024);
    if (bytes < 1024LL * 1024 * 1024)
        return QString("%1 MB").arg(double(bytes) / (1024.0 * 1024.0), 0, 'f', 1);
    return QString("%1 GB").arg(double(bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

inline QString fileIcon(const QString &fileName)
{
    const QString ext = fileName.section('.', -1).toLower();
    if (ext == "pdf")                                                    return "📄";
    if (ext == "png"  || ext == "jpg" || ext == "jpeg"
        || ext == "gif" || ext == "webp" || ext == "bmp"
        || ext == "heic")                                               return "🖼";
    if (ext == "mp4"  || ext == "mov" || ext == "avi"
        || ext == "mkv" || ext == "webm")                               return "🎬";
    if (ext == "mp3"  || ext == "wav" || ext == "flac"
        || ext == "ogg" || ext == "aac")                                return "🎵";
    if (ext == "zip"  || ext == "tar" || ext == "gz"
        || ext == "7z"  || ext == "rar")                                return "🗜";
    if (ext == "cpp"  || ext == "h"   || ext == "py"  || ext == "js"
        || ext == "ts"  || ext == "java" || ext == "rs" || ext == "go"
        || ext == "cs")                                                  return "💻";
    if (ext == "txt"  || ext == "md"  || ext == "csv")                  return "📝";
    if (ext == "doc"  || ext == "docx" || ext == "odt")                 return "📃";
    if (ext == "xls"  || ext == "xlsx" || ext == "ods")                 return "📊";
    if (ext == "ppt"  || ext == "pptx" || ext == "odp")                 return "📽";
    return "📁";
}

enum class FilePreviewType { Image, Video, Audio, Text, Generic };

inline FilePreviewType filePreviewType(const QString &fileName)
{
    const QString ext = fileName.section('.', -1).toLower();
    if (ext=="png"||ext=="jpg"||ext=="jpeg"||ext=="gif"||ext=="webp"||ext=="bmp"||ext=="heic")
        return FilePreviewType::Image;
    if (ext=="mp4"||ext=="mov"||ext=="avi"||ext=="mkv"||ext=="webm")
        return FilePreviewType::Video;
    if (ext=="mp3"||ext=="wav"||ext=="flac"||ext=="ogg"||ext=="aac")
        return FilePreviewType::Audio;
    if (ext=="txt"||ext=="md"||ext=="csv"||ext=="cpp"||ext=="h"||ext=="py"
        ||ext=="js"||ext=="ts"||ext=="java"||ext=="rs"||ext=="go"||ext=="cs")
        return FilePreviewType::Text;
    return FilePreviewType::Generic;
}