#pragma once

#include <cstdio>

/*
 * core/log.hpp — minimal logging macros.
 *
 * Replaces qDebug() / qWarning() / qCritical() in the core library so
 * core/ builds without linking Qt.  Writes to stderr with a prefix.
 *
 * Usage:
 *   P2P_LOG("[Relay] connecting to " << url);
 *   P2P_WARN("decryptField: all keys failed");
 *
 * Defined as expression macros (do-while to keep statement semantics at the
 * call site).  The `<<` operators use std::ostringstream internally so any
 * type with an ostream operator works — including std::string, int, size_t,
 * pointer, etc.  Qt types (QString etc.) are NOT supported; convert first.
 *
 * QT_NO_DEBUG_OUTPUT still silences P2P_LOG (matches prior behaviour).
 * P2P_WARN and P2P_CRITICAL always fire.
 */

#include <sstream>
#include <string>

#ifdef QT_NO_DEBUG_OUTPUT
#  define P2P_LOG(expr) do {} while (0)
#else
#  define P2P_LOG(expr) do {                          \
       std::ostringstream _p2p_log_ss;                \
       _p2p_log_ss << expr;                           \
       std::fprintf(stderr, "%s\n",                   \
                    _p2p_log_ss.str().c_str());       \
   } while (0)
#endif

#define P2P_WARN(expr) do {                           \
    std::ostringstream _p2p_log_ss;                   \
    _p2p_log_ss << "WARN: " << expr;                  \
    std::fprintf(stderr, "%s\n",                      \
                 _p2p_log_ss.str().c_str());          \
} while (0)

#define P2P_CRITICAL(expr) do {                       \
    std::ostringstream _p2p_log_ss;                   \
    _p2p_log_ss << "CRITICAL: " << expr;              \
    std::fprintf(stderr, "%s\n",                      \
                 _p2p_log_ss.str().c_str());          \
} while (0)
