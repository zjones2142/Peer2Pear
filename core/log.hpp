#pragma once

#include <cstdio>

/*
 * core/log.hpp — minimal logging macros.
 *
 * Replaces qDebug() / qWarning() / qCritical() in the core library so
 * core/ builds without linking Qt.  Writes to stderr with a prefix.
 *
 * On Apple platforms (where stderr is bit-bucketed for app processes)
 * the same line is mirrored to `os_log` under the `com.peer2pear.core`
 * subsystem.  That makes `xcrun simctl spawn $UDID log show
 * --predicate 'subsystem == "com.peer2pear.core"'` a viable way to
 * capture live protocol-level traces from the simulator.
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

#ifdef __APPLE__
#  include <os/log.h>
#  define P2P_OSLOG_DEFAULT \
       (os_log_create("com.peer2pear.core", "default"))
#  define P2P_OSLOG(level, msg) \
       os_log_with_type(P2P_OSLOG_DEFAULT, level, "%{public}s", msg)
#else
#  define P2P_OSLOG(level, msg) do {} while (0)
#endif

#ifdef QT_NO_DEBUG_OUTPUT
#  define P2P_LOG(expr) do {} while (0)
#else
#  define P2P_LOG(expr) do {                          \
       std::ostringstream _p2p_log_ss;                \
       _p2p_log_ss << expr;                           \
       const std::string _p2p_log_str =               \
           _p2p_log_ss.str();                         \
       std::fprintf(stderr, "%s\n",                   \
                    _p2p_log_str.c_str());            \
       P2P_OSLOG(OS_LOG_TYPE_DEFAULT,                 \
                 _p2p_log_str.c_str());               \
   } while (0)
#endif

#define P2P_WARN(expr) do {                           \
    std::ostringstream _p2p_log_ss;                   \
    _p2p_log_ss << "WARN: " << expr;                  \
    const std::string _p2p_log_str =                  \
        _p2p_log_ss.str();                            \
    std::fprintf(stderr, "%s\n",                      \
                 _p2p_log_str.c_str());               \
    P2P_OSLOG(OS_LOG_TYPE_FAULT,                      \
              _p2p_log_str.c_str());                  \
} while (0)

#define P2P_CRITICAL(expr) do {                       \
    std::ostringstream _p2p_log_ss;                   \
    _p2p_log_ss << "CRITICAL: " << expr;              \
    const std::string _p2p_log_str =                  \
        _p2p_log_ss.str();                            \
    std::fprintf(stderr, "%s\n",                      \
                 _p2p_log_str.c_str());               \
    P2P_OSLOG(OS_LOG_TYPE_FAULT,                      \
              _p2p_log_str.c_str());                  \
} while (0)
