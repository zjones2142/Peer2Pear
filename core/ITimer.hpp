#pragma once

#include <functional>
#include <memory>

/*
 * ITimer — platform abstraction for single-shot + restartable timers.
 *
 * Desktop provides a QTimer-backed impl (desktop/QtTimer.hpp); iOS
 * provides a dispatch_after-backed impl; Android provides a Handler-
 * backed impl.  Core code never touches QTimer directly.
 *
 * Usage:
 *   auto t = factory.create();
 *   t->startSingleShot(1000, [this]{ onReconnect(); });
 *   ...
 *   t->stop();   // cancel pending fire
 *
 * Thread model: all calls and callbacks happen on the host's main/event
 * thread.  Not thread-safe by design — mirrors QTimer semantics.
 */
class ITimer {
public:
    virtual ~ITimer() = default;

    /// Schedule @p cb to fire once after @p delayMs milliseconds.
    /// If the timer already has a pending fire, this replaces it.
    virtual void startSingleShot(int delayMs, std::function<void()> cb) = 0;

    /// Cancel any pending fire.  No-op if the timer is idle.
    virtual void stop() = 0;

    /// True if a scheduled fire is still pending.
    virtual bool isActive() const = 0;
};

/*
 * ITimerFactory — host-provided factory for ITimer instances.
 *
 * Passed into RelayClient / FileTransferManager / ChatController so they
 * don't have to know about the host's timer subsystem.
 */
class ITimerFactory {
public:
    virtual ~ITimerFactory() = default;

    /// Create a new idle timer.  Caller owns the returned unique_ptr.
    virtual std::unique_ptr<ITimer> create() = 0;

    /// Fire a one-shot callback after @p delayMs — convenience for ad-hoc
    /// scheduling (e.g. jitter).  Equivalent to create() + startSingleShot()
    /// followed by letting the timer self-destruct, but the host implements
    /// it efficiently (QTimer::singleShot on desktop, dispatch_after on iOS).
    virtual void singleShot(int delayMs, std::function<void()> cb) = 0;
};
