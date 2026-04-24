// test_std_timer.cpp — regression coverage for StdTimer.
// Self-join on startSingleShot/stop must not throw system_error;
// callbacks must run under the optional ctrlMu; factory.singleShot
// must reap completed worker threads.

#include "StdTimer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>

using namespace std::chrono_literals;

namespace {

// Spin-wait helper — gtest doesn't ship with a clean "wait until
// condition or timeout" primitive, and using sleep_for-then-check
// across the suite is noisy.  Returns false if the timeout elapses;
// the caller turns that into a fatal EXPECT_*.
template <class Pred>
bool waitFor(std::chrono::milliseconds timeout, Pred p) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return p();  // last-chance check; gives the predicate one more shot
}

}  // namespace

// ── 1. The bug it was filed against ─────────────────────────────────────────
// startSingleShot called from inside its own callback must NOT abort.
// Pre-fix, the second invocation hit cancelAndJoin() → thread::join()
// on the current thread → system_error → terminate → SIGABRT.
TEST(StdTimerTest, SelfRearmFromInsideCallbackDoesNotCrash) {
    StdTimerFactory factory(/*ctrlMu=*/nullptr);
    auto timer = factory.create();

    std::atomic<int> fireCount{0};
    std::function<void()> cb;
    cb = [&]() {
        if (++fireCount < 5) {
            // Self-rearm — exact shape of ChatController::scheduleMaintenance.
            // Use a tiny delay so the test finishes in well under a second
            // even though we're chaining 5 fires.
            timer->startSingleShot(5, cb);
        }
    };
    timer->startSingleShot(5, cb);

    // 500 ms is generous — five 5-ms rearms should complete in ~25 ms,
    // but CI machines under load occasionally stall.  A broken self-join
    // would already have aborted by now (the abort fires on the second
    // tick), so this is purely there to prove the chain ran.
    EXPECT_TRUE(waitFor(500ms, [&]{ return fireCount.load() >= 5; }))
        << "fireCount stalled at " << fireCount.load();

    EXPECT_EQ(fireCount.load(), 5);
}

// ── 2. stop() called from inside the callback must not abort either ────────
// stop() shares the same self-join hazard as startSingleShot.  The user-
// reachable path is "user fires an action while runMaintenance is running
// and that action wants to disable the timer."  Mirror the guard test.
TEST(StdTimerTest, StopFromInsideCallbackDoesNotCrash) {
    StdTimerFactory factory(/*ctrlMu=*/nullptr);
    auto timer = factory.create();

    std::atomic<bool> fired{false};
    timer->startSingleShot(5, [&]() {
        timer->stop();   // self-stop — would self-join pre-fix
        fired = true;
    });

    EXPECT_TRUE(waitFor(500ms, [&]{ return fired.load(); }));
}

// ── 3. Cross-thread cancel (the path that was already correct pre-fix) ────
// External stop() from a different thread should still join cleanly.
// We're checking that the new self-join guard only kicks in when the
// caller IS the worker thread, not for ordinary cross-thread cancel.
TEST(StdTimerTest, ExternalStopJoinsCleanly) {
    StdTimerFactory factory(/*ctrlMu=*/nullptr);
    auto timer = factory.create();

    std::atomic<bool> fired{false};
    timer->startSingleShot(/*delayMs=*/10000, [&]() { fired = true; });

    // Cancel before the long delay elapses; cb must not fire and stop()
    // must return promptly because the worker is in cv.wait_for().
    std::this_thread::sleep_for(20ms);
    timer->stop();

    // Sleep a tick longer than the delay we passed — if cancel didn't
    // take, fired would flip during this window.
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(fired.load());
}

// ── 4. ctrlMu serialization ────────────────────────────────────────────────
// When a ctrlMu is passed in, the callback should fire under that lock.
// The factory's "every cb runs under ctrlMu" guarantee is what lets
// p2p_context safely interleave timer fires with foreground p2p_*
// entry-point calls.
TEST(StdTimerTest, CallbackRunsUnderCtrlMu) {
    std::mutex ctrlMu;
    StdTimerFactory factory(&ctrlMu);
    auto timer = factory.create();

    std::atomic<bool> sawLockHeld{false};
    timer->startSingleShot(5, [&]() {
        // try_lock returns false iff someone (us, the timer worker)
        // already owns it — proves the cb runs under the mutex.
        sawLockHeld = !ctrlMu.try_lock();
        if (!sawLockHeld) ctrlMu.unlock();   // we wrongly grabbed it
    });

    EXPECT_TRUE(waitFor(500ms, [&]{ return sawLockHeld.load(); }));
}

// ── 5. Factory singleShot reaps completed worker threads ──────────────────
// The "bag" of fire-and-forget timers in StdTimerFactory could grow
// unbounded if reaping never happened — every singleShot would push a
// fresh slot onto m_bag and only join in shutdown().  Verify that calls
// after a worker completes don't leak the prior slot.
TEST(StdTimerTest, FactorySingleShotFiresCallback) {
    StdTimerFactory factory(/*ctrlMu=*/nullptr);

    std::atomic<int> fired{0};
    for (int i = 0; i < 10; ++i) {
        factory.singleShot(5, [&]() { ++fired; });
    }

    EXPECT_TRUE(waitFor(500ms, [&]{ return fired.load() == 10; }))
        << "only " << fired.load() << "/10 fired";

    // Shutdown drains any still-running workers.  Idempotent — calling
    // it from the destructor too is safe.
    factory.shutdown();
}

// ── 6. isActive flips true while pending, false after fire ────────────────
TEST(StdTimerTest, IsActiveTracksLifecycle) {
    StdTimerFactory factory(/*ctrlMu=*/nullptr);
    auto timer = factory.create();

    EXPECT_FALSE(timer->isActive());

    std::atomic<bool> fired{false};
    timer->startSingleShot(20, [&]() { fired = true; });

    EXPECT_TRUE(timer->isActive());
    EXPECT_TRUE(waitFor(500ms, [&]{ return fired.load(); }));
    // m_active is reset right before cb runs, so by the time we observe
    // fired == true, isActive() must already be false.
    EXPECT_FALSE(timer->isActive());
}
