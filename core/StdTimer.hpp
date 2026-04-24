#pragma once
//
// StdTimer / StdTimerFactory — thread-based ITimer implementation.
//
// Extracted from peer2pear_api.cpp so the timers are reachable from
// tests without going through the full p2p_context setup.  Nothing in
// this file depends on Qt; the C API hosts (iOS, Android, generic)
// use these directly because they don't have a Qt event loop.  The
// desktop build substitutes QtTimer instead.
//
// Threading model:
//   • startSingleShot() spawns a worker thread that sleeps until the
//     deadline (or a cancellation arrives via m_cv) and then fires cb().
//   • The cb() is invoked under *ctrlMu if the caller passed one, so
//     the host's WS/HTTP callbacks and the maintenance timer serialize
//     on a single mutex.
//   • When cb() calls startSingleShot() on the same timer (the
//     ChatController::scheduleMaintenance re-arm case), we detach the
//     outgoing thread instead of joining it — std::thread::join() on
//     the current thread throws system_error → std::terminate → abort.
//
// StdTimerFactory::singleShot() is the fire-and-forget cousin: the
// thread owns its lifetime through an m_bag of Slot handles, reaping
// completed siblings on each new call + draining in shutdown().

#include "ITimer.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

class StdTimer : public ITimer {
public:
    // ctrlMu must outlive every callback we fire.  In practice the
    // p2p_context owns both this timer and the mutex, destroyed together.
    explicit StdTimer(std::mutex* ctrlMu) : m_ctrlMu(ctrlMu) {}
    ~StdTimer() override { cancelAndJoin(); }

    StdTimer(const StdTimer&) = delete;
    StdTimer& operator=(const StdTimer&) = delete;

    void startSingleShot(int delayMs, std::function<void()> cb) override {
        // Self-rearm case: the caller IS our callback thread (e.g.
        // ChatController::scheduleMaintenance re-arms itself from inside
        // runMaintenance).  Joining ourselves would throw system_error
        // and call std::terminate → abort.  Detach the outgoing thread
        // — its body is already returning after this call, so the OS
        // cleans it up naturally — and spawn a fresh one.
        if (m_thread.joinable() &&
            m_thread.get_id() == std::this_thread::get_id()) {
            m_thread.detach();
        } else {
            cancelAndJoin();
        }
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_canceled = false;
            m_active = true;
        }
        auto* ctrlMu = m_ctrlMu;
        m_thread = std::thread([this, delayMs, ctrlMu, cb = std::move(cb)]() {
            std::unique_lock<std::mutex> lk(m_mu);
            const bool gotCancel = m_cv.wait_for(
                lk, std::chrono::milliseconds(delayMs),
                [this] { return m_canceled; });
            const bool fire = !gotCancel;
            m_active = false;
            lk.unlock();
            if (fire && cb) {
                // Serialize with p2p_* entry points.
                if (ctrlMu) {
                    std::lock_guard<std::mutex> cg(*ctrlMu);
                    cb();
                } else {
                    cb();
                }
            }
        });
    }

    void stop() override {
        // Same self-join guard: `stop()` from within the callback thread
        // (e.g. a user action fires during runMaintenance) must not join
        // itself.  Detach instead; the thread body is about to return.
        if (m_thread.joinable() &&
            m_thread.get_id() == std::this_thread::get_id()) {
            {
                std::lock_guard<std::mutex> lk(m_mu);
                m_canceled = true;
            }
            m_cv.notify_all();
            m_thread.detach();
            return;
        }
        cancelAndJoin();
    }

    bool isActive() const override {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_active;
    }

private:
    void cancelAndJoin() {
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_canceled = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }

    mutable std::mutex      m_mu;
    std::condition_variable m_cv;
    bool                    m_canceled = false;
    bool                    m_active   = false;
    std::thread             m_thread;
    std::mutex*             m_ctrlMu   = nullptr;
};

class StdTimerFactory : public ITimerFactory {
public:
    explicit StdTimerFactory(std::mutex* ctrlMu) : m_ctrlMu(ctrlMu) {}

    ~StdTimerFactory() override { shutdown(); }

    // Drain any still-pending singleShot worker threads.  MUST be called
    // by p2p_destroy BEFORE tearing down the ChatController — otherwise a
    // cb mid-execution can dereference the already-destroyed controller
    // (the cb captured references to it).  Idempotent.
    void shutdown() {
        std::vector<std::unique_ptr<Slot>> pending;
        {
            std::lock_guard<std::mutex> lk(m_bagMu);
            if (m_shuttingDown) return;
            m_shuttingDown = true;
            pending.swap(m_bag);
        }
        for (auto& s : pending) {
            if (s->t.joinable()) s->t.join();
        }
    }

    std::unique_ptr<ITimer> create() override {
        return std::make_unique<StdTimer>(m_ctrlMu);
    }

    void singleShot(int delayMs, std::function<void()> cb) override {
        auto* ctrlMu = m_ctrlMu;
        auto* self = this;

        auto slot = std::make_unique<Slot>();
        Slot* slotRaw = slot.get();

        slot->t = std::thread([self, slotRaw, delayMs, ctrlMu, cb = std::move(cb)]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            if (cb) {
                // Skip the callback if teardown has started — the shutdown
                // path will still join this thread via m_bag.
                bool shuttingDown = false;
                {
                    std::lock_guard<std::mutex> lk(self->m_bagMu);
                    shuttingDown = self->m_shuttingDown;
                }
                if (!shuttingDown) {
                    if (ctrlMu) {
                        std::lock_guard<std::mutex> cg(*ctrlMu);
                        cb();
                    } else {
                        cb();
                    }
                }
            }
            // Mark ourselves reapable — a later singleShot() call (or
            // shutdown()) will join + erase us from m_bag.  Must be the
            // last write; after this point the reaper may join us.
            slotRaw->done.store(true, std::memory_order_release);
        });

        std::lock_guard<std::mutex> lk(m_bagMu);
        // Reap completed siblings before pushing the new slot.  This is
        // what keeps m_bag bounded over session lifetime instead of
        // accumulating one handle per timer tick.
        reapLocked();
        if (m_shuttingDown) {
            // Racing with destruction — detach and let the thread's own
            // m_shuttingDown re-check skip the cb.
            slot->t.detach();
        } else {
            m_bag.push_back(std::move(slot));
        }
    }

private:
    struct Slot {
        std::thread        t;
        std::atomic<bool>  done{false};
    };

    // Caller holds m_bagMu.  Walks m_bag erasing any Slot whose worker
    // has finished (done==true); joins before erase so the thread is
    // fully reclaimed.  join() on a done thread returns immediately.
    void reapLocked() {
        auto it = m_bag.begin();
        while (it != m_bag.end()) {
            if ((*it)->done.load(std::memory_order_acquire)) {
                if ((*it)->t.joinable()) (*it)->t.join();
                it = m_bag.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::mutex*                           m_ctrlMu = nullptr;
    std::mutex                            m_bagMu;
    std::vector<std::unique_ptr<Slot>>    m_bag;
    bool                                  m_shuttingDown = false;
};
