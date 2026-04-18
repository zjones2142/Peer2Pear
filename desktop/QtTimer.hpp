#pragma once

#include "ITimer.hpp"
#include <QObject>
#include <QTimer>
#include <memory>

/*
 * QtTimer — ITimer impl backed by QTimer.  Desktop-only.
 * QtTimerFactory hands these out to core/ components.
 */
class QtTimer : public ITimer {
public:
    QtTimer() {
        m_t.setSingleShot(true);
        QObject::connect(&m_t, &QTimer::timeout, &m_t, [this]() {
            if (m_cb) m_cb();
        });
    }

    void startSingleShot(int delayMs, std::function<void()> cb) override {
        m_cb = std::move(cb);
        m_t.start(delayMs);
    }

    void stop() override { m_t.stop(); m_cb = {}; }
    bool isActive() const override { return m_t.isActive(); }

private:
    QTimer                m_t;
    std::function<void()> m_cb;
};

class QtTimerFactory : public ITimerFactory {
public:
    std::unique_ptr<ITimer> create() override {
        return std::make_unique<QtTimer>();
    }

    void singleShot(int delayMs, std::function<void()> cb) override {
        // Capture-by-value since the lambda outlives this call.  The lambda
        // runs on the main thread via Qt's event loop.
        QTimer::singleShot(delayMs, [cb = std::move(cb)]() { if (cb) cb(); });
    }
};
