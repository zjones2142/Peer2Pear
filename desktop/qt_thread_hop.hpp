#pragma once
//
// qt_thread_hop — marshal a callable onto a QObject's owning thread.
//
// QNetworkAccessManager and QWebSocket are pinned to the thread that
// owns them; calling them from ICE/QUIC/msquic worker threads triggers
// "QObject: Cannot create children for a parent that is in a different
// thread" and the resulting QNetworkReply or send is silently dropped.
// QtHttpClient and QtWebSocket both wrap mutating entry points with
// this helper so per-call hopping logic doesn't have to be duplicated.
//
// Fast path: if the caller is already on the QObject's owning thread,
// the callable runs synchronously and there's no event-loop round trip.

#include <QMetaObject>
#include <QObject>
#include <QThread>

#include <utility>

namespace p2p {

template <class F>
void runOnOwnerThread(QObject* owner, F&& fn) {
    if (QThread::currentThread() == owner->thread()) {
        fn();
    } else {
        QMetaObject::invokeMethod(owner, std::forward<F>(fn),
                                   Qt::QueuedConnection);
    }
}

}  // namespace p2p
