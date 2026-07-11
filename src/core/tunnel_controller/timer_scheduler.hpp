#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace exv::core {

/// A simple thread-based timer scheduler.
///
/// Schedules callbacks to run after a specified delay.  Uses a dedicated
/// background thread and condition_variable for sleeping, so no external
/// library (Boost.Asio, etc.) is required.
///
/// Thread safety: schedule() and cancel_all() may be called from any thread.
/// Callbacks execute on the scheduler's own background thread.
class TimerScheduler {
public:
    using Callback = std::function<void()>;

    TimerScheduler();
    ~TimerScheduler();

    TimerScheduler(const TimerScheduler&) = delete;
    TimerScheduler& operator=(const TimerScheduler&) = delete;

    /// Schedule a callback to run after @p delay.  If cancel_all() is called
    /// before the delay elapses, the callback will not execute.
    void schedule(std::chrono::milliseconds delay, Callback cb);

    /// Cancel all pending timers.  Any callbacks that have not yet started
    /// executing will be discarded.  Callbacks already in-flight will finish.
    void cancel_all();

    /// Cancel pending timers and wait for any in-flight callback to finish.
    /// If called from the scheduler callback thread, it only clears pending
    /// timers to avoid waiting on itself.
    void cancel_all_and_wait();

    /// Stop the scheduler worker and discard all pending timers. After this,
    /// schedule() is a no-op. Safe to call more than once.
    void shutdown();

    /// Returns the number of pending (not yet fired) timers.  Useful for
    /// testing.
    std::size_t pending_count() const;

private:
    void worker_loop();

    mutable std::mutex              mtx_;
    std::condition_variable         cv_;
    std::condition_variable         done_cv_;    // notified when a timer fires
    std::thread                     worker_;
    std::thread::id                 worker_id_;
    bool                            stopped_ = false;
    std::size_t                     active_callbacks_ = 0;

    struct PendingTimer {
        std::chrono::steady_clock::time_point fire_at;
        Callback                             cb;
        std::size_t                          id;      // for cancellation tracking
    };

    std::vector<PendingTimer>       pending_;
    std::atomic<std::size_t>        next_id_{1};
};

} // namespace exv::core
