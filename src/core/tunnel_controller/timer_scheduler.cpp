#include "timer_scheduler.hpp"

#include <algorithm>
#include <cassert>

namespace exv::core {

TimerScheduler::TimerScheduler() {
    worker_ = std::thread(&TimerScheduler::worker_loop, this);
}

TimerScheduler::~TimerScheduler() {
    shutdown();
}

void TimerScheduler::shutdown() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (stopped_) {
            return;
        }
        stopped_ = true;
        pending_.clear();
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void TimerScheduler::schedule(std::chrono::milliseconds delay, Callback cb) {
    auto fire_at = std::chrono::steady_clock::now() + delay;
    auto id      = next_id_.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (stopped_) {
            return;
        }
        pending_.push_back({fire_at, std::move(cb), id});
    }
    cv_.notify_all();
}

void TimerScheduler::cancel_all() {
    std::lock_guard<std::mutex> lk(mtx_);
    pending_.clear();
}

void TimerScheduler::cancel_all_and_wait() {
    std::unique_lock<std::mutex> lk(mtx_);
    pending_.clear();
    if (std::this_thread::get_id() == worker_id_) {
        return;
    }
    done_cv_.wait(lk, [this] {
        return active_callbacks_ == 0;
    });
    pending_.clear();
}

std::size_t TimerScheduler::pending_count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return pending_.size();
}

void TimerScheduler::worker_loop() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        worker_id_ = std::this_thread::get_id();
    }

    for (;;) {
        std::unique_lock<std::mutex> lk(mtx_);

        // Wait until we have at least one pending timer or we are stopped.
        cv_.wait(lk, [this] {
            return stopped_ || !pending_.empty();
        });

        if (stopped_ && pending_.empty()) {
            return;
        }

        // Find the timer that should fire next (earliest deadline).
        auto earliest = std::min_element(pending_.begin(), pending_.end(),
            [](const PendingTimer& a, const PendingTimer& b) {
                return a.fire_at < b.fire_at;
            });

        assert(earliest != pending_.end());

        const auto now = std::chrono::steady_clock::now();
        if (earliest->fire_at <= now) {
            // Ready to fire — move callback out, remove from pending, unlock,
            // then execute outside the lock.
            Callback cb = std::move(earliest->cb);
            pending_.erase(earliest);
            ++active_callbacks_;
            lk.unlock();

            if (cb) {
                cb();
            }

            lk.lock();
            --active_callbacks_;
            done_cv_.notify_all();
        } else {
            // Copy the deadline out of pending_. schedule() may reallocate the
            // vector while wait_until releases the lock, invalidating iterators
            // and references into the container.
            const auto wake_at = earliest->fire_at;
            cv_.wait_until(lk, wake_at, [this, wake_at] {
                if (stopped_) return true;

                auto it = std::min_element(pending_.begin(), pending_.end(),
                    [](const PendingTimer& a, const PendingTimer& b) {
                        return a.fire_at < b.fire_at;
                    });
                if (it == pending_.end()) return true;

                return it->fire_at < wake_at ||
                       std::chrono::steady_clock::now() >= it->fire_at;
            });
        }
    }
}

} // namespace exv::core
