// my_socket_utils.h

#pragma once

namespace my {
template <typename T> struct no_copy {
    no_copy(const no_copy&) = delete;
    no_copy& operator=(const no_copy&) = delete;
    no_copy() = default;
    no_copy& operator=(no_copy&&) = default;
    no_copy(no_copy&&) = default;
};

} // namespace my
#include <chrono>
using namespace std::chrono_literals;

namespace my {

namespace timing {
    template <typename T, typename Rep, typename Period>
    T duration_cast(const std::chrono::duration<Rep, Period>& duration) {
        return duration.count() * static_cast<T>(Period::num)
            / static_cast<T>(Period::den);
    }
    template <typename Clock = std::chrono::steady_clock> class stopwatch {
        typename Clock::time_point last_;

        public:
        using Duration_t = typename Clock::duration;
        stopwatch() : last_(Clock::now()) {}

        void reset() { last_ = Clock::now(); }

        typename Clock::duration elapsed() const { return Clock::now() - last_; }
        typename std::chrono::milliseconds elapsed_ms() const {
            return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed());
        }
        typename std::chrono::seconds elapsed_secs() const {
            return std::chrono::duration_cast<std::chrono::seconds>(elapsed());
        }

        typename Clock::duration tick() {
            auto now = Clock::now();
            auto elapsed = now - last_;
            last_ = now;
            return elapsed;
        }
    };
    // hi res clock is NOT guaranteed to never go backwards.
    using stopwatch_t = stopwatch<std::chrono::steady_clock>;
} // namespace timing
} // namespace my
