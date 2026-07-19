#include "doctest.h"

#include <chrono>
#include <thread>

#include "SLSLogRateLimiter.hpp"

// The limiter bounds per-key log volume under hot event loops (an OBS media
// source retrying a dead stream reconnects about once per second with no
// backoff). Policy under test: the first `threshold` events of a window log
// verbatim, after which at most one line per `min_interval_ms` gets through
// regardless of event rate; a new window starts fresh.

TEST_CASE("CSLSLogRateLimiter: first threshold events log verbatim, then output is time-bounded")
{
    // 60s window, 3 verbatim, then min 50ms between logged lines.
    CSLSLogRateLimiter limiter(60000, 3, 50);
    CSLSLogRateLimiter::EventStats stats{};

    // Events 1..3: verbatim.
    CHECK(limiter.should_log("peer:pkfail", stats));
    CHECK(stats.count == 1);
    CHECK(limiter.should_log("peer:pkfail", stats));
    CHECK(stats.count == 2);
    CHECK(limiter.should_log("peer:pkfail", stats));
    CHECK(stats.count == 3);

    // A hot burst right after: suppressed, no matter how many events.
    int logged = 0;
    for (int i = 0; i < 50; i++)
        if (limiter.should_log("peer:pkfail", stats))
            logged++;
    CHECK(logged == 0);
    CHECK(stats.total_suppressed > 0);

    // After the interval elapses, exactly one line gets through, then the
    // burst is suppressed again.
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    logged = 0;
    for (int i = 0; i < 50; i++)
        if (limiter.should_log("peer:pkfail", stats))
            logged++;
    CHECK(logged == 1);
    // The line that got through reports the full event count for the window.
    CHECK(stats.count > 50);
}

TEST_CASE("CSLSLogRateLimiter: keys are independent and a new window resets verbatim logging")
{
    // Tiny 80ms window so expiry is testable without long sleeps.
    CSLSLogRateLimiter limiter(80, 2, 1000);
    CSLSLogRateLimiter::EventStats stats{};

    CHECK(limiter.should_log("a", stats));
    CHECK(limiter.should_log("a", stats));
    CHECK_FALSE(limiter.should_log("a", stats)); // 3rd within window: suppressed

    // A different key is unaffected by key "a" being hot.
    CHECK(limiter.should_log("b", stats));

    // Window expiry: key "a" logs verbatim again with a reset count.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    CHECK(limiter.should_log("a", stats));
    CHECK(stats.count == 1);
}
