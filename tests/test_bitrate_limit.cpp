#include "doctest.h"

#include "SLSBitrateLimit.hpp"
#include "common.hpp"

// CSLSBitrateLimit is a pure-logic sliding-window rate limiter — it takes a
// caller-provided timestamp so tests do not need to sleep on the wall clock.
// We pin: accumulation within a window, the OK / VIOLATION / DISCONNECT
// transitions across the spike limit and the violation timeout, and that
// old data ages out when the window slides.

namespace
{
constexpr int KBPS = 1000;
}

TEST_CASE("CSLSBitrateLimit::init: rejects invalid parameters")
{
    CSLSBitrateLimit lim;
    CHECK(lim.init(-1) == SLS_ERROR);
    CHECK(lim.init(1000, 0) == SLS_ERROR);
    CHECK(lim.init(1000, 30, 0) == SLS_ERROR);
    CHECK(lim.init(1000, 30, 5000, 0.5f) == SLS_ERROR);
}

TEST_CASE("CSLSBitrateLimit: zero max_bitrate disables limiting, always OK")
{
    CSLSBitrateLimit lim;
    REQUIRE(lim.init(0) == SLS_OK);

    // Push a sustained burst worth ~80 Mbps; should still be OK because the
    // limiter is disabled.
    int64_t t = 0;
    for (int i = 0; i < 10; i++)
    {
        CHECK(lim.check_data_bitrate(10 * 1024 * 1024 / 10, t) ==
              CSLSBitrateLimit::BITRATE_OK);
        t += 100;
    }
}

TEST_CASE("CSLSBitrateLimit: traffic below the spike limit stays OK")
{
    CSLSBitrateLimit lim;
    // 1000 kbps cap, 2x spike => spike limit 2000 kbps.
    REQUIRE(lim.init(1000 * KBPS, 30, 5000, 2.0f) == SLS_OK);

    int64_t t = 0;
    // Feed 500 kbps for several seconds: 62_500 bytes/s = 6_250 bytes/100ms.
    for (int i = 0; i < 60; i++)
    {
        auto rc = lim.check_data_bitrate(6250, t);
        CHECK(rc == CSLSBitrateLimit::BITRATE_OK);
        t += 100;
    }
    auto stats = lim.get_stats();
    CHECK_FALSE(stats.is_in_violation);
    CHECK(stats.total_bytes_received > 0);
}

TEST_CASE("CSLSBitrateLimit: bursts above spike limit raise VIOLATION but not DISCONNECT before timeout")
{
    CSLSBitrateLimit lim;
    // 100 kbps cap, 2x spike => spike limit 200 kbps. Violation timeout 5s.
    REQUIRE(lim.init(100, 5, 5000, 2.0f) == SLS_OK);

    int64_t t = 0;
    // 1 MB/s sustained = ~8000 kbps, well over the 200 kbps spike limit.
    CSLSBitrateLimit::BitrateCheckResult last = CSLSBitrateLimit::BITRATE_OK;
    bool saw_violation = false;
    for (int i = 0; i < 20; i++) // 2 seconds of traffic, below 5s timeout
    {
        last = lim.check_data_bitrate(100 * 1024, t);
        if (last == CSLSBitrateLimit::BITRATE_VIOLATION)
            saw_violation = true;
        // Must not have hit DISCONNECT inside the 5s timeout window.
        CHECK(last != CSLSBitrateLimit::BITRATE_DISCONNECT);
        t += 100;
    }
    CHECK(saw_violation);
    CHECK(lim.get_stats().is_in_violation);
}

TEST_CASE("CSLSBitrateLimit: sustained violation past timeout escalates to DISCONNECT")
{
    CSLSBitrateLimit lim;
    REQUIRE(lim.init(100, 2, 5000, 2.0f) == SLS_OK); // 2s violation timeout

    int64_t t = 0;
    bool got_disconnect = false;
    // 3 seconds of overrun traffic — past the 2s timeout.
    for (int i = 0; i < 30; i++)
    {
        auto rc = lim.check_data_bitrate(100 * 1024, t);
        if (rc == CSLSBitrateLimit::BITRATE_DISCONNECT)
        {
            got_disconnect = true;
            break;
        }
        t += 100;
    }
    CHECK(got_disconnect);
}

TEST_CASE("CSLSBitrateLimit: old data ages out so a quiet period returns to OK")
{
    CSLSBitrateLimit lim;
    REQUIRE(lim.init(100, 30, 5000, 2.0f) == SLS_OK);

    // The limiter's internal cleanup is gated by m_last_cleanup_time which
    // init() seeds from sls_gettime_ms() (wall clock). Anchor injected
    // timestamps to wall clock so the cleanup branch can actually trigger
    // when we advance time past the 5s window.
    int64_t t0 = sls_gettime_ms();
    int64_t t = t0;
    for (int i = 0; i < 5; i++)
    {
        (void)lim.check_data_bitrate(100 * 1024, t);
        t += 100;
    }
    CHECK(lim.get_stats().is_in_violation);

    // Advance past both the 5s sliding window and the 1s cleanup cadence.
    t = t0 + 7000;
    auto rc = lim.check_data_bitrate(10, t);
    CHECK(rc == CSLSBitrateLimit::BITRATE_OK);
    CHECK_FALSE(lim.get_stats().is_in_violation);
}

TEST_CASE("CSLSBitrateLimit::reset_stats clears counters")
{
    CSLSBitrateLimit lim;
    REQUIRE(lim.init(1000, 30, 5000, 2.0f) == SLS_OK);
    int64_t t = 0;
    lim.check_data_bitrate(1024, t);
    CHECK(lim.get_stats().total_bytes_received >= 1024);
    lim.reset_stats();
    CHECK(lim.get_stats().total_bytes_received == 0);
    CHECK_FALSE(lim.get_stats().is_in_violation);
}
