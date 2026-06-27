#include "doctest.h"

#include "sls_idle.hpp"

// These tests pin the reaping contract that protects a stream key from being
// squatted by a connection that completes the SRT handshake but never delivers
// media (a player/preview pointed at the ingest port). The decision is pure, so
// it is exercised here without a live role or socket.

// Convention used below: connect happened at t=0 (last_activity_ms = 0) and no
// media has been received (last_recv_data_ms = 0) unless a test says otherwise.

TEST_CASE("first-data probation reaps a publisher that never sent media")
{
    const int first_data_ms = 2000;
    const int idle_s = 10;

    SUBCASE("not yet at the deadline -> keep")
    {
        CHECK_FALSE(sls_should_reap_role(1999, /*last_recv*/ 0, /*activity*/ 0, first_data_ms, idle_s));
    }
    SUBCASE("exactly at the deadline -> reap")
    {
        CHECK(sls_should_reap_role(2000, 0, 0, first_data_ms, idle_s));
    }
    SUBCASE("past the deadline -> reap")
    {
        CHECK(sls_should_reap_role(5000, 0, 0, first_data_ms, idle_s));
    }
    SUBCASE("probation fires long before the much larger idle timeout")
    {
        // 3s elapsed: under the 10s idle timeout, but past the 2s probation.
        CHECK(sls_should_reap_role(3000, 0, 0, first_data_ms, idle_s));
    }
}

TEST_CASE("the first media packet ends probation")
{
    // last_recv_data_ms != 0 means media has flowed; probation no longer
    // applies even though the probation window is tiny. last_activity_ms tracks
    // the last read, so a freshly delivering publisher is nowhere near idle.
    CHECK_FALSE(sls_should_reap_role(/*now*/ 10000, /*last_recv*/ 9990,
                                     /*activity*/ 9990, /*first_data*/ 2000,
                                     /*idle_s*/ 10));
}

TEST_CASE("a publisher that delivered then went quiet is reaped by the idle timeout")
{
    // Received data up to t=1000, now idle. activity marker sits at 1000.
    SUBCASE("within idle window -> keep")
    {
        CHECK_FALSE(sls_should_reap_role(10000, /*last_recv*/ 1000,
                                         /*activity*/ 1000, 2000, /*idle_s*/ 10));
    }
    SUBCASE("past idle window -> reap")
    {
        CHECK(sls_should_reap_role(11001, 1000, 1000, 2000, /*idle_s*/ 10));
    }
}

TEST_CASE("probation disabled (timeout <= 0) leaves a silent role to the idle timeout")
{
    // This is the player/puller default: first_data_timeout_ms = 0. A role that
    // has never "received" is then governed purely by the idle timeout.
    SUBCASE("disabled probation, within idle -> keep")
    {
        CHECK_FALSE(sls_should_reap_role(5000, 0, 0, /*first_data*/ 0, /*idle_s*/ 10));
    }
    SUBCASE("disabled probation, past idle -> reap")
    {
        CHECK(sls_should_reap_role(10000, 0, 0, /*first_data*/ 0, /*idle_s*/ 10));
    }
    SUBCASE("negative probation value also means disabled")
    {
        CHECK_FALSE(sls_should_reap_role(5000, 0, 0, /*first_data*/ -1, /*idle_s*/ 10));
    }
}

TEST_CASE("unlimited idle timeout (-1) never reaps once probation is satisfied or disabled")
{
    SUBCASE("media received, unlimited idle -> never reap")
    {
        CHECK_FALSE(sls_should_reap_role(1000000, /*last_recv*/ 1, /*activity*/ 1,
                                         /*first_data*/ 2000, /*idle_s*/ -1));
    }
    SUBCASE("probation disabled, unlimited idle -> never reap")
    {
        CHECK_FALSE(sls_should_reap_role(1000000, 0, 0, /*first_data*/ 0, /*idle_s*/ -1));
    }
}

TEST_CASE("probation still applies even when idle is unlimited")
{
    // A non-delivering publisher must not get a free pass just because idle is
    // disabled: probation is the only thing reaping a silent ingest squatter.
    CHECK(sls_should_reap_role(3000, /*last_recv*/ 0, /*activity*/ 0,
                               /*first_data*/ 2000, /*idle_s*/ -1));
}
