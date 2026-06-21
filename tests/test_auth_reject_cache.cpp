#include "doctest.h"

#include <chrono>
#include <thread>

#include "auth_reject_cache.hpp"

// Negative cache of streamids that recently failed webhook authorization.
// Resolution is wall-clock seconds (uses time(nullptr)), so TTL tests rely
// on small sleeps. Keep total test time bounded.

TEST_CASE("AuthRejectCache: recorded streamid is blocked")
{
    AuthRejectCache c(30);
    c.record_failure("publisher-1");
    CHECK(c.is_blocked("publisher-1"));
}

TEST_CASE("AuthRejectCache: unknown streamid is not blocked")
{
    AuthRejectCache c(30);
    c.record_failure("publisher-1");
    CHECK_FALSE(c.is_blocked("other-publisher"));
}

TEST_CASE("AuthRejectCache: empty streamid is never blocked and never recorded")
{
    AuthRejectCache c(30);
    c.record_failure(""); // no-op
    CHECK_FALSE(c.is_blocked(""));
    // Empty key being recorded would also be wrong; confirm via observable
    // side effect — a non-empty same prefix is unaffected.
    CHECK_FALSE(c.is_blocked("anything"));
}

TEST_CASE("AuthRejectCache: entry expires after TTL elapses")
{
    AuthRejectCache c(1); // 1 second TTL
    c.record_failure("publisher-1");
    CHECK(c.is_blocked("publisher-1"));

    // Cache uses time(nullptr) (whole-second resolution) and is_blocked
    // returns true iff expiry > now. With TTL=1 the entry can survive for
    // anywhere between just-over-1s and just-under-2s of wall time
    // depending on where the second boundary lands, so sleep TTL + 1.5s
    // to guarantee at least one boundary crossing past expiry.
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    CHECK_FALSE(c.is_blocked("publisher-1"));
}

TEST_CASE("AuthRejectCache: cleanup() drops expired entries")
{
    AuthRejectCache c(1);
    c.record_failure("a");
    c.record_failure("b");
    // Same TTL + 1.5s rule as the expiry test above: anything shorter can
    // straddle a second boundary and leave the entries alive.
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    c.cleanup();
    // Lazy expiry on is_blocked would also report false; cleanup() simply
    // makes the drop eager. We assert via the public is_blocked contract.
    CHECK_FALSE(c.is_blocked("a"));
    CHECK_FALSE(c.is_blocked("b"));
}

TEST_CASE("AuthRejectCache: set_ttl ignores non-positive values")
{
    AuthRejectCache c(30);
    c.set_ttl(0);    // ignored
    c.set_ttl(-1);   // ignored
    c.record_failure("p");
    // Still blocked under the original 30s TTL.
    CHECK(c.is_blocked("p"));
}

TEST_CASE("AuthRejectCache: re-recording refreshes the expiry")
{
    // Whole-second resolution means any positive is_blocked() check after a
    // sleep can straddle a boundary. Drive the test off two unambiguous
    // states instead: first observe the entry as expired (TTL + 1.5s slop),
    // then re-record and check immediately — no boundary crossed between
    // the refresh and the assertion.
    AuthRejectCache c(1);
    c.record_failure("p");
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    CHECK_FALSE(c.is_blocked("p"));
    c.record_failure("p");      // refresh
    CHECK(c.is_blocked("p"));   // immediate, no sleep
}
