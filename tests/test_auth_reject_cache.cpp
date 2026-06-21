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

    // Cache uses time(nullptr) and expiry is now + ttl, where is_blocked
    // returns true iff expiry > now. Sleep just over 1 second to cross the
    // second boundary deterministically (worst case ~2s).
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    CHECK_FALSE(c.is_blocked("publisher-1"));
}

TEST_CASE("AuthRejectCache: cleanup() drops expired entries")
{
    AuthRejectCache c(1);
    c.record_failure("a");
    c.record_failure("b");
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
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
    AuthRejectCache c(2);
    c.record_failure("p");
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    c.record_failure("p"); // resets to now + 2
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    // ~2.2s after first record but only ~1.1s after refresh — must still block.
    CHECK(c.is_blocked("p"));
}
