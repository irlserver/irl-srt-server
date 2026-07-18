#include "doctest.h"

#include <cstdint>

#include "SLSMapData.hpp"
#include "common.hpp"

// CSLSMapData owns the per-stream publisher rings and the global ring budget
// (stream-count + cumulative-bytes caps) that guard against pre-auth ring OOM.
// These tests pin the two invariants the security fix relies on: caps refuse
// allocation past their limit, and the budget counters stay exactly
// alloc-balanced across idempotent re-adds and removals.

TEST_CASE("CSLSMapData::add refuses new streams past the stream-count cap")
{
    CSLSMapData m;
    m.set_caps(2, 0); // 0 = unlimited bytes; cap on count only

    char s1[] = "app/s1";
    char s2[] = "app/s2";
    char s3[] = "app/s3";

    CHECK(m.add(s1) == SLS_OK);
    CHECK(m.add(s2) == SLS_OK);
    CHECK(m.get_stream_count() == 2);

    CHECK(m.add(s3) == SLS_ERROR);    // third stream over the cap of 2
    CHECK(m.get_stream_count() == 2); // a refused add must not change the count
}

TEST_CASE("CSLSMapData::add refuses new streams past the total ring-memory cap")
{
    // Probe the default per-stream ring size (no bitrate/latency hint).
    CSLSMapData probe;
    probe.set_caps(0, 0);
    char pk[] = "app/probe";
    CHECK(probe.add(pk) == SLS_OK);
    int64_t ring = probe.get_total_ring_bytes();
    CHECK(ring > 0);

    // Budget for exactly one default ring (1.5x leaves no room for a second).
    CSLSMapData m;
    m.set_caps(0, ring + ring / 2);
    char a[] = "app/a";
    char b[] = "app/b";

    CHECK(m.add(a) == SLS_OK);
    CHECK(m.get_total_ring_bytes() == ring);

    CHECK(m.add(b) == SLS_ERROR); // second ring would exceed the byte cap
    CHECK(m.get_stream_count() == 1);
    CHECK(m.get_total_ring_bytes() == ring); // refusal leaves the budget intact
}

TEST_CASE("CSLSMapData budget is alloc-balanced across add / dupe-add / remove")
{
    CSLSMapData m;
    m.set_caps(0, 0); // unlimited

    char k[] = "app/dup";

    CHECK(m.add(k) == SLS_OK);
    CHECK(m.get_stream_count() == 1);
    int64_t after_add = m.get_total_ring_bytes();
    CHECK(after_add > 0);

    // Idempotent re-add (the puller's connect-time double-add pattern) must
    // hit the early-return and NOT double-count the budget.
    CHECK(m.add(k) == SLS_OK);
    CHECK(m.get_stream_count() == 1);
    CHECK(m.get_total_ring_bytes() == after_add);

    CHECK(m.remove(k) == SLS_OK);
    CHECK(m.get_stream_count() == 0);
    CHECK(m.get_total_ring_bytes() == 0);
}

TEST_CASE("CSLSMapData::clear zeroes the budget for every freed ring")
{
    CSLSMapData m;
    m.set_caps(0, 0);

    char k1[] = "app/c1";
    char k2[] = "app/c2";
    CHECK(m.add(k1) == SLS_OK);
    CHECK(m.add(k2) == SLS_OK);
    CHECK(m.get_stream_count() == 2);
    CHECK(m.get_total_ring_bytes() > 0);

    m.clear();
    CHECK(m.get_stream_count() == 0);
    CHECK(m.get_total_ring_bytes() == 0);
}
