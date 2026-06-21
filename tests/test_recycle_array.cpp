#include "doctest.h"

#include <cstring>
#include <string>

#include "SLSRecycleArray.hpp"
#include "common.hpp"

// CSLSRecycleArray is the publisher->viewer ring buffer at the centre of the
// data path. The interesting bugs are: wrap-around producing two-segment
// reads, and reader overrun handing back corrupt bytes when the writer has
// lapped the buffer. Both are exercised below.

namespace
{
SLSRecycleArrayID fresh_reader()
{
    SLSRecycleArrayID r{};
    r.bFirst = true;
    return r;
}

// First get() after bFirst=true only snapshots write head; data must be put
// AFTER this call to be visible to the reader.
void anchor(CSLSRecycleArray &ring, SLSRecycleArrayID &id)
{
    char tmp[1];
    int rc = ring.get(tmp, 1, &id, 0);
    CHECK(rc == SLS_OK);
    CHECK_FALSE(id.bFirst);
}
}

TEST_CASE("CSLSRecycleArray: put then get round-trips bytes without wrap")
{
    CSLSRecycleArray ring;
    ring.setSize(1024);

    SLSRecycleArrayID id = fresh_reader();
    anchor(ring, id);

    const char payload[] = "hello-world-12345";
    const int n = (int)sizeof(payload) - 1;
    CHECK(ring.put(const_cast<char *>(payload), n) == n);

    char out[64] = {0};
    int got = ring.get(out, sizeof(out), &id, 0);
    CHECK(got == n);
    CHECK(std::memcmp(out, payload, n) == 0);
}

TEST_CASE("CSLSRecycleArray: put that crosses the seam reassembles correctly on get")
{
    // Pick a tiny ring so it's easy to force the writer near the seam.
    const int RING = 16;
    CSLSRecycleArray ring;
    ring.setSize(RING);

    // First, advance the write position to near the end with a fill that is
    // discarded by the reader anchor below.
    char fill[12];
    std::memset(fill, 'A', sizeof(fill));
    CHECK(ring.put(fill, sizeof(fill)) == (int)sizeof(fill));

    SLSRecycleArrayID id = fresh_reader();
    anchor(ring, id); // snapshot: writer at 12, dataCount at 12

    // Now write 10 bytes — 4 fit before the seam, the remaining 6 wrap.
    char payload[10];
    for (int i = 0; i < 10; i++)
        payload[i] = (char)('a' + i);
    CHECK(ring.put(payload, sizeof(payload)) == (int)sizeof(payload));

    char out[10] = {0};
    int got = ring.get(out, sizeof(out), &id, 0);
    CHECK(got == 10);
    CHECK(std::memcmp(out, payload, 10) == 0);
}

TEST_CASE("CSLSRecycleArray: reader that fell behind by > ring size is resynced (overrun)")
{
    const int RING = 64;
    CSLSRecycleArray ring;
    ring.setSize(RING);

    SLSRecycleArrayID id = fresh_reader();
    anchor(ring, id);

    // Writer laps the reader: push more than RING bytes worth of data.
    char chunk[16];
    std::memset(chunk, 'X', sizeof(chunk));
    for (int i = 0; i < 8; i++) // 128 bytes total > 64
        CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));

    // The reader is now > RING bytes behind. get() must report overrun (rc=0,
    // i.e. SLS_OK) and resync to the write head, NOT return wrapped garbage.
    char out[64];
    int got = ring.get(out, sizeof(out), &id, 0);
    CHECK(got == SLS_OK); // overrun path returns SLS_OK, no copy
    CHECK(ring.get_overrun_count() >= 1);
}

TEST_CASE("CSLSRecycleArray: zero-length put is rejected")
{
    CSLSRecycleArray ring;
    ring.setSize(1024);
    char buf[1] = {0};
    CHECK(ring.put(buf, 0) == SLS_ERROR);
    CHECK(ring.put(buf, -5) == SLS_ERROR);
}

TEST_CASE("CSLSRecycleArray: oversized put (len > ring size) is rejected")
{
    CSLSRecycleArray ring;
    ring.setSize(32);
    char buf[64] = {0};
    CHECK(ring.put(buf, 64) == SLS_ERROR);
}

TEST_CASE("CSLSRecycleArray: null data pointer is rejected")
{
    CSLSRecycleArray ring;
    ring.setSize(64);
    CHECK(ring.put(nullptr, 8) == SLS_ERROR);
}
