#include "doctest.h"

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

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
} // namespace

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

TEST_CASE("CSLSRecycleArray: reader backlog and high-water track how far a reader is behind")
{
    CSLSRecycleArray ring;
    ring.setSize(4096);

    SLSRecycleArrayID id = fresh_reader();
    // A reader that has not anchored reports no backlog (avoids a bogus huge
    // value from the uninitialised nDataCount before the first snapshot).
    CHECK(ring.get_reader_backlog(&id) == 0);
    anchor(ring, id);
    CHECK(ring.get_reader_backlog(&id) == 0);

    char chunk[100];
    std::memset(chunk, 'Q', sizeof(chunk));
    CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));

    // Writer is now 100 bytes ahead of this reader: that is its backlog.
    CHECK(ring.get_reader_backlog(&id) == 100);

    char out[256];
    CHECK(ring.get(out, sizeof(out), &id, 0) == 100);

    // Drained: caught up to the write head, backlog back to 0, but the
    // high-water remembers the peak for /stats.
    CHECK(ring.get_reader_backlog(&id) == 0);
    CHECK(ring.get_max_reader_backlog(false) >= 100);

    // clear=true returns the peak and resets, so the next interval starts fresh.
    CHECK(ring.get_max_reader_backlog(true) >= 100);
    CHECK(ring.get_max_reader_backlog(false) == 0);
}

TEST_CASE("CSLSRecycleArray: viewer backpressure events accumulate and clear")
{
    CSLSRecycleArray ring;
    ring.setSize(1024);

    CHECK(ring.get_viewer_backpressure_events(false) == 0);
    ring.report_viewer_backpressure();
    ring.report_viewer_backpressure();
    CHECK(ring.get_viewer_backpressure_events(false) == 2);
    // clear=true drains the counter so /stats can report a per-interval delta.
    CHECK(ring.get_viewer_backpressure_events(true) == 2);
    CHECK(ring.get_viewer_backpressure_events(false) == 0);
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

// Locks the under-lock bFirst snapshot. get()'s first call samples the write
// head (m_nWritePos, a plain int guarded only by the rwlock) together with the
// byte counter under the read lock, so a concurrent put() cannot tear the
// (pos, count) pair. A writer thread hammers put() while many readers take
// their first snapshot at the same instant and then drain. Under TSan this is
// a race detector for the snapshot: if a future change moved the m_nWritePos
// read out of the read lock, TSan would flag it against put()'s write-locked
// m_nWritePos update. Functionally, every aligned get() must stay non-negative
// and CHUNK-aligned (a torn snapshot would mis-size the copy or spuriously
// trip overrun). doctest macros are not thread-safe, so threads only record
// outcomes into atomics and all CHECKs run on the main thread after join.
TEST_CASE("CSLSRecycleArray: bFirst snapshot stays consistent under concurrent put/get")
{
    const int RING = 64 * 188; // room for real copies AND frequent laps
    const int CHUNK = 188;     // one TS packet; drives aligned get()
    const int WRITER_ITERS = 5000;
    const int N_READERS = 8;

    CSLSRecycleArray ring;
    ring.setSize(RING);

    std::atomic<bool> start{false};
    std::atomic<bool> writer_done{false};
    std::atomic<int> anchor_ok{0};
    std::atomic<int> drain_ok{0};

    std::thread writer(
        [&]
        {
            char chunk[CHUNK];
            std::memset(chunk, 'Z', sizeof(chunk));
            while (!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            for (int i = 0; i < WRITER_ITERS; i++)
                ring.put(chunk, CHUNK);
            writer_done.store(true, std::memory_order_release);
        });

    std::vector<std::thread> readers;
    readers.reserve(N_READERS);
    for (int r = 0; r < N_READERS; r++)
    {
        readers.emplace_back(
            [&]
            {
                SLSRecycleArrayID id{};
                id.bFirst = true;
                char out[CHUNK * 4];
                while (!start.load(std::memory_order_acquire))
                    std::this_thread::yield();

                // First get(): the bFirst snapshot, concurrent with put().
                int rc = ring.get(out, sizeof(out), &id, CHUNK);
                if (rc == SLS_OK && !id.bFirst)
                    anchor_ok.fetch_add(1, std::memory_order_relaxed);

                bool ok = true;
                for (int i = 0; i < WRITER_ITERS + 100; i++)
                {
                    int g = ring.get(out, sizeof(out), &id, CHUNK);
                    if (g < 0 || (g % CHUNK) != 0 || g > (int)sizeof(out))
                    {
                        ok = false;
                        break;
                    }
                    if (writer_done.load(std::memory_order_acquire) && g == 0)
                        break;
                }
                if (ok)
                    drain_ok.fetch_add(1, std::memory_order_relaxed);
            });
    }

    start.store(true, std::memory_order_release);
    writer.join();
    for (auto &t : readers)
        t.join();

    CHECK(anchor_ok.load() == N_READERS);
    CHECK(drain_ok.load() == N_READERS);
}
