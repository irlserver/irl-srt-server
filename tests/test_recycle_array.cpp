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

// Publisher reconnect scenario: the fork keeps player roles (and their
// SLSRecycleArrayID) alive across a publisher takeover, but the ring is
// deleted and recreated with the publisher. A reader carrying its old
// anchor into the new ring must be re-anchored at the live write head —
// draining from the stale position replays the previous session's bytes
// out of the recycled allocation to a live viewer.
TEST_CASE("CSLSRecycleArray: reader surviving ring teardown/recreate re-anchors at live head")
{
    const int RING = 4096;
    auto *ring_a = new CSLSRecycleArray;
    ring_a->setSize(RING);

    SLSRecycleArrayID id = fresh_reader();
    anchor(*ring_a, id);

    // Old session: the viewer watches (drains) some content.
    char old_payload[512];
    std::memset(old_payload, 'O', sizeof(old_payload));
    CHECK(ring_a->put(old_payload, sizeof(old_payload)) == (int)sizeof(old_payload));
    char out[1024];
    CHECK(ring_a->get(out, sizeof(out), &id, 0) == (int)sizeof(old_payload));

    // Publisher reconnects: old ring destroyed, fresh ring for the same key.
    delete ring_a;
    CSLSRecycleArray ring_b;
    ring_b.setSize(RING);

    // The new session has already written a little before the reader's next
    // poll. With the stale anchor (nReadPos=512 > write head=256) the old code
    // computed ~RING bytes of "ready" data and copied from the dead offset.
    char new_head[256];
    std::memset(new_head, 'N', sizeof(new_head));
    CHECK(ring_b.put(new_head, sizeof(new_head)) == (int)sizeof(new_head));

    // First get() against the recreated ring: re-anchor only, no bytes.
    CHECK(ring_b.get(out, sizeof(out), &id, 0) == SLS_OK);

    // From the rejoin point the viewer receives exactly the live data.
    char live[128];
    std::memset(live, 'L', sizeof(live));
    CHECK(ring_b.put(live, sizeof(live)) == (int)sizeof(live));
    std::memset(out, 0, sizeof(out));
    int got = ring_b.get(out, sizeof(out), &id, 0);
    CHECK(got == (int)sizeof(live));
    CHECK(std::memcmp(out, live, sizeof(live)) == 0);
}

// Same scenario but the recreated ring is smaller than the old one, so the
// stale nReadPos points past the entire new buffer. Without re-anchoring this
// is a heap overread (caught by ASan), not just a replay.
TEST_CASE("CSLSRecycleArray: stale reader against a smaller recreated ring cannot overread")
{
    auto *big = new CSLSRecycleArray;
    big->setSize(4096);
    // Push the write head deep into the big ring before anchoring, so the
    // anchor lands far beyond the small ring's extent.
    char fill[3000];
    std::memset(fill, 'F', sizeof(fill));
    CHECK(big->put(fill, sizeof(fill)) == (int)sizeof(fill));
    SLSRecycleArrayID id = fresh_reader();
    anchor(*big, id); // nReadPos = 3000
    delete big;

    CSLSRecycleArray small;
    small.setSize(64);
    char tiny[16];
    std::memset(tiny, 't', sizeof(tiny));
    CHECK(small.put(tiny, sizeof(tiny)) == (int)sizeof(tiny));

    char out[64];
    CHECK(small.get(out, sizeof(out), &id, 0) == SLS_OK); // re-anchor, no copy
    CHECK(small.put(tiny, sizeof(tiny)) == (int)sizeof(tiny));
    CHECK(small.get(out, sizeof(out), &id, 0) == (int)sizeof(tiny));
    CHECK(std::memcmp(out, tiny, sizeof(tiny)) == 0);
}

// setSize() replaces the buffer wholesale, which is the same invalidation as a
// teardown/recreate from a reader's point of view.
TEST_CASE("CSLSRecycleArray: setSize invalidates readers anchored on the old buffer")
{
    CSLSRecycleArray ring;
    ring.setSize(1024);

    SLSRecycleArrayID id = fresh_reader();
    anchor(ring, id);
    char chunk[200];
    std::memset(chunk, 'A', sizeof(chunk));
    CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));

    ring.setSize(2048);

    char out[512];
    CHECK(ring.get(out, sizeof(out), &id, 0) == SLS_OK); // re-anchor, no copy

    std::memset(chunk, 'B', sizeof(chunk));
    CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));
    CHECK(ring.get(out, sizeof(out), &id, 0) == (int)sizeof(chunk));
    CHECK(std::memcmp(out, chunk, sizeof(chunk)) == 0);
}

// Backstop for the generation check: a reader whose byte counter is ahead of
// the ring's monotonic counter cannot belong to this incarnation. It must be
// resynced, never used to index the buffer.
TEST_CASE("CSLSRecycleArray: reader counter ahead of the ring resyncs instead of reading stale bytes")
{
    CSLSRecycleArray ring;
    ring.setSize(1024);

    SLSRecycleArrayID id = fresh_reader();
    anchor(ring, id);

    char chunk[100];
    std::memset(chunk, 'D', sizeof(chunk));
    CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));

    // Corrupt the reader's counter so the delta goes negative while the
    // generation still matches.
    id.nDataCount += 1000000;

    char out[256];
    CHECK(ring.get(out, sizeof(out), &id, 0) == SLS_OK); // resync, no copy
    CHECK(ring.get_overrun_count() >= 1);

    std::memset(chunk, 'E', sizeof(chunk));
    CHECK(ring.put(chunk, sizeof(chunk)) == (int)sizeof(chunk));
    CHECK(ring.get(out, sizeof(out), &id, 0) == (int)sizeof(chunk));
    CHECK(std::memcmp(out, chunk, sizeof(chunk)) == 0);
}
