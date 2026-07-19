
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Edward.Wu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <atomic>
#include <cstdint>

#include "common.hpp"
#include "SLSLock.hpp"

struct SLSRecycleArrayID
{
    int nReadPos;
    int64_t nDataCount;
    bool bFirst;
    // Identity of the ring this reader anchored on. Player roles outlive a
    // publisher reconnect (takeover), but the ring is deleted and recreated
    // with the publisher; a reader whose generation does not match the ring it
    // is handed must be re-anchored, or its stale nReadPos/nDataCount would
    // let it drain bytes from the recycled buffer that the new session never
    // wrote — seen by viewers as a replay of the previous session. 0 means
    // "never anchored" and matches no live ring.
    uint64_t nGeneration;
};

/**
 * CSLSRecycleArray
 */
class CSLSRecycleArray
{
public:
    CSLSRecycleArray();
    ~CSLSRecycleArray();

public:
    int put(char *data, int len);
    int get(char *dst, int size, SLSRecycleArrayID *read_id, int aligned = 0);

    void setSize(int n);
    int count();
    int get_data_size() const
    {
        return m_nDataSize;
    }

    int64_t get_last_read_time();
    // Number of times a reader was detected to have fallen far enough behind
    // the writer that the buffer wrapped past them. When this fires the
    // reader's position is forcibly advanced to the current write head so
    // they resume with fresh data instead of silently reading garbage.
    // Atomic so /stats can read it without taking m_rwclock — that lock
    // serialises with put() and used to be a periodic source of viewer
    // delivery stalls when the HTTP probe hit /stats every 10-15s.
    int64_t get_overrun_count() const
    {
        return m_overrun_count.load(std::memory_order_relaxed);
    }

    // How many bytes this specific reader is behind the write head right now,
    // i.e. the backlog it would burst out on its next drain. 0 for a reader
    // that has not yet anchored (bFirst) or has caught up. Clamped to the
    // buffer size because a reader further behind than that has already been
    // (or is about to be) overrun-resynced. Lock-free: m_nDataCount is atomic
    // and read_id is owned by the calling worker thread. Diagnostic only — this
    // is the metric that answers "is SLS holding a catch-up burst for a viewer".
    int64_t get_reader_backlog(const SLSRecycleArrayID *read_id) const;

    // High-water of get_reader_backlog seen across ALL readers since the last
    // clear. This is the per-stream signal an operator polls to see whether any
    // viewer fell far enough behind that its eventual catch-up drain is bursty
    // (visible to that viewer as a time-skip). clear=true resets it so /stats
    // can report a per-interval peak instead of a lifetime max.
    int64_t get_max_reader_backlog(bool clear = false);

    // Aggregate egress backpressure across the viewers reading this ring. The
    // per-role counter lived on the player role, but /stats only enumerates
    // publishers, so it was never surfaced. Players report here (a shared,
    // publisher-visible object) on each EASYNCSND so publisher /stats can show
    // real viewer backpressure instead of the publisher role's always-zero one.
    void report_viewer_backpressure();
    int64_t get_viewer_backpressure_events(bool clear = false);

private:
    char *m_arrayData;
    int m_nDataSize;
    // Total bytes written across the buffer's lifetime. Used by readers to
    // detect overrun (writer lapped the reader by > m_nDataSize) and to
    // detect "no new data" between successive get() calls. Touched from
    // put() (writer) and the bFirst snapshot path in get() outside the
    // write lock, so the access is atomic. int64_t so the counter does
    // not realistically overflow during any uptime.
    std::atomic<int64_t> m_nDataCount{0};
    int m_nWritePos;
    // Written by every concurrent get() reader (under the rwlock's shared/read
    // side, so the writes still race each other) and read with no lock by
    // get_last_read_time() on the group idle-check thread. The reader store is
    // release and the idle-check load is acquire so that observing a fresh
    // timestamp happens-after the reader progress that produced it, giving the
    // idle/timeout decision a defined ordering rather than relying on relaxed
    // timing.
    std::atomic<int64_t> m_last_read_time{0};
    std::atomic<int64_t> m_overrun_count;

    // Diagnostic gauges (see the public accessors). Written off the read path in
    // get() and by viewer roles reporting backpressure; read by the /stats HTTP
    // thread. Atomic, relaxed — purely observational, no ordering requirements.
    std::atomic<int64_t> m_max_reader_backlog{0};
    std::atomic<int64_t> m_viewer_backpressure_events{0};

    // Unique per buffer incarnation (fresh value on construction and on every
    // setSize() realloc), compared against SLSRecycleArrayID::nGeneration in
    // get() to detect readers that anchored on a previous incarnation. Atomic
    // only because setSize() writes it under the write lock while diagnostic
    // accessors may read lock-free; relaxed ordering is sufficient — the value
    // is an identity token, not a synchronisation point.
    std::atomic<uint64_t> m_nGeneration{0};

    CSLSRWLock m_rwclock;
};
