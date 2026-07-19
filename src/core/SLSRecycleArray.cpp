
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

#include <stdio.h>
#include <cassert>
#include "spdlog/spdlog.h"

#include "SLSRecycleArray.hpp"
#include "SLSLog.hpp"

// 8 MB default. The previous 1024*1316 comment said "about 5mbps*2sec" but
// the buffer is *the* point where viewers can fall behind: at 9 Mbps the
// old default held barely 1.2s, well inside the typical 2s SRT latency
// window, so jitter would silently lap the buffer (see overrun detection
// in get() below). 8 MB gives ~7s headroom at 9 Mbps, ~3s at 20 Mbps,
// even before adaptive resize. Callers that know the publisher's
// bitrate + latency upper-bound should still call setSize() for a tight
// fit (see CSLSMapData::add overload).
const int DEFAULT_MAX_DATA_SIZE = 8 * 1024 * 1024;

// Monotonic-max update of an atomic without a lock. Used off the read path to
// keep a high-water gauge; relaxed ordering is fine (the value is diagnostic and
// has no happens-before relationship with the data it describes).
static void atomic_store_max(std::atomic<int64_t> &slot, int64_t candidate)
{
    int64_t prev = slot.load(std::memory_order_relaxed);
    while (candidate > prev && !slot.compare_exchange_weak(prev, candidate, std::memory_order_relaxed))
    {
    }
}

// Process-wide source of ring identities. Starts at 1 so the zero-initialised
// SLSRecycleArrayID::nGeneration of a never-anchored reader can never match a
// live ring.
static std::atomic<uint64_t> s_next_generation{1};

CSLSRecycleArray::CSLSRecycleArray()
{
    m_nDataSize = DEFAULT_MAX_DATA_SIZE;
    m_nWritePos = 0;
    m_nDataCount.store(0, std::memory_order_relaxed);
    m_overrun_count.store(0, std::memory_order_relaxed);
    m_max_reader_backlog.store(0, std::memory_order_relaxed);
    m_viewer_backpressure_events.store(0, std::memory_order_relaxed);
    m_nGeneration.store(s_next_generation.fetch_add(1, std::memory_order_relaxed), std::memory_order_relaxed);

    m_last_read_time.store(sls_gettime_ms(), std::memory_order_relaxed);

    // Value-initialised: a recreated ring frequently gets the just-freed
    // previous ring's allocation back from the allocator with the prior
    // session's media bytes intact. Any stale-index bug must leak zeros, not
    // another session's (or another stream's) video.
    m_arrayData = new char[m_nDataSize]();
}

CSLSRecycleArray::~CSLSRecycleArray()
{
    CSLSLock lock(&m_rwclock, true);
    if (m_arrayData != NULL)
    {
        delete[] m_arrayData;
        m_arrayData = NULL;
    }
}

int CSLSRecycleArray::count()
{
    // Atomic load; m_nDataCount is published outside the rwlock by put().
    return (int)m_nDataCount.load(std::memory_order_relaxed);
}

// please call this function before get and put,
// if not, the read data will be make confusion.
void CSLSRecycleArray::setSize(int n)
{
    // Write lock: setSize() reallocates the underlying buffer, so any
    // concurrent reader (which holds the read lock in get()) must be
    // serialised against it or it will dereference freed memory.
    CSLSLock lock(&m_rwclock, true);
    delete[] m_arrayData;
    m_nDataSize = n;
    m_nWritePos = 0;
    // The buffer is being replaced wholesale; the byte counter is meaningful
    // only relative to the live buffer, so reset it alongside the realloc.
    // A new generation invalidates any reader anchored on the old buffer —
    // its positions are meaningless against the replacement.
    m_nDataCount.store(0, std::memory_order_relaxed);
    m_nGeneration.store(s_next_generation.fetch_add(1, std::memory_order_relaxed), std::memory_order_relaxed);
    m_arrayData = new char[m_nDataSize]();
}

int CSLSRecycleArray::put(char *data, int len)
{
    if (!data || len <= 0)
    {
        spdlog::error("[{}] CSLSRecycleArray::put, failed, data={:p}, len={:d}.", fmt::ptr(this), data, len);
        return SLS_ERROR;
    }

    if (len > m_nDataSize)
    {
        spdlog::error("[{}] CSLSRecycleArray::put, failed, len={:d} is bigger than m_nDataSize={:d}.", fmt::ptr(this),
                      len, m_nDataSize);
        return SLS_ERROR;
    }

    {
        CSLSLock lock(&m_rwclock, true);
        if (m_nDataSize - m_nWritePos >= len)
        {
            // copy directly
            memcpy(m_arrayData + m_nWritePos, data, len);
            m_nWritePos += len;
        }
        else
        {
            int first_len = m_nDataSize - m_nWritePos;
            memcpy(m_arrayData + m_nWritePos, data, first_len);
            memcpy(m_arrayData, data + first_len, len - first_len);
            m_nWritePos = (len - first_len);
        }

        if (m_nWritePos == m_nDataSize)
            m_nWritePos = 0;
    }
    // m_nDataCount is std::atomic<int64_t> so this increment is safe outside
    // the rwlock; the int64 width also retires the old "no consider int
    // wrapround" caveat — the counter won't overflow in any realistic uptime.
    int64_t new_count = m_nDataCount.fetch_add(len, std::memory_order_relaxed) + len;
    SPDLOG_TRACE("[{}] CSLSRecycleArray::put, len={:d}, m_nWritePos={:d}, m_nDataCount={:d}, m_nDataSize={:d}.",
                 fmt::ptr(this), len, m_nWritePos, new_count, m_nDataSize);
    return len;
}

int CSLSRecycleArray::get(char *data, int size, SLSRecycleArrayID *read_id, int aligned)
{
    if (NULL == m_arrayData)
    {
        spdlog::error("[{}] CSLSRecycleArray::get, failed, m_arrayData is NULL.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (NULL == read_id)
    {
        spdlog::error("[{}] CSLSRecycleArray::get, failed, read_id is NULL.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (read_id->bFirst)
    {
        // Snapshot the write head and byte counter under the read lock so a
        // concurrent put() can't tear the pair (write head moved forward but
        // the byte counter still showing the pre-write value, or vice versa).
        CSLSLock lock(&m_rwclock, false);
        read_id->nReadPos = m_nWritePos;
        read_id->nDataCount = m_nDataCount.load(std::memory_order_relaxed);
        read_id->nGeneration = m_nGeneration.load(std::memory_order_relaxed);
        read_id->bFirst = false;
        SPDLOG_TRACE("[{}] CSLSRecycleArray::get, the first time.", fmt::ptr(this));
        return SLS_OK;
    }

    CSLSLock lock(&m_rwclock, false);

    // A generation mismatch means this reader anchored on a different buffer
    // incarnation: the publisher reconnected (ring deleted + recreated for the
    // same stream key) while the player role survived, or setSize() replaced
    // the buffer. The reader's nReadPos/nDataCount describe the dead buffer;
    // draining with them would hand out whatever the recycled allocation still
    // holds — the "viewer sees a replay of the previous session" bug. Rejoin
    // at the live write head instead, exactly like a first anchor.
    if (read_id->nGeneration != m_nGeneration.load(std::memory_order_relaxed))
    {
        spdlog::info("[{}] CSLSRecycleArray::get, reader anchored on a previous ring incarnation "
                     "(reader_gen={:d}, ring_gen={:d}), re-anchoring at live write head.",
                     fmt::ptr(this), read_id->nGeneration, m_nGeneration.load(std::memory_order_relaxed));
        read_id->nReadPos = m_nWritePos;
        read_id->nDataCount = m_nDataCount.load(std::memory_order_relaxed);
        read_id->nGeneration = m_nGeneration.load(std::memory_order_relaxed);
        return SLS_OK;
    }

    int64_t cur_data_count = m_nDataCount.load(std::memory_order_relaxed);
    if (read_id->nReadPos == m_nWritePos && cur_data_count == read_id->nDataCount)
    {
        SPDLOG_TRACE("[{}] CSLSRecycleArray::get, no new data.", fmt::ptr(this));
        return SLS_OK;
    }

    // Overrun detection: if the writer has produced more than m_nDataSize
    // bytes since this reader last sampled the buffer, the contents the
    // reader was about to consume have already been overwritten by newer
    // data. Without this check we'd silently hand back a wrapped-around
    // region of the ring containing bytes that don't belong to the
    // reader's logical position — producing corrupt TS / out-of-order
    // delivery to the subscriber. Force the reader to resync to the
    // current write head and count the event for diagnostics.
    //
    // A negative delta is equally disqualifying: m_nDataCount is monotonic
    // for a given ring incarnation, so a reader counter ahead of the ring's
    // proves the reader's state belongs to some other incarnation. The
    // generation check above should have caught that; this is the backstop
    // that keeps a missed case from dereferencing stale positions.
    int64_t bytes_since_last_read = cur_data_count - read_id->nDataCount;
    if (bytes_since_last_read >= (int64_t)m_nDataSize || bytes_since_last_read < 0)
    {
        int64_t new_count = m_overrun_count.fetch_add(1, std::memory_order_relaxed) + 1;
        spdlog::warn("[{}] CSLSRecycleArray::get, reader overrun: writer advanced {:d}"
                     " bytes since last read, buffer size {:d}. Resyncing reader to"
                     " write head (overrun_count={:d}).",
                     fmt::ptr(this), (int)bytes_since_last_read, m_nDataSize, (int)new_count);
        read_id->nReadPos = m_nWritePos;
        read_id->nDataCount = cur_data_count;
        return SLS_OK;
    }

    // Diagnostic high-water: how far behind the write head this reader was on
    // entry (i.e. the backlog it is about to drain). A large value means the
    // reader's next drains will burst out a catch-up, which a viewer perceives
    // as a time-skip. Non-overrun path only — the overrun case is capped at the
    // buffer size and already has its own counter. See get_max_reader_backlog.
    atomic_store_max(m_max_reader_backlog, bytes_since_last_read);

    SPDLOG_TRACE(
        "[{}] CSLSRecycleArray::get, read_id->nReadPos={:d}, m_nWritePos={:d}, m_nDataCount={:d}, m_nDataSize={:d}.",
        fmt::ptr(this), read_id->nReadPos, m_nWritePos, cur_data_count, m_nDataSize);

    // update the last read time
    m_last_read_time.store(sls_gettime_ms(), std::memory_order_release);

    int ready_data_len = 0;
    int copy_data_len = 0;
    if (read_id->nReadPos < m_nWritePos)
    {
        // read pos is behind in the write pos
        ready_data_len = m_nWritePos - read_id->nReadPos;
        copy_data_len = ready_data_len <= size ? ready_data_len : size;
        if (aligned > 0)
        {
            copy_data_len = copy_data_len / aligned * aligned;
        }
        // sls_log(SLS_LOG_TRACE, "[%p]CSLSRecycleArray::get, read pos is behind in the write pos, copy_data_len=%d,
        // ready_data_len=%d, size=%d.", 		this, copy_data_len, ready_data_len, size);
        if (copy_data_len > 0)
        {
            memcpy(data, m_arrayData + read_id->nReadPos, copy_data_len);
            read_id->nReadPos += copy_data_len;
        }
    }
    else
    {
        ready_data_len = m_nDataSize - read_id->nReadPos + m_nWritePos;
        copy_data_len = ready_data_len <= size ? ready_data_len : size;
        if (aligned > 0)
        {
            copy_data_len = copy_data_len / aligned * aligned;
        }
        // sls_log(SLS_LOG_TRACE, "[%p]CSLSRecycleArray::get, read pos is before of the write pos, copy_data_len=%d,
        // ready_data_len=%d, size=%d.", 		this, copy_data_len, ready_data_len, size);
        if (copy_data_len > 0)
        {
            if (m_nDataSize - read_id->nReadPos >= copy_data_len)
            {
                // no wrap round
                memcpy(data, m_arrayData + read_id->nReadPos, copy_data_len);
                read_id->nReadPos += copy_data_len;
            }
            else
            {
                memcpy(data, m_arrayData + read_id->nReadPos, m_nDataSize - read_id->nReadPos);
                // wrap around
                memcpy(data + (m_nDataSize - read_id->nReadPos), m_arrayData,
                       copy_data_len - (m_nDataSize - read_id->nReadPos));
                read_id->nReadPos = copy_data_len - (m_nDataSize - read_id->nReadPos);
            }
        }
    }
    // Defensive post-wrap invariants: a violation means the ring math produced
    // an index/length the memcpy above would have read past. assert in debug;
    // the runtime clamp just below still corrects nReadPos in release.
    assert(copy_data_len >= 0 && copy_data_len <= size);
    assert(read_id->nReadPos >= 0 && read_id->nReadPos <= m_nDataSize);
    if (read_id->nReadPos == m_nDataSize)
        read_id->nReadPos = 0;

    if (read_id->nReadPos > m_nDataSize)
    {
        spdlog::warn("[{}] CSLSRecycleArray::get, read_id->nReadPos={:d}, but m_nDataSize={:d}.", fmt::ptr(this),
                     read_id->nReadPos, m_nDataSize);
        read_id->nReadPos = 0;
    }
    read_id->nDataCount = cur_data_count;
    SPDLOG_TRACE("[{}] CSLSRecycleArray::get, copy_data_lens={:d}.", fmt::ptr(this), copy_data_len);
    return copy_data_len;
}

int64_t CSLSRecycleArray::get_last_read_time()
{
    return m_last_read_time.load(std::memory_order_acquire);
}

int64_t CSLSRecycleArray::get_reader_backlog(const SLSRecycleArrayID *read_id) const
{
    if (NULL == read_id || read_id->bFirst)
        return 0;
    int64_t behind = m_nDataCount.load(std::memory_order_relaxed) - read_id->nDataCount;
    if (behind < 0)
        behind = 0;
    if (behind > m_nDataSize)
        behind = m_nDataSize;
    return behind;
}

int64_t CSLSRecycleArray::get_max_reader_backlog(bool clear)
{
    if (clear)
        return m_max_reader_backlog.exchange(0, std::memory_order_relaxed);
    return m_max_reader_backlog.load(std::memory_order_relaxed);
}

void CSLSRecycleArray::report_viewer_backpressure()
{
    m_viewer_backpressure_events.fetch_add(1, std::memory_order_relaxed);
}

int64_t CSLSRecycleArray::get_viewer_backpressure_events(bool clear)
{
    if (clear)
        return m_viewer_backpressure_events.exchange(0, std::memory_order_relaxed);
    return m_viewer_backpressure_events.load(std::memory_order_relaxed);
}
