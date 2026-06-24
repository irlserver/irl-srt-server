
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
    int get_data_size() const { return m_nDataSize; }

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
    // get_last_read_time() on the group idle-check thread. Atomic so that
    // cross-thread read and the racing reader writes are well-defined.
    std::atomic<int64_t> m_last_read_time{0};
    std::atomic<int64_t> m_overrun_count;

    CSLSRWLock m_rwclock;
};
