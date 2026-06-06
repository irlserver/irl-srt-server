
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

CSLSRecycleArray::CSLSRecycleArray()
{
    m_nDataSize = DEFAULT_MAX_DATA_SIZE;
    m_nWritePos = 0;
    m_nDataCount = 0;
    m_overrun_count.store(0, std::memory_order_relaxed);

    m_last_read_time = sls_gettime_ms();

    m_arrayData = new char[m_nDataSize];
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
    CSLSLock lock(&m_rwclock, false);
    return m_nDataCount;
}

//please call this function before get and put,
//if not, the read data will be make confusion.
void CSLSRecycleArray::setSize(int n)
{
    CSLSLock lock(&m_rwclock, false);
    delete[] m_arrayData;
    m_nDataSize = n;
    m_nWritePos = 0;
    m_arrayData = new char[m_nDataSize];
}

int CSLSRecycleArray::put(char *data, int len)
{
    if (!data || len <= 0)
    {
        spdlog::error("[{}] CSLSRecycleArray::put, failed, data={:p}, len={:d}.",
                      fmt::ptr(this), data, len);
        return SLS_ERROR;
    }

    if (len > m_nDataSize)
    {
        spdlog::error("[{}] CSLSRecycleArray::put, failed, len={:d} is bigger than m_nDataSize={:d}.",
                      fmt::ptr(this), data, len, m_nDataSize);
        return SLS_ERROR;
    }

    {
        CSLSLock lock(&m_rwclock, true);
        if (m_nDataSize - m_nWritePos >= len)
        {
            //copy directly
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
    //no consider int wrapround;
    m_nDataCount += len;
    spdlog::trace("[{}] CSLSRecycleArray::put, len={:d}, m_nWritePos={:d}, m_nDataCount={:d}, m_nDataSize={:d}.",
                  fmt::ptr(this), len, m_nWritePos, m_nDataCount, m_nDataSize);
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
        read_id->nReadPos = m_nWritePos;
        read_id->nDataCount = m_nDataCount;
        read_id->bFirst = false;
        spdlog::trace("[{}] CSLSRecycleArray::get, the first time.", fmt::ptr(this));
        return SLS_OK;
    }

    CSLSLock lock(&m_rwclock, false);
    if (read_id->nReadPos == m_nWritePos && m_nDataCount == read_id->nDataCount)
    {
        spdlog::trace("[{}] CSLSRecycleArray::get, no new data.", fmt::ptr(this));
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
    int64_t bytes_since_last_read =
        (int64_t)m_nDataCount - (int64_t)read_id->nDataCount;
    if (bytes_since_last_read >= (int64_t)m_nDataSize)
    {
        int64_t new_count =
            m_overrun_count.fetch_add(1, std::memory_order_relaxed) + 1;
        spdlog::warn("[{}] CSLSRecycleArray::get, reader overrun: writer advanced {:d}"
                     " bytes since last read, buffer size {:d}. Resyncing reader to"
                     " write head (overrun_count={:d}).",
                     fmt::ptr(this), (int)bytes_since_last_read, m_nDataSize,
                     (int)new_count);
        read_id->nReadPos = m_nWritePos;
        read_id->nDataCount = m_nDataCount;
        return SLS_OK;
    }

    spdlog::trace("[{}] CSLSRecycleArray::get, read_id->nReadPos={:d}, m_nWritePos={:d}, m_nDataCount={:d}, m_nDataSize={:d}.",
                  fmt::ptr(this), read_id->nReadPos, m_nWritePos, m_nDataCount, m_nDataSize);

    //update the last read time
    m_last_read_time = sls_gettime_ms();

    int ready_data_len = 0;
    int copy_data_len = 0;
    if (read_id->nReadPos < m_nWritePos)
    {
        //read pos is behind in the write pos
        ready_data_len = m_nWritePos - read_id->nReadPos;
        copy_data_len = ready_data_len <= size ? ready_data_len : size;
        if (aligned > 0)
        {
            copy_data_len = copy_data_len / aligned * aligned;
        }
        //sls_log(SLS_LOG_TRACE, "[%p]CSLSRecycleArray::get, read pos is behind in the write pos, copy_data_len=%d, ready_data_len=%d, size=%d.",
        //		this, copy_data_len, ready_data_len, size);
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
        //sls_log(SLS_LOG_TRACE, "[%p]CSLSRecycleArray::get, read pos is before of the write pos, copy_data_len=%d, ready_data_len=%d, size=%d.",
        //		this, copy_data_len, ready_data_len, size);
        if (copy_data_len > 0)
        {
            if (m_nDataSize - read_id->nReadPos >= copy_data_len)
            {
                //no wrap round
                memcpy(data, m_arrayData + read_id->nReadPos, copy_data_len);
                read_id->nReadPos += copy_data_len;
            }
            else
            {
                memcpy(data, m_arrayData + read_id->nReadPos, m_nDataSize - read_id->nReadPos);
                //wrap around
                memcpy(data + (m_nDataSize - read_id->nReadPos), m_arrayData, copy_data_len - (m_nDataSize - read_id->nReadPos));
                read_id->nReadPos = copy_data_len - (m_nDataSize - read_id->nReadPos);
            }
        }
    }
    if (read_id->nReadPos == m_nDataSize)
        read_id->nReadPos = 0;

    if (read_id->nReadPos > m_nDataSize)
    {
        spdlog::warn("[{}] CSLSRecycleArray::get, read_id->nReadPos={:d}, but m_nDataSize={:d}.",
                     fmt::ptr(this), read_id->nReadPos, m_nDataSize);
        read_id->nReadPos = 0;
    }
    read_id->nDataCount = m_nDataCount;
    spdlog::trace("[{}] CSLSRecycleArray::get, copy_data_lens={:d}.",
                  fmt::ptr(this), copy_data_len);
    return copy_data_len;
}

int64_t CSLSRecycleArray::get_last_read_time()
{
    return m_last_read_time;
}
