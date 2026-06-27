
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

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <srt/srt.h>
#include "spdlog/spdlog.h"

#include "SLSClient.hpp"
#include "SLSLog.hpp"
#include "util.hpp"

/**
 * CSLSClient class implementation
 */

#define POLLING_TIME 100 /// Time in milliseconds between interrupt check

CSLSClient::CSLSClient()
{
    m_eid = 0;
    m_out_file = -1;
    m_data_count = 0;
    m_bit_rate = 0;

    m_ts_file_time_reader = NULL;
    m_invalid_begin_tm = sls_gettime_ms();

    memset(m_url, 0, 1024);
    memset(m_ts_file_name, 0, 1024);
    memset(m_out_file_name, 0, 1024);

    snprintf(m_role_name, sizeof(m_role_name), "client");
}

CSLSClient::~CSLSClient() {}

int CSLSClient::init_epoll()
{
    m_eid = CSLSSrt::libsrt_epoll_create();
    if (m_eid < 0)
    {
        spdlog::info("[{}] CSLSClient::work, srt_epoll_create failed.", fmt::ptr(this));
        return CSLSSrt::libsrt_neterrno();
    }
    // compatible with srt v1.4.0 when container is empty.
    if (srt_epoll_set(m_eid, SRT_EPOLL_ENABLE_EMPTY) == -1)
    {
        spdlog::info("[{}] CSLSClient::work, srt_epoll_set failed.", fmt::ptr(this));
        return CSLSSrt::libsrt_neterrno();
    }
    return SLS_OK;
}

int CSLSClient::uninit_epoll()
{
    if (m_eid >= 0)
    {
        CSLSSrt::libsrt_epoll_release(m_eid);
        spdlog::info("[{}] CSLSEpollThread::work, srt_epoll_release ok.", fmt::ptr(this));
    }
    return SLS_OK;
}

int CSLSClient::play(const char *url, const char *out_file_name)
{
    m_is_write = false;
    if (out_file_name != NULL && strlen(out_file_name) > 0)
    {
        strlcpy(m_out_file_name, out_file_name, sizeof(m_out_file_name));
    }

    return open_url(url);
}

int CSLSClient::open_url(const char *url)
{
    int ret;

    if (url == NULL || strlen(url) == 0)
    {
        spdlog::info("[{}] CSLSClient::play, url='{}', must like 'srt://hostname:port?streamid=your_stream_id' or "
                     "'srt://hostname:port/app/stream_name'.",
                     fmt::ptr(this), url ? url : "null");
        return SLS_ERROR;
    }

    if (SLS_OK != (ret = open(url)))
    {
        return ret;
    }

    // add to epoll
    if (SLS_OK != init_epoll())
    {
        spdlog::info("[{}] CSLSClient::play, init_epoll failed.", fmt::ptr(this));
        return CSLSSrt::libsrt_neterrno();
    }
    if (SLS_OK != add_to_epoll(m_eid))
    {
        spdlog::warn("[{}}]CSLSClient::play, add_to_epoll failed.", fmt::ptr(this));
        return CSLSSrt::libsrt_neterrno();
    }
    // The push loop (write_data_handler) sends only when srt_epoll_wait reports
    // the socket writable. libsrt_add_to_epoll no longer arms writable roles for
    // SRT_EPOLL_OUT by default (the server drives egress from its worker tick),
    // so this standalone client must arm OUT itself or it would never see the
    // socket become writable and would never send a packet.
    if (m_is_write && NULL != m_srt)
    {
        m_srt->libsrt_arm_epoll_out(true);
    }
    return SLS_OK;
}

int CSLSClient::push(const char *url, const char *ts_file_name, bool loop)
{
    if (NULL == ts_file_name || strlen(ts_file_name) == 0)
    {
        spdlog::error("[{}] CSLSClient::push, failed, wrong ts_file_name='{}'.", fmt::ptr(this), ts_file_name);
        return SLS_ERROR;
    }
    if (NULL == m_ts_file_time_reader)
    {
        m_ts_file_time_reader = new CTSFileTimeReader;
    }
    int ret = m_ts_file_time_reader->open(ts_file_name, loop);
    if (SLS_OK != ret)
    {
        spdlog::error("[{}] CSLSClient::push, m_ts_file_time_reader->open failed, ts_file_name='{}'.", fmt::ptr(this),
                      ts_file_name);
        return SLS_ERROR;
    }

    m_is_write = true;
    return open_url(url);
}

int CSLSClient::close()
{
    if (m_out_file >= 0)
    {
        ::close(m_out_file);
        m_out_file = -1;
    }
    if (0 != m_eid)
    {
        spdlog::info("[{}] CSLSClient::close, ok, url='{}'.", fmt::ptr(this), m_url);
        remove_from_epoll();
        uninit_epoll();
        m_eid = 0;
    }
    if (NULL != m_ts_file_time_reader)
    {
        delete m_ts_file_time_reader;
        m_ts_file_time_reader = NULL;
    }
    return CSLSRelay::close();
}

int CSLSClient::handler()
{
    if (m_is_write)
    {
        return write_data_handler();
    }
    return read_data_handler();
}
int CSLSClient::write_data_handler()
{
    uint8_t szData[TS_UDP_LEN];
    SRTSOCKET read_socks[1];
    SRTSOCKET write_socks[1];
    int read_len = 0;
    int write_len = 1;
    int64_t tm_ms;
    bool jitter = false;

    if (NULL == m_srt)
    {
        spdlog::error("[{}] CSLSClient::write_data_handler, failed, m_srt is null.", fmt::ptr(this));
        return SLS_ERROR;
    }
    if (0 == m_eid)
    {
        spdlog::error("[{}] CSLSClient::write_data_handler, failed, m_eid = 0.", fmt::ptr(this));
        return SLS_ERROR;
    }
    // check epoll
    int ret = srt_epoll_wait(m_eid, read_socks, &read_len, write_socks, &write_len, POLLING_TIME, 0, 0, 0, 0);
    if (0 > ret)
    {
        return SLS_OK;
    }
    if (0 >= write_socks[0])
    {
        return SLS_OK;
    }

    ret = m_ts_file_time_reader->get(szData, TS_UDP_LEN, tm_ms, jitter);
    if (SLS_OK != ret)
    {
        return SLS_ERROR;
    }
    // write data
    int n = m_srt->libsrt_write((char *)szData, TS_UDP_LEN);
    if (n <= 0)
    {
        spdlog::trace("[{}] CSLSClient::write_data_handler, libsrt_read failure, n={:d} expect {:d}.", fmt::ptr(this),
                      n, TS_UDP_LEN);
        int state = get_state();
        if (SLS_RS_INVALID == state || SLS_RS_UNINIT == state)
        {
            spdlog::error("[{}] CSLSClient::write_data_handler, state_failure={:d}", fmt::ptr(this), state);
            return SLS_ERROR;
        }
    }
    m_sync_clock.wait(tm_ms);

    m_data_count += n;
    int64_t cur_tm = sls_gettime_ms();
    int d = cur_tm - m_invalid_begin_tm;
    if (d >= 500)
    {
        m_bit_rate = m_data_count * 8 / d;
        m_data_count = 0;
        m_invalid_begin_tm = sls_gettime_ms();
    }
    return n;
}

int CSLSClient::read_data_handler()
{
    char szData[TS_UDP_LEN];
    SRTSOCKET read_socks[1];
    SRTSOCKET write_socks[1];
    int read_len = 0;
    int write_len = 0;

    if (m_is_write)
    {
        // push
        return SLS_OK;
    }
    else
    {
        // play
        if (NULL == m_srt)
        {
            spdlog::error("[{}] CSLSClient::read_data_handler, failed, m_srt is null.", fmt::ptr(this));
            return SLS_ERROR;
        }
        if (0 == m_eid)
        {
            spdlog::error("[{}] CSLSClient::read_data_handler, failed, m_eid = 0.", fmt::ptr(this));
            return SLS_ERROR;
        }
        read_len = 1;
        // check epoll
        int ret = srt_epoll_wait(m_eid, read_socks, &read_len, write_socks, &write_len, POLLING_TIME, 0, 0, 0, 0);
        if (0 > ret)
        {
            return SLS_OK;
        }
        if (0 >= read_socks[0])
        {
            return SLS_OK;
        }

        // read data
        int n = m_srt->libsrt_read(szData, TS_UDP_LEN);
        if (n <= 0)
        {
            spdlog::error("[{}] CSLSClient::read_data_handler, libsrt_read failure, n={:d} expect {:d}.",
                          fmt::ptr(this), n, TS_UDP_LEN);
            return SLS_OK;
        }

        // update invalid begin time
        // m_invalid_begin_tm = sls_gettime();

        if (m_out_file < 0)
        {
            if (strlen(m_out_file_name) > 0)
            {
                m_out_file = ::open(m_out_file_name, O_WRONLY | O_CREAT,
                                    S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
                if (m_out_file < 0)
                {
                    spdlog::error("[{}] CSLSClient::read_data_handler, open file='{}' failed, '{}'.", fmt::ptr(this),
                                  m_out_file_name, strerror(errno));
                    return SLS_ERROR;
                }
            }
        }
        if (m_out_file >= 0)
        {
            ::write(m_out_file, szData, TS_UDP_LEN);
        }
        m_data_count += n;
        int64_t cur_tm = sls_gettime_ms();
        int d = cur_tm - m_invalid_begin_tm;
        if (d >= 500)
        {
            m_bit_rate = m_data_count * 8 / d;
            m_data_count = 0;
            m_invalid_begin_tm = sls_gettime_ms();
        }

        if (n != TS_UDP_LEN)
        {
            spdlog::trace("[{}] CSLSClient::read_data_handler, libsrt_read n={:d}, expect {:d}.", fmt::ptr(this), n,
                          TS_UDP_LEN);
        }
        return n;
    }
}

int64_t CSLSClient::get_bitrate()
{
    return m_bit_rate;
}
