
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
#include <sys/stat.h>

#include <nlohmann/json.hpp>
#include "spdlog/spdlog.h"

#include "SLSRole.hpp"
#include "SLSLog.hpp"
#include "SLSLogCategory.hpp"
#include "SLSPublisher.hpp"
#include "SLSPushUrlValidator.hpp"
#include "util.hpp"
#include "SLSBitrateLimit.hpp"

/**
 * CSLSRole class implementation
 */

CSLSRole::CSLSRole()
{
    m_srt = NULL;
    m_is_write = true;                           //listener: 0, publisher: 0, player: 1
    m_stat_start_time        = sls_gettime_ms();
    m_invalid_begin_tm = sls_gettime_ms();       //
    m_stat_bitrate_last_tm = m_invalid_begin_tm; //
    m_stat_bitrate_interval = 1000;              //ms
    m_stat_bitrate_datacount = 0;
    m_kbitrate = 0;              //kb
    m_idle_streams_timeout = 10; //unit: s, -1: unlimited
    m_latency = 20;              //ms

    m_state = SLS_RS_UNINIT;
    m_back_log = 1024; //maximum number of connections at the same time
    m_port = 0;
    memset(m_peer_ip, 0, IP_MAX_LEN);
    m_peer_port = 0;
    memset(m_role_name, 0, STR_MAX_LEN);
    memset(m_streamid, 0, URL_MAX_LEN);
    memset(m_http_url, 0, URL_MAX_LEN);
    m_http_passed = true;

    m_conf = NULL;
    m_map_data = NULL;
    memset(m_map_data_key, 0, URL_MAX_LEN);
    memset(&m_map_data_id, 0, sizeof(SLSRecycleArrayID));

    memset(m_data, 0, DATA_BUFF_SIZE);
    m_data_len = 0;
    m_data_pos = 0;
    m_need_reconnect = false;
    m_http_future = nullptr;

    // Initialize bitrate limiter
    m_bitrate_limiter = NULL;

    snprintf(m_role_name, sizeof(m_role_name), "role");
}

CSLSRole::~CSLSRole()
{
    cleanup_bitrate_limiter();
    uninit();
}

int CSLSRole::init()
{
    int ret = 0;
    m_state = SLS_RS_INITED;

    m_map_data_id.bFirst = true;
    m_map_data_id.nDataCount = 0;
    m_map_data_id.nReadPos = 0;

    return ret;
}

int CSLSRole::uninit()
{
    int ret = 0;
    m_http_future = nullptr;

    if (SLS_RS_UNINIT != m_state)
    {
        m_state = SLS_RS_UNINIT;
        remove_from_epoll();
        invalid_srt();
    }

    return ret;
}

int CSLSRole::invalid_srt()
{
    if (m_srt)
    {
        int fd = get_fd(); // Get fd before closing
        spdlog::info("[{}] CSLSRole::invalid_srt, close sock={:d}, m_state={:d}.", fmt::ptr(this), fd, m_state);
        
        // Close and cleanup SRT socket
        m_srt->libsrt_close();
        delete m_srt;
        m_srt = NULL;

        // Notify about disconnection
        on_close();
    }
    return SLS_OK;
}

void CSLSRole::request_kick()
{
    m_kick_requested.store(true, std::memory_order_relaxed);
}

int CSLSRole::get_state(int64_t cur_time_ms)
{
    if (SLS_RS_INVALID == m_state)
        return m_state;

    // Honour a cross-thread kick (publisher takeover). Doing the teardown
    // here keeps invalid_srt() on the socket-owning worker, so it can't race
    // a concurrent handler() read on the same CSLSSrt.
    if (m_kick_requested.load(std::memory_order_relaxed))
    {
        spdlog::info("[{}] CSLSRole::get_state, kick requested for {}, fd={:d}, call invalid_srt.",
                     fmt::ptr(this), m_role_name, get_fd());
        m_state = SLS_RS_INVALID;
        invalid_srt();
        return m_state;
    }

    if (check_idle_streams_duration(cur_time_ms))
    {
        spdlog::info("[{}] CSLSRole::get_state, check_idle_streams_duration is true, cur m_state={:d}, m_idle_streams_timeout={:d}s, call invalid_srt.",
                     fmt::ptr(this), m_state, m_idle_streams_timeout);
        m_state = SLS_RS_INVALID;
        invalid_srt();
        return m_state;
    }

    int ret = get_sock_state();
    if (SLS_ERROR == ret || SRTS_BROKEN == ret || SRTS_CLOSED == ret || SRTS_NONEXIST == ret)
    {
        spdlog::info("[{}] CSLSRole::get_state, get_sock_state, ret={:d}, call invalid_srt.",
                     fmt::ptr(this), ret);
        if (SRTS_BROKEN == ret || SRTS_CLOSED == ret || SRTS_NONEXIST == ret)
        {
            CSLSSrt::libsrt_neterrno();
        }
        m_state = SLS_RS_INVALID;
        invalid_srt();
        return m_state;
    }
    return m_state;
}

int CSLSRole::handler()
{
    int ret = 0;
    //spdlog::info("CSLSRole::handler()");
    return ret;
}

int CSLSRole::get_fd()
{
    if (m_srt)
        return m_srt->libsrt_get_fd();
    return 0;
}

int CSLSRole::set_eid(int eid)
{
    if (m_srt)
        return m_srt->libsrt_set_eid(eid);
    return 0;
}

int CSLSRole::set_srt(CSLSSrt *srt)
{
    if (m_srt)
    {
        spdlog::error("[{}] CSLSRole::setSrt, m_srt={} is not null.", fmt::ptr(this), fmt::ptr(m_srt));
        return SLS_ERROR;
    }
    m_srt = srt;
    return 0;
}

int CSLSRole::write(const char *buf, int size)
{
    if (NULL == m_srt)
    {
        spdlog::error("[{}] CSLSRole::write, m_srt is NULL, cannot write {:d} bytes.",
                      fmt::ptr(this), size);
        return SLS_ERROR;
    }
    if (NULL == buf || size <= 0)
    {
        spdlog::error("[{}] CSLSRole::write, invalid parameters: buf={}, size={:d}.",
                      fmt::ptr(this), fmt::ptr(buf), size);
        return SLS_ERROR;
    }
    return m_srt->libsrt_write(buf, size);
}

int CSLSRole::add_to_epoll(int eid)
{
    int ret = SLS_ERROR;
    if (m_srt)
    {
        m_srt->libsrt_set_eid(eid);
        ret = m_srt->libsrt_add_to_epoll(eid, m_is_write);
        // Log at TRACE level (epoll operations are very verbose)
        spdlog::trace("[{}] CSLSRole::add_to_epoll, {}, sock={:d}, m_is_write={:d}, ret={:d}.",
                     fmt::ptr(this), m_role_name, get_fd(), m_is_write, ret);
    }
    return ret;
}

int CSLSRole::remove_from_epoll()
{
    int ret = SLS_ERROR;
    if (m_srt)
    {
        ret = m_srt->libsrt_remove_from_epoll();
        // Log at TRACE level (epoll operations are very verbose)
        spdlog::trace("[{}] CSLSRole::remove_from_epoll, {}, sock={:d}, ret={:d}.",
                     fmt::ptr(this), m_role_name, get_fd(), ret);
    }
    return ret;
}

int CSLSRole::set_epoll_out(bool enable)
{
    if (NULL == m_srt)
        return SLS_ERROR;
    if (enable == m_epoll_out_armed)
        return SLS_OK;
    int ret = m_srt->libsrt_arm_epoll_out(enable);
    if (SLS_OK == ret)
        m_epoll_out_armed = enable;
    return ret;
}

void CSLSRole::update_egress_arming()
{
    if (!m_is_write)
        return;
    // Staged data we couldn't fully send (m_data_pos < m_data_len) means
    // the SRT send buffer is backpressured; arm OUT so libsrt wakes the
    // worker when it drains. Otherwise we are caught up — disarm so the
    // always-writable socket doesn't busy-return from srt_epoll_wait.
    set_epoll_out(m_data_pos < m_data_len);
}

int CSLSRole::get_sock_state()
{
    if (m_srt)
        return m_srt->libsrt_getsockstate();
    return SLS_ERROR;
}

char *CSLSRole::get_role_name()
{
    return m_role_name;
}

char *CSLSRole::get_streamid()
{
    if (strlen(m_streamid) != 0)
    {
        return m_streamid;
    }
    int sid_size = sizeof(m_streamid);
    if (m_srt)
    {
        m_srt->libsrt_getsockopt(SRTO_STREAMID, "SRTO_STREAMID", m_streamid, &sid_size);
    }
    return m_streamid;
}

void CSLSRole::set_streamid(const char *sid)
{
    if (sid == NULL)
    {
        return;
    }
    strlcpy(m_streamid, sid, sizeof(m_streamid));
}

char *CSLSRole::get_map_data_key()
{
    return m_map_data_key;
}

bool CSLSRole::is_reconnect()
{
    return m_need_reconnect;
}

void CSLSRole::set_conf(sls_conf_base_t *conf)
{
    m_conf = conf;
}

void CSLSRole::set_map_data(const char *map_key, CSLSMapData *map_data)
{
    if (NULL != map_key)
    {
        strlcpy(m_map_data_key, map_key, sizeof(m_map_data_key));
        m_map_data = map_data;
        on_map_data_set();
    }
    else
    {
        spdlog::error("[{}] CSLSRole::set_map_data, failed, map_key is null.", fmt::ptr(this));
    }
}

void CSLSRole::set_idle_streams_timeout(int timeout)
{
    m_idle_streams_timeout = timeout;
}

bool CSLSRole::check_idle_streams_duration(int64_t cur_time_ms)
{
    if (-1 == m_idle_streams_timeout)
    {
        return false;
    }
    if (0 == cur_time_ms)
    {
        cur_time_ms = sls_gettime_ms();
    }
    int duration = cur_time_ms - m_invalid_begin_tm;
    if (duration >= m_idle_streams_timeout * 1000)
    {
        return true;
    }
    return false;
}

int CSLSRole::check_http_client()
{
    if (!m_http_future)
        return SLS_ERROR;
    return SLS_OK;
}

int CSLSRole::close()
{
    if (m_srt)
    {
        m_srt->libsrt_close();
        delete m_srt;
        m_srt = NULL;
    }
    return 0;
}

int CSLSRole::handler_read_data(int64_t *last_read_time)
{
    char szData[TS_UDP_LEN];

    if (SLS_OK != check_http_passed())
    {
        return SLS_OK;
    }

    if (NULL == m_srt)
    {
        spdlog::error("[{}] CSLSRole::handler_read_data, m_srt is null.", fmt::ptr(this));
        return SLS_ERROR;
    }
    //read data
    int n = m_srt->libsrt_read(szData, TS_UDP_LEN);
    if (n <= 0)
    {
        spdlog::error("[{}] CSLSRole::handler_read_data, libsrt_read failure, n={:d}, expected={:d}.", fmt::ptr(this), n, TS_UDP_LEN);
        return SLS_ERROR;
    }

    // Update invalid begin time
    m_invalid_begin_tm = sls_gettime_ms();
    
    // Check bitrate limiting if enabled
    if (m_bitrate_limiter) {
        CSLSBitrateLimit::BitrateCheckResult result = m_bitrate_limiter->check_data_bitrate(n, m_invalid_begin_tm);
        if (result == CSLSBitrateLimit::BITRATE_DISCONNECT) {
            // Stream should be disconnected due to sustained bitrate violations
            spdlog::error("[{}] CSLSRole::handler_read_data, disconnecting stream due to bitrate limit violation", fmt::ptr(this));
            invalid_srt();
            return SLS_ERROR;
        }
        // For BITRATE_VIOLATION and BITRATE_OK, we continue processing the data
    }

    m_stat_bitrate_datacount += n;
    int d = m_invalid_begin_tm - m_stat_bitrate_last_tm;
    if (d >= m_stat_bitrate_interval)
    {
        m_kbitrate = m_stat_bitrate_datacount * 8 / d;
        m_stat_bitrate_datacount = 0;
        m_stat_bitrate_last_tm = m_invalid_begin_tm;
    }

    if (n != TS_UDP_LEN)
    {
        spdlog::trace("[{}] CSLSRole::handler_read_data, libsrt_read n={:d}, expect {:d}.", fmt::ptr(this), n, TS_UDP_LEN);
    }

    if (NULL == m_map_data)
    {
        spdlog::error("[{}] CSLSRole::handler_read_data, no data handled, m_map_data is NULL.", fmt::ptr(this));
        return SLS_ERROR;
    }

    spdlog::trace("[{}] CSLSRole::handler_read_data, ok, libsrt_read n={:d}.", fmt::ptr(this), n);
    int ret = m_map_data->put(m_map_data_key, szData, n, last_read_time);

    return ret;
}

int CSLSRole::get_statistics(SRT_TRACEBSTATS *currentStats, int clear) {
    if (m_srt) {
        m_srt->libsrt_get_statistics(currentStats, clear);
        return SLS_OK;
    }
    return SLS_ERROR;
}

int CSLSRole::get_bitrate() {
    return m_kbitrate;
}

int CSLSRole::get_uptime() {
    int difference = sls_gettime_ms() - m_stat_start_time;
    return difference/1000;
}

int CSLSRole::handler_write_data()
{
    int write_size = 0;

    if (check_http_passed())
    {
        return SLS_OK;
    }

    // Critical: Check if SRT socket is still valid
    if (NULL == m_srt)
    {
        spdlog::error("[{}] CSLSRole::handler_write_data, m_srt is NULL, cannot write data.",
                      fmt::ptr(this));
        return SLS_ERROR;
    }

    //read data from publisher's data array
    if (NULL == m_map_data)
    {
        spdlog::error("[{}] CSLSRole::handler_write_data, no data, m_map_data is NULL.",
                      fmt::ptr(this));
        return SLS_ERROR;
    }
    if (strlen(m_map_data_key) == 0)
    {
        spdlog::error("[{}] CSLSRole::handler_write_data, no data, m_map_data_key is ''.",
                      fmt::ptr(this));
        return SLS_ERROR;
    }

    // Drain up to MAX_EGRESS_BATCHES publisher-ring batches per call.
    // Egress is driven by the worker's periodic pass rather than a
    // permanently-armed SRT_EPOLL_OUT, so this inner loop is what stops
    // throughput being capped at one DATA_BUFF_SIZE per worker wakeup: a
    // viewer that fell behind can pull several batches here before the
    // worker moves on to the publisher read and the other roles. We stop
    // early the moment the ring has no more data (get() returns 0) or the
    // socket backpressures (EASYNCSND).
    for (int batch = 0; batch < MAX_EGRESS_BATCHES; ++batch)
    {
        // Re-check m_srt before fetching / writing in case it was closed
        // mid-operation (e.g. invalidated by another path this cycle).
        if (NULL == m_srt)
        {
            spdlog::error("[{}] CSLSRole::handler_write_data, m_srt became NULL during drain loop.",
                          fmt::ptr(this));
            return SLS_ERROR;
        }

        if (m_data_len < TS_UDP_LEN)
        {
            int got = m_map_data->get(m_map_data_key, m_data, DATA_BUFF_SIZE, &m_map_data_id, TS_UDP_LEN);
            if (got < 0)
            {
                //maybe no publisher, wait for timeout.
                break;
            }
            if (got == 0)
            {
                // No new data yet (caught up to the write head, first-call
                // priming, or an overrun resync). Nothing more to drain.
                break;
            }
            m_data_pos = 0;
            m_data_len = got;

            m_stat_bitrate_datacount += got;
            //update invalid begin time
            m_invalid_begin_tm = sls_gettime_ms();
            int d = m_invalid_begin_tm - m_stat_bitrate_last_tm;
            if (d >= m_stat_bitrate_interval)
            {
                m_kbitrate = m_stat_bitrate_datacount * 8 / d;
                m_stat_bitrate_datacount = 0;
                m_stat_bitrate_last_tm = m_invalid_begin_tm;
            }
        }

        int len = m_data_len - m_data_pos;
        int remainer = m_data_len - m_data_pos;
        while (remainer >= TS_UDP_LEN)
        {
            // Re-check m_srt before each write in case it was closed mid-operation
            if (NULL == m_srt)
            {
                spdlog::error("[{}] CSLSRole::handler_write_data, m_srt became NULL during write loop.",
                              fmt::ptr(this));
                return SLS_ERROR;
            }

            int ret = write(m_data + m_data_pos, TS_UDP_LEN);
            if (ret < TS_UDP_LEN)
            {
                // Distinguish transient backpressure (SRT_EASYNCSND, errno
                // 6001) from real failures. EASYNCSND means the per-socket
                // SRT send buffer is momentarily full and the write should
                // be retried on the next SRT_EPOLL_OUT wake (the worker
                // arms OUT via update_egress_arming once we return with
                // m_data_pos < m_data_len). Treating it as fatal (the old
                // behaviour) silently disconnected any viewer that hit a
                // brief congestion event on their link. Leaving
                // m_data_pos/m_data_len intact so the next handler call
                // resumes from the same offset.
                if (ret < 0)
                {
                    int err_no = CSLSSrt::libsrt_lasterror();
                    if (err_no == SRT_EASYNCSND)
                    {
                        m_send_backpressure_count.fetch_add(1, std::memory_order_relaxed);

                        // Stuck-viewer detection. The per-packet success
                        // path above has already reset m_backpressure_stuck_since_ms
                        // to 0 on any progress made earlier in this call, so
                        // observing it == 0 here means this is the first
                        // EASYNCSND of a fresh stuck streak; start the timer.
                        // If it was already non-zero, the stuck streak is
                        // ongoing — kick the viewer if it has exceeded the
                        // timeout. Continuous zero-progress backpressure
                        // means the viewer's link cannot sustain the stream
                        // and they would otherwise hold a publisher-ring
                        // read position open indefinitely.
                        int64_t stuck_timeout_ms = backpressure_stuck_timeout_ms();
                        if (m_backpressure_stuck_since_ms == 0)
                        {
                            m_backpressure_stuck_since_ms = sls_gettime_ms();
                        }
                        else if ((sls_gettime_ms() - m_backpressure_stuck_since_ms)
                                 > stuck_timeout_ms)
                        {
                            spdlog::warn("[{}] CSLSRole::handler_write_data, viewer stuck in backpressure {} ms (>{}ms, latency={}ms), disconnecting. backpressureEvents={}.",
                                         fmt::ptr(this),
                                         (long long)(sls_gettime_ms() - m_backpressure_stuck_since_ms),
                                         (long long)stuck_timeout_ms,
                                         m_latency,
                                         m_send_backpressure_count.load(std::memory_order_relaxed));
                            return SLS_ERROR;
                        }

                        spdlog::trace("[{}] CSLSRole::handler_write_data, backpressure, pos={:d}, remaining={:d}.",
                                      fmt::ptr(this), m_data_pos, remainer);
                        return write_size;
                    }
                    spdlog::error("[{}] CSLSRole::handler_write_data, write data failed, len={:d}, ret={:d}, errno={:d}, not {:d}.",
                                  fmt::ptr(this), len, ret, err_no, TS_UDP_LEN);
                    spdlog::error("[{}] CSLSRole::handler_write_data, critical write failure (ret={:d}, errno={:d}), marking connection invalid.",
                                  fmt::ptr(this), ret, err_no);
                    return SLS_ERROR;
                }
                // Partial write (0 < ret < TS_UDP_LEN). SRT message API is
                // all-or-nothing per message so this branch is unexpected;
                // log and break to surface the anomaly without killing the
                // connection.
                spdlog::error("[{}] CSLSRole::handler_write_data, short write, len={:d}, ret={:d}, not {:d}.",
                              fmt::ptr(this), len, ret, TS_UDP_LEN);
                break;
            }
            m_data_pos += TS_UDP_LEN;
            write_size += TS_UDP_LEN;
            // Any successful write counts as progress and clears the
            // stuck-since marker — a viewer who can drain even slowly is
            // not zombie-stuck, just slow. Cheap to do per packet; field
            // is not shared across threads.
            m_backpressure_stuck_since_ms = 0;
            remainer = m_data_len - m_data_pos;
        }

        if (m_data_pos > m_data_len)
        {
            spdlog::error("[{}] CSLSRole::handler_write_data, write data, data error, len={:d}, m_data_pos={:d} > m_data_len={:d}.", fmt::ptr(this), len, m_data_pos, m_data_len);
        }

        if (m_data_pos < m_data_len)
        {
            // Staged batch not fully flushed (only reachable via the
            // unexpected short-write path; EASYNCSND already returned
            // above). Preserve the offset and stop — the worker arms OUT
            // and we resume next cycle.
            spdlog::trace("[{}] CSLSRole::handler_write_data, write data, len={:d}, remainder={:d}.", fmt::ptr(this), len, m_data_len - m_data_pos);
            return write_size;
        }

        // Batch fully sent — reset and loop to drain the next one.
        m_data_pos = m_data_len = 0;
    }

    return write_size;
}

void CSLSRole::set_stat_info_base(stat_info_t &v)
{
    m_stat_info_base = v;
}

stat_info_t CSLSRole::get_stat_info()
{
    m_stat_info_base.kbitrate = m_kbitrate;
    return m_stat_info_base;
}

int CSLSRole::get_peer_info(char *peer_name, int &peer_port)
{
    int ret = SLS_ERROR;
    if (m_srt)
    {
        ret = m_srt->libsrt_getpeeraddr(peer_name, peer_port);
    }
    return ret;
}

void CSLSRole::set_http_url(const char *http_url)
{
    if (NULL == http_url || strlen(http_url) == 0)
    {
        return;
    }
    strlcpy(m_http_url, http_url, sizeof(m_http_url));
    m_http_passed = false;
}

int CSLSRole::on_connect()
{
    if (strlen(m_http_url) == 0)
        return SLS_ERROR;

    char on_event_url[URL_MAX_LEN] = {0};
    if (strlen(m_peer_ip) == 0)
        get_peer_info(m_peer_ip, m_peer_port);
    
    int ret = snprintf(on_event_url, sizeof(on_event_url), "%s?on_event=on_connect&role_name=%s&srt_url=%s&remote_ip=%s&remote_port=%d",
                       m_http_url, url_encode(m_role_name).c_str(), url_encode(get_streamid()).c_str(), m_peer_ip, m_peer_port);
    if (ret < 0 || (unsigned)ret >= sizeof(on_event_url)) {
        spdlog::error("[{}] CSLSRole::on_connect, on_event_url is too long, ret={:d}.", fmt::ptr(this), ret);
        return SLS_ERROR;
    }

    auto future = AsyncHttpClient::instance().post_async(on_event_url, "", "application/json", 5);
    m_http_future = std::make_shared<std::shared_future<AsyncHttpResponse>>(std::move(future));
    return SLS_OK;
}

int CSLSRole::on_close()
{
    if (!m_http_passed)
        return SLS_OK;
    if (strlen(m_http_url) == 0)
        return SLS_OK;

    char on_event_url[URL_MAX_LEN] = {0};
    if (strlen(m_peer_ip) == 0)
        get_peer_info(m_peer_ip, m_peer_port);
    
    int ret = snprintf(on_event_url, sizeof(on_event_url), "%s?on_event=on_close&role_name=%s&srt_url=%s&remote_ip=%s&remote_port=%d",
                       m_http_url, url_encode(m_role_name).c_str(), url_encode(get_streamid()).c_str(), m_peer_ip, m_peer_port);
    if (ret < 0 || (unsigned)ret >= sizeof(on_event_url)) {
        spdlog::error("[SLSRole::on_close] callback URL too long, truncating [len={:d}]", ret);
        return SLS_ERROR;
    }

    auto future = AsyncHttpClient::instance().post_async(on_event_url, "", "application/json", 5);
    m_http_future = std::make_shared<std::shared_future<AsyncHttpResponse>>(std::move(future));
    return SLS_OK;
}

int CSLSRole::check_http_passed()
{
    if (m_http_passed)
        return SLS_OK;

    if (!m_http_future)
        return SLS_OK;

    using namespace std::chrono_literals;
    if (m_http_future->wait_for(0ms) != std::future_status::ready)
        return SLS_ERROR;

    auto response = m_http_future->get();
    m_http_future = nullptr;

    if (!response.success || response.status_code != 200) {
        spdlog::error("[{}] CSLSRole::check_http_client_response, http refused, invalid {} http_url='{}', status={}, error='{}'.",
                      fmt::ptr(this), m_role_name, m_http_url, response.status_code, response.error);
        invalid_srt();
        return SLS_ERROR;
    }

    spdlog::info("[{}] CSLSRole::check_http_client_response, http finished, {}, http_url='{}', status={}, response='{}'.",
                 fmt::ptr(this), m_role_name, m_http_url, response.status_code, response.body);
    m_http_passed = true;

    // Optional JSON payload from the publisher-auth webhook may carry a
    // list of outbound SRT push destinations. Parse only when the body
    // looks like JSON; older webhooks return plain "OK" and must keep
    // working. Validate each URL again here even though irlserver2 already
    // checked at save time, so a misconfigured webhook can't push to
    // loopback or to the SLS host itself.
    if (!response.body.empty() && response.body[0] == '{') {
        sls_conf_app_t *app_conf = static_cast<sls_conf_app_t *>(m_conf);
        if (app_conf == NULL || app_conf->push_destination_max <= 0) {
            return SLS_OK;
        }
        try {
            auto parsed = nlohmann::json::parse(response.body);
            if (!parsed.contains("pushTargets") || !parsed["pushTargets"].is_array()) {
                return SLS_OK;
            }
            const auto &self_addrs = push_url_self_addresses();
            int kept = 0;
            for (const auto &entry : parsed["pushTargets"]) {
                if (kept >= app_conf->push_destination_max) {
                    spdlog::warn("[relay] push destination rejected | reason=over_limit url={}",
                                 entry.contains("url") && entry["url"].is_string()
                                     ? entry["url"].get<std::string>()
                                     : std::string("<no url>"));
                    continue;
                }
                if (!entry.is_object() || !entry.contains("url") || !entry["url"].is_string()) {
                    continue;
                }
                std::string url = entry["url"].get<std::string>();
                PushUrlReject verdict = validate_push_url(url, *app_conf, self_addrs);
                if (verdict != PushUrlReject::Ok) {
                    spdlog::warn("[relay] push destination rejected | reason={} url={}",
                                 push_url_reject_reason(verdict), url);
                    continue;
                }
                m_push_urls.push_back(std::move(url));
                ++kept;
            }
            if (kept > 0) {
                spdlog::info("[relay] push destinations accepted for {} | count={} streamid='{}'",
                             m_role_name, kept, get_streamid());
            }
        } catch (const std::exception &e) {
            spdlog::warn("[{}] CSLSRole::check_http_passed, JSON parse error: {}",
                         fmt::ptr(this), e.what());
        }
    }

    return SLS_OK;
}

void CSLSRole::on_map_data_set()
{
}

bool CSLSRole::is_audio_gap_fill_enabled() const
{
    return false;
}

bool CSLSRole::get_audio_gap_stats(CSLSMapData::AudioGapStreamStats &stats, int clear) const
{
    stats = CSLSMapData::AudioGapStreamStats();
    stats.enabled = is_audio_gap_fill_enabled();

    if (m_map_data == NULL || strlen(m_map_data_key) == 0)
        return false;

    bool found = m_map_data->get_audio_gap_stats(m_map_data_key, stats, clear);
    stats.enabled = is_audio_gap_fill_enabled();
    return found;
}

int64_t CSLSRole::get_ring_overrun_count() const
{
    if (m_map_data == NULL || strlen(m_map_data_key) == 0)
        return -1;
    return m_map_data->get_overrun_count(m_map_data_key);
}

int CSLSRole::init_bitrate_limiter(int max_bitrate_kbps, int violation_timeout_seconds, float spike_tolerance)
{
    cleanup_bitrate_limiter();

    if (max_bitrate_kbps <= 0) {
        spdlog::info("[{}] CSLSRole::init_bitrate_limiter, bitrate limiting disabled (max_bitrate_kbps={:d})",
                    fmt::ptr(this), max_bitrate_kbps);
        return SLS_OK;
    }

    m_bitrate_limiter = new CSLSBitrateLimit();
    if (!m_bitrate_limiter) {
        spdlog::error("[{}] CSLSRole::init_bitrate_limiter, failed to allocate bitrate limiter", fmt::ptr(this));
        return SLS_ERROR;
    }

    int ret = m_bitrate_limiter->init(max_bitrate_kbps, violation_timeout_seconds, 5000, spike_tolerance);
    if (ret != SLS_OK) {
        spdlog::error("[{}] CSLSRole::init_bitrate_limiter, failed to initialize bitrate limiter", fmt::ptr(this));
        delete m_bitrate_limiter;
        m_bitrate_limiter = NULL;
        return ret;
    }

    spdlog::info("[{}] CSLSRole::init_bitrate_limiter, initialized with max_bitrate={:d}kbps, violation_timeout={:d}s, spike_tolerance={:.2f}",
                fmt::ptr(this), max_bitrate_kbps, violation_timeout_seconds, spike_tolerance);
    return SLS_OK;
}

void CSLSRole::cleanup_bitrate_limiter()
{
    if (m_bitrate_limiter) {
        delete m_bitrate_limiter;
        m_bitrate_limiter = NULL;
    }
}

CSLSBitrateLimit::BitrateStats CSLSRole::get_bitrate_stats() const
{
    if (m_bitrate_limiter) {
        return m_bitrate_limiter->get_stats();
    }
    
    CSLSBitrateLimit::BitrateStats empty_stats = {};
    return empty_stats;
}
