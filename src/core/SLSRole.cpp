
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

#include "spdlog/spdlog.h"

#include "SLSRole.hpp"
#include "SLSLog.hpp"
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
    m_http_client = NULL;

    snprintf(m_record_hls, sizeof(m_record_hls), "off"); //default off
    m_record_hls_ts_fd = 0;
    memset(m_record_hls_ts_filename, 0, URL_MAX_LEN);
    m_record_hls_vod_fd = 0;
    memset(m_record_hls_vod_filename, 0, FILENAME_MAX);
    snprintf(m_record_hls_path, sizeof(m_record_hls_path), "./vod"); //default current path
    m_record_hls_begin_tm_ms = 0;
    m_record_hls_segment_duration = 10; //default 10s
    m_record_hls_target_duration = m_record_hls_segment_duration;

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
    if (NULL != m_http_client)
    {
        m_http_client->close();
        delete m_http_client;
        m_http_client = NULL;
    }

    if (SLS_RS_UNINIT != m_state)
    {
        m_state = SLS_RS_UNINIT;
        remove_from_epoll();
        invalid_srt();
    }
    close_hls_file();

    return ret;
}

int CSLSRole::invalid_srt()
{
    if (m_srt)
    {
        spdlog::info("[{}] CSLSRole::invalid_srt, close sock={:d}, m_state={:d}.", fmt::ptr(this), get_fd(), m_state);
        m_srt->libsrt_close();
        delete m_srt;
        m_srt = NULL;

        on_close();
    }
    return SLS_OK;
}

int CSLSRole::get_state(int64_t cur_time_ms)
{
    if (SLS_RS_INVALID == m_state)
        return m_state;

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
    if (m_srt)
        return m_srt->libsrt_write(buf, size);
    return SLS_ERROR;
}

int CSLSRole::add_to_epoll(int eid)
{
    int ret = SLS_ERROR;
    if (m_srt)
    {
        m_srt->libsrt_set_eid(eid);
        ret = m_srt->libsrt_add_to_epoll(eid, m_is_write);
        spdlog::info("[{}] CSLSRole::add_to_epoll, {}, sock={:d}, m_is_write={:d}, ret={:d}.",
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
        spdlog::info("[{}] CSLSRole::remove_from_epoll, {}, sock={:d}, ret={:d}.",
                     fmt::ptr(this), m_role_name, get_fd(), ret);
    }
    return ret;
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
    return m_streamid;
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

void CSLSRole::set_record_hls_path(const char *hls_path)
{
    if (hls_path && strlen(hls_path) > 0)
    {
        strlcpy(m_record_hls_path, hls_path, sizeof(m_record_hls_path));
    }
}

int CSLSRole::check_http_client()
{
    if (NULL == m_http_client)
    {
        return SLS_ERROR;
    }
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

void CSLSRole::close_hls_file()
{

    if (m_record_hls_ts_fd)
    {
        spdlog::info("[{}] CSLSRole::close_hls_file, close ts file='{}', fd={:d}.", fmt::ptr(this), m_record_hls_ts_filename, m_record_hls_ts_fd);
        ::close(m_record_hls_ts_fd);
        m_record_hls_ts_fd = 0;
    }
    if (0 != m_record_hls_vod_fd)
    {
        ::close(m_record_hls_vod_fd);
        int vod_fd = 0;
        vod_fd = ::open(m_record_hls_vod_filename, O_RDONLY, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
        spdlog::info("[{}] CSLSRole::close_hls_file, prepare open '{}', fd={:d}.", fmt::ptr(this), m_record_hls_vod_filename, vod_fd);
        snprintf(m_record_hls_vod_filename, sizeof(m_record_hls_vod_filename), "%s/vod.m3u8", m_record_hls_path);
        struct stat stat_file;
        if (0 == stat(m_record_hls_vod_filename, &stat_file))
        {
            m_record_hls_vod_fd = ::open(m_record_hls_vod_filename, O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
        }
        else
        {
            m_record_hls_vod_fd = ::open(m_record_hls_vod_filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
        }
        //write header
        char m3u8_info[URL_MAX_LEN] = {0};
        snprintf(m3u8_info, sizeof(m3u8_info), "#EXTM3U\n\
#EXT-X-VERSION:3\n\
#EXT-X-TARGETDURATION:%d\n",
                 (int)(m_record_hls_target_duration + 1));
        ::write(m_record_hls_vod_fd, m3u8_info, strlen(m3u8_info));
        const int buf_len = 4096;
        char buf[buf_len] = {0};
        while (true)
        {
            int len = ::read(vod_fd, buf, buf_len);
            spdlog::info("[{}] CSLSRole::close_hls_file, read data len={:d}, fd={:d}.", fmt::ptr(this), len, vod_fd);
            if (len == buf_len)
            {
                ::write(m_record_hls_vod_fd, buf, len);
            }
            else
            {
                if (len > 0)
                    ::write(m_record_hls_vod_fd, buf, len);
                break;
            }
        }
        ::close(vod_fd);

        snprintf(m3u8_info, sizeof(m3u8_info), "#EXT-X-ENDLIST");
        ::write(m_record_hls_vod_fd, m3u8_info, strlen(m3u8_info));
        ::close(m_record_hls_vod_fd);
        m_record_hls_vod_fd = 0;
    }
}

void CSLSRole::check_hls_file()
{
    //check file duration
    int64_t cur_tm_ms = sls_gettime_ms();
    float d = cur_tm_ms - m_record_hls_begin_tm_ms;
    d /= 1000;
    if (d < m_record_hls_segment_duration)
    {
        return;
    }
    m_record_hls_begin_tm_ms = cur_tm_ms;

    //check path
    if (sls_mkdir_p(m_record_hls_path) != -1)
    {
        spdlog::info("[{}] CSLSRole::check_hls_file, mkdir '{}' ok.", fmt::ptr(this), m_record_hls_path);
    }
    else
    {
        if (errno != EEXIST)
        {
            spdlog::error("[{}] CSLSRole::check_hls_file, mkdir '{}' failed.", fmt::ptr(this), m_record_hls_path);
            return;
        }
        spdlog::info("[{}] CSLSRole::check_hls_file, '{}' exist.", fmt::ptr(this), m_record_hls_path);
    }

    //update ts file
    if (m_record_hls_ts_fd)
    {
        m_record_hls_target_duration = m_record_hls_target_duration < d ? d : m_record_hls_target_duration;
        spdlog::info("[{}] CSLSRole::check_hls_file, close ts file='{}', fd={:d}.", fmt::ptr(this), m_record_hls_ts_filename, m_record_hls_ts_fd);
        ::close(m_record_hls_ts_fd);
        m_record_hls_ts_fd = 0;

        char ts_item[STR_MAX_LEN] = {0};
        int ret = snprintf(ts_item, sizeof(ts_item), "#EXTINF:%0.3f,\n%s\n", d, m_record_hls_ts_filename);
        if (ret < 0 || (unsigned)ret >= sizeof(ts_item))
        {
            spdlog::error("[{}] CSLSRole::check_hls_file, snprintf ts item failed.", fmt::ptr(this));
            return;
        }

        //update vod file
        if (0 == m_record_hls_vod_fd)
        {
            snprintf(m_record_hls_vod_filename, sizeof(m_record_hls_vod_filename), "%s/vod-%ld.m3u8.extinfo", m_record_hls_path, cur_tm_ms / 1000);
            struct stat stat_file;
            if (0 == stat(m_record_hls_vod_filename, &stat_file))
            {
                m_record_hls_vod_fd = ::open(m_record_hls_vod_filename, O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
            }
            else
            {
                m_record_hls_vod_fd = ::open(m_record_hls_vod_filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
            }
            spdlog::info("[{}] CSLSRole::check_hls_file, create vod file='{}', fd={:d}.", fmt::ptr(this), m_record_hls_vod_filename, m_record_hls_vod_fd);
        }
        if (0 != m_record_hls_vod_fd)
        {
            ::write(m_record_hls_vod_fd, ts_item, strlen(ts_item));
        }
    }
    char full_ts_name[FILENAME_MAX] = {0};
    snprintf(m_record_hls_ts_filename, sizeof(m_record_hls_ts_filename), "%ld.ts", cur_tm_ms / 1000);
    snprintf(full_ts_name, sizeof(full_ts_name), "%s/%s", m_record_hls_path, m_record_hls_ts_filename);
    m_record_hls_ts_fd = ::open(full_ts_name, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);
    spdlog::info("[{}] CSLSRole::check_hls_file, create ts file='{}', fd={:d}.", fmt::ptr(this), full_ts_name, m_record_hls_ts_fd);
    if (m_record_hls_ts_fd)
    {
        //write sps pps
        if (m_map_data)
        {
            char ts_info[TS_UDP_LEN] = {0};
            int re = m_map_data->get_ts_info(m_map_data_key, ts_info, TS_UDP_LEN);
            if (re > 0)
            {
                ::write(m_record_hls_ts_fd, ts_info, re);
            }
        }
    }
}

void CSLSRole::record_data2hls(char *data, int len)
{
    //check hls file
    check_hls_file();

    if (0 != m_record_hls_ts_fd)
    {
        ::write(m_record_hls_ts_fd, data, len);
    }
    /*
    //save data
    static char out_file_name[URL_MAX_LEN] = {0};
    if (strlen(out_file_name) == 0) {
    char cur_tm[256];
    sls_gettime_default_string(cur_tm);
    snprintf(out_file_name, sizeof(out_file_name), "./obs_%s.ts", cur_tm);
    }
    static int fd_out = open(out_file_name, O_WRONLY|O_CREAT, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH);

    if (0 != fd_out) {
    write(fd_out, data, len);
    }
    */
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

    //record data
    if (strcmp(m_record_hls, "on") == 0)
    {
        record_data2hls(szData, n);
    }

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
    int ret = 0;
    int write_size = 0;

    if (check_http_passed())
    {
        return SLS_OK;
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

    if (m_data_len < TS_UDP_LEN)
    {
        ret = m_map_data->get(m_map_data_key, m_data, DATA_BUFF_SIZE, &m_map_data_id, TS_UDP_LEN);
        if (ret < 0)
        {
            //maybe no publisher, wait for timeout.
            return SLS_OK;
        }
        m_data_pos = 0;
        m_data_len = ret;
    }

    m_stat_bitrate_datacount += ret;
    //update invalid begin time
    m_invalid_begin_tm = sls_gettime_ms();
    int d = m_invalid_begin_tm - m_stat_bitrate_last_tm;
    if (d >= m_stat_bitrate_interval)
    {
        m_kbitrate = m_stat_bitrate_datacount * 8 / d;
        m_stat_bitrate_datacount = 0;
        m_stat_bitrate_last_tm = m_invalid_begin_tm;
    }

    int len = m_data_len - m_data_pos;
    int remainer = m_data_len - m_data_pos;
    while (remainer >= TS_UDP_LEN)
    {
        ret = write(m_data + m_data_pos, TS_UDP_LEN);
        if (ret < TS_UDP_LEN)
        {
            spdlog::error("[{}] CSLSRole::handler_write_data, write data failed, len={:d}, ret={:d}, not {:d}.", fmt::ptr(this), len, ret, TS_UDP_LEN);
            break;
        }
        m_data_pos += TS_UDP_LEN;
        write_size += TS_UDP_LEN;
        remainer = m_data_len - m_data_pos;
    }

    if (m_data_pos < m_data_len)
    {
        spdlog::trace("[{}] CSLSRole::handler_write_data, write data, len={:d}, remainder={:d}.", fmt::ptr(this), len, m_data_len - m_data_pos);
        return SLS_OK;
    }
    if (m_data_pos > m_data_len)
    {
        spdlog::error("[{}] CSLSRole::handler_write_data, write data, data error, len={:d}, m_data_pos={:d} > m_data_len={:d}.", fmt::ptr(this), len, m_data_pos, m_data_len);
    }
    else
    {
        //spdlog::trace("[{}] CSLSRole::handler_write_data, write data, m_data_len={:d}.", fmt::ptr(this), m_data_len);
    }
    m_data_pos = m_data_len = 0;

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
    if (NULL == m_http_client)
    {
        m_http_client = new CHttpClient;
        m_http_passed = false;
    }
}

int CSLSRole::on_connect()
{
    if (strlen(m_http_url) == 0)
    {
        return SLS_ERROR;
    }
    if (NULL == m_http_client)
    {
        m_http_client = new CHttpClient;
    }

    char on_event_url[URL_MAX_LEN] = {0};
    if (strlen(m_peer_ip) == 0)
    {
        get_peer_info(m_peer_ip, m_peer_port);
    }
    int ret = snprintf(on_event_url, sizeof(on_event_url), "%s?on_event=on_connect&role_name=%s&srt_url=%s&remote_ip=%s&remote_port=%d",
                       m_http_url, url_encode(m_role_name).c_str(), url_encode(get_streamid()).c_str(), m_peer_ip, m_peer_port);
    if (ret < 0 || (unsigned)ret >= sizeof(on_event_url))
    {
        spdlog::error("[{}] CSLSRole::on_connect, on_event_url is too long, ret={:d}.", fmt::ptr(this), ret);
        return SLS_ERROR;
    }

    return m_http_client->open(on_event_url);
}

int CSLSRole::on_close()
{
    if (!m_http_passed)
    {
        return SLS_OK;
    }
    if (strlen(m_http_url) == 0)
    {
        return SLS_OK;
    }
    if (NULL == m_http_client)
    {
        m_http_client = new CHttpClient;
    }

    char on_event_url[URL_MAX_LEN] = {0};
    if (strlen(m_peer_ip) == 0)
    {
        get_peer_info(m_peer_ip, m_peer_port);
    }
    int ret = snprintf(on_event_url, sizeof(on_event_url), "%s?on_event=on_close&role_name=%s&srt_url=%s&remote_ip=%s&remote_port=%d",
                       m_http_url, url_encode(m_role_name).c_str(), url_encode(get_streamid()).c_str(), m_peer_ip, m_peer_port);
    if (ret < 0 || (unsigned)ret >= sizeof(on_event_url))
    {
        spdlog::error("[SLSRole::on_close] callback URL too long, truncating [len={:d}]",
                      ret);
        return SLS_ERROR;
    }

    return m_http_client->open(on_event_url);
}

int CSLSRole::check_http_passed()
{
    if (m_http_passed)
        return SLS_OK;

    if (!m_http_client)
    {
        return SLS_OK;
    }

    m_http_client->handler();

    if (SLS_OK != m_http_client->check_finished() && SLS_OK != m_http_client->check_timeout())
    {
        return SLS_ERROR;
    }

    HTTP_RESPONSE_INFO *re = m_http_client->get_response_info();
    if (NULL == re)
    {
        return SLS_ERROR;
    }

    int ret = strcmp(re->m_response_code.c_str(), HTTP_RESPONSE_CODE_200);
    if (0 == ret)
    {
        spdlog::info("[{}] CSLSRole::check_http_client_response, http finished, {}, http_url='{}', response_code={}, response='{}'.",
                     fmt::ptr(this), m_role_name, m_http_url, re->m_response_code.c_str(), re->m_response_content.c_str());
        m_http_client->close();
        delete m_http_client;
        m_http_client = NULL;
        m_http_passed = true;
        return SLS_OK;
    }
    else
    {
        spdlog::error("[{}] CSLSPlayer::check_http_client_response, http refused, invalid {} http_url='{}', response_code={}, response='{}'.",
                      fmt::ptr(this), m_role_name, m_http_url, re->m_response_code.c_str(), re->m_response_content.c_str());
        m_http_client->close();
        delete m_http_client;
        m_http_client = NULL;
        invalid_srt();
        return SLS_ERROR;
    }
}

int CSLSRole::init_bitrate_limiter(int max_bitrate_kbps, int violation_timeout_seconds)
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
    
    int ret = m_bitrate_limiter->init(max_bitrate_kbps, violation_timeout_seconds);
    if (ret != SLS_OK) {
        spdlog::error("[{}] CSLSRole::init_bitrate_limiter, failed to initialize bitrate limiter", fmt::ptr(this));
        delete m_bitrate_limiter;
        m_bitrate_limiter = NULL;
        return ret;
    }
    
    spdlog::info("[{}] CSLSRole::init_bitrate_limiter, initialized with max_bitrate={:d}kbps, violation_timeout={:d}s", 
                fmt::ptr(this), max_bitrate_kbps, violation_timeout_seconds);
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
