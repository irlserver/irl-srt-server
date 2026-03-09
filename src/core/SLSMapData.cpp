
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
#include <fcntl.h>
#include <string.h>
#include "spdlog/spdlog.h"

#include "SLSMapData.hpp"
#include "SLSLog.hpp"

/**
 * CSLSMapData class implementation
 */

CSLSMapData::CSLSMapData()
{
}
CSLSMapData::~CSLSMapData()
{
    clear();
}

int CSLSMapData::add(char *key)
{
    int ret = SLS_OK;
    std::string strKey = std::string(key);

    CSLSLock lock(&m_rwclock, true);

    std::map<std::string, CSLSRecycleArray *>::iterator item;
    item = m_map_array.find(strKey);
    if (item != m_map_array.end())
    {
        CSLSRecycleArray *array_data = item->second;
        if (array_data)
        {
            spdlog::info("[{}] CSLSMapData::add, failed, key={}, array_data={}, exist.",
                         fmt::ptr(this), key, fmt::ptr(array_data));
            return ret;
        }
        // m_map_array.erase(item);
    }

    CSLSRecycleArray *data_array = new CSLSRecycleArray;
    // m_map_array.insert(make_pair(strKey, data_array));
    m_map_array[strKey] = data_array;
    spdlog::info("[{}] CSLSMapData::add ok, key='{}'.",
                 fmt::ptr(this), key);
    return ret;
}

int CSLSMapData::remove(char *key)
{
    int ret = SLS_ERROR;
    std::string strKey = std::string(key);

    CSLSLock lock(&m_rwclock, true);

    std::map<std::string, ts_info *>::iterator item_ti;
    item_ti = m_map_ts_info.find(strKey);
    if (item_ti != m_map_ts_info.end())
    {
        ts_info *ti = item_ti->second;
        if (ti)
        {
            delete ti;
        }
        m_map_ts_info.erase(item_ti);
    }

    std::map<std::string, CSLSRecycleArray *>::iterator item;
    item = m_map_array.find(strKey);
    if (item != m_map_array.end())
    {
        CSLSRecycleArray *array_data = item->second;
        spdlog::info("[{}] CSLSMapData::remove, key='{}' delete array_data={}.",
                     fmt::ptr(this), key, fmt::ptr(array_data));
        if (array_data)
        {
            delete array_data;
        }
        m_map_array.erase(item);
        return SLS_OK;
    }
    return ret;
}

bool CSLSMapData::is_exist(char *key)
{

    CSLSLock lock(&m_rwclock, true);
    std::string strKey = std::string(key);

    std::map<std::string, CSLSRecycleArray *>::iterator item;
    item = m_map_array.find(key);
    if (item != m_map_array.end())
    {
        CSLSRecycleArray *array_data = item->second;
        if (array_data)
        {
            spdlog::trace("[{}] CSLSMapData::is_exist, key={}, exist.",
                          fmt::ptr(this), key);
            return true;
        }
        else
        {
            spdlog::trace("[{}] CSLSMapData::is_exist, is_exist, key={}, data_array is null.",
                          fmt::ptr(this), key);
        }
    }
    else
    {
        spdlog::trace("[{}] CSLSMapData::add, is_exist, key={}, not exist.",
                      fmt::ptr(this), key);
    }
    return false;
}

int CSLSMapData::put(char *key, char *data, int len, int64_t *last_read_time)
{
    int ret = SLS_OK;

    CSLSLock lock(&m_rwclock, true);
    std::string strKey = std::string(key);

    std::map<std::string, CSLSRecycleArray *>::iterator item;
    item = m_map_array.find(strKey);
    if (item == m_map_array.end())
    {
        spdlog::error("[{}] CSLSMapData::put, key={}, not found data array.",
                      fmt::ptr(this), key);
        return SLS_ERROR;
    }
    CSLSRecycleArray *array_data = item->second;
    if (NULL == array_data)
    {
        spdlog::error("[{}] CSLSMapData::get, key={}, array_data is NULL.",
                      fmt::ptr(this), key);
    }

    ret = array_data->put(data, len);
    if (ret != len)
    {
        spdlog::error("[{}] CSLSMapData::put, key={}, array_data->put failed, len={:d}, but ret={:d}.",
                      fmt::ptr(this), key, len, ret);
    }
    if (NULL != last_read_time)
    {
        *last_read_time = array_data->get_last_read_time();
    }

    // check sps and pps
    ts_info *ti = NULL;
    std::map<std::string, ts_info *>::iterator item_ti;
    item_ti = m_map_ts_info.find(strKey);
    if (item_ti == m_map_ts_info.end())
    {
        ti = new ts_info;
        sls_init_ts_info(ti);
        ti->need_spspps = true;
        m_map_ts_info[strKey] = ti;
    }
    else
    {
        ti = item_ti->second;
    }

    if (SLS_OK == check_ts_info(data, len, ti))
    {
        spdlog::info("[{}] CSLSMapData::put, check_spspps ok, key={}.",
                     fmt::ptr(this), key);
    }

    // Audio gap filling: detect and insert silent packets
    if (m_audio_gap_fill_enabled)
    {
        check_audio_gap(data, len, ti, array_data);
    }

    return ret;
}

int CSLSMapData::get(char *key, char *data, int len, SLSRecycleArrayID *read_id, int aligned)
{
    int ret = SLS_OK;

    CSLSLock lock(&m_rwclock, false);
    std::string strKey = std::string(key);

    std::map<std::string, CSLSRecycleArray *>::iterator item;
    item = m_map_array.find(strKey);
    if (item == m_map_array.end())
    {
        spdlog::trace("[{}] CSLSMapData::get, key={}, not found data array,",
                      fmt::ptr(this), key);
        return SLS_ERROR;
    }
    CSLSRecycleArray *array_data = item->second;
    if (NULL == array_data)
    {
        spdlog::warn("[{}] CSLSMapData::get, key={}, array_data is NULL.",
                     fmt::ptr(this), key);
        return SLS_ERROR;
    }

    bool b_first = read_id->bFirst;
    ret = array_data->get(data, len, read_id, aligned);
    if (b_first)
    {
        // get sps and pps
        ret = get_ts_info(key, data, len);
        spdlog::info("[{}] CSLSMapData::get, get sps pps ok, key={}, len={:d}.",
                     fmt::ptr(this), key, ret);
    }
    return ret;
}

int CSLSMapData::get_ts_info(char *key, char *data, int len)
{
    int ret = 0;
    ts_info *ti = NULL;
    std::string strKey = std::string(key);
    std::map<std::string, ts_info *>::iterator item_ti;
    item_ti = m_map_ts_info.find(strKey);
    if (item_ti != m_map_ts_info.end())
    {
        ti = item_ti->second;
        if (len >= TS_UDP_LEN)
        {
            memcpy(data, ti->ts_data, TS_UDP_LEN);
            ret = TS_UDP_LEN;
        }
    }
    return ret;
}

void CSLSMapData::clear()
{
    CSLSLock lock(&m_rwclock, true);
    std::map<std::string, CSLSRecycleArray *>::iterator it;
    for (it = m_map_array.begin(); it != m_map_array.end();)
    {
        CSLSRecycleArray *array_data = it->second;
        if (array_data)
        {
            delete array_data;
        }
        it++;
    }
    m_map_array.clear();
    std::map<std::string, ts_info *>::iterator item_ti;
    for (item_ti = m_map_ts_info.begin(); item_ti != m_map_ts_info.end();)
    {
        ts_info *ti = item_ti->second;
        if (ti)
        {
            delete ti;
        }
        item_ti++;
    }
    m_map_ts_info.clear();
}

int CSLSMapData::check_ts_info(char *data, int len, ts_info *ti)
{
    // only get the first, suppose the sps and pps are not changed always.
    for (int i = 0; i < len;)
    {
        if (ti->sps_len > 0 && ti->pps_len > 0 && ti->pat_len > 0 && ti->pat_len > 0)
        {
            break;
        }
        sls_parse_ts_info((const uint8_t *)data + i, ti);
        i += TS_PACK_LEN;
    }

    return SLS_ERROR;
}

void CSLSMapData::set_audio_gap_fill(bool enabled)
{
    m_audio_gap_fill_enabled = enabled;
}

void CSLSMapData::check_audio_gap(char *data, int len, ts_info *ti, CSLSRecycleArray *array_data)
{
    if (!ti->pmt_parsed || ti->audio_track_count == 0)
        return;

    // Scan TS packets for audio PES with PTS on any tracked audio track
    for (int i = 0; i < len; i += TS_PACK_LEN)
    {
        const uint8_t *pkt = (const uint8_t *)data + i;
        if (pkt[0] != TS_SYNC_BYTE)
            continue;

        int pid = ((pkt[1] & 0x1F) << 8) | (pkt[2] & 0xFF);

        // Find which audio track this PID belongs to
        audio_track_info *track = NULL;
        for (int t = 0; t < ti->audio_track_count; t++)
        {
            if (ti->audio_tracks[t].pid == pid)
            {
                track = &ti->audio_tracks[t];
                break;
            }
        }
        if (!track)
            continue;

        int is_start = pkt[1] & 0x40;
        if (!is_start)
        {
            track->cc = (pkt[3] & 0x0F);
            continue;
        }

        track->cc = (pkt[3] & 0x0F);

        // Find PES payload
        int afc = (pkt[3] >> 4) & 3;
        int pos = 4;
        if (afc & 2)
            pos += 1 + (pkt[pos] & 0xFF);
        if (pos + 9 >= TS_PACK_LEN)
            continue;

        // Check PES start code and audio stream_id (0xC0-0xDF)
        if (pkt[pos] != 0x00 || pkt[pos + 1] != 0x00 || pkt[pos + 2] != 0x01)
            continue;
        int stream_id = pkt[pos + 3] & 0xFF;
        if (stream_id < 0xC0 || stream_id > 0xDF)
            continue;

        // Record the actual stream_id from the PES header
        track->stream_id = stream_id;

        // Parse PTS
        int flags = pkt[pos + 7] & 0xFF;
        if ((flags & 0x80) == 0)
            continue;

        int64_t current_pts = 0;
        const uint8_t *pts_buf = pkt + pos + 9;
        current_pts = ((int64_t)(pts_buf[0] & 0x0E) << 29) |
                      ((int64_t)(pts_buf[1] & 0xFF) << 22) |
                      ((int64_t)(pts_buf[2] & 0xFE) << 14) |
                      ((int64_t)(pts_buf[3] & 0xFF) << 7) |
                      ((int64_t)(pts_buf[4] & 0xFE) >> 1);

        // Try to detect audio format from ES payload if not yet detected
        if (!track->format_detected)
        {
            int pes_header_len = pkt[pos + 8] & 0xFF;
            int es_offset = pos + 9 + pes_header_len;
            if (es_offset < TS_PACK_LEN)
            {
                SLSAudioGapFiller::detect_format(
                    pkt + es_offset, TS_PACK_LEN - es_offset, track);
            }
        }

        // Generate gap fill packets if there's a gap
        if (track->last_pts != INVALID_DTS_PTS && track->format_detected)
        {
            uint8_t fill_cc = (track->cc + 1) & 0x0F;
            std::vector<uint8_t> gap_packets = SLSAudioGapFiller::generate_gap_packets(
                track, track->last_pts, current_pts, fill_cc);

            if (!gap_packets.empty())
            {
                array_data->put((char *)gap_packets.data(), gap_packets.size());
                spdlog::info("CSLSMapData::check_audio_gap: PID={} inserted {} silent packets ({} bytes)",
                             track->pid, gap_packets.size() / TS_PACK_LEN, gap_packets.size());
            }
        }

        track->last_pts = current_pts;
    }
}
