
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
#include <map>
#include <string>

#include "SLSRecycleArray.hpp"
#include "SLSLock.hpp"
#include "SLSAudioGapFiller.hpp"

class CSLSMapData
{
public:
    struct AudioGapTrackStats
    {
        int pid = INVALID_PID;
        int stream_type = 0;
        uint8_t stream_id = 0;
        bool format_detected = false;
        int sample_rate = 0;
        int channels = 0;
        uint64_t gap_count = 0;
        uint64_t silent_frames_inserted = 0;
        uint64_t silent_packets_inserted = 0;
        uint64_t silent_bytes_inserted = 0;
        int64_t last_gap_pts_delta = 0;
        int last_gap_frames = 0;
    };

    struct AudioGapStreamStats
    {
        bool enabled = false;
        bool pmt_parsed = false;
        int audio_track_count = 0;
        uint64_t gap_count = 0;
        uint64_t silent_frames_inserted = 0;
        uint64_t silent_packets_inserted = 0;
        uint64_t silent_bytes_inserted = 0;
        std::vector<AudioGapTrackStats> tracks;
    };

    CSLSMapData();
    virtual ~CSLSMapData();

    // Add a publisher data array for `key`. If `max_bitrate_kbps` and
    // `latency_ms` are both positive, the underlying ring buffer is sized
    // to hold ~2x the SRT latency window at the configured bitrate, so a
    // subscriber falling up to one full latency window behind is still
    // safe from overruns. Both default to 0, in which case the array uses
    // CSLSRecycleArray's compiled-in DEFAULT_MAX_DATA_SIZE.
    int add(char *key, int max_bitrate_kbps = 0, int latency_ms = 0);
    int remove(char *key);
    void clear();

    // Global, pre-allocation guardrails against ring-buffer memory exhaustion.
    // add() refuses to create a new ring once either the live stream count or
    // the cumulative ring-byte total would exceed these caps. A value of 0
    // means "unlimited" for that dimension. Both are set once at startup from
    // the srt-block config (max_streams / max_total_ring_mb) before any
    // listener accepts a connection, so no locking is required to publish them.
    void set_caps(int max_streams, int64_t max_total_ring_bytes);
    // Live count of allocated rings (one per active publisher/relay stream).
    int get_stream_count() const { return m_stream_count.load(std::memory_order_relaxed); }
    // Cumulative bytes committed across all allocated rings.
    int64_t get_total_ring_bytes() const { return m_total_ring_bytes.load(std::memory_order_relaxed); }

    // Cumulative overrun count across the publisher's ring buffer
    // (writer lapped the reader). Returns -1 if `key` is unknown.
    int64_t get_overrun_count(const char *key);

    int put(char *key, char *data, int len, int64_t *last_read_time = NULL);
    void set_audio_gap_fill(const char *key, bool enabled);
    bool get_audio_gap_stats(const char *key, AudioGapStreamStats &stats, int clear = 0);
    int get(char *key, char *data, int len, SLSRecycleArrayID *read_id, int aligned = 0);

    bool is_exist(char *key);

    int get_ts_info(char *key, char *data, int len);

private:
    // Transparent comparator (std::less<>) lets hot lookups (put/get) use
    // std::string_view{key} without constructing a temporary std::string —
    // saves a per-packet heap allocation per direction.
    std::map<std::string, CSLSRecycleArray *, std::less<>> m_map_array; //uplive_key_stream:data'
    std::map<std::string, ts_info *, std::less<>> m_map_ts_info;        //uplive_key_stream:ts_info'
    CSLSRWLock m_rwclock;

    // Global ring-budget accounting. Mutated only under m_rwclock's write lock
    // (in add/remove/clear, exactly at the new/delete of a CSLSRecycleArray) so
    // the check-then-allocate in add() is atomic against concurrent add/remove
    // on the same map. Kept atomic so /stats and other readers can sample them
    // without taking the write lock. m_stream_count tracks live rings;
    // m_total_ring_bytes tracks the summed get_data_size() of those rings.
    std::atomic<int> m_stream_count{0};
    std::atomic<int64_t> m_total_ring_bytes{0};
    // Caps applied before allocation (0 == unlimited). Set once at startup via
    // set_caps(); read-only thereafter, hence plain (non-atomic) members.
    int m_max_streams{0};
    int64_t m_max_total_ring_bytes{0};

    int check_ts_info(char *data, int len, ts_info *ti);
    void check_audio_gap(char *data, int len, ts_info *ti, CSLSRecycleArray *array_data);
};
