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

#include "SLSBitrateLimit.hpp"
#include "common.hpp"
#include "spdlog/spdlog.h"

CSLSBitrateLimit::CSLSBitrateLimit()
{
    m_max_bitrate_kbps = 0;
    m_window_ms = 5000;
    m_spike_tolerance = 2.0f;
    m_total_bytes_in_window = 0;
    m_total_bytes_received = 0;
    m_total_bytes_dropped = 0;
    m_last_cleanup_time = 0;
}

CSLSBitrateLimit::~CSLSBitrateLimit()
{
    // Clear the queue
    while (!m_data_window.empty()) {
        m_data_window.pop();
    }
}

int CSLSBitrateLimit::init(int max_bitrate_kbps, int window_ms, float spike_tolerance)
{
    if (max_bitrate_kbps < 0 || window_ms <= 0 || spike_tolerance < 1.0f) {
        spdlog::error("[{}] CSLSBitrateLimit::init, invalid parameters: max_bitrate_kbps={:d}, window_ms={:d}, spike_tolerance={:.2f}",
                     fmt::ptr(this), max_bitrate_kbps, window_ms, spike_tolerance);
        return SLS_ERROR;
    }

    m_max_bitrate_kbps = max_bitrate_kbps;
    m_window_ms = window_ms;
    m_spike_tolerance = spike_tolerance;
    
    // Clear any existing data
    while (!m_data_window.empty()) {
        m_data_window.pop();
    }
    
    m_total_bytes_in_window = 0;
    reset_stats();
    
    spdlog::info("[{}] CSLSBitrateLimit::init, initialized with max_bitrate={:d}kbps, window={:d}ms, spike_tolerance={:.2f}",
                fmt::ptr(this), max_bitrate_kbps, window_ms, spike_tolerance);
    
    return SLS_OK;
}

bool CSLSBitrateLimit::check_data_allowed(int data_bytes, int64_t current_time_ms)
{
    m_total_bytes_received += data_bytes;
    
    // If no limit is set, allow all data
    if (m_max_bitrate_kbps == 0) {
        // Still add to window for statistics
        DataPoint point = {current_time_ms, data_bytes};
        m_data_window.push(point);
        m_total_bytes_in_window += data_bytes;
        cleanup_old_data(current_time_ms);
        return true;
    }
    
    // Clean up old data periodically (every second)
    if (current_time_ms - m_last_cleanup_time > 1000) {
        cleanup_old_data(current_time_ms);
        m_last_cleanup_time = current_time_ms;
    }
    
    // Calculate what the bitrate would be if we allow this data
    int64_t projected_bytes = m_total_bytes_in_window + data_bytes;
    int64_t effective_window_ms = m_window_ms;
    
    // If we don't have a full window of data yet, adjust the calculation
    if (!m_data_window.empty()) {
        int64_t actual_window_ms = current_time_ms - m_data_window.front().timestamp_ms;
        if (actual_window_ms < m_window_ms) {
            effective_window_ms = std::max((int64_t)1000, actual_window_ms); // At least 1 second
        }
    }
    
    // Calculate projected bitrate in kbps
    int projected_bitrate_kbps = (int)(projected_bytes * 8 * 1000 / effective_window_ms / 1000);
    
    // Allow spikes up to spike_tolerance * max_bitrate
    int spike_limit_kbps = (int)(m_max_bitrate_kbps * m_spike_tolerance);
    
    // Check if this would exceed our limits
    bool allow_data = (projected_bitrate_kbps <= spike_limit_kbps);
    
    if (allow_data) {
        // Add to sliding window
        DataPoint point = {current_time_ms, data_bytes};
        m_data_window.push(point);
        m_total_bytes_in_window += data_bytes;
    } else {
        // Drop the data
        m_total_bytes_dropped += data_bytes;
        
        spdlog::warn("[{}] CSLSBitrateLimit::check_data_allowed, dropping {:d} bytes. "
                    "Projected bitrate: {:d}kbps, spike limit: {:d}kbps, window: {:d}ms",
                    fmt::ptr(this), data_bytes, projected_bitrate_kbps, spike_limit_kbps, (int)effective_window_ms);
    }
    
    return allow_data;
}

void CSLSBitrateLimit::cleanup_old_data(int64_t current_time_ms)
{
    int64_t cutoff_time = current_time_ms - m_window_ms;
    
    while (!m_data_window.empty() && m_data_window.front().timestamp_ms < cutoff_time) {
        m_total_bytes_in_window -= m_data_window.front().bytes;
        m_data_window.pop();
    }
}

int CSLSBitrateLimit::calculate_current_bitrate_kbps(int64_t current_time_ms) const
{
    if (m_data_window.empty()) {
        return 0;
    }
    
    int64_t window_start = current_time_ms - m_window_ms;
    int64_t actual_start = std::max(window_start, m_data_window.front().timestamp_ms);
    int64_t actual_window_ms = current_time_ms - actual_start;
    
    if (actual_window_ms <= 0) {
        return 0;
    }
    
    // Calculate bitrate: (bytes * 8 bits/byte * 1000 ms/s) / (window_ms * 1000 bits/kbit)
    return (int)(m_total_bytes_in_window * 8 * 1000 / actual_window_ms / 1000);
}

int CSLSBitrateLimit::get_current_bitrate_kbps() const
{
    return calculate_current_bitrate_kbps(sls_gettime_ms());
}

CSLSBitrateLimit::BitrateStats CSLSBitrateLimit::get_stats() const
{
    BitrateStats stats;
    int64_t current_time = sls_gettime_ms();
    
    stats.total_bytes_received = m_total_bytes_received;
    stats.total_bytes_dropped = m_total_bytes_dropped;
    stats.current_bitrate_kbps = calculate_current_bitrate_kbps(current_time);
    stats.average_bitrate_kbps = stats.current_bitrate_kbps; // In sliding window, current = average
    stats.is_limiting_active = (m_max_bitrate_kbps > 0) && (stats.current_bitrate_kbps > m_max_bitrate_kbps);
    
    return stats;
}

void CSLSBitrateLimit::reset_stats()
{
    m_total_bytes_received = 0;
    m_total_bytes_dropped = 0;
    m_last_cleanup_time = sls_gettime_ms();
}