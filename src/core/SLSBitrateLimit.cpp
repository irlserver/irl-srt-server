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
    m_violation_threshold_ms = 30000; // 30 seconds of sustained violations = disconnect (default)
    m_total_bytes_in_window = 0;
    
    // Violation tracking
    m_in_violation = false;
    m_violation_start_time = 0;
    m_last_violation_log_time = 0;
    
    // Statistics
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

int CSLSBitrateLimit::init(int max_bitrate_kbps, int violation_timeout_seconds, int window_ms, float spike_tolerance)
{
    if (max_bitrate_kbps < 0 || violation_timeout_seconds <= 0 || window_ms <= 0 || spike_tolerance < 1.0f) {
        spdlog::error("[{}] CSLSBitrateLimit::init, invalid parameters: max_bitrate_kbps={:d}, violation_timeout_seconds={:d}, window_ms={:d}, spike_tolerance={:.2f}",
                     fmt::ptr(this), max_bitrate_kbps, violation_timeout_seconds, window_ms, spike_tolerance);
        return SLS_ERROR;
    }

    m_max_bitrate_kbps = max_bitrate_kbps;
    m_violation_threshold_ms = violation_timeout_seconds * 1000; // Convert seconds to milliseconds
    m_window_ms = window_ms;
    m_spike_tolerance = spike_tolerance;
    
    // Clear any existing data
    while (!m_data_window.empty()) {
        m_data_window.pop();
    }
    
    m_total_bytes_in_window = 0;
    reset_stats();
    
    spdlog::info("[{}] CSLSBitrateLimit::init, initialized with max_bitrate={:d}kbps, violation_timeout={:d}s, window={:d}ms, spike_tolerance={:.2f}",
                fmt::ptr(this), max_bitrate_kbps, violation_timeout_seconds, window_ms, spike_tolerance);
    
    return SLS_OK;
}

CSLSBitrateLimit::BitrateCheckResult CSLSBitrateLimit::check_data_bitrate(int data_bytes, int64_t current_time_ms)
{
    m_total_bytes_received += data_bytes;
    
    // Always add data to window for statistics (we don't drop packets anymore)
    DataPoint point = {current_time_ms, data_bytes};
    m_data_window.push(point);
    m_total_bytes_in_window += data_bytes;
    
    // If no limit is set, always return OK
    if (m_max_bitrate_kbps == 0) {
        cleanup_old_data(current_time_ms);
        return BITRATE_OK;
    }
    
    // Clean up old data periodically (every second)
    if (current_time_ms - m_last_cleanup_time > 1000) {
        cleanup_old_data(current_time_ms);
        m_last_cleanup_time = current_time_ms;
    }
    
    // Calculate current bitrate
    int64_t effective_window_ms = m_window_ms;
    if (!m_data_window.empty()) {
        int64_t actual_window_ms = current_time_ms - m_data_window.front().timestamp_ms;
        if (actual_window_ms < m_window_ms) {
            effective_window_ms = std::max((int64_t)1000, actual_window_ms); // At least 1 second
        }
    }
    
    // Calculate current bitrate in kbps
    int current_bitrate_kbps = (int)(m_total_bytes_in_window * 8 * 1000 / effective_window_ms / 1000);
    
    // Allow spikes up to spike_tolerance * max_bitrate
    int spike_limit_kbps = (int)(m_max_bitrate_kbps * m_spike_tolerance);
    
    // Check if we're in violation
    bool exceeds_spike_limit = (current_bitrate_kbps > spike_limit_kbps);
    
    if (exceeds_spike_limit) {
        // We're exceeding the spike limit
        if (!m_in_violation) {
            // Starting a new violation period
            m_in_violation = true;
            m_violation_start_time = current_time_ms;
            m_last_violation_log_time = current_time_ms;
            
            spdlog::warn("[{}] CSLSBitrateLimit::check_data_bitrate, bitrate violation started. "
                        "Current bitrate: {:d}kbps, spike limit: {:d}kbps, max: {:d}kbps",
                        fmt::ptr(this), current_bitrate_kbps, spike_limit_kbps, m_max_bitrate_kbps);
        } else {
            // Continuing violation - log periodically (every 2 seconds)
            if (current_time_ms - m_last_violation_log_time > 2000) {
                int64_t violation_duration = current_time_ms - m_violation_start_time;
                spdlog::warn("[{}] CSLSBitrateLimit::check_data_bitrate, sustained violation for {:d}ms. "
                            "Current bitrate: {:d}kbps, limit: {:d}kbps",
                            fmt::ptr(this), (int)violation_duration, current_bitrate_kbps, spike_limit_kbps);
                m_last_violation_log_time = current_time_ms;
            }
        }
        
        // Check if we should disconnect
        int64_t violation_duration = current_time_ms - m_violation_start_time;
        if (violation_duration >= m_violation_threshold_ms) {
            spdlog::error("[{}] CSLSBitrateLimit::check_data_bitrate, disconnecting stream due to sustained bitrate violation. "
                         "Duration: {:d}ms, current bitrate: {:d}kbps, limit: {:d}kbps",
                         fmt::ptr(this), (int)violation_duration, current_bitrate_kbps, spike_limit_kbps);
            return BITRATE_DISCONNECT;
        }
        
        return BITRATE_VIOLATION;
    } else {
        // We're within limits
        if (m_in_violation) {
            // Violation period ended
            int64_t violation_duration = current_time_ms - m_violation_start_time;
            spdlog::info("[{}] CSLSBitrateLimit::check_data_bitrate, bitrate violation ended after {:d}ms. "
                        "Current bitrate: {:d}kbps",
                        fmt::ptr(this), (int)violation_duration, current_bitrate_kbps);
            m_in_violation = false;
            m_violation_start_time = 0;
        }
        
        return BITRATE_OK;
    }
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
    stats.is_in_violation = m_in_violation;
    stats.violation_duration_ms = m_in_violation ? (current_time - m_violation_start_time) : 0;
    
    return stats;
}

void CSLSBitrateLimit::reset_stats()
{
    m_total_bytes_received = 0;
    m_total_bytes_dropped = 0;
    m_in_violation = false;
    m_violation_start_time = 0;
    m_last_violation_log_time = 0;
    m_last_cleanup_time = sls_gettime_ms();
}