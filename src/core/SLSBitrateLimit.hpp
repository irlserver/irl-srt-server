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

#include <queue>
#include <cstdint>

/**
 * CSLSBitrateLimit - Implements sliding window average bitrate limiting
 * Allows temporary spikes while enforcing average limits over time
 */
class CSLSBitrateLimit
{
public:
    CSLSBitrateLimit();
    virtual ~CSLSBitrateLimit();

    /**
     * Initialize the bitrate limiter
     * @param max_bitrate_kbps Maximum average bitrate in kilobits per second (0 = unlimited)
     * @param violation_timeout_seconds Timeout in seconds before disconnecting violating streams (default: 30s)
     * @param window_ms Time window for averaging in milliseconds (default: 5000ms = 5 seconds)
     * @param spike_tolerance Multiplier for spike tolerance (default: 2.0 = allow 2x spikes)
     */
    int init(int max_bitrate_kbps, int violation_timeout_seconds = 30, int window_ms = 5000, float spike_tolerance = 2.0f);

    enum BitrateCheckResult {
        BITRATE_OK = 0,           // Data is within limits
        BITRATE_VIOLATION = 1,    // Data exceeds limits but stream continues
        BITRATE_DISCONNECT = 2    // Stream should be disconnected due to sustained violations
    };

    /**
     * Check incoming data against bitrate limits
     * @param data_bytes Number of bytes being received
     * @param current_time_ms Current timestamp in milliseconds
     * @return BitrateCheckResult indicating action to take
     */
    BitrateCheckResult check_data_bitrate(int data_bytes, int64_t current_time_ms);

    /**
     * Get current average bitrate in kbps
     */
    int get_current_bitrate_kbps() const;

    /**
     * Get statistics about dropped data
     */
         struct BitrateStats {
         int64_t total_bytes_received;
         int64_t total_bytes_dropped;
         int current_bitrate_kbps;
         int average_bitrate_kbps;
         bool is_limiting_active;
         bool is_in_violation;
         int64_t violation_duration_ms;
     };
    
    BitrateStats get_stats() const;

    /**
     * Reset statistics
     */
    void reset_stats();

private:
    struct DataPoint {
        int64_t timestamp_ms;
        int bytes;
    };

         int m_max_bitrate_kbps;
     int m_window_ms;
     float m_spike_tolerance;
     int m_violation_threshold_ms;  // Time limit for sustained violations before disconnect
     
     std::queue<DataPoint> m_data_window;
     int64_t m_total_bytes_in_window;
     
     // Violation tracking
     bool m_in_violation;
     int64_t m_violation_start_time;
     int64_t m_last_violation_log_time;
     
     // Statistics
     int64_t m_total_bytes_received;
     int64_t m_total_bytes_dropped;
     int64_t m_last_cleanup_time;
    
    void cleanup_old_data(int64_t current_time_ms);
    int calculate_current_bitrate_kbps(int64_t current_time_ms) const;
};