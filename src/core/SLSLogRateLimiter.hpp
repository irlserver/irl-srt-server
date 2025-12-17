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

#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include "common.hpp"

/**
 * Rate limiter for connection log events
 * 
 * Prevents log flooding by tracking event occurrences per key (e.g., IP address)
 * and only allowing logs every N occurrences within a time window.
 * 
 * Example: If threshold=5 and window=60000ms, a player reconnecting every 5 seconds
 *          will only generate a log every 5 connections (every 25 seconds).
 */
class CSLSLogRateLimiter
{
public:
    struct EventStats
    {
        int64_t first_timestamp_ms;  // Timestamp of first event in current window
        int64_t last_timestamp_ms;   // Timestamp of most recent event
        int count;                   // Number of events in current window
        int total_suppressed;        // Total events suppressed since first event
    };

    /**
     * Constructor
     * @param window_ms Time window in milliseconds for rate limiting (default: 60000ms = 1 minute)
     * @param threshold Log every Nth event (default: 5)
     */
    CSLSLogRateLimiter(int64_t window_ms = 60000, int threshold = 5);
    ~CSLSLogRateLimiter();

    /**
     * Check if event should be logged
     * @param key Unique identifier for the event (e.g., "192.168.1.100:connect")
     * @param stats Output parameter filled with event statistics
     * @return true if event should be logged, false if suppressed
     */
    bool should_log(const std::string& key, EventStats& stats);

    /**
     * Clear all rate limit tracking (useful for testing or config reload)
     */
    void clear();

    /**
     * Set rate limiting parameters
     */
    void set_window_ms(int64_t window_ms);
    void set_threshold(int threshold);

    /**
     * Get current configuration
     */
    int64_t get_window_ms() const { return m_window_ms; }
    int get_threshold() const { return m_threshold; }

private:
    int64_t m_window_ms;  // Time window in milliseconds
    int m_threshold;      // Log every Nth event
    
    std::unordered_map<std::string, EventStats> m_events;
    std::mutex m_mutex;

    /**
     * Clean up old entries (called periodically to prevent unbounded growth)
     */
    void cleanup_old_entries(int64_t current_time_ms);
};
