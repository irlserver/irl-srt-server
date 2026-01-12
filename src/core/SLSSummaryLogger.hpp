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

#include <cstdint>
#include <atomic>
#include <mutex>
#include <string>

/**
 * Summary logger for periodic operational statistics
 * 
 * Tracks high-level metrics and generates periodic summary logs:
 * - Active publishers and players
 * - Connection/disconnection counts
 * - Error counts
 * - Traffic statistics
 * 
 * Example output:
 * [summary] Active: 1 publishers, 23 players, 1 streams | Last 60s: 15 connects, 12 disconnects, 0 errors
 */
class CSLSSummaryLogger
{
public:
    CSLSSummaryLogger();
    ~CSLSSummaryLogger();

    /**
     * Record events
     */
    void record_player_connect();
    void record_player_disconnect();
    void record_publisher_start();
    void record_publisher_stop();
    void record_error();
    
    /**
     * Set current active counts (called by manager)
     */
    void set_active_counts(int publishers, int players, int streams);
    
    /**
     * Check if summary should be logged and generate log message
     * @param interval_sec Interval in seconds between summaries (default: 60)
     * @return true if summary should be logged (along with message in out_message)
     */
    bool should_log_summary(int interval_sec, std::string& out_message);

    /**
     * Reset all counters (useful for testing or config reload)
     */
    void reset();

private:
    // Event counters (since last summary)
    std::atomic<int> m_player_connects;
    std::atomic<int> m_player_disconnects;
    std::atomic<int> m_publisher_starts;
    std::atomic<int> m_publisher_stops;
    std::atomic<int> m_errors;
    
    // Current active counts
    std::atomic<int> m_active_publishers;
    std::atomic<int> m_active_players;
    std::atomic<int> m_active_streams;
    
    // Timing
    int64_t m_last_summary_time_ms;
    std::mutex m_mutex;
};
