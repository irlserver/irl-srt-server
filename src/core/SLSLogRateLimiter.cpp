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

#include "SLSLogRateLimiter.hpp"
#include "common.hpp"

CSLSLogRateLimiter::CSLSLogRateLimiter(int64_t window_ms, int threshold)
    : m_window_ms(window_ms), m_threshold(threshold)
{
}

CSLSLogRateLimiter::~CSLSLogRateLimiter()
{
}

bool CSLSLogRateLimiter::should_log(const std::string& key, EventStats& stats)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int64_t current_time_ms = sls_gettime_ms();
    
    // Cleanup old entries periodically (every 100 events)
    static int cleanup_counter = 0;
    if (++cleanup_counter >= 100)
    {
        cleanup_counter = 0;
        cleanup_old_entries(current_time_ms);
    }
    
    auto it = m_events.find(key);
    
    if (it == m_events.end())
    {
        // First occurrence of this event
        EventStats new_stats;
        new_stats.first_timestamp_ms = current_time_ms;
        new_stats.last_timestamp_ms = current_time_ms;
        new_stats.count = 1;
        new_stats.total_suppressed = 0;
        
        m_events[key] = new_stats;
        stats = new_stats;
        return true; // Always log first occurrence
    }
    
    EventStats& event_stats = it->second;
    
    // Check if we're outside the time window - reset if so
    if (current_time_ms - event_stats.first_timestamp_ms > m_window_ms)
    {
        event_stats.first_timestamp_ms = current_time_ms;
        event_stats.last_timestamp_ms = current_time_ms;
        event_stats.count = 1;
        event_stats.total_suppressed = 0;
        stats = event_stats;
        return true; // Log first event of new window
    }
    
    // Within window - increment count
    event_stats.count++;
    event_stats.last_timestamp_ms = current_time_ms;
    
    // Check if we should log (every Nth occurrence)
    if (event_stats.count % m_threshold == 0)
    {
        stats = event_stats;
        event_stats.total_suppressed = 0; // Reset after logging
        return true;
    }
    
    // Suppress this log
    event_stats.total_suppressed++;
    stats = event_stats;
    return false;
}

void CSLSLogRateLimiter::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
}

void CSLSLogRateLimiter::set_window_ms(int64_t window_ms)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_window_ms = window_ms;
}

void CSLSLogRateLimiter::set_threshold(int threshold)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_threshold = threshold;
}

void CSLSLogRateLimiter::cleanup_old_entries(int64_t current_time_ms)
{
    // Remove entries older than 10 windows (to prevent unbounded growth)
    int64_t expiry_time = current_time_ms - (m_window_ms * 10);
    
    for (auto it = m_events.begin(); it != m_events.end();)
    {
        if (it->second.last_timestamp_ms < expiry_time)
        {
            it = m_events.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
