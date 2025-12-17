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

#include "SLSSummaryLogger.hpp"
#include "common.hpp"
#include <sstream>

CSLSSummaryLogger::CSLSSummaryLogger()
    : m_player_connects(0),
      m_player_disconnects(0),
      m_publisher_starts(0),
      m_publisher_stops(0),
      m_errors(0),
      m_active_publishers(0),
      m_active_players(0),
      m_active_streams(0),
      m_last_summary_time_ms(sls_gettime_ms())
{
}

CSLSSummaryLogger::~CSLSSummaryLogger()
{
}

void CSLSSummaryLogger::record_player_connect()
{
    m_player_connects.fetch_add(1, std::memory_order_relaxed);
}

void CSLSSummaryLogger::record_player_disconnect()
{
    m_player_disconnects.fetch_add(1, std::memory_order_relaxed);
}

void CSLSSummaryLogger::record_publisher_start()
{
    m_publisher_starts.fetch_add(1, std::memory_order_relaxed);
}

void CSLSSummaryLogger::record_publisher_stop()
{
    m_publisher_stops.fetch_add(1, std::memory_order_relaxed);
}

void CSLSSummaryLogger::record_error()
{
    m_errors.fetch_add(1, std::memory_order_relaxed);
}

void CSLSSummaryLogger::set_active_counts(int publishers, int players, int streams)
{
    m_active_publishers.store(publishers, std::memory_order_relaxed);
    m_active_players.store(players, std::memory_order_relaxed);
    m_active_streams.store(streams, std::memory_order_relaxed);
}

bool CSLSSummaryLogger::should_log_summary(int interval_sec, std::string& out_message)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int64_t current_time_ms = sls_gettime_ms();
    int64_t interval_ms = interval_sec * 1000;
    
    if (current_time_ms - m_last_summary_time_ms < interval_ms)
    {
        return false;
    }
    
    // Time to generate summary
    int connects = m_player_connects.exchange(0, std::memory_order_relaxed);
    int disconnects = m_player_disconnects.exchange(0, std::memory_order_relaxed);
    int pub_starts = m_publisher_starts.exchange(0, std::memory_order_relaxed);
    int pub_stops = m_publisher_stops.exchange(0, std::memory_order_relaxed);
    int errors = m_errors.exchange(0, std::memory_order_relaxed);
    
    int active_pubs = m_active_publishers.load(std::memory_order_relaxed);
    int active_plays = m_active_players.load(std::memory_order_relaxed);
    int active_strms = m_active_streams.load(std::memory_order_relaxed);
    
    // Generate summary message
    std::ostringstream oss;
    oss << "[summary] Active: " << active_pubs << " publishers, " 
        << active_plays << " players, " << active_strms << " streams";
    
    if (connects > 0 || disconnects > 0 || pub_starts > 0 || pub_stops > 0 || errors > 0)
    {
        oss << " | Last " << interval_sec << "s: ";
        
        if (connects > 0)
            oss << connects << " player connects, ";
        if (disconnects > 0)
            oss << disconnects << " player disconnects, ";
        if (pub_starts > 0)
            oss << pub_starts << " publishers started, ";
        if (pub_stops > 0)
            oss << pub_stops << " publishers stopped, ";
        if (errors > 0)
            oss << errors << " errors";
        
        // Remove trailing comma and space
        std::string msg = oss.str();
        if (msg.length() >= 2 && msg.substr(msg.length() - 2) == ", ")
        {
            msg = msg.substr(0, msg.length() - 2);
        }
        out_message = msg;
    }
    else
    {
        out_message = oss.str();
    }
    
    m_last_summary_time_ms = current_time_ms;
    return true;
}

void CSLSSummaryLogger::reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_player_connects.store(0, std::memory_order_relaxed);
    m_player_disconnects.store(0, std::memory_order_relaxed);
    m_publisher_starts.store(0, std::memory_order_relaxed);
    m_publisher_stops.store(0, std::memory_order_relaxed);
    m_errors.store(0, std::memory_order_relaxed);
    m_active_publishers.store(0, std::memory_order_relaxed);
    m_active_players.store(0, std::memory_order_relaxed);
    m_active_streams.store(0, std::memory_order_relaxed);
    m_last_summary_time_ms = sls_gettime_ms();
}
