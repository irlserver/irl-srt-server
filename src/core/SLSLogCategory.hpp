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

/**
 * Log categories for hierarchical logging control
 */
enum class SLSLogCategory
{
    CONNECTION = 0, // Player/publisher connect/disconnect
    LISTENER,       // Listener lifecycle, accepts
    STREAM,         // Stream lifecycle, publishers
    DATA,           // Data flow, bitrate, packets
    RELAY,          // Puller/pusher operations
    HTTP,           // HTTP API, webhooks
    AUTH,           // Authentication, player keys
    SYSTEM,         // Startup, shutdown, configuration
    COUNT           // Total number of categories
};

/**
 * Convert category to string name
 */
inline const char* sls_log_category_name(SLSLogCategory category)
{
    switch (category)
    {
    case SLSLogCategory::CONNECTION: return "connection";
    case SLSLogCategory::LISTENER:   return "listener";
    case SLSLogCategory::STREAM:     return "stream";
    case SLSLogCategory::DATA:       return "data";
    case SLSLogCategory::RELAY:      return "relay";
    case SLSLogCategory::HTTP:       return "http";
    case SLSLogCategory::AUTH:       return "auth";
    case SLSLogCategory::SYSTEM:     return "system";
    default:                         return "unknown";
    }
}

/**
 * Parse category from string
 */
inline SLSLogCategory sls_log_category_from_string(const char* str)
{
    std::string s(str);
    if (s == "connection") return SLSLogCategory::CONNECTION;
    if (s == "listener")   return SLSLogCategory::LISTENER;
    if (s == "stream")     return SLSLogCategory::STREAM;
    if (s == "data")       return SLSLogCategory::DATA;
    if (s == "relay")      return SLSLogCategory::RELAY;
    if (s == "http")       return SLSLogCategory::HTTP;
    if (s == "auth")       return SLSLogCategory::AUTH;
    if (s == "system")     return SLSLogCategory::SYSTEM;
    return SLSLogCategory::SYSTEM; // Default
}
