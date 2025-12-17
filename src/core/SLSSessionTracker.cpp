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

#include "SLSSessionTracker.hpp"
#include "common.hpp"
#include <sstream>
#include <iomanip>

// Initialize static counter
std::atomic<uint32_t> CSLSSessionTracker::s_counter(0);

std::string CSLSSessionTracker::generate_session_id(bool short_form)
{
    uint32_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);
    
    if (short_form)
    {
        // Generate short session ID (just hex counter)
        // Format: "a3f2" (4 hex digits, wraps around at 0xFFFF)
        std::ostringstream oss;
        oss << std::hex << std::setw(4) << std::setfill('0') << (counter & 0xFFFF);
        return oss.str();
    }
    else
    {
        // Generate full session ID with timestamp
        // Format: "1734437445123-a3f2"
        int64_t timestamp_ms = sls_gettime_ms();
        std::ostringstream oss;
        oss << timestamp_ms << "-" 
            << std::hex << std::setw(4) << std::setfill('0') << (counter & 0xFFFF);
        return oss.str();
    }
}
