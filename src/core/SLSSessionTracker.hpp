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
#include <cstdint>
#include <atomic>

/**
 * Session ID tracker for logging
 * 
 * Generates unique, short session IDs for connection tracking.
 * Format: {timestamp_ms}-{counter}
 * Example: "1734437445123-a3f2" or just "a3f2" (short form)
 * 
 * Session IDs allow correlating log messages across a connection's lifecycle.
 */
class CSLSSessionTracker
{
public:
    /**
     * Generate a new session ID
     * @param short_form If true, returns only the counter portion (default: true)
     * @return Session ID string
     */
    static std::string generate_session_id(bool short_form = true);

private:
    static std::atomic<uint32_t> s_counter;
};
