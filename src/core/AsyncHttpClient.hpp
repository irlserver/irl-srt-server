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

#include "../../lib/thread-pool/include/BS_thread_pool.hpp"
#include <future>
#include <string>
#include <chrono>

/**
 * Async HTTP response structure
 */
struct AsyncHttpResponse {
    bool success;
    int status_code;
    std::string body;
    std::string error;
    int64_t duration_ms;
    
    AsyncHttpResponse() : success(false), status_code(0), duration_ms(0) {}
};

/**
 * High-performance async HTTP client using BS::thread_pool
 * 
 * FEATURES:
 * - NON-BLOCKING: All requests execute asynchronously in a thread pool
 * - Returns immediately with std::shared_future for immediate continue
 * - Prevents thread starvation on listener thread
 * - Perfect for player key validation, webhook calls, and auth APIs
 * - Uses cpp-httplib v0.18.0+ for actual HTTP operations
 * 
 * USAGE:
 *   auto future = AsyncHttpClient::instance().get_async("http://example.com/api", 5);
 *   // Do other work here...
 *   auto response = future.get();  // Wait for result when needed
 * 
 * PERFORMANCE BENEFITS:
 * - Listener thread never blocks on network I/O
 * - Supports thousands of concurrent connections without thread pool overhead
 * - Graceful timeout handling
 * - Metrics for monitoring thread pool health
 */
class AsyncHttpClient {
public:
    static AsyncHttpClient& instance() {
        static AsyncHttpClient client;
        return client;
    }

    /**
     * Async GET request - returns immediately with a future
     * The actual HTTP request happens in the thread pool
     * @param url Target URL (supports http:// and https://)
     * @param timeout_sec Request timeout in seconds (default 5)
     * @return shared_future that can be waited on
     */
    std::shared_future<AsyncHttpResponse> get_async(const std::string& url, int timeout_sec = 5);

    /**
     * Async POST request - returns immediately with a future
     * @param url Target URL
     * @param body Request body payload
     * @param content_type MIME type (default "application/json")
     * @param timeout_sec Request timeout in seconds (default 5)
     * @return shared_future that can be waited on
     */
    std::shared_future<AsyncHttpResponse> post_async(const std::string& url, 
                                               const std::string& body,
                                               const std::string& content_type,
                                               int timeout_sec = 5);

    /**
     * Get thread pool statistics
     */
    size_t get_tasks_queued() const;
    size_t get_tasks_running() const;
    size_t get_thread_count() const;

private:
    AsyncHttpClient();
    ~AsyncHttpClient();

    AsyncHttpClient(const AsyncHttpClient&) = delete;
    AsyncHttpClient& operator=(const AsyncHttpClient&) = delete;

    static AsyncHttpResponse execute_get(const std::string& url, int timeout_sec);
    static AsyncHttpResponse execute_post(const std::string& url, 
                                          const std::string& body,
                                          const std::string& content_type,
                                          int timeout_sec);

    static bool parse_url(const std::string& url, 
                         std::string& scheme, 
                         std::string& host, 
                         int& port, 
                         std::string& path);

    BS::thread_pool<> m_pool;
};
