/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Edward.Wu
 */

#include "AsyncHttpClient.hpp"
#include <httplib.h>
#include <chrono>
#include "spdlog/spdlog.h"

AsyncHttpClient::AsyncHttpClient() : m_pool(std::max(4u, std::thread::hardware_concurrency() / 2)) {
    spdlog::info("[AsyncHttpClient] Initialized with {} worker threads", m_pool.get_thread_count());
}

AsyncHttpClient::~AsyncHttpClient() {
    spdlog::info("[AsyncHttpClient] Shutting down");
}

std::shared_future<AsyncHttpResponse> AsyncHttpClient::get_async(const std::string& url, int timeout_sec) {
    return m_pool.submit_task([url, timeout_sec]() {
        return execute_get(url, timeout_sec);
    }).share();
}

std::shared_future<AsyncHttpResponse> AsyncHttpClient::post_async(const std::string& url, 
                                           const std::string& body,
                                           const std::string& content_type,
                                           int timeout_sec) {
    return m_pool.submit_task([url, body, content_type, timeout_sec]() {
        return execute_post(url, body, content_type, timeout_sec);
    }).share();
}

size_t AsyncHttpClient::get_tasks_queued() const {
    return m_pool.get_tasks_queued();
}

size_t AsyncHttpClient::get_tasks_running() const {
    return m_pool.get_tasks_running();
}

size_t AsyncHttpClient::get_thread_count() const {
    return m_pool.get_thread_count();
}

AsyncHttpResponse AsyncHttpClient::execute_get(const std::string& url, int timeout_sec) {
    AsyncHttpResponse response;
    auto start = std::chrono::steady_clock::now();
    
    try {
        std::string scheme, host, path;
        int port;
        
        if (!parse_url(url, scheme, host, port, path)) {
            response.error = "Failed to parse URL: " + url;
            spdlog::error("[AsyncHttpClient] Failed to parse URL: {}", url);
            return response;
        }

        httplib::Client client(host, port);
        client.set_connection_timeout(timeout_sec, 0);
        client.set_read_timeout(timeout_sec, 0);
        client.set_write_timeout(timeout_sec, 0);

        auto res = client.Get(path.c_str());
        
        auto end = std::chrono::steady_clock::now();
        response.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        if (res) {
            response.success = true;
            response.status_code = res->status;
            response.body = res->body;
            spdlog::debug("[AsyncHttpClient] GET {} completed in {}ms, status={}", 
                         url, response.duration_ms, res->status);
        } else {
            response.error = httplib::to_string(res.error());
            spdlog::error("[AsyncHttpClient] GET {} failed after {}ms: {}", 
                         url, response.duration_ms, response.error);
        }
    } catch (const std::exception& e) {
        auto end = std::chrono::steady_clock::now();
        response.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        response.error = std::string("Exception: ") + e.what();
        spdlog::error("[AsyncHttpClient] GET {} exception: {}", url, e.what());
    }

    return response;
}

AsyncHttpResponse AsyncHttpClient::execute_post(const std::string& url, 
                                      const std::string& body,
                                      const std::string& content_type,
                                      int timeout_sec) {
    AsyncHttpResponse response;
    auto start = std::chrono::steady_clock::now();
    
    try {
        std::string scheme, host, path;
        int port;
        
        if (!parse_url(url, scheme, host, port, path)) {
            response.error = "Failed to parse URL: " + url;
            spdlog::error("[AsyncHttpClient] Failed to parse URL: {}", url);
            return response;
        }

        httplib::Client client(host, port);
        client.set_connection_timeout(timeout_sec, 0);
        client.set_read_timeout(timeout_sec, 0);
        client.set_write_timeout(timeout_sec, 0);

        auto res = client.Post(path.c_str(), body, content_type.c_str());
        
        auto end = std::chrono::steady_clock::now();
        response.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        if (res) {
            response.success = true;
            response.status_code = res->status;
            response.body = res->body;
            spdlog::debug("[AsyncHttpClient] POST {} completed in {}ms, status={}", 
                         url, response.duration_ms, res->status);
        } else {
            response.error = httplib::to_string(res.error());
            spdlog::error("[AsyncHttpClient] POST {} failed after {}ms: {}", 
                         url, response.duration_ms, response.error);
        }
    } catch (const std::exception& e) {
        auto end = std::chrono::steady_clock::now();
        response.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        response.error = std::string("Exception: ") + e.what();
        spdlog::error("[AsyncHttpClient] POST {} exception: {}", url, e.what());
    }

    return response;
}

bool AsyncHttpClient::parse_url(const std::string& url, 
                     std::string& scheme, 
                     std::string& host, 
                     int& port, 
                     std::string& path) {
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return false;
    }

    scheme = url.substr(0, scheme_end);
    size_t host_start = scheme_end + 3;
    
    size_t path_start = url.find('/', host_start);
    std::string host_port;
    
    if (path_start != std::string::npos) {
        host_port = url.substr(host_start, path_start - host_start);
        path = url.substr(path_start);
    } else {
        host_port = url.substr(host_start);
        path = "/";
    }

    size_t port_start = host_port.find(':');
    if (port_start != std::string::npos) {
        host = host_port.substr(0, port_start);
        port = std::stoi(host_port.substr(port_start + 1));
    } else {
        host = host_port;
        port = (scheme == "https") ? 443 : 80;
    }

    return true;
}
