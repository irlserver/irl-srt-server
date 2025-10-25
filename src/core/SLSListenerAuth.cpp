#include "SLSListener.hpp"
#include "HttpClient.hpp"
#include "util.hpp"
#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <regex>
#include <deque>
#include <string>
#include <cstring>
#include <unistd.h>

using namespace std;

bool CSLSListener::validate_player_key_format(const char* player_key)
{
    if (!player_key) {
        return false;
    }

    size_t key_len = strlen(player_key);

    if (key_len < (size_t)m_player_key_min_length || key_len > (size_t)m_player_key_max_length) {
        spdlog::warn("[{}] CSLSListener::validate_player_key_format, key length {} outside range [{}, {}].",
                     fmt::ptr(this), key_len, m_player_key_min_length, m_player_key_max_length);
        return false;
    }

    try {
        if (!std::regex_match(player_key, m_player_key_regex)) {
            spdlog::warn("[{}] CSLSListener::validate_player_key_format, key '{}' doesn't match required format.",
                         fmt::ptr(this), player_key);
            return false;
        }
    } catch (const std::regex_error& e) {
        spdlog::error("[{}] CSLSListener::validate_player_key_format, regex error: {}.", fmt::ptr(this), e.what());
        return false;
    }

    return true;
}

bool CSLSListener::is_rate_limited(const char* client_ip)
{
    if (m_player_key_rate_limit_requests == -1) {
        return false;
    }
    if (!client_ip || strlen(client_ip) == 0) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    std::string ip_str(client_ip);

    cleanup_expired_rate_limits();

    auto rate_it = m_rate_limit_map.find(ip_str);
    if (rate_it == m_rate_limit_map.end()) {
        return false;
    }

    RateLimitEntry& entry = rate_it->second;
    auto window_start = now - std::chrono::milliseconds(m_player_key_rate_limit_window);
    while (!entry.request_times.empty() && entry.request_times.front() < window_start) {
        entry.request_times.pop_front();
    }

    if ((int)entry.request_times.size() >= m_player_key_rate_limit_requests) {
        spdlog::warn("[{}] CSLSListener::is_rate_limited, IP '{}' exceeded rate limit: {} requests in {}ms window.",
                     fmt::ptr(this), client_ip, entry.request_times.size(), m_player_key_rate_limit_window);
        return true;
    }

    return false;
}

void CSLSListener::update_rate_limit(const char* client_ip)
{
    if (m_player_key_rate_limit_requests == -1) {
        return;
    }
    if (!client_ip || strlen(client_ip) == 0) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    std::string ip_str(client_ip);
    m_rate_limit_map[ip_str].request_times.push_back(now);
}

void CSLSListener::cleanup_expired_rate_limits()
{
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::milliseconds(m_player_key_rate_limit_window * 2);

    for (auto it = m_rate_limit_map.begin(); it != m_rate_limit_map.end();) {
        RateLimitEntry& entry = it->second;
        while (!entry.request_times.empty() && entry.request_times.front() < window_start) {
            entry.request_times.pop_front();
        }
        if (entry.request_times.empty()) {
            it = m_rate_limit_map.erase(it);
        } else {
            ++it;
        }
    }
}

int CSLSListener::validate_player_key(const char* player_key, char* resolved_stream_id, size_t resolved_stream_id_size, const char* client_ip)
{
    if (strlen(m_player_key_auth_url) == 0) {
        spdlog::debug("[{}] CSLSListener::validate_player_key, player key authentication disabled.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!validate_player_key_format(player_key)) {
        spdlog::warn("[{}] CSLSListener::validate_player_key, invalid player key format for key='{}'.", fmt::ptr(this), player_key);
        return SLS_ERROR;
    }

    if (client_ip && is_rate_limited(client_ip)) {
        spdlog::warn("[{}] CSLSListener::validate_player_key, rate limited request from IP='{}'.", fmt::ptr(this), client_ip);
        return SLS_ERROR;
    }

    std::string key_str(player_key);
    auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(m_cache_mutex);
        auto cache_it = m_player_key_cache.find(key_str);
        if (cache_it != m_player_key_cache.end()) {
            if (now < cache_it->second.expiry_time) {
                if (cache_it->second.is_valid) {
                    strlcpy(resolved_stream_id, cache_it->second.resolved_stream_id.c_str(), resolved_stream_id_size);
                    spdlog::debug("[{}] CSLSListener::validate_player_key, cache hit (valid) for player_key='{}', resolved to: '{}'.",
                                 fmt::ptr(this), player_key, resolved_stream_id);
                    return SLS_OK;
                } else {
                    spdlog::debug("[{}] CSLSListener::validate_player_key, cache hit (invalid) for player_key='{}'",
                                 fmt::ptr(this), player_key);
                    return SLS_ERROR;
                }
            } else {
                m_player_key_cache.erase(cache_it);
                spdlog::debug("[{}] CSLSListener::validate_player_key, cache expired for player_key='{}'.", fmt::ptr(this), player_key);
            }
        }
    }

    if (client_ip) {
        update_rate_limit(client_ip);
    }

    CHttpClient *http_client = new CHttpClient;
    if (!http_client) {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to create HTTP client.", fmt::ptr(this));
        return SLS_ERROR;
    }

    http_client->set_timeout(m_player_key_auth_timeout / 1000);

    char auth_url[URL_MAX_LEN * 2] = {0};
    if (strlen(m_player_key_auth_url) > URL_MAX_LEN - 100) {
        spdlog::error("[{}] CSLSListener::validate_player_key, base auth URL too long.", fmt::ptr(this));
        delete http_client;
        return SLS_ERROR;
    }
    int ret = snprintf(auth_url, sizeof(auth_url), "%s?player_key=%s",
                       m_player_key_auth_url, url_encode(player_key).c_str());
    if (ret < 0 || (unsigned)ret >= sizeof(auth_url)) {
        spdlog::error("[{}] CSLSListener::validate_player_key, auth URL too long, ret={:d}.", fmt::ptr(this), ret);
        delete http_client;
        return SLS_ERROR;
    }

    spdlog::info("[{}] CSLSListener::validate_player_key, validating player_key='{}' at URL='{}', timeout={}ms.",
                 fmt::ptr(this), player_key, auth_url, m_player_key_auth_timeout);

    ret = http_client->open(auth_url, "GET");
    if (ret != SLS_OK) {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to open HTTP request, ret={:d}.", fmt::ptr(this), ret);
        delete http_client;
        return SLS_ERROR;
    }

    int64_t start_time = sls_gettime_ms();
    int64_t timeout_ms = m_player_key_auth_timeout;
    bool request_completed = false;

    while (!request_completed) {
        http_client->handler();
        if (SLS_OK == http_client->check_finished()) {
            request_completed = true;
            break;
        }
        int64_t current_time = sls_gettime_ms();
        if (current_time - start_time >= timeout_ms) {
            spdlog::error("[{}] CSLSListener::validate_player_key, HTTP request timeout after {}ms for player_key='{}'.",
                         fmt::ptr(this), timeout_ms, player_key);
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }
        if (SLS_OK == http_client->check_timeout(current_time)) {
            spdlog::error("[{}] CSLSListener::validate_player_key, HTTP client timeout for player_key='{}'.",
                         fmt::ptr(this), player_key);
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }
        usleep(1000);
    }

    HTTP_RESPONSE_INFO *response = http_client->get_response_info();
    if (!response) {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to get HTTP response.", fmt::ptr(this));
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    if (response->m_response_code != HTTP_RESPONSE_CODE_200) {
        spdlog::error("[{}] CSLSListener::validate_player_key, API returned error code: {}, response: '{}'.",
                     fmt::ptr(this), response->m_response_code.c_str(), response->m_response_content.c_str());
        PlayerKeyCacheEntry negative_cache_entry;
        negative_cache_entry.resolved_stream_id = "";
        negative_cache_entry.is_valid = false;
        negative_cache_entry.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration / 4);
        negative_cache_entry.has_max_players_override = false;
        negative_cache_entry.max_players_per_stream_override = -1;
        {
            std::lock_guard<std::mutex> lk(m_cache_mutex);
            m_player_key_cache[key_str] = negative_cache_entry;
        }
        spdlog::debug("[{}] CSLSListener::validate_player_key, cached negative result for player_key='{}', expires in {}ms.",
                     fmt::ptr(this), player_key, m_player_key_cache_duration / 4);
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    std::string response_content = response->m_response_content;
    spdlog::info("[{}] CSLSListener::validate_player_key, API response: '{}'.", fmt::ptr(this), response_content.c_str());

    std::string stream_id;
    int json_max_players_override = -1;
    bool json_has_max_players_override = false;
    try {
        nlohmann::json json_response = nlohmann::json::parse(response_content);
        if (json_response.contains("stream_id") && json_response["stream_id"].is_string()) {
            stream_id = json_response["stream_id"];
        } else {
            spdlog::error("[{}] CSLSListener::validate_player_key, JSON response missing 'stream_id' field or field is not a string.", fmt::ptr(this));
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }
        if (json_response.contains("max_players_per_stream")) {
            if (json_response["max_players_per_stream"].is_number_integer()) {
                json_max_players_override = json_response["max_players_per_stream"].get<int>();
                json_has_max_players_override = true;
            } else {
                spdlog::warn("[{}] CSLSListener::validate_player_key, 'max_players_per_stream' present but not an integer; ignoring.", fmt::ptr(this));
            }
        }
    } catch (const nlohmann::json::exception& e) {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to parse JSON response: {}.", fmt::ptr(this), e.what());
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    http_client->close();
    delete http_client;

    if (stream_id.empty() || stream_id.length() >= resolved_stream_id_size) {
        spdlog::error("[{}] CSLSListener::validate_player_key, invalid or empty stream_id returned: '{}'.",
                     fmt::ptr(this), stream_id.c_str());
        return SLS_ERROR;
    }

    PlayerKeyCacheEntry cache_entry;
    cache_entry.resolved_stream_id = stream_id;
    cache_entry.is_valid = true;
    cache_entry.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration);
    cache_entry.has_max_players_override = json_has_max_players_override;
    cache_entry.max_players_per_stream_override = json_max_players_override;
    {
        std::lock_guard<std::mutex> lk(m_cache_mutex);
        m_player_key_cache[key_str] = cache_entry;
    }

    spdlog::debug("[{}] CSLSListener::validate_player_key, cached result for player_key='{}', expires in {}ms.{}",
                 fmt::ptr(this), player_key, m_player_key_cache_duration,
                 cache_entry.has_max_players_override ? " (with per-key max_players_per_stream override)" : "");

    strlcpy(resolved_stream_id, stream_id.c_str(), resolved_stream_id_size);
    spdlog::info("[{}] CSLSListener::validate_player_key, player_key='{}' validated successfully, resolved to stream_id='{}'.",
                 fmt::ptr(this), player_key, resolved_stream_id);

    return SLS_OK;
}