#include "SLSListener.hpp"
#include "AsyncHttpClient.hpp"
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

namespace {
// Hard ceiling on cached player keys. Each entry is a key string plus a
// resolved stream id (both bounded by the streamid buffer), so this bounds
// the cache's memory. Sized well above any plausible legitimate concurrent
// audience; only a rotating-key flood ever reaches it.
constexpr size_t MAX_PLAYER_KEY_CACHE_ENTRIES = 50000;
// Minimum spacing between full expired-entry sweeps of the player-key cache.
constexpr auto PLAYER_KEY_CACHE_SWEEP_INTERVAL = std::chrono::seconds(5);
// Hard ceiling on tracked source IPs for player-key rate limiting.
constexpr size_t MAX_RATE_LIMIT_ENTRIES = 100000;
// Minimum spacing between full sweeps of the rate-limit map.
constexpr auto RATE_LIMIT_CLEANUP_INTERVAL = std::chrono::seconds(1);
// Hard ceiling on concurrent in-flight player-key webhook validations. Bounds
// both the pending map and the webhook backlog a flood of distinct uncached
// keys can create. They drain quickly (the pool processes them), so this is
// only reached under abuse.
constexpr size_t MAX_PENDING_PLAYER_KEY_VALIDATIONS = 1024;
} // namespace

void CSLSListener::insert_player_key_cache_locked(const std::string& key, const PlayerKeyCacheEntry& entry)
{
    // Refreshing an existing key never grows the map.
    auto existing = m_player_key_cache.find(key);
    if (existing != m_player_key_cache.end()) {
        existing->second = entry;
        return;
    }

    if (m_player_key_cache.size() >= MAX_PLAYER_KEY_CACHE_ENTRIES) {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_player_key_cache.begin(); it != m_player_key_cache.end();) {
            if (it->second.expiry_time <= now)
                it = m_player_key_cache.erase(it);
            else
                ++it;
        }
        // All remaining entries are still live: evict the one closest to
        // expiring so a valid, recently validated key is the last to go.
        if (m_player_key_cache.size() >= MAX_PLAYER_KEY_CACHE_ENTRIES) {
            auto victim = m_player_key_cache.begin();
            for (auto it = std::next(m_player_key_cache.begin()); it != m_player_key_cache.end(); ++it) {
                if (it->second.expiry_time < victim->second.expiry_time)
                    victim = it;
            }
            if (victim != m_player_key_cache.end())
                m_player_key_cache.erase(victim);
        }
    }
    m_player_key_cache[key] = entry;
}

void CSLSListener::sweep_player_key_cache()
{
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(m_cache_mutex);
    if (now - m_last_player_key_cache_sweep < PLAYER_KEY_CACHE_SWEEP_INTERVAL)
        return;
    m_last_player_key_cache_sweep = now;
    for (auto it = m_player_key_cache.begin(); it != m_player_key_cache.end();) {
        if (it->second.expiry_time <= now)
            it = m_player_key_cache.erase(it);
        else
            ++it;
    }
}

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

    // Cap the number of tracked source IPs so a distributed / spoofed-source
    // flood cannot grow the map without bound. A new IP that would exceed the
    // cap forces an immediate sweep; if the map is still full of live entries
    // the new IP is simply left untracked (not rate-limited) rather than
    // admitted, which keeps memory bounded without locking out the existing
    // tracked sources.
    if (m_rate_limit_map.find(ip_str) == m_rate_limit_map.end() &&
        m_rate_limit_map.size() >= MAX_RATE_LIMIT_ENTRIES) {
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
        if (m_rate_limit_map.size() >= MAX_RATE_LIMIT_ENTRIES) {
            return;
        }
    }

    m_rate_limit_map[ip_str].request_times.push_back(now);
}

void CSLSListener::cleanup_expired_rate_limits()
{
    auto now = std::chrono::steady_clock::now();
    // Time-gate the full-map scan: is_rate_limited calls this on every player
    // accept, but the per-IP deque trim there already keeps the checked IP
    // correct, so the map-wide GC only needs to run periodically.
    if (now - m_last_rate_limit_cleanup < RATE_LIMIT_CLEANUP_INTERVAL) {
        return;
    }
    m_last_rate_limit_cleanup = now;
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

    // Cache miss: validate asynchronously so the worker is never blocked on
    // the webhook. Reject this connection now and let the result populate the
    // cache; the client (e.g. OBS, which reconnects automatically while a
    // stream key is valid) hits the cache on its retry. This trades one
    // reconnect cycle of latency on a cold key for never parking a worker
    // thread on a slow or unreachable auth backend.
    start_player_key_validation(key_str, client_ip);
    return SLS_PENDING;
}

void CSLSListener::start_player_key_validation(const std::string& key, const char* client_ip)
{
    // One in-flight webhook per key is enough; concurrent reconnects for the
    // same key share the single outstanding validation.
    if (m_pending_player_key_validations.find(key) != m_pending_player_key_validations.end()) {
        return;
    }
    // Bound concurrent outstanding validations so a flood of distinct uncached
    // keys cannot grow the pending map or the webhook backlog without limit.
    if (m_pending_player_key_validations.size() >= MAX_PENDING_PLAYER_KEY_VALIDATIONS) {
        spdlog::warn("[{}] CSLSListener::start_player_key_validation, pending validation cap reached ({}), deferring key='{}'.",
                     fmt::ptr(this), m_pending_player_key_validations.size(), key);
        return;
    }

    // Count the webhook against the source IP's rate budget on dispatch.
    if (client_ip) {
        update_rate_limit(client_ip);
    }

    char auth_url[URL_MAX_LEN * 2] = {0};
    if (strlen(m_player_key_auth_url) > URL_MAX_LEN - 100) {
        spdlog::error("[{}] CSLSListener::start_player_key_validation, base auth URL too long.", fmt::ptr(this));
        return;
    }
    int ret = snprintf(auth_url, sizeof(auth_url), "%s?player_key=%s",
                       m_player_key_auth_url, url_encode(key).c_str());
    if (ret < 0 || (unsigned)ret >= sizeof(auth_url)) {
        spdlog::error("[{}] CSLSListener::start_player_key_validation, auth URL too long, ret={:d}.", fmt::ptr(this), ret);
        return;
    }

    int timeout_sec = (m_player_key_auth_timeout + 999) / 1000; // round up to seconds
    m_pending_player_key_validations[key] =
        AsyncHttpClient::instance().get_async(auth_url, timeout_sec);
    spdlog::debug("[{}] CSLSListener::start_player_key_validation, dispatched webhook for key='{}'.", fmt::ptr(this), key);
}

void CSLSListener::process_player_key_response(const std::string& key, const AsyncHttpResponse& response)
{
    auto now = std::chrono::steady_clock::now();

    auto cache_negative = [&]() {
        PlayerKeyCacheEntry e;
        e.resolved_stream_id = "";
        e.is_valid = false;
        e.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration / 4);
        e.has_max_players_override = false;
        e.max_players_per_stream_override = -1;
        std::lock_guard<std::mutex> lk(m_cache_mutex);
        insert_player_key_cache_locked(key, e);
    };

    if (!response.success) {
        spdlog::error("[{}] CSLSListener::process_player_key_response, HTTP request failed for key='{}': {}",
                     fmt::ptr(this), key, response.error);
        cache_negative();
        return;
    }

    if (response.status_code != 200) {
        spdlog::error("[{}] CSLSListener::process_player_key_response, API returned error code {} for key='{}', response: '{}'.",
                     fmt::ptr(this), response.status_code, key, response.body.c_str());
        cache_negative();
        return;
    }

    std::string stream_id;
    int json_max_players_override = -1;
    bool json_has_max_players_override = false;
    try {
        nlohmann::json json_response = nlohmann::json::parse(response.body);
        if (json_response.contains("stream_id") && json_response["stream_id"].is_string()) {
            stream_id = json_response["stream_id"];
        } else {
            spdlog::error("[{}] CSLSListener::process_player_key_response, JSON response missing 'stream_id' for key='{}'.", fmt::ptr(this), key);
            cache_negative();
            return;
        }
        if (json_response.contains("max_players_per_stream")) {
            if (json_response["max_players_per_stream"].is_number_integer()) {
                json_max_players_override = json_response["max_players_per_stream"].get<int>();
                // -1 is the documented "unlimited" sentinel; any value below
                // that is meaningless and likely a misconfigured backend.
                if (json_max_players_override < -1) {
                    spdlog::warn("[{}] CSLSListener::process_player_key_response, max_players_per_stream={} invalid (< -1) for key='{}'; ignoring override.",
                                 fmt::ptr(this), json_max_players_override, key);
                    json_has_max_players_override = false;
                } else {
                    json_has_max_players_override = true;
                }
            } else {
                spdlog::warn("[{}] CSLSListener::process_player_key_response, 'max_players_per_stream' present but not an integer for key='{}'; ignoring.", fmt::ptr(this), key);
            }
        }
    } catch (const nlohmann::json::exception& e) {
        spdlog::error("[{}] CSLSListener::process_player_key_response, failed to parse JSON for key='{}': {}.", fmt::ptr(this), key, e.what());
        cache_negative();
        return;
    }

    // Reject a resolved id that would not fit the handler's streamid buffer
    // rather than silently truncating it into a different stream key.
    if (stream_id.empty() || stream_id.length() >= URL_MAX_LEN) {
        spdlog::error("[{}] CSLSListener::process_player_key_response, invalid or empty stream_id '{}' for key='{}'.",
                     fmt::ptr(this), stream_id.c_str(), key);
        cache_negative();
        return;
    }

    PlayerKeyCacheEntry cache_entry;
    cache_entry.resolved_stream_id = stream_id;
    cache_entry.is_valid = true;
    cache_entry.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration);
    cache_entry.has_max_players_override = json_has_max_players_override;
    cache_entry.max_players_per_stream_override = json_max_players_override;
    {
        std::lock_guard<std::mutex> lk(m_cache_mutex);
        insert_player_key_cache_locked(key, cache_entry);
    }

    spdlog::debug("[{}] CSLSListener::process_player_key_response, cached result for key='{}', resolved to '{}', expires in {}ms.{}",
                 fmt::ptr(this), key, stream_id, m_player_key_cache_duration,
                 cache_entry.has_max_players_override ? " (with per-key max_players_per_stream override)" : "");
}

void CSLSListener::drain_player_key_validations()
{
    if (m_pending_player_key_validations.empty()) {
        return;
    }
    using namespace std::chrono_literals;
    for (auto it = m_pending_player_key_validations.begin(); it != m_pending_player_key_validations.end();) {
        if (it->second.wait_for(0ms) != std::future_status::ready) {
            ++it;
            continue;
        }
        AsyncHttpResponse response = it->second.get();
        process_player_key_response(it->first, response);
        it = m_pending_player_key_validations.erase(it);
    }
}