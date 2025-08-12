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

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <vector>
#include "spdlog/spdlog.h"

#include "SLSListener.hpp"
#include "SLSPublisher.hpp"
#include "SLSPlayer.hpp"
#include "HttpClient.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>
#include <chrono>

/**
 * server conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(server)

/**
 * CSLSListener class implementation
 */

CSLSListener::CSLSListener()
{
    m_conf = NULL;
    m_back_log = 1024;
    m_is_write = 0;
    m_port = 0;

    m_list_role = NULL;
    m_map_publisher = NULL;
    m_map_puller = NULL;
    m_map_pusher = NULL;
    m_is_publisher_listener = false;
    m_is_legacy_listener = false;
    m_idle_streams_timeout = UNLIMITED_TIMEOUT;
    m_idle_streams_timeout_role = 0;
    m_stat_info = {};
    memset(m_default_sid, 0, STR_MAX_LEN);
    memset(m_http_url_role, 0, URL_MAX_LEN);
    memset(m_player_key_auth_url, 0, URL_MAX_LEN);
    memset(m_record_hls_path_prefix, 0, URL_MAX_LEN);
    
    // Initialize player key validation configuration
    m_domain_players.clear();
    m_domain_publisher.clear();
    m_app_players.clear();
    m_player_key_cache.clear();
    m_rate_limit_map.clear();
    m_player_key_auth_timeout = 2000; // 2 seconds default
    m_player_key_cache_duration = 60000; // 1 minute default
    m_player_key_rate_limit_requests = -1; // No rate limit by default
    m_player_key_rate_limit_window = 60000; // 1 minute window default
    m_player_key_max_length = 64; // 64 characters max default
    m_player_key_min_length = 8; // 8 characters min default
    // Default regex: Most printable characters, 8-64 characters (allows query parameters, etc.)
    m_player_key_regex = std::regex("^[\\x20-\\x7E]{8,64}$");

    sprintf(m_role_name, "listener");
}

CSLSListener::~CSLSListener()
{
}

int CSLSListener::init()
{
    return CSLSRole::init();
}

int CSLSListener::uninit()
{
    CSLSLock lock(&m_mutex);
    stop();
    return CSLSRole::uninit();
}

void CSLSListener::set_role_list(CSLSRoleList *list_role)
{
    m_list_role = list_role;
}

void CSLSListener::set_map_publisher(CSLSMapPublisher *publisher)
{
    m_map_publisher = publisher;
}

void CSLSListener::set_map_puller(CSLSMapRelay *map_puller)
{
    m_map_puller = map_puller;
}

void CSLSListener::set_map_pusher(CSLSMapRelay *map_pusher)
{
    m_map_pusher = map_pusher;
}

void CSLSListener::set_record_hls_path_prefix(char *path)
{
    if (path != NULL && strlen(path) > 0)
    {
        strlcpy(m_record_hls_path_prefix, path, sizeof(m_record_hls_path_prefix));
    }
}


void CSLSListener::set_listener_type(bool is_publisher)
{
    m_is_publisher_listener = is_publisher;
    if (is_publisher) {
        sprintf(m_role_name, "listener-publisher");
    } else {
        sprintf(m_role_name, "listener-player");
    }
}

void CSLSListener::set_legacy_mode(bool is_legacy)
{
    m_is_legacy_listener = is_legacy;
    if (is_legacy) {
        if (m_is_publisher_listener) {
            sprintf(m_role_name, "listener-legacy");
        } else {
            sprintf(m_role_name, "listener-legacy-player");
        }
    }
}

bool CSLSListener::should_handle_app(const std::string& app_name, bool is_publisher_connection)
{
    if (!m_conf) {
        return true; // Default to allowing if no config
    }
    
    sls_conf_server_t *conf_server = (sls_conf_server_t *)m_conf;
    sls_conf_app_t *conf_app = (sls_conf_app_t *)conf_server->child;
    
    if (!conf_app) {
        return true; // Default to allowing if no app config
    }
    
    // Legacy listeners accept everything for backwards compatibility
    if (m_is_legacy_listener) {
        return true;
    }
    
    // Check if the app name matches any of the configured app names for this listener type
    int app_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_app);
    sls_conf_app_t *ca = conf_app;
    
    for (int i = 0; i < app_count; i++) {
        if (is_publisher_connection) {
            // For publisher connections, check against app_publisher
            if (app_name == std::string(ca->app_publisher)) {
                return m_is_publisher_listener; // Publisher listeners should handle publisher apps
            }
        } else {
            // For player connections, check against app_player
            if (app_name == std::string(ca->app_player)) {
                return !m_is_publisher_listener; // Player listeners should handle player apps
            }
        }
        ca = (sls_conf_app_t *)ca->sibling;
    }
    
    // Dedicated listeners are strict - no backwards compatibility
    return false;
}

bool CSLSListener::validate_player_key_format(const char* player_key)
{
    if (!player_key) {
        return false;
    }
    
    size_t key_len = strlen(player_key);
    
    // Check length constraints
    if (key_len < (size_t)m_player_key_min_length || key_len > (size_t)m_player_key_max_length) {
        spdlog::warn("[{}] CSLSListener::validate_player_key_format, key length {} outside range [{}, {}].", 
                     fmt::ptr(this), key_len, m_player_key_min_length, m_player_key_max_length);
        return false;
    }
    
    // Check format with regex
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
    // Check if rate limiting is disabled
    if (m_player_key_rate_limit_requests == -1) {
        return false; // Rate limiting disabled
    }
    
    if (!client_ip || strlen(client_ip) == 0) {
        return false; // No IP means no rate limiting
    }
    
    auto now = std::chrono::steady_clock::now();
    std::string ip_str(client_ip);
    
    // Clean up expired rate limit entries periodically
    cleanup_expired_rate_limits();
    
    auto rate_it = m_rate_limit_map.find(ip_str);
    if (rate_it == m_rate_limit_map.end()) {
        return false; // No previous requests from this IP
    }
    
    RateLimitEntry& entry = rate_it->second;
    
    // Remove expired requests from the deque
    auto window_start = now - std::chrono::milliseconds(m_player_key_rate_limit_window);
    while (!entry.request_times.empty() && entry.request_times.front() < window_start) {
        entry.request_times.pop_front();
    }
    
    // Check if we've exceeded the rate limit
    if ((int)entry.request_times.size() >= m_player_key_rate_limit_requests) {
        spdlog::warn("[{}] CSLSListener::is_rate_limited, IP '{}' exceeded rate limit: {} requests in {}ms window.", 
                     fmt::ptr(this), client_ip, entry.request_times.size(), m_player_key_rate_limit_window);
        return true;
    }
    
    return false;
}

void CSLSListener::update_rate_limit(const char* client_ip)
{
    // Skip tracking if rate limiting is disabled
    if (m_player_key_rate_limit_requests == -1) {
        return;
    }
    
    if (!client_ip || strlen(client_ip) == 0) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    std::string ip_str(client_ip);
    
    // Add current request time
    m_rate_limit_map[ip_str].request_times.push_back(now);
}

void CSLSListener::cleanup_expired_rate_limits()
{
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::milliseconds(m_player_key_rate_limit_window * 2); // Keep some buffer
    
    for (auto it = m_rate_limit_map.begin(); it != m_rate_limit_map.end();) {
        RateLimitEntry& entry = it->second;
        
        // Remove expired requests
        while (!entry.request_times.empty() && entry.request_times.front() < window_start) {
            entry.request_times.pop_front();
        }
        
        // Remove empty entries
        if (entry.request_times.empty()) {
            it = m_rate_limit_map.erase(it);
        } else {
            ++it;
        }
    }
}

int CSLSListener::validate_player_key(const char* player_key, char* resolved_stream_id, size_t resolved_stream_id_size, const char* client_ip)
{
    // Check if player key authentication is enabled
    if (strlen(m_player_key_auth_url) == 0)
    {
        spdlog::debug("[{}] CSLSListener::validate_player_key, player key authentication disabled.", fmt::ptr(this));
        return SLS_ERROR; // No auth URL configured, reject
    }

    // Validate player key format first (fast check)
    if (!validate_player_key_format(player_key))
    {
        spdlog::warn("[{}] CSLSListener::validate_player_key, invalid player key format for key='{}'.", fmt::ptr(this), player_key);
        return SLS_ERROR;
    }

    // Check rate limiting
    if (client_ip && is_rate_limited(client_ip))
    {
        spdlog::warn("[{}] CSLSListener::validate_player_key, rate limited request from IP='{}'.", fmt::ptr(this), client_ip);
        return SLS_ERROR;
    }

    std::string key_str(player_key);
    auto now = std::chrono::steady_clock::now();
    
    // Check cache first (including negative cache)
    auto cache_it = m_player_key_cache.find(key_str);
    if (cache_it != m_player_key_cache.end())
    {
        if (now < cache_it->second.expiry_time)
        {
            // Cache hit - return cached result
            if (cache_it->second.is_valid)
            {
                strlcpy(resolved_stream_id, cache_it->second.resolved_stream_id.c_str(), resolved_stream_id_size);
                spdlog::debug("[{}] CSLSListener::validate_player_key, cache hit (valid) for player_key='{}', resolved to: '{}'.", 
                             fmt::ptr(this), player_key, resolved_stream_id);
                return SLS_OK;
            }
            else
            {
                spdlog::debug("[{}] CSLSListener::validate_player_key, cache hit (invalid) for player_key='{}'.", 
                             fmt::ptr(this), player_key);
                return SLS_ERROR;
            }
        }
        else
        {
            // Cache expired - remove entry
            m_player_key_cache.erase(cache_it);
            spdlog::debug("[{}] CSLSListener::validate_player_key, cache expired for player_key='{}'.", fmt::ptr(this), player_key);
        }
    }

    // Update rate limiting counter
    if (client_ip)
    {
        update_rate_limit(client_ip);
    }

    // Create HTTP client for the API call
    CHttpClient *http_client = new CHttpClient;
    if (!http_client)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to create HTTP client.", fmt::ptr(this));
        return SLS_ERROR;
    }

    // Set timeout for the HTTP request (convert ms to seconds)
    http_client->set_timeout(m_player_key_auth_timeout / 1000);

    // Build the API URL with player key parameter
    char auth_url[URL_MAX_LEN * 2] = {0};
    // Ensure base URL leaves room for parameters
    if (strlen(m_player_key_auth_url) > URL_MAX_LEN - 100) {
        spdlog::error("[{}] CSLSListener::validate_player_key, base auth URL too long.", fmt::ptr(this));
        delete http_client;
        return SLS_ERROR;
    }
    int ret = snprintf(auth_url, sizeof(auth_url), "%s?player_key=%s",
                       m_player_key_auth_url, url_encode(player_key).c_str());
    if (ret < 0 || (unsigned)ret >= sizeof(auth_url))
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, auth URL too long, ret={:d}.", fmt::ptr(this), ret);
        delete http_client;
        return SLS_ERROR;
    }

    spdlog::info("[{}] CSLSListener::validate_player_key, validating player_key='{}' at URL='{}', timeout={}ms.", 
                 fmt::ptr(this), player_key, auth_url, m_player_key_auth_timeout);

    // Make the HTTP request
    ret = http_client->open(auth_url, "GET");
    if (ret != SLS_OK)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to open HTTP request, ret={:d}.", fmt::ptr(this), ret);
        delete http_client;
        return SLS_ERROR;
    }

    // Non-blocking request processing with timeout
    int64_t start_time = sls_gettime_ms();
    int64_t timeout_ms = m_player_key_auth_timeout;
    bool request_completed = false;
    
    while (!request_completed)
    {
        // Process HTTP data
        http_client->handler();
        
        // Check if request is complete
        if (SLS_OK == http_client->check_finished())
        {
            request_completed = true;
            break;
        }
        
        // Check timeout
        int64_t current_time = sls_gettime_ms();
        if (current_time - start_time >= timeout_ms)
        {
            spdlog::error("[{}] CSLSListener::validate_player_key, HTTP request timeout after {}ms for player_key='{}'.", 
                         fmt::ptr(this), timeout_ms, player_key);
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }
        
        // Check for timeout on HTTP client side
        if (SLS_OK == http_client->check_timeout(current_time))
        {
            spdlog::error("[{}] CSLSListener::validate_player_key, HTTP client timeout for player_key='{}'.", 
                         fmt::ptr(this), player_key);
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }
        
        // Small sleep to prevent busy waiting (1ms)
        usleep(1000);
    }

    // Get response info
    HTTP_RESPONSE_INFO *response = http_client->get_response_info();
    if (!response)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to get HTTP response.", fmt::ptr(this));
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    // Check response code
    if (response->m_response_code != HTTP_RESPONSE_CODE_200)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, API returned error code: {}, response: '{}'.", 
                     fmt::ptr(this), response->m_response_code.c_str(), response->m_response_content.c_str());
        
        // Cache negative result for failed validations (shorter duration)
        PlayerKeyCacheEntry negative_cache_entry;
        negative_cache_entry.resolved_stream_id = "";
        negative_cache_entry.is_valid = false;
        negative_cache_entry.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration / 4); // 1/4 of normal cache time
        negative_cache_entry.has_max_players_override = false;
        negative_cache_entry.max_players_per_stream_override = -1;
        m_player_key_cache[key_str] = negative_cache_entry;
        
        spdlog::debug("[{}] CSLSListener::validate_player_key, cached negative result for player_key='{}', expires in {}ms.", 
                     fmt::ptr(this), player_key, m_player_key_cache_duration / 4);
        
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    // Parse the JSON response to extract the stream ID
    // Expected response format: {"stream_id": "publish/live/streamname"}
    std::string response_content = response->m_response_content;
    spdlog::info("[{}] CSLSListener::validate_player_key, API response: '{}'.", fmt::ptr(this), response_content.c_str());

    std::string stream_id;
    int json_max_players_override = -1;
    bool json_has_max_players_override = false;
    try
    {
        nlohmann::json json_response = nlohmann::json::parse(response_content);
        
        if (json_response.contains("stream_id") && json_response["stream_id"].is_string())
        {
            stream_id = json_response["stream_id"];
        }
        else
        {
            spdlog::error("[{}] CSLSListener::validate_player_key, JSON response missing 'stream_id' field or field is not a string.", fmt::ptr(this));
            http_client->close();
            delete http_client;
            return SLS_ERROR;
        }

        // Optional per-key max players override
        if (json_response.contains("max_players_per_stream")) {
            if (json_response["max_players_per_stream"].is_number_integer()) {
                json_max_players_override = json_response["max_players_per_stream"].get<int>();
                json_has_max_players_override = true;
            } else {
                spdlog::warn("[{}] CSLSListener::validate_player_key, 'max_players_per_stream' present but not an integer; ignoring.", fmt::ptr(this));
            }
        }
    }
    catch (const nlohmann::json::exception& e)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, failed to parse JSON response: {}.", fmt::ptr(this), e.what());
        http_client->close();
        delete http_client;
        return SLS_ERROR;
    }

    // Clean up HTTP client
    http_client->close();
    delete http_client;

    // Validate the resolved stream ID
    if (stream_id.empty() || stream_id.length() >= resolved_stream_id_size)
    {
        spdlog::error("[{}] CSLSListener::validate_player_key, invalid or empty stream_id returned: '{}'.", 
                     fmt::ptr(this), stream_id.c_str());
        return SLS_ERROR;
    }

    // Cache the successful result
    PlayerKeyCacheEntry cache_entry;
    cache_entry.resolved_stream_id = stream_id;
    cache_entry.is_valid = true;
    cache_entry.expiry_time = now + std::chrono::milliseconds(m_player_key_cache_duration);
    cache_entry.has_max_players_override = json_has_max_players_override;
    cache_entry.max_players_per_stream_override = json_max_players_override;
    m_player_key_cache[key_str] = cache_entry;
    
    spdlog::debug("[{}] CSLSListener::validate_player_key, cached result for player_key='{}', expires in {}ms.{}", 
                 fmt::ptr(this), player_key, m_player_key_cache_duration,
                 cache_entry.has_max_players_override ? " (with per-key max_players_per_stream override)" : "");

    // Copy the resolved stream ID to output buffer
    strlcpy(resolved_stream_id, stream_id.c_str(), resolved_stream_id_size);
    spdlog::info("[{}] CSLSListener::validate_player_key, player_key='{}' validated successfully, resolved to stream_id='{}'.", 
                 fmt::ptr(this), player_key, resolved_stream_id);

    return SLS_OK;
}

int CSLSListener::init_conf_app()
{
    string strLive;
    string strUplive;
    string strLiveDomain;
    string strUpliveDomain;
    string strTemp;
    vector<string> domain_players;
    sls_conf_server_t *conf_server;

    if (NULL == m_map_puller)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app failed, m_map_puller is null.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (NULL == m_map_pusher)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app failed, m_map_pusher is null.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!m_conf)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app failed, conf is null.", fmt::ptr(this));
        return SLS_ERROR;
    }
    conf_server = (sls_conf_server_t *)m_conf;

    m_back_log = conf_server->backlog;
    m_idle_streams_timeout_role = conf_server->idle_streams_timeout;
    strlcpy(m_http_url_role, conf_server->on_event_url, sizeof(m_http_url_role));
    strlcpy(m_player_key_auth_url, conf_server->player_key_auth_url, sizeof(m_player_key_auth_url));
    m_player_key_auth_timeout = conf_server->player_key_auth_timeout;
    m_player_key_cache_duration = conf_server->player_key_cache_duration;
    m_player_key_rate_limit_requests = conf_server->player_key_rate_limit_requests;
    m_player_key_rate_limit_window = conf_server->player_key_rate_limit_window;
    m_player_key_max_length = conf_server->player_key_max_length;
    m_player_key_min_length = conf_server->player_key_min_length;
    
    // Build regex pattern based on configured min/max length
    char regex_pattern[256];
    snprintf(regex_pattern, sizeof(regex_pattern), "^[\\x20-\\x7E]{%d,%d}$", 
             m_player_key_min_length, m_player_key_max_length);
    try {
        m_player_key_regex = std::regex(regex_pattern);
    } catch (const std::regex_error& e) {
        spdlog::warn("[{}] CSLSListener::init_conf_app, invalid regex pattern '{}', using default.", fmt::ptr(this), regex_pattern);
        m_player_key_regex = std::regex("^[\\x20-\\x7E]{8,64}$");
    }
    
    strlcpy(m_default_sid, conf_server->default_sid, sizeof(m_default_sid));
    spdlog::info("[{}] CSLSListener::init_conf_app, m_back_log={:d}, m_idle_streams_timeout={:d}.",
                 fmt::ptr(this), m_back_log, m_idle_streams_timeout_role);

    // domain
    domain_players = sls_conf_string_split(conf_server->domain_player, " ");
    if (domain_players.size() == 0)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app, wrong domain_player='{}'.", fmt::ptr(this), conf_server->domain_player);
        return SLS_ERROR;
    }
    strUpliveDomain = conf_server->domain_publisher;
    if (strUpliveDomain.length() == 0)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app, wrong domain_publisher='{}'.", fmt::ptr(this), conf_server->domain_publisher);
        return SLS_ERROR;
    }
    
    // Store configuration in member variables for player key validation
    m_domain_players = domain_players;
    m_domain_publisher = strUpliveDomain;

    sls_conf_app_t *conf_app = (sls_conf_app_t *)conf_server->child;
    if (!conf_app)
    {
        spdlog::error("[{}] CSLSListener::init_conf_app, no app conf info.", fmt::ptr(this));
        return SLS_ERROR;
    }

    int app_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_app);
    sls_conf_app_t *ca = conf_app;
    for (int i = 0; i < app_count; i++)
    {
        strUplive = ca->app_publisher;
        if (strUplive.length() == 0)
        {
            spdlog::error("[{}] CSLSListener::init_conf_app, wrong app_publisher='{}', domain_publisher='{}'.",
                          fmt::ptr(this), strUplive, strUpliveDomain);
            return SLS_ERROR;
        }
        strUplive = strUpliveDomain + "/" + strUplive;
        // If we cannot add publisher to the map, we have a duplicate publisher
        // This can happen when multiple listeners share the same publisher map
        if (m_map_publisher->set_conf(strUplive, (sls_conf_base_t *)ca) != SLS_OK)
        {
            // Check if this is a duplicate due to multiple listeners sharing the same map
            // If the configuration already exists, we can safely skip this initialization
            if (m_map_publisher->get_ca(strUplive) != NULL)
            {
                spdlog::info("[{}] CSLSListener::init_conf_app, app_publisher='{}' already initialized, skipping.",
                             fmt::ptr(this), strUplive);
            }
            else
            {
                spdlog::error("[{}] SLSListener::init_conf_app, duplicate app_publisher='{}'",
                              fmt::ptr(this), strUplive);
                return SLS_ERROR;
            }
        }
        else
        {
            spdlog::info("[{}] CSLSListener::init_conf_app, add app push '{}'.",
                         fmt::ptr(this), strUplive);
        }

        strLive = ca->app_player;
        if (strLive.length() == 0)
        {
            spdlog::error("[{}] CSLSListener::init_conf_app, wrong app_player='{}', domain_publisher='{}'.",
                          fmt::ptr(this), strLive, strUpliveDomain);
            return SLS_ERROR;
        }
        
        // Store app_player configuration for player key validation
        m_app_players.push_back(strLive);

        // Setup mapping between player endpoints and publishing endpoints
        // Each player endpoint has a corresponding (not necessarily unique)
        // publishing endpoint.
        for (unsigned int j = 0; j < domain_players.size(); j++)
        {
            strLiveDomain = domain_players[j];
            strTemp = strLiveDomain + "/" + strLive;
            if (strUplive == strTemp)
            {
                spdlog::error("[{}] CSLSListener::init_conf_app failed, domain/uplive='{}' and domain/live='{}' must not be equal.",
                              fmt::ptr(this), strUplive.c_str(), strTemp.c_str());
                return SLS_ERROR;
            }
            // m_map_live_2_uplive[strTemp]  = strUplive;
            //  If we cannot add player to the map, we have a duplicate player
            // This can happen when multiple listeners share the same publisher map
            if (m_map_publisher->set_live_2_uplive(strTemp, strUplive) != SLS_OK)
            {
                // Check if this is a duplicate due to multiple listeners sharing the same map
                // If the mapping already exists, we can safely skip this initialization
                std::string existing_uplive = m_map_publisher->get_uplive(strTemp);
                if (!existing_uplive.empty() && existing_uplive == strUplive)
                {
                    spdlog::info("[{}] CSLSListener::init_conf_app, app_player='{}' already mapped to '{}', skipping.",
                                 fmt::ptr(this), strTemp, strUplive);
                }
                else
                {
                    spdlog::error("[{}] CSLSListener::init_conf_app, duplicate app_player='{}'",
                                  fmt::ptr(this), strTemp);
                    return SLS_ERROR;
                }
            }
            else
            {
                spdlog::info("[{}] CSLSListener::init_conf_app, add app live='{}', app push='{}'.",
                             fmt::ptr(this), strTemp.c_str(), strUplive.c_str());
            }
        }

        if (NULL != ca->child)
        {
            sls_conf_relay_t *cr = (sls_conf_relay_t *)ca->child;
            while (cr)
            {
                if (strcmp(cr->type, "pull") == 0)
                {
                    if (SLS_OK != m_map_puller->add_relay_conf(strUplive.c_str(), cr))
                    {
                        spdlog::warn("[{}] CSLSListener::init_conf_app, m_map_puller.add_app_conf faile. relay type='{}', app push='{}'.",
                                     fmt::ptr(this), cr->type, strUplive.c_str());
                    }
                }
                else if (strcmp(cr->type, "push") == 0)
                {
                    if (SLS_OK != m_map_pusher->add_relay_conf(strUplive.c_str(), cr))
                    {
                        spdlog::warn("[{}] CSLSListener::init_conf_app, m_map_pusher.add_app_conf faile. relay type='{}', app push='{}'.",
                                     fmt::ptr(this), cr->type, strUplive.c_str());
                    }
                }
                else
                {
                    spdlog::error("[{}] CSLSListener::init_conf_app, wrong relay type='{}', app push='{}'.",
                                  fmt::ptr(this), cr->type, strUplive.c_str());
                    return SLS_ERROR;
                }
                cr = (sls_conf_relay_t *)cr->sibling;
            }
        }

        ca = (sls_conf_app_t *)ca->sibling;
    }
    return SLS_OK;
}

int CSLSListener::start()
{
    int ret = 0;
    std::string strLive;
    std::string strUplive;
    std::string strLiveDomain;
    std::string strUpliveDomain;

    if (NULL == m_conf)
    {
        spdlog::error("[{}] CSLSListener::start failed, conf is null.", fmt::ptr(this));
        return SLS_ERROR;
    }
    spdlog::info("[{}] CSLSListener::start", fmt::ptr(this));

    ret = init_conf_app();
    if (SLS_OK != ret)
    {
        spdlog::error("[{}] CSLSListener::start, init_conf_app failed.", fmt::ptr(this));
        return SLS_ERROR;
    }

    // init listener
    if (NULL == m_srt)
        m_srt = new CSLSSrt();

    // Dynamic latency handling: only publisher listeners enforce minimum latency
    sls_conf_server_t* server_conf = (sls_conf_server_t*)m_conf;
    if (m_is_publisher_listener && !m_is_legacy_listener) {
        // Set minimum latency on publisher listener socket if configured
        // This enforces the minimum but clients can choose higher
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            spdlog::info("[{}] CSLSListener::start, set minimum latency={} ms on publisher listener socket.", 
                        fmt::ptr(this), server_conf->latency_min);
        } else {
            spdlog::info("[{}] CSLSListener::start, not setting latency on publisher listener socket to allow full client control.", fmt::ptr(this));
        }
    } else if (m_is_legacy_listener) {
        // Legacy listeners use old behavior for backwards compatibility
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            spdlog::info("[{}] CSLSListener::start, set latency={} ms on legacy listener socket for backwards compatibility.", 
                        fmt::ptr(this), server_conf->latency_min);
        }
    } else {
        // Player listeners don't set latency - it's determined by network conditions
        spdlog::info("[{}] CSLSListener::start, player listener - latency determined by network, not configured.", fmt::ptr(this));
    }

    // Use different ports for legacy, publisher and player listeners
    if (m_is_legacy_listener) {
        m_port = server_conf->listen;
    } else if (m_is_publisher_listener) {
        m_port = server_conf->listen_publisher;
        // Fallback to legacy listen port if publisher port not configured
        if (m_port <= 0) {
            m_port = server_conf->listen;
        }
    } else {
        m_port = server_conf->listen_player;
        // Fallback to legacy listen port if player port not configured (for backwards compatibility)
        if (m_port <= 0) {
            m_port = server_conf->listen;
        }
    }
    
    if (m_port <= 0) {
        spdlog::error("[{}] CSLSListener::start, invalid port %d for %s listener.", 
                fmt::ptr(this), m_port, m_is_publisher_listener ? "publisher" : "player");
        return SLS_ERROR;
    }

    ret = m_srt->libsrt_setup(m_port);
    if (SLS_OK != ret)
    {
        spdlog::error("[{}] CSLSListener::start, libsrt_setup failure.", fmt::ptr(this));
        return ret;
    }

    spdlog::info("[{}] CSLSListener::start, libsrt_setup ok on port %d for %s.", 
        fmt::ptr(this), m_port, m_is_publisher_listener ? "publisher" : "player");

    ret = m_srt->libsrt_listen(m_back_log);
    if (SLS_OK != ret)
    {
        spdlog::info("[{}] CSLSListener::start, libsrt_listen failure.", fmt::ptr(this));
        return ret;
    }

    spdlog::info("[{}] CSLSListener::start, m_list_role={}.", fmt::ptr(this), fmt::ptr(m_list_role));
    if (NULL == m_list_role)
    {
        spdlog::info("[{}] CSLSListener::start, m_roleList is null.", fmt::ptr(this));
        return ret;
    }

    spdlog::info("[{}] CSLSListener::start, push to m_list_role={}.", fmt::ptr(this), fmt::ptr(m_list_role));
    m_list_role->push(this);

    return ret;
}

int CSLSListener::stop()
{
    int ret = SLS_OK;
    spdlog::info("[{}] CSLSListener::stop.", fmt::ptr(this));

    return ret;
}

int CSLSListener::handler()
{
    int ret = SLS_OK;
    int fd_client = 0;
    CSLSSrt *srt = NULL;
    char sid[1024] = {0};
    std::map<std::string, std::string> sid_kv;
    int sid_size = sizeof(sid);
    char host_name[URL_MAX_LEN] = {0};
    char app_name[URL_MAX_LEN] = {0};
    char stream_name[URL_MAX_LEN] = {0};
    char key_app[URL_MAX_LEN] = {0};
    char key_stream_name[URL_MAX_LEN] = {0};
    char tmp[URL_MAX_LEN] = {0};
    char peer_name[IP_MAX_LEN] = {0};
    int peer_port = 0;
    unsigned long peer_addr_raw = 0;
    struct in6_addr peer_addr6_raw;
    int client_count = 0;

    // 1: accept
    fd_client = m_srt->libsrt_accept();
    if (fd_client < 0)
    {
        spdlog::error("[{}] CSLSListener::handler, srt_accept failed, fd={:d}.", fmt::ptr(this), get_fd());
        CSLSSrt::libsrt_neterrno();
        return client_count;
    }
    client_count = 1;

    // 2.check streamid, split it
    srt = new CSLSSrt;
    srt->libsrt_set_fd(fd_client);
    ret = srt->libsrt_getpeeraddr(peer_name, peer_port);
    if (ret != 0)
    {
        spdlog::error("[{}] CSLSListener::handler, libsrt_getpeeraddr failed, fd={:d}.", fmt::ptr(this), srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    spdlog::info("[{}] CSLSListener::handler, new client[{}:{:d}], fd={:d}, listener_type={}, legacy={}, port={}.", 
                 fmt::ptr(this), peer_name, peer_port, fd_client, 
                 m_is_publisher_listener ? "publisher" : "player", 
                 m_is_legacy_listener ? "true" : "false", m_port);

    // Read the negotiated latency after accept
    sls_conf_server_t* conf_server = (sls_conf_server_t*)m_conf;
    int negotiated_latency = 0;
    int latency_len = sizeof(negotiated_latency);
    int final_latency = 0;
    
    // Try to read the negotiated latency
    if (0 != srt->libsrt_getsockopt(SRTO_LATENCY, "SRTO_LATENCY", &negotiated_latency, &latency_len)) {
        // If we can't read the latency, use configured minimum or SRT default
        negotiated_latency = conf_server->latency_min > 0 ? conf_server->latency_min : 120;
        spdlog::warn("[{}] CSLSListener::handler, [{}:{:d}], failed to read latency, using fallback {} ms.", 
                fmt::ptr(this), peer_name, peer_port, negotiated_latency);
    } else {
        // Successfully read latency
        const char* role = m_is_publisher_listener ? "publisher" : "player";
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], {} latency={} ms.", 
                fmt::ptr(this), peer_name, peer_port, role, negotiated_latency);
        
        // Enforce maximum latency for both publishers and players
        if (conf_server->latency_max > 0 && negotiated_latency > conf_server->latency_max) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], rejecting {}: latency {} ms exceeds maximum {} ms.", 
                    fmt::ptr(this), peer_name, peer_port, role, negotiated_latency, conf_server->latency_max);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
    }
    
    final_latency = negotiated_latency;

    if (0 != srt->libsrt_getsockopt(SRTO_STREAMID, "SRTO_STREAMID", &sid, &sid_size))
    {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, get streamid info failed.",
                      fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    
    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], received stream_id: '{}'", 
                 fmt::ptr(this), peer_name, peer_port, sid);

    // If the stream ID is empty, close the connection
    if (strlen(sid) == 0) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, empty stream ID not allowed.", fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    sid_kv = srt->libsrt_parse_sid(sid);
    bool sidValid = true;
    // Host (defined in spec)
    if (sid_kv.count("h")) {
        strlcpy(host_name, sid_kv.at("h").c_str(), sizeof(host_name));
    } else {
        sidValid = false;
    }
    // Application Name (venor supplied)
    if (sid_kv.count("sls_app")) {
        strlcpy(app_name, sid_kv.at("sls_app").c_str(), sizeof(app_name));
    } else {
        sidValid = false;
    }
    // Resource (defined in spec)
    if (sid_kv.count("r")) {
        strlcpy(stream_name, sid_kv.at("r").c_str(), sizeof(stream_name));
    } else {
        sidValid = false;
    }
    if (!sidValid)
    {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], parse sid='{}' failed.", fmt::ptr(this), peer_name, peer_port, sid);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], sid '{}/{}/{}'",
                 fmt::ptr(this), peer_name, peer_port, host_name, app_name, stream_name);

    // app exist?
    snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);

    std::string app_uplive = "";
    sls_conf_app_t *ca = NULL;

    char cur_time[STR_DATE_TIME_LEN] = {0};
    sls_gettime_default_string(cur_time, sizeof(cur_time));

    // Check if this connection type matches this listener type (with backwards compatibility)
    app_uplive = m_map_publisher->get_uplive(key_app);
    bool is_player_connection = (app_uplive.length() > 0);
    bool connection_allowed = true;
    
    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], connection analysis: key_app='{}', app_uplive='{}', is_player_connection={}, listener_type={}, legacy={}", 
                 fmt::ptr(this), peer_name, peer_port, key_app, app_uplive, is_player_connection ? "true" : "false", 
                 m_is_publisher_listener ? "publisher" : "player", m_is_legacy_listener ? "true" : "false");
    
    // Enhanced logic: strict mode for dedicated listeners, backwards compatibility only for legacy listeners
    if (m_is_legacy_listener) {
        // Legacy listener: accepts both publishers and players (backwards compatible)
        spdlog::debug("[{}] CSLSListener::handler, {} connection with app '{}' accepted on legacy listener (port {}) - backwards compatible.",
                      fmt::ptr(this), is_player_connection ? "player" : "publisher", app_name, m_port);
    } else {
        // Dedicated listeners: strict type checking
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], validation check: is_publisher_listener={}, is_player_connection={}", 
                     fmt::ptr(this), peer_name, peer_port, m_is_publisher_listener ? "true" : "false", is_player_connection ? "true" : "false");
        
        if (!m_is_publisher_listener && !is_player_connection) {
            // Player listener receiving publisher connection - STRICT REJECTION
            spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], publisher connection with app '{}' attempted on dedicated player listener (port {}).",
                         fmt::ptr(this), peer_name, peer_port, app_name, m_port);
            connection_allowed = false;
        } else if (m_is_publisher_listener && is_player_connection) {
            // Publisher listener receiving player connection - STRICT REJECTION
            spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], player connection with app '{}' attempted on dedicated publisher listener (port {}).",
                         fmt::ptr(this), peer_name, peer_port, app_name, m_port);
            connection_allowed = false;
        } else {
            // Connection matches expected type for dedicated listener
            spdlog::info("[{}] CSLSListener::handler, {} connection with app '{}' matches dedicated {} listener (port {}), proceeding normally.",
                          fmt::ptr(this), is_player_connection ? "player" : "publisher", app_name, 
                          m_is_publisher_listener ? "publisher" : "player", m_port);
        }
    }
    
    if (!connection_allowed) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], connection REJECTED by validation logic", fmt::ptr(this), peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    } else {
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], connection ACCEPTED by validation logic, proceeding to create role", fmt::ptr(this), peer_name, peer_port);
    }

    // Player key validation for player connections using traditional stream ID format
    char validated_stream_id[URL_MAX_LEN] = {0};
    char player_key[URL_MAX_LEN] = {0};
    bool player_key_validation_required = false;
    
    // Parse traditional stream ID format: domain/app/stream_name
    // For player key auth, the stream_name part is the player key
    char domain[URL_MAX_LEN] = {0};
    char app[URL_MAX_LEN] = {0};
    char stream_part[URL_MAX_LEN] = {0};
    
    // Split the stream ID by '/' delimiter
    char* sid_copy = strdup(sid);
    char* token = strtok(sid_copy, "/");
    int part_count = 0;
    
    if (token) {
        strlcpy(domain, token, sizeof(domain));
        part_count++;
        token = strtok(NULL, "/");
        if (token) {
            strlcpy(app, token, sizeof(app));
            part_count++;
            token = strtok(NULL, "/");
            if (token) {
                strlcpy(stream_part, token, sizeof(stream_part));
                part_count++;
            }
        }
    }
    free(sid_copy);
    
    // Check if we have the traditional 3-part format and if this is a configured player connection
    bool is_player_domain = false;
    bool is_player_app = false;
    
    // Check if domain matches any configured player domain
    for (const auto& player_domain : m_domain_players) {
        if (strcmp(domain, player_domain.c_str()) == 0) {
            is_player_domain = true;
            break;
        }
    }
    
    // Check if app matches any configured player app
    for (const auto& player_app : m_app_players) {
        if (strcmp(app, player_app.c_str()) == 0) {
            is_player_app = true;
            break;
        }
    }
    
    if (part_count == 3 && is_player_domain && is_player_app && strlen(m_player_key_auth_url) > 0) {
        // Use stream_part as player key
        strlcpy(player_key, stream_part, sizeof(player_key));
        player_key_validation_required = true;
        
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], detected player connection with configured format '{}/{}', player_key='{}', validating...", 
                     fmt::ptr(this), peer_name, peer_port, domain, app, player_key);
        
        // Validate the player key and get the resolved stream ID
        int validation_result = validate_player_key(player_key, validated_stream_id, sizeof(validated_stream_id), peer_name);
        if (validation_result != SLS_OK) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], player key validation FAILED for key='{}'", 
                         fmt::ptr(this), peer_name, peer_port, player_key);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], player key validation SUCCESS, resolved to stream_id='{}'", 
                     fmt::ptr(this), peer_name, peer_port, validated_stream_id);
        
        // Replace the original stream ID with the validated one
        strlcpy(sid, validated_stream_id, sizeof(sid));
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], updated stream_id to: '{}'",
                     fmt::ptr(this), peer_name, peer_port, sid);
        
        // If the validated player key had a per-key override, update the per-stream cap
        {
            auto it_cache = m_player_key_cache.find(std::string(player_key));
            if (it_cache != m_player_key_cache.end()) {
                const PlayerKeyCacheEntry &entry = it_cache->second;
                auto now_ts = std::chrono::steady_clock::now();
                if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                    // We do not yet know final key_stream_name until app_uplive is known below; store by resolved stream id temporarily
                    // We'll update after we compute key_stream_name as well
                    // Here, we can't compute key_stream_name reliably; defer mapping until after app_uplive concatenation
                }
            }
        }
                       
        // Re-parse the validated stream ID to get the correct host, app, and stream name
        // This ensures player limits are applied to the actual resolved stream, not the player key
        sid_kv = srt->libsrt_parse_sid(sid);
        bool validated_sid_valid = true;
        
        // Re-extract values from the validated stream ID
        if (sid_kv.count("h")) {
            strlcpy(host_name, sid_kv.at("h").c_str(), sizeof(host_name));
        } else {
            validated_sid_valid = false;
        }
        if (sid_kv.count("sls_app")) {
            strlcpy(app_name, sid_kv.at("sls_app").c_str(), sizeof(app_name));
        } else {
            validated_sid_valid = false;
        }
        if (sid_kv.count("r")) {
            strlcpy(stream_name, sid_kv.at("r").c_str(), sizeof(stream_name));
        } else {
            validated_sid_valid = false;
        }
        
        if (!validated_sid_valid) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], validated stream_id '{}' has invalid format", 
                         fmt::ptr(this), peer_name, peer_port, sid);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        
        // Update key_app with the validated values
        snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);
        
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], re-parsed validated stream: '{}/{}/{}'",
                     fmt::ptr(this), peer_name, peer_port, host_name, app_name, stream_name);
    }
    
    // Continue with normal SID parsing using the (possibly updated) stream ID

    // 3.is player?
    if (app_uplive.length() > 0)
    {
        snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name);
        // Ensure per-stream override map is updated if the validated key carried an override
        if (player_key_validation_required) {
            auto now_ts = std::chrono::steady_clock::now();
            auto it_cache = m_player_key_cache.find(std::string(player_key));
            if (it_cache != m_player_key_cache.end()) {
                const PlayerKeyCacheEntry &entry = it_cache->second;
                if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                    StreamPlayerLimitEntry stream_entry;
                    stream_entry.has_override = true;
                    stream_entry.max_players_per_stream = entry.max_players_per_stream_override;
                    // Align expiry with player key cache entry to avoid stale overrides
                    stream_entry.expiry_time = entry.expiry_time;
                    m_stream_player_limit_map[std::string(key_stream_name)] = stream_entry;
                    spdlog::info("[{}] CSLSListener::handler, applied per-stream cap override for stream='{}' to {} (from key).",
                                 fmt::ptr(this), key_stream_name, stream_entry.max_players_per_stream);
                }
            }
        }
        CSLSRole *pub = m_map_publisher->get_publisher(key_stream_name);
        if (NULL == pub)
        {
            //*
            // 3.1 check pullers
            if (NULL == m_map_puller)
            {
                spdlog::info("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream='{}', publisher is NULL and m_map_puller is NULL.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            CSLSRelayManager *puller_manager = m_map_puller->add_relay_manager(app_uplive.c_str(), stream_name);
            if (NULL == puller_manager)
            {
                spdlog::info("[{}] CSLSListener::handler, m_map_puller->add_relay_manager failed, new role[{}:{:d}], stream='{}', publisher is NULL, no puller_manager.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }

            puller_manager->set_map_data(m_map_data);
            puller_manager->set_map_publisher(m_map_publisher);
            puller_manager->set_role_list(m_list_role);
            puller_manager->set_listen_port(m_port);

            if (SLS_OK != puller_manager->start())
            {
                spdlog::info("[{}] CSLSListener::handler, puller_manager->start failed, new client[{}:{:d}], stream='{}'.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            spdlog::info("[{}] CSLSListener::handler, puller_manager->start ok, new client[{}:{:d}], stream={}.",
                         fmt::ptr(this), peer_name, peer_port, key_stream_name);

            pub = m_map_publisher->get_publisher(key_stream_name);
            if (NULL == pub)
            {
                spdlog::info("[{}] CSLSListener::handler, m_map_publisher->get_publisher failed, new client[{}:{:d}], stream={}.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            else
            {
                spdlog::info("[{}] CSLSListener::handler, m_map_publisher->get_publisher ok, pub={}, new client[{}:{:d}], stream={}.",
                             fmt::ptr(this), fmt::ptr(pub), peer_name, peer_port, key_stream_name);
            }
        }

        // Check if IP is allowed to stream from the app
        ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
        if (ca == nullptr)
        {
            spdlog::error("[{}] CSLSListener::handler, refused, configuration does not exist [stream={}]",
                          fmt::ptr(this), key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        else
        {
            // Get IP address of remote peer
            if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK)
            {
                // If/when we match an address, set this flag to break out of the for loop
                bool address_matched = false;
                for (sls_ip_access_t &acl_entry : ca->ip_actions.play)
                {
                    if (acl_entry.ip_address == peer_addr_raw || acl_entry.ip_address == 0)
                    {
                        switch (acl_entry.action)
                        {
                        case sls_access_action::ACCEPT:
                            address_matched = true;
                            spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}'",
                                         fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                            break;
                        case sls_access_action::DENY:
                            spdlog::warn("[{}] CSLSListener::handler Rejected connection from {}:{:d} for app '{}'",
                                         fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                            srt->libsrt_close();
                            delete srt;
                            return client_count;
                        default:
                            spdlog::error("[{}] CSLSListener::handler Unknown action [sls_access_action={:d}], ignoring",
                                          fmt::ptr(this), (int)acl_entry.action);
                        }
                    }

                    if (address_matched)
                        break;
                }
                // If we don't have any entries regarding the peer, accept by default
                if (!address_matched)
                {
                    spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                                 fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                }
            }
            else
            {
                spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
                spdlog::error("[{}] CSLSListener::handler Accepting connection by default", fmt::ptr(this));
            }
        }

        // 3.2 handle new play
        if (!m_map_data->is_exist(key_stream_name))
        {
            spdlog::error("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream={}, but publisher data doesn't exist in m_map_data.",
                          fmt::ptr(this), peer_name, peer_port, key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        // Check player limit per stream
        {
            int effective_max_players = ca->max_players_per_stream;
            bool using_override = false;
            auto now_ts = std::chrono::steady_clock::now();

            // First, enforce per-stream override if present and valid
            auto it_stream_cap = m_stream_player_limit_map.find(std::string(key_stream_name));
            if (it_stream_cap != m_stream_player_limit_map.end()) {
                const StreamPlayerLimitEntry &sentry = it_stream_cap->second;
                if (sentry.has_override && now_ts < sentry.expiry_time) {
                    effective_max_players = sentry.max_players_per_stream;
                    using_override = true;
                } else if (now_ts >= sentry.expiry_time) {
                    // Expired entry: remove it
                    m_stream_player_limit_map.erase(it_stream_cap);
                }
            }

            // Backward fallback: if no per-stream cap was set, allow per-key override during this connection
            if (!using_override && player_key_validation_required) {
                auto it_cache = m_player_key_cache.find(std::string(player_key));
                if (it_cache != m_player_key_cache.end()) {
                    const PlayerKeyCacheEntry& entry = it_cache->second;
                    if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                        effective_max_players = entry.max_players_per_stream_override;
                        using_override = true;
                    }
                }
            }
 
            if (effective_max_players > 0) {
                int current_player_count = m_list_role->count_players_for_stream(key_stream_name);
                if (current_player_count >= effective_max_players)
                {
                    spdlog::warn("[{}] CSLSListener::handler, refused, new player[{}:{:d}], stream={}, player limit reached ({:d}/{:d}){}.",
                                 fmt::ptr(this), peer_name, peer_port, key_stream_name, current_player_count, effective_max_players,
                                 using_override ? " [override]" : "");
                    srt->libsrt_close();
                    delete srt;
                    return client_count;
                }
                spdlog::debug("[{}] CSLSListener::handler, new player[{}:{:d}], stream={}, player count ({:d}/{:d}){}.",
                              fmt::ptr(this), peer_name, peer_port, key_stream_name, current_player_count, effective_max_players,
                              using_override ? " [override]" : "");
            }
        }
        
        // new player
        if (srt->libsrt_socket_nonblock(0) < 0)
            spdlog::warn("[{}] CSLSListener::handler, new player[{}:{:d}], libsrt_socket_nonblock failed.",
                         fmt::ptr(this), peer_name, peer_port);

        CSLSPlayer *player = new CSLSPlayer;
        player->init();
        player->set_idle_streams_timeout(m_idle_streams_timeout_role);
        player->set_srt(srt);
        player->set_map_data(key_stream_name, m_map_data);
        player->set_latency(final_latency);

        // stat info
        stat_info_t *stat_info_obj = new stat_info_t();
        stat_info_obj->port = m_port;
        stat_info_obj->role = player->get_role_name();
        stat_info_obj->pub_domain_app = app_uplive;
        stat_info_obj->stream_name = stream_name;
        stat_info_obj->url = sid;
        stat_info_obj->remote_ip = peer_name;
        stat_info_obj->remote_port = peer_port;
        stat_info_obj->start_time = cur_time;
        player->set_stat_info_base(*stat_info_obj);

        player->set_http_url(m_http_url_role);
        player->on_connect();

        m_list_role->push(player);
        spdlog::info("[{}] CSLSListener::handler, new player[{}] =[{}:{:d}], key_stream_name={}, {}={}, m_list_role->size={:d}.",
                     fmt::ptr(this), fmt::ptr(player), peer_name, peer_port, key_stream_name, player->get_role_name(), fmt::ptr(player), m_list_role->size());
        return client_count;
    }

    // 4. is publisher?
    app_uplive = key_app;
    snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name);
    ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
    if (NULL == ca)
    {
        spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], non-existent publishing domain [stream='{}']",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    // Check if IP is allowed to publish to the app
    if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK)
    {
        // If/when we match an address, set this flag to break out of the for loop
        bool address_matched = false;
        for (sls_ip_access_t &acl_entry : ca->ip_actions.publish)
        {
            if (acl_entry.ip_address == peer_addr_raw || acl_entry.ip_address == 0)
            {
                switch (acl_entry.action)
                {
                case sls_access_action::ACCEPT:
                    address_matched = true;
                    spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}'",
                                 fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                    break;
                case sls_access_action::DENY:
                    spdlog::warn("[{}] CSLSListener::handler Rejected connection from {}:{:d} for app '{}'",
                                 fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                    srt->libsrt_close();
                    delete srt;
                    return client_count;
                default:
                    spdlog::error("[{}] CSLSListener::handler Unknown action [sls_access_action={:d}], ignoring",
                                  fmt::ptr(this), (int)acl_entry.action);
                }
            }

            if (address_matched)
                break;
        }
        // If we don't have any entries regarding the peer, accept by default
        if (!address_matched)
        {
            spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                         fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
        }
    }
    else
    {
        spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
        spdlog::error("[{}] CSLSListener::handler Accepting connection by default", fmt::ptr(this));
    }

    // Check if publisher for the stream already exists
    CSLSRole *publisher = m_map_publisher->get_publisher(key_stream_name);
    if (NULL != publisher)
    {
        spdlog::error("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream='{}',but publisher={} is not NULL.",
                      fmt::ptr(this), peer_name, peer_port, key_stream_name, fmt::ptr(publisher));
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    // create new publisher
    CSLSPublisher *pub = new CSLSPublisher;
    pub->set_srt(srt);
    pub->set_conf((sls_conf_base_t *)ca);
    pub->init();
    pub->set_idle_streams_timeout(m_idle_streams_timeout_role);
    pub->set_latency(final_latency);

    // stat info
    stat_info_t *stat_info_obj = new stat_info_t();
    stat_info_obj->port = m_port;
    stat_info_obj->role = pub->get_role_name();
    stat_info_obj->pub_domain_app = app_uplive;
    stat_info_obj->stream_name = stream_name;
    stat_info_obj->url = sid;
    stat_info_obj->remote_ip = peer_name;
    stat_info_obj->remote_port = peer_port;
    stat_info_obj->start_time = cur_time;

    pub->set_stat_info_base(*stat_info_obj);

    pub->set_http_url(m_http_url_role);
    // set hls record path
    ret = snprintf(tmp, sizeof(tmp), "%s/%d/%s",
                   m_record_hls_path_prefix, m_port, key_stream_name);
    if (ret < 0 || (unsigned)ret >= sizeof(tmp))
    {
        spdlog::error("[{}] CSLSListener::handler, snprintf failed, ret={:d}, errno={:d}",
                      fmt::ptr(this), ret, errno);
        pub->close();
        srt->libsrt_close();
        delete srt;
        delete pub;
        return client_count;
    }
    pub->set_record_hls_path(tmp);

    spdlog::info("[{}] CSLSListener::handler, new pub={}, key_stream_name={}.",
                 fmt::ptr(this), fmt::ptr(pub), key_stream_name);

    // init data array
    if (SLS_OK != m_map_data->add(key_stream_name))
    {
        spdlog::warn("[{}] CSLSListener::handler, m_map_data->add failed, new pub[{}:{:d}], stream={}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        pub->uninit();
        delete pub;
        pub = NULL;
        return client_count;
    }

    if (SLS_OK != m_map_publisher->set_push_2_publisher(key_stream_name, pub))
    {
        spdlog::warn("[{}] CSLSListener::handler, m_map_publisher->set_push_2_publisher failed, key_stream_name={}.",
                     fmt::ptr(this), key_stream_name);
        pub->uninit();
        delete pub;
        pub = NULL;
        return client_count;
    }
    pub->set_map_publisher(m_map_publisher);
    pub->set_map_data(key_stream_name, m_map_data);
    pub->on_connect();
    m_list_role->push(pub);
    spdlog::info("[{}] CSLSListener::handler, new publisher[{}:{:d}], key_stream_name={}.",
                 fmt::ptr(this), peer_name, peer_port, key_stream_name);

    // 5. check pusher
    if (NULL == m_map_pusher)
    {
        return client_count;
    }
    CSLSRelayManager *pusher_manager = m_map_pusher->add_relay_manager(app_uplive.c_str(), stream_name);
    if (NULL == pusher_manager)
    {
        spdlog::info("[{}] CSLSListener::handler, m_map_pusher->add_relay_manager failed, new role[{}:{:d}], key_stream_name={}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        return client_count;
    }
    pusher_manager->set_map_data(m_map_data);
    pusher_manager->set_map_publisher(m_map_publisher);
    pusher_manager->set_role_list(m_list_role);
    pusher_manager->set_listen_port(m_port);

    if (SLS_OK != pusher_manager->start())
    {
        spdlog::info("[{}] CSLSListener::handler, pusher_manager->start failed, new role[{}:{:d}], key_stream_name={}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
    }
    return client_count;
}

stat_info_t CSLSListener::get_stat_info()
{
    if (m_stat_info.port == 0)
    {
        char cur_time[STR_DATE_TIME_LEN] = {0};
        sls_gettime_default_string(cur_time, sizeof(cur_time));

        m_stat_info.port = m_port;
        m_stat_info.role = m_role_name,
        m_stat_info.start_time = cur_time;
    }
    return m_stat_info;
}
