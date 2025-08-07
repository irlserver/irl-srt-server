
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

#include <map>
#include <string>

#include "SLSRole.hpp"
#include "SLSRoleList.hpp"
#include "SLSPublisher.hpp"
#include "conf.hpp"
#include "SLSRecycleArray.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSMapRelay.hpp"
#include "SLSSrt.hpp"
#include <map>
#include <chrono>

/**
 * server conf
 */
SLS_CONF_DYNAMIC_DECLARE_BEGIN(server)
char domain_player[URL_MAX_LEN];
char domain_publisher[URL_MAX_LEN];
int listen;
int listen_publisher;
int listen_player;
int backlog;
int latency_min;
int latency_max;
int idle_streams_timeout; //unit s; -1: unlimited
char on_event_url[URL_MAX_LEN];
char player_key_auth_url[URL_MAX_LEN];
int player_key_auth_timeout;
int player_key_cache_duration;
char default_sid[STR_MAX_LEN];
SLS_CONF_DYNAMIC_DECLARE_END

/**
 * sls_conf_server_t
 */
SLS_CONF_CMD_DYNAMIC_DECLARE_BEGIN(server)
SLS_SET_CONF(server, string, domain_player, "play domain", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, string, domain_publisher, "", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, int, listen, "listen port (legacy, use listen_publisher/listen_player)", 1, 65535),
    SLS_SET_CONF(server, int, listen_publisher, "publisher listen port", 1, 65535),
    SLS_SET_CONF(server, int, listen_player, "player listen port", 1, 65535),
    SLS_SET_CONF(server, int, backlog, "how many sockets may be allowed to wait until they are accepted", 1, 1024),
    SLS_SET_CONF(server, int, latency_min, "minimum allowed latency (ms) - enforced on publisher listeners only", 0, 5000),
    SLS_SET_CONF(server, int, latency_max, "maximum allowed latency (ms) - enforced on all connections", 0, 10000),
    SLS_SET_CONF(server, int, idle_streams_timeout, "players idle timeout when no publisher", -1, 86400),
    SLS_SET_CONF(server, string, on_event_url, "on connect/close http url", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, string, player_key_auth_url, "player key authentication API endpoint", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, int, player_key_auth_timeout, "player key authentication timeout (ms)", 1, 30000),
    SLS_SET_CONF(server, int, player_key_cache_duration, "player key cache duration (ms)", 1, 300000),
    SLS_SET_CONF(server, string, default_sid, "default sid to use when no streamid is given", 1, STR_MAX_LEN - 1),
    SLS_CONF_CMD_DYNAMIC_DECLARE_END

    /**
 * SLSListener
 */
    class CSLSListener : public CSLSRole
{
public:
    CSLSListener();
    ~CSLSListener();

    int init();
    int uninit();

    virtual int start();
    virtual int stop();

    virtual int handler();

    void set_role_list(CSLSRoleList *list_role);
    void set_map_publisher(CSLSMapPublisher *publisher);
    void set_map_puller(CSLSMapRelay *map_puller);
    void set_map_pusher(CSLSMapRelay *map_puller);
    void set_record_hls_path_prefix(char *path);
    void set_listener_type(bool is_publisher);
    void set_legacy_mode(bool is_legacy);
    bool should_handle_app(const std::string& app_name, bool is_publisher_connection);

    virtual stat_info_t get_stat_info();

protected:
    int validate_player_key(const char* player_key, char* resolved_stream_id, size_t resolved_stream_id_size);

private:
    CSLSRoleList *m_list_role;
    CSLSMapPublisher *m_map_publisher;
    CSLSMapRelay *m_map_puller;
    CSLSMapRelay *m_map_pusher;
    bool m_is_publisher_listener;
    bool m_is_legacy_listener;

    CSLSMutex m_mutex;

    int m_idle_streams_timeout_role;
    stat_info_t m_stat_info;
    char m_default_sid[1024];
    char m_http_url_role[URL_MAX_LEN];
    char m_player_key_auth_url[URL_MAX_LEN];
    char m_record_hls_path_prefix[URL_MAX_LEN];
    
    // Configuration for player key validation
    std::vector<std::string> m_domain_players;
    std::string m_domain_publisher;
    std::vector<std::string> m_app_players;
    
    // Player key cache structure
    struct PlayerKeyCacheEntry {
        std::string resolved_stream_id;
        std::chrono::steady_clock::time_point expiry_time;
    };
    std::map<std::string, PlayerKeyCacheEntry> m_player_key_cache;
    int m_player_key_auth_timeout;
    int m_player_key_cache_duration;

    int init_conf_app();
};
