#include "SLSListener.hpp"
#include "SLSSrt.hpp"
#include "SLSRoleList.hpp"
#include "spdlog/spdlog.h"
#include <string.h>
#include <errno.h>
#include <regex>
#include <mutex>

// Keep the server conf implementation in exactly one TU
SLS_CONF_DYNAMIC_IMPLEMENT(server)

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

    m_domain_players.clear();
    m_domain_publisher.clear();
    m_app_players.clear();
    {
        std::lock_guard<std::mutex> lk(m_cache_mutex);
        m_player_key_cache.clear();
    }
    m_rate_limit_map.clear();
    m_player_key_auth_timeout = 2000;
    m_player_key_cache_duration = 60000;
    m_player_key_rate_limit_requests = -1;
    m_player_key_rate_limit_window = 60000;
    m_player_key_max_length = 64;
    m_player_key_min_length = 8;
    m_player_key_regex = std::regex("^[\\x20-\\x7E]{8,64}$");

    sprintf(m_role_name, "listener");
}

CSLSListener::~CSLSListener() {}

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

int CSLSListener::start()
{
    int ret = 0;

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

    if (NULL == m_srt)
        m_srt = new CSLSSrt();

    sls_conf_server_t* server_conf = (sls_conf_server_t*)m_conf;
    if (m_is_publisher_listener && !m_is_legacy_listener) {
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            spdlog::info("[{}] CSLSListener::start, set minimum latency={} ms on publisher listener socket.",
                        fmt::ptr(this), server_conf->latency_min);
        } else {
            spdlog::info("[{}] CSLSListener::start, not setting latency on publisher listener socket to allow full client control.", fmt::ptr(this));
        }
    } else if (m_is_legacy_listener) {
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            spdlog::info("[{}] CSLSListener::start, set latency={} ms on legacy listener socket for backwards compatibility.",
                        fmt::ptr(this), server_conf->latency_min);
        }
    } else {
        spdlog::info("[{}] CSLSListener::start, player listener - latency determined by network, not configured.", fmt::ptr(this));
    }

    if (m_is_legacy_listener) {
        m_port = server_conf->listen;
    } else if (m_is_publisher_listener) {
        m_port = server_conf->listen_publisher;
        if (m_port <= 0) {
            m_port = server_conf->listen;
        }
    } else {
        m_port = server_conf->listen_player;
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