#include "SLSListener.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSMapRelay.hpp"
#include "spdlog/spdlog.h"
#include <regex>
#include <vector>
#include <string>

using namespace std;

bool CSLSListener::should_handle_app(const std::string& app_name, bool is_publisher_connection)
{
    if (!m_conf) {
        return true;
    }

    sls_conf_server_t *conf_server = (sls_conf_server_t *)m_conf;
    sls_conf_app_t *conf_app = (sls_conf_app_t *)conf_server->child;

    if (!conf_app) {
        return true;
    }

    if (m_is_legacy_listener) {
        return true;
    }

    int app_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_app);
    sls_conf_app_t *ca = conf_app;

    for (int i = 0; i < app_count; i++) {
        if (is_publisher_connection) {
            if (app_name == std::string(ca->app_publisher)) {
                return m_is_publisher_listener;
            }
        } else {
            if (app_name == std::string(ca->app_player)) {
                return !m_is_publisher_listener;
            }
        }
        ca = (sls_conf_app_t *)ca->sibling;
    }

    return false;
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

    if (NULL == m_map_puller) {
        spdlog::error("[{}] CSLSListener::init_conf_app failed, m_map_puller is null.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (NULL == m_map_pusher) {
        spdlog::error("[{}] CSLSListener::init_conf_app failed, m_map_pusher is null.", fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!m_conf) {
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

    domain_players = sls_conf_string_split(conf_server->domain_player, " ");
    if (domain_players.size() == 0) {
        spdlog::error("[{}] CSLSListener::init_conf_app, wrong domain_player='{}'.", fmt::ptr(this), conf_server->domain_player);
        return SLS_ERROR;
    }
    strUpliveDomain = conf_server->domain_publisher;
    if (strUpliveDomain.length() == 0) {
        spdlog::error("[{}] CSLSListener::init_conf_app, wrong domain_publisher='{}'.", fmt::ptr(this), conf_server->domain_publisher);
        return SLS_ERROR;
    }

    m_domain_players = domain_players;
    m_domain_publisher = strUpliveDomain;

    sls_conf_app_t *conf_app = (sls_conf_app_t *)conf_server->child;
    if (!conf_app) {
        spdlog::error("[{}] CSLSListener::init_conf_app, no app conf info.", fmt::ptr(this));
        return SLS_ERROR;
    }

    int app_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_app);
    sls_conf_app_t *ca = conf_app;
    for (int i = 0; i < app_count; i++) {
        strUplive = ca->app_publisher;
        if (strUplive.length() == 0) {
            spdlog::error("[{}] CSLSListener::init_conf_app, wrong app_publisher='{}', domain_publisher='{}'.",
                          fmt::ptr(this), strUplive, strUpliveDomain);
            return SLS_ERROR;
        }
        strUplive = strUpliveDomain + "/" + strUplive;
        if (m_map_publisher->set_conf(strUplive, (sls_conf_base_t *)ca) != SLS_OK) {
            if (m_map_publisher->get_ca(strUplive) != NULL) {
                spdlog::info("[{}] CSLSListener::init_conf_app, app_publisher='{}' already initialized, skipping.",
                             fmt::ptr(this), strUplive);
            } else {
                spdlog::error("[{}] SLSListener::init_conf_app, duplicate app_publisher='{}'",
                              fmt::ptr(this), strUplive);
                return SLS_ERROR;
            }
        } else {
            spdlog::info("[{}] CSLSListener::init_conf_app, add app push '{}'.",
                         fmt::ptr(this), strUplive);
        }

        strLive = ca->app_player;
        if (strLive.length() == 0) {
            spdlog::error("[{}] CSLSListener::init_conf_app, wrong app_player='{}', domain_publisher='{}'.",
                          fmt::ptr(this), strLive, strUpliveDomain);
            return SLS_ERROR;
        }

        m_app_players.push_back(strLive);

        for (unsigned int j = 0; j < domain_players.size(); j++) {
            strLiveDomain = domain_players[j];
            strTemp = strLiveDomain + "/" + strLive;
            if (strUplive == strTemp) {
                spdlog::error("[{}] CSLSListener::init_conf_app failed, domain/uplive='{}' and domain/live='{}' must not be equal.",
                              fmt::ptr(this), strUplive.c_str(), strTemp.c_str());
                return SLS_ERROR;
            }
            if (m_map_publisher->set_live_2_uplive(strTemp, strUplive) != SLS_OK) {
                std::string existing_uplive = m_map_publisher->get_uplive(strTemp);
                if (!existing_uplive.empty() && existing_uplive == strUplive) {
                    spdlog::info("[{}] CSLSListener::init_conf_app, app_player='{}' already mapped to '{}', skipping.",
                                 fmt::ptr(this), strTemp, strUplive);
                } else {
                    spdlog::error("[{}] CSLSListener::init_conf_app, duplicate app_player='{}'",
                                  fmt::ptr(this), strTemp);
                    return SLS_ERROR;
                }
            } else {
                spdlog::info("[{}] CSLSListener::init_conf_app, add app live='{}', app push='{}'.",
                             fmt::ptr(this), strTemp.c_str(), strUplive.c_str());
            }
        }

        if (NULL != ca->child) {
            sls_conf_relay_t *cr = (sls_conf_relay_t *)ca->child;
            while (cr) {
                if (strcmp(cr->type, "pull") == 0) {
                    if (SLS_OK != m_map_puller->add_relay_conf(strUplive.c_str(), cr)) {
                        spdlog::warn("[{}] CSLSListener::init_conf_app, m_map_puller.add_app_conf faile. relay type='{}', app push='{}'.",
                                     fmt::ptr(this), cr->type, strUplive.c_str());
                    }
                } else if (strcmp(cr->type, "push") == 0) {
                    if (SLS_OK != m_map_pusher->add_relay_conf(strUplive.c_str(), cr)) {
                        spdlog::warn("[{}] CSLSListener::init_conf_app, m_map_pusher.add_app_conf faile. relay type='{}', app push='{}'.",
                                     fmt::ptr(this), cr->type, strUplive.c_str());
                    }
                } else {
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