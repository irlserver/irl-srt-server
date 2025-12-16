#include "SLSListener.hpp"
#include "SLSPlayer.hpp"
#include "SLSPublisher.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSMapRelay.hpp"
#include "SLSSrt.hpp"
#include "util.hpp"
#include "spdlog/spdlog.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <chrono>

int CSLSListener::handler()
{
    cleanupExpiredStreamOverrides();
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

    fd_client = m_srt->libsrt_accept();
    if (fd_client < 0) {
        spdlog::error("[{}] CSLSListener::handler, srt_accept failed, fd={:d}.", fmt::ptr(this), get_fd());
        CSLSSrt::libsrt_neterrno();
        return client_count;
    }
    client_count = 1;

    srt = new CSLSSrt;
    srt->libsrt_set_fd(fd_client);
    ret = srt->libsrt_getpeeraddr(peer_name, peer_port);
    if (ret != 0) {
        spdlog::error("[{}] CSLSListener::handler, libsrt_getpeeraddr failed, fd={:d}.", fmt::ptr(this), srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    spdlog::info("[{}] CSLSListener::handler, new client[{}:{:d}], fd={:d}, listener_type={}, legacy={}, port={}.",
                 fmt::ptr(this), peer_name, peer_port, fd_client,
                 m_is_publisher_listener ? "publisher" : "player",
                 m_is_legacy_listener ? "true" : "false", m_port);

    sls_conf_server_t* conf_server = (sls_conf_server_t*)m_conf;
    int negotiated_latency = 0;
    int latency_len = sizeof(negotiated_latency);
    int final_latency = 0;

    if (0 != srt->libsrt_getsockopt(SRTO_LATENCY, "SRTO_LATENCY", &negotiated_latency, &latency_len)) {
        negotiated_latency = conf_server->latency_min > 0 ? conf_server->latency_min : 120;
        spdlog::warn("[{}] CSLSListener::handler, [{}:{:d}], failed to read latency, using fallback {} ms.",
                fmt::ptr(this), peer_name, peer_port, negotiated_latency);
    } else {
        const char* role = m_is_publisher_listener ? "publisher" : "player";
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], {} latency={} ms.",
                fmt::ptr(this), peer_name, peer_port, role, negotiated_latency);
        if (conf_server->latency_max > 0 && negotiated_latency > conf_server->latency_max) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], rejecting {}: latency {} ms exceeds maximum {} ms.",
                    fmt::ptr(this), peer_name, peer_port, role, negotiated_latency, conf_server->latency_max);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
    }

    final_latency = negotiated_latency;

    if (0 != srt->libsrt_getsockopt(SRTO_STREAMID, "SRTO_STREAMID", &sid, &sid_size)) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, get streamid info failed.",
                      fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], received stream_id: '{}'",
                 fmt::ptr(this), peer_name, peer_port, sid);

    if (strlen(sid) == 0) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, empty stream ID not allowed.", fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    sid_kv = srt->libsrt_parse_sid(sid);
    bool sidValid = true;
    if (sid_kv.count("h")) {
        strlcpy(host_name, sid_kv.at("h").c_str(), sizeof(host_name));
    } else {
        sidValid = false;
    }
    if (sid_kv.count("sls_app")) {
        strlcpy(app_name, sid_kv.at("sls_app").c_str(), sizeof(app_name));
    } else {
        sidValid = false;
    }
    if (sid_kv.count("r")) {
        strlcpy(stream_name, sid_kv.at("r").c_str(), sizeof(stream_name));
    } else {
        sidValid = false;
    }
    if (!sidValid) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], parse sid='{}' failed.", fmt::ptr(this), peer_name, peer_port, sid);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], sid '{}/{}/{}'",
                 fmt::ptr(this), peer_name, peer_port, host_name, app_name, stream_name);

    snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);

    std::string app_uplive = "";
    sls_conf_app_t *ca = NULL;

    char cur_time[STR_DATE_TIME_LEN] = {0};
    sls_gettime_default_string(cur_time, sizeof(cur_time));

    app_uplive = m_map_publisher->get_uplive(key_app);
    bool is_player_connection = (app_uplive.length() > 0);
    bool connection_allowed = true;

    spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], connection analysis: key_app='{}', app_uplive='{}', is_player_connection={}, listener_type={}, legacy={}",
                 fmt::ptr(this), peer_name, peer_port, key_app, app_uplive, is_player_connection ? "true" : "false",
                 m_is_publisher_listener ? "publisher" : "player", m_is_legacy_listener ? "true" : "false");

    if (m_is_legacy_listener) {
        spdlog::debug("[{}] CSLSListener::handler, {} connection with app '{}' accepted on legacy listener (port {}) - backwards compatible.",
                      fmt::ptr(this), is_player_connection ? "player" : "publisher", app_name, m_port);
    } else {
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], validation check: is_publisher_listener={}, is_player_connection={}",
                     fmt::ptr(this), peer_name, peer_port, m_is_publisher_listener ? "true" : "false", is_player_connection ? "true" : "false");

        if (!m_is_publisher_listener && !is_player_connection) {
            spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], publisher connection with app '{}' attempted on dedicated player listener (port {}).",
                         fmt::ptr(this), peer_name, peer_port, app_name, m_port);
            connection_allowed = false;
        } else if (m_is_publisher_listener && is_player_connection) {
            spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], player connection with app '{}' attempted on dedicated publisher listener (port {}).",
                         fmt::ptr(this), peer_name, peer_port, app_name, m_port);
            connection_allowed = false;
        } else {
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

    char validated_stream_id[URL_MAX_LEN] = {0};
    char player_key[URL_MAX_LEN] = {0};
    bool player_key_validation_required = false;

    char domain[URL_MAX_LEN] = {0};
    char app[URL_MAX_LEN] = {0};
    char stream_part[URL_MAX_LEN] = {0};

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

    bool is_player_domain = false;
    bool is_player_app = false;

    for (const auto& player_domain : m_domain_players) {
        if (strcmp(domain, player_domain.c_str()) == 0) {
            is_player_domain = true;
            break;
        }
    }

    for (const auto& player_app : m_app_players) {
        if (strcmp(app, player_app.c_str()) == 0) {
            is_player_app = true;
            break;
        }
    }

    if (part_count == 3 && is_player_domain && is_player_app && strlen(m_player_key_auth_url) > 0) {
        strlcpy(player_key, stream_part, sizeof(player_key));
        player_key_validation_required = true;

        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], detected player connection with configured format '{}/{}', player_key='{}', validating...",
                     fmt::ptr(this), peer_name, peer_port, domain, app, player_key);

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

        strlcpy(sid, validated_stream_id, sizeof(sid));
        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], updated stream_id to: '{}'",
                     fmt::ptr(this), peer_name, peer_port, sid);

        sid_kv = srt->libsrt_parse_sid(sid);
        bool validated_sid_valid = true;

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

        snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);

        spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], re-parsed validated stream: '{}/{}/{}'",
                     fmt::ptr(this), peer_name, peer_port, host_name, app_name, stream_name);
    }

    if (app_uplive.length() > 0) {
        snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name);
        if (player_key_validation_required) {
            auto now_ts = std::chrono::steady_clock::now();
            PlayerKeyCacheEntry entry;
            bool found_entry = false;
            {
                std::lock_guard<std::mutex> lk(m_cache_mutex);
                auto it_cache = m_player_key_cache.find(std::string(player_key));
                if (it_cache != m_player_key_cache.end()) {
                    entry = it_cache->second;
                    found_entry = true;
                }
            }
            if (found_entry) {
                if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                    StreamPlayerLimitEntry stream_entry;
                    stream_entry.has_override = true;
                    stream_entry.max_players_per_stream = entry.max_players_per_stream_override;
                    stream_entry.expiry_time = entry.expiry_time;
                    m_stream_player_limit_map[std::string(key_stream_name)] = stream_entry;
                    spdlog::info("[{}] CSLSListener::handler, applied per-stream cap override for stream='{}' to {} (from key).",
                                 fmt::ptr(this), key_stream_name, stream_entry.max_players_per_stream);
                }
            }
        }
        CSLSRole *pub = m_map_publisher->get_publisher(key_stream_name);
        if (NULL == pub) {
            if (NULL == m_map_puller) {
                spdlog::info("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream='{}', publisher is NULL and m_map_puller is NULL.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            CSLSRelayManager *puller_manager = m_map_puller->add_relay_manager(app_uplive.c_str(), stream_name);
            if (NULL == puller_manager) {
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

            if (SLS_OK != puller_manager->start()) {
                spdlog::info("[{}] CSLSListener::handler, puller_manager->start failed, new client[{}:{:d}], stream='{}'.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            spdlog::info("[{}] CSLSListener::handler, puller_manager->start ok, new client[{}:{:d}], stream={}.",
                         fmt::ptr(this), peer_name, peer_port, key_stream_name);

            pub = m_map_publisher->get_publisher(key_stream_name);
            if (NULL == pub) {
                spdlog::warn("[{}] CSLSListener::handler, publisher not ready after puller start, new client[{}:{:d}], stream='{}'. Client should retry.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            spdlog::info("[{}] CSLSListener::handler, m_map_publisher->get_publisher ok, pub={}, new client[{}:{:d}], stream='{}'.",
                         fmt::ptr(this), fmt::ptr(pub), peer_name, peer_port, key_stream_name);
        }

        ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
        if (ca == nullptr) {
            spdlog::error("[{}] CSLSListener::handler, refused, configuration does not exist [stream={}]",
                           fmt::ptr(this), key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        } else {
            if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK) {
                bool address_matched = false;
                for (sls_ip_access_t &acl_entry : ca->ip_actions.play) {
                    if (acl_entry.ip_address == peer_addr_raw || acl_entry.ip_address == 0) {
                        switch (acl_entry.action) {
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
                    if (address_matched) break;
                }
                if (!address_matched) {
                    spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                                 fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
                }
            } else {
                spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
                spdlog::error("[{}] CSLSListener::handler Accepting connection by default", fmt::ptr(this));
            }
        }

        CSLSRole *pub_check = m_map_publisher->get_publisher(key_stream_name);
        if (NULL == pub_check) {
            spdlog::error("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream={}, publisher no longer exists.",
                          fmt::ptr(this), peer_name, peer_port, key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        {
            int effective_max_players = ca->max_players_per_stream;
            bool using_override = false;
            auto now_ts = std::chrono::steady_clock::now();

            auto it_stream_cap = m_stream_player_limit_map.find(std::string(key_stream_name));
            if (it_stream_cap != m_stream_player_limit_map.end()) {
                const StreamPlayerLimitEntry &sentry = it_stream_cap->second;
                if (sentry.has_override && now_ts < sentry.expiry_time) {
                    effective_max_players = sentry.max_players_per_stream;
                    using_override = true;
                } else if (now_ts >= sentry.expiry_time) {
                    m_stream_player_limit_map.erase(it_stream_cap);
                }
            }

            if (!using_override && player_key_validation_required) {
                PlayerKeyCacheEntry entry;
                bool found_entry = false;
                {
                    std::lock_guard<std::mutex> lk(m_cache_mutex);
                    auto it_cache = m_player_key_cache.find(std::string(player_key));
                    if (it_cache != m_player_key_cache.end()) {
                        entry = it_cache->second;
                        found_entry = true;
                    }
                }
                if (found_entry) {
                    if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                        effective_max_players = entry.max_players_per_stream_override;
                        using_override = true;
                    }
                }
            }

            if (effective_max_players > 0) {
                int current_player_count = m_list_role->count_players_for_stream(key_stream_name);
                if (current_player_count >= effective_max_players) {
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

        if (srt->libsrt_socket_nonblock(0) < 0)
            spdlog::warn("[{}] CSLSListener::handler, new player[{}:{:d}], libsrt_socket_nonblock failed.",
                         fmt::ptr(this), peer_name, peer_port);

        CSLSPlayer *player = new CSLSPlayer;
        if (NULL == player) {
            spdlog::error("[{}] CSLSListener::handler, failed to allocate player for [{}:{:d}]",
                         fmt::ptr(this), peer_name, peer_port);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        player->init();
        player->set_idle_streams_timeout(m_idle_streams_timeout_role);
        player->set_srt(srt);
        player->set_map_data(key_stream_name, m_map_data);
        player->set_latency(final_latency);

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

    app_uplive = key_app;
    snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name);
    ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
    if (NULL == ca) {
        spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], non-existent publishing domain [stream='{}']",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK) {
        bool address_matched = false;
        for (sls_ip_access_t &acl_entry : ca->ip_actions.publish) {
            if (acl_entry.ip_address == peer_addr_raw || acl_entry.ip_address == 0) {
                switch (acl_entry.action) {
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
            if (address_matched) break;
        }
        if (!address_matched) {
            spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                         fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
        }
    } else {
        spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
        spdlog::error("[{}] CSLSListener::handler Accepting connection by default", fmt::ptr(this));
    }

    CSLSRole *publisher = m_map_publisher->get_publisher(key_stream_name);
    if (NULL != publisher) {
        spdlog::error("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream='{}',but publisher={} is not NULL.",
                      fmt::ptr(this), peer_name, peer_port, key_stream_name, fmt::ptr(publisher));
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    CSLSPublisher *pub = new CSLSPublisher;
    pub->set_srt(srt);
    pub->set_conf((sls_conf_base_t *)ca);
    pub->init();
    pub->set_idle_streams_timeout(m_idle_streams_timeout_role);
    pub->set_latency(final_latency);

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
    int nret = snprintf(tmp, sizeof(tmp), "%s/%d/%s",
                   m_record_hls_path_prefix, m_port, key_stream_name);
    if (nret < 0 || (unsigned)nret >= sizeof(tmp)) {
        spdlog::error("[{}] CSLSListener::handler, snprintf failed, ret={:d}, errno={:d}",
                      fmt::ptr(this), nret, errno);
        pub->close();
        srt->libsrt_close();
        delete srt;
        delete pub;
        return client_count;
    }
    pub->set_record_hls_path(tmp);

    spdlog::info("[{}] CSLSListener::handler, new pub={}, key_stream_name={}.",
                 fmt::ptr(this), fmt::ptr(pub), key_stream_name);

    if (SLS_OK != m_map_data->add(key_stream_name)) {
        spdlog::warn("[{}] CSLSListener::handler, m_map_data->add failed, new pub[{}:{:d}], stream= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        pub->uninit();
        delete pub;
        pub = NULL;
        return client_count;
    }

    if (SLS_OK != m_map_publisher->set_push_2_publisher(key_stream_name, pub)) {
        spdlog::warn("[{}] CSLSListener::handler, m_map_publisher->set_push_2_publisher failed, key_stream_name= {}.",
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
    spdlog::info("[{}] CSLSListener::handler, new publisher[{}:{:d}], key_stream_name= {}.",
                 fmt::ptr(this), peer_name, peer_port, key_stream_name);

    if (NULL == m_map_pusher) {
        return client_count;
    }
    CSLSRelayManager *pusher_manager = m_map_pusher->add_relay_manager(app_uplive.c_str(), stream_name);
    if (NULL == pusher_manager) {
        spdlog::info("[{}] CSLSListener::handler, m_map_pusher->add_relay_manager failed, new role[{}:{:d}], key_stream_name= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        return client_count;
    }
    pusher_manager->set_map_data(m_map_data);
    pusher_manager->set_map_publisher(m_map_publisher);
    pusher_manager->set_role_list(m_list_role);
    pusher_manager->set_listen_port(m_port);

    if (SLS_OK != pusher_manager->start()) {
        spdlog::info("[{}] CSLSListener::handler, pusher_manager->start failed, new role[{}:{:d}], key_stream_name= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
    }
    return client_count;
}

void CSLSListener::cleanupExpiredStreamOverrides()
{
    auto now_ts = std::chrono::steady_clock::now();
    for (auto it = m_stream_player_limit_map.begin(); it != m_stream_player_limit_map.end(); ) {
        const StreamPlayerLimitEntry &entry = it->second;
        if (entry.expiry_time <= now_ts) {
            it = m_stream_player_limit_map.erase(it);
        } else {
            ++it;
        }
    }
}