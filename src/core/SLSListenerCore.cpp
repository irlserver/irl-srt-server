#include "SLSListener.hpp"
#include "SLSSrt.hpp"
#include "SLSRoleList.hpp"
#include "sls_sid.hpp"
#include "spdlog/spdlog.h"
#include <string.h>
#include <errno.h>
#include <regex>
#include <mutex>
#include "SLSLog.hpp"
#include "SLSLogCategory.hpp"

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
    m_is_srtla_listener = false;
    m_is_legacy_listener = false;
    m_port_override = 0;
    m_idle_streams_timeout = UNLIMITED_TIMEOUT;
    m_idle_streams_timeout_role = 0;
    m_publisher_first_data_grace_role = 0;
    m_stat_info = {};
    memset(m_default_sid, 0, STR_MAX_LEN);
    memset(m_http_url_role, 0, URL_MAX_LEN);
    memset(m_player_key_auth_url, 0, URL_MAX_LEN);

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

void CSLSListener::set_listener_type(bool is_publisher)
{
    m_is_publisher_listener = is_publisher;
    if (is_publisher) {
        sprintf(m_role_name, "listener-publisher");
    } else {
        sprintf(m_role_name, "listener-player");
    }
}

void CSLSListener::set_srtla_mode(bool is_srtla)
{
    m_is_srtla_listener = is_srtla;
    if (is_srtla && m_is_publisher_listener) {
        sprintf(m_role_name, "listener-publisher-srtla");
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

void CSLSListener::set_port_override(int port)
{
    m_port_override = port;
}

int CSLSListener::start()
{
    int ret = 0;

    if (NULL == m_conf)
    {
        spdlog::error("[listener] Start failed, conf is null");
        return SLS_ERROR;
    }
    if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
        spdlog::debug("[listener] Starting listener");
    }

    ret = init_conf_app();
    if (SLS_OK != ret)
    {
        spdlog::error("[listener] Start failed, init_conf_app failed");
        return SLS_ERROR;
    }

    if (NULL == m_srt)
        m_srt = new CSLSSrt();

    sls_conf_server_t* server_conf = (sls_conf_server_t*)m_conf;
    if (m_is_publisher_listener && !m_is_legacy_listener) {
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::info)) {
				spdlog::info("[listener] Publisher listener latency set | latency={}ms",
							 server_conf->latency_min);
				}
        } else {
            if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
				spdlog::debug("[listener] Publisher listener allows client latency control");
				}
        }
    } else if (m_is_legacy_listener) {
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::info)) {
				spdlog::info("[listener] Legacy listener latency set | latency={}ms",
							 server_conf->latency_min);
				}
        }
    } else {
        // Player listener: also apply latency_min as a floor. SRT handshake
        // negotiates the effective latency to max(caller_proposed,
        // listener_configured), so this clamps viewers that connect with
        // libsrt's 120ms default upward to the operator's minimum.
        //
        // Why: at low latency (120ms) and modest bitrate (4 Mbps), the
        // SLS-to-viewer SRT delivery window holds only ~60 KB of in-flight
        // data, which is smaller than one DATA_BUFF_SIZE write burst from
        // handler_write_data. Even a brief viewer-side network hiccup
        // fills the send buffer and triggers EASYNCSND. Raising the floor
        // gives proportionally more headroom for retransmit and pacing.
        if (server_conf->latency_min > 0) {
            m_srt->libsrt_set_latency(server_conf->latency_min);
            if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::info)) {
                spdlog::info("[listener] Player listener latency floor set | latency={}ms",
                             server_conf->latency_min);
            }
        } else {
            if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
                spdlog::debug("[listener] Player listener uses network-determined latency");
            }
        }
    }

    if (m_port_override > 0) {
        m_port = m_port_override;
    } else {
        // Only the legacy / fallback listener reaches here and binds the single
        // `listen` directive. Publisher, SRTLA and player listeners always
        // receive an explicit port from CSLSManager, which expands their
        // (possibly multi-port) spec into one listener per port.
        m_port = server_conf->listen;
    }

    if (m_port <= 0) {
        spdlog::error("[listener] Start failed, invalid port | port={} type={}",
				m_port, m_is_publisher_listener ? "publisher" : "player");
        return SLS_ERROR;
    }

    // SRTLA patches are enabled for SRTLA listeners (bonded connections)
    // They are disabled for regular publisher listeners (direct SRT)
    // Player listeners don't need patches (server is sender, not receiver)
    bool use_srtla_patches = m_is_srtla_listener;

    if (server_conf->srt_pbkeylen != 0 && server_conf->srt_pbkeylen != 16 &&
        server_conf->srt_pbkeylen != 24 && server_conf->srt_pbkeylen != 32)
    {
        spdlog::error("[listener] Start failed, srt_pbkeylen={} is invalid (must be 0/16/24/32) | port={}",
                      server_conf->srt_pbkeylen, m_port);
        return SLS_ERROR;
    }
    if (server_conf->srt_passphrase[0] != '\0')
    {
        size_t pass_len = strlen(server_conf->srt_passphrase);
        if (pass_len < 10 || pass_len > 79)
        {
            spdlog::error("[listener] Start failed, srt_passphrase length {} out of range (must be 10-79 bytes) | port={}",
                          pass_len, m_port);
            return SLS_ERROR;
        }
        m_srt->libsrt_set_passphrase(server_conf->srt_passphrase, server_conf->srt_pbkeylen);
        spdlog::info("[listener] SRT encryption enabled | port={} pbkeylen={}",
                     m_port, server_conf->srt_pbkeylen);
    }

    // Inherited by every accepted socket on this listener. See libsrt_setup
    // for the bonding-tolerance tradeoff; 0 leaves the fork default.
    if (server_conf->peer_idle_timeout > 0) {
        m_srt->libsrt_set_peer_idle_timeout(server_conf->peer_idle_timeout);
    }

    ret = m_srt->libsrt_setup(m_port, use_srtla_patches);
    if (SLS_OK != ret)
    {
        spdlog::error("[listener] Start failed, libsrt_setup error | port={}", m_port);
        return ret;
    }

    const char* listener_type = m_is_srtla_listener ? "publisher-srtla" :
                                (m_is_publisher_listener ? "publisher" : "player");
    spdlog::info("[listener] Listener started | port={} type={} srtla_patches={}",
		m_port, listener_type, use_srtla_patches ? "on" : "off");

    ret = m_srt->libsrt_listen(m_back_log);
    if (SLS_OK != ret)
    {
        spdlog::error("[listener] Start failed, libsrt_listen error | port={}", m_port);
        return ret;
    }

    // Reject malformed streamids and recently-failed publisher keys during the
    // handshake, before srt_accept and any webhook. Publisher listeners only
    // (the DoS-relevant path); the negative cache is passed as the opaque and
    // may be null, in which case only the format gate applies. Non-fatal: a
    // failure here just falls back to the post-accept validation.
    if (m_is_publisher_listener)
    {
        if (m_srt->libsrt_set_listen_callback(sls_publisher_listen_callback,
                                              m_auth_reject_cache.get()) != SLS_OK)
        {
            spdlog::warn("[listener] set_listen_callback failed | port={}", m_port);
        }
    }
    else
    {
        // Player listeners get a format-only gate: reject malformed streamids
        // at the handshake so a garbage-streamid flood never reaches
        // srt_accept. No auth cache here (the player path authorizes via the
        // player_key webhook post-accept, not the publisher negative cache).
        if (m_srt->libsrt_set_listen_callback(sls_player_listen_callback,
                                              nullptr) != SLS_OK)
        {
            spdlog::warn("[listener] set_listen_callback (player) failed | port={}", m_port);
        }
    }

    if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
			spdlog::debug("[listener] Checking role list");
			}
    if (NULL == m_list_role)
    {
        if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
				spdlog::debug("[listener] Role list is null");
				}
        return ret;
    }

    if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::debug)) {
			spdlog::debug("[listener] Added to role list");
			}
    m_list_role->push(this);

    return ret;
}

int CSLSListener::stop()
{
    int ret = SLS_OK;
    if (sls_should_log_category(SLSLogCategory::LISTENER, spdlog::level::info)) {
			spdlog::info("[listener] Listener stopped | port={}", m_port);
			}
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