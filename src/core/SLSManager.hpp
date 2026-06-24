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

#include <vector>

#include "common.hpp"
#include "SLSRole.hpp"
#include "SLSRoleList.hpp"
#include "SLSGroup.hpp"
#include "SLSListener.hpp"
#include "conf.hpp"
#include "SLSMapData.hpp"
#include "SLSMapRelay.hpp"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

/**
 * srt conf declare
 */
SLS_CONF_DYNAMIC_DECLARE_BEGIN(srt)
char log_file[URL_MAX_LEN];
char log_level[URL_MAX_LEN];
char pidfile[URL_MAX_LEN];
int worker_threads;
int worker_connections;
char stat_post_url[URL_MAX_LEN];
int stat_post_interval;
char user[SHORT_STR_MAX_LEN];
char group[SHORT_STR_MAX_LEN];
int http_port;
// HTTP control-plane bind address. Empty => keep the historical default of all
// interfaces ("::"). Set 127.0.0.1 to restrict the stats/disconnect API to
// loopback when it should not be reachable off-box.
char http_bind_addr[URL_MAX_LEN];
char cors_header[URL_MAX_LEN];
std::vector<std::string> api_keys;
// New logging configuration options
int log_rate_limit_enabled;
int log_rate_limit_window;
int log_rate_limit_threshold;
int log_summary_enabled;
int log_summary_interval;
int log_session_ids;
char log_format[32];
// Category-specific log levels
char log_level_connection[32];
char log_level_listener[32];
char log_level_stream[32];
char log_level_data[32];
char log_level_relay[32];
char log_level_http[32];
char log_level_auth[32];
char log_level_system[32];
// Hard deadline (ms) for resolving a webhook push-destination host name. The
// lookup runs OFF the SRT epoll worker thread; if it overruns this deadline the
// push URL is rejected so a slow/hostile resolver can never stall unrelated
// streams sharing the worker. 0 => built-in default of 5000 ms.
int push_url_dns_timeout_ms;
// Per-socket SRT receive buffer in MB (caps SRTO_RCVBUF and scales SRTO_FC on
// every listener and outbound relay socket). 0 => derive from the bitrate
// ceiling and max latency below instead of a flat constant. The old hardcoded
// 100 MB / 128000-packet window was a pre-auth memory flood amplifier.
int rcv_buf_mb;
// Inputs for the derived receive-buffer default (used only when rcv_buf_mb==0).
// The buffer must hold ~latency-worth of data at peak bitrate plus
// retransmission headroom; sizing it from our own ceilings keeps high-latency
// bonding streams (belabox/moblin, multi-second latency) from starving while
// still bounding pre-auth memory. 0 => built-in defaults (20000 kbps / 8000 ms).
int rcv_sizing_max_bitrate_kbps;
int rcv_sizing_max_latency_ms;
// Global ring-buffer guardrails (pre-auth OOM prevention). 0 means "use the
// built-in default" (256 streams / 2048 MB) — see CSLSManager::start.
int max_streams;
int max_total_ring_mb;
SLS_CONF_DYNAMIC_DECLARE_END

/**
 * srt cmd declare
 */
SLS_CONF_CMD_DYNAMIC_DECLARE_BEGIN(srt)
SLS_SET_CONF(srt, string, log_file, "save log file name.", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, string, log_level, "log level", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, string, pidfile, "PID file path", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, int, worker_threads, "count of worker thread, if 0, only main thread.", 0, 100),
    SLS_SET_CONF(srt, int, worker_connections, "", 1, 1024),
    SLS_SET_CONF(srt, string, stat_post_url, "statistic info post url", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, int, stat_post_interval, "interval of statistic info post.", 1, 60),
    SLS_SET_CONF(srt, string, user, "drop privileges to this user after bind", 1, SHORT_STR_MAX_LEN - 1),
    SLS_SET_CONF(srt, string, group, "drop privileges to this group after bind (defaults to user's primary group)", 1, SHORT_STR_MAX_LEN - 1),
    SLS_SET_CONF(srt, int, http_port, "rest api port", 1, 65535),
    SLS_SET_CONF(srt, string, http_bind_addr, "http control-plane bind address (empty=all interfaces; set 127.0.0.1 for loopback only)", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, string, cors_header, "cors header", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(srt, string_list, api_keys, "comma-separated list of API keys for /stats endpoint", 0, 10240),
    // New logging configuration
    SLS_SET_CONF(srt, int, log_rate_limit_enabled, "enable log rate limiting", 0, 1),
    SLS_SET_CONF(srt, int, log_rate_limit_window, "rate limit window in seconds", 1, 3600),
    SLS_SET_CONF(srt, int, log_rate_limit_threshold, "log every Nth event", 1, 1000),
    SLS_SET_CONF(srt, int, log_summary_enabled, "enable periodic summary logging", 0, 1),
    SLS_SET_CONF(srt, int, log_summary_interval, "summary interval in seconds", 1, 3600),
    SLS_SET_CONF(srt, int, log_session_ids, "enable session ID tracking", 0, 1),
    SLS_SET_CONF(srt, string, log_format, "log format: text or json", 1, 31),
    SLS_SET_CONF(srt, string, log_level_connection, "connection category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_listener, "listener category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_stream, "stream category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_data, "data category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_relay, "relay category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_http, "http category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_auth, "auth category log level", 1, 31),
    SLS_SET_CONF(srt, string, log_level_system, "system category log level", 1, 31),
    SLS_SET_CONF(srt, int, push_url_dns_timeout_ms, "hard deadline in ms for off-worker push-URL DNS resolution (0=default 5000)", 0, 60000),
    SLS_SET_CONF(srt, int, rcv_buf_mb, "per-socket SRT receive buffer in MB; also scales SRTO_FC (0=derive from bitrate/latency below)", 0, 1024),
    SLS_SET_CONF(srt, int, rcv_sizing_max_bitrate_kbps, "peak bitrate (kbps) used to size the receive buffer when rcv_buf_mb=0 (0=default 20000)", 0, 1000000),
    SLS_SET_CONF(srt, int, rcv_sizing_max_latency_ms, "max latency (ms) used to size the receive buffer when rcv_buf_mb=0 (0=default 8000)", 0, 60000),
    SLS_SET_CONF(srt, int, max_streams, "max concurrent publisher/relay streams (rings) per server (0=default 256)", 0, 100000),
    SLS_SET_CONF(srt, int, max_total_ring_mb, "max cumulative ring-buffer memory in MB per server (0=default 2048)", 0, 1048576),
    SLS_CONF_CMD_DYNAMIC_DECLARE_END

    /**
 * CSLSManager , manage players, publishers and listener
 */
    class CSLSManager
{
public:
    CSLSManager();
    virtual ~CSLSManager();

    int start();
    int stop();
    int reload();
    int single_thread_handler();
    json generate_json_for_publisher(std::string publisherName, int clear);
    json generate_json_for_all_publishers(int clear);
    json create_json_stats_for_publisher(CSLSRole *role, int clear);
    int check_invalid();
    bool is_single_thread();

    std::string get_stat_info();

    json disconnect_stream(std::string streamName);

private:
    vector<CSLSListener *> m_servers;
    int m_server_count;
    CSLSMapData *m_map_data;
    CSLSMapPublisher *m_map_publisher;
    CSLSMapRelay *m_map_puller;
    CSLSMapRelay *m_map_pusher;

    vector<CSLSGroup *> m_workers;
    int m_worker_threads;

    CSLSRoleList *m_list_role;
    CSLSGroup *m_single_group;

    // Process-wide negative-auth cache, shared (by shared_ptr) with every
    // publisher listener and the roles they create. Held here so it outlives
    // any listener whose handshake callback still references it via .get().
    std::shared_ptr<AuthRejectCache> m_auth_reject_cache;

    // Owns this manager's configuration generation. Listeners, roles and relays
    // created in start() keep raw sls_conf_* pointers into this tree; holding
    // the reference-counted handle here keeps the tree alive for the manager's
    // whole lifetime, so a manager draining after a SIGHUP reload never derefs a
    // freed conf node. Released automatically when the manager is destroyed.
    std::shared_ptr<sls_conf_base_t> m_conf_generation;
};
