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

#include <errno.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include "spdlog/spdlog.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "common.hpp"
#include "SLSManager.hpp"
#include "SLSLog.hpp"
#include "SLSListener.hpp"
#include "SLSPublisher.hpp"
#include "auth_reject_cache.hpp"

/**
 * srt conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(srt)

/**
 * CSLSManager class implementation
 */
#define DEFAULT_GROUP 1

CSLSManager::CSLSManager()
{
    m_worker_threads = DEFAULT_GROUP;
    m_server_count = 1;
    m_single_group = NULL;
    // m_map_* (std::vector) and m_list_role (std::unique_ptr) default-construct
    // empty; populated in start(), released by RAII in stop()/dtor.
}

CSLSManager::~CSLSManager() {}

int CSLSManager::start()
{
    int ret = 0;
    int i = 0;

    // Read loaded config file
    sls_conf_srt_t *conf_srt = (sls_conf_srt_t *)sls_conf_get_root_conf();

    if (!conf_srt)
    {
        spdlog::error("[{}] CSLSManager::start, no srt info, please check the conf file.", fmt::ptr(this));
        return SLS_ERROR;
    }

    // Take ownership of the current configuration generation for this manager's
    // whole lifetime. The reference-counted tree is freed only when the last
    // owning manager is destroyed, so roles/relays draining after a SIGHUP
    // reload never dereference a freed sls_conf_* node (UAF fix).
    m_conf_generation = sls_conf_get_root_shared();

    // set log level
    if (strlen(conf_srt->log_level) > 0)
    {
        sls_set_log_level(conf_srt->log_level);
    }
    // set log file
    if (strlen(conf_srt->log_file) > 0)
    {
        sls_set_log_file(conf_srt->log_file);
    }

    // Apply new logging configuration
    sls_log_config_t &log_config = sls_get_log_config();
    log_config.rate_limit_enabled = (conf_srt->log_rate_limit_enabled != 0);
    if (conf_srt->log_rate_limit_window > 0)
    {
        log_config.rate_limit_window_sec = conf_srt->log_rate_limit_window;
        sls_get_rate_limiter().set_window_ms(conf_srt->log_rate_limit_window * 1000);
    }
    if (conf_srt->log_rate_limit_threshold > 0)
    {
        log_config.rate_limit_threshold = conf_srt->log_rate_limit_threshold;
        sls_get_rate_limiter().set_threshold(conf_srt->log_rate_limit_threshold);
    }
    log_config.summary_enabled = (conf_srt->log_summary_enabled != 0);
    if (conf_srt->log_summary_interval > 0)
    {
        log_config.summary_interval_sec = conf_srt->log_summary_interval;
    }
    log_config.session_ids_enabled = (conf_srt->log_session_ids != 0);

    if (strlen(conf_srt->log_format) > 0)
    {
        std::string format(conf_srt->log_format);
        log_config.json_format = (format == "json");
    }

    // Apply category-specific log levels
    if (strlen(conf_srt->log_level_connection) > 0)
        sls_set_category_log_level(SLSLogCategory::CONNECTION, conf_srt->log_level_connection);
    if (strlen(conf_srt->log_level_listener) > 0)
        sls_set_category_log_level(SLSLogCategory::LISTENER, conf_srt->log_level_listener);
    if (strlen(conf_srt->log_level_stream) > 0)
        sls_set_category_log_level(SLSLogCategory::STREAM, conf_srt->log_level_stream);
    if (strlen(conf_srt->log_level_data) > 0)
        sls_set_category_log_level(SLSLogCategory::DATA, conf_srt->log_level_data);
    if (strlen(conf_srt->log_level_relay) > 0)
        sls_set_category_log_level(SLSLogCategory::RELAY, conf_srt->log_level_relay);
    if (strlen(conf_srt->log_level_http) > 0)
        sls_set_category_log_level(SLSLogCategory::HTTP, conf_srt->log_level_http);
    if (strlen(conf_srt->log_level_auth) > 0)
        sls_set_category_log_level(SLSLogCategory::AUTH, conf_srt->log_level_auth);
    if (strlen(conf_srt->log_level_system) > 0)
        sls_set_category_log_level(SLSLogCategory::SYSTEM, conf_srt->log_level_system);

    sls_conf_server_t *conf_server = (sls_conf_server_t *)conf_srt->child;
    if (!conf_server)
    {
        spdlog::error("[{}] CSLSManager::start, no server info, please check the conf file.", fmt::ptr(this));
        return SLS_ERROR;
    }
    m_server_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_server);
    spdlog::info("[{}] CSLSManager::start, detected {} server configuration(s)", fmt::ptr(this), m_server_count);

    sls_conf_server_t *conf = conf_server;
    // Construct fresh, exactly-sized vectors (default-insert; no element moves,
    // so the CSLSMutex members are fine). Never resized after this, keeping the
    // &m_map_*[i] pointers handed to listeners stable for the manager's lifetime.
    m_map_data = std::vector<CSLSMapData>(m_server_count);
    m_map_publisher = std::vector<CSLSMapPublisher>(m_server_count);
    m_map_puller = std::vector<CSLSMapRelay>(m_server_count);
    m_map_pusher = std::vector<CSLSMapRelay>(m_server_count);

    int cap_max_streams = conf_srt->max_streams > 0 ? conf_srt->max_streams : 256;
    int cap_max_total_ring_mb = conf_srt->max_total_ring_mb > 0 ? conf_srt->max_total_ring_mb : 2048;
    int64_t cap_max_total_ring_bytes = (int64_t)cap_max_total_ring_mb * 1024 * 1024;
    for (int s = 0; s < m_server_count; s++)
    {
        m_map_data[s].set_caps(cap_max_streams, cap_max_total_ring_bytes);
    }
    spdlog::info("[{}] CSLSManager::start, ring caps per server: max_streams={}, max_total_ring_mb={}.", fmt::ptr(this),
                 cap_max_streams, cap_max_total_ring_mb);

    // role list
    m_list_role = std::make_unique<CSLSRoleList>();
    spdlog::info("[{}] CSLSManager::start, new m_list_role={}.", fmt::ptr(this), fmt::ptr(m_list_role.get()));

    // One negative-auth cache shared across all listeners and roles. TTL is
    // applied per publisher listener from its conf in init_conf_app; default
    // 30s until then.
    m_auth_reject_cache = std::make_shared<AuthRejectCache>();

    // create listeners according config, delete by groups
    for (i = 0; i < m_server_count; i++)
    {
        spdlog::info("[{}] CSLSManager::start, creating listeners for server {} of {}", fmt::ptr(this), i + 1,
                     m_server_count);
        std::vector<std::string> created_listeners;
        std::vector<int> bound_ports; // ports already bound on this server, to avoid double-bind

        auto port_taken = [&bound_ports](int p)
        { return std::find(bound_ports.begin(), bound_ports.end(), p) != bound_ports.end(); };

        // Build a fully-configured listener for an explicit port. Roles are set
        // by the flags; the port is forced via set_port_override so the listener
        // does not re-derive it from the (now multi-port) conf spec.
        auto make_listener = [&](int port, bool is_publisher, bool srtla, bool legacy) -> CSLSListener *
        {
            CSLSListener *l = new CSLSListener(); // deleted by groups
            l->set_role_list(m_list_role.get());
            l->set_auth_reject_cache(m_auth_reject_cache);
            l->set_conf((sls_conf_base_t *)conf);
            l->set_map_data("", &m_map_data[i]);
            l->set_map_publisher(&m_map_publisher[i]);
            l->set_map_puller(&m_map_puller[i]);
            l->set_map_pusher(&m_map_pusher[i]);
            l->set_listener_type(is_publisher);
            if (srtla)
                l->set_srtla_mode(true);
            if (legacy)
                l->set_legacy_mode(true);
            l->set_port_override(port);
            return l;
        };

        // Expand a port spec and create one listener per port. Returns false on a
        // hard failure (a configured listener that could not start).
        auto create_for_spec = [&](const char *spec, bool is_publisher, bool srtla, const char *label) -> bool
        {
            std::vector<int> ports;
            if (sls_parse_port_list(spec, ports) < 0)
            {
                spdlog::error("[{}] CSLSManager::start, invalid {} port spec '{}'.", fmt::ptr(this), label, spec);
                return false;
            }
            for (int port : ports)
            {
                if (port_taken(port))
                {
                    spdlog::warn(
                        "[{}] CSLSManager::start, {} port {} already bound on this server, skipping duplicate.",
                        fmt::ptr(this), label, port);
                    continue;
                }
                CSLSListener *l = make_listener(port, is_publisher, srtla, false);
                if (l->init() != SLS_OK)
                {
                    spdlog::error("[{}] CSLSManager::start, {} listener init failed on port {}.", fmt::ptr(this), label,
                                  port);
                    delete l;
                    return false;
                }
                if (l->start() != SLS_OK)
                {
                    spdlog::error("[{}] CSLSManager::start, {} listener start failed on port {}.", fmt::ptr(this),
                                  label, port);
                    delete l;
                    return false;
                }
                m_servers.push_back(l);
                bound_ports.push_back(port);
                created_listeners.push_back(std::string(label) + " (port " + std::to_string(port) + ")");
            }
            return true;
        };

        // 1. Publisher listeners (direct SRT). 2. SRTLA publisher listeners
        //    (bonded). 3. Player listeners. Each accepts a multi-port spec.
        if (!create_for_spec(conf->listen_publisher, true, false, "publisher"))
            return SLS_ERROR;
        if (!create_for_spec(conf->listen_publisher_srtla, true, true, "publisher-srtla"))
            return SLS_ERROR;
        if (!create_for_spec(conf->listen_player, false, false, "player"))
            return SLS_ERROR;

        // 4. Legacy listener (accepts both publishers and players) on the single
        //    `listen` port, unless that port is already bound by one of the
        //    role-specific listeners above.
        spdlog::info("[{}] CSLSManager::start, checking legacy listener: listen={}", fmt::ptr(this), conf->listen);
        if (conf->listen > 0 && !port_taken(conf->listen))
        {
            spdlog::info("[{}] CSLSManager::start, creating legacy listener on port {}", fmt::ptr(this), conf->listen);
            CSLSListener *legacy_listener = make_listener(conf->listen, true, false, true);

            if (legacy_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, legacy listener init failed.", fmt::ptr(this));
                delete legacy_listener;
                return SLS_ERROR;
            }
            if (legacy_listener->start() != SLS_OK)
            {
                spdlog::warn("[{}] CSLSManager::start, legacy listener start failed on port {} - might already be "
                             "bound, continuing...",
                             fmt::ptr(this), conf->listen);
                delete legacy_listener; // Clean up failed listener
                // Don't return error - continue with existing listeners
            }
            else
            {
                spdlog::info("[{}] CSLSManager::start, legacy listener started successfully on port {}", fmt::ptr(this),
                             conf->listen);
                m_servers.push_back(legacy_listener);
                bound_ports.push_back(conf->listen);
                created_listeners.push_back("legacy (port " + std::to_string(conf->listen) + ", accepts both)");
            }
        }

        // 5. Fallback: if no listeners were created, create a legacy one
        if (created_listeners.empty())
        {
            int fallback_port = conf->listen > 0 ? conf->listen : 30000;

            CSLSListener *fallback_listener = make_listener(fallback_port, true, false, true);

            if (fallback_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, fallback listener init failed.", fmt::ptr(this));
                delete fallback_listener;
                return SLS_ERROR;
            }
            if (fallback_listener->start() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, fallback listener start failed.", fmt::ptr(this));
                delete fallback_listener;
                return SLS_ERROR;
            }
            m_servers.push_back(fallback_listener);
            bound_ports.push_back(fallback_port);
            created_listeners.push_back("fallback (port " + std::to_string(fallback_port) + ", accepts both)");
        }

        // Log what was created
        std::string listeners_str = "";
        for (size_t j = 0; j < created_listeners.size(); ++j)
        {
            if (j > 0)
                listeners_str += ", ";
            listeners_str += created_listeners[j];
        }
        spdlog::info("[{}] CSLSManager::start, created listeners for server {}: {}", fmt::ptr(this), i, listeners_str);

        conf = (sls_conf_server_t *)conf->sibling;
    }
    spdlog::info("[{}] CSLSManager::start, init listeners, count={:d}.", fmt::ptr(this), m_server_count);

    // create groups

    m_worker_threads = conf_srt->worker_threads;
    if (m_worker_threads == 0)
    {
        CSLSGroup *p = new CSLSGroup();
        p->set_worker_number(0);
        p->set_role_list(m_list_role.get());
        p->set_worker_connections(conf_srt->worker_connections);
        p->set_stat_post_interval(conf_srt->stat_post_interval);
        if (SLS_OK != p->init_epoll())
        {
            spdlog::error("[{}] CSLSManager::start, p->init_epoll failed.", fmt::ptr(this));
            return SLS_ERROR;
        }
        m_workers.push_back(p);
        m_single_group = p;
    }
    else
    {
        for (i = 0; i < m_worker_threads; i++)
        {
            CSLSGroup *p = new CSLSGroup();
            p->set_worker_number(i);
            p->set_role_list(m_list_role.get());
            p->set_worker_connections(conf_srt->worker_connections);
            p->set_stat_post_interval(conf_srt->stat_post_interval);
            if (SLS_OK != p->init_epoll())
            {
                spdlog::error("[{}] CSLSManager::start, p->init_epoll failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            p->start();
            m_workers.push_back(p);
        }
    }
    spdlog::info("[{}] CSLSManager::start, init worker, count={:d}.", fmt::ptr(this), m_worker_threads);

    return ret;
}

json CSLSManager::generate_json_for_publisher(std::string publisherName, int clear)
{
    json ret;
    ret["status"] = "ok";
    ret["publishers"] = json::object();

    for (int i = 0; i < m_server_count; i++)
    {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        // Hold the shared_ptr for the whole stats read: it keeps the publisher
        // alive even if the worker thread tears it down concurrently.
        std::shared_ptr<CSLSRole> role = publisher_map->get_publisher(publisherName);

        if (role == NULL)
            continue;

        ret["publishers"][publisherName] = create_json_stats_for_publisher(role.get(), clear);
        break;
    }

    return ret;
}

json CSLSManager::generate_json_for_all_publishers(int clear)
{
    json ret;
    ret["status"] = "ok";
    ret["publishers"] = json::object();

    for (int i = 0; i < m_server_count; i++)
    {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        // Snapshot holds a reference to every publisher for the whole loop, so
        // none can be freed by the worker thread mid-iteration.
        std::map<std::string, std::shared_ptr<CSLSRole>> all_pubs = publisher_map->get_publishers();

        for (auto const &[pub_name, role] : all_pubs)
        {
            if (role != nullptr)
            {
                ret["publishers"][pub_name] = create_json_stats_for_publisher(role.get(), clear);
            }
        }
    }
    return ret;
}

json CSLSManager::create_json_stats_for_publisher(CSLSRole *role, int clear)
{
    json ret = json::object();
    SRT_TRACEBSTATS stats = {0};
    role->get_statistics(&stats, clear);
    // Interval
    ret["pktRcvLoss"] = stats.pktRcvLoss;
    ret["pktRcvDrop"] = stats.pktRcvDrop;
    ret["bytesRcvLoss"] = stats.byteRcvLoss;
    ret["bytesRcvDrop"] = stats.byteRcvDrop;
    ret["mbpsRecvRate"] = stats.mbpsRecvRate;
    // NAK / retransmit counters. A publisher role's SRT socket is the server's
    // RECEIVE side, so it SENDS NAKs upstream (pktSentNAKTotal) and RECEIVES the
    // resulting retransmits (pktRcvRetrans) — the L1-vs-L2 differential: L1 keeps
    // periodic NAK on so these climb under loss, L2 (NAK off) stays near zero.
    ret["pktSentNAKTotal"] = stats.pktSentNAKTotal;
    ret["pktRecvNAKTotal"] = stats.pktRecvNAKTotal;
    ret["pktRetransTotal"] = stats.pktRetransTotal;
    ret["pktRcvRetrans"] = stats.pktRcvRetrans;
#ifdef SRT_HAVE_SRTLA_REORDER_HOLD
    // How long a gap must persist before this socket calls it lost, measured
    // from the spread between the bonded links feeding it. Reported alongside
    // the NAK counters above because it is what governs them: too short and
    // the retransmit counters climb with packets that were never lost, merely
    // still in flight on a slower link. Absent when built against a libsrt
    // without the SRTLA patches, and 0 on a connection that is not bonded.
    ret["msSrtlaReorderHold"] = stats.msSrtlaReorderHold;
#endif
    // Instant
    ret["rtt"] = stats.msRTT;
    ret["msRcvBuf"] = stats.msRcvBuf;
    ret["mbpsBandwidth"] = stats.mbpsBandwidth;
    ret["bitrate"] = role->get_bitrate(); // in kbps
    ret["uptime"] = role->get_uptime();   // in seconds
    ret["latency"] = role->get_latency(); // in milliseconds
    // Publisher ring-buffer overruns (writer lapped a slow subscriber).
    // Stays at 0 on healthy streams; non-zero means at least one
    // subscriber's read position was forcibly resynced to the write head
    // to avoid handing back corrupted wrapped-around data.
    ret["ringOverruns"] = role->get_ring_overrun_count();
    // Egress send-buffer backpressure events, aggregated across every viewer of
    // this stream. Counts how often srt_sendmsg to a viewer returned EASYNCSND
    // (SRT send buffer full) — the viewer's link could not absorb a write burst,
    // so SLS deferred the remainder to the next epoll wake instead of dropping
    // the viewer. Sourced from the shared publisher ring, NOT the publisher
    // role's own per-role counter: /stats enumerates only publishers, and a
    // publisher never runs the egress write path, so that counter was always 0.
    // Steady growth means viewers are falling behind — under-provisioned links
    // for the stream bitrate, or a viewer latency window that is too small.
    ret["sendBackpressure"] = role->get_viewer_backpressure_events(clear);
    // Sender-side TLPKTDROP toward this stream's viewers, aggregated across
    // every player socket: packets libsrt discarded from a viewer's send queue
    // for exceeding that viewer's latency window — the per-packet skip-forward
    // a viewer perceives as a small jump. Non-zero here with pktRcvDrop at 0
    // means the jumps are on the viewer side (link or latency window), not
    // lost publisher content.
    ret["viewerPktSndDrop"] = role->get_viewer_snd_drops(clear);
    // Furthest any viewer of this stream fell behind the publisher ring write
    // head (bytes) since the last clear. This is the catch-up burst a viewer
    // will drain when it recovers, which the viewer perceives as a time-skip /
    // "replay". Divide by the stream bitrate for a millisecond figure
    // (maxReaderBacklogMs below). 0 on a healthy stream where every viewer keeps
    // up with the write head.
    int64_t max_backlog_bytes = role->get_max_reader_backlog(clear);
    ret["maxReaderBacklogBytes"] = max_backlog_bytes;
    // Same figure expressed as playout time, so operators do not have to do the
    // bitrate math. ms = bytes * 8 / kbps. Only meaningful once a bitrate is
    // known; reported as 0 otherwise.
    int bitrate_kbps = role->get_bitrate();
    ret["maxReaderBacklogMs"] =
        (max_backlog_bytes > 0 && bitrate_kbps > 0) ? (int64_t)(max_backlog_bytes * 8 / bitrate_kbps) : 0;

    return ret;
}

json CSLSManager::disconnect_stream(std::string streamName)
{
    json ret;
    ret["status"] = "error";
    ret["message"] = "Stream not found";

    bool found = false;

    // Iterate through all servers to find and disconnect the stream
    for (int i = 0; i < m_server_count; i++)
    {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        std::shared_ptr<CSLSRole> publisher_role = publisher_map->get_publisher(streamName);

        if (publisher_role != NULL)
        {
            found = true;

            // Ask the owning worker to tear the publisher down on its next
            // get_state() tick. Calling publisher_role->close() directly from
            // the HTTP control thread would delete m_srt while the worker
            // thread is still dereferencing it on the data path — a UAF
            // reachable from the admin /disconnect endpoint. request_kick()
            // only flips an atomic flag, so it is safe across threads, and
            // the actual invalid_srt()/map cleanup happens on the socket
            // owner exactly as it does for publisher takeover.
            spdlog::info("[{}] CSLSManager::disconnect_stream, kicking publisher for stream '{}'.", fmt::ptr(this),
                         streamName);
            publisher_role->request_kick();

            // The players will be disconnected automatically when the publisher closes
            // as they won't be able to read data anymore

            ret["status"] = "ok";
            ret["message"] = "Stream disconnected successfully";
            ret["stream"] = streamName;
            break;
        }
    }

    if (!found)
    {
        spdlog::warn("[{}] CSLSManager::disconnect_stream, stream '{}' not found.", fmt::ptr(this), streamName);
    }

    return ret;
}

int CSLSManager::single_thread_handler()
{
    if (m_single_group)
    {
        return m_single_group->handler();
    }
    return SLS_OK;
}

bool CSLSManager::is_single_thread()
{
    if (m_single_group)
        return true;
    return false;
}

int CSLSManager::stop()
{
    int ret = 0;
    int i = 0;
    //
    spdlog::info("[{}] CSLSManager::stop.", fmt::ptr(this));

    // stop all listeners
    for (CSLSListener *server : m_servers)
    {
        if (server)
        {
            server->uninit();
        }
    }
    m_servers.clear();

    vector<CSLSGroup *>::iterator it_worker;
    for (it_worker = m_workers.begin(); it_worker != m_workers.end(); it_worker++)
    {
        CSLSGroup *p = *it_worker;
        if (p)
        {
            p->stop();
            p->uninit_epoll();
            delete p;
            p = NULL;
        }
    }
    m_workers.clear();

    // Must run AFTER the worker loop above: workers hold raw &m_map_*[i]
    // pointers into these vectors, so the elements outlive every worker.
    m_map_data.clear();
    m_map_publisher.clear();
    m_map_puller.clear();
    m_map_pusher.clear();

    // release rolelist
    if (m_list_role)
    {
        spdlog::info("[{}] CSLSManager::stop, release rolelist, size={:d}.", fmt::ptr(this), m_list_role->size());
        m_list_role->erase();
        m_list_role.reset();
    }
    return ret;
}

int CSLSManager::reload()
{
    spdlog::info("[{}] CSLSManager::reload begin.", fmt::ptr(this));

    // stop all listeners
    for (CSLSListener *server : m_servers)
    {
        if (server)
        {
            server->uninit();
        }
    }
    m_servers.clear();

    // set all groups reload flag
    for (CSLSGroup *worker : m_workers)
    {
        if (worker)
        {
            worker->reload();
        }
    }
    return 0;
}

int CSLSManager::check_invalid()
{
    vector<CSLSGroup *>::iterator it;
    vector<CSLSGroup *>::iterator it_erase;
    vector<CSLSGroup *>::iterator it_end = m_workers.end();
    for (it = m_workers.begin(); it != it_end;)
    {
        CSLSGroup *worker = *it;
        it_erase = it;
        it++;
        if (NULL == worker)
        {
            m_workers.erase(it_erase);
            continue;
        }
        if (worker->is_exit())
        {
            spdlog::info("[{}] CSLSManager::check_invalid, delete worker={}.", fmt::ptr(this), fmt::ptr(worker));
            worker->stop();
            worker->uninit_epoll();
            delete worker;
            m_workers.erase(it_erase);
        }
    }

    if (m_workers.size() == 0)
        return SLS_OK;
    return SLS_ERROR;
}

std::string CSLSManager::get_stat_info()
{
    json info_obj;
    info_obj["stats"] = json::array();

    for (CSLSGroup *worker : m_workers)
    {
        if (worker)
        {
            vector<stat_info_t> worker_info;
            worker->get_stat_info(worker_info);

            for (stat_info_t &role_info : worker_info)
            {
                info_obj["stats"].push_back(json{{"port", role_info.port},
                                                 {"role", role_info.role},
                                                 {"pub_domain_app", role_info.pub_domain_app},
                                                 {"stream_name", role_info.stream_name},
                                                 {"url", role_info.url},
                                                 {"remote_ip", role_info.remote_ip},
                                                 {"remote_port", role_info.remote_port},
                                                 {"start_time", role_info.start_time},
                                                 {"kbitrate", role_info.kbitrate}});
            }
        }
    }

    return info_obj.dump();
}
