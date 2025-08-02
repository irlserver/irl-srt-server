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
#include "spdlog/spdlog.h"

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "common.hpp"
#include "SLSManager.hpp"
#include "SLSLog.hpp"
#include "SLSListener.hpp"
#include "SLSPublisher.hpp"

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
    m_list_role = NULL;
    m_single_group = NULL;

    m_map_data = NULL;
    m_map_publisher = NULL;
    m_map_puller = NULL;
    m_map_pusher = NULL;
}

CSLSManager::~CSLSManager()
{
}

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
    //set log level
    if (strlen(conf_srt->log_level) > 0)
    {
        sls_set_log_level(conf_srt->log_level);
    }
    //set log file
    if (strlen(conf_srt->log_file) > 0)
    {
        sls_set_log_file(conf_srt->log_file);
    }

    sls_conf_server_t *conf_server = (sls_conf_server_t *)conf_srt->child;
    if (!conf_server)
    {
        spdlog::error("[{}] CSLSManager::start, no server info, please check the conf file.", fmt::ptr(this));
        return SLS_ERROR;
    }
    m_server_count = sls_conf_get_conf_count((sls_conf_base_t *)conf_server);
    spdlog::info("[{}] CSLSManager::start, detected {} server configuration(s)", fmt::ptr(this), m_server_count);
    
    sls_conf_server_t *conf = conf_server;
    m_map_data = new CSLSMapData[m_server_count];
    m_map_publisher = new CSLSMapPublisher[m_server_count];
    m_map_puller = new CSLSMapRelay[m_server_count];
    m_map_pusher = new CSLSMapRelay[m_server_count];

    //role list
    m_list_role = new CSLSRoleList;
    spdlog::info("[{}] CSLSManager::start, new m_list_role={}.", fmt::ptr(this), fmt::ptr(m_list_role));

    //create listeners according config, delete by groups
    for (i = 0; i < m_server_count; i++)
    {
        spdlog::info("[{}] CSLSManager::start, creating listeners for server {} of {}", fmt::ptr(this), i + 1, m_server_count);
        std::vector<std::string> created_listeners;
        
        // 1. Create publisher listener if configured
        if (conf->listen_publisher > 0)
        {
            CSLSListener *pub_listener = new CSLSListener(); //deleted by groups
            pub_listener->set_role_list(m_list_role);
            pub_listener->set_conf((sls_conf_base_t *)conf);
            pub_listener->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
            pub_listener->set_map_data("", &m_map_data[i]);
            pub_listener->set_map_publisher(&m_map_publisher[i]);
            pub_listener->set_map_puller(&m_map_puller[i]);
            pub_listener->set_map_pusher(&m_map_pusher[i]);
            pub_listener->set_listener_type(true); // Publisher listener
            
            if (pub_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, publisher listener init failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            if (pub_listener->start() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, publisher listener start failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            m_servers.push_back(pub_listener);
            created_listeners.push_back("publisher (port " + std::to_string(conf->listen_publisher) + ")");
        }
        
        // 2. Create player listener if configured
        if (conf->listen_player > 0)
        {
            CSLSListener *player_listener = new CSLSListener(); //deleted by groups
            player_listener->set_role_list(m_list_role);
            player_listener->set_conf((sls_conf_base_t *)conf);
            player_listener->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
            player_listener->set_map_data("", &m_map_data[i]);
            player_listener->set_map_publisher(&m_map_publisher[i]);
            player_listener->set_map_puller(&m_map_puller[i]);
            player_listener->set_map_pusher(&m_map_pusher[i]);
            player_listener->set_listener_type(false); // Player listener
            
            if (player_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, player listener init failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            if (player_listener->start() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, player listener start failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            m_servers.push_back(player_listener);
            created_listeners.push_back("player (port " + std::to_string(conf->listen_player) + ")");
        }
        
        // 3. Create legacy listener if listen port is different from listen_publisher
        //    (If they're the same, listen_publisher takes precedence)
        spdlog::info("[{}] CSLSManager::start, checking legacy listener: listen={}, listen_publisher={}", 
                     fmt::ptr(this), conf->listen, conf->listen_publisher);
        if (conf->listen > 0 && conf->listen != conf->listen_publisher)
        {
            spdlog::info("[{}] CSLSManager::start, creating legacy listener on port {}", fmt::ptr(this), conf->listen);
            CSLSListener *legacy_listener = new CSLSListener(); //deleted by groups
            legacy_listener->set_role_list(m_list_role);
            legacy_listener->set_conf((sls_conf_base_t *)conf);
            legacy_listener->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
            legacy_listener->set_map_data("", &m_map_data[i]);
            legacy_listener->set_map_publisher(&m_map_publisher[i]);
            legacy_listener->set_map_puller(&m_map_puller[i]);
            legacy_listener->set_map_pusher(&m_map_pusher[i]);
            // Legacy listener accepts both publishers and players for backwards compatibility
            legacy_listener->set_listener_type(true);
            legacy_listener->set_legacy_mode(true); // Mark as legacy for backwards compatibility
            
            if (legacy_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, legacy listener init failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            if (legacy_listener->start() != SLS_OK)
            {
                spdlog::warn("[{}] CSLSManager::start, legacy listener start failed on port {} - might already be bound, continuing...", fmt::ptr(this), conf->listen);
                delete legacy_listener; // Clean up failed listener
                // Don't return error - continue with existing listeners
            } else {
                spdlog::info("[{}] CSLSManager::start, legacy listener started successfully on port {}", fmt::ptr(this), conf->listen);
                m_servers.push_back(legacy_listener);
                created_listeners.push_back("legacy (port " + std::to_string(conf->listen) + ", accepts both)");
            }
        }
        
        // 4. Fallback: if no listeners were created, create a legacy one
        if (created_listeners.empty())
        {
            int fallback_port = conf->listen > 0 ? conf->listen : (conf->listen_publisher > 0 ? conf->listen_publisher : 30000);
            
            CSLSListener *fallback_listener = new CSLSListener(); //deleted by groups
            fallback_listener->set_role_list(m_list_role);
            fallback_listener->set_conf((sls_conf_base_t *)conf);
            fallback_listener->set_record_hls_path_prefix(conf_srt->record_hls_path_prefix);
            fallback_listener->set_map_data("", &m_map_data[i]);
            fallback_listener->set_map_publisher(&m_map_publisher[i]);
            fallback_listener->set_map_puller(&m_map_puller[i]);
            fallback_listener->set_map_pusher(&m_map_pusher[i]);
            fallback_listener->set_listener_type(true); // Default to publisher listener for backwards compatibility
            fallback_listener->set_legacy_mode(true); // Fallback is also legacy/backwards compatible
            
            if (fallback_listener->init() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, fallback listener init failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            if (fallback_listener->start() != SLS_OK)
            {
                spdlog::error("[{}] CSLSManager::start, fallback listener start failed.", fmt::ptr(this));
                return SLS_ERROR;
            }
            m_servers.push_back(fallback_listener);
            created_listeners.push_back("fallback (port " + std::to_string(fallback_port) + ", accepts both)");
        }
        
        // Log what was created
        std::string listeners_str = "";
        for (size_t j = 0; j < created_listeners.size(); ++j) {
            if (j > 0) listeners_str += ", ";
            listeners_str += created_listeners[j];
        }
        spdlog::info("[{}] CSLSManager::start, created listeners for server {}: {}",
                     fmt::ptr(this), i, listeners_str);
        
        conf = (sls_conf_server_t *)conf->sibling;
    }
    spdlog::info("[{}] CSLSManager::start, init listeners, count={:d}.", fmt::ptr(this), m_server_count);

    //create groups

    m_worker_threads = conf_srt->worker_threads;
    if (m_worker_threads == 0)
    {
        CSLSGroup *p = new CSLSGroup();
        p->set_worker_number(0);
        p->set_role_list(m_list_role);
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
            p->set_role_list(m_list_role);
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

json CSLSManager::generate_json_for_publisher(std::string publisherName, int clear) {
    json ret;
    ret["status"] = "ok";
    ret["publishers"] = json::object();

    for (int i = 0; i < m_server_count; i++) {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        CSLSRole *role = publisher_map->get_publisher(publisherName);

        if (role == NULL) continue;

        ret["publishers"][publisherName] = create_json_stats_for_publisher(role, clear);
        break;
    }

    return ret;
}

json CSLSManager::generate_json_for_all_publishers(int clear) {
    json ret;
    ret["status"] = "ok";
    ret["publishers"] = json::object();

    for (int i = 0; i < m_server_count; i++) {
        CSLSMapPublisher *publisher_map = &m_map_publisher[i];
        // Get all publishers for this server instance
        std::map<std::string, CSLSRole *> all_pubs = publisher_map->get_publishers();

        for (auto const& [pub_name, role] : all_pubs) {
            if (role != nullptr) {
                // Add stats for this publisher to the JSON object
                ret["publishers"][pub_name] = create_json_stats_for_publisher(role, clear);
            }
        }
    }
    return ret;
}

json CSLSManager::create_json_stats_for_publisher(CSLSRole *role, int clear) {
    json ret = json::object();
    SRT_TRACEBSTATS stats = {0};
    role->get_statistics(&stats, clear);
    // Interval
    ret["pktRcvLoss"]       = stats.pktRcvLoss;
    ret["pktRcvDrop"]       = stats.pktRcvDrop;
    ret["bytesRcvLoss"]     = stats.byteRcvLoss;
    ret["bytesRcvDrop"]     = stats.byteRcvDrop;
    ret["mbpsRecvRate"]     = stats.mbpsRecvRate;
    // Instant
    ret["rtt"]              = stats.msRTT;
    ret["msRcvBuf"]         = stats.msRcvBuf;
    ret["mbpsBandwidth"]    = stats.mbpsBandwidth;
    ret["bitrate"]          = role->get_bitrate(); // in kbps
    ret["uptime"]           = role->get_uptime(); // in seconds
    ret["latency"]          = role->get_latency(); // in milliseconds
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

    //stop all listeners
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

    if (m_map_data)
    {
        delete[] m_map_data;
        m_map_data = NULL;
    }
    if (m_map_publisher)
    {
        delete[] m_map_publisher;
        m_map_publisher = NULL;
    }

    if (m_map_puller)
    {
        delete[] m_map_puller;
        m_map_puller = NULL;
    }

    if (m_map_pusher)
    {
        delete[] m_map_pusher;
        m_map_pusher = NULL;
    }

    //release rolelist
    if (m_list_role)
    {
        spdlog::info("[{}] CSLSManager::stop, release rolelist, size={:d}.", fmt::ptr(this), m_list_role->size());
        m_list_role->erase();
        delete m_list_role;
        m_list_role = NULL;
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
            spdlog::info("[{}] CSLSManager::check_invalid, delete worker={}.",
                         fmt::ptr(this), fmt::ptr(worker));
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
                info_obj["stats"].push_back(json{
                    {"port", role_info.port},
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

int CSLSManager::stat_client_callback(void *p, HTTP_CALLBACK_TYPE type, void *v, void *context)
{
    CSLSManager *manager = (CSLSManager *)context;
    if (HCT_REQUEST_CONTENT == type)
    {
        std::string *p_response = (std::string *)v;
        p_response->assign(manager->get_stat_info());
    }
    else if (HCT_RESPONSE_END == type)
    {
        //response info maybe include info that server send client, such as reload cmd...
    }
    else
    {
    }
    return SLS_OK;
}
