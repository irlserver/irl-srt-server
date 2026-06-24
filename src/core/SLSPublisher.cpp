
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

#include "SLSPublisher.hpp"
#include "SLSPlayer.hpp"
#include "SLSLog.hpp"
#include "SLSLogCategory.hpp"
#include "SLSPusherManager.hpp"
#include "SLSRelayManager.hpp"
#include "util.hpp"

/**
 * app conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(app)

/**
 * CSLSPublisher class implementation
 */

CSLSPublisher::CSLSPublisher()
{
    m_is_write = 0;
    m_map_publisher = NULL;

    sprintf(m_role_name, "publisher");
    
    // Record publisher start for summary logging
    sls_get_summary_logger().record_publisher_start();
}

CSLSPublisher::~CSLSPublisher()
{
    //release
    // Record publisher stop for summary logging
    sls_get_summary_logger().record_publisher_stop();
}

int CSLSPublisher::init()
{
    int ret = CSLSRole::init();
    if (m_conf)
    {
        sls_conf_app_t *app_conf = ((sls_conf_app_t *)m_conf);
        //m_exit_delay = ((sls_conf_app_t *)m_conf)->publisher_exit_delay;

        // Initialize bitrate limiter if configured
        if (app_conf->max_input_bitrate_kbps > 0) {
            int violation_timeout = app_conf->max_input_bitrate_violation_timeout;
            if (violation_timeout <= 0) {
                violation_timeout = 30; // Default to 30 seconds if not configured
            }
            // Spike tolerance: config is percentage (e.g. 120 = 1.2x), default to 120 if not set
            float spike_tolerance = 1.2f;
            if (app_conf->max_input_bitrate_spike_tolerance > 0) {
                spike_tolerance = app_conf->max_input_bitrate_spike_tolerance / 100.0f;
            }
            ret = init_bitrate_limiter(app_conf->max_input_bitrate_kbps, violation_timeout, spike_tolerance);
            if (ret != SLS_OK) {
                spdlog::error("[{}] CSLSPublisher::init, failed to initialize bitrate limiter", fmt::ptr(this));
                return ret;
            }
        }
    }

    return ret;
}

int CSLSPublisher::uninit()
{
    int ret = SLS_OK;

    // Dynamic pusher teardown order is load-bearing (UAF fix): (1) detach+kick
    // the child pushers so none reconnects through the manager; (2) drop the
    // publisher from the maps so a concurrent reconnect() sees no_publisher and
    // spawns no fresh child; (3) ONLY THEN free the manager+SRI. Freeing first
    // (the old order) let an orphaned pusher deref a freed manager.
    if (m_dynamic_pusher_manager)
    {
        m_dynamic_pusher_manager->detach_child_relays();
    }

    if (m_map_data)
    {
        ret = m_map_data->remove(m_map_data_key);
        spdlog::info("[{}] CSLSPublisher::uninit, removed publisher from m_map_data, ret={:d}.",
                     fmt::ptr(this), ret);
    }

    if (m_map_publisher)
    {
        ret = m_map_publisher->remove(this);
        spdlog::info("[{}] CSLSPublisher::uninit, removed publisher from m_map_publisher, ret={:d}.",
                     fmt::ptr(this), ret);
    }

    if (m_dynamic_pusher_manager)
    {
        delete m_dynamic_pusher_manager;
        m_dynamic_pusher_manager = NULL;
        spdlog::info("[relay] dynamic pusher torn down for {}", m_map_data_key);
    }
    if (m_dynamic_pusher_sri)
    {
        delete m_dynamic_pusher_sri;
        m_dynamic_pusher_sri = NULL;
    }

    return CSLSRole::uninit();
}

void CSLSPublisher::set_map_publisher(CSLSMapPublisher *publisher)
{
    m_map_publisher = publisher;
}

int CSLSPublisher::handler()
{
    int ret = handler_read_data();
    // The webhook flips m_http_passed and populates m_push_urls
    // asynchronously inside check_http_passed; once both happen we spin up
    // exactly one CSLSPusherManager carrying every accepted URL.
    if (m_dynamic_pusher_manager == NULL && !m_push_urls.empty()) {
        try_spawn_dynamic_pusher();
    }
    return ret;
}

void CSLSPublisher::try_spawn_dynamic_pusher()
{
    if (m_role_list == NULL || m_map_data == NULL || m_map_publisher == NULL) {
        spdlog::warn("[relay] cannot spawn dynamic pusher for {}: missing context (role_list/map_data/map_publisher)",
                     m_map_data_key);
        // Avoid retrying every handler tick on a misconfigured deploy.
        m_push_urls.clear();
        return;
    }

    // Split m_map_data_key ("app_uplive/stream_name") for the pusher manager.
    const char *slash = strchr(m_map_data_key, '/');
    if (slash == NULL || slash == m_map_data_key) {
        spdlog::warn("[relay] cannot spawn dynamic pusher: malformed key='{}'", m_map_data_key);
        m_push_urls.clear();
        return;
    }
    std::string app_uplive(m_map_data_key, slash - m_map_data_key);
    std::string stream_name(slash + 1);

    m_dynamic_pusher_sri = new SLS_RELAY_INFO;
    snprintf(m_dynamic_pusher_sri->m_type, sizeof(m_dynamic_pusher_sri->m_type), "push");
    m_dynamic_pusher_sri->m_mode = SLS_PM_ALL;
    m_dynamic_pusher_sri->m_reconnect_interval = 10;
    m_dynamic_pusher_sri->m_idle_streams_timeout = 10;
    m_dynamic_pusher_sri->m_upstreams = m_push_urls;

    m_dynamic_pusher_manager = new CSLSPusherManager();
    m_dynamic_pusher_manager->set_relay_conf(m_dynamic_pusher_sri);
    m_dynamic_pusher_manager->set_relay_info(app_uplive.c_str(), stream_name.c_str());
    m_dynamic_pusher_manager->set_map_data(m_map_data);
    m_dynamic_pusher_manager->set_map_publisher(m_map_publisher);
    m_dynamic_pusher_manager->set_role_list(m_role_list);
    m_dynamic_pusher_manager->set_listen_port(m_listen_port);

    if (SLS_OK != m_dynamic_pusher_manager->start()) {
        spdlog::warn("[relay] dynamic pusher start failed for {}, will retry on reconnect", m_map_data_key);
        // Leave the manager allocated so the reconnect loop in CSLSGroup
        // gets a chance to retry; teardown in uninit() will clean it up.
    } else {
        spdlog::info("[relay] dynamic pusher started for {} | upstream_count={}",
                     m_map_data_key, m_push_urls.size());
    }
}

void CSLSPublisher::on_map_data_set()
{
    // The ring (and its ts_info) is allocated lazily on the first authorized
    // packet, so at accept-time set_map_data() there is nothing to flip yet.
    // handler_read_data re-invokes this hook right after the lazy add(), with
    // m_ring_added set, so the gap-fill flag lands on the freshly-created
    // ts_info instead of warning about a missing entry.
    if (!m_ring_added)
        return;
    if (m_map_data && strlen(m_map_data_key) > 0 && is_audio_gap_fill_enabled()) {
        m_map_data->set_audio_gap_fill(m_map_data_key, true);
        spdlog::info("[{}] CSLSPublisher::on_map_data_set, audio gap filling enabled for {}",
                     fmt::ptr(this), m_map_data_key);
    }
}

bool CSLSPublisher::is_audio_gap_fill_enabled() const
{
    const sls_conf_app_t *app_conf = (const sls_conf_app_t *)m_conf;
    return app_conf && app_conf->audio_gap_fill;
}
