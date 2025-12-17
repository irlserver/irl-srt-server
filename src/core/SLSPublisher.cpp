
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
        strlcpy(m_record_hls, app_conf->record_hls, sizeof(m_record_hls));
        m_record_hls_segment_duration = app_conf->record_hls_segment_duration;
        
        // Initialize bitrate limiter if configured
        if (app_conf->max_input_bitrate_kbps > 0) {
            int violation_timeout = app_conf->max_input_bitrate_violation_timeout;
            if (violation_timeout <= 0) {
                violation_timeout = 30; // Default to 30 seconds if not configured
            }
            ret = init_bitrate_limiter(app_conf->max_input_bitrate_kbps, violation_timeout);
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
    return CSLSRole::uninit();
}

void CSLSPublisher::set_map_publisher(CSLSMapPublisher *publisher)
{
    m_map_publisher = publisher;
}

int CSLSPublisher::handler()
{
    return handler_read_data();
}
