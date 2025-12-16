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

#include "SLSMapPublisher.hpp"
#include "SLSLog.hpp"

/**
 * CSLSMapPublisher class implementation
 */

CSLSMapPublisher::CSLSMapPublisher()
{
}
CSLSMapPublisher::~CSLSMapPublisher()
{
    clear();
}

int CSLSMapPublisher::set_conf(std::string key, sls_conf_base_t *ca)
{
    CSLSLock lock(&m_rwclock, true);
    // Check if publisher with this name already exists
    if (m_map_uplive_2_conf.count(key) > 0)
    {
        return SLS_ERROR;
    }
    m_map_uplive_2_conf[key] = ca;
    return SLS_OK;
}

int CSLSMapPublisher::set_live_2_uplive(std::string strLive, std::string strUplive)
{
    CSLSLock lock(&m_rwclock, true);
    // Check if player with this name already exists
    if (m_map_live_2_uplive.count(strLive) > 0)
    {
        return SLS_ERROR;
    }
    m_map_live_2_uplive[strLive] = strUplive;
    return SLS_OK;
}

int CSLSMapPublisher::set_push_2_publisher(std::string app_streamname, CSLSRole *role)
{
    CSLSLock lock(&m_rwclock, true);
    std::map<std::string, CSLSRole *>::iterator it;
    it = m_map_push_2_publisher.find(app_streamname);
    if (it != m_map_push_2_publisher.end())
    {
        CSLSRole *cur_role = it->second;
        if (NULL != cur_role)
        {
            spdlog::error("[{}] CSLSMapPublisher::set_push_2_publisher, failed, cur_role={}, exist, app_streamname={}, m_map_push_2_publisher.size()={:d}.",
                          fmt::ptr(this), fmt::ptr(cur_role), app_streamname.c_str(), m_map_push_2_publisher.size());
            return SLS_ERROR;
        }
    }

    m_map_push_2_publisher[app_streamname] = role;
    spdlog::info("[{}] CSLSMapPublisher::set_push_2_publisher, ok, {}={}, app_streamname={}, m_map_push_2_publisher.size()={:d}.",
                 fmt::ptr(this), role->get_role_name(), fmt::ptr(role), app_streamname.c_str(), m_map_push_2_publisher.size());
    return SLS_OK;
}

std::string CSLSMapPublisher::get_uplive(std::string key_app)
{
    CSLSLock lock(&m_rwclock, false);
    std::string uplive_app = "";
    std::map<std::string, std::string>::iterator it;
    it = m_map_live_2_uplive.find(key_app); // is publisher?
    if (it != m_map_live_2_uplive.end())
    {
        uplive_app = it->second;
    }
    return uplive_app;
}

sls_conf_base_t *CSLSMapPublisher::get_ca(std::string key_app)
{
    CSLSLock lock(&m_rwclock, false);
    sls_conf_base_t *ca = NULL;
    std::map<std::string, sls_conf_base_t *>::iterator it;
    it = m_map_uplive_2_conf.find(key_app);
    if (it == m_map_uplive_2_conf.end())
    {
        return ca;
    }
    ca = it->second;
    return ca;
}

CSLSRole *CSLSMapPublisher::get_publisher(std::string strAppStreamName)
{
    CSLSLock lock(&m_rwclock, false);

    CSLSRole *publisher = NULL;
    std::map<std::string, CSLSRole *>::iterator item;
    item = m_map_push_2_publisher.find(strAppStreamName);
    if (item != m_map_push_2_publisher.end())
    {
        publisher = item->second;
    }
    return publisher;
}

std::vector<std::string> CSLSMapPublisher::get_publisher_names() {
    std::vector<std::string> ret;
    for (auto val : m_map_push_2_publisher) {
        std::string streamName = val.first;
        ret.push_back(streamName);
    }
    return ret;
}

std::map<std::string, CSLSRole *> CSLSMapPublisher::get_publishers()
{
    CSLSLock lock(&m_rwclock, false); // Read lock
    // Return a copy of the map to avoid issues with concurrent modification
    // if the caller iterates while another thread modifies the original map.
    return m_map_push_2_publisher;
}

int CSLSMapPublisher::remove(CSLSRole *role)
{
    int ret = SLS_ERROR;

    CSLSLock lock(&m_rwclock, true);

    for (auto it = m_map_push_2_publisher.begin(); it != m_map_push_2_publisher.end(); ++it)
    {
        if (role == it->second)
        {
            spdlog::info("[{}] CSLSMapPublisher::remove, {}={}, live_key={}.",
                         fmt::ptr(this), it->second->get_role_name(), fmt::ptr(it->second), it->first.c_str());
            m_map_push_2_publisher.erase(it);
            ret = SLS_OK;
            break;
        }
    }
    return ret;
}

void CSLSMapPublisher::clear()
{
    CSLSLock lock(&m_rwclock, true);
    spdlog::debug("[{}] CSLSMapPublisher::clear", fmt::ptr(this));
    m_map_push_2_publisher.clear();
    m_map_live_2_uplive.clear();
    m_map_uplive_2_conf.clear();
}
