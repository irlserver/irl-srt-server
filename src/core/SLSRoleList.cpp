
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
#include <vector>
#include "spdlog/spdlog.h"

#include "SLSRoleList.hpp"
#include "SLSLog.hpp"
#include "SLSLock.hpp"

/**
 * CSLSRoleList class implementation
 */

CSLSRoleList::CSLSRoleList() {}
CSLSRoleList::~CSLSRoleList() {}

int CSLSRoleList::push(std::shared_ptr<CSLSRole> role)
{
    if (role)
    {
        CSLSLock lock(&m_mutex);
        m_list_role.push_back(std::move(role));
    }
    return 0;
}

std::shared_ptr<CSLSRole> CSLSRoleList::pop()
{
    CSLSLock lock(&m_mutex);
    std::shared_ptr<CSLSRole> role;
    if (!m_list_role.empty())
    {
        role = std::move(m_list_role.front());
        m_list_role.pop_front();
    }
    return role;
}

void CSLSRoleList::erase()
{
    CSLSLock lock(&m_mutex);
    spdlog::trace("[{}] CSLSRoleList::erase, list.count={:d}", fmt::ptr(this), m_list_role.size());
    for (auto &role : m_list_role)
    {
        if (role)
        {
            // Drop the raw delete: the shared_ptr destructor frees the role
            // once the last owner releases it. uninit() stays so teardown
            // (epoll removal, SRT close, map removal) runs deterministically
            // here rather than being deferred to whichever thread happens to
            // hold the final reference.
            role->uninit();
        }
    }
    m_list_role.clear();
}

int CSLSRoleList::size()
{
    CSLSLock lock(&m_mutex);
    return m_list_role.size();
}

int CSLSRoleList::reap_unadopted(int64_t now_ms, int64_t ttl_ms)
{
    std::vector<std::shared_ptr<CSLSRole>> stale;
    {
        CSLSLock lock(&m_mutex);
        for (auto it = m_list_role.begin(); it != m_list_role.end();)
        {
            std::shared_ptr<CSLSRole> &role = *it;
            const char *name = role ? role->get_role_name() : nullptr;
            // Never reap a listener: it lives in this handoff list only until
            // the worker adopts it, and dropping it would stop all accepts on
            // its port. Only transient data roles (publisher/player/puller)
            // that have sat un-adopted past the admission TTL are reaped.
            bool is_listener = name && strncmp(name, "listener", 8) == 0;
            if (role && !is_listener && now_ms - role->get_stat_start_time() > ttl_ms)
            {
                stale.push_back(role);
                it = m_list_role.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    // uninit() outside the list lock: it takes other locks (epoll removal, map
    // self-removal), so holding m_mutex across it could invert lock order.
    for (auto &role : stale)
    {
        if (role)
            role->uninit();
    }
    return static_cast<int>(stale.size());
}

int CSLSRoleList::count_players_for_stream(const char *stream_key)
{
    if (!stream_key)
    {
        return 0;
    }

    CSLSLock lock(&m_mutex);
    int player_count = 0;

    for (auto &role : m_list_role)
    {
        const char *role_name = role ? role->get_role_name() : nullptr;
        if (role && role_name && strcmp(role_name, "player") == 0)
        {
            // Check if this player is connected to the specified stream
            const char *map_data_key = role->get_map_data_key();
            if (map_data_key && strcmp(map_data_key, stream_key) == 0)
            {
                player_count++;
            }
        }
    }

    spdlog::debug("[{}] CSLSRoleList::count_players_for_stream, stream='{}', player_count={:d}", fmt::ptr(this),
                  stream_key, player_count);
    return player_count;
}
