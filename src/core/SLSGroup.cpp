
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

#include "SLSGroup.hpp"
#include "SLSLog.hpp"

// Max time the worker blocks in srt_epoll_wait when nothing is ready.
// Since players/pushers are no longer permanently armed for
// SRT_EPOLL_OUT (see CSLSSrt::libsrt_add_to_epoll), egress is driven by
// the worker's periodic pass over the publisher ring; for a viewer whose
// publisher lives in a *different* worker, this timeout is therefore the
// worst-case forwarding latency (that worker has no SRT event to wake it
// when ring data arrives). 10ms keeps cross-worker egress latency well
// inside any viewer's TSBPD budget while costing only ~100 idle wakeups
// per second per worker (each a tiny no-op pass), with no busy-spin
// because nothing is permanently writable.
#define POLLING_TIME 10

// Housekeeping cadence (idle_check). Decoupled from POLLING_TIME so the
// per-role srt_getsockstate sweep and role-list pops run at a steady
// ~20 Hz regardless of how often the egress tick fires. See
// maybe_idle_check.
#define IDLE_CHECK_INTERVAL 50

/**
 * CSLSGroup class implementation
 */

CSLSGroup::CSLSGroup()
{
    m_list_role = NULL;
    m_worker_connections = 100;
    m_worker_number = 0;
    m_reload = false;

    m_stat_post_last_tm_ms = sls_gettime_ms();
    m_stat_post_interval = 5; // 5s default
    m_last_idle_check_ms = 0; // force idle_check on the first iteration
}
CSLSGroup::~CSLSGroup()
{
    spdlog::trace("[{}] CSLSGroup::~CSLSGroup(), role={}", fmt::ptr(this), fmt::ptr(m_list_role));
    // Note: m_list_role is NOT owned by CSLSGroup, it's shared from CSLSManager
    // CSLSManager is responsible for deleting it, so we just set it to NULL
    m_list_role = NULL;
}

int CSLSGroup::start()
{
    spdlog::info("[{}] CSLSGroup::start, worker_number={:d}.", fmt::ptr(this), m_worker_number);
    // do something here
    return CSLSEpollThread::start();
}

int CSLSGroup::stop()
{
    int ret = 0;
    spdlog::info("[{}] CSLSGroup::stop, worker_number={:d}.", fmt::ptr(this), m_worker_number);
    // Kick the worker out of srt_epoll_wait so it observes m_exit
    // (set by CSLSEpollThread::stop) immediately instead of waiting for
    // the next idle timeout. Safe to call from any thread.
    wake();
    ret = CSLSEpollThread::stop();

    std::list<CSLSRole *>::iterator it_erase;
    for (std::list<CSLSRole *>::iterator it = m_list_wait_http_role.begin(); it != m_list_wait_http_role.end();)
    {
        CSLSRole *role = *it;
        if (role)
        {
            role->uninit();
            delete role;
        }
        it++;
    }
    m_list_wait_http_role.clear();
    spdlog::info("[{}] CSLSGroup::stop, m_list_wait_http_role.clear, worker_number={:d}.", fmt::ptr(this), m_worker_number);
    return ret;
}

void CSLSGroup::reload()
{
    m_reload = true;
    // Wake the worker so the reload check (in handler()) runs without
    // waiting for the next idle timeout.
    wake();
}

void CSLSGroup::check_new_role()
{

    // first, check rolelist
    if (NULL == m_list_role)
        return;
    if (m_map_role.size() >= m_worker_connections)
        return;

    CSLSRole *role = m_list_role->pop();
    if (NULL == role)
        return;

    int fd = role->get_fd();
    if (fd == 0)
    {
        // invalid role
        delete role;
        return;
    }

    // add to epoll
    if (0 == role->add_to_epoll(m_eid))
    {
        m_map_role[fd] = role;
        // Log at DEBUG level (worker operations are verbose)
        spdlog::debug("[{}] CSLSGroup::check_new_role, worker={:d}, {}={}, fd={:d}, role_map.size={:d}.",
                     fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role), fd, m_map_role.size());
    }
    else
    {
        spdlog::error("[{}] CSLSGroup::check_new_role, worker={:d}, {}={}, add_to_epoll failed, fd={:d}.",
                      fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role), fd);
        delete role;
    }
}

int CSLSGroup::handler()
{
    int ret = 0;
    int i;
    int read_len = MAX_SOCK_COUNT;
    int write_len = MAX_SOCK_COUNT;
    // System sockets (eventfd from CSLSEpollThread) returned by srt_epoll_wait.
    // Only one entry needed today (the wake fd) but room for growth.
    SYSSOCKET sys_read_socks[4];
    int sys_read_len = (int)(sizeof(sys_read_socks) / sizeof(sys_read_socks[0]));
    int sys_write_len = 0; // we never register system sockets for write events

    int handler_count = 0;

    if (m_reload && (m_map_role.size() == 0))
    {
        spdlog::info("[{}] CSLSGroup::handle, worker_number={:d} stop, m_reload is true, m_map_role.size()=0.",
                     fmt::ptr(this), m_worker_number);
        m_exit = true;
        return SLS_OK;
    }

    // Event-driven wait. Blocks up to POLLING_TIME ms unless a socket
    // event fires (publisher IN, a backpressured role's OUT once its send
    // buffer drains, or any role's ERR) or wake() is called via the
    // eventfd. On timeout we still fall through to the egress pass below,
    // because writable roles are no longer permanently armed for OUT and
    // a role whose publisher lives in another worker has no SRT event to
    // wake this one when fresh ring data appears.
    ret = srt_epoll_wait(m_eid, m_read_socks, &read_len,
                         m_write_socks, &write_len,
                         POLLING_TIME,
                         sys_read_socks, &sys_read_len,
                         NULL, &sys_write_len);
    if (ret < 0)
    {
        ret = srt_getlasterror(NULL);
        if (ret != SRT_ETIMEOUT) // 6003: ordinary idle timeout, not an error
            CSLSSrt::libsrt_neterrno();
        // No usable read/write sets on this path; skip the read loop and
        // go straight to the egress pass + housekeeping.
        read_len = 0;
    }
    else
    {
        // Drain the wake fd if it fired. We don't care which fd
        // specifically (only one is registered today) — drain_wake_fd is
        // idempotent.
        if (sys_read_len > 0)
        {
            drain_wake_fd();
        }

        spdlog::trace("[{}] CSLSGroup::handle, worker_number={:d}, writable sock count={:d}, readable sock count={:d}.",
                      fmt::ptr(this), m_worker_number, write_len, read_len);

        // Reads: publishers and pullers. (Writable roles are serviced by
        // the egress pass below, not from m_write_socks — OUT events only
        // matter as a wake signal for backpressure recovery, which the
        // pass then handles.)
        for (i = 0; i < read_len; i++)
        {
            std::map<int, CSLSRole *>::iterator it = m_map_role.find(m_read_socks[i]);
            if (it == m_map_role.end())
            {
                spdlog::warn("[{}] CSLSGroup::handle, worker_number={:d}, no role map readable sock={:d}, why?",
                             fmt::ptr(this), m_worker_number, m_read_socks[i]);
                continue;
            }

            CSLSRole *role = it->second;
            if (!role)
            {
                spdlog::warn("[{}] CSLSGroup::handle, worker_number={:d}, role is null, readable sock={:d}, why?",
                             fmt::ptr(this), m_worker_number, m_read_socks[i]);
                continue;
            }

            ret = role->handler();
            if (ret < 0)
            {
                // handle exception
                spdlog::trace("[{}] CSLSGroup::handle, worker_number={:d}, readable sock={:d} is invalid, {}={}, readable len={:d}, role_map.size={:d}.",
                              fmt::ptr(this), m_worker_number, m_read_socks[i], role->get_role_name(), fmt::ptr(role), read_len, m_map_role.size());
                role->invalid_srt();
            }
            else
            {
                handler_count += ret;
            }
        }
    }

    // Egress pass. Players/pushers register ERR-only and are driven from
    // here rather than from a permanently-armed SRT_EPOLL_OUT (which, being
    // level-triggered, would make srt_epoll_wait busy-return every
    // iteration and peg a core). Forward any newly-available publisher-ring
    // data to every writable role, then let the role arm/disarm OUT based
    // on whether it is backpressured. invalid_srt() here does not erase
    // from m_map_role (check_invalid_sock does, later), so iterating is
    // safe.
    for (std::map<int, CSLSRole *>::iterator it = m_map_role.begin(); it != m_map_role.end(); ++it)
    {
        CSLSRole *role = it->second;
        if (!role)
            continue;

        // Periodic hook for every role, independent of socket events. The
        // listener uses it to complete deferred player accepts whose async
        // validation has resolved, even when no new connection arrives.
        role->on_worker_tick();

        if (!role->is_write())
            continue;

        ret = role->handler();
        if (ret < 0)
        {
            spdlog::trace("[{}] CSLSGroup::handle, worker_number={:d}, egress sock={:d} is invalid, {}={}, role_map.size={:d}.",
                          fmt::ptr(this), m_worker_number, it->first, role->get_role_name(), fmt::ptr(role), m_map_role.size());
            role->invalid_srt();
        }
        else
        {
            handler_count += ret;
            role->update_egress_arming();
        }
    }

    maybe_idle_check();

    // Safety floor. With nothing permanently armed for OUT the worker
    // normally parks in srt_epoll_wait (up to POLLING_TIME) when idle, so
    // this rarely fires. It only guards the case where srt_epoll_wait
    // returns immediately with events that move no bytes (e.g. a
    // backpressured role's OUT flapping while its link is congested):
    // yield briefly instead of spinning. 2ms is far below any viewer's
    // TSBPD budget so playback is unaffected.
    if (handler_count == 0)
    {
        msleep(2);
    }
    return handler_count;
}

void CSLSGroup::idle_check()
{
    check_wait_http_role();
    check_reconnect_relay();
    check_invalid_sock();
    check_new_role();
}

void CSLSGroup::maybe_idle_check()
{
    // Housekeeping (relay reconnects, dead-socket cleanup + per-role
    // srt_getsockstate, new-role pickup, stats) is cheap per call but
    // not free: check_invalid_sock alone issues one libsrt syscall per
    // role, each taking libsrt's global control lock. The data loop can
    // spin thousands of times/sec while a publisher streams, so running
    // this every iteration starves libsrt's own send/recv/ACK threads
    // of that lock. Gating to POLLING_TIME restores the cadence the
    // pre-eventfd loop had (its unconditional trailing msleep paced the
    // whole loop to ~POLLING_TIME) without reintroducing that sleep on
    // the data path.
    int64_t now_ms = sls_gettime_ms();
    if (now_ms - m_last_idle_check_ms < IDLE_CHECK_INTERVAL)
        return;
    m_last_idle_check_ms = now_ms;
    idle_check();
}

void CSLSGroup::check_wait_http_role()
{
    std::list<CSLSRole *>::iterator it;
    std::list<CSLSRole *>::iterator it_erase;
    for (it = m_list_wait_http_role.begin(); it != m_list_wait_http_role.end();)
    {
        CSLSRole *role = *it;
        it_erase = it;
        it++;
        if (!role)
        {
            m_list_wait_http_role.erase(it_erase);
            continue;
        }
        if (SLS_ERROR == role->check_http_client())
        {
            spdlog::info("[{}] CSLSGroup::check_wait_http_role, worker_number={d}, delete {}={}.",
                         fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role));
            role->uninit();
            delete role;
            m_list_wait_http_role.erase(it_erase);
        }
        else
        {
            role->handler();
        }
    }
}

void CSLSGroup::check_reconnect_relay()
{
    int64_t cur_time_ms = sls_gettime_ms(); // m_cur_time_microsec;

    CSLSRelayManager *relay_manager = NULL;
    std::list<CSLSRelayManager *>::iterator it_erase;
    std::list<CSLSRelayManager *>::iterator it;
    for (it = m_list_reconnect_relay_manager.begin(); it != m_list_reconnect_relay_manager.end();)
    {
        CSLSRelayManager *relay_manager = *it;
        if (NULL == relay_manager)
        {
            spdlog::info("[{}] CSLSGroup::check_reconnect_relay, worker_number={:d}, remove invalid relay_manager.",
                         fmt::ptr(this), m_worker_number);
            it_erase = it;
            it++;
            m_list_reconnect_relay_manager.erase(it_erase);
            continue;
        }
        int ret = relay_manager->reconnect(cur_time_ms);
        if (SLS_OK != ret)
        {
            it++;
            continue;
        }
        it_erase = it;
        it++;
        m_list_reconnect_relay_manager.erase(it_erase);
    }
}

void CSLSGroup::check_invalid_sock()
{
    bool update_stat_info = false;
    int64_t cur_time_ms = sls_gettime_ms();
    int d = cur_time_ms - m_stat_post_last_tm_ms;
    if (d >= m_stat_post_interval * 1000)
    {
        update_stat_info = true;
        m_stat_info.clear();
        m_stat_post_last_tm_ms = cur_time_ms;
    }

    std::map<int, CSLSRole *>::iterator it;
    std::map<int, CSLSRole *>::iterator it_erase;
    for (it = m_map_role.begin(); it != m_map_role.end();)
    {
        CSLSRole *role = it->second;
        it_erase = it;
        it++;
        if (!role)
        {
            m_map_role.erase(it_erase);
            continue;
        }

        if (update_stat_info)
        {

            stat_info_t stat_info = role->get_stat_info();

            CSLSLock lock(&m_mutex_stat);
            m_stat_info.push_back(stat_info);
        }

        int state = role->get_state(cur_time_ms);
        if (SLS_RS_INVALID == state || SLS_RS_UNINIT == state)
        {
            spdlog::info("[{}] CSLSGroup::check_invalid_sock, worker_number={:d}, {}={}, invalid sock={:d}, state={:d}, role_map.size={:d}.",
                         fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role), role->get_fd(), state, m_map_role.size());
            // check relay
            if (role->is_reconnect())
            {
                CSLSRelay *relay = (CSLSRelay *)role;
                CSLSRelayManager *relay_manager = (CSLSRelayManager *)relay->get_relay_manager();
                m_list_reconnect_relay_manager.push_back(relay_manager);
                spdlog::info("[{}] CSLSGroup::check_invalid_sock, worker_number={:d}, {}={}, need reconnect.",
                             fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role));
            }

            role->uninit();
            if (SLS_OK == role->check_http_client())
            {
                m_list_wait_http_role.push_back(role);
                spdlog::info("[{}] CSLSGroup::check_invalid_sock, worker_number={:d}, {}={}, put into m_list_wait_http_role.",
                             fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role));
            }
            else
            {
                spdlog::info("[{}] CSLSGroup::check_invalid_sock, worker_number={:d}, {}={}, delete.",
                             fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role));
                delete role;
            }
            m_map_role.erase(it_erase);
            continue;
        }
    }
}

void CSLSGroup::clear()
{
    spdlog::info("[{}] CSLSGroup::clear, worker_number={:d}, role_map.size={:d}.",
                 fmt::ptr(this), m_worker_number, m_map_role.size());
    std::map<int, CSLSRole *>::iterator it;
    for (it = m_map_role.begin(); it != m_map_role.end(); it++)
    {
        CSLSRole *role = it->second;
        if (role)
        {
            spdlog::info("[{}] CSLSGroup::clear, worker_number={:d}, delete {}={}.",
                         fmt::ptr(this), m_worker_number, role->get_role_name(), fmt::ptr(role));
            role->uninit();
            delete role;
        }
    }
    m_map_role.clear();
}

void CSLSGroup::set_role_list(CSLSRoleList *list_role)
{
    m_list_role = list_role;
}

void CSLSGroup::set_worker_number(int n)
{
    m_worker_number = n;
}

void CSLSGroup::set_worker_connections(unsigned int n)
{
    m_worker_connections = n;
}

void CSLSGroup::set_stat_post_interval(int interval)
{
    m_stat_post_interval = interval;
}

void CSLSGroup::get_stat_info(vector<stat_info_t> &info)
{
    CSLSLock lock(&m_mutex_stat);
    info.insert(info.end(), m_stat_info.begin(), m_stat_info.end());
}
