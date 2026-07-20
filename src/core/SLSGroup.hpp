
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

#include <list>
#include <map>
#include <memory>

#include "SLSEpollThread.hpp"
#include "SLSRoleList.hpp"
#include "SLSRole.hpp"
#include "SLSMapRelay.hpp"

/**
 * CSLSGroup , group of players, publishers and listener
 */
class CSLSGroup final : public CSLSEpollThread
{
public:
    CSLSGroup();
    ~CSLSGroup() override;

    int start();
    int stop();
    void reload();

    void set_role_list(CSLSRoleList *list_role);
    void set_worker_connections(unsigned int n);
    void set_worker_number(int n);

    virtual int handler() override;

    void set_stat_post_interval(int interval);
    void get_stat_info(vector<stat_info_t> &info);

protected:
    virtual void clear() override;

private:
    CSLSRoleList *m_list_role;
    std::list<std::shared_ptr<CSLSRole>> m_list_wait_http_role;
    std::map<int, std::shared_ptr<CSLSRole>> m_map_role;
    std::list<CSLSRelayManager *> m_list_reconnect_relay_manager;

    void idle_check();
    // Runs idle_check() only if at least POLLING_TIME ms have elapsed
    // since the last run, so worker housekeeping keeps its original
    // ~POLLING_TIME cadence regardless of how hot the data loop spins.
    void maybe_idle_check();
    void check_reconnect_relay();
    void check_invalid_sock();
    void check_new_role();
    void reap_unadopted_backlog();
    void check_wait_http_role();

    unsigned int m_worker_connections;
    unsigned int m_worker_number;
    bool m_reload;

    int64_t m_stat_post_last_tm_ms;
    int m_stat_post_interval;
    // Wall-clock (ms) of the last idle_check() run. idle_check does
    // per-role libsrt syscalls (srt_getsockstate) plus role-list pops;
    // running it every worker iteration hammers libsrt's global control
    // lock at spin frequency. Gate it to POLLING_TIME cadence instead.
    int64_t m_last_idle_check_ms;
    CSLSMutex m_mutex_stat;
    std::vector<stat_info_t> m_stat_info;
};
