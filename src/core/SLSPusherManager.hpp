
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

#include <memory>
#include <vector>
#include <string>

#include "SLSRelayManager.hpp"
#include "SLSLock.hpp"
#include "conf.hpp"

/**
 * CSLSPusherManager
 */
class CSLSPusherManager final : public CSLSRelayManager
{
public:
    CSLSPusherManager();
    virtual ~CSLSPusherManager() override;

    virtual int start() override;
    virtual int add_reconnect_stream(char *relay_url) override;
    virtual int reconnect(int64_t cur_tm_ms) override;

    // Detach + kick every live child pusher this manager spawned, so an
    // orphaned pusher can never deref this manager after the publisher frees
    // it (UAF). Must run BEFORE delete. Cross-thread safe: per-relay atomics
    // under m_child_relays_mutex only (never m_rwclock) => no lock-order edge.
    void detach_child_relays();

private:
    int connect_all();
    virtual CSLSRelay *create_relay() override;
    virtual int set_relay_param(std::shared_ptr<CSLSRelay> relay) override;
    int check_relay_param();
    int reconnect_all(int64_t cur_tm_ms, bool no_publisher);

    CSLSRWLock m_rwclock;
    std::map<std::string, int64_t> m_map_reconnect_relay; //relay:timeout

    // Weak handles to the child pushers spawned via set_relay_param(). Weak so
    // tracking never extends a pusher's lifetime; the owning worker's role map
    // remains the sole owner. Guarded by its OWN mutex (NOT m_rwclock) so the
    // detach path cannot deadlock/invert against reconnect_all(), which holds
    // m_rwclock while it calls connect()->set_relay_param().
    std::vector<std::weak_ptr<CSLSRelay>> m_child_relays;
    CSLSMutex m_child_relays_mutex;
};
