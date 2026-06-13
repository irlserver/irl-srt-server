#include "auth_reject_cache.hpp"

void AuthRejectCache::set_ttl(time_t ttl_seconds)
{
    if (ttl_seconds <= 0)
        return;
    std::lock_guard<std::mutex> lk(m_mtx);
    m_ttl = ttl_seconds;
}

void AuthRejectCache::record_failure(const std::string &streamid)
{
    if (streamid.empty())
        return;
    time_t now = time(nullptr);
    std::lock_guard<std::mutex> lk(m_mtx);
    // Time-gate the sweep to at most once per second so a high-rate failure
    // flood does not turn every insert into an O(n) scan of the map.
    if (now != m_last_sweep)
    {
        for (auto it = m_blocked.begin(); it != m_blocked.end();)
        {
            if (it->second <= now)
                it = m_blocked.erase(it);
            else
                ++it;
        }
        m_last_sweep = now;
    }
    m_blocked[streamid] = now + m_ttl;
}

bool AuthRejectCache::is_blocked(const std::string &streamid) const
{
    if (streamid.empty())
        return false;
    time_t now = time(nullptr);
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_blocked.find(streamid);
    return it != m_blocked.end() && it->second > now;
}

void AuthRejectCache::cleanup()
{
    time_t now = time(nullptr);
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto it = m_blocked.begin(); it != m_blocked.end();)
    {
        if (it->second <= now)
            it = m_blocked.erase(it);
        else
            ++it;
    }
}
