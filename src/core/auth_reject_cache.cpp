#include "auth_reject_cache.hpp"

#include <iterator>

// Hard ceiling on distinct cached entries. Mirrors MAX_PLAYER_KEY_CACHE_ENTRIES
// so a (peer-scoped) streamid-rotating flood cannot grow the map without bound.
static constexpr size_t MAX_AUTH_REJECT_ENTRIES = 50000;

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
    // Enforce the entry cap only when inserting a NEW key (refreshing an
    // existing one never grows the map). When full, evict the entry closest to
    // expiring so the freshest blocks survive — mirrors the player-key cache.
    if (m_blocked.find(streamid) == m_blocked.end() &&
        m_blocked.size() >= MAX_AUTH_REJECT_ENTRIES)
    {
        auto victim = m_blocked.begin();
        for (auto it = std::next(m_blocked.begin()); it != m_blocked.end(); ++it)
        {
            if (it->second < victim->second)
                victim = it;
        }
        if (victim != m_blocked.end())
            m_blocked.erase(victim);
    }
    m_blocked[streamid] = now + m_ttl;
}

size_t AuthRejectCache::size() const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_blocked.size();
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
