#pragma once

#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>

// Process-wide negative cache of publisher streamids that recently failed
// webhook authorization. The listener thread reads it inside the SRT
// handshake callback (is_blocked), and worker threads write it on auth
// failure (record_failure). This turns a streamid-rotating attacker's
// repeat attempts on the same bad key into cheap handshake rejections
// instead of a full accept plus on_event_url webhook lookup each time.
//
// One instance is owned by CSLSManager and injected into the publisher
// listeners and the roles they create (dependency injection, no global
// singleton). Stored as a shared_ptr by every holder so the cache outlives
// any listener socket whose handshake callback still references it.
class AuthRejectCache
{
public:
    explicit AuthRejectCache(time_t ttl_seconds = 30) : m_ttl(ttl_seconds > 0 ? ttl_seconds : 30) {}

    // TTL in seconds. Non-positive values are ignored so a missing config
    // key (zeroed conf block) keeps the constructor default.
    void set_ttl(time_t ttl_seconds);

    // Block this streamid for the configured TTL. Sweeps expired entries on
    // the way in, so the map stays bounded by the failure rate within one
    // TTL window even under a rotating-key flood.
    void record_failure(const std::string &streamid);

    // True if the streamid is currently blocked. Read-only and const: an
    // expired entry is treated as not blocked (lazy expiry) without
    // mutating the map, so the latency-sensitive handshake path never has
    // to sweep or take a write lock's worth of work.
    bool is_blocked(const std::string &streamid) const;

    // Drop expired entries. record_failure already sweeps on insert; this
    // is exposed for an explicit periodic call if one is ever wired in.
    void cleanup();

private:
    mutable std::mutex m_mtx;
    std::unordered_map<std::string, time_t> m_blocked; // streamid -> expiry (epoch seconds)
    time_t m_ttl;
    // Wall-clock second of the last full sweep. record_failure only sweeps
    // once per second instead of on every insert, so a streamid-rotating
    // flood that fails auth thousands of times a second pays an O(n) scan at
    // most once per second rather than once per failure. Lazy expiry on read
    // (is_blocked) keeps correctness independent of sweep cadence.
    time_t m_last_sweep = 0;
};
