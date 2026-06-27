
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

#include <map>
#include <string>

#include "SLSRole.hpp"
#include "SLSRoleList.hpp"
#include "SLSPublisher.hpp"
#include "conf.hpp"
#include "SLSRecycleArray.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSMapRelay.hpp"
#include "SLSSrt.hpp"
#include "AsyncHttpClient.hpp"
#include <map>
#include <chrono>
#include <regex>
#include <deque>
#include <mutex>
#include <future>

/**
 * server conf
 */
SLS_CONF_DYNAMIC_DECLARE_BEGIN(server)
char domain_player[URL_MAX_LEN];
char domain_publisher[URL_MAX_LEN];
int listen;
// Port specs: a single port ("4001"), a comma list ("4001,4011"), or
// inclusive ranges ("5000-5005"), or any mix. Expanded into one listener
// per port by CSLSManager. Stored as the raw string so the spec survives
// the memset-zeroed POD conf block (no std::containers allowed here).
char listen_publisher[SHORT_STR_MAX_LEN];
char listen_publisher_srtla[SHORT_STR_MAX_LEN];
char listen_player[SHORT_STR_MAX_LEN];
int backlog;
int latency_min;
int latency_max;
int idle_streams_timeout;       // unit s; -1: unlimited
int publisher_first_data_grace; // ms added on top of negotiated latency before a silent new publisher is reaped;
                                // 0=default(3000), -1=disabled
char on_event_url[URL_MAX_LEN];
char player_key_auth_url[URL_MAX_LEN];
int player_key_auth_timeout;
int player_key_cache_duration;
int player_key_rate_limit_requests;
int player_key_rate_limit_window;
int player_key_max_length;
int player_key_min_length;
char default_sid[STR_MAX_LEN];
char srt_passphrase[80];
int srt_pbkeylen;
int peer_idle_timeout;     // SRTO_PEERIDLETIMEO (ms) applied to accepted sockets; 0 = libsrt/fork default
int auth_reject_cache_ttl; // negative-auth-cache TTL (seconds); 0 = default 30
SLS_CONF_DYNAMIC_DECLARE_END

/**
 * sls_conf_server_t
 */
SLS_CONF_CMD_DYNAMIC_DECLARE_BEGIN(server)
SLS_SET_CONF(server, string, domain_player, "play domain", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, string, domain_publisher, "", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, int, listen, "listen port (legacy, use listen_publisher/listen_player)", 1, 65535),
    SLS_SET_CONF(server, portlist, listen_publisher,
                 "publisher listen port(s) (direct SRT); comma list and a-b ranges allowed", 1, SHORT_STR_MAX_LEN - 1),
    SLS_SET_CONF(server, portlist, listen_publisher_srtla,
                 "publisher listen port(s) for SRTLA/bonded connections; comma list and a-b ranges allowed", 1,
                 SHORT_STR_MAX_LEN - 1),
    SLS_SET_CONF(server, portlist, listen_player, "player listen port(s); comma list and a-b ranges allowed", 1,
                 SHORT_STR_MAX_LEN - 1),
    SLS_SET_CONF(server, int, backlog, "how many sockets may be allowed to wait until they are accepted", 1, 1024),
    SLS_SET_CONF(server, int, latency_min,
                 "minimum allowed latency (ms) - enforced on both publisher and player listeners via SRTO_LATENCY "
                 "handshake floor",
                 0, 5000),
    SLS_SET_CONF(server, int, latency_max, "maximum allowed latency (ms) - enforced on all connections", 0, 10000),
    SLS_SET_CONF(server, int, idle_streams_timeout, "players idle timeout when no publisher", -1, 86400),
    SLS_SET_CONF(server, int, publisher_first_data_grace,
                 "ms added on top of a new publisher's negotiated SRT latency to form the deadline by which it must "
                 "deliver its first media packet or be reaped (0 = default 3000ms, -1 = disabled)",
                 -1, 60000),
    SLS_SET_CONF(server, string, on_event_url, "on connect/close http url", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, string, player_key_auth_url, "player key authentication API endpoint", 1, URL_MAX_LEN - 1),
    SLS_SET_CONF(server, int, player_key_auth_timeout, "player key authentication timeout (ms)", 1, 30000),
    SLS_SET_CONF(server, int, player_key_cache_duration, "player key cache duration (ms)", 1, 300000),
    SLS_SET_CONF(server, int, player_key_rate_limit_requests,
                 "max player key requests per IP per window (-1=unlimited)", -1, 1000),
    SLS_SET_CONF(server, int, player_key_rate_limit_window, "rate limit time window (ms)", 1000, 3600000),
    SLS_SET_CONF(server, int, player_key_max_length, "maximum player key length", 1, 256),
    SLS_SET_CONF(server, int, player_key_min_length, "minimum player key length", 1, 64),
    SLS_SET_CONF(server, string, default_sid, "default sid to use when no streamid is given", 1, STR_MAX_LEN - 1),
    SLS_SET_CONF(server, string, srt_passphrase, "listener-wide SRT passphrase (10-79 bytes; empty = no encryption)", 0,
                 79),
    SLS_SET_CONF(server, int, srt_pbkeylen, "SRT key length: 0/16/24/32 (0 = libsrt default)", 0, 32),
    SLS_SET_CONF(server, int, peer_idle_timeout,
                 "SRTO_PEERIDLETIMEO (ms) for accepted sockets; reaps dead publishers faster (0 = libsrt/fork default)",
                 0, 60000),
    SLS_SET_CONF(
        server, int, auth_reject_cache_ttl,
        "negative auth cache TTL in seconds; rejects recently-failed publisher keys at the handshake (0 = default 30)",
        0, 3600),
    SLS_CONF_CMD_DYNAMIC_DECLARE_END

    /**
     * SLSListener
     */
    class CSLSListener final : public CSLSRole
{
public:
    CSLSListener();
    ~CSLSListener() override;

    int init() override;
    int uninit() override;

    virtual int start();
    virtual int stop();

    virtual int handler() override;
    virtual void on_worker_tick() override;

    void set_role_list(CSLSRoleList *list_role);
    void set_map_publisher(CSLSMapPublisher *publisher);
    void set_map_puller(CSLSMapRelay *map_puller);
    void set_map_pusher(CSLSMapRelay *map_puller);
    void set_listener_type(bool is_publisher);
    void set_srtla_mode(bool is_srtla);
    void set_legacy_mode(bool is_legacy);
    // Bind this listener to an explicit port instead of deriving it from the
    // conf block. CSLSManager uses this to expand a multi-port spec into one
    // listener per port.
    void set_port_override(int port);
    bool should_handle_app(const std::string &app_name, bool is_publisher_connection);

    virtual stat_info_t get_stat_info() override;

protected:
    // Returns SLS_OK (resolved from cache), SLS_ERROR (hard reject: bad
    // format, rate limited, or a cached negative result), or SLS_PENDING (no
    // cached result yet; an async webhook validation has been kicked off and
    // this connection should be rejected so the client's reconnect can hit the
    // now-populated cache). Never blocks the worker on the network.
    int validate_player_key(const char *player_key, char *resolved_stream_id, size_t resolved_stream_id_size,
                            const char *client_ip = nullptr);
    bool is_rate_limited(const char *client_ip);
    bool validate_player_key_format(const char *player_key);
    void cleanup_expired_rate_limits();
    void update_rate_limit(const char *client_ip);
    // Kick a webhook validation for an uncached key into the AsyncHttpClient
    // pool (deduplicated and capped) without waiting for it. Worker-only.
    void start_player_key_validation(const std::string &key, const char *client_ip);
    // Turn a completed webhook response into a positive/negative cache entry.
    void process_player_key_response(const std::string &key, const AsyncHttpResponse &response);
    // Poll in-flight validations; fold any that have completed into the cache.
    // Called at the top of handler() so a reconnect sees the prior attempt's
    // result. Worker-only.
    void drain_player_key_validations();

private:
    CSLSRoleList *m_list_role;
    CSLSMapPublisher *m_map_publisher;
    CSLSMapRelay *m_map_puller;
    CSLSMapRelay *m_map_pusher;
    bool m_is_publisher_listener;
    bool m_is_srtla_listener;
    bool m_is_legacy_listener;
    int m_port_override; // >0: bind this explicit port (set by CSLSManager)

    CSLSMutex m_mutex;

    int m_idle_streams_timeout_role;
    // Probation grace (ms) handed to each accepted publisher: added on top of
    // its negotiated SRT receive latency to form the deadline by which it must
    // deliver a media packet or be reaped. The latency term matters because
    // SRT's TSBPD holds the first packet for the full receive-latency window,
    // so a legitimate high-latency encoder surfaces its first byte only after
    // that window. Stops a player/preview pointed at the ingest port from
    // squatting (or, with the takeover guard, repeatedly evicting) a real
    // broadcaster's key. 0 = disabled.
    int m_publisher_first_data_grace_role;
    stat_info_t m_stat_info;
    char m_default_sid[1024];
    char m_http_url_role[URL_MAX_LEN];
    char m_player_key_auth_url[URL_MAX_LEN];

    // Configuration for player key validation
    std::vector<std::string> m_domain_players;
    std::string m_domain_publisher;
    std::vector<std::string> m_app_players;

    // Player key cache structure
    struct PlayerKeyCacheEntry
    {
        std::string resolved_stream_id = "";
        std::chrono::steady_clock::time_point expiry_time{};
        bool is_valid = false;                 // true for successful validation, false for failed validation
        bool has_max_players_override = false; // true if the API provided a per-key override
        int max_players_per_stream_override =
            -1; // override value (-1 = unlimited). Ignored if has_max_players_override is false
    };
    std::map<std::string, PlayerKeyCacheEntry> m_player_key_cache;
    std::mutex m_cache_mutex;
    // Last time expired entries were swept from m_player_key_cache. The cache
    // is otherwise only pruned lazily when the same key is looked up again, so
    // a flood of distinct never-recurring keys would leak entries until their
    // TTL without this periodic sweep. Guarded by m_cache_mutex.
    std::chrono::steady_clock::time_point m_last_player_key_cache_sweep{};
    // Insert with eviction, assumes m_cache_mutex is already held. Drops
    // expired entries first, then (if still at the hard cap) the soonest-to-
    // expire entry, so the map can never grow without bound under a rotating-
    // key flood while freshly validated hot entries are preserved.
    void insert_player_key_cache_locked(const std::string &key, const PlayerKeyCacheEntry &entry);
    // Time-gated sweep of expired player-key cache entries. Cheap no-op when
    // called more than once within the sweep interval.
    void sweep_player_key_cache();
    // In-flight player-key webhook validations, keyed by player key. The
    // owning worker owns these futures (the pool runs the request), so there
    // is no detached cross-thread access to this listener. Worker-thread-only.
    std::map<std::string, std::shared_future<AsyncHttpResponse>> m_pending_player_key_validations;

    // A player connection accepted at the SRT layer but held while its
    // player-key webhook is still in flight (deferred accept). The socket
    // stays open so a one-shot client (VLC, ffplay) that does not reconnect
    // still gets in: once the validation resolves the worker completes the
    // accept, or closes the socket on rejection/timeout. Worker-thread-only.
    struct PendingPlayerConnection
    {
        CSLSSrt *srt = nullptr;
        std::string app_uplive; // publisher uplive for the player's app (from the original sid)
        std::string player_key; // key being validated; also the cache lookup key
        std::string session_id;
        std::string peer_name;
        int peer_port = 0;
        int final_latency = 0;
        std::string cur_time;
        std::chrono::steady_clock::time_point deadline{};
    };
    std::vector<PendingPlayerConnection> m_pending_player_connections;
    // Complete a player accept once the (possibly player-key-resolved) stream
    // is known. Shared by the synchronous accept path and the deferred path.
    // Takes ownership of `srt`: on every return the socket has either been
    // handed to a pushed CSLSPlayer or been closed and deleted. Returns 1.
    int finish_player_accept(CSLSSrt *srt, const std::string &app_uplive, const std::string &stream_name,
                             const std::string &effective_sid, const std::string &player_key,
                             bool player_key_validation_required, const char *peer_name, int peer_port,
                             int final_latency, const std::string &session_id, const std::string &cur_time);
    // Advance held connections: finish those whose validation resolved valid,
    // close those rejected or past their deadline. Worker-tick driven.
    void drive_pending_player_connections();

    // Rate limiting structure
    struct RateLimitEntry
    {
        std::deque<std::chrono::steady_clock::time_point> request_times;
    };
    std::map<std::string, RateLimitEntry> m_rate_limit_map;
    // Throttles cleanup_expired_rate_limits so the full-map scan runs at most
    // once per second instead of on every player accept.
    std::chrono::steady_clock::time_point m_last_rate_limit_cleanup{};

    // Per-stream player limit override structure
    struct StreamPlayerLimitEntry
    {
        bool has_override = false;
        int max_players_per_stream = 0;
        std::chrono::steady_clock::time_point expiry_time{};
    };
    std::map<std::string, StreamPlayerLimitEntry> m_stream_player_limit_map;
    void cleanupExpiredStreamOverrides();

    // Security configuration
    int m_player_key_auth_timeout;
    int m_player_key_cache_duration;
    int m_player_key_rate_limit_requests;
    int m_player_key_rate_limit_window;
    int m_player_key_max_length;
    int m_player_key_min_length;
    std::regex m_player_key_regex;

    int init_conf_app();
};
