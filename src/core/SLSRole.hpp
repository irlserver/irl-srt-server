
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
#include <vector>
#include <sys/socket.h>

#include "SLSRole.hpp"
#include "SLSSrt.hpp"
#include "SLSMapData.hpp"
#include "conf.hpp"
#include "SLSLock.hpp"
#include "common.hpp"
#include "AsyncHttpClient.hpp"
#include <future>
#include <memory>
#include <atomic>
#include "SLSBitrateLimit.hpp"

class AuthRejectCache;

enum SLS_ROLE_STATE
{
    SLS_RS_UNINIT = 0,
    SLS_RS_INITED = 1,
    SLS_RS_INVALID = 2,
};

// Per-role egress staging buffer, in bytes. Each handler_write_data
// call drains up to this much from the publisher ring and then issues
// one srt_sendmsg per TS_UDP_LEN chunk in a tight loop. 100 packets
// (~131 KB) was historical: it produced fairness problems (one slow
// viewer monopolised the worker for 100 sendmsg calls before yielding)
// and made a single epoll wake routinely overshoot the SRT send-buffer
// budget of a low-latency viewer, triggering EASYNCSND. 16 packets
// (~21 KB) is roughly the per-cycle drain budget at common bitrates
// and lets epoll re-arm sooner across roles. Net memory saved on a
// 100-viewer node is ~11 MB (was ~13 MB of static role buffer space).
const int DATA_BUFF_SIZE = 16 * 1316;
const int UNLIMITED_TIMEOUT = -1;

// Max publisher-ring batches drained per handler_write_data() call.
// Egress is driven by the worker's periodic pass (players are no longer
// permanently armed for SRT_EPOLL_OUT), so without an inner drain loop
// throughput would be capped at one DATA_BUFF_SIZE per worker wakeup.
// 8 * DATA_BUFF_SIZE (~168 KB) per call lets a catching-up viewer pull a
// large backlog quickly while still bounding how long one role holds the
// worker before it yields to the publisher read and the other roles.
const int MAX_EGRESS_BATCHES = 8;
/**
 * CSLSRole , the base of player, publisher and listener
 */
class CSLSRole
{
public:
    CSLSRole();
    virtual ~CSLSRole();

    virtual int init();
    virtual int uninit();
    virtual int handler();
    // Periodic hook run by the worker on every role in its map once per loop
    // pass (~POLLING_TIME), independent of socket events. Default no-op;
    // CSLSListener overrides it to advance work that must progress without a
    // new connection event (draining async player-key validations and
    // completing deferred player accepts). Runs on the owning worker thread.
    virtual void on_worker_tick() {}

    int open(char *url);
    int close();

    int get_fd();
    int set_eid(int eid);
    bool is_write() { return m_is_write; };

    int set_srt(CSLSSrt *srt);
    int invalid_srt();

    int write(const char *buf, int size);

    int add_to_epoll(int eid);
    int remove_from_epoll();
    // Reconcile this writable role's SRT_EPOLL_OUT arm state with whether
    // it still has staged egress data it could not fully send. Called by
    // the worker after each egress attempt: arms OUT while backpressured
    // (so the worker wakes when the send buffer drains) and disarms once
    // caught up (so an idle writable socket does not busy-return). No-op
    // for read roles. Only issues a syscall on an actual state change.
    void update_egress_arming();
    int get_state(int64_t cur_time_microsec = 0);
    int get_sock_state();
    char *get_role_name();
    // Creation timestamp (ms), stamped once at construction and never updated.
    // Used to reap roles that sit un-adopted in the worker handoff list.
    int64_t get_stat_start_time() { return m_stat_start_time; }

    // Ask the owning worker to tear this role down on its next state check.
    // Safe to call from another thread (the listener uses it for publisher
    // takeover): it only flips an atomic flag. The actual invalid_srt() and
    // map cleanup still run on the worker that owns the SRT socket, via
    // get_state(), so we never race a concurrent handler() on the same socket.
    void request_kick();

    void set_conf(sls_conf_base_t *conf);
    void set_map_data(const char *map_key, CSLSMapData *map_data);

    void set_idle_streams_timeout(int timeout);
    // Probation deadline (ms) for a receiving role that has not yet delivered
    // any media. 0 disables it. Set by the listener only on accept-path
    // publishers; players/pullers never receive on the ingest socket, so they
    // are left at 0.
    void set_first_data_timeout(int timeout_ms);
    bool check_idle_streams_duration(int64_t cur_time_ms = 0);

    // True if this role has read media within `within_ms` of `now_ms`. The
    // listener calls this cross-thread at takeover to tell a live incumbent
    // publisher (keep it) from a flapped/zombie one (evict it). Reads an
    // atomic; never blocks and never touches the socket.
    bool has_recent_recv_data(int64_t now_ms, int64_t within_ms) const;

    // Whether an actively-delivering incumbent of this role type should be
    // shielded from publisher takeover. Only a real external broadcaster
    // (CSLSPublisher) is: a puller/relay incumbent must stay evictable so a
    // local publisher can take over a pulled stream (origin/edge promotion).
    virtual bool is_takeover_protected() const { return false; }

    char *get_streamid();
    // Override the cached streamid so that webhook / stats reporting can see
    // the value derived after server-side processing (e.g. the stream a player
    // was resolved to via player_key_auth_url), instead of the raw value the
    // client set on SRTO_STREAMID.
    void set_streamid(const char *sid);
    bool is_reconnect();
    char *get_map_data_key();

    void set_stat_info_base(stat_info_t &v);
    virtual stat_info_t get_stat_info();

    void update_stat_info();
    virtual int get_peer_info(char *peer_name, int &peer_port);

    void set_http_url(const char *http_url);
    // Inject the shared negative-auth cache. Only publisher roles receive a
    // non-null cache; check_http_passed records a failed key here so the
    // listener callback can reject its repeats at the next handshake.
    void set_auth_reject_cache(std::shared_ptr<AuthRejectCache> cache);
    int on_connect();
    int on_close();
    // Push destinations harvested from the publish-auth webhook response.
    // Populated by check_http_passed; consumed by the listener handler to
    // spin up a dynamic CSLSPusherManager per publisher.
    const std::vector<std::string> &get_push_urls() const { return m_push_urls; }
    int get_statistics(SRT_TRACEBSTATS *currentStats, int clear);
    int get_bitrate();
    int get_uptime();
    int get_latency() { return m_latency; }
    void set_latency(int latency) { m_latency = latency; }
    bool get_audio_gap_stats(CSLSMapData::AudioGapStreamStats &stats, int clear = 0) const;
    // Cumulative overrun count for this publisher's ring buffer. Each
    // overrun means a subscriber fell so far behind the writer that the
    // ring lapped them — visible to viewers as a delivery hiccup that
    // "fixes itself" on subscriber reconnect. Returns -1 if not bound to
    // a map_data key.
    int64_t get_ring_overrun_count() const;

    // Count of times handler_write_data() hit SRT send-buffer
    // backpressure (errno EASYNCSND) on this role. Each event means a
    // viewer egress write was deferred to the next epoll cycle rather
    // than killing the connection. Surfaced via /stats so operators can
    // see when viewers are falling behind.
    uint64_t get_send_backpressure_count() const
    {
        return m_send_backpressure_count.load(std::memory_order_relaxed);
    }
    int check_http_client();
    int check_http_passed();

    // Bitrate limiting methods
    int init_bitrate_limiter(int max_bitrate_kbps, int violation_timeout_seconds = 30, float spike_tolerance = 2.0f);
    void cleanup_bitrate_limiter();
    CSLSBitrateLimit::BitrateStats get_bitrate_stats() const;
    virtual void on_map_data_set();
    virtual bool is_audio_gap_fill_enabled() const;

protected:
    CSLSSrt *m_srt;
    bool m_is_write;                //listener: 0, publisher: 0, player: 1
    int64_t      m_stat_start_time;
    int64_t m_invalid_begin_tm;     //
    int64_t m_stat_bitrate_last_tm; //
    int m_stat_bitrate_interval;    //ms
    int64_t m_stat_bitrate_datacount;
    int m_kbitrate;             //kb
    int m_idle_streams_timeout; //unit: s, -1: unlimited
    // Probation window (ms) before a publisher that has never delivered media
    // is reaped. 0 = disabled. Only set on accept-path publishers.
    int m_first_data_timeout_ms{0};
    // Wall clock (sls_gettime_ms) of the most recent successful media read, or
    // 0 if this role has never received data. Written on the owning worker in
    // handler_read_data; read cross-thread by the listener at takeover, hence
    // atomic. Relaxed ordering is sufficient: we only need a recent-enough
    // snapshot to tell a delivering publisher from a silent one, not a
    // happens-before against any other state.
    std::atomic<int64_t> m_last_recv_data_tm{0};
    int m_latency;              //ms

    int m_state;
    // Cross-thread teardown request set by request_kick(). Observed by
    // get_state() on the owning worker. Atomic so the listener thread can
    // signal a takeover without locking the socket hot path.
    std::atomic<bool> m_kick_requested{false};
    int m_back_log; //maximum number of connections at the same time
    int m_port;
    char m_peer_ip[IP_MAX_LEN];
    int m_peer_port;
    char m_role_name[STR_MAX_LEN];
    char m_streamid[URL_MAX_LEN];
    char m_http_url[URL_MAX_LEN];
    // Auth gate written by set_http_url() (false) on the listener-owning
    // worker and by check_http_passed() (true) / read by on_close() on the
    // role-owning worker — a different OS thread in multi-worker mode. Atomic
    // (release/acquire) makes the transition well-defined without a lock on
    // the handler_read/write_data hot path.
    std::atomic<bool> m_http_passed{true};

    sls_conf_base_t *m_conf;
    CSLSMapData *m_map_data;
    char m_map_data_key[URL_MAX_LEN];
    SLSRecycleArrayID m_map_data_id;
    // Set once when this role's publisher ring is allocated in m_map_data.
    // Publishers allocate lazily on the first authorized data packet (see
    // handler_read_data) rather than at accept, so an unauthenticated or
    // never-sending connection cannot pin a multi-megabyte ring (pre-auth
    // OOM). Relays add their ring eagerly at connect; for them the lazy add
    // is an idempotent no-op that simply flips this flag.
    //
    // Flipped in handler_read_data() and read in on_map_data_set(), both on
    // the role-owning worker; also read on the listener-owning worker via the
    // accept-time on_map_data_set(). Atomic (release/acquire) keeps the lazy
    // flag well-defined across that worker boundary without a lock; the
    // lazy-allocation behaviour is unchanged.
    std::atomic<bool> m_ring_added{false};

    char m_data[DATA_BUFF_SIZE];
    // Worker-confined egress cursor: written and read only by the owning
    // worker (handler_write_data / update_egress_arming), never by the
    // stats/HTTP thread. Plain int — no cross-thread access to race, and
    // keeping it off the atomic path avoids cost on the write hot loop.
    int m_data_len;
    int m_data_pos;
    // Relay reconnect flag. Set once at construction on the building thread
    // (listener/manager or a worker), read on the owning worker via
    // is_reconnect() in CSLSGroup::check_invalid_sock — writer and reader are
    // distinct threads. Atomic (relaxed; advisory, set before publication) to
    // keep that cross-thread access explicit and TSan-clean, matching the
    // file's other relay flags (m_kick_requested, m_relay_manager).
    std::atomic<bool> m_need_reconnect{false};

    // Incremented every time srt_sendmsg returns EASYNCSND on this
    // role's egress write. Read concurrently by the stats HTTP server,
    // hence atomic. Relaxed ordering is sufficient: we only care about
    // monotonic growth for operator dashboards, not happens-before
    // against any other state.
    std::atomic<uint64_t> m_send_backpressure_count{0};

    // Wall-clock (sls_gettime_ms) of the first EASYNCSND-with-no-progress
    // event in the current stuck streak. Cleared back to 0 on any
    // successful write byte. handler_write_data uses this to break out
    // of a permanently-backpressured viewer (link too slow for the
    // stream) instead of holding their publisher-ring read position
    // open indefinitely.
    int64_t m_backpressure_stuck_since_ms{0};

    // Whether SRT_EPOLL_OUT is currently armed on this writable role's
    // socket. Writable roles register ERR-only (see libsrt_add_to_epoll);
    // OUT is toggled on demand by update_egress_arming() so we only pay
    // the srt_epoll_update_usock syscall when the backpressure state
    // actually flips. Touched only from the owning worker thread.
    bool m_epoll_out_armed{false};
    // Arms/disarms SRT_EPOLL_OUT, updating m_epoll_out_armed. Returns
    // early without a syscall when already in the requested state.
    int set_epoll_out(bool enable);

    // Floor below which the stuck-viewer timeout will never drop. Even
    // at very low negotiated latency (e.g. 20ms), 500ms gives genuine
    // network blips room to recover before we kick. Independent of any
    // single SRT cycle.
    static constexpr int64_t kBackpressureStuckFloorMs = 500;

    // Multiplier applied to the role's negotiated SRT latency to derive
    // the stuck-viewer kick threshold. With TLPKTDROP on, once we have
    // been stuck for `latency_ms` the SLS sender is already dropping
    // packets internally (their TSBPD time has expired) — the viewer
    // is missing content. We allow three full latency cycles past that
    // point before deciding the link is permanently broken; below that
    // we would risk killing viewers on a single bad 1-RTT spike.
    static constexpr int64_t kBackpressureStuckLatencyMultiple = 3;

    // Per-role stuck-viewer kick threshold (ms). Scales with the
    // negotiated SRT latency so a 200ms-latency viewer is kicked at
    // 600ms of pure backpressure, while a 4000ms-latency viewer gets
    // 12000ms before the kick fires. Floor at kBackpressureStuckFloorMs
    // so we never kick on sub-millisecond noise.
    int64_t backpressure_stuck_timeout_ms() const
    {
        int64_t scaled = (int64_t)m_latency * kBackpressureStuckLatencyMultiple;
        return scaled > kBackpressureStuckFloorMs ? scaled : kBackpressureStuckFloorMs;
    }
    stat_info_t m_stat_info_base;
    std::shared_ptr<std::shared_future<AsyncHttpResponse>> m_http_future;

    // Bitrate limiting
    CSLSBitrateLimit *m_bitrate_limiter;

    // Push destinations from publish-auth webhook (publisher roles only).
    std::vector<std::string> m_push_urls;
    // Vetted destination address per m_push_urls entry, index-aligned. The
    // pusher dials this checked IP rather than re-resolving (DNS-rebinding SSRF).
    std::vector<sockaddr_storage> m_push_vetted_addrs;

    // Shared negative-auth cache (publisher roles only; null otherwise).
    std::shared_ptr<AuthRejectCache> m_auth_reject_cache;

    int handler_write_data();
    int handler_read_data(int64_t *last_read_time = NULL);

private:
};
