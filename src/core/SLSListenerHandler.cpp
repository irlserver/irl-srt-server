#include "SLSListener.hpp"
#include "SLSPlayer.hpp"
#include "SLSPublisher.hpp"
#include "SLSMapPublisher.hpp"
#include "SLSMapRelay.hpp"
#include "SLSSrt.hpp"
#include "util.hpp"
#include "SLSLog.hpp"
#include "SLSLogCategory.hpp"
#include "SLSSessionTracker.hpp"
#include "spdlog/spdlog.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <chrono>
#include <vector>

namespace {
// Hard ceiling on the shared handoff list (roles accepted by a listener but
// not yet picked up by a worker). Under normal operation workers drain this
// to near-zero; it only backs up when accepts outpace the workers, i.e. a
// connection flood. Refusing new accepts past this keeps the list (and the
// live role/object count it feeds) bounded. Generous so it never trips under
// legitimate load.
constexpr int MAX_HANDOFF_BACKLOG = 4096;
// Hard ceiling on player connections held open awaiting their async
// player-key validation (deferred accept). Bounds the open SRT sockets a
// flood of uncached keys can park; past it, a new uncached connection is
// refused outright instead of held.
constexpr size_t MAX_PENDING_PLAYER_CONNECTIONS = 1024;

// At publisher takeover, an incumbent that delivered a media packet within this
// window counts as actively streaming and is NOT evicted by a new connection
// for the same key — the newcomer is refused instead. This stops a player or
// preview pointed at the ingest port from grey-screening a live broadcaster.
// Kept short: a genuine encoder reconnect (SRTLA/SRT session reset) only lands
// after the old session stopped delivering for at least a detect + handshake
// cycle, which exceeds this window, so flap recovery (kick the stale incumbent)
// still works. A continuously delivering TS publisher refreshes its marker every
// few ms, so it always reads as active here.
constexpr int64_t ACTIVE_INCUMBENT_RECV_WINDOW_MS = 1000;

// IP-ACL match outcome shared between the publisher and player ACL paths.
enum class AclMatch { ACCEPT, DENY, NO_MATCH };

// Evaluate the configured ACL entries against a peer (IPv4 or IPv6).
//
// Entries are family-tagged (sls_ip_family). A WILDCARD entry ("all") matches
// any peer; a V4 entry matches only an IPv4 peer with the same host-order
// address (unchanged from the original IPv4-only path); a V6 entry matches
// only an IPv6 peer with the same 128-bit address. IPv4 clients arriving on
// the dual-stack listener as ::ffff:a.b.c.d are normalised to IPv4 upstream
// (libsrt_getpeeraddr_raw), so they are matched by V4 entries here. On no
// match the caller applies its documented default (accept by default).
AclMatch sls_check_ip_acl(const std::vector<sls_ip_access_t> &entries,
                          unsigned long peer_addr_v4,
                          const struct in6_addr &peer_addr_v6,
                          bool peer_is_ipv6,
                          const void *log_tag,
                          const char *peer_name,
                          int peer_port,
                          const char *app_name)
{
    for (const sls_ip_access_t &acl_entry : entries) {
        bool matched = false;
        switch (acl_entry.family) {
        case sls_ip_family::WILDCARD:
            matched = true;
            break;
        case sls_ip_family::V4:
            matched = (!peer_is_ipv6 && acl_entry.ip_address == peer_addr_v4);
            break;
        case sls_ip_family::V6:
            matched = (peer_is_ipv6 &&
                       memcmp(&acl_entry.ip_address6, &peer_addr_v6,
                              sizeof(struct in6_addr)) == 0);
            break;
        }
        if (!matched) continue;
        switch (acl_entry.action) {
        case sls_access_action::ACCEPT:
            spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}'",
                         log_tag, peer_name, peer_port, app_name);
            return AclMatch::ACCEPT;
        case sls_access_action::DENY:
            spdlog::warn("[{}] CSLSListener::handler Rejected connection from {}:{:d} for app '{}'",
                         log_tag, peer_name, peer_port, app_name);
            return AclMatch::DENY;
        default:
            spdlog::error("[{}] CSLSListener::handler Unknown action [sls_access_action={:d}], ignoring",
                          log_tag, (int)acl_entry.action);
        }
    }
    return AclMatch::NO_MATCH;
}
} // namespace

int CSLSListener::handler()
{
    // Periodic maintenance (override sweep, player-key cache sweep, draining
    // completed async validations, advancing deferred accepts) runs in
    // on_worker_tick on every worker pass, not just on a new connection.
    int ret = SLS_OK;
    int fd_client = 0;
    CSLSSrt *srt = NULL;
    char sid[1024] = {0};
    std::map<std::string, std::string> sid_kv;
    int sid_size = sizeof(sid);
    char host_name[URL_MAX_LEN] = {0};
    char app_name[URL_MAX_LEN] = {0};
    char stream_name[URL_MAX_LEN] = {0};
    char key_app[URL_MAX_LEN] = {0};
    char key_stream_name[URL_MAX_LEN] = {0};
    char peer_name[IP_MAX_LEN] = {0};
    int peer_port = 0;
    unsigned long peer_addr_raw = 0;
    struct in6_addr peer_addr6_raw = in6addr_any;
    int client_count = 0;
    
    // Generate session ID for this connection
    std::string session_id = CSLSSessionTracker::generate_session_id();

    fd_client = m_srt->libsrt_accept();
    if (fd_client < 0) {
        spdlog::error("[{}] CSLSListener::handler, srt_accept failed, fd={:d}.", fmt::ptr(this), get_fd());
        CSLSSrt::libsrt_neterrno();
        return client_count;
    }
    client_count = 1;

    srt = new CSLSSrt;
    srt->libsrt_set_fd(fd_client);
    ret = srt->libsrt_getpeeraddr(peer_name, peer_port);
    if (ret != 0) {
        spdlog::error("[{}] CSLSListener::handler, libsrt_getpeeraddr failed, fd={:d}.", fmt::ptr(this), srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    // Log new connection at DEBUG level (reduced from INFO)
    if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
    {
        spdlog::debug("[connection:{}] New client {}:{} fd={} type={} legacy={} port={}",
                     session_id, peer_name, peer_port, fd_client,
                     m_is_publisher_listener ? "publisher" : "player",
                     m_is_legacy_listener, m_port);
    }

    // Global backpressure: if the shared handoff list (roles accepted but not
    // yet picked up by a worker) has backed up past the ceiling, the workers
    // cannot keep pace, so stop admitting new connections until it drains
    // instead of letting accepts pile up unbounded. Self-correcting: size()
    // falls as workers pop, so there is no counter to leak. Log is
    // rate-limited to avoid amplifying a flood into log spam.
    if (m_list_role != NULL && m_list_role->size() >= MAX_HANDOFF_BACKLOG) {
        std::string rate_key = std::string("handoff_backlog:") + std::to_string(m_port);
        CSLSLogRateLimiter::EventStats stats;
        if (!sls_get_log_config().rate_limit_enabled ||
            sls_get_rate_limiter().should_log(rate_key, stats)) {
            spdlog::warn("[{}] CSLSListener::handler, refused [{}:{:d}]: handoff backlog at ceiling ({}), workers overloaded.",
                         fmt::ptr(this), peer_name, peer_port, MAX_HANDOFF_BACKLOG);
        }
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    sls_conf_server_t* conf_server = (sls_conf_server_t*)m_conf;
    const bool is_publisher = m_is_publisher_listener;
    const char* role = is_publisher ? "publisher" : "player";

    // The latency that governs quality differs by role, and SRTO_LATENCY's
    // getter is just an alias for SRTO_RCVLATENCY (see srt.h). For a publisher
    // we are the receiver, so SRTO_RCVLATENCY is the real TSBPD window that
    // absorbs retransmits (too small => glitching on lossy links). For a player
    // we are the sender and never receive media from them, so RCVLATENCY is
    // meaningless; what matters is SRTO_PEERLATENCY, the floor we impose on the
    // viewer's own receive buffer. Reading the role-appropriate field keeps the
    // floor/ceiling checks meaningful instead of flagging players on a value
    // that does not affect them.
    const SRT_SOCKOPT lat_opt = is_publisher ? SRTO_RCVLATENCY : SRTO_PEERLATENCY;
    const char* lat_opt_name = is_publisher ? "SRTO_RCVLATENCY" : "SRTO_PEERLATENCY";

    int negotiated_latency = 0;
    int latency_len = sizeof(negotiated_latency);
    int final_latency = 0;

    if (0 != srt->libsrt_getsockopt(lat_opt, lat_opt_name, &negotiated_latency, &latency_len)) {
        negotiated_latency = conf_server->latency_min > 0 ? conf_server->latency_min : 120;
        spdlog::warn("[{}] CSLSListener::handler, [{}:{:d}], failed to read latency, using fallback {} ms.",
                fmt::ptr(this), peer_name, peer_port, negotiated_latency);
    } else {
        // Log latency at DEBUG level
        if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
        {
            spdlog::debug("[connection:{}] {} {}:{} latency={} ms",
                    session_id, role, peer_name, peer_port, negotiated_latency);
        }
        if (conf_server->latency_max > 0 && negotiated_latency > conf_server->latency_max) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], rejecting {}: latency {} ms exceeds maximum {} ms.",
                    fmt::ptr(this), peer_name, peer_port, role, negotiated_latency, conf_server->latency_max);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
    }

    final_latency = negotiated_latency;

    // A connection landing below latency_min means the listener floor
    // (SRTO_LATENCY/RCVLATENCY/PEERLATENCY set in CSLSListener::start) did not
    // win the handshake negotiation for this peer. Our pre-bind floor should
    // force effective = max(our_floor, peer_proposed), so a sub-floor result is
    // peer-dependent: certain (often older/HSv4) SRT senders negotiate it down.
    // We cannot raise it post-accept (RCVLATENCY is a pre-connect option), so
    // capture the peer's SRT version here to identify the offending clients.
    if (conf_server->latency_min > 0 && negotiated_latency > 0 &&
        negotiated_latency < conf_server->latency_min)
    {
        int peer_version = 0;
        int peer_version_len = sizeof(peer_version);
        srt->libsrt_getsockopt(SRTO_PEERVERSION, "SRTO_PEERVERSION",
                               &peer_version, &peer_version_len);
        spdlog::warn("[connection:{}] {} {}:{} negotiated {} {} ms below latency_min {} ms (peer SRT version {:#x}).",
                     session_id, role, peer_name, peer_port, lat_opt_name,
                     negotiated_latency, conf_server->latency_min, peer_version);
    }

    if (0 != srt->libsrt_getsockopt(SRTO_STREAMID, "SRTO_STREAMID", &sid, &sid_size)) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, get streamid info failed.",
                      fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    // Log stream ID at DEBUG level
    if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
    {
        spdlog::debug("[connection:{}] Received stream_id '{}' from {}:{}",
                     session_id, sid, peer_name, peer_port);
    }

    if (strlen(sid) == 0) {
        spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], fd={:d}, empty stream ID not allowed.", fmt::ptr(this), peer_name, peer_port, srt->libsrt_get_fd());
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    sid_kv = srt->libsrt_parse_sid(sid);
    bool sidValid = true;
    if (sid_kv.count("h")) {
        strlcpy(host_name, sid_kv.at("h").c_str(), sizeof(host_name));
    } else {
        sidValid = false;
    }
    if (sid_kv.count("sls_app")) {
        strlcpy(app_name, sid_kv.at("sls_app").c_str(), sizeof(app_name));
    } else {
        sidValid = false;
    }
    if (sid_kv.count("r")) {
        strlcpy(stream_name, sid_kv.at("r").c_str(), sizeof(stream_name));
    } else {
        sidValid = false;
    }
    if (!sidValid) {
        spdlog::error("[connection:{}] Parse SID '{}' failed for {}:{}",
                     session_id, sid, peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    if (!sls_is_safe_name(host_name) || !sls_is_safe_name(app_name) || !sls_is_safe_name(stream_name)) {
        spdlog::error("[connection:{}] Refused SID '{}' from {}:{} — unsafe characters in host/app/stream",
                     session_id, sid, peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    // Log parsed SID at DEBUG level
    if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
    {
        spdlog::debug("[connection:{}] Parsed SID: {}/{}/{} from {}:{}",
                     session_id, host_name, app_name, stream_name, peer_name, peer_port);
    }

    snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);

    std::string app_uplive = "";
    sls_conf_app_t *ca = NULL;

    char cur_time[STR_DATE_TIME_LEN] = {0};
    sls_gettime_default_string(cur_time, sizeof(cur_time));

    app_uplive = m_map_publisher->get_uplive(key_app);
    bool is_player_connection = (app_uplive.length() > 0);
    bool connection_allowed = true;

    // Verbose connection analysis at DEBUG level
    if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
    {
        spdlog::debug("[connection:{}] Analysis: app='{}' uplive='{}' is_player={} type={} legacy={}",
                     session_id, key_app, app_uplive, is_player_connection,
                     m_is_publisher_listener ? "publisher" : "player", m_is_legacy_listener);
    }

    if (m_is_legacy_listener) {
        spdlog::debug("[connection:{}] {} app='{}' accepted on legacy listener port={} (backward compat)",
                      session_id, is_player_connection ? "Player" : "Publisher", app_name, m_port);
    } else {
        // Validation check at DEBUG level
        if (sls_should_log_category(SLSLogCategory::CONNECTION, spdlog::level::debug))
        {
            spdlog::debug("[connection:{}] Validation: pub_listener={} is_player={}",
                         session_id, m_is_publisher_listener, is_player_connection);
        }

        if (!m_is_publisher_listener && !is_player_connection) {
            spdlog::warn("[connection:{}] REFUSED: Publisher app='{}' on player listener port={} from {}:{}",
                         session_id, app_name, m_port, peer_name, peer_port);
            connection_allowed = false;
        } else if (m_is_publisher_listener && is_player_connection) {
            spdlog::warn("[connection:{}] REFUSED: Player app='{}' on publisher listener port={} from {}:{}",
                         session_id, app_name, m_port, peer_name, peer_port);
            connection_allowed = false;
        } else {
            // Connection accepted - log at INFO level with rate limiting
            CSLSLogRateLimiter::EventStats stats;
            std::string rate_key = std::string(peer_name) + ":" + (is_player_connection ? "player" : "publisher");
            
            if (sls_get_log_config().rate_limit_enabled && 
                sls_get_rate_limiter().should_log(rate_key, stats))
            {
                if (stats.count > 1)
                {
                    spdlog::info("[connection:{}] {} connected app='{}' stream='{}' latency={}ms ({} times in {}s)",
                                session_id, is_player_connection ? "Player" : "Publisher", 
                                app_name, stream_name, final_latency, stats.count, 
                                sls_get_log_config().rate_limit_window_sec);
                }
                else
                {
                    spdlog::info("[connection:{}] {} connected app='{}' stream='{}' latency={}ms",
                                session_id, is_player_connection ? "Player" : "Publisher",
                                app_name, stream_name, final_latency);
                }
            }
            else if (!sls_get_log_config().rate_limit_enabled)
            {
                spdlog::info("[connection:{}] {} connected app='{}' stream='{}' latency={}ms",
                            session_id, is_player_connection ? "Player" : "Publisher",
                            app_name, stream_name, final_latency);
            }
        }
    }

    if (!connection_allowed) {
        spdlog::error("[connection:{}] Connection REJECTED from {}:{}", 
                     session_id, peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    char validated_stream_id[URL_MAX_LEN] = {0};
    char player_key[URL_MAX_LEN] = {0};
    bool player_key_validation_required = false;

    char domain[URL_MAX_LEN] = {0};
    char app[URL_MAX_LEN] = {0};
    char stream_part[URL_MAX_LEN] = {0};

    char* sid_copy = strdup(sid);
    if (!sid_copy) {
        spdlog::error("[{}] CSLSListener::handler, strdup(sid) failed (OOM); rejecting connection from {}:{}.",
                     fmt::ptr(this), peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }
    char* token = strtok(sid_copy, "/");
    int part_count = 0;

    if (token) {
        strlcpy(domain, token, sizeof(domain));
        part_count++;
        token = strtok(NULL, "/");
        if (token) {
            strlcpy(app, token, sizeof(app));
            part_count++;
            token = strtok(NULL, "/");
            if (token) {
                strlcpy(stream_part, token, sizeof(stream_part));
                part_count++;
            }
        }
    }
    free(sid_copy);

    // strtok keeps any stray whitespace/newline a client tacked onto the
    // streamid, which would break the m_domain_players/m_app_players matches
    // below and the player_key sent to the auth URL. Trim before they're used.
    strlcpy(domain, sls_trim(domain).c_str(), sizeof(domain));
    strlcpy(app, sls_trim(app).c_str(), sizeof(app));
    strlcpy(stream_part, sls_trim(stream_part).c_str(), sizeof(stream_part));

    bool is_player_domain = false;
    bool is_player_app = false;

    for (const auto& player_domain : m_domain_players) {
        if (strcmp(domain, player_domain.c_str()) == 0) {
            is_player_domain = true;
            break;
        }
    }

    for (const auto& player_app : m_app_players) {
        if (strcmp(app, player_app.c_str()) == 0) {
            is_player_app = true;
            break;
        }
    }

    if (part_count == 3 && is_player_domain && is_player_app && strlen(m_player_key_auth_url) > 0) {
        strlcpy(player_key, stream_part, sizeof(player_key));
        player_key_validation_required = true;

        // Check if player key is already cached - if so, we can check stream status first
        // to reduce log noise from repeated reconnection attempts to offline streams
        bool key_is_cached = false;
        bool stream_offline_cached = false;
        std::string cached_stream_id;
        {
            std::lock_guard<std::mutex> lk(m_cache_mutex);
            auto cache_it = m_player_key_cache.find(std::string(player_key));
            if (cache_it != m_player_key_cache.end()) {
                auto now = std::chrono::steady_clock::now();
                if (now < cache_it->second.expiry_time && cache_it->second.is_valid) {
                    key_is_cached = true;
                    cached_stream_id = cache_it->second.resolved_stream_id;
                }
            }
        }

        // If key is cached, check if stream is offline before doing verbose logging
        if (key_is_cached) {
            // Parse cached stream ID to check publisher status
            char cached_sid_buf[1024] = {0};
            strlcpy(cached_sid_buf, cached_stream_id.c_str(), sizeof(cached_sid_buf));
            std::map<std::string, std::string> cached_sid_kv = srt->libsrt_parse_sid(cached_sid_buf);
            if (cached_sid_kv.count("h") && cached_sid_kv.count("sls_app") && cached_sid_kv.count("r")) {
                char temp_key_app[URL_MAX_LEN] = {0};
                snprintf(temp_key_app, sizeof(temp_key_app), "%s/%s",
                         cached_sid_kv.at("h").c_str(), cached_sid_kv.at("sls_app").c_str());
                std::string temp_uplive = m_map_publisher->get_uplive(temp_key_app);
                if (temp_uplive.length() > 0) {
                    char temp_key_stream[URL_MAX_LEN] = {0};
                    snprintf(temp_key_stream, sizeof(temp_key_stream), "%s/%s",
                             temp_uplive.c_str(), cached_sid_kv.at("r").c_str());
                    CSLSRole *temp_pub = m_map_publisher->get_publisher(temp_key_stream);
                    if (NULL == temp_pub && NULL == m_map_puller) {
                        stream_offline_cached = true;
                    }
                }
            }
        }

        // Rate-limit logs for cached keys connecting to offline streams
        if (key_is_cached && stream_offline_cached) {
            std::string rate_key = std::string(peer_name) + ":playerkey:" + player_key + ":offline";
            CSLSLogRateLimiter::EventStats stats;
            if (sls_get_log_config().rate_limit_enabled &&
                !sls_get_rate_limiter().should_log(rate_key, stats)) {
                // Suppressed - just log at debug and reject
                spdlog::debug("[connection:{}] Player key '{}' from {}:{} - stream offline (suppressed, {} attempts)",
                             session_id, player_key, peer_name, peer_port, stats.count);
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            // First in window or rate limiting disabled - log at info but note it's offline
            spdlog::info("[connection:{}] Player key '{}' from {}:{} - stream currently offline",
                        session_id, sls_redact_secret(player_key), peer_name, peer_port);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        // Not cached or stream is online - proceed with normal validation
        if (!key_is_cached) {
            spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], detected player connection with configured format '{}/{}', player_key='{}', validating...",
                         fmt::ptr(this), peer_name, peer_port, domain, app, sls_redact_secret(player_key));
        }

        int validation_result = validate_player_key(player_key, validated_stream_id, sizeof(validated_stream_id), peer_name);
        if (validation_result == SLS_PENDING) {
            // Uncached key: an async webhook validation was dispatched. Hold
            // the accepted socket open (deferred accept) instead of rejecting,
            // so a one-shot client that does not auto-reconnect (VLC, ffplay)
            // still gets in once the validation resolves. The worker completes
            // or closes it in drive_pending_player_connections. srt ownership
            // transfers to the pending list on success below.
            if (m_pending_player_connections.size() >= MAX_PENDING_PLAYER_CONNECTIONS) {
                spdlog::warn("[connection:{}] deferred player accept: pending cap reached ({}), refusing key='{}'.",
                             session_id, m_pending_player_connections.size(), sls_redact_secret(player_key));
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            PendingPlayerConnection pend;
            pend.srt = srt;
            pend.app_uplive = app_uplive;
            pend.player_key = player_key;
            pend.session_id = session_id;
            pend.peer_name = peer_name;
            pend.peer_port = peer_port;
            pend.final_latency = final_latency;
            pend.cur_time = cur_time;
            pend.deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(m_player_key_auth_timeout + 2000);
            m_pending_player_connections.push_back(std::move(pend));
            spdlog::debug("[connection:{}] Player key '{}' from {}:{} - validation pending, holding connection",
                         session_id, player_key, peer_name, peer_port);
            return client_count;
        }
        if (validation_result != SLS_OK) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], player key validation FAILED for key='{}'",
                         fmt::ptr(this), peer_name, peer_port, sls_redact_secret(player_key));
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        if (!key_is_cached) {
            spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], player key validation SUCCESS, resolved to stream_id='{}'",
                         fmt::ptr(this), peer_name, peer_port, sls_redact_secret(validated_stream_id));
        }

        strlcpy(sid, validated_stream_id, sizeof(sid));
        if (!key_is_cached) {
            spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], updated stream_id to: '{}'",
                         fmt::ptr(this), peer_name, peer_port, sls_redact_secret(sid));
        }

        sid_kv = srt->libsrt_parse_sid(sid);
        bool validated_sid_valid = true;

        if (sid_kv.count("h")) {
            strlcpy(host_name, sid_kv.at("h").c_str(), sizeof(host_name));
        } else {
            validated_sid_valid = false;
        }
        if (sid_kv.count("sls_app")) {
            strlcpy(app_name, sid_kv.at("sls_app").c_str(), sizeof(app_name));
        } else {
            validated_sid_valid = false;
        }
        if (sid_kv.count("r")) {
            strlcpy(stream_name, sid_kv.at("r").c_str(), sizeof(stream_name));
        } else {
            validated_sid_valid = false;
        }

        if (!validated_sid_valid) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], validated stream_id '{}' has invalid format",
                         fmt::ptr(this), peer_name, peer_port, sid);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        if (!sls_is_safe_name(host_name) || !sls_is_safe_name(app_name) || !sls_is_safe_name(stream_name)) {
            spdlog::error("[{}] CSLSListener::handler, [{}:{:d}], refused validated stream_id '{}' — unsafe characters in host/app/stream",
                         fmt::ptr(this), peer_name, peer_port, sid);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        snprintf(key_app, sizeof(key_app), "%s/%s", host_name, app_name);

        if (!key_is_cached) {
            spdlog::info("[{}] CSLSListener::handler, [{}:{:d}], re-parsed validated stream: '{}/{}/{}'",
                         fmt::ptr(this), peer_name, peer_port, host_name, app_name, stream_name);
        }
    }

    if (app_uplive.length() > 0) {
        return finish_player_accept(srt, app_uplive, stream_name, sid,
                                    std::string(player_key), player_key_validation_required,
                                    peer_name, peer_port, final_latency, session_id, cur_time);
    }

    app_uplive = key_app;
    snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name);
    ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
    if (NULL == ca) {
        spdlog::warn("[{}] CSLSListener::handler, refused, new role[{}:{:d}], non-existent publishing domain [stream='{}']",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK) {
        AclMatch acl_result = sls_check_ip_acl(ca->ip_actions.publish, peer_addr_raw,
                                               peer_addr6_raw,
                                               srt->libsrt_is_ipv6_peer(),
                                               fmt::ptr(this), peer_name, peer_port,
                                               ca->app_publisher);
        if (acl_result == AclMatch::DENY) {
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        if (acl_result == AclMatch::NO_MATCH) {
            // Documented default: accept when no ACL entry (v4, v6, or
            // wildcard) matched this peer.
            spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                         fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
        }
    } else {
        spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
        spdlog::error("[{}] CSLSListener::handler Rejecting connection by default", fmt::ptr(this));
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    CSLSRole *publisher = m_map_publisher->get_publisher(key_stream_name);
    if (NULL != publisher) {
        // Publisher takeover. A publisher is already registered for this
        // stream, but a fresh connection for the same key is almost always
        // the same encoder reconnecting (SRTLA link flap / SRT session
        // reset). The incumbent's socket can squat the key for the whole
        // idle_streams_timeout: the peer's SHUTDOWN is sent over the same
        // flapping path and routinely never arrives, so SLS only notices the
        // stale publisher via the idle timer (~10s of black screen on every
        // reconnect). Instead, mark the incumbent for teardown so its owning
        // worker reaps it within one idle tick (~50ms) through the normal
        // cleanup path; the encoder's next reconnect then registers cleanly.
        //
        // We still refuse THIS connection rather than adopting its socket in
        // place: evicting the incumbent and swapping in the new socket
        // atomically would mean touching the incumbent's map_data ring (shared
        // with any current players) and publisher entry from the listener
        // thread while another worker still owns that role — not safe. One
        // extra reconnect is a fine price for staying race-free.
        //
        // Caveat: this is last-writer-wins. Two distinct encoders configured
        // with the same stream key will evict each other on a loop. That
        // requires possession of the (secret) stream key and passing the IP
        // ACL, and is logged below so operators can spot it.
        //
        // Active-incumbent guard: only evict an incumbent that has gone quiet
        // (flapped / zombie). If it is a real broadcaster currently delivering
        // media, the newcomer is far more likely a misdirected player/preview
        // or a duplicate than a real reconnect, so refuse the newcomer and
        // leave the live stream alone. Without this, a player parked on the
        // ingest port (valid key, sends nothing) would request_kick() the real
        // broadcaster on every reconnect. Scoped to is_takeover_protected() so
        // a puller/relay incumbent stays evictable (a local publisher must be
        // able to take over a pulled stream). has_recent_recv_data reads an
        // atomic; same cross-thread safety as the request_kick() call below.
        if (publisher->is_takeover_protected() &&
            publisher->has_recent_recv_data(sls_gettime_ms(), ACTIVE_INCUMBENT_RECV_WINDOW_MS)) {
            spdlog::warn("[{}] CSLSListener::handler, refused new role[{}:{:d}] for stream='{}': incumbent publisher={} is actively receiving, not evicting.",
                         fmt::ptr(this), peer_name, peer_port, key_stream_name, fmt::ptr(publisher));
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        publisher->request_kick();
        spdlog::warn("[{}] CSLSListener::handler, publisher takeover for stream='{}', evicting stale publisher={}, new role[{}:{:d}] will reconnect.",
                     fmt::ptr(this), key_stream_name, fmt::ptr(publisher), peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    CSLSPublisher *pub = new CSLSPublisher;
    pub->set_srt(srt);
    pub->set_conf((sls_conf_base_t *)ca);
    pub->init();
    pub->set_idle_streams_timeout(m_idle_streams_timeout_role);
    // Probation: reap this publisher fast if it never delivers a media packet
    // (a player/preview pointed at the ingest port), rather than letting it
    // squat the stream key for the full idle timeout. The deadline is the
    // negotiated receive latency plus the configured grace: SRT's TSBPD holds
    // the first packet for the whole latency window before delivering it to the
    // app, so a legitimate high-latency encoder (Moblin ~3000ms, Belabox
    // 2000-3000ms) must not be reaped while it is still buffering. grace covers
    // RTT, encoder warmup, and TSBPD jitter on top of that. 0 grace = disabled.
    const int first_data_deadline = (m_publisher_first_data_grace_role > 0)
                                        ? final_latency + m_publisher_first_data_grace_role
                                        : 0;
    pub->set_first_data_timeout(first_data_deadline);
    pub->set_latency(final_latency);

    stat_info_t stat_info_obj{};
    stat_info_obj.port = m_port;
    stat_info_obj.role = pub->get_role_name();
    stat_info_obj.pub_domain_app = app_uplive;
    stat_info_obj.stream_name = stream_name;
    stat_info_obj.url = sid;
    stat_info_obj.remote_ip = peer_name;
    stat_info_obj.remote_port = peer_port;
    stat_info_obj.start_time = cur_time;

    pub->set_stat_info_base(stat_info_obj);

    pub->set_http_url(m_http_url_role);
    // Hand the publisher the shared negative-auth cache so a non-200 webhook
    // response records this streamid for handshake-time rejection of repeats.
    pub->set_auth_reject_cache(m_auth_reject_cache);

    spdlog::info("[{}] CSLSListener::handler, new pub={}, key_stream_name={}.",
                 fmt::ptr(this), fmt::ptr(pub), key_stream_name);

    // Size the publisher's ring buffer to the configured max input bitrate
    // and the SRT latency window. Without this hint CSLSRecycleArray falls
    // back to its compile-time default; the dynamic sizing here right-fits
    // each publisher so a subscriber that falls a full latency window
    // behind is still safe from buffer overrun (which would otherwise
    // silently corrupt the delivered stream — visible to viewers as
    // periodic skips that "reset" when they refresh the source).
    int map_data_bitrate_hint = 0;
    if (ca != NULL) {
        map_data_bitrate_hint = ((sls_conf_app_t *)ca)->max_input_bitrate_kbps;
    }
    if (SLS_OK != m_map_data->add(key_stream_name, map_data_bitrate_hint, final_latency)) {
        spdlog::warn("[{}] CSLSListener::handler, m_map_data->add failed, new pub[{}:{:d}], stream= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        pub->uninit();
        delete pub;
        pub = NULL;
        return client_count;
    }

    if (SLS_OK != m_map_publisher->set_push_2_publisher(key_stream_name, pub)) {
        spdlog::warn("[{}] CSLSListener::handler, m_map_publisher->set_push_2_publisher failed, key_stream_name= {}.",
                     fmt::ptr(this), key_stream_name);
        pub->uninit();
        delete pub;
        pub = NULL;
        return client_count;
    }
    pub->set_map_publisher(m_map_publisher);
    pub->set_map_data(key_stream_name, m_map_data);
    pub->set_role_list(m_list_role);
    pub->set_listen_port(m_port);
    pub->on_connect();
    m_list_role->push(pub);
    spdlog::info("[{}] CSLSListener::handler, new publisher[{}:{:d}], key_stream_name= {}.",
                 fmt::ptr(this), peer_name, peer_port, key_stream_name);

    if (NULL == m_map_pusher) {
        return client_count;
    }
    CSLSRelayManager *pusher_manager = m_map_pusher->add_relay_manager(app_uplive.c_str(), stream_name);
    if (NULL == pusher_manager) {
        spdlog::info("[{}] CSLSListener::handler, m_map_pusher->add_relay_manager failed, new role[{}:{:d}], key_stream_name= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
        return client_count;
    }
    pusher_manager->set_map_data(m_map_data);
    pusher_manager->set_map_publisher(m_map_publisher);
    pusher_manager->set_role_list(m_list_role);
    pusher_manager->set_listen_port(m_port);

    if (SLS_OK != pusher_manager->start()) {
        spdlog::info("[{}] CSLSListener::handler, pusher_manager->start failed, new role[{}:{:d}], key_stream_name= {}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);
    }
    return client_count;
}

void CSLSListener::cleanupExpiredStreamOverrides()
{
    auto now_ts = std::chrono::steady_clock::now();
    for (auto it = m_stream_player_limit_map.begin(); it != m_stream_player_limit_map.end(); ) {
        const StreamPlayerLimitEntry &entry = it->second;
        if (entry.expiry_time <= now_ts) {
            it = m_stream_player_limit_map.erase(it);
        } else {
            ++it;
        }
    }
}

int CSLSListener::finish_player_accept(CSLSSrt *srt,
                                       const std::string &app_uplive,
                                       const std::string &stream_name,
                                       const std::string &effective_sid,
                                       const std::string &player_key,
                                       bool player_key_validation_required,
                                       const char *peer_name, int peer_port,
                                       int final_latency,
                                       const std::string &session_id,
                                       const std::string &cur_time)
{
    int client_count = 1;
    char key_stream_name[URL_MAX_LEN] = {0};
    unsigned long peer_addr_raw = 0;
    struct in6_addr peer_addr6_raw = in6addr_any;
    sls_conf_app_t *ca = NULL;

    snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", app_uplive.c_str(), stream_name.c_str());
    if (player_key_validation_required) {
        auto now_ts = std::chrono::steady_clock::now();
        PlayerKeyCacheEntry entry;
        bool found_entry = false;
        {
            std::lock_guard<std::mutex> lk(m_cache_mutex);
            auto it_cache = m_player_key_cache.find(player_key);
            if (it_cache != m_player_key_cache.end()) {
                entry = it_cache->second;
                found_entry = true;
            }
        }
        if (found_entry) {
            if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                StreamPlayerLimitEntry stream_entry;
                stream_entry.has_override = true;
                stream_entry.max_players_per_stream = entry.max_players_per_stream_override;
                stream_entry.expiry_time = entry.expiry_time;
                m_stream_player_limit_map[std::string(key_stream_name)] = stream_entry;
            }
        }
    }
    CSLSRole *pub = m_map_publisher->get_publisher(key_stream_name);
    if (NULL == pub) {
        if (NULL == m_map_puller) {
            // Rate-limit "stream offline" logs to reduce noise from repeated reconnection attempts
            std::string rate_key = std::string(peer_name) + ":stream_offline:" + key_stream_name;
            CSLSLogRateLimiter::EventStats stats;
            if (sls_get_log_config().rate_limit_enabled &&
                !sls_get_rate_limiter().should_log(rate_key, stats)) {
                spdlog::debug("[connection:{}] Stream '{}' offline, refusing {}:{} (suppressed, {} attempts)",
                             session_id, key_stream_name, peer_name, peer_port, stats.count);
            } else {
                spdlog::info("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream='{}', publisher is NULL and m_map_puller is NULL.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
            }
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        CSLSRelayManager *puller_manager = m_map_puller->add_relay_manager(app_uplive.c_str(), stream_name.c_str());
        if (NULL == puller_manager) {
            srt->libsrt_close();
            delete srt;
            return client_count;
        }

        puller_manager->set_map_data(m_map_data);
        puller_manager->set_map_publisher(m_map_publisher);
        puller_manager->set_role_list(m_list_role);
        puller_manager->set_listen_port(m_port);

        if (SLS_OK != puller_manager->start()) {
            spdlog::info("[{}] CSLSListener::handler, puller_manager->start failed, new client[{}:{:d}], stream='{}'.",
                         fmt::ptr(this), peer_name, peer_port, key_stream_name);
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        spdlog::info("[{}] CSLSListener::handler, puller_manager->start ok, new client[{}:{:d}], stream={}.",
                     fmt::ptr(this), peer_name, peer_port, key_stream_name);

        pub = m_map_publisher->get_publisher(key_stream_name);
        if (NULL == pub) {
            // Rate-limit "publisher not ready" logs to reduce noise from repeated reconnection attempts
            std::string rate_key = std::string(peer_name) + ":pub_not_ready:" + key_stream_name;
            CSLSLogRateLimiter::EventStats stats;
            if (sls_get_log_config().rate_limit_enabled &&
                !sls_get_rate_limiter().should_log(rate_key, stats)) {
                spdlog::debug("[connection:{}] Publisher not ready for '{}', refusing {}:{} (suppressed, {} attempts)",
                             session_id, key_stream_name, peer_name, peer_port, stats.count);
            } else {
                spdlog::warn("[{}] CSLSListener::handler, publisher not ready after puller start, new client[{}:{:d}], stream='{}'. Client should retry.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name);
            }
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
        spdlog::info("[{}] CSLSListener::handler, m_map_publisher->get_publisher ok, pub={}, new client[{}:{:d}], stream='{}'.",
                     fmt::ptr(this), fmt::ptr(pub), peer_name, peer_port, key_stream_name);
    }

    ca = (sls_conf_app_t *)m_map_publisher->get_ca(app_uplive);
    if (ca == nullptr) {
        spdlog::error("[{}] CSLSListener::handler, refused, configuration does not exist [stream={}]",
                       fmt::ptr(this), key_stream_name);
        srt->libsrt_close();
        delete srt;
        return client_count;
    } else {
        if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK) {
            AclMatch acl_result = sls_check_ip_acl(ca->ip_actions.play, peer_addr_raw,
                                                   peer_addr6_raw,
                                                   srt->libsrt_is_ipv6_peer(),
                                                   fmt::ptr(this), peer_name, peer_port,
                                                   ca->app_publisher);
            if (acl_result == AclMatch::DENY) {
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            if (acl_result == AclMatch::NO_MATCH) {
                spdlog::info("[{}] CSLSListener::handler Accepted connection from {}:{:d} for app '{}' by default",
                             fmt::ptr(this), peer_name, peer_port, ca->app_publisher);
            }
        } else {
            spdlog::error("[{}] CSLSListener::handler ACL check failed: could not get peer address", fmt::ptr(this));
            spdlog::error("[{}] CSLSListener::handler Rejecting connection by default", fmt::ptr(this));
            srt->libsrt_close();
            delete srt;
            return client_count;
        }
    }

    CSLSRole *pub_check = m_map_publisher->get_publisher(key_stream_name);
    if (NULL == pub_check) {
        spdlog::error("[{}] CSLSListener::handler, refused, new role[{}:{:d}], stream={}, publisher no longer exists.",
                      fmt::ptr(this), peer_name, peer_port, key_stream_name);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    {
        int effective_max_players = ca->max_players_per_stream;
        bool using_override = false;
        auto now_ts = std::chrono::steady_clock::now();

        auto it_stream_cap = m_stream_player_limit_map.find(std::string(key_stream_name));
        if (it_stream_cap != m_stream_player_limit_map.end()) {
            const StreamPlayerLimitEntry &sentry = it_stream_cap->second;
            if (sentry.has_override && now_ts < sentry.expiry_time) {
                effective_max_players = sentry.max_players_per_stream;
                using_override = true;
            } else if (now_ts >= sentry.expiry_time) {
                m_stream_player_limit_map.erase(it_stream_cap);
            }
        }

        if (!using_override && player_key_validation_required) {
            PlayerKeyCacheEntry entry;
            bool found_entry = false;
            {
                std::lock_guard<std::mutex> lk(m_cache_mutex);
                auto it_cache = m_player_key_cache.find(player_key);
                if (it_cache != m_player_key_cache.end()) {
                    entry = it_cache->second;
                    found_entry = true;
                }
            }
            if (found_entry) {
                if (entry.is_valid && now_ts < entry.expiry_time && entry.has_max_players_override) {
                    effective_max_players = entry.max_players_per_stream_override;
                    using_override = true;
                }
            }
        }

        if (effective_max_players > 0) {
            int current_player_count = m_list_role->count_players_for_stream(key_stream_name);
            if (current_player_count >= effective_max_players) {
                spdlog::warn("[{}] CSLSListener::handler, refused, new player[{}:{:d}], stream={}, player limit reached ({:d}/{:d}){}.",
                             fmt::ptr(this), peer_name, peer_port, key_stream_name, current_player_count, effective_max_players,
                             using_override ? " [override]" : "");
                srt->libsrt_close();
                delete srt;
                return client_count;
            }
            spdlog::debug("[{}] CSLSListener::handler, new player[{}:{:d}], stream={}, player count ({:d}/{:d}){}.",
                          fmt::ptr(this), peer_name, peer_port, key_stream_name, current_player_count, effective_max_players,
                          using_override ? " [override]" : "");
        }
    }

    if (srt->libsrt_socket_nonblock(0) < 0)
        spdlog::warn("[{}] CSLSListener::handler, new player[{}:{:d}], libsrt_socket_nonblock failed.",
                     fmt::ptr(this), peer_name, peer_port);

    CSLSPlayer *player = new CSLSPlayer;
    if (NULL == player) {
        spdlog::error("[{}] CSLSListener::handler, failed to allocate player for [{}:{:d}]",
                     fmt::ptr(this), peer_name, peer_port);
        srt->libsrt_close();
        delete srt;
        return client_count;
    }

    player->init();
    player->set_idle_streams_timeout(m_idle_streams_timeout_role);
    player->set_srt(srt);
    player->set_map_data(key_stream_name, m_map_data);
    player->set_latency(final_latency);
    // Seed the role's streamid with the (possibly player-key-resolved) sid
    // so downstream hooks like on_event_url report the real stream instead
    // of the raw SRTO_STREAMID the client sent.
    player->set_streamid(effective_sid.c_str());

    stat_info_t stat_info_obj{};
    stat_info_obj.port = m_port;
    stat_info_obj.role = player->get_role_name();
    stat_info_obj.pub_domain_app = app_uplive;
    stat_info_obj.stream_name = stream_name;
    stat_info_obj.url = effective_sid;
    stat_info_obj.remote_ip = peer_name;
    stat_info_obj.remote_port = peer_port;
    stat_info_obj.start_time = cur_time;
    player->set_stat_info_base(stat_info_obj);

    player->set_http_url(m_http_url_role);
    player->on_connect();

    m_list_role->push(player);
    spdlog::info("[{}] CSLSListener::handler, new player[{}] =[{}:{:d}], key_stream_name={}, {}={}, m_list_role->size={:d}.",
                 fmt::ptr(this), fmt::ptr(player), peer_name, peer_port, key_stream_name, player->get_role_name(), fmt::ptr(player), m_list_role->size());
    return client_count;
}

void CSLSListener::on_worker_tick()
{
    cleanupExpiredStreamOverrides();
    sweep_player_key_cache();
    // Fold completed async player-key webhooks into the cache, then advance
    // any connections held open waiting on those results.
    drain_player_key_validations();
    drive_pending_player_connections();
}

void CSLSListener::drive_pending_player_connections()
{
    if (m_pending_player_connections.empty())
        return;

    auto now = std::chrono::steady_clock::now();
    for (auto it = m_pending_player_connections.begin(); it != m_pending_player_connections.end();) {
        bool found = false;
        bool valid = false;
        std::string resolved;
        {
            std::lock_guard<std::mutex> lk(m_cache_mutex);
            auto c = m_player_key_cache.find(it->player_key);
            if (c != m_player_key_cache.end() && now < c->second.expiry_time) {
                found = true;
                valid = c->second.is_valid;
                resolved = c->second.resolved_stream_id;
            }
        }

        if (found && valid) {
            // Parse and safety-check the resolved stream id, mirroring the
            // synchronous post-validation path, then complete the accept.
            char resolved_buf[1024] = {0};
            strlcpy(resolved_buf, resolved.c_str(), sizeof(resolved_buf));
            std::map<std::string, std::string> kv = it->srt->libsrt_parse_sid(resolved_buf);
            if (kv.count("h") && kv.count("sls_app") && kv.count("r") &&
                sls_is_safe_name(kv.at("h").c_str()) &&
                sls_is_safe_name(kv.at("sls_app").c_str()) &&
                sls_is_safe_name(kv.at("r").c_str())) {
                finish_player_accept(it->srt, it->app_uplive, kv.at("r"), resolved,
                                     it->player_key, true,
                                     it->peer_name.c_str(), it->peer_port,
                                     it->final_latency, it->session_id, it->cur_time);
            } else {
                spdlog::error("[connection:{}] deferred player accept: resolved stream_id '{}' invalid for key='{}', closing.",
                             it->session_id, sls_redact_secret(resolved), sls_redact_secret(it->player_key));
                it->srt->libsrt_close();
                delete it->srt;
            }
            it = m_pending_player_connections.erase(it);
        } else if (found && !valid) {
            spdlog::debug("[connection:{}] deferred player accept: key='{}' rejected by auth, closing.",
                         it->session_id, it->player_key);
            it->srt->libsrt_close();
            delete it->srt;
            it = m_pending_player_connections.erase(it);
        } else if (now >= it->deadline) {
            spdlog::warn("[connection:{}] deferred player accept: key='{}' not resolved before deadline, closing.",
                         it->session_id, sls_redact_secret(it->player_key));
            it->srt->libsrt_close();
            delete it->srt;
            it = m_pending_player_connections.erase(it);
        } else {
            ++it; // still waiting on the webhook result
        }
    }
}