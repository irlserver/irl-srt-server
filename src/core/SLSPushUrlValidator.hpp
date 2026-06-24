#pragma once

#include <string>

#include "SLSPublisher.hpp"

/**
 * Two-stage validation for push destination URLs coming from the publish
 * auth webhook. The irlserver2 layer already rejects obviously bad URLs at
 * save time, but those checks can be bypassed (direct DB writes, late DNS
 * rebinding, operator misconfiguration). SLS runs the same checks again at
 * use time so a misbehaving webhook can never make SLS dial into its own
 * loopback or into the publisher's intranet without an explicit opt-in.
 */

enum class PushUrlReject {
    Ok,
    TooLong,
    InvalidUrl,
    WrongScheme,
    MissingHost,
    MissingStreamid,
    DnsFailure,
    DenyInternal,
    DenySelf,
    BadPlaceholder,
};

const char *push_url_reject_reason(PushUrlReject reason);

// The only brace sequence a push URL may carry; substituted with the stream name.
extern const char *const kPushUrlStreamNameToken;

/**
 * Replace every literal "{stream_name}" token in `url_template` with
 * `stream_name` and return the result. This is a plain textual substitution:
 * the template is NEVER interpreted as a fmt/printf format string, so an
 * attacker-supplied spec such as "{stream_name:>1500000000}" is copied
 * verbatim (and rejected upstream by validate_push_url) rather than expanded
 * into a multi-gigabyte string (CWE-134 format-string DoS).
 */
std::string sls_substitute_stream_name(const std::string &url_template,
                                       const std::string &stream_name);

/**
 * Default hard deadline (milliseconds) for resolving a push-destination host
 * name. A literal IPv4/IPv6 host resolves inline with no network and no thread;
 * a real host name is resolved on a SEPARATE thread and the caller waits at
 * most this long. If the lookup does not finish in time the URL is rejected
 * (DnsFailure) so a slow or hostile DNS server can never stall the unrelated
 * streams that share the SRT epoll worker. Operators tune the effective value
 * with the `push_url_dns_timeout_ms` srt directive (0 => this default).
 */
constexpr int kPushUrlDnsTimeoutDefaultMs = 5000;

/**
 * Validate one push destination URL against the per-app conf knobs.
 * Returns PushUrlReject::Ok if the URL is acceptable. Otherwise returns a
 * reject reason; caller should log it and drop the URL.
 *
 * DNS resolution NEVER blocks the calling thread indefinitely: a numeric host
 * is resolved inline, while a host name is resolved on a dedicated thread and
 * abandoned past kPushUrlDnsTimeoutDefaultMs (or the operator-configured
 * push_url_dns_timeout_ms). This makes the function safe to reach from the SRT
 * epoll worker — a stuck resolver bounds out instead of wedging every stream on
 * that worker.
 *
 * `bind_addresses` is the set of local-listener addresses to compare
 * against when push_destination_allow_self is false. Pass an empty vector
 * to skip that check.
 */
PushUrlReject validate_push_url(const std::string &url,
                                const sls_conf_app_t &app_conf,
                                const std::vector<std::string> &bind_addresses);

/**
 * Returns the cached list of bind addresses from getifaddrs(). Cached on
 * first call. Loopback addresses are intentionally excluded; the loopback
 * check is handled by the allow_internal flag.
 */
const std::vector<std::string> &push_url_self_addresses();
