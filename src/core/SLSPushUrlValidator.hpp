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
};

const char *push_url_reject_reason(PushUrlReject reason);

/**
 * Validate one push destination URL against the per-app conf knobs.
 * Returns PushUrlReject::Ok if the URL is acceptable. Otherwise returns a
 * reject reason; caller should log it and drop the URL.
 *
 * Performs DNS resolution synchronously via getaddrinfo, so it is safe to
 * call from the publisher handler thread but not from the SRT epoll loop.
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
