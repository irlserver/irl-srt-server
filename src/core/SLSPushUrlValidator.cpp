#include "SLSPushUrlValidator.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ifaddrs.h>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

#include "SLSLogCategory.hpp"
#include "SLSManager.hpp"
#include "conf.hpp"
#include "url.hpp"

namespace {

constexpr int kDefaultMaxUrlLen = 1024;
const char *kDefaultAllowSchemes = "srt";

bool scheme_allowed(const std::string &scheme, const char *allow_list) {
    if (!allow_list || !*allow_list) {
        // Default whitelist when operator left the conf empty.
        return scheme == "srt";
    }
    const std::string list(allow_list);
    size_t pos = 0;
    while (pos < list.size()) {
        while (pos < list.size() && (list[pos] == ' ' || list[pos] == '\t' ||
                                     list[pos] == ',' || list[pos] == ';')) {
            ++pos;
        }
        size_t start = pos;
        while (pos < list.size() && list[pos] != ' ' && list[pos] != '\t' &&
               list[pos] != ',' && list[pos] != ';') {
            ++pos;
        }
        if (start < pos) {
            if (list.compare(start, pos - start, scheme) == 0) {
                return true;
            }
        }
    }
    return false;
}

bool ipv4_in_cidr(uint32_t addr_host_order, const char *base, int prefix) {
    in_addr base_addr{};
    if (inet_pton(AF_INET, base, &base_addr) != 1) return false;
    uint32_t base_host = ntohl(base_addr.s_addr);
    uint32_t mask = prefix == 0 ? 0u : (~0u << (32 - prefix));
    return (addr_host_order & mask) == (base_host & mask);
}

bool is_loopback_v4(uint32_t addr_host_order) {
    return ipv4_in_cidr(addr_host_order, "127.0.0.0", 8);
}

bool is_link_local_v4(uint32_t addr_host_order) {
    return ipv4_in_cidr(addr_host_order, "169.254.0.0", 16);
}

bool is_private_v4(uint32_t addr_host_order) {
    return ipv4_in_cidr(addr_host_order, "10.0.0.0", 8) ||
           ipv4_in_cidr(addr_host_order, "172.16.0.0", 12) ||
           ipv4_in_cidr(addr_host_order, "192.168.0.0", 16);
}

bool is_loopback_v6(const in6_addr &a) {
    static const in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
    return memcmp(&a, &loopback, sizeof(in6_addr)) == 0;
}

bool is_link_local_v6(const in6_addr &a) {
    // fe80::/10
    return a.s6_addr[0] == 0xfe && (a.s6_addr[1] & 0xc0) == 0x80;
}

bool is_ula_v6(const in6_addr &a) {
    // fc00::/7
    return (a.s6_addr[0] & 0xfe) == 0xfc;
}

struct AddrCategory {
    bool loopback = false;
    bool link_local = false;
    bool privnet = false;
};

AddrCategory categorize_addr(const sockaddr *sa) {
    AddrCategory c;
    if (sa->sa_family == AF_INET) {
        uint32_t v = ntohl(reinterpret_cast<const sockaddr_in *>(sa)->sin_addr.s_addr);
        c.loopback = is_loopback_v4(v);
        c.link_local = is_link_local_v4(v);
        c.privnet = is_private_v4(v);
    } else if (sa->sa_family == AF_INET6) {
        const in6_addr &v = reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr;
        c.loopback = is_loopback_v6(v);
        c.link_local = is_link_local_v6(v);
        c.privnet = is_ula_v6(v);
    }
    return c;
}

std::string addr_to_string(const sockaddr *sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr,
                  buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        inet_ntop(AF_INET6,
                  &reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr,
                  buf, sizeof(buf));
    }
    return std::string(buf);
}

std::vector<std::string> discover_self_addresses() {
    std::vector<std::string> out;
    ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        spdlog::warn("[relay] push validator: getifaddrs failed, deny_self will be best-effort");
        return out;
    }
    for (ifaddrs *it = ifaddr; it != nullptr; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        const sockaddr *sa = it->ifa_addr;
        if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) continue;
        AddrCategory c = categorize_addr(sa);
        // Loopback is handled by allow_internal, not allow_self.
        if (c.loopback) continue;
        out.push_back(addr_to_string(sa));
    }
    freeifaddrs(ifaddr);
    return out;
}

bool addr_matches_any(const sockaddr *sa, const std::vector<std::string> &list) {
    if (list.empty()) return false;
    std::string s = addr_to_string(sa);
    for (const auto &entry : list) {
        if (entry == s) return true;
    }
    return false;
}

} // namespace

const char *push_url_reject_reason(PushUrlReject reason) {
    switch (reason) {
    case PushUrlReject::Ok: return "ok";
    case PushUrlReject::TooLong: return "too_long";
    case PushUrlReject::InvalidUrl: return "invalid_url";
    case PushUrlReject::WrongScheme: return "wrong_scheme";
    case PushUrlReject::MissingHost: return "missing_host";
    case PushUrlReject::MissingStreamid: return "missing_streamid";
    case PushUrlReject::DnsFailure: return "dns_failure";
    case PushUrlReject::DenyInternal: return "deny_internal";
    case PushUrlReject::DenySelf: return "deny_self";
    case PushUrlReject::BadPlaceholder: return "bad_placeholder";
    }
    return "unknown";
}

const char *const kPushUrlStreamNameToken = "{stream_name}";

std::string sls_substitute_stream_name(const std::string &url_template,
                                       const std::string &stream_name) {
    const std::string token(kPushUrlStreamNameToken);
    std::string out;
    out.reserve(url_template.size());
    size_t pos = 0;
    for (;;) {
        size_t hit = url_template.find(token, pos);
        if (hit == std::string::npos) {
            out.append(url_template, pos, std::string::npos);
            break;
        }
        out.append(url_template, pos, hit - pos);
        out.append(stream_name);
        pos = hit + token.size();
    }
    return out;
}

namespace {

// After removing every {stream_name} token, a residual '{' or '}' is an
// attacker fmt spec ({stream_name:>1500000000}) or unknown placeholder ({foo}).
bool has_stray_brace(const std::string &url) {
    const std::string stripped = sls_substitute_stream_name(url, std::string());
    return stripped.find('{') != std::string::npos ||
           stripped.find('}') != std::string::npos;
}

void collect_addrinfo(const addrinfo *results,
                      std::vector<sockaddr_storage> &out) {
    for (const addrinfo *it = results; it != nullptr; it = it->ai_next) {
        if (it->ai_addr == nullptr || it->ai_addrlen == 0) continue;
        sockaddr_storage ss{};
        size_t n = it->ai_addrlen <= sizeof(ss) ? it->ai_addrlen : sizeof(ss);
        memcpy(&ss, it->ai_addr, n);
        out.push_back(ss);
    }
}

// AI_NUMERICHOST resolves an IPv4/IPv6 literal with no network and no thread,
// and returns EAI_NONAME for a real host name (which then takes the off-thread
// path). Returns the gai code; addrs is filled on success.
int resolve_numeric(const char *host, const char *service,
                    std::vector<sockaddr_storage> &addrs) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo *results = nullptr;
    int gai = getaddrinfo(host, service, &hints, &results);
    if (gai == 0 && results) collect_addrinfo(results, addrs);
    if (results) freeaddrinfo(results);
    return gai;
}

// Rendezvous between the SRT worker (waiter) and a detached resolver thread.
// On timeout the worker abandons it, but the resolver still holds a shared_ptr
// copy, so the state outlives the worker's wait and the late getaddrinfo result
// is freed by the resolver itself — no dangling pointer, no blocked worker.
struct ResolveRendezvous {
    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    int gai = EAI_AGAIN;
    std::vector<sockaddr_storage> addrs;
};

// Resolve `host` on a dedicated thread and wait at most `timeout_ms`. Returns
// false on timeout (the detached thread frees its own addrinfo in the
// background); on success returns true and moves the addresses into `addrs`.
bool resolve_with_timeout(const std::string &host, const std::string &service,
                          int timeout_ms, int &gai_out,
                          std::vector<sockaddr_storage> &addrs) {
    auto rv = std::make_shared<ResolveRendezvous>();
    std::thread([rv, host, service]() {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo *results = nullptr;
        int gai = getaddrinfo(host.c_str(),
                              service.empty() ? nullptr : service.c_str(),
                              &hints, &results);
        std::vector<sockaddr_storage> local;
        if (gai == 0 && results) collect_addrinfo(results, local);
        if (results) freeaddrinfo(results);
        {
            std::lock_guard<std::mutex> lk(rv->mtx);
            rv->gai = gai;
            rv->addrs = std::move(local);
            rv->done = true;
        }
        rv->cv.notify_one();
    }).detach();

    std::unique_lock<std::mutex> lk(rv->mtx);
    if (!rv->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                         [&] { return rv->done; })) {
        return false;
    }
    gai_out = rv->gai;
    addrs = std::move(rv->addrs);
    return true;
}

// Operator-tuned deadline (srt push_url_dns_timeout_ms), else the built-in
// default. The root conf is NULL in unit tests with no loaded config.
int push_url_dns_timeout_ms() {
    const sls_conf_srt_t *root =
        reinterpret_cast<const sls_conf_srt_t *>(sls_conf_get_root_conf());
    if (root && root->push_url_dns_timeout_ms > 0) {
        return root->push_url_dns_timeout_ms;
    }
    return kPushUrlDnsTimeoutDefaultMs;
}

} // namespace

const std::vector<std::string> &push_url_self_addresses() {
    static std::once_flag once;
    static std::vector<std::string> cache;
    std::call_once(once, []() { cache = discover_self_addresses(); });
    return cache;
}

PushUrlReject validate_push_url(const std::string &url,
                                const sls_conf_app_t &app_conf,
                                const std::vector<std::string> &bind_addresses,
                                sockaddr_storage *vetted_addr) {
    int max_len = app_conf.push_destination_max_url_len > 0
                      ? app_conf.push_destination_max_url_len
                      : kDefaultMaxUrlLen;
    if (url.empty()) return PushUrlReject::InvalidUrl;
    if (static_cast<int>(url.size()) > max_len) return PushUrlReject::TooLong;
    if (has_stray_brace(url)) return PushUrlReject::BadPlaceholder;

    // Resolve the one legitimate template token to a benign value so the URL
    // parser (which rejects '{') sees a brace-free string and the structural /
    // DNS checks below run against what will actually be dialed.
    const std::string resolved = sls_substitute_stream_name(url, "streamname");

    std::string scheme;
    std::string host;
    std::string port_str;
    bool has_streamid = false;
    try {
        Url parsed(resolved);
        scheme = parsed.scheme();
        host = parsed.host();
        port_str = parsed.port();
        for (const Url::KeyVal &kv : parsed.query()) {
            if (kv.key() == "streamid" && !kv.val().empty()) {
                has_streamid = true;
                break;
            }
        }
    } catch (const std::exception &) {
        return PushUrlReject::InvalidUrl;
    }

    const char *allow_schemes = app_conf.push_destination_allow_schemes[0]
                                    ? app_conf.push_destination_allow_schemes
                                    : kDefaultAllowSchemes;
    if (!scheme_allowed(scheme, allow_schemes)) return PushUrlReject::WrongScheme;
    if (host.empty()) return PushUrlReject::MissingHost;
    if (!has_streamid) return PushUrlReject::MissingStreamid;

    std::vector<sockaddr_storage> addrs;
    const char *service = port_str.empty() ? nullptr : port_str.c_str();

    int gai = resolve_numeric(host.c_str(), service, addrs);
    if (gai != 0 || addrs.empty()) {
        // A real host name. getaddrinfo() has no native timeout, so resolve it
        // OFF this thread (this is reachable from the SRT epoll worker) and wait
        // only up to the deadline; a slow or hostile resolver is abandoned
        // instead of stalling every other stream sharing the worker.
        addrs.clear();
        const int timeout_ms = push_url_dns_timeout_ms();
        int async_gai = EAI_AGAIN;
        if (!resolve_with_timeout(host, port_str, timeout_ms, async_gai, addrs)) {
            spdlog::warn("[relay] push validator: DNS resolution exceeded {}ms "
                         "deadline, rejecting host='{}'",
                         timeout_ms, host);
            return PushUrlReject::DnsFailure;
        }
        gai = async_gai;
    }
    if (gai != 0 || addrs.empty()) {
        return PushUrlReject::DnsFailure;
    }

    PushUrlReject verdict = PushUrlReject::Ok;
    for (const sockaddr_storage &ss : addrs) {
        const sockaddr *sa = reinterpret_cast<const sockaddr *>(&ss);
        AddrCategory c = categorize_addr(sa);
        if (!app_conf.push_destination_allow_internal &&
            (c.loopback || c.link_local || c.privnet)) {
            verdict = PushUrlReject::DenyInternal;
            break;
        }
        if (!app_conf.push_destination_allow_self &&
            addr_matches_any(sa, bind_addresses)) {
            verdict = PushUrlReject::DenySelf;
            break;
        }
    }

    // Hand the caller the exact address that just passed every category check so
    // it can srt_connect to it directly. Re-resolving the host at connect time
    // is the DNS-rebinding TOCTOU this whole function exists to close: the loop
    // above only reaches Ok when no resolved address was internal/self, so the
    // first one is safe to dial.
    if (verdict == PushUrlReject::Ok && vetted_addr != nullptr && !addrs.empty()) {
        *vetted_addr = addrs.front();
    }
    return verdict;
}
