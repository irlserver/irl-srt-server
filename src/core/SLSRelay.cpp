
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

#include <errno.h>
#include "spdlog/spdlog.h"

#include "CxxUrl.hpp"
#include "SLSRelay.hpp"
#include "SLSLog.hpp"
#include "SLSRelayManager.hpp"
#include "util.hpp"

#define DEFAULT_LATENCY 120

// SRT option limits
#define LATENCY_MIN 0
#define LATENCY_MAX 10000
#define CONNECT_TIMEOUT_MIN 0
#define CONNECT_TIMEOUT_MAX 30000
#define PASSPHRASE_MAX_LEN 79
#define PBKEYLEN_VALID_0 0
#define PBKEYLEN_VALID_16 16
#define PBKEYLEN_VALID_24 24
#define PBKEYLEN_VALID_32 32
#define MSS_MIN 76
#define MSS_MAX 1500
#define OHEADBW_MIN 5
#define OHEADBW_MAX 100
#define LOSSMAXTTL_MIN 0
#define LOSSMAXTTL_MAX 1000
#define IPTTL_MIN 1
#define IPTTL_MAX 255
#define IPTOS_MIN 0
#define IPTOS_MAX 255
#define FC_MIN 32
#define FC_MAX 1000000
#define BUFFER_MIN 0
#define BUFFER_MAX (1024 * 1024 * 1024)  // 1GB max buffer

/**
 * relay conf
 */
SLS_CONF_DYNAMIC_IMPLEMENT(relay)

/**
 * CSLSRelay class implementation
 */

CSLSRelay::CSLSRelay()
{
    m_is_write = 0;
    memset(m_url, 0, URL_MAX_LEN);
    memset(m_server_ip, 0, IP_MAX_LEN);

    m_server_port = 0;
    m_map_publisher = NULL;
    m_relay_manager = NULL;
    m_need_reconnect = true;

    sprintf(m_role_name, "relay");
}

CSLSRelay::~CSLSRelay()
{
    // release
}

int CSLSRelay::uninit()
{
    // for reconnect
    if (NULL != m_relay_manager)
    {
        ((CSLSRelayManager *)m_relay_manager)->add_reconnect_stream(m_url);
        spdlog::info("[{}] CSLSRelay::uninit, add_reconnect_stream, m_url={}.",
                     fmt::ptr(this), m_url);
    }

    return CSLSRole::uninit();
}

void CSLSRelay::set_map_publisher(CSLSMapPublisher *map_publisher)
{
    m_map_publisher = map_publisher;
}

void CSLSRelay::set_relay_manager(void *relay_manager)
{
    m_relay_manager = relay_manager;
}

void *CSLSRelay::get_relay_manager()
{
    return m_relay_manager;
}

// Helper to parse integer with bounds checking
static bool parse_int_option(const std::string &val, int &out, int min_val, int max_val, const char *name, void *ctx)
{
    try {
        int parsed = std::stoi(val);
        if (parsed < min_val || parsed > max_val) {
            spdlog::warn("[{}] CSLSRelay::parse_url {} value {} out of range [{}-{}], ignoring",
                         fmt::ptr(ctx), name, parsed, min_val, max_val);
            return false;
        }
        out = parsed;
        return true;
    } catch (const std::exception &) {
        spdlog::warn("[{}] CSLSRelay::parse_url invalid {} value '{}', ignoring",
                     fmt::ptr(ctx), name, val);
        return false;
    }
}

// Helper to parse int64 with bounds checking
static bool parse_int64_option(const std::string &val, int64_t &out, int64_t min_val, int64_t max_val, const char *name, void *ctx)
{
    try {
        int64_t parsed = std::stoll(val);
        if (parsed < min_val || parsed > max_val) {
            spdlog::warn("[{}] CSLSRelay::parse_url {} value {} out of range [{}-{}], ignoring",
                         fmt::ptr(ctx), name, parsed, min_val, max_val);
            return false;
        }
        out = parsed;
        return true;
    } catch (const std::exception &) {
        spdlog::warn("[{}] CSLSRelay::parse_url invalid {} value '{}', ignoring",
                     fmt::ptr(ctx), name, val);
        return false;
    }
}

int CSLSRelay::parse_url(char *url, char *host_name, size_t host_name_size, int &port, SRTUrlOptions &options)
{
    // Parse the URL
    Url parsed_url(url);
    string scheme;
    bool streamid_found = false;
    try
    {
        // Check if URL scheme is correct
        scheme = parsed_url.scheme();
        if (scheme.compare("srt") != 0)
        {
            spdlog::error("[{}] CSLSRelay::parse_url invalid URL scheme [scheme='{}']", fmt::ptr(this), scheme);
            return SLS_ERROR;
        }
        // Copy hostname
        strlcpy(host_name, parsed_url.host().c_str(), host_name_size);
        // Set port
        port = stoi(parsed_url.port());

        for (Url::KeyVal query_param : parsed_url.query())
        {
            const std::string &key = query_param.key();
            const std::string &val = query_param.val();

            if (key == "streamid")
            {
                streamid_found = true;
                strlcpy(options.streamid, val.c_str(), sizeof(options.streamid));
            }
            else if (key == "latency")
            {
                parse_int_option(val, options.latency, LATENCY_MIN, LATENCY_MAX, "latency", this);
            }
            else if (key == "connect_timeout" || key == "conntimeo")
            {
                parse_int_option(val, options.connect_timeout, CONNECT_TIMEOUT_MIN, CONNECT_TIMEOUT_MAX, "connect_timeout", this);
            }
            else if (key == "passphrase")
            {
                if (val.length() > PASSPHRASE_MAX_LEN) {
                    spdlog::warn("[{}] CSLSRelay::parse_url passphrase too long (max {} chars), ignoring",
                                 fmt::ptr(this), PASSPHRASE_MAX_LEN);
                } else if (val.length() < 10) {
                    spdlog::warn("[{}] CSLSRelay::parse_url passphrase too short (min 10 chars), ignoring",
                                 fmt::ptr(this));
                } else {
                    strlcpy(options.passphrase, val.c_str(), sizeof(options.passphrase));
                }
            }
            else if (key == "pbkeylen")
            {
                int keylen = 0;
                if (parse_int_option(val, keylen, 0, 32, "pbkeylen", this)) {
                    // Only allow valid key lengths: 0, 16, 24, 32
                    if (keylen == PBKEYLEN_VALID_0 || keylen == PBKEYLEN_VALID_16 ||
                        keylen == PBKEYLEN_VALID_24 || keylen == PBKEYLEN_VALID_32) {
                        options.pbkeylen = keylen;
                    } else {
                        spdlog::warn("[{}] CSLSRelay::parse_url pbkeylen must be 0, 16, 24, or 32, ignoring value {}",
                                     fmt::ptr(this), keylen);
                    }
                }
            }
            else if (key == "maxbw")
            {
                parse_int64_option(val, options.maxbw, -1, INT64_MAX, "maxbw", this);
            }
            else if (key == "inputbw")
            {
                parse_int64_option(val, options.inputbw, 0, INT64_MAX, "inputbw", this);
            }
            else if (key == "oheadbw")
            {
                parse_int_option(val, options.oheadbw, OHEADBW_MIN, OHEADBW_MAX, "oheadbw", this);
            }
            else if (key == "rcvbuf")
            {
                parse_int_option(val, options.rcvbuf, BUFFER_MIN, BUFFER_MAX, "rcvbuf", this);
            }
            else if (key == "sndbuf")
            {
                parse_int_option(val, options.sndbuf, BUFFER_MIN, BUFFER_MAX, "sndbuf", this);
            }
            else if (key == "fc")
            {
                parse_int_option(val, options.fc, FC_MIN, FC_MAX, "fc", this);
            }
            else if (key == "mss")
            {
                parse_int_option(val, options.mss, MSS_MIN, MSS_MAX, "mss", this);
            }
            else if (key == "lossmaxttl")
            {
                parse_int_option(val, options.lossmaxttl, LOSSMAXTTL_MIN, LOSSMAXTTL_MAX, "lossmaxttl", this);
            }
            else if (key == "ipttl")
            {
                parse_int_option(val, options.ipttl, IPTTL_MIN, IPTTL_MAX, "ipttl", this);
            }
            else if (key == "iptos")
            {
                parse_int_option(val, options.iptos, IPTOS_MIN, IPTOS_MAX, "iptos", this);
            }
            else if (key == "tlpktdrop")
            {
                parse_int_option(val, options.tlpktdrop, 0, 1, "tlpktdrop", this);
            }
            else if (key == "nakreport")
            {
                parse_int_option(val, options.nakreport, 0, 1, "nakreport", this);
            }
        }
    }
    catch (Url::parse_error const &error)
    {
        spdlog::error("[{}] CSLSRelay::parse_url error [{}]",
                      fmt::ptr(this), error.what());
        spdlog::error("[{}] CSLSRelay::parse_url URL should be in format 'srt://hostname:port?streamid=your_stream_id'",
                      fmt::ptr(this));
        return SLS_ERROR;
    }

    if (!streamid_found)
    {
        spdlog::error("[{}] CSLSRelay::parse_url query parameter 'streamid' not found in URL '{}'",
                      fmt::ptr(this), url);
        spdlog::error("[{}] CSLSRelay::parse_url URL should be in format 'srt://hostname:port?streamid=your_stream_id'",
                      fmt::ptr(this));
        return SLS_ERROR;
    }

    if (options.latency == -1)
    {
        options.latency = DEFAULT_LATENCY;
        spdlog::debug("[{}] CSLSRelay::parse_url using default latency {}ms", fmt::ptr(this), DEFAULT_LATENCY);
    }

    spdlog::debug("[{}] CSLSRelay::parse_url parsed URL: {}:{} streamid='{}'", fmt::ptr(this), host_name, port, options.streamid);

    return SLS_OK;
}

// Helper macro for setting socket options with error handling
#define SET_SOCKOPT(fd, opt, val, desc) do { \
    if (srt_setsockopt(fd, 0, opt, &val, sizeof(val)) == SRT_ERROR) { \
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt {} failure. err={}.", fmt::ptr(this), desc, srt_getlasterror_str()); \
        srt_close(fd); \
        return SLS_ERROR; \
    } \
} while(0)

#define SET_SOCKOPT_STR(fd, opt, val, len, desc) do { \
    if (srt_setsockopt(fd, 0, opt, val, len) == SRT_ERROR) { \
        spdlog::error("[{}] CSLSRelay::open, srt_setsockopt {} failure. err={}.", fmt::ptr(this), desc, srt_getlasterror_str()); \
        srt_close(fd); \
        return SLS_ERROR; \
    } \
} while(0)

int CSLSRelay::open(const char *srt_url)
{
    const int bool_false = 0;
    const int bool_true = 1;

    int ret;
    char host_name[HOST_MAX_LEN] = {};
    char server_ip[IP_MAX_LEN] = {};
    int server_port = 0;
    char url[URL_MAX_LEN] = {};
    SRTUrlOptions options;

    if (strnlen(srt_url, URL_MAX_LEN) >= URL_MAX_LEN)
    {
        spdlog::error("[{}] CSLSRelay::open invalid URL [url='{}']", fmt::ptr(this), srt_url);
        return SLS_ERROR;
    }
    strncpy(m_url, srt_url, sizeof(m_url) - 1);
    strncpy(url, srt_url, sizeof(url) - 1);

    // init listener
    if (NULL != m_srt)
    {
        spdlog::error("[{}] CSLSRelay::open, failure, url='{}', m_srt = {}, not NULL.", fmt::ptr(this), url, fmt::ptr(m_srt));
        return SLS_ERROR;
    }

    // parse url
    if (SLS_OK != parse_url(url, host_name, sizeof(host_name), server_port, options))
    {
        return SLS_ERROR;
    }
    spdlog::info("[{}] CSLSRelay::open, parse_url ok, url='{}'.", fmt::ptr(this), m_url);

    if ((ret = strnlen(options.streamid, URL_MAX_LEN)) == 0)
    {
        spdlog::error("[{}] CSLSRelay::open, url='{}', no 'stream', url must be like 'hostname:port?streamid=your_stream_id'.", fmt::ptr(this), m_url);
        return SLS_ERROR;
    }
    else if (ret >= URL_MAX_LEN)
    {
        spdlog::error("[{}] CSLSRelay::open, url='{}', 'stream' too long.", fmt::ptr(this), m_url);
        return SLS_ERROR;
    }

    SRTSOCKET fd = srt_create_socket();
    if (fd == SRT_INVALID_SOCK)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_create_socket failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    int status;

    // === Required options ===
    SET_SOCKOPT(fd, SRTO_LATENCY, options.latency, "SRTO_LATENCY");
    SET_SOCKOPT(fd, SRTO_SNDSYN, bool_false, "SRTO_SNDSYN");  // async write
    SET_SOCKOPT(fd, SRTO_RCVSYN, bool_false, "SRTO_RCVSYN");  // async read

    // === Default socket options ===
    int ipv6Only = 0;
    int default_fc = 128 * 1000;
    int default_lossmaxttl = 200;
    int default_rcv_buf = 100 * 1024 * 1024;

    SET_SOCKOPT(fd, SRTO_IPV6ONLY, ipv6Only, "SRTO_IPV6ONLY");

    // === Optional URL-specified options ===

    // Connection timeout
    if (options.connect_timeout >= 0) {
        SET_SOCKOPT(fd, SRTO_CONNTIMEO, options.connect_timeout, "SRTO_CONNTIMEO");
        spdlog::debug("[{}] CSLSRelay::open, set connect_timeout={}ms", fmt::ptr(this), options.connect_timeout);
    }

    // Encryption options
    if (strlen(options.passphrase) > 0) {
        SET_SOCKOPT_STR(fd, SRTO_PASSPHRASE, options.passphrase, strlen(options.passphrase), "SRTO_PASSPHRASE");
        spdlog::debug("[{}] CSLSRelay::open, set passphrase (length={})", fmt::ptr(this), strlen(options.passphrase));
    }
    if (options.pbkeylen >= 0) {
        SET_SOCKOPT(fd, SRTO_PBKEYLEN, options.pbkeylen, "SRTO_PBKEYLEN");
        spdlog::debug("[{}] CSLSRelay::open, set pbkeylen={}", fmt::ptr(this), options.pbkeylen);
    }

    // Bandwidth options
    if (options.maxbw >= 0) {
        SET_SOCKOPT(fd, SRTO_MAXBW, options.maxbw, "SRTO_MAXBW");
        spdlog::debug("[{}] CSLSRelay::open, set maxbw={}", fmt::ptr(this), options.maxbw);
    }
    if (options.inputbw >= 0) {
        SET_SOCKOPT(fd, SRTO_INPUTBW, options.inputbw, "SRTO_INPUTBW");
        spdlog::debug("[{}] CSLSRelay::open, set inputbw={}", fmt::ptr(this), options.inputbw);
    }
    if (options.oheadbw >= 0) {
        SET_SOCKOPT(fd, SRTO_OHEADBW, options.oheadbw, "SRTO_OHEADBW");
        spdlog::debug("[{}] CSLSRelay::open, set oheadbw={}%", fmt::ptr(this), options.oheadbw);
    }

    // Buffer options - use URL values if specified, otherwise defaults
    int fc_value = (options.fc >= 0) ? options.fc : default_fc;
    SET_SOCKOPT(fd, SRTO_FC, fc_value, "SRTO_FC");
    if (options.fc >= 0) {
        spdlog::debug("[{}] CSLSRelay::open, set fc={}", fmt::ptr(this), options.fc);
    }

    int rcvbuf_value = (options.rcvbuf >= 0) ? options.rcvbuf : default_rcv_buf;
    SET_SOCKOPT(fd, SRTO_RCVBUF, rcvbuf_value, "SRTO_RCVBUF");
    if (options.rcvbuf >= 0) {
        spdlog::debug("[{}] CSLSRelay::open, set rcvbuf={}", fmt::ptr(this), options.rcvbuf);
    }

    if (options.sndbuf >= 0) {
        SET_SOCKOPT(fd, SRTO_SNDBUF, options.sndbuf, "SRTO_SNDBUF");
        spdlog::debug("[{}] CSLSRelay::open, set sndbuf={}", fmt::ptr(this), options.sndbuf);
    }

    // Network options
    int lossmaxttl_value = (options.lossmaxttl >= 0) ? options.lossmaxttl : default_lossmaxttl;
    SET_SOCKOPT(fd, SRTO_LOSSMAXTTL, lossmaxttl_value, "SRTO_LOSSMAXTTL");
    if (options.lossmaxttl >= 0) {
        spdlog::debug("[{}] CSLSRelay::open, set lossmaxttl={}", fmt::ptr(this), options.lossmaxttl);
    }

    if (options.mss >= 0) {
        SET_SOCKOPT(fd, SRTO_MSS, options.mss, "SRTO_MSS");
        spdlog::debug("[{}] CSLSRelay::open, set mss={}", fmt::ptr(this), options.mss);
    }
    if (options.ipttl >= 0) {
        SET_SOCKOPT(fd, SRTO_IPTTL, options.ipttl, "SRTO_IPTTL");
        spdlog::debug("[{}] CSLSRelay::open, set ipttl={}", fmt::ptr(this), options.ipttl);
    }
    if (options.iptos >= 0) {
        SET_SOCKOPT(fd, SRTO_IPTOS, options.iptos, "SRTO_IPTOS");
        spdlog::debug("[{}] CSLSRelay::open, set iptos={}", fmt::ptr(this), options.iptos);
    }

    // Reliability options
    if (options.tlpktdrop >= 0) {
        SET_SOCKOPT(fd, SRTO_TLPKTDROP, options.tlpktdrop, "SRTO_TLPKTDROP");
        spdlog::debug("[{}] CSLSRelay::open, set tlpktdrop={}", fmt::ptr(this), options.tlpktdrop);
    }
    if (options.nakreport >= 0) {
        SET_SOCKOPT(fd, SRTO_NAKREPORT, options.nakreport, "SRTO_NAKREPORT");
        spdlog::debug("[{}] CSLSRelay::open, set nakreport={}", fmt::ptr(this), options.nakreport);
    }

    // Stream ID (required)
    SET_SOCKOPT_STR(fd, SRTO_STREAMID, options.streamid, strlen(options.streamid), "SRTO_STREAMID");

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(server_port);

    sls_gethostbyname(host_name, server_ip);
    if (inet_pton(AF_INET, server_ip, &sa.sin_addr) != 1)
    {
        spdlog::error("[{}] CSLSRelay::open, inet_pton failure. server_ip={}, server_port={:d}.", fmt::ptr(this), server_ip, server_port);
        srt_close(fd);
        return SLS_ERROR;
    }

    struct sockaddr *psa = (struct sockaddr *)&sa;
    status = srt_connect(fd, psa, sizeof sa);
    if (status == SRT_ERROR)
    {
        spdlog::error("[{}] CSLSRelay::open, srt_connect failure. server_ip={}, server_port={:d}, err={}.",
                      fmt::ptr(this), server_ip, server_port, srt_getlasterror_str());
        srt_close(fd);
        return SLS_ERROR;
    }
    m_srt = new CSLSSrt();
    m_srt->libsrt_set_fd(fd);
    strlcpy(m_server_ip, server_ip, sizeof(m_server_ip));
    m_server_port = server_port;
    return status;
}

#undef SET_SOCKOPT
#undef SET_SOCKOPT_STR

int CSLSRelay::close()
{
    int ret = SLS_OK;
    if (m_srt)
    {
        spdlog::info("[{}] CSLSRelay::close, ok, url='{}'.", fmt::ptr(this), m_url);
        ret = m_srt->libsrt_close();
        delete m_srt;
        m_srt = NULL;
    }
    return ret;
}

char *CSLSRelay::get_url()
{
    return m_url;
}

int CSLSRelay::get_peer_info(char *peer_name, int &peer_port)
{
    strcpy(peer_name, m_server_ip);
    peer_port = m_server_port;
    return SLS_OK;
}

int CSLSRelay::get_stat_base(char *stat_base)
{
    return SLS_OK;
}
