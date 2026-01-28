
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

#include "SLSRole.hpp"
#include "SLSMapPublisher.hpp"

/**
 * SRT URL options parsed from query parameters
 * All values of -1 indicate "use default" (not specified in URL)
 */
struct SRTUrlOptions {
    // Stream identification (required)
    char streamid[URL_MAX_LEN] = {0};

    // Timing options
    int latency = -1;           // SRTO_LATENCY: latency in ms (0-10000, default 120)
    int connect_timeout = -1;   // SRTO_CONNTIMEO: connect timeout in ms (0-30000)

    // Encryption options
    char passphrase[80] = {0};  // SRTO_PASSPHRASE: max 79 chars + null
    int pbkeylen = -1;          // SRTO_PBKEYLEN: 0 (disabled), 16, 24, or 32

    // Bandwidth options
    int64_t maxbw = -1;         // SRTO_MAXBW: max bandwidth bytes/sec (0=infinite, -1=auto)
    int64_t inputbw = -1;       // SRTO_INPUTBW: input bandwidth estimate bytes/sec
    int oheadbw = -1;           // SRTO_OHEADBW: overhead bandwidth % (5-100)

    // Buffer options
    int rcvbuf = -1;            // SRTO_RCVBUF: receive buffer size bytes
    int sndbuf = -1;            // SRTO_SNDBUF: send buffer size bytes
    int fc = -1;                // SRTO_FC: flight flag size (flow control window)

    // Network options
    int mss = -1;               // SRTO_MSS: max segment size (76-1500)
    int lossmaxttl = -1;        // SRTO_LOSSMAXTTL: packet reorder tolerance (0-1000)
    int ipttl = -1;             // SRTO_IPTTL: IP time-to-live (1-255)
    int iptos = -1;             // SRTO_IPTOS: IP type of service (0-255)

    // Reliability options
    int tlpktdrop = -1;         // SRTO_TLPKTDROP: too-late packet drop (0 or 1)
    int nakreport = -1;         // SRTO_NAKREPORT: periodic NAK reports (0 or 1)
};

/**
 * sls_conf_relay_t
 */

SLS_CONF_DYNAMIC_DECLARE_BEGIN(relay)
char type[32];
char mode[32];
char upstreams[1024];
int reconnect_interval;
int idle_streams_timeout;
SLS_CONF_DYNAMIC_DECLARE_END

/**
 * relay cmd declare
 */

SLS_CONF_CMD_DYNAMIC_DECLARE_BEGIN(relay)
SLS_SET_CONF(relay, string, type, "pull, push", 1, 31),
    SLS_SET_CONF(relay, string, mode, "relay mode.", 1, 31),
    SLS_SET_CONF(relay, string, upstreams, "upstreams", 1, 1023),
    SLS_SET_CONF(relay, int, reconnect_interval, "reconnect interval, unit s", 1, 3600),
    SLS_SET_CONF(relay, int, idle_streams_timeout, "idle streams timeout, unit s", -1, 3600),

    SLS_CONF_CMD_DYNAMIC_DECLARE_END

    enum SLS_PULL_MODE { SLS_PM_LOOP = 0,
                         SLS_PM_HASH = 1,
                         SLS_PM_ALL = 2,
    };

/**
 * CSLSRelay
 */
class CSLSRelay : public CSLSRole
{
public:
    CSLSRelay();
    virtual ~CSLSRelay();

    virtual int uninit();

    void set_map_publisher(CSLSMapPublisher *publisher);
    void set_relay_manager(void *relay_manager);
    void *get_relay_manager();
    char *get_url();

    int open(const char *url);
    virtual int close();
    virtual int get_peer_info(char *peer_name, int &peer_port);
    virtual int get_stat_base(char *stat_base);

protected:
    char m_url[URL_MAX_LEN];
    char m_upstream[URL_MAX_LEN];
    char m_server_ip[IP_MAX_LEN];
    int m_server_port;

    CSLSMapPublisher *m_map_publisher;
    void *m_relay_manager;

    int parse_url(char *url, char *host_name, size_t host_name_size, int &port, SRTUrlOptions &options);
};
