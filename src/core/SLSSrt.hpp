
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

#include <srt/srt.h>
#include <netinet/in.h>

enum SRTMode
{
    SRT_MODE_CALLER = 0,
    SRT_MODE_LISTENER = 1,
    SRT_MODE_RENDEZVOUS = 2
};

typedef struct SRTContext
{
    SRTSOCKET fd;
    int eid;
    int flag;
    int port;
    char hostname[1024];
    int reuse;
    int backlog;

    int64_t rw_timeout;
    int64_t listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;

    int64_t maxbw;
    int pbkeylen;
    char *passphrase;
    int mss;
    int ffs;
    int ipttl;
    int iptos;
    int64_t inputbw;
    int oheadbw;
    int64_t latency;
    int tlpktdrop;
    int nakreport;
    int64_t connect_timeout;
    int payload_size;
    int64_t rcvlatency;
    int64_t peerlatency;
    enum SRTMode mode;
    int sndbuf;
    int rcvbuf;
    int lossmaxttl;
    int minversion;
    char *streamid;
    char *smoother;
    int messageapi;
    SRT_TRANSTYPE transtype;
    double mbpsBandwidth;
    double msRTT;
} SRTContext;

/**
 * CSLSSrt ,functions of srt
 */
class CSLSSrt
{
public:
    CSLSSrt();
    ~CSLSSrt();

    static int libsrt_init();
    static int libsrt_uninit();
    static int libsrt_epoll_create();
    static void libsrt_epoll_release(int eid);

    void libsrt_set_context(SRTContext *sc);

    int libsrt_setup(int port, bool srtla_patches = false);
    int libsrt_close();

    int libsrt_listen(int backlog);
    int libsrt_set_listen_callback(srt_listen_callback_fn * listen_callback_fn);
    int libsrt_accept();

    int libsrt_get_fd();
    int libsrt_set_fd(int fd);

    int libsrt_set_eid(int eid);

    int libsrt_read(char *buf, int size);
    int libsrt_write(const char *buf, int size);

    int libsrt_socket_nonblock(int enable);

    int libsrt_getsockopt(SRT_SOCKOPT optname, const char *optnamestr, void *optval, int *optlen);
    int libsrt_setsockopt(SRT_SOCKOPT optname, const char *optnamestr, const void *optval, int optlen);

    std::map<std::string, std::string>  libsrt_parse_sid(char *sid);

    int libsrt_add_to_epoll(int eid, bool write);
    int libsrt_remove_from_epoll();

    int libsrt_getsockstate();
    int libsrt_getpeeraddr(char *peer_name, int &port);
    int libsrt_getpeeraddr_raw(unsigned long &address, struct in6_addr &address6);
    int libsrt_get_statistics(SRT_TRACEBSTATS *currentStats, int clear);

    void libsrt_set_latency(int latency);

    static int libsrt_neterrno();
    static void libsrt_print_error_info();

protected:
    SRTContext m_sc;
    char m_peer_name[256]; //peer ip addr, such as 172.12.22.14
    int m_peer_port;
    unsigned long m_peer_addr_raw;  //  Peer IP addr in unsigned long format
    struct in6_addr m_peer_addr6_raw; // IPv6 address
    bool m_is_ipv6;                 // Flag to indicate if the address is IPv6

private:
    static bool m_inited;
};
