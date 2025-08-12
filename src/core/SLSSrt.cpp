
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
#include <string.h>
#include <map>
#include <string>
#include <memory.h>
#include "spdlog/spdlog.h"

#include "SLSSrt.hpp"
#include "SLSLog.hpp"
#include "SLSLock.hpp"
#include "util.hpp"

/**
 * CSLSSrt class implementation
 */
extern const struct in6_addr in6addr_any;        /* :: */
extern const struct in6_addr in6addr_loopback;   /* ::1 */
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

bool CSLSSrt::m_inited = false;

CSLSSrt::CSLSSrt()
{
    memset(&m_sc, 0x0, sizeof(m_sc));
    m_sc.port = 8000; //for test
    m_sc.fd = 0;
    m_sc.eid = 0;
    m_sc.latency = 20;

    m_sc.backlog = 128;
    memset(m_peer_name, 0, sizeof(m_peer_name));
    m_peer_port = 0;
    m_peer_addr_raw = 0;
    m_peer_addr6_raw = in6addr_any;
}
CSLSSrt::~CSLSSrt()
{
}

int CSLSSrt::libsrt_init()
{
    if (m_inited)
        return SLS_OK;

    if (srt_startup() < 0)
    {
        return SLSERROR_UNKNOWN;
    }
    m_inited = true;

    uint32_t libsrt_version = srt_getversion();
    spdlog::info("Initialized libsrt v{:d}.{:d}.{:d}",
                 (libsrt_version >> 16) & 0xff, (libsrt_version >> 8) & 0xff, libsrt_version & 0xff);

    return SLS_OK;
}

int CSLSSrt::libsrt_uninit()
{
    if (!m_inited)
        return SLS_OK;
    srt_cleanup();
    return SLS_OK;
}

int CSLSSrt::libsrt_epoll_create()
{
    return srt_epoll_create();
}

void CSLSSrt::libsrt_epoll_release(int eid)
{
    srt_epoll_release(eid);
}

void CSLSSrt::libsrt_print_error_info()
{
    /**
SRTS_BROKEN: The socket was connected, but the connection was broken
SRTS_CLOSING: The socket may still be open and active, but closing is requested, so no further operations will be accepted (active operations will be completed before closing)
SRTS_CLOSED: The socket has been closed, but not yet removed by the GC thread
SRTS_NONEXIST:
     */

#define set_error_map(k) \
    map_error[k] = std::string(#k);

    char szBuf[1024] = {0};
    std::map<int, std::string> map_error;

    set_error_map(SRTS_INIT);
    set_error_map(SRTS_OPENED);
    set_error_map(SRTS_LISTENING);
    set_error_map(SRTS_CONNECTING);
    set_error_map(SRTS_CONNECTED);
    set_error_map(SRTS_BROKEN);
    set_error_map(SRTS_CLOSING);
    set_error_map(SRTS_CLOSED);
    set_error_map(SRTS_NONEXIST);

    set_error_map(SRT_ENOCONN);
    set_error_map(SRT_ECONNLOST);
    set_error_map(SRT_EINVALMSGAPI);
    set_error_map(SRT_EINVALBUFFERAPI);
    set_error_map(SRT_EASYNCSND);
    set_error_map(SRT_ETIMEOUT);
    set_error_map(SRT_EPEERERR);

    spdlog::error("--------srt error--------");
    std::map<int, std::string>::iterator it;
    for (it = map_error.begin(); it != map_error.end(); ++it)
    {
        snprintf(szBuf, sizeof(szBuf), "%d: %s", it->first, it->second.c_str());
        spdlog::error(szBuf);
    }
    spdlog::error("----------end------------");
    map_error.clear();
}

int CSLSSrt::libsrt_neterrno()
{
    int err = srt_getlasterror(NULL);
    spdlog::error("CSLSSrt::libsrt_neterrno, err={:d}, {}.", err, srt_getlasterror_str());
    return err;
}

void CSLSSrt::libsrt_set_context(SRTContext *sc)
{
    m_sc = *sc;
}

void CSLSSrt::libsrt_set_latency(int latency)
{
    m_sc.latency = latency;
}

int CSLSSrt::libsrt_setup(int port)
{
    struct addrinfo hints = {0}, *ai;
    int fd = -1;
    int ret;
    char portstr[10];
    SRTContext *s = &m_sc;

    m_sc.port = port;

    hints.ai_family = AF_INET6;//AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(portstr, sizeof(portstr), "%d", s->port);
    hints.ai_flags |= AI_PASSIVE;
    ret = getaddrinfo(s->hostname[0] ? s->hostname : NULL, portstr, &hints, &ai);
    if (ret)
    {
        spdlog::error("[{}] CSLSSrt::libsrt_setup, Failed to resolve hostname {}: {}.",
                      fmt::ptr(this), s->hostname, gai_strerror(ret));
        return ret;
    }

    fd = srt_create_socket();
    if (fd < 0)
    {
        ret = libsrt_neterrno();
        freeaddrinfo(ai);
        return ret;
    }

    /*
    if (libsrt_setsockopt(h, fd, SRTO_STREAMID, "SRTO_STREAMID", sc->streamid, strlen(s->streamid)) < 0) {
        ret = libsrt_neterrno();
        freeaddrinfo(ai);
        return ret;
    }
*/
    int ipv6Only = 0;
    int srtlaPatches = 1;
    int fc = 128 * 1000;
    int lossmaxttlvalue = 200;
    int rcv_buf = 100 * 1024 * 1024;

    int status = srt_setsockopt(fd, SOL_SOCKET, SRTO_IPV6ONLY, &ipv6Only, sizeof(ipv6Only));
    if (status < 0) {
        spdlog::error("[{}] CSLSSrt::open, srt_setsockopt SRTO_IPV6ONLY failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    status = srt_setsockopt(fd, SOL_SOCKET, SRTO_LOSSMAXTTL, &lossmaxttlvalue, sizeof(lossmaxttlvalue));
    if (status < 0) {
        spdlog::error("[{}] CSLSSrt::open, srt_setsockopt SRTO_LOSSMAXTTL failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    status = srt_setsockopt(fd, SOL_SOCKET, SRTO_FC, &fc, sizeof(fc));
    if (status < 0) {
        spdlog::error("[{}] CSLSSrt::open, srt_setsockopt SRTO_FC failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }
    status = srt_setsockopt(fd, SOL_SOCKET, SRTO_RCVBUF, &rcv_buf, sizeof(rcv_buf));
    if (status < 0) {
        spdlog::error("[{}] CSLSSrt::open, srt_setsockopt SRTO_RCVBUF failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    status = srt_setsockopt(fd, SOL_SOCKET, SRTO_SRTLAPATCHES, &srtlaPatches, sizeof(srtlaPatches));
    if (status < 0) {
        spdlog::error("[{}] CSLSSrt::open, srt_setsockopt SRTO_SRTLAPATCHES failure. err={}.", fmt::ptr(this), srt_getlasterror_str());
        return SLS_ERROR;
    }

    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->latency > 0)
    {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_LATENCY, &s->latency, sizeof(s->latency));
    }
    if (s->recv_buffer_size > 0)
    {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_UDP_RCVBUF, &s->recv_buffer_size, sizeof(s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0)
    {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_UDP_SNDBUF, &s->send_buffer_size, sizeof(s->send_buffer_size));
    }
    if (s->reuse)
    {
        if (srt_setsockopt(fd, SOL_SOCKET, SRTO_REUSEADDR, &s->reuse, sizeof(s->reuse)))
            spdlog::warn("[{}] CSLSSrt::libsrt_setup, setsockopt(SRTO_REUSEADDR) failed.", fmt::ptr(this));
    }

    ret = srt_bind(fd, ai->ai_addr, ai->ai_addrlen);
    if (ret)
    {
        srt_close(fd);
        freeaddrinfo(ai);
        return libsrt_neterrno();
    }

    s->fd = fd;

    freeaddrinfo(ai);
    spdlog::info("[{}] CSLSSrt::libsrt_setup, fd={:d}.", fmt::ptr(this), fd);

    return SLS_OK;
}

int CSLSSrt::libsrt_listen(int backlog)
{
    m_sc.backlog = backlog;
    int ret = srt_listen(m_sc.fd, backlog);
    if (ret)
        return libsrt_neterrno();

    spdlog::info("[{}] CSLSSrt::libsrt_listen, ok, fd={:d}, at port={:d}.", fmt::ptr(this), m_sc.fd, m_sc.port);
    return SLS_OK;
}

int CSLSSrt::libsrt_set_listen_callback(srt_listen_callback_fn * listen_callback_fn) {
    int ret = srt_listen_callback(m_sc.fd, listen_callback_fn, NULL);
    if (ret) {
        return SLS_ERROR;
    }
    return SLS_OK;
}

int CSLSSrt::libsrt_accept()
{
    struct sockaddr_in6  scl;
    int sclen = sizeof(scl);
    char ip[INET6_ADDRSTRLEN] = {0};
    struct sockaddr_in6  *addrtmp;

    int new_sock = srt_accept(m_sc.fd, (struct sockaddr *)&scl, &sclen); //NULL, NULL);//(sockaddr*)&scl, &sclen);
    if (new_sock == SRT_INVALID_SOCK)
    {
        int err_no = libsrt_neterrno();
        spdlog::info("[{}] CSLSSrt::libsrt_accept failed, sock={:d}, error_no={:d}.",
                     fmt::ptr(this), m_sc.fd, err_no);
        return SLS_ERROR;
    } 
    addrtmp = (struct sockaddr_in6 *)&scl;
    inet_ntop(AF_INET6, &addrtmp->sin6_addr, ip, INET6_ADDRSTRLEN);
    spdlog::info("[{}] CSLSSrt::libsrt_accept ok, new sock={:d}, {}:{:d}.",
                 fmt::ptr(this), new_sock, ip, ntohs(addrtmp->sin6_port));

    return new_sock;
}

int CSLSSrt::libsrt_close()
{
    if (m_sc.fd)
    {
        spdlog::info("[{}] CSLSSrt::libsrt_close, fd={:d}.", fmt::ptr(this), m_sc.fd);
        srt_close(m_sc.fd);
        m_sc.fd = 0;
    }
    return SLS_OK;
}

int CSLSSrt::libsrt_set_fd(int fd)
{
    libsrt_close();
    m_sc.fd = fd;
    return SLS_OK;
}

int CSLSSrt::libsrt_get_fd()
{
    return m_sc.fd;
}

int CSLSSrt::libsrt_set_eid(int eid)
{
    m_sc.eid = eid;
    return SLS_OK;
}

int CSLSSrt::libsrt_getsockopt(SRT_SOCKOPT optname, const char *optnamestr, void *optval, int *optlen)
{
    if (srt_getsockopt(m_sc.fd, 0, optname, optval, optlen) < 0)
    {
        spdlog::error("[{}] CSLSSrt::libsrt_getsockopt, failed to get option {} on socket: {}", fmt::ptr(this), optnamestr, srt_getlasterror_str());
        return SLSERROR(EIO);
    }
    return 0;
}

int CSLSSrt::libsrt_setsockopt(SRT_SOCKOPT optname, const char *optnamestr, const void *optval, int optlen)
{
    if (srt_setsockopt(m_sc.fd, 0, optname, optval, optlen) < 0)
    {
        spdlog::error("[{}] CSLSSrt::libsrt_setsockopt, failed to set option {} on socket: {}", fmt::ptr(this), optnamestr, srt_getlasterror_str());
        return SLSERROR(EIO);
    }
    return 0;
}

int CSLSSrt::libsrt_socket_nonblock(int enable)
{
    int ret = srt_setsockopt(m_sc.fd, 0, SRTO_SNDSYN, &enable, sizeof(enable));
    if (ret < 0)
        return ret;
    return srt_setsockopt(m_sc.fd, 0, SRTO_RCVSYN, &enable, sizeof(enable));
}

std::map<std::string, std::string> CSLSSrt::libsrt_parse_sid(char *sid)
{
    static const char stdhdr[] = "#!::";
    uint32_t *pattern = (uint32_t *)stdhdr;
    std::map<std::string, std::string> ret;
    if (strlen(sid) > 4 && *(uint32_t *)sid == *pattern)
    {
        std::vector<string> items;
        sls_split_string(sid + 4, ",", items);
        for (auto &i : items)
        {
            std::vector<string> kv;
            sls_split_string(i, "=", kv);
            if (kv.size() == 2)
            {

                ret[kv.at(0)] = kv.at(1);
            }
        }
    }
    else
    {
        std::vector<string> items;
        sls_split_string(sid, "/", items);
        if (items.size() >= 3)
        {
            ret["h"] = items.at(0);
            ret["sls_app"] = items.at(1);
            ret["r"] = items.at(2);
        }
    }
    return ret;
}

int CSLSSrt::libsrt_read(char *buf, int size)
{
    int ret;
    ret = srt_recvmsg(m_sc.fd, buf, size);
    if (ret < 0)
    {
        int err_no = libsrt_neterrno();
        spdlog::warn("[{}] CSLSSrt::libsrt_read failed, sock={:d}, ret={:d}, err_no={:d}.",
                     fmt::ptr(this), m_sc.fd, ret, err_no);
    }
    return ret;
}

int CSLSSrt::libsrt_write(const char *buf, int size)
{
    int ret;
    ret = srt_sendmsg(m_sc.fd, buf, size, -1, 0);
    if (ret < 0)
    { //SRTS_BROKEN
        int err_no = libsrt_neterrno();
        spdlog::warn("[{}] CSLSSrt::libsrt_write failed, sock={:d}, ret={:d}, errno={:d}.",
                     fmt::ptr(this), m_sc.fd, ret, err_no);
    }
    return ret;
}

int CSLSSrt::libsrt_add_to_epoll(int eid, bool write)
{
    int ret = SLS_OK;
    int fd = m_sc.fd;
    int modes = write ? SRT_EPOLL_OUT : SRT_EPOLL_IN;

    if (!eid)
    {
        spdlog::error("[{}] CSLSSrt::libsrt_add_to_epoll failed, m_eid={:d}.", fmt::ptr(this), eid);
        return SLS_ERROR;
    }

    modes |= SRT_EPOLL_ERR;
    ret = srt_epoll_add_usock(eid, fd, &modes);
    if (ret < 0)
    {
        spdlog::error("[{}] CSLSSrt::libsrt_add_to_epoll, srt_epoll_add_usock failed, m_eid={:d}, fd={:d}, modes={:d}.",
                      fmt::ptr(this), eid, fd, modes);
        return libsrt_neterrno();
    }
    return ret;
}

int CSLSSrt::libsrt_remove_from_epoll()
{
    int ret = SLS_OK;
    int fd = m_sc.fd;
    int eid = m_sc.eid;

    if (!eid)
    {
        spdlog::error("[{}] CSLSSrt::remove_from_epoll failed, m_eid={:d}.", fmt::ptr(this), eid);
        return SLS_ERROR;
    }

    ret = srt_epoll_remove_usock(eid, fd);
    if (ret < 0)
    {
        spdlog::error("[{}] CSLSSrt::remove_from_epoll, srt_epoll_remove_usock failed, m_eid={:d}, fd={:d}.",
                      fmt::ptr(this), eid, fd);
        return libsrt_neterrno();
    }
    return ret;
}

int CSLSSrt::libsrt_getsockstate()
{
    return srt_getsockstate(m_sc.fd);
}

int CSLSSrt::libsrt_getpeeraddr(char *peer_name, int &port)
{
    int ret = SLS_ERROR;
    struct sockaddr_in6 peer_addr;
    int peer_addr_len = sizeof(peer_addr);

    if (strlen(m_peer_name) == 0 || m_peer_port == 0)
    {
        ret = srt_getpeername(m_sc.fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (0 == ret)
        {
            inet_ntop(AF_INET6, &peer_addr.sin6_addr, m_peer_name, sizeof(m_peer_name));
            m_peer_port = ntohs(peer_addr.sin6_port);

            strcpy(peer_name, m_peer_name);
            port = m_peer_port;
            ret = SLS_OK;
        }
    }
    else
    {
        strcpy(peer_name, m_peer_name);
        port = m_peer_port;
        ret = SLS_OK;
    }
    return ret;
}


int CSLSSrt::libsrt_getpeeraddr_raw(unsigned long &address, struct in6_addr &address6) {
    int ret = SLS_ERROR;
    struct sockaddr_storage peer_addr; // Use sockaddr_storage
    int peer_addr_len = sizeof(peer_addr);

    if (0 == m_peer_addr_raw && !m_is_ipv6) { // Check if no address is stored yet
        ret = srt_getpeername(m_sc.fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (0 == ret) {
            if (peer_addr.ss_family == AF_INET) {
                // IPv4
                struct sockaddr_in *addr_in = (struct sockaddr_in *)&peer_addr;
                m_peer_addr_raw = ntohl(addr_in->sin_addr.s_addr);
                address = m_peer_addr_raw;
                m_is_ipv6 = false;
                ret = SLS_OK;
            } else if (peer_addr.ss_family == AF_INET6) {
                // IPv6
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&peer_addr;
                m_peer_addr6_raw = addr_in6->sin6_addr;
                address6 = m_peer_addr6_raw;
                m_is_ipv6 = true;
                ret = SLS_OK;
            } else {
                spdlog::error("[{}] SLSSrt::libsrt_getpeeraddr_raw failed: unsupported address family", fmt::ptr(this));
            }
        } else {
            spdlog::error("[{}] SLSSrt::libsrt_getpeeraddr_raw failed: not get peer IP address [ret={:d}]", fmt::ptr(this), ret);
        }
    } else {
        // Return the stored address based on the flag
        if (m_is_ipv6) {
            address6 = m_peer_addr6_raw;
        } else {
            address = m_peer_addr_raw;
        }
        ret = SLS_OK;
    }

    return ret;
}

int CSLSSrt::libsrt_get_statistics(SRT_TRACEBSTATS *currentStats, int clear) {
    int result = srt_bistats(m_sc.fd, currentStats, clear, 1);
    if (result == SLS_ERROR) {
        return SLS_ERROR;
    }
    return SLS_OK;
}
