
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
#include <unistd.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/eventfd.h>
#endif
#include "spdlog/spdlog.h"

#include "SLSEpollThread.hpp"
#include "SLSLog.hpp"
#include "common.hpp"
#include "SLSRole.hpp"

#include <srt/srt.h>

/**
 * CSLSThread class implementation
 */

CSLSEpollThread::CSLSEpollThread()
{
    m_eid = -1;
    m_wake_fd = -1;
    m_wake_fd_write = -1;
}

CSLSEpollThread::~CSLSEpollThread()
{
}

int CSLSEpollThread::init_epoll()
{
    int ret = 0;

    m_eid = CSLSSrt::libsrt_epoll_create();
    if (m_eid < 0)
    {
        spdlog::info("[{}] CSLSEpollThread::work, srt_epoll_create failed. th_id={:d}.", fmt::ptr(this), m_th_id);
        return CSLSSrt::libsrt_neterrno();
    }
    // compatible with srt v1.4.0 when container is empty.
    srt_epoll_set(m_eid, SRT_EPOLL_ENABLE_EMPTY);

    // Create the wake eventfd and register it with the SRT epoll as a
    // system socket. Reading the eventfd in srt_epoll_wait's lrfds output
    // tells us wake() was called and we should drain it. This replaces
    // the previous "epoll-timeout + msleep" polling backoff with proper
    // event-driven idle behaviour: the loop only wakes when there's
    // socket work or an explicit wake(), never spurious.
#if defined(__linux__)
    m_wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_wake_fd < 0)
    {
        spdlog::error("[{}] CSLSEpollThread::init_epoll, eventfd() failed: {}",
                      fmt::ptr(this), strerror(errno));
        return SLS_ERROR;
    }
    m_wake_fd_write = m_wake_fd; // eventfd is read+write on one fd
#else
    int pipefd[2];
    if (pipe(pipefd) != 0)
    {
        spdlog::error("[{}] CSLSEpollThread::init_epoll, pipe() failed: {}",
                      fmt::ptr(this), strerror(errno));
        return SLS_ERROR;
    }
    for (int i = 0; i < 2; ++i)
    {
        int fl = fcntl(pipefd[i], F_GETFL, 0);
        fcntl(pipefd[i], F_SETFL, fl | O_NONBLOCK);
        fcntl(pipefd[i], F_SETFD, FD_CLOEXEC);
    }
    m_wake_fd = pipefd[0];
    m_wake_fd_write = pipefd[1];
#endif
    int events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
    if (srt_epoll_add_ssock(m_eid, m_wake_fd, &events) != SRT_SUCCESS)
    {
        spdlog::error("[{}] CSLSEpollThread::init_epoll, srt_epoll_add_ssock(wake_fd={:d}) failed.",
                      fmt::ptr(this), m_wake_fd);
        close(m_wake_fd);
        if (m_wake_fd_write != m_wake_fd)
            close(m_wake_fd_write);
        m_wake_fd = -1;
        m_wake_fd_write = -1;
        return SLS_ERROR;
    }
    return ret;
}

int CSLSEpollThread::uninit_epoll()
{
    int ret = 0;
    if (m_wake_fd >= 0)
    {
        if (m_eid >= 0)
            srt_epoll_remove_ssock(m_eid, m_wake_fd);
        close(m_wake_fd);
        if (m_wake_fd_write != m_wake_fd && m_wake_fd_write >= 0)
            close(m_wake_fd_write);
        m_wake_fd = -1;
        m_wake_fd_write = -1;
    }
    if (m_eid >= 0)
    {
        CSLSSrt::libsrt_epoll_release(m_eid);
        spdlog::info("[{}] CSLSEpollThread::work, srt_epoll_release ok, m_th_id={:d}.", fmt::ptr(this), m_th_id);
        m_eid = -1;
    }
    return ret;
}

void CSLSEpollThread::wake()
{
    if (m_wake_fd_write < 0)
        return;
    uint64_t one = 1;
    // EFD_NONBLOCK / O_NONBLOCK: write fails with EAGAIN only when the
    // counter would overflow (eventfd) or the pipe buffer is full. Neither
    // is realistic under any sane wake rate, and a missed wake is harmless
    // because the worker is already awake / about to wake.
    ssize_t n = ::write(m_wake_fd_write, &one, sizeof(one));
    (void)n;
}

bool CSLSEpollThread::drain_wake_fd()
{
    if (m_wake_fd < 0)
        return false;
    uint64_t v;
    // Loop in case multiple wakes piled up since last drain. EAGAIN means
    // no more pending data; both EAGAIN and a successful read return the
    // same logical outcome (fd is now drained), the caller just needs to
    // know whether ANY signal was pending so they can run wake-driven
    // work paths.
    bool drained_any = false;
    while (::read(m_wake_fd, &v, sizeof(v)) == (ssize_t)sizeof(v))
    {
        drained_any = true;
    }
    return drained_any;
}

int CSLSEpollThread::work()
{
    int ret = 0;
    spdlog::info("[{}] CSLSEpollThread::work, begin th_id={:d}.", fmt::ptr(this), m_th_id);
    // epoll loop
    while (!m_exit)
    {
        handler();
    }

    clear();
    spdlog::info("[{}] CSLSEpollThread::work, end th_id={:d}.", fmt::ptr(this), m_th_id);
    return ret;
}

int CSLSEpollThread::handler()
{
    int ret = 0;

    return ret;
}
