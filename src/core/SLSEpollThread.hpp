
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
#include "SLSThread.hpp"
#include "SLSHandle.hpp"

#define MAX_SOCK_COUNT 1024

/**
 * CSLSEpollThread , the base thread class
 */
class CSLSEpollThread : public CSLSThread
{
public:
    virtual ~CSLSEpollThread();
    CSLSEpollThread();
    // ~CSLSEpollThread();

    virtual int work() override;

    int init_epoll();
    int uninit_epoll();

    // Wake the worker thread out of its current srt_epoll_wait. Safe to
    // call from any thread. Used by stop() / reload() so shutdown and
    // config reload don't have to wait for the next epoll timeout.
    void wake();

protected:
    virtual int handler();

    int add_to_epoll(int fd, bool write);

    // Drain pending wake-fd signals. Returns true if the wake fd was
    // among the system-socket events returned from srt_epoll_wait.
    // Subclasses must call this from their handler() loop when system
    // sockets were reported readable.
    bool drain_wake_fd();
    int wake_fd() const
    {
        return m_wake_fd;
    }

    // RAII owner for the SRT epoll id; get() yields the same raw id the plain
    // int used to hold (value unchanged), reset() releases the prior one.
    SrtEpollHandle m_eid;
    // Wake primitive: on Linux a single eventfd (read==write fd); elsewhere a
    // self-pipe (m_wake_fd is the read end registered with the epoll, m_wake_fd_write
    // is the write end). wake() writes the write end; drain_wake_fd() reads m_wake_fd.
    int m_wake_fd;
    int m_wake_fd_write;
    SRTSOCKET m_read_socks[MAX_SOCK_COUNT];
    SRTSOCKET m_write_socks[MAX_SOCK_COUNT];
};
