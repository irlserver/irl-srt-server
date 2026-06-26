
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

// Small, move-only RAII owners for the two libsrt resources whose lifetime SLS
// manages by hand: the SRT epoll id and the SRT listen socket. Each releases its
// resource on destruction, so an early return / exception between acquisition and
// the point where ownership is handed to a long-lived member cannot leak the fd.
// Both are deliberately thin wrappers around the same srt_* primitives the code
// already calls (srt_epoll_create/release, srt_create_socket/srt_close) — they
// change *who closes the fd and when*, never the fd value itself, so the values
// exposed via CSLSSrt::libsrt_get_fd / libsrt_set_fd and the epoll arming logic
// are untouched. release() relinquishes ownership (the value survives into the
// member); reset() adopts a fresh value, releasing any previously held one.

// Owns an SRT epoll id (srt_epoll_create -> srt_epoll_release). The invalid
// sentinel is -1, matching srt_epoll_create's <0 failure return, so a
// default-constructed or moved-from handle releases nothing.
class SrtEpollHandle
{
public:
    static constexpr int kInvalid = -1;

    SrtEpollHandle() noexcept : m_eid(kInvalid) {}
    explicit SrtEpollHandle(int eid) noexcept : m_eid(eid) {}

    SrtEpollHandle(SrtEpollHandle &&other) noexcept : m_eid(other.m_eid) { other.m_eid = kInvalid; }
    SrtEpollHandle &operator=(SrtEpollHandle &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_eid = other.m_eid;
            other.m_eid = kInvalid;
        }
        return *this;
    }

    SrtEpollHandle(const SrtEpollHandle &) = delete;
    SrtEpollHandle &operator=(const SrtEpollHandle &) = delete;

    ~SrtEpollHandle() { reset(); }

    int get() const noexcept { return m_eid; }
    bool valid() const noexcept { return m_eid >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    // Relinquish ownership without releasing; the returned id is now the
    // caller's responsibility to release.
    int release() noexcept
    {
        int eid = m_eid;
        m_eid = kInvalid;
        return eid;
    }

    // Release the currently-held id (if any) and adopt a new one.
    void reset(int eid = kInvalid) noexcept
    {
        if (m_eid >= 0)
            srt_epoll_release(m_eid);
        m_eid = eid;
    }

private:
    int m_eid;
};

// Owns an SRT socket (srt_create_socket -> srt_close). Anything < 0
// (i.e. SRT_INVALID_SOCK, srt_create_socket's failure return) is treated as
// "nothing to close", matching the hand-rolled `fd >= 0` guard this replaces.
class SrtSocketHandle
{
public:
    SrtSocketHandle() noexcept : m_sock(SRT_INVALID_SOCK) {}
    explicit SrtSocketHandle(SRTSOCKET sock) noexcept : m_sock(sock) {}

    SrtSocketHandle(SrtSocketHandle &&other) noexcept : m_sock(other.m_sock) { other.m_sock = SRT_INVALID_SOCK; }
    SrtSocketHandle &operator=(SrtSocketHandle &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_sock = other.m_sock;
            other.m_sock = SRT_INVALID_SOCK;
        }
        return *this;
    }

    SrtSocketHandle(const SrtSocketHandle &) = delete;
    SrtSocketHandle &operator=(const SrtSocketHandle &) = delete;

    ~SrtSocketHandle() { reset(); }

    SRTSOCKET get() const noexcept { return m_sock; }
    bool valid() const noexcept { return m_sock >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    // Relinquish ownership without closing; the returned socket is now the
    // caller's responsibility to close (e.g. handed to CSLSSrt::m_sc.fd).
    SRTSOCKET release() noexcept
    {
        SRTSOCKET sock = m_sock;
        m_sock = SRT_INVALID_SOCK;
        return sock;
    }

    // Close the currently-held socket (if any) and adopt a new one.
    void reset(SRTSOCKET sock = SRT_INVALID_SOCK) noexcept
    {
        if (m_sock >= 0)
            srt_close(m_sock);
        m_sock = sock;
    }

private:
    SRTSOCKET m_sock;
};
