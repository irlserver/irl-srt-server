# Plan 000: Restore macOS build support (portable epoll wakeup)

> **Executor instructions**: Follow this plan step by step. Run every verification command
> and confirm the expected result before moving on. Touch only the files listed in scope.
> If a STOP condition occurs, stop immediately and report. When done, report in the format
> your dispatcher specified.
>
> **Drift check (run first)**: `git diff --stat 78d67c0..HEAD -- src/core/SLSEpollThread.cpp src/core/SLSEpollThread.hpp`
> If these changed since this plan was written, compare the "Current state" excerpts to the
> live code before editing; on a structural mismatch, STOP.

## Status

- **Priority**: P0 (gates 001 and all build-verified plans on macOS)
- **Effort**: S
- **Risk**: LOW (isolated to the wake primitive; Linux path stays byte-for-byte identical)
- **Depends on**: none
- **Category**: dx / portability
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

The server stopped building on macOS when commit `0167cc38` ("event-driven worker via
eventfd") introduced a Linux-only `eventfd` wakeup primitive. `<sys/eventfd.h>` does not
exist on macOS, so the build fails immediately at `SLSEpollThread.cpp:27`. `eventfd` is the
**only** Linux-only dependency in the core (SRT provides its own cross-platform epoll, so
there is no `<sys/epoll.h>` to worry about). Replacing it with the portable self-pipe
equivalent restores macOS as a development/test platform without changing behavior on Linux.

## Current state

The wakeup is fully contained in two files.

`src/core/SLSEpollThread.hpp:64-65`:
```cpp
    int m_eid;
    int m_wake_fd; // Linux eventfd, signalled by wake() to interrupt epoll.
```
`wake_fd()` getter at `:62` returns `m_wake_fd` — `CSLSGroup` uses it to recognize the wake
fd among the system sockets returned by `srt_epoll_wait`. The registered fd must be the
**read end**.

`src/core/SLSEpollThread.cpp`:
- `:27` `#include <sys/eventfd.h>` (Linux-only header).
- `:42-46` ctor sets `m_eid = -1; m_wake_fd = -1;`.
- `:65-86` `init_epoll`: `m_wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);` then
  `srt_epoll_add_ssock(m_eid, m_wake_fd, &events)` with `events = SRT_EPOLL_IN | SRT_EPOLL_ERR`.
- `:90-107` `uninit_epoll`: `srt_epoll_remove_ssock` + `close(m_wake_fd)`.
- `:109-120` `wake()`: writes `uint64_t one = 1;` to `m_wake_fd`.
- `:122-138` `drain_wake_fd()`: reads `uint64_t v;` in a loop until the read no longer
  returns 8 bytes; returns whether anything was drained.

Repo conventions: `m_`-prefixed members, 4-space indent, `spdlog` for logging, `SLS_OK`/
`SLS_ERROR` returns. Match them.

## Commands you will need

Builds require the SRT **fork** (belabox, installed at `/Users/thomaslekanger/srt/_install`)
because the code uses `SRTO_SRTLAPATCHES`. Export these before any cmake/build:

```sh
export SRT_PREFIX=/Users/thomaslekanger/srt/_install
export CPATH=$SRT_PREFIX/include
export LIBRARY_PATH=$SRT_PREFIX/lib
export DYLD_LIBRARY_PATH=$SRT_PREFIX/lib
export PKG_CONFIG_PATH=$SRT_PREFIX/lib/pkgconfig
```

| Purpose | Command | Expected |
|---|---|---|
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug` | exit 0 |
| Build core | `cmake --build build -j --target sls_core` | exit 0 (the failing target today) |
| Build all | `cmake --build build -j` | exit 0; `build/bin/srt_server` and `srt_client` exist |

## Scope

**In scope**: `src/core/SLSEpollThread.cpp`, `src/core/SLSEpollThread.hpp`.

**Out of scope**: `CSLSGroup` and every caller of `wake()`/`wake_fd()`/`drain_wake_fd()` —
the public interface must not change (same method signatures, `wake_fd()` still returns the
fd registered with the epoll). Any other portability issue that surfaces in a *different*
file (see STOP conditions).

## Steps

### Step 1: Add a portable write-end member to the header

In `src/core/SLSEpollThread.hpp`, change the wake-fd members to keep the read end in
`m_wake_fd` (so `wake_fd()` and the epoll registration are unchanged) and add a separate
write end:
```cpp
    int m_eid;
    // Wake primitive: on Linux a single eventfd (read==write fd); elsewhere a
    // self-pipe (m_wake_fd is the read end registered with the epoll, m_wake_fd_write
    // is the write end). wake() writes the write end; drain_wake_fd() reads m_wake_fd.
    int m_wake_fd;
    int m_wake_fd_write;
```

### Step 2: Make the include and creation portable

In `src/core/SLSEpollThread.cpp`:
- Guard the Linux-only header and add the headers the pipe path needs:
```cpp
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/eventfd.h>
#endif
```
- In the constructor, initialize the new member: `m_wake_fd = -1; m_wake_fd_write = -1;`.
- In `init_epoll`, replace the single `eventfd(...)` creation with a platform branch that
  sets both fds (read end in `m_wake_fd`, write end in `m_wake_fd_write`), keeping the
  existing `srt_epoll_add_ssock(m_eid, m_wake_fd, &events)` registration of the read end
  unchanged:
```cpp
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
    m_wake_fd = pipefd[0];       // read end, registered with the epoll
    m_wake_fd_write = pipefd[1]; // write end, used by wake()
#endif
```
Keep the `srt_epoll_add_ssock(m_eid, m_wake_fd, &events)` block exactly as is. On its
failure path, also close the write end if it differs:
```cpp
        close(m_wake_fd);
        if (m_wake_fd_write != m_wake_fd)
            close(m_wake_fd_write);
        m_wake_fd = -1;
        m_wake_fd_write = -1;
        return SLS_ERROR;
```

### Step 3: Close both ends in `uninit_epoll`

```cpp
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
```

### Step 4: Write to the write end; keep drain reading the read end

In `wake()`, write to `m_wake_fd_write` instead of `m_wake_fd` (guard on it being valid).
The existing 8-byte `uint64_t one = 1;` write is fine for both eventfd and a pipe (a pipe
accepts arbitrary lengths):
```cpp
void CSLSEpollThread::wake()
{
    if (m_wake_fd_write < 0)
        return;
    uint64_t one = 1;
    ssize_t n = ::write(m_wake_fd_write, &one, sizeof(one));
    (void)n;
}
```
`drain_wake_fd()` reads `m_wake_fd` (the read end) and is unchanged in logic. For a pipe the
8-byte-chunk read loop still drains correctly (it reads whatever is queued; the loop exits
when a read returns fewer than 8 bytes or EAGAIN). Leave it as is, only confirm it reads
`m_wake_fd`.

### Step 5: Build and verify

Export the SRT env (see Commands), then:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j --target sls_core
cmake --build build -j
```

**Verify**: `sls_core` compiles (the `sys/eventfd.h` fatal error is gone) and the full
build produces `build/bin/srt_server` and `build/bin/srt_client`.

## Done criteria

ALL must hold:
- [ ] `cmake --build build -j` exits 0 on macOS; `build/bin/srt_server` and `build/bin/srt_client` exist
- [ ] No `#include <sys/eventfd.h>` outside a `#if defined(__linux__)` guard
- [ ] `wake_fd()` still returns the epoll-registered read end (public interface unchanged)
- [ ] `git diff --stat` shows only `src/core/SLSEpollThread.cpp` and `.hpp` modified
- [ ] On a Linux toolchain the eventfd path is unchanged (verify by reading the `#if defined(__linux__)` branch matches the original code)

## STOP conditions

- After the eventfd fix, the build fails on a **different** Linux-only API in another file
  (e.g. `prctl`, `sched_setaffinity`, `/proc`, another missing header). STOP and report the
  exact file/line/symbol — that is a separate portability fix, not in this plan's scope.
- `srt_epoll_add_ssock` rejects the pipe read end on macOS (report the error). 
- Any verification fails twice after a reasonable fix attempt.

## Maintenance notes

- This keeps Linux on eventfd (single fd, no behavior change) and macOS/BSD on a self-pipe.
- If the wake mechanism is extended (e.g. carrying a payload), remember eventfd is a counter
  and a pipe is a byte stream — keep the payload semantics platform-agnostic.
- A CI macOS job (plan 001 / 005) would keep this from regressing again.
