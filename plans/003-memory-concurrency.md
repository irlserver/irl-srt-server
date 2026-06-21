# Plan 003: Memory & concurrency fixes

> **Executor instructions**: Follow this plan step by step. Each step is an independent
> fix with its own verification. Run every verification command and confirm the expected
> result before moving on. If anything in "STOP conditions" occurs, stop and report — do
> not improvise. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 78d67c0..HEAD -- src/core/SLSRecycleArray.cpp src/core/SLSRecycleArray.hpp src/core/SLSManager.cpp src/core/SLSRole.cpp src/core/SLSRole.hpp src/core/SLSListenerHandler.cpp src/srt-live-server.cpp src/core/SLSSrt.cpp`
> For any in-scope file that changed, compare the "Current state" excerpt against the live
> code before editing; on a mismatch, treat that step as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW–MED per step (noted inline; Step 3 is the highest)
- **Depends on**: 001 (the ring-buffer fixes should be regression-tested; the disconnect
  fix should be validated under TSan)
- **Category**: bug / concurrency
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

This server shares ring buffers and role objects across an accept thread, multiple epoll
worker threads, a thread pool, and the HTTP control thread, with manual memory management.
The audit found a use-after-free reachable from the admin `/disconnect` endpoint, a
per-connection memory leak, two data races on the ring buffer's byte counter and resize,
iterator UB on config reload, an IPv6 ACL bypass, and fd/addrinfo leaks on a setup error
path. These are the latent-crash and resource-leak class — exactly what ASan/TSan from
plan 001 will keep fixed.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` | exit 0 |
| Build | `cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan build | `cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_TSAN=ON && cmake --build build-tsan -j` | exit 0 |
| ASan build | `cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_SANITIZE=ON && cmake --build build-asan -j` | exit 0 |

## Scope

**In scope**: `src/core/SLSRecycleArray.cpp`, `src/core/SLSRecycleArray.hpp`,
`src/core/SLSManager.cpp`, `src/core/SLSRole.cpp`, `src/core/SLSRole.hpp` (only if
`request_kick` plumbing needs it), `src/core/SLSListenerHandler.cpp`,
`src/srt-live-server.cpp`, `src/core/SLSSrt.cpp`, and `tests/*`.

**Out of scope**: the global `CSLSMapData` lock architecture (plan 007 — do not change the
locking *design* here, only the two narrow ring-buffer bugs); any refactor.

## Git workflow

- Branch: `advisor/003-memory-concurrency`
- One commit per step, conventional-commits, lowercase, scoped.
- Do NOT push or open a PR unless instructed.

---

## Step 1: Fix the `stat_info_t` per-connection leak

**Risk: LOW.** **Confidence: HIGH.** Two sites.

`stat_info_t` is heap-allocated, copied by value into the role, then the pointer is
dropped — leaked on every accepted publisher and player.

Current state — `src/core/SLSListenerHandler.cpp:608-618` (publisher):
```cpp
    stat_info_t *stat_info_obj = new stat_info_t();
    stat_info_obj->port = m_port;
    ...
    pub->set_stat_info_base(*stat_info_obj);
```
…and `src/core/SLSListenerHandler.cpp:927-936` (player), same pattern with `player->set_stat_info_base(*stat_info_obj);`.
The setter copies — `src/core/SLSRole.cpp:656-659`:
```cpp
void CSLSRole::set_stat_info_base(stat_info_t &v) { m_stat_info_base = v; }
```

Fix: at both sites, use a stack local instead of `new`:
```cpp
    stat_info_t stat_info_obj{};
    stat_info_obj.port = m_port;
    ...                           // change every `->` to `.`
    pub->set_stat_info_base(stat_info_obj);   // (player->... at the second site)
```
No `delete` needed; semantics are identical (the setter already copies).

**Verify**: `cmake --build build -j` → exit 0;
`grep -n "new stat_info_t" src/core/SLSListenerHandler.cpp` → no matches.

---

## Step 2: Make `m_nDataCount` race-free in the ring buffer

**Risk: LOW.** **Confidence: HIGH.**

`m_nDataCount` is incremented *outside* the write lock in `put()` and read both lock-free
(the `bFirst` path) and under the read lock in `get()`. It is a plain `int`; the race can
cause a false overrun resync (viewer glitch) or a missed overrun (corrupt TS delivered).

Current state — `src/core/SLSRecycleArray.cpp:96-118`:
```cpp
    {
        CSLSLock lock(&m_rwclock, true);
        ... memcpy ...
        if (m_nWritePos == m_nDataSize) m_nWritePos = 0;
    }
    //no consider int wrapround;
    m_nDataCount += len;          // <-- outside the lock
```
And lock-free read at `:138-139`:
```cpp
    if (read_id->bFirst) {
        read_id->nReadPos  = m_nWritePos;     // also read outside the lock
        read_id->nDataCount = m_nDataCount;
        ...
    }
```

Fix (preferred — minimal and correct): change the type to atomic in
`src/core/SLSRecycleArray.hpp` (find the `m_nDataCount` member; it is currently `int`):
```cpp
    std::atomic<int64_t> m_nDataCount{0};
```
Then in `.cpp`: use `m_nDataCount.fetch_add(len, std::memory_order_relaxed);` for the
increment, and `m_nDataCount.load(std::memory_order_relaxed)` at every read site
(`count()`, the `bFirst` snapshot, the overrun comparison). Note the `bFirst` snapshot
also reads `m_nWritePos` lock-free — take the read lock around that snapshot too (move the
`CSLSLock lock(&m_rwclock, false);` above the `bFirst` block, or snapshot both under it).
Confirm `<atomic>` and `<cstdint>` are included (add if missing).

Widening to `int64_t` also fixes the "no consider int wrapround" comment — the counter no
longer overflows in any realistic uptime.

**Test**: add to `tests/test_recycle_array.cpp` — the overrun-resync case from plan 001
still passes with the atomic counter; the round-trip and wrap cases still pass.

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` → pass;
TSan build compiles.

---

## Step 3: Take a write lock in `setSize()`

**Risk: LOW (the change); MED (the area).** **Confidence: HIGH.**

`setSize()` does `delete[]` + `new[]` on the buffer under a **read** lock, so concurrent
readers (which also hold the read lock) can race the reallocation — a latent use-after-free
masked today only by call-site ordering.

Current state — `src/core/SLSRecycleArray.cpp:71-78`:
```cpp
void CSLSRecycleArray::setSize(int n)
{
    CSLSLock lock(&m_rwclock, false);   // false == read lock
    delete[] m_arrayData;
    m_nDataSize = n;
    m_nWritePos = 0;
    m_arrayData = new char[m_nDataSize];
}
```

Fix: change the second argument to `true` (write lock). Behaviorally identical for the
current single call site (`CSLSMapData::add`, which calls `setSize` before publishing the
array), but correct if any future caller resizes a live buffer.

```cpp
    CSLSLock lock(&m_rwclock, true);
```

Also reset `m_nDataCount` here (it should be zeroed when the buffer is replaced — confirm
it currently is or add `m_nDataCount = 0;` / `.store(0)` to match the atomic from Step 2).

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` → pass.

---

## Step 4: Fix the reload-loop iterator UB

**Risk: LOW.** **Confidence: HIGH.**

On SIGHUP reload, the loop `erase(it)`s from a `std::vector` and then the `for` header runs
`it++` on the invalidated iterator — UB when ≥2 managers retire in one pass.

Current state — `src/srt-live-server.cpp:430-441`:
```cpp
    std::vector<CSLSManager *>::iterator it;
    for (it = reload_manager_list.begin(); it != reload_manager_list.end(); it++)
    {
        CSLSManager *manager = *it;
        if (nullptr != manager && SLS_OK == manager->check_invalid())
        {
            spdlog::info("Checking reloaded manager, deleting manager={:p} ...", fmt::ptr(manager));
            manager->stop();
            reload_manager_list.erase(it);
            delete manager;
        }
    }
```

Fix: use the erase-returns-next-iterator idiom and only advance otherwise:
```cpp
    for (auto it = reload_manager_list.begin(); it != reload_manager_list.end(); )
    {
        CSLSManager *manager = *it;
        if (nullptr != manager && SLS_OK == manager->check_invalid())
        {
            spdlog::info("Checking reloaded manager, deleting manager={:p} ...", fmt::ptr(manager));
            manager->stop();
            it = reload_manager_list.erase(it);
            delete manager;
        }
        else
        {
            ++it;
        }
    }
```

**Verify**: `cmake --build build -j` → exit 0.

---

## Step 5: Make `disconnect_stream()` cross-thread-safe (use-after-free)

**Risk: MED.** **Confidence: HIGH.**

The HTTP control thread calls `publisher_role->close()`, which does `delete m_srt; m_srt = NULL`,
while the owning worker thread is dereferencing `m_srt` on the data path — a use-after-free
/ teardown race triggerable from the admin endpoint.

Current state — `src/core/SLSManager.cpp:460-477`:
```cpp
        CSLSRole *publisher_role = publisher_map->get_publisher(streamName);
        if (publisher_role != NULL) {
            found = true;
            ...
            publisher_role->close();   // <-- frees m_srt from the HTTP thread
            ...
        }
```
`close()` — `src/core/SLSRole.cpp:376-385`:
```cpp
int CSLSRole::close() {
    if (m_srt) { m_srt->libsrt_close(); delete m_srt; m_srt = NULL; }
    return 0;
}
```

The codebase already has a cross-thread teardown mechanism: a `request_kick()` /
`m_kick_requested` atomic flag that the owning worker observes and acts on at a safe point
(used for publisher takeover — read `CSLSRole::request_kick` and how `get_state` /
`invalid_srt` consume it in `SLSRole.cpp`).

Fix: in `disconnect_stream`, replace `publisher_role->close();` with
`publisher_role->request_kick();` so the role is torn down by its owning worker, not the
HTTP thread. Read `SLSRole.cpp` to confirm `request_kick()` exists and is public; if the
kick flag uses `std::memory_order_relaxed`, upgrade the store in `request_kick` to
`release` and the load in the consumer to `acquire` while you are here (the flag hands off
state between threads). Verify a kicked publisher actually gets cleaned up by the worker
(the takeover path already relies on this).

**Test**: this needs concurrency to exercise; rely on the TSan build + a manual check
(connect a publisher, hit `/disconnect`, confirm clean teardown in logs with no crash).
Document that an automated test is deferred to an integration harness.

**Verify**: `cmake --build build-tsan -j` → exit 0;
`grep -n "publisher_role->close()" src/core/SLSManager.cpp` → no matches.

---

## Step 6: Fix the IPv6 IP-ACL bypass

**Risk: MED.** **Confidence: MED.**

For IPv6 peers, the IPv4 address field handed to the ACL loop stays `0`, so only wildcard
(`ip_address == 0`) ACL entries match — specific deny/allow rules silently do not apply to
IPv6 clients.

Current state — `src/core/SLSSrt.cpp:632-671` (`libsrt_getpeeraddr_raw` leaves `address`
untouched on the IPv6 branch, only sets `address6`/`m_is_ipv6`). ACL loop —
`src/core/SLSListenerHandler.cpp:534-560`:
```cpp
    if (srt->libsrt_getpeeraddr_raw(peer_addr_raw, peer_addr6_raw) == SLS_OK) {
        bool address_matched = false;
        for (sls_ip_access_t &acl_entry : ca->ip_actions.publish) {
            if (acl_entry.ip_address == peer_addr_raw || acl_entry.ip_address == 0) {
                ... ACCEPT / DENY ...
            }
            if (address_matched) break;
        }
        if (!address_matched) { /* default accept */ }
    }
```
The same block is duplicated in `finish_player_accept()` (around `:808-841`) — both must be fixed.

This is the **investigate-then-implement** step. The clean fix requires deciding the IPv6
ACL semantics, which the current `sls_ip_access_t` may not even represent (it appears to
store an IPv4 `ip_address`). Before coding:
1. Read `sls_ip_access_t` (search `struct sls_ip_access_t`) and the ACL config parser
   (likely in `SLSListenerConfig.cpp` / `conf.cpp`) to see whether IPv6 ACL entries can be
   expressed at all.
2. If IPv6 ACL entries **cannot** currently be configured, the safest correct behavior is:
   when the peer is IPv6 (`m_is_ipv6`), and the app has any non-wildcard ACL entries,
   apply a clear, documented policy rather than silently defaulting to accept. Recommended
   minimum: if there are any explicit ACL entries (allow or deny) and the peer is IPv6 with
   no IPv6 entry to match, **log a warning** that IPv6 ACL matching is not implemented and
   fall back to the app's default action — and surface this as a known limitation. Do NOT
   silently accept as if the ACL passed.
3. If IPv6 ACL entries **can** be configured, extend the matcher to compare `peer_addr6_raw`
   against IPv6 entries when `m_is_ipv6` is true, keeping the IPv4 path byte-for-byte identical.

Pick the approach the code supports, implement it in **both** ACL blocks (extract a shared
helper to avoid them drifting — but keep the helper local to this file, not a broad
refactor), and document the resulting IPv6 ACL behavior in the config docs (note for plan 006).

**Test**: add a unit test for the matcher helper if you extract one (IPv4 allow/deny still
works; IPv6 peer hits the documented path).

**Verify**: `cmake --build build -j` → exit 0; both ACL blocks call the same matching logic.

---

## Step 7: Plug fd/addrinfo leaks on the `libsrt_setup` error paths

**Risk: LOW.** **Confidence: HIGH (error path only).**

Between `srt_create_socket()` and `srt_bind()`, several `srt_setsockopt` failures
`return SLS_ERROR;` without closing the socket or freeing the `addrinfo`, leaking an SRT
socket and a small heap allocation per failed listener setup.

Current state — `src/core/SLSSrt.cpp` (the `libsrt_setup`/listener-setup function around
`:209-275`): early `return SLS_ERROR;` after each sockopt failure (e.g. `SRTO_IPV6ONLY`,
`SRTO_LOSSMAXTTL`, `SRTO_FC`, `SRTO_RCVBUF`, `SRTO_SRTLAPATCHES`, `SRTO_TLPKTDROP`), while
the later `SRTO_PBKEYLEN`/`SRTO_PASSPHRASE` failures *do* call `srt_close(fd)` +
`freeaddrinfo(ai)` before returning.

Fix: introduce a single cleanup path. Read the function for the exact local names (`fd`,
`ai`), then route every early sockopt-failure return through a `goto cleanup;` (or a small
RAII guard) that does `if (fd >= 0) srt_close(fd); if (ai) freeaddrinfo(ai);` before
returning `SLS_ERROR`. Keep the success path unchanged.

**Verify**: `cmake --build build -j` → exit 0; every `srt_setsockopt(...) ... return SLS_ERROR`
in this function is preceded by (or routed through) the socket/addrinfo cleanup.

---

## Test plan

- `tests/test_recycle_array.cpp` — extend with the atomic-counter and overrun cases (Steps 2–3).
- Steps 5–6 concurrency/ACL behavior: validate via TSan build + manual integration check;
  add a unit test for the IPv6 matcher helper if one is extracted.
- `ctest --test-dir build --output-on-failure` → all pass.

## Done criteria

ALL must hold:

- [ ] `cmake --build build -j` exits 0; ASan and TSan builds compile
- [ ] `ctest --test-dir build --output-on-failure` passes (ring-buffer tests included)
- [ ] `grep -n "new stat_info_t" src/core/SLSListenerHandler.cpp` → no matches
- [ ] `grep -n "publisher_role->close()" src/core/SLSManager.cpp` → no matches
- [ ] `setSize` takes a write lock; `m_nDataCount` is atomic/`int64`
- [ ] The reload loop uses `it = erase(it)` and does not `it++` after erase
- [ ] Both IP-ACL blocks handle IPv6 with a documented, non-silent-accept policy
- [ ] No `srt_setsockopt`-failure return in `libsrt_setup` leaks the socket/addrinfo
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` status row for 003 updated

## STOP conditions

- Step 5: `request_kick()` does not exist or is not safe to call from the HTTP thread —
  STOP and report; do not invent a new teardown mechanism here.
- Step 6: `sls_ip_access_t` / the parser cannot express the policy you need and the right
  behavior is unclear — STOP and report for an operator decision on IPv6 ACL semantics.
- Step 2/3: changing `m_nDataCount` to atomic breaks an assumption elsewhere
  (`grep -rn "m_nDataCount" src/`) — STOP and report.
- Any step's verification fails twice after a reasonable fix attempt.

## Maintenance notes

- Plan 007's lock rework will revisit `CSLSMapData`/`SLSRecycleArray` locking; the atomic
  counter and write-locked `setSize` from this plan are forward-compatible with it.
- If `request_kick` semantics change, re-check `disconnect_stream`.
- The IPv6 ACL behavior chosen here should be reflected in the config docs (plan 006) so
  operators know whether IPv6 ACLs are enforced.
- Reviewer: scrutinize Step 5 (teardown ownership) and Step 6 (don't silently accept IPv6).
