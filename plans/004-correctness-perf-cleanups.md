# Plan 004: Correctness & performance cleanups (lower-leverage)

> **Executor instructions**: Follow this plan step by step. Each step is independent with
> its own verification. If anything in "STOP conditions" occurs, stop and report. When
> done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 78d67c0..HEAD -- src/core/TSFileTimeReader.cpp src/core/SLSMapData.cpp src/core/SLSRecycleArray.cpp src/core/SLSRole.cpp src/core/SLSGroup.cpp src/core/constants.hpp`
> Compare excerpts against live code for any changed file; mismatch ⇒ STOP for that step.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: 001 (soft — tests for the TSFileTimeReader fix)
- **Category**: bug / perf
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

These are the lower-leverage items the audit surfaced: a real correctness bug in the file
replay path (wrong buffer used on loop wrap, plus a NULL-deref guard with inverted logic),
a needless write-lock that stalls the data path, a per-packet string allocation, and
per-packet log-formatting cost. None is an emergency, but each is cheap and removing them
reduces data-path overhead and tail-latency risk.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` | exit 0 |
| Build | `cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |

## Scope

**In scope**: `src/core/TSFileTimeReader.cpp`, `src/core/SLSMapData.cpp`,
`src/core/SLSMapData.hpp` (only if a transparent-comparator map change is made),
`src/core/SLSRecycleArray.cpp`, `src/core/SLSRole.cpp`, `src/core/SLSGroup.cpp`,
`src/core/constants.hpp` (only for the spdlog compile-time level), `CMakeLists.txt` (only
for `SPDLOG_ACTIVE_LEVEL`), and `tests/*`.

**Out of scope**: the global `CSLSMapData` lock design (plan 007); the ring-buffer counter
race (plan 003 Step 2 — do not duplicate it here).

## Git workflow

- Branch: `advisor/004-correctness-perf-cleanups`
- One commit per step, conventional-commits, lowercase, scoped.

---

## Step 1: Fix the TSFileTimeReader loop-wrap and NULL guards

**Risk: LOW.** **Confidence: HIGH.** Test-tool / file-replay path.

Three bugs in `src/core/TSFileTimeReader.cpp`:

(a) On loop reopen, the freshly read bytes in `rts_data` are ignored and the caller's
output buffer `data` is fed into the ring instead. Current state — `:144-148`:
```cpp
            n = ::read(m_rts_fd, rts_data, RTS_BUF_SIZE);
            if (n > 0)
            {
                m_array_data.put(data, n);   // BUG: should be rts_data
            }
```
Compare to the correct first-read at `:119-122` which uses `rts_data`. Fix: `m_array_data.put(rts_data, n);`.

(b) NULL guard with inverted operator — current state `:192`:
```cpp
    if (NULL == ts_file_name && strlen(ts_file_name) == 0)
```
`&&` means `strlen(NULL)` runs when `ts_file_name == NULL` (UB). Fix: change `&&` to `||`.

(c) Bad log arguments that will throw inside fmt (caught by spdlog, so the diagnostic is
lost rather than crashing). Current state `:169-170` and `:182-183`:
```cpp
        spdlog::error("[{}] CTSFileTimeReader::get, failed, m_array_data.get rts, ret={:d}.",
                      fmt::ptr(this), m_file_name, ret);          // 2 placeholders, 3 args, m_file_name -> {:d}
...
        spdlog::error("[{}] CTSFileTimeReader::get, failed, m_array_data. get data, ret={:d}, not {:d}.",
                      fmt::ptr(this), ret, m_file_name, ret, size); // 3 placeholders, 5 args, wrong order
```
Fix: make placeholders and arguments match, with correct types. For `:169-170`:
```cpp
        spdlog::error("[{}] CTSFileTimeReader::get, failed, m_array_data.get rts, file='{}', ret={:d}.",
                      fmt::ptr(this), m_file_name, ret);
```
For `:182-183`:
```cpp
        spdlog::error("[{}] CTSFileTimeReader::get, failed, m_array_data.get data, file='{}', ret={:d}, not {:d}.",
                      fmt::ptr(this), m_file_name, ret, size);
```

**Test**: if a unit seam exists (`CTSFileTimeReader` constructible without a live socket —
read `TSFileTimeReader.hpp`), add `tests/test_ts_file_time_reader.cpp`: write a small TS
file to a temp path, read it in loop mode, and assert the bytes returned after a wrap match
the start of the file (proving `rts_data` is used). If construction needs more than a file
path, note it and rely on the fixes being mechanical.

**Verify**: `cmake --build build -j` → exit 0;
`grep -n "m_array_data.put(data" src/core/TSFileTimeReader.cpp` → no matches;
`grep -n "NULL == ts_file_name && " src/core/TSFileTimeReader.cpp` → no matches.

---

## Step 2: Make `CSLSMapData::is_exist` use a read lock

**Risk: LOW.** **Confidence: HIGH.**

`is_exist` only reads but takes the write lock, which momentarily blocks every publisher
`put` and player `get` across the whole server.

Current state — `src/core/SLSMapData.cpp:169-172`:
```cpp
bool CSLSMapData::is_exist(char *key)
{
    CSLSLock lock(&m_rwclock, true);   // true == write lock, but this is read-only
    std::string strKey = std::string(key);
    ...
```

Fix: change `true` to `false`. Confirm the function body does not mutate `m_map_array`
(read it fully first; it only does a `find` and reads the entry).

**Verify**: `cmake --build build -j` → exit 0.

---

## Step 3: Remove the per-packet `std::string(key)` allocation on the data path

**Risk: LOW.** **Confidence: HIGH.**

`CSLSMapData::put` and `get` construct a `std::string` from the key on every packet, for a
`std::map` lookup — a heap allocation per packet per direction for realistic key lengths.

Current state — `src/core/SLSMapData.cpp:213-214` (`put`) and `:276-277` (`get`):
```cpp
    std::string strKey = std::string(key);
    ... m_map_array.find(strKey) ... (or find(key))
```

Fix (preferred, low-risk): give the map a transparent comparator so it can be looked up by
`std::string_view`/`const char*` without constructing a `std::string`. In
`src/core/SLSMapData.hpp`, change the map type from
`std::map<std::string, CSLSRecycleArray *>` to
`std::map<std::string, CSLSRecycleArray *, std::less<>>` (do the same for the other
per-key maps in this class that are hit on the data path — `m_map_ts_info` etc.; check the
header). Then in the hot `put`/`get` paths, look up with `std::string_view{key}` directly
and avoid building `strKey`. Keep `std::string` keys for `add`/`remove` (not hot).

Confirm `<string_view>` is included. Verify every `find`/`insert` still compiles with the
transparent comparator. Do NOT change the map to `unordered_map` (larger blast radius;
iteration order may matter elsewhere — `std::less<>` is the safe minimal change).

**Test**: covered indirectly by existing behavior; add no new test unless a seam exists.
The win is allocation count, not observable behavior.

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` → pass;
`grep -n "std::string strKey = std::string(key)" src/core/SLSMapData.cpp` → reduced to the
non-hot (`add`/`remove`) sites only, or removed.

> If the transparent-comparator change touches more call sites than expected and risks
> behavior change, fall back to the minimal version: only remove the `strKey` construction
> in `put`/`get` by calling `m_map_array.find(key)` where `key` is already comparable, and
> leave the type alone. If neither is clean, STOP and report.

---

## Step 4: Stop paying for per-packet `spdlog::trace` argument evaluation

**Risk: LOW.** **Confidence: HIGH.**

Per-packet `spdlog::trace(...)` calls on the data path evaluate their format arguments
(`fmt::ptr(this)`, counters) even though the default level filters them out, and if anyone
raises the log level to trace in production the formatter becomes the dominant data-path
cost and can take the server down.

Current state — examples: `src/core/SLSRecycleArray.cpp:117,141,148,176`,
`src/core/SLSRole.cpp` (per-packet read/write handlers), `src/core/SLSGroup.cpp` egress.
Default level — `src/core/constants.hpp:8` `DEFAULT_LOG_LEVEL = info`.

Fix (compile-time, lowest-risk and most effective): define the spdlog active level at
compile time so `trace`/`debug` calls compile to nothing in release builds. In
`CMakeLists.txt`, add a compile definition (guarded so a debug build can still get them if
desired):
```cmake
add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
```
`SPDLOG_ACTIVE_LEVEL` only takes effect for the `SPDLOG_TRACE(...)`/`SPDLOG_DEBUG(...)`
*macros*, not the `spdlog::trace(...)` *function* calls. So either:
- (a) keep it simple and accept that this only helps if/when call sites use the macros, OR
- (b) convert the **hot-path** per-packet `spdlog::trace(...)` call sites listed above to
  the `SPDLOG_TRACE(...)` macro form, which the compile-time level then strips entirely in
  release. Do this only for the per-packet sites (RecycleArray put/get, Role read/write
  handlers, Group egress), not every trace in the codebase.

Prefer (b) for the handful of per-packet sites; it is the change that actually removes the
cost. Confirm `#include <spdlog/spdlog.h>` exposes the macros (it does).

**Verify**: `cmake --build build -j` → exit 0; a release build
(`cmake -S . -B build-rel -DCMAKE_BUILD_TYPE=Release && cmake --build build-rel -j`) still
links; spot-check that the converted sites use `SPDLOG_TRACE`.

---

## Test plan

- `tests/test_ts_file_time_reader.cpp` (Step 1) if a seam exists.
- No new tests for Steps 2–4 (behavior-preserving perf changes); rely on the existing suite
  not regressing.
- `ctest --test-dir build --output-on-failure` → all pass.

## Done criteria

ALL must hold:

- [ ] `cmake --build build -j` exits 0; release build links
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] `grep -n "m_array_data.put(data" src/core/TSFileTimeReader.cpp` → no matches
- [ ] `is_exist` takes a read lock
- [ ] Per-packet `put`/`get` no longer construct a `std::string` for the lookup
- [ ] Hot-path per-packet trace sites use `SPDLOG_TRACE` (or the compile-time level is set and the limitation noted)
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` status row for 004 updated

## STOP conditions

- Step 3: the transparent-comparator change ripples into many call sites / risks behavior
  change and the minimal fallback isn't clean — STOP and report.
- Any step's verification fails twice after a reasonable fix.

## Maintenance notes

- Step 3 interacts with plan 007's lock rework (which may cache the entry pointer on the
  role and bypass the map lookup entirely) — that would supersede this micro-optimization;
  keep the change minimal so it's easy to revisit.
- If new per-packet log lines are added later, use `SPDLOG_TRACE`, not `spdlog::trace`.
