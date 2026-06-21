# Plan 008: `CSLSMapData` per-entry routing (lock rework)

> **Executor instructions**: This is the follow-up execution plan produced by Spike A of
> plan 007. It is staged: it begins with characterization tests and a prototype, then a
> measured decision, then a refactor only if the measurement justifies it. Do not skip
> the prototype/measure step. Run every verification before moving on. STOP per the STOP
> conditions; do not improvise around them. When done, update the row for this plan in
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat a7c358e..HEAD -- src/core/SLSMapData.hpp src/core/SLSMapData.cpp src/core/SLSRole.hpp src/core/SLSRole.cpp src/core/SLSPlayer.cpp src/core/SLSPublisher.cpp src/core/SLSPuller.cpp src/core/SLSRecycleArray.hpp src/core/SLSRecycleArray.cpp`
> For any in-scope file that changed, re-read the live "Current state" excerpts below
> before editing; on a structural mismatch, STOP and re-scope.

## Status

- **Priority**: P3
- **Effort**: L (prototype S, full lifetime rework L)
- **Risk**: HIGH (touches the per-packet data path and entry lifetime)
- **Depends on**: 001 (hard — characterization tests + TSan); 003 (atomic counter +
  write-locked `setSize` are forward-compatible foundations); 004 (transparent
  comparators + the cheap `is_exist` read-lock already landed and shrink the scope
  of this plan to the real win).
- **Category**: tech-debt / perf
- **Planned at**: commit `a7c358e`, 2026-06-21

## Why this matters

Today every `put()` and `get()` on the publisher ring traverses `CSLSMapData`'s per-server
rwlock (`m_rwclock`) just to find the entry, then immediately takes the per-entry ring
lock inside `CSLSRecycleArray`. With plan 004 the map lookup is a read lock, so puts and
gets to *different* keys no longer block each other. What remains is:

- Two `std::map` find calls per packet (m_map_array, m_map_ts_info), each O(log n)
  comparisons of a `std::string_view` against `std::string` keys.
- The rwlock's read-lock cache line bouncing across worker cores even when the lookups
  are uncontended (every worker pays the ticket).
- `add`/`remove`/`clear` still take the lock in **write** mode, which momentarily stalls
  every other put/get on the same server — fine in practice today (publisher churn is
  low), but it ties future work like cross-worker fan-out (plan 012) to a global gate.

Plan 004 already harvested the cheap wins (read-lock `is_exist`, transparent comparators,
read-lock `set_audio_gap_fill`). The real win — cutting the map lookup out of the
per-packet path entirely — needs a lifetime-safe way for a role to hold the
`CSLSRecycleArray*` and `ts_info*` directly.

## Current state

`src/core/SLSMapData.hpp:91-101` — the map shape (now with transparent comparators):

```cpp
private:
    std::map<std::string, CSLSRecycleArray *, std::less<>> m_map_array;
    std::map<std::string, ts_info *, std::less<>> m_map_ts_info;
    CSLSRWLock m_rwclock;
```

`src/core/SLSMapData.cpp:196-265` (`put` — the per-packet hot path):

```cpp
int CSLSMapData::put(char *key, char *data, int len, int64_t *last_read_time)
{
    ...
    CSLSLock lock(&m_rwclock, false);                 // read lock per packet
    std::string_view keyView{key};

    auto item = m_map_array.find(keyView);            // O(log n) per packet
    ...
    auto item_ti = m_map_ts_info.find(keyView);       // O(log n) per packet
    ...
    ret = array_data->put(data, len);                 // then the per-entry ring lock
```

`src/core/SLSMapData.cpp:267-298` (`get` — same shape on the read side; one map lookup
plus an optional `get_ts_info` lookup at first read).

`src/core/SLSMapData.cpp:133-165` (`remove` — write lock; deletes the
`CSLSRecycleArray*` and `ts_info*`):

```cpp
CSLSLock lock(&m_rwclock, true);
auto item_ti = m_map_ts_info.find(strKey);
... delete ti; ...
auto item = m_map_array.find(strKey);
... delete array_data; ...
```

The data-path callers — `src/core/SLSRole.cpp:338-345` (`set_map_data`) — already cache
the `CSLSMapData*` and the key string on the role; they do NOT cache the
`CSLSRecycleArray*` / `ts_info*`. Every put/get re-discovers them.

There is one `CSLSMapData` per configured server (`src/core/SLSManager.cpp:145`:
`m_map_data = new CSLSMapData[m_server_count]`); a single typical deployment runs one
server, so this is effectively process-global on the data path.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure` | exit 0, no races |
| ASan | `cmake -S . -B build-asan -DSLS_SANITIZE=ON -DSLS_BUILD_TESTS=ON && cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure` | exit 0, no UAF |
| Microbench (Step 1) | (new) `build/bin/sls_bench_mapdata` driven from the test harness | publishes baseline numbers |

## Scope

**In scope**: `src/core/SLSMapData.hpp`, `src/core/SLSMapData.cpp`,
`src/core/SLSRole.hpp/.cpp` (to hold the cached pointers), the per-direction call sites
that read those pointers (`SLSPublisher`, `SLSPuller`, `SLSPlayer`), and the test/bench
harness under `tests/`.

**Out of scope**: any change to `CSLSRecycleArray`'s internals (it already has its own
write lock); cross-worker fan-out (plan 012; it composes with this but is its own plan);
the per-server `CSLSMapData[N]` allocation (still owned by `SLSManager`).

## Git workflow

- Branch: `advisor/008-mapdata-lock-rework`
- One commit per step, conventional-commits, lowercase, scoped: `perf(mapdata): ...`,
  `test(mapdata): ...`. Do NOT push or open a PR unless instructed.

---

## Step 1: Characterization tests + microbench (preconditions)

**Risk: LOW.** **Confidence: HIGH.**

Before touching the data path, lock its current behavior and measure the cost of the
status quo. The whole point of this plan is "skip the map lookup per packet", so we have
to demonstrate the lookup actually costs something on the hot path; otherwise plan 007's
own STOP condition fires.

Add to `tests/` (using the doctest harness from plan 001):

1. `tests/test_mapdata.cpp` — characterization for `CSLSMapData`:
   - `add` then `put` then `get` round-trips a packet through the ring for the same key.
   - Two keys can `put` concurrently from two threads (rough; doctest assertion that no
     data race triggers under TSan — leave to TSan to flag).
   - `remove(key)` while a worker is in mid-put on that key is the **interesting** case;
     this test is the regression net for the lifetime change in Step 3. The current
     implementation does NOT have a safe `remove`-during-`put` path (it relies on the
     accept thread never racing the worker's put for the same key); the test should
     therefore start by **documenting** the current invariant (single-publisher-writer
     per key) and only later — after Step 3 — exercise the cross-thread teardown.
2. `tests/bench_mapdata.cpp` — a microbench, gated behind `-DSLS_BUILD_BENCH=ON` so it
   does not run in default CI. Drives `put()` from N threads on M keys for T seconds,
   reports ns/op, and compares against a baseline run we save in
   `tests/data/bench_mapdata_baseline.txt`. **The threshold for proceeding past Step 2
   is documented in this file**: per-packet `find()` overhead must be >= ~50ns at
   realistic M (say 64 keys, 4 worker threads) to justify the lifetime rework. Lower
   than that — STOP and write a "not worth doing" note (plan 007 STOP condition).

**Verify**:
- `cmake --build build -j` → exit 0
- `ctest --test-dir build --output-on-failure` → new mapdata tests pass
- `build/bin/sls_bench_mapdata --keys=64 --threads=4 --secs=5` → produces ns/op + p99
  numbers; write baseline to `tests/data/bench_mapdata_baseline.txt`

---

## Step 2: Prototype the cached-pointer fast path (no lifetime change)

**Risk: LOW (prototype, behind a feature flag).** **Confidence: MED.**

Goal: show the cached-pointer path beats the map lookup by enough to be worth the
lifetime work. Keep the existing API; add a parallel one and toggle it with a build
flag.

Add to `src/core/SLSMapData.hpp`:

```cpp
public:
    struct EntryHandle {
        CSLSRecycleArray *array = nullptr;
        ts_info          *ti    = nullptr;
        // For Step 3: a versioned tag or shared_ptr/weak_ptr to detect
        // staleness. Left as a TODO comment in the prototype.
    };

    // Look up once at set_map_data time; the result is only valid as long
    // as the entry is not remove()'d. In the prototype, the caller MUST
    // call this AFTER add() and stop using the handle BEFORE remove();
    // this is exactly the invariant the role lifecycle already enforces.
    EntryHandle lookup_entry(const char *key);

    // Fast-path put/get that bypasses the map. Same semantics as
    // put/get otherwise; the per-entry ring lock inside
    // CSLSRecycleArray is the only synchronisation that runs.
    int put_via(EntryHandle h, char *data, int len, int64_t *last_read_time = nullptr);
    int get_via(EntryHandle h, char *data, int len, SLSRecycleArrayID *read_id, int aligned = 0);
```

In `SLSRole.cpp::set_map_data` cache `EntryHandle` alongside `m_map_data_key`. Gate the
fast path with a runtime flag from config (`mapdata_fast_path=on/off`) so we can
compare in production:

```cpp
if (sls_conf_get_root_conf()->mapdata_fast_path) {
    return m_map_data->put_via(m_map_data_entry, ...);
}
return m_map_data->put(m_map_data_key, ...);   // existing path
```

This is a prototype, NOT the final state — `EntryHandle` carries the raw pointers
unchanged from `m_map_array.find()`, so a `remove()` from another thread still races.
That is exactly why Step 3 exists. The prototype is safe under the *current* invariant
that `remove()` runs strictly after the owning publisher role has been torn down.

**Verify**:
- Build with the flag off: identical behavior to today; all tests pass.
- Build with the flag on: tests still pass; bench shows the expected put/get speedup
  (>= the threshold from Step 1). Record before/after numbers in the commit message.

**STOP**: bench delta < threshold → STOP, write up "not worth doing" in
`plans/008-mapdata-lock-rework.md` (replace this plan's Done criteria with a finding
note and reject the row in `plans/README.md`). Do NOT proceed to Step 3.

---

## Step 3: Entry lifetime — make `EntryHandle` safe to outlive a `remove()`

**Risk: HIGH.** **Confidence: MED.** This is the only step that changes correctness;
the rest is mechanical.

The fast path is only safe to ship if a worker can be mid-`put_via(h, ...)` while another
thread `remove()`s the entry, without UAF. Three viable designs — pick one in this step:

**Option A: `shared_ptr<EntryData>` + atomic snapshot in the map.**
Wrap `CSLSRecycleArray*` and `ts_info*` in `struct EntryData { CSLSRecycleArray array;
ts_info ti; };` owned by `std::shared_ptr<EntryData>`. `m_map_array` holds the
`shared_ptr`. `EntryHandle` is also a `shared_ptr` snapshot. `remove()` erases from the
map; the last `shared_ptr` reaping (held by the in-flight `put_via` callers) deletes the
data. Simple, well-understood; cost is the per-`set_map_data` `shared_ptr` copy (atomic
inc/dec) — **not** per packet, because the role holds it for the whole connection.

**Option B: RCU-style two-phase delete.**
`remove()` flips a `draining` flag on the entry and pushes it onto a retire list;
workers' next per-iteration tick checks the list and reclaims entries no longer in use
(tracked by a per-worker generation counter). Lowest steady-state overhead, highest
implementation cost, hardest to get right under TSan. Probably overkill for SLS's
publisher churn rate.

**Option C: `weak_ptr<EntryData>` cached on the role, `lock()` per packet.**
Same ownership as A but the role holds a `weak_ptr`; `put_via` does `auto sp =
weak.lock(); if (!sp) return SLS_ERROR;` per packet. Crashes-safe by construction but
re-introduces an atomic refcount op per packet — likely eats most of the win Step 1
measured.

**Recommendation**: start with **Option A**. The role already holds the entry for its
entire lifetime (set in `SLSRole::set_map_data`, released on teardown), so a single
`shared_ptr` copy per connection has no measurable per-packet cost. We retain the
existing invariant that `remove()` runs after the publisher role is torn down — the
`shared_ptr` ownership just makes that invariant *enforced by the type system* instead
of by code review.

Migration:
1. Change `m_map_array` to `std::map<std::string, std::shared_ptr<RingEntry>, std::less<>>`
   where `RingEntry { CSLSRecycleArray array; ts_info ti; bool draining{false}; };`.
   `ts_info` and `CSLSRecycleArray` become value members of `RingEntry` (no separate
   `new`/`delete`).
2. `EntryHandle` becomes `std::shared_ptr<RingEntry>`.
3. `add()` constructs the entry with `std::make_shared<RingEntry>()`. `remove()` erases
   from the map; the last role/manager holding a reference frees it.
4. Delete `m_map_ts_info` — `ts_info` is now part of `RingEntry`.
5. All non-fast-path callers (`is_exist`, `get_overrun_count`, `set_audio_gap_fill`,
   `get_audio_gap_stats`, `get_ts_info`) keep using the map under the rwlock; only
   `put_via`/`get_via` (and an analogous `audio_gap_fill_via` if we want it) take the
   handle. **This is intentional** — the management calls are not on the hot path.
6. Remove the flag from Step 2: the fast path is now the only path for `put`/`get`. Keep
   the slow `put(key, ...)` / `get(key, ...)` API around for relays that build a handle
   lazily (the puller path constructs a `CSLSPuller` and then calls `set_map_data` — same
   flow as a publisher; verify it caches the handle the same way).

**Verify**:
- ASan + TSan builds clean.
- A new test `tests/test_mapdata_lifetime.cpp` constructs a remover thread that calls
  `remove()` repeatedly while a putter thread holds a handle and calls `put_via` — must
  not UAF, must not race. Use the doctest harness with explicit join.
- Existing characterization from Step 1 still passes.

**STOP**: TSan flags a race that Option A should have ruled out → STOP and re-review
the lock interaction with `CSLSRecycleArray`'s own write lock; the most likely cause is
an entry being reaped while its ring is mid-write because the role teardown order is
wrong, which would be a real bug to surface.

---

## Step 4: Migrate the per-server `CSLSMapData[N]` allocation to `std::vector`

**Risk: LOW.** **Confidence: HIGH.**

Tied to Step 3 because `RingEntry` now owns a `CSLSRecycleArray` by value; the
`CSLSMapData[m_server_count]` array allocation in `SLSManager.cpp:145-148` becomes
copy-constructibility-sensitive. Replace the four raw `new[]` arrays
(`m_map_data`, `m_map_publisher`, `m_map_puller`, `m_map_pusher`) with
`std::vector<CSLSMapData>` / `std::vector<CSLSMapPublisher>` etc. Plan 010 picks this up
as its first step; coordinate so plans 008 and 010 do not both touch
`SLSManager::start()` independently. (Easiest order: do plan 010 Step 1 first, then this
plan.)

**Verify**: `cmake --build build -j` → exit 0; `valgrind --leak-check=full` (or ASan) on
a smoke run shows no leak.

---

## Test plan

- `tests/test_mapdata.cpp` (Step 1) — characterization round-trip + concurrent puts on
  different keys.
- `tests/bench_mapdata.cpp` (Step 1) — microbench gated by `-DSLS_BUILD_BENCH=ON`, with
  a baseline file checked into `tests/data/`.
- `tests/test_mapdata_lifetime.cpp` (Step 3) — remove-during-put under TSan.
- `ctest --test-dir build --output-on-failure` and TSan/ASan variants all green.

## Done criteria

ALL must hold:

- [ ] Characterization tests for `CSLSMapData` land before any production-code change
- [ ] Microbench baseline is checked into `tests/data/` and is referenced from this plan
- [ ] Either the fast path lands AND meets the bench threshold, OR a "not worth doing"
      finding is recorded and the README row is REJECTED with the measurement
- [ ] TSan and ASan builds clean on a smoke run with at least one publisher + one
      player + a `/disconnect` from the HTTP control thread
- [ ] No call site outside this plan's scope was modified (`git status`)
- [ ] `plans/README.md` row for 008 updated

## STOP conditions

- Bench delta < threshold from Step 1 → STOP (write the "not worth doing" finding and
  REJECT this plan).
- Step 3 lifetime change cannot be made safe under TSan with any of the three designs
  → STOP and report; do NOT ship a fast path with a known race even behind a flag.
- A drift-check mismatch on `SLSMapData.*` or `SLSRole.*` → STOP and re-scope.
- Plan 001's TSan target is not green on `main` before this plan starts → STOP.

## Maintenance notes

- Plan 012 (cross-worker fan-out) composes with this: dispatching a player into the
  publisher's worker reduces the multi-core data-path traffic that this plan accelerates.
  Land 008 first, then 012 — 012's win is on top of the per-packet floor 008 sets.
- The `shared_ptr<RingEntry>` choice keeps the entry-lifetime contract obvious from the
  type. If we ever need a publisher to move keys (rename) at runtime, the same machinery
  generalises (insert + drop the old handle), but that is not a goal of this plan.
- Reviewer: scrutinize Step 3 (lifetime) and confirm Step 4 was coordinated with plan
  010 to avoid two refactors fighting over `SLSManager::start()`.

## Open questions

1. Do any management calls (`/stats`, audio-gap toggles) need to be added to the fast
   path, or is the rwlock-protected slow path sufficient for them forever? Plan 007's
   audit suggests forever; confirm during Step 2.
2. Does any relay code (`CSLSPuller`, `CSLSPusher`) call `m_map_data->put/get` with a
   key OTHER than the one stashed in `m_map_data_key`? `grep -n "->put(\|->get(" src/core`
   to confirm before Step 3. If yes, those sites need a handle too or stay on the slow
   path.
3. `set_audio_gap_fill` currently takes a read lock and mutates a `bool` field; under
   Option A this becomes a plain store on the handle's `ts_info` — verify no other
   reader expects the rwlock to fence that write.
