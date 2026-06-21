# Plan 012: Worker affinity — co-locate players with their publisher

> **Executor instructions**: This is the follow-up execution plan produced by Spike E of
> plan 007. It is staged: characterization + latency measurement first, then a small
> dispatch change, then verification. The whole point is "measure, then move", not "move
> and hope". Run every verification before moving on. STOP per the STOP conditions.
> When done, update the row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat a7c358e..HEAD -- src/core/SLSGroup.cpp src/core/SLSGroup.hpp src/core/SLSManager.cpp src/core/SLSManager.hpp src/core/SLSListenerHandler.cpp src/core/SLSRoleList.cpp src/core/SLSRoleList.hpp src/core/SLSMapPublisher.cpp src/core/SLSMapPublisher.hpp`
> For any in-scope file that changed, re-read the live excerpts below before editing;
> structural mismatch is a STOP condition.

## Status

- **Priority**: P3
- **Effort**: M (measurement S, dispatch change S, validation M)
- **Risk**: MED–HIGH (touches the worker dispatch — the single most concurrency-sensitive
  decision in the server). A misrouted player is invisible from the role's PoV but
  silently re-introduces the 10ms latency this plan is trying to eliminate.
- **Depends on**: 001 (hard — measurement harness); 008 (soft — composes with the
  per-entry routing; a misrouted player still works, just costs the map lookup it
  otherwise would not). Land 008 first if possible; 012 still ships if 008 stalls.
- **Category**: perf / arch
- **Planned at**: commit `a7c358e`, 2026-06-21

## Why this matters

`POLLING_TIME` in `src/core/SLSGroup.cpp:42` is `10` ms — the worst-case wait for a
worker's `srt_epoll_wait` to wake when there is no SRT event. Since plan 004's epoll
arming changes, players and pushers register **ERR-only** for epoll events; egress is
driven by the worker's periodic pass over the publisher ring. That works perfectly when
the publisher and the players share a worker (the publisher's IN event wakes the same
worker that owns the players). **When they do not share a worker, the player worker has
no SRT event to wake it when ring data appears — so it sleeps the full POLLING_TIME
before it next checks the ring.** Result: a viewer whose publisher lives in another
worker eats up to 10 ms of forwarding latency per packet train, on top of SRT's own
TSBPD budget.

10 ms is a deliberate, well-commented trade-off — it caps the idle-wakeup cost at
~100 wakeups/sec/worker. Shortening it costs CPU; lengthening it costs latency. The
right fix is to make sure a player **lives in its publisher's worker by construction**,
so the cross-worker path is rare and the 10 ms POLLING_TIME stays cheap.

A second, smaller benefit: a stream's publisher + players + pusher all touching the
same `CSLSMapData` ring lock from one core reduces cache-line bouncing — composes with
plan 008's per-entry routing.

The audit listed two candidate designs (worker affinity vs wake-on-put). This plan
picks worker affinity. Wake-on-put has worse failure modes (eventfd write storms under
fan-out) and overlaps with what srt_epoll already does for the publisher worker.

## Current state

`src/core/SLSGroup.cpp:32-42` — the POLLING_TIME comment that documents the latency:

```cpp
// Max time the worker blocks in srt_epoll_wait when nothing is ready.
// Since players/pushers are no longer permanently armed for
// SRT_EPOLL_OUT (see CSLSSrt::libsrt_add_to_epoll), egress is driven by
// the worker's periodic pass over the publisher ring; for a viewer whose
// publisher lives in a *different* worker, this timeout is therefore the
// worst-case forwarding latency (that worker has no SRT event to wake it
// when ring data arrives). 10ms keeps cross-worker egress latency well
// inside any viewer's TSBPD budget while costing only ~100 idle wakeups
// per second per worker (each a tiny no-op pass), with no busy-spin
// because nothing is permanently writable.
#define POLLING_TIME 10
```

`src/core/SLSGroup.cpp:114-149` — `check_new_role` pops the *next* role off the shared
`m_list_role` without regard to which publisher's stream it serves:

```cpp
CSLSRole *role = m_list_role->pop();
if (NULL == role) return;
...
if (0 == role->add_to_epoll(m_eid)) {
    m_map_role[fd] = role;
    ...
}
```

`src/core/SLSRoleList.hpp:35-52` — the shared role list:

```cpp
class CSLSRoleList {
public:
    int push(CSLSRole *role);
    CSLSRole *pop();   // FIFO; no per-worker partition
    int size();
    int count_players_for_stream(const char *stream_key);
private:
    std::list<CSLSRole *> m_list_role;
    CSLSMutex m_mutex;
};
```

`src/core/SLSListenerHandler.cpp:721` (publisher push) and `:988` (player push) push to
the same shared list. The listener thread does not know which worker should own a given
role; it can only push to the global queue. Whichever worker happens to be in
`check_new_role` next pops the role — random affinity.

`src/core/SLSManager.cpp:307-342` — the workers themselves: `m_workers` is a
`std::vector<CSLSGroup*>`, indexed by `worker_number`. Each worker calls
`check_new_role` from its `idle_check` cadence; the first one to look gets the next
role.

`src/core/SLSMapPublisher.cpp` (not shown — read it) owns the `key_stream_name ->
CSLSRole*` map of active publishers; the listener already uses
`get_publisher(key_stream_name)` to detect takeover. That same lookup is the seam this
plan uses to find the publisher's worker.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure` | exit 0 |
| Latency probe (Step 1) | (new) `tools/probe_latency.sh` — publisher + 2 players, log per-packet timestamp deltas | p95/p99 numbers recorded |

## Scope

**In scope**:
- `src/core/SLSRoleList.{hpp,cpp}` (per-worker partition).
- `src/core/SLSGroup.{hpp,cpp}` (worker now pops from its own queue or accepts a
  pushed role).
- `src/core/SLSManager.{hpp,cpp}` (own the worker vector; provide a way for the
  listener to look up the publisher's worker).
- `src/core/SLSListenerHandler.cpp` (dispatch logic — pick a worker on push).
- `src/core/SLSMapPublisher.{hpp,cpp}` (optionally record the worker that owns a
  publisher; see Step 3 for the recommended seam).
- `tools/probe_latency.sh` (or equivalent — new bench harness).

**Out of scope**:
- The puller/pusher dispatch (relays are pushed by listener like everything else;
  they get the same routing); plan 011 owns their internal structure.
- The data path itself (`CSLSMapData`, `CSLSRecycleArray`). Plan 008 owns that.
- Reducing `POLLING_TIME` below 10. Doing so trades CPU for latency the same way
  fixing affinity does, but with a worse cost/benefit; this plan rules it out.

## Git workflow

- Branch: `advisor/012-worker-affinity`
- One commit per step; the measurement commits land first (they are the contract).
- Conventional commits, lowercase, scoped: `bench(worker): ...`, `perf(worker): ...`,
  `refactor(worker): ...`. Do NOT push or open a PR unless instructed.

---

## Step 1: Measurement — characterise the cross-worker latency cost

**Risk: LOW.** **Confidence: MED (the measurement is doable; the threshold below is a
recommendation, not a number we got from the field).**

Before changing the dispatch, get numbers. A misrouted player on a *single-worker*
deployment costs zero — `worker_threads = 0` (or `1`) is a very common config and the
whole problem disappears there. The measurement decides:

(a) whether the cross-worker path is hit in practice (it is hit if workers > 1 AND
    the publisher + player happen to land in different workers — random affinity makes
    that >= 50% likely on 2 workers).
(b) what the latency cost actually is (p99 should be near POLLING_TIME on a
    cross-worker placement, near zero on a same-worker placement).

Build the probe:

1. `tools/probe_latency.sh` (or a small C++ harness in `tools/`) brings up sls with
   `worker_threads = 4`, one publisher, two players, an integration runner that:
   - injects timestamped TS packets at the publisher,
   - captures the same packets at the player(s),
   - reports per-packet end-to-end delta.
2. Run with the **current code** (random affinity) — collect p50/p95/p99 over 60s.
3. Compute the cross-worker hit rate: if both players land in the publisher's worker,
   you observed the best case; if either lands elsewhere, that one shows the cost.
   Random affinity should give ~75% cross-worker incidence on 4 workers.

Add to `src/core/SLSGroup.cpp` (gated behind `-DSLS_DEBUG_AFFINITY=ON`): per-role
debug logging on first packet that records `worker_number == publisher_worker_number`.
That label is what the probe reads to bucket samples.

**Acceptance threshold for proceeding to Step 2**: p99 cross-worker latency is at least
~5 ms higher than p99 same-worker latency. Lower than that — STOP and write up "not
worth doing" (plan 007 STOP condition). Configure `worker_threads = 0` is the moral
equivalent of affinity for single-stream deployments.

**Verify**:
- `tools/probe_latency.sh` runs end-to-end and produces JSON/CSV with the deltas.
- Numbers are recorded in `tests/data/latency_baseline.txt` and referenced in the
  commit message.

**STOP**: p99 cross-worker delta < threshold → STOP, write the "not worth doing"
finding, REJECT this plan in `plans/README.md`. The 10ms `POLLING_TIME` is a documented
worst case; if production doesn't hit it, do not bother.

---

## Step 2: Partition `CSLSRoleList` per worker

**Risk: MED.** **Confidence: HIGH.** Mechanical, but touches a hot mutex.

Today there is one `CSLSRoleList` shared by all workers. Each worker pops in
`check_new_role`; the mutex is contended only on push (listener) + pop (worker).
With per-worker partitioning we want N independent lists, one per worker.

Shape the change:

```cpp
// SLSManager.hpp — own the list shape directly; CSLSRoleList stays a thin per-worker
// wrapper around the mutex+list it has today.
std::vector<CSLSGroup *> m_workers;          // unchanged
// Each worker carries its own CSLSRoleList; remove the shared one.
```

`CSLSGroup` already has access to its own role list reference (the existing
`set_role_list`); change that from "pointer to shared" to "pointer to its own" — same
type, different ownership. The listener still pushes via a list reference; the change
is which list it picks.

The listener now needs a way to pick a worker. Replace the listener's
`set_role_list(CSLSRoleList *)` with `set_workers(const std::vector<CSLSGroup *> *)` and
move the push-dispatch into a new listener method (Step 3 fleshes this out).

**Backpressure**: keep the `MAX_HANDOFF_BACKLOG` ceiling (`SLSListenerHandler.cpp:25`)
per worker, NOT total. A flooded worker should refuse, not pile onto a quieter one
(that would silently re-introduce the cross-worker latency we just removed).

**Verify**:
- `wc -l src/core/SLSRoleList.cpp` is unchanged (we did not change the list itself).
- A smoke build + the existing tests pass.
- `count_players_for_stream` still works (now scoped to a single worker's list — the
  listener's per-stream cap check needs to iterate workers, or use the map_publisher
  worker lookup; verify the count is correct).

**STOP**: `count_players_for_stream` returns the wrong number after partitioning →
STOP, fix the iteration; the per-stream cap is a security/policy invariant.

---

## Step 3: Record the publisher's worker; route players to it

**Risk: MED.** **Confidence: HIGH.** This is the actual affinity change.

The publisher's worker is known at the moment the worker calls
`check_new_role` and adopts the publisher role. Capture that:

- In `CSLSGroup::check_new_role`, when the popped role is a publisher (or the *first*
  registration for a `key_stream_name`), call
  `m_map_publisher->record_publisher_worker(key_stream_name, m_worker_number)`.
- Add `record_publisher_worker(const char *key, int worker_number)` and
  `get_publisher_worker(const char *key)` to `CSLSMapPublisher`. Use the existing
  map mutex — these are coarse operations (one per publisher accept/teardown), not
  hot path.
- On publisher teardown, clear the mapping.

In `CSLSListener::handler` (specifically `finish_player_accept_v2` after plan 009
landed — or the existing `finish_player_accept` if not), pick the destination worker
on player push:

```cpp
int worker = m_workers->get_worker_for_publisher(key_stream_name);
// worker == -1 means publisher not registered yet (puller race, pre-accept) — fall
// through to round-robin; the player will pick up the publisher's later registration
// via the next epoll event (slow path, but correct).
if (worker < 0) worker = round_robin_worker_for_listener_balance();
(*m_workers)[worker]->push_role(player);
```

`CSLSGroup::push_role(CSLSRole *)` enqueues onto that worker's local
`CSLSRoleList`. It also calls `wake()` (already implemented) on that worker so
`check_new_role` runs immediately, not after the next POLLING_TIME — eliminates the
first-packet latency at adoption time too.

For pushers / pullers (relays), use the same rule: the relay role belongs to the
worker that owns the publisher (pusher) or the puller-as-publisher (puller). Plan
011's relay rewrite slots into the same `push_role` call.

**Verify**:
- The probe from Step 1 reports same-worker placement >= 99% (only races where the
  player arrives before the publisher land elsewhere; they self-correct on takeover).
- Cross-worker latency p99 drops to same-worker p99.
- TSan clean on a publisher-takeover + multi-player smoke run.
- `count_players_for_stream` still returns the right total per stream (now: query the
  worker that owns the publisher).

**STOP**: p99 latency does not improve — STOP, verify the affinity took effect (was
the publisher's worker recorded before the player push? Is the player actually being
pushed to that worker's queue and not the wrong one?). The most likely bug is a stale
or missing `record_publisher_worker` call on the takeover path.

---

## Step 4: Long-tail — handle the races

**Risk: LOW–MED.** **Confidence: MED.**

Three race conditions to handle explicitly:

1. **Player arrives before publisher.** Today the player is pushed; the publisher
   later registers; the player picks up data on its first ring read. Under affinity,
   the player lands in whatever worker the listener picked (round-robin in our
   fallback), which may not be the publisher's worker. On the publisher's first
   `set_push_2_publisher`, the manager learns the publisher's worker — but the player
   is already adopted elsewhere. Mitigation: leave this race in. The player still
   works; it just keeps the original cross-worker latency until it reconnects. The
   probe should show this is a small fraction in steady state.
2. **Publisher takeover.** `request_kick` evicts the incumbent publisher (plan 003 Step
   5). The new publisher will likely land in a different worker (round-robin). All
   existing players keep their adopted-at-accept-time worker — same race as #1.
   Mitigation: same as #1. Optional follow-up: re-adopt players when the publisher's
   worker changes (an opt-in feature, not free).
3. **Worker shutdown.** During reload (`stop()` path in `SLSManager.cpp:540`), a worker
   may be reaped while it still has roles. The existing `m_list_wait_http_role`
   cleanup handles roles waiting for HTTP; partition the role list cleanup similarly
   so each worker drains its own list.

**Verify**:
- A reload (`SIGHUP`) with active streams completes cleanly under ASan.
- The probe's affinity rate is logged and observed to be >= 99% in steady state.

---

## Test plan

- `tools/probe_latency.sh` (Step 1) — produces baseline + post-affinity numbers,
  stored in `tests/data/latency_baseline.txt` and `tests/data/latency_after.txt`.
- `tests/test_worker_dispatch.cpp` — unit-level test: push two players to a manager
  with two workers; the publisher is in worker 0, both players should be enqueued to
  worker 0's role list. Push a player before the publisher; verify the fallback
  behaviour (round-robin, no crash, player keeps working).
- TSan + ASan smoke runs (publisher + multi-player + reload + `/disconnect`).

## Done criteria

ALL must hold:

- [ ] Baseline cross-worker latency is recorded BEFORE any dispatch change lands
- [ ] Post-change measurement shows p99 cross-worker latency drops to within ~1 ms of
      same-worker p99 (or the plan is REJECTED per STOP condition)
- [ ] `CSLSRoleList` is per-worker; the shared one is gone
- [ ] `CSLSMapPublisher` records the publisher's worker; the listener uses it on
      player push
- [ ] `MAX_HANDOFF_BACKLOG` is now a per-worker ceiling
- [ ] `count_players_for_stream` returns the correct count under partitioning
- [ ] TSan + ASan clean on a smoke run including reload and publisher takeover
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` row for 012 updated

## STOP conditions

- Step 1 measurement shows cross-worker latency p99 is not meaningfully higher than
  same-worker — STOP and REJECT this plan with the measurement attached.
- Step 3 affinity lands but p99 does not improve — STOP, do not ship; the dispatch is
  not actually routing where you think.
- Step 2 partitioning breaks `count_players_for_stream` — STOP and fix before
  proceeding; the per-stream cap is a security/policy invariant.
- A drift-check mismatch on any of the four core files (`SLSGroup`, `SLSManager`,
  `SLSListenerHandler`, `SLSMapPublisher`) — STOP and re-read.
- Plan 001 is not green on `main` — STOP; this plan needs the verification baseline.

## Maintenance notes

- Affinity composes with plan 008 (per-entry routing): an affined worker hits the same
  ring entry every packet, so the per-entry cache lines stay hot on that core.
- The Step 3 race ("player before publisher") may warrant a re-adoption mechanism if
  the probe shows the affined fraction is < 99% in real workloads. Open follow-up.
- `POLLING_TIME = 10` stays as-is. Its rationale (cap idle wakeups) is independent of
  this plan; lowering it post-affinity costs CPU for no latency benefit (the win is
  already cashed by routing).
- If `worker_threads = 0` (single-threaded mode), this whole plan is a no-op by
  construction. Make sure the dispatch code handles that case (lookup returns 0,
  push_role goes to the only worker).
- Reviewer: scrutinize Step 3's `record_publisher_worker` call sites — every adoption
  path (initial accept, puller-as-publisher, post-takeover re-registration) must
  record. Missing one silently regresses to random affinity for that stream.

## Open questions

1. Should the listener re-affine existing players when the publisher's worker changes
   (takeover or worker reaped on reload)? Probably yes for completeness, but it
   requires moving a live SRT socket between two `epoll` sets — non-trivial and worth
   its own plan if Step 1's measurement justifies the work.
2. Pullers (which act as publishers from `CSLSMapData`'s PoV) need the same affinity
   recording. Verify the puller's adoption flow goes through `set_push_2_publisher`
   and that the manager records the worker the same way as a publisher accept.
3. Should the per-worker queue be a lock-free MPMC instead of `std::list + mutex`?
   Today the contention is one push per accept and one pop per worker tick — far below
   what a mutex chokes on. Defer; mark as a follow-up only if a profile shows it.
