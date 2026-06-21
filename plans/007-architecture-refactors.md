# Plan 007: Architecture refactors (design / spike)

> **Executor instructions**: This is a **design/spike plan**, not a build-it-blind plan.
> Each section asks you to investigate, prototype small, define an approach, and produce a
> concrete follow-up execution plan (a new `plans/00N-*.md`) — NOT to land a large refactor
> in one pass. Do not start any of these refactors against production code until plan 001
> (the verification baseline) has landed and the relevant characterization tests exist.
> When done with a spike, write its findings + proposed execution plan and update
> `plans/README.md`.
>
> **Hard prerequisite**: plan 001 (tests + ASan/TSan + CI) MUST be DONE first. These
> refactors are high-risk and the repo has no regression net without it.

## Status

- **Priority**: P3
- **Effort**: L (each sub-item is its own multi-day effort once specced)
- **Risk**: HIGH (these touch the hottest, most concurrency-sensitive code)
- **Depends on**: 001 (hard). Several also want 003 landed first.
- **Category**: tech-debt
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

The audit found real architectural debt: a single per-server lock that serializes the
entire data path, a 653-line accept-time god function that duplicates security-sensitive
logic, two ~1000-line junk-drawer files, an 80%-duplicated Puller/Pusher pair, and a
designed-in cross-worker forwarding latency. Each slows feature work and concentrates risk.
But each is also a large, dangerous change in a codebase with (until plan 001) no tests.
The right move is to spike each one: understand it, prototype the seam, measure, and write a
tight execution plan — rather than improvise a big-bang refactor.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j` | exit 0 |

## Scope

**In scope (for the spikes)**: read-only investigation across `src/core/`, small throwaway
prototypes on a branch, and **writing new plan files** under `plans/`. Any production code
change beyond a measured, reversible prototype belongs in the follow-up execution plan the
spike produces.

**Out of scope**: landing any of these refactors in this plan; the small ring-buffer fixes
(plan 003 owns those).

## Git workflow

- Branch: `advisor/007-<spike-name>` per spike.
- Prototypes are throwaway; the deliverable is a `plans/00N-*.md` execution plan plus a
  short findings note.

---

## Spike A: Global `CSLSMapData` rwlock serializes the whole data path

**Evidence**: `src/core/SLSMapData.cpp:172` (`is_exist`, write lock — also fixed cheaply in
plan 004), `:213` (`put`), `:276` (`get`) all take one per-server `m_rwclock`
(`SLSMapData.hpp:94`); `add`/`remove`/`clear` take it in write mode and stall every stream.

**Investigate**:
- Confirm there is one `CSLSMapData` per server holding all stream keys (`SLSManager.cpp`
  array allocation).
- Measure: with N publishers + M players, is the contention real? Prototype a benchmark or
  reason from the per-packet lock acquisitions.
- Evaluate the audit's two-layer proposal: (1) cheap wins (`is_exist` read lock — done in
  004; `set_audio_gap_fill` read lock); (2) the real win — cache the `CSLSRecycleArray*` +
  `ts_info*` on the `CSLSRole` at `set_map_data` time so `put`/`get` bypass the map lock
  entirely, needing only the per-entry ring lock. This requires a safe
  reference-count/quiescence step before destroying an entry a worker may still hold
  (RCU-style, or a "draining" flag + delayed delete).

**Deliverable**: `plans/008-mapdata-lock-rework.md` with the chosen approach, the entry-
lifetime safety mechanism, the migration order, and TSan-backed verification. Note interplay
with plan 004 Step 3 (transparent-comparator map) and plan 003 Step 2 (atomic counter).

---

## Spike B: Decompose `CSLSListener::handler()` (653-line accept god function)

**Evidence**: `src/core/SLSListenerHandler.cpp:32-684`; the duplicated SID-parse +
safe-name + IP-ACL logic appears twice (`handler()` and `finish_player_accept()` around
`:808-841`), and the strdup/strtok re-parse (`:309-327`) duplicates the earlier
`libsrt_parse_sid`.

**Investigate**:
- This is the security boundary (SID parse, safe-name, IP ACL, publisher takeover,
  player-key cache, deferred accept). It MUST have characterization tests first — a
  publisher + player + player-key webhook stub exercising the accept paths.
- Identify the pure, side-effect-free helpers to extract first (lowest risk): SID
  parse+validate (once), IP-ACL evaluation (shared by both blocks). Then the larger split:
  `accept_socket` / `negotiate_latency` / `authorize_publisher` / `authorize_player`
  (folding `finish_player_accept`).

**Deliverable**: `plans/009-decompose-listener-handler.md` that (1) lists the
characterization tests to write first (and confirms whether they need a test seam — which
may itself be a precursor plan), (2) extracts the pure helpers as step one, (3) sequences
publisher path then player/deferred path. Mark the whole thing blocked on those tests.

---

## Spike C: Split `common.cpp` and `CSLSManager::start()`

**Evidence**: `common.cpp` (1263 lines) mixes time/hashing/DNS/filesystem/PID/privileges/
string/TS-parsing concerns; `SLSManager::start()` (`:67-346`) mixes log config, four raw
`new[]` data-plane arrays, listener-factory lambdas, and worker spawning.

**Investigate**:
- `common.cpp` is mostly mechanical code-motion into per-concern TUs (`sls_time`,
  `sls_string`, `sls_path`, `sls_pid`, `sls_privileges`, `ts_parser`). Plan 005 already
  removes the `av_*`/`sls_format` dead weight — do C **after** 005 so the split is smaller.
  The TS-parser extraction is the highest-value (it's the ~550-line untestable chunk and
  the home of the SPS/PPS overflow from plan 002).
- `SLSManager::start()` split is riskier (boot path, hard to test). Lowest-blast-radius
  order: vectorise the four `new[]` arrays into `std::vector` (RAII), extract
  `apply_log_config`, then `init_workers`, then `init_listeners` last.
- Also fold in the trim/split duplication (three `trim` impls: `common.cpp:662`,
  `conf.cpp:382`, `conf.cpp:720`) into one `sls_string` module as part of the common split.

**Deliverable**: `plans/010-split-common-and-manager.md` with the file-by-file move map,
include-hygiene checks (`common.hpp` is included almost everywhere), and the trim/split
consolidation. Sequence: TS-parser extraction first (cleanest boundary, enables direct unit
tests of the SPS/PPS parser).

---

## Spike D: De-duplicate `CSLSPullerManager` / `CSLSPusherManager`

**Evidence**: `SLSPullerManager.cpp` and `SLSPusherManager.cpp` share ~80% of their bodies
(connect loop, start, check/set relay param, reconnect, the repeated
`snprintf("%s/%s", m_app_uplive, m_stream_name)`), already drifting in log text and
rate-limit keys. Both inherit `CSLSRelayManager`.

**Investigate**:
- Identify the shared scaffolding to promote into the `CSLSRelayManager` base
  (`make_stream_key`, `format_upstream_url`, `dispatch_by_mode`) vs the genuine policy
  differences (publisher-presence check direction, iteration strategy: puller circular vs
  pusher all).
- This path drives production push targets; needs characterization tests for the relay
  reconnect/connect behavior before motion.

**Deliverable**: `plans/011-relay-manager-dedup.md` with the base-class extraction design,
the policy hooks the subclasses keep, and the relay tests to write first.

---

## Spike E: Cross-worker fan-out latency (designed-in 10ms)

**Evidence**: `src/core/SLSGroup.cpp` `POLLING_TIME 10` is documented as the worst-case
cross-worker forwarding latency; a player whose publisher lives in a different worker waits
up to 10ms per packet train. `SLSManager.cpp` spins `m_worker_threads` independent epolls;
`SLSListenerHandler.cpp:941` pushes players to a shared list with no publisher affinity.

**Investigate**:
- Two candidate approaches (from the audit): (a) **worker affinity** — dispatch a new
  player into the worker that owns its publisher (also reduces lock contention and keeps a
  stream's data on one core); (b) **wake-on-put** — `CSLSMapData::put` wakes exactly the
  subscriber workers via their eventfd (must be idempotent/coalesced or it becomes its own
  contention point).
- (a) is cleaner and composes with Spike A. Prototype the publisher→worker lookup and
  measure the latency improvement on a cross-worker viewer.

**Deliverable**: `plans/012-worker-affinity.md` with the chosen approach, the dispatch
change, interaction with the role-list/handoff path, and a latency measurement method.

---

## Test plan

Each spike's deliverable plan must specify its own characterization tests (written into the
plan-001 harness) as a precondition. This plan produces plans, not code; its "test" is that
each follow-up plan names concrete, runnable verification.

## Done criteria

ALL must hold:

- [ ] Plan 001 confirmed DONE before any production-code prototyping
- [ ] Five follow-up plans authored: `plans/008-mapdata-lock-rework.md`,
      `plans/009-decompose-listener-handler.md`, `plans/010-split-common-and-manager.md`,
      `plans/011-relay-manager-dedup.md`, `plans/012-worker-affinity.md`
- [ ] Each follow-up plan names its prerequisite characterization tests and verification
- [ ] `plans/README.md` updated with the new plan rows and this plan's status

## STOP conditions

- Plan 001 is not done — do not prototype against production code; spikes can still be
  written from reading, but mark each follow-up plan blocked on 001.
- A spike reveals the change is not worth the risk (e.g. measured contention is negligible)
  — record "not worth doing" with the measurement in the deliverable, rather than forcing a plan.

## Maintenance notes

- Order matters: A and E compose (worker affinity reduces the data-path contention A
  targets); C's TS-parser extraction unblocks direct unit testing of the SPS/PPS code that
  plan 002 only clamped. Sequence the follow-up plans accordingly.
- These are the plans most likely to drift; re-run the drift check in each follow-up plan
  against its own in-scope files.
