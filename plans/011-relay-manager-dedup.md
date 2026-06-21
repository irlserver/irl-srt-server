# Plan 011: Dedup `CSLSPullerManager` / `CSLSPusherManager`

> **Executor instructions**: Follow this plan step by step. This is the follow-up
> execution plan produced by Spike D of plan 007. It MUST start with relay
> characterization tests; the puller and pusher paths drive production push targets and
> have no automated coverage today. Run every verification command before moving on.
> STOP per the STOP conditions. When done, update the row for this plan in
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat a7c358e..HEAD -- src/core/SLSRelayManager.cpp src/core/SLSRelayManager.hpp src/core/SLSPullerManager.cpp src/core/SLSPullerManager.hpp src/core/SLSPusherManager.cpp src/core/SLSPusherManager.hpp src/core/SLSMapRelay.cpp src/core/SLSPuller.cpp src/core/SLSPusher.cpp`
> For any in-scope file that changed, re-read the live "Current state" excerpts below
> before editing; structural mismatch is a STOP condition.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: MED (no automated tests today; relays drive production push targets;
  reconnect interval semantics MUST be byte-for-byte preserved)
- **Depends on**: 001 (hard — the test harness; relay tests do not exist yet); 010 is
  not a hard dependency but `sls_hash_key` lives in `sls_string` after 010, so prefer
  landing 010 first.
- **Category**: tech-debt
- **Planned at**: commit `a7c358e`, 2026-06-21

## Why this matters

`SLSPullerManager.cpp` (284 lines) and `SLSPusherManager.cpp` (362 lines) share ~80%
of their bodies. Both:

- Format `key_stream_name` with `snprintf("%s/%s", m_app_uplive, m_stream_name)` —
  6 separate call sites across the two files, each with its own length check.
- Build the upstream URL with `snprintf("srt://%s/%s", ...)` — pusher additionally
  handles the `srt://` prefix and the `{stream_name}` template substitution.
- Open a relay via the inherited `CSLSRelayManager::connect(url)`, which builds a
  `stat_info_t` with `new`, calls `set_relay_param`, and bails on failure.
- Dispatch by `m_sri->m_mode` (`SLS_PM_LOOP`/`SLS_PM_ALL`/`SLS_PM_HASH`) — pusher
  iterates all upstreams, puller round-robins.
- Implement `reconnect()` that compares `cur_tm_ms - m_reconnect_begin_tm` against
  `m_sri->m_reconnect_interval * 1000` and checks `check_relay_param`.

The drift is already starting: log text differs (`"Puller ..."` vs `"Pusher ..."`),
rate-limit keys are spelled different ways (`"puller_reconnect_"` vs
`"pusher_reconnect"`), and pusher's `add_reconnect_stream` writes a per-URL deadline
map while puller's just records one timestamp. Without consolidation, the next
drift is "puller silently honours a reconnect_interval that the pusher does not"
or vice versa — and there are no tests to catch it.

The base class `CSLSRelayManager` already exists (`src/core/SLSRelayManager.hpp:47`):
it owns `m_map_publisher`, `m_map_data`, `m_role_list`, `m_sri`, `m_app_uplive`,
`m_stream_name`, `m_listen_port`, `m_reconnect_begin_tm`, plus the shared `connect`,
`connect_hash`, `get_hash_url`. The split happens at `start()`, `reconnect()`,
`check_relay_param()`, `set_relay_param()`, and `create_relay()`. Most of `start()` and
`reconnect()` is policy-free scaffolding that belongs in the base; the differences
(puller: round-robin vs hash; pusher: connect-all + per-URL reconnect map) are the real
policy.

## Current state

`src/core/SLSRelayManager.hpp:47-84` — base class (already in place):

```cpp
class CSLSRelayManager {
public:
    virtual int start() = 0;
    virtual int reconnect(int64_t cur_tm_ms) = 0;
    virtual int add_reconnect_stream(char *relay_url) = 0;
    ...
protected:
    CSLSMapPublisher *m_map_publisher;
    CSLSMapData *m_map_data;
    CSLSRoleList *m_role_list;
    SLS_RELAY_INFO *m_sri;
    int64_t m_reconnect_begin_tm;
    int m_listen_port;
    char m_app_uplive[1024];
    char m_stream_name[1024];
    int connect(const char *url);
    int connect_hash();
    virtual CSLSRelay *create_relay() = 0;
    std::string get_hash_url();
    virtual int set_relay_param(CSLSRelay *relay) = 0;
};
```

The shared `connect(url)` at `src/core/SLSRelayManager.cpp:85-140` is the only piece of
behavior the base provides today; everything else is `=0`.

`src/core/SLSPullerManager.cpp:51-104` (`connect_loop`) — circular round-robin across
`m_sri->m_upstreams`, advances `m_cur_loop_index`.

`src/core/SLSPullerManager.cpp:106-153` (`start`) — checks publisher does NOT exist;
dispatches to `connect_loop` (LOOP mode) or `connect_hash` (HASH mode).

`src/core/SLSPullerManager.cpp:236-240` (`add_reconnect_stream`) — only records a single
timestamp; ignores its `relay_url` argument.

`src/core/SLSPullerManager.cpp:242-284` (`reconnect`) — guard on
`cur_tm_ms - m_reconnect_begin_tm < interval`, then calls `start()` again.

`src/core/SLSPusherManager.cpp:50-101` (`connect_all`) — iterates all upstreams; on
failure, inserts the URL into `m_map_reconnect_relay` under a lock.

`src/core/SLSPusherManager.cpp:103-151` (`start`) — checks publisher DOES exist;
dispatches to `connect_all` (ALL mode) or `connect_hash` (HASH mode).

`src/core/SLSPusherManager.cpp:178-209` (`add_reconnect_stream`) — for ALL mode, writes
per-URL timestamp; for HASH mode, writes a single timestamp.

`src/core/SLSPusherManager.cpp:302-362` (`reconnect_all`) — iterates the per-URL map,
respects the per-URL interval, calls `connect(url)` per due entry, removes successful
entries.

The asymmetries to preserve (not eliminate — these are real policy differences):

| Concern | Puller | Pusher |
|---|---|---|
| Publisher presence | must NOT exist (would conflict) | must exist (we push it out) |
| Iteration | round-robin one upstream at a time | all upstreams in parallel |
| URL template substitution | none | `fmt::format(... fmt::arg("stream_name", ...))` |
| Reconnect bookkeeping | one timestamp | per-URL map under `m_rwclock` |
| `set_relay_param` | calls `set_push_2_publisher` (puller becomes the publisher) | does NOT |

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure` | exit 0 |
| Local relay smoke | run two sls instances; one as publisher target, one as puller | second receives stream |

## Scope

**In scope**:
- `src/core/SLSRelayManager.{hpp,cpp}` (extended base).
- `src/core/SLSPullerManager.{hpp,cpp}` (subclass narrowed to policy).
- `src/core/SLSPusherManager.{hpp,cpp}` (subclass narrowed to policy).
- `tests/test_relay_manager.cpp` (new — see Step 1).

**Out of scope**: `SLSPuller.cpp` / `SLSPusher.cpp` (the role implementations); the
relay map (`SLSMapRelay`); the webhook-driven dynamic pusher creation in the listener
handler (plan 009's domain). The relay-info config parsing in `SLSPublisher` stays the
same.

## Git workflow

- Branch: `advisor/011-relay-manager-dedup`
- One commit per extraction; the tests land first.
- Conventional commits, lowercase, scoped: `test(relay): ...`,
  `refactor(relay): ...`. Do NOT push or open a PR unless instructed.

---

## Step 1: Relay characterization tests (precondition)

**Risk: LOW.** **Confidence: MED.** The fixturing is non-trivial (relays open sockets).

Decide first: do the tests drive a real loopback SRT socket or a mock? Real-socket
tests would catch the most behavior but require an SRT server in the test fixture; mock
tests are faster but only verify the orchestration. Recommendation: **mock-based**.
The behavior we want to pin is the dispatch + reconnect bookkeeping logic, not the
network I/O — that is covered by manual integration smoke.

Introduce a test seam at the `connect(const char *url)` boundary in `CSLSRelayManager`:

```cpp
// SLSRelayManager.hpp (protected) — new in this plan
virtual int do_connect(const char *url) { return connect(url); }  // default = real path
```

The existing `connect` keeps its behavior; the virtual wrapper lets tests subclass
`CSLSRelayManager` (or its derivatives) and replace `do_connect` with a function that
records the URL and returns a canned result. `connect_loop` and `connect_all` call
`do_connect(url)` instead of `connect(url)` so the test fixture observes the dispatch
order.

`tests/test_relay_manager.cpp` adds doctest CASEs:

Puller policy:
- `LOOP` mode, 3 upstreams: `connect_loop` calls `do_connect` on each upstream in
  order; `m_cur_loop_index` advances correctly; after a full sweep without success,
  returns SLS_ERROR.
- `HASH` mode: `connect_hash` hits a deterministic upstream for a given stream name.
- `start()` returns SLS_ERROR when a publisher already exists.
- `add_reconnect_stream` updates `m_reconnect_begin_tm`; a subsequent `reconnect()`
  before the interval elapses returns SLS_ERROR without calling `do_connect`.
- `reconnect()` after the interval calls `start()`.

Pusher policy:
- `ALL` mode, 3 upstreams: `connect_all` calls `do_connect` for each; failing URLs are
  recorded in `m_map_reconnect_relay`.
- `start()` returns SLS_ERROR when a publisher does NOT exist.
- `add_reconnect_stream(url)` in ALL mode adds to `m_map_reconnect_relay`.
- `reconnect_all` respects per-URL intervals and removes URLs whose `do_connect`
  succeeds.
- URL template substitution: `srt://host/{stream_name}` is rendered to
  `srt://host/<actual_stream_name>`; an upstream entry whose template key is missing
  is logged and dropped without crashing.

Each test uses `CSLSPullerManager`/`CSLSPusherManager` with a test-only seam: either
mock the parent via `do_connect`, or instantiate a `CSLSMapPublisher` fixture that
stores a stub `CSLSRole`.

**Verify**:
- `cmake --build build -j` → exit 0.
- `ctest --test-dir build --output-on-failure` → new relay tests pass on the
  unrefactored code (the test suite is the contract going into the refactor).

**STOP**: a test reveals a behavior delta from what we *thought* the code does → STOP
and record it; the delta is the bug, the refactor would only hide it. Surface it as a
follow-up bug fix before continuing.

---

## Step 2: Promote `make_stream_key` and `format_upstream_url` into the base

**Risk: LOW.** **Confidence: HIGH.** Pure code motion.

Add to `CSLSRelayManager` (`SLSRelayManager.hpp`):

```cpp
protected:
    // Build "app_uplive/stream_name" into out (URL_MAX_LEN bytes). Returns
    // SLS_OK or SLS_ERROR on snprintf truncation/error.
    int make_stream_key(char *out, size_t out_len) const;

    // Build "srt://<host_spec>/<stream_name>" into out, honouring the
    // {stream_name} template placeholder if the pusher path uses it. The
    // base impl assumes no templating (puller); the pusher override
    // applies fmt::format. Returns SLS_OK or SLS_ERROR.
    virtual int format_upstream_url(const char *host_spec, char *out, size_t out_len) const;
```

Replace the six inline `snprintf("%s/%s", m_app_uplive, m_stream_name, ...)` sites in
puller + pusher with `make_stream_key(buf, sizeof(buf))`. The error log strings are
preserved verbatim (this is intentional — operators grep for them).

Override `format_upstream_url` in `CSLSPusherManager` to do the `fmt::format` template
handling (`{stream_name}` substitution + `srt://` prefix detection).

**Verify**:
- `grep -n 'snprintf.*%s/%s.*m_app_uplive' src/core/SLSPullerManager.cpp src/core/SLSPusherManager.cpp`
  → 0
- Tests from Step 1 still pass; behavior unchanged.

---

## Step 3: Promote `check_relay_param` into the base

**Risk: LOW.** **Confidence: HIGH.**

Both subclasses implement `check_relay_param()` identically (modulo log text). Move the
canonical impl into `CSLSRelayManager`:

```cpp
int CSLSRelayManager::check_relay_param() const {
    if (m_role_list == nullptr) return SLS_ERROR;
    if (m_map_data == nullptr) return SLS_ERROR;
    return SLS_OK;
}
```

Puller additionally requires `m_map_publisher != nullptr`; pusher does NOT — pusher's
`check_relay_param` does not check publisher. **Preserve the difference**: pusher's
publisher-presence check is its own (in `start()` and `reconnect()`), not a
`check_relay_param` concern.

For the publisher-presence check we add an overridable hook with explicit semantics:

```cpp
// True iff this manager type *requires* the publisher to already exist for
// start()/reconnect() to proceed. Puller: false (would conflict).
// Pusher:  true  (we have nothing to push otherwise).
virtual bool requires_publisher_present() const = 0;
```

Move the publisher-presence dispatch into a shared base helper that uses this hook,
then both subclasses lose ~30 lines.

**Verify**:
- `grep -n 'check_relay_param' src/core/SLSPullerManager.cpp src/core/SLSPusherManager.cpp`
  → only definitions of the override (or zero matches if eliminated).
- Tests still pass.

**STOP**: removing the duplicate `check_relay_param` changes any log message operators
rely on → STOP, restore the message (with an `if (sls_should_log_category(...))` guard
if needed) and proceed.

---

## Step 4: Promote `start()`/`reconnect()` scaffolding

**Risk: MED.** **Confidence: MED.** This is the largest move.

Shape the base class to own the *scaffolding* of `start()` and `reconnect()`, leaving
each subclass to provide only the *policy*:

```cpp
// Base
int CSLSRelayManager::start() {
    if (m_sri == nullptr) return SLS_ERROR;
    char key_stream[URL_MAX_LEN]{};
    if (make_stream_key(key_stream, sizeof(key_stream)) != SLS_OK) return SLS_ERROR;
    if (requires_publisher_present()) {
        if (m_map_publisher == nullptr ||
            m_map_publisher->get_publisher(key_stream) == nullptr) return SLS_ERROR;
    } else {
        if (m_map_publisher != nullptr &&
            m_map_publisher->get_publisher(key_stream) != nullptr) return SLS_ERROR;
    }
    return dispatch_by_mode();   // <-- policy hook
}

// Subclass policy
int CSLSPullerManager::dispatch_by_mode() {
    if (m_sri->m_mode == SLS_PM_LOOP) return connect_loop();
    if (m_sri->m_mode == SLS_PM_HASH) return connect_hash();
    return SLS_ERROR;
}
int CSLSPusherManager::dispatch_by_mode() {
    if (m_sri->m_mode == SLS_PM_ALL)  return connect_all();
    if (m_sri->m_mode == SLS_PM_HASH) return connect_hash();
    return SLS_ERROR;
}
```

Similarly for `reconnect`:

```cpp
// Base
int CSLSRelayManager::reconnect(int64_t cur_tm_ms) {
    if (check_relay_param() != SLS_OK) return SLS_ERROR;
    if (m_sri == nullptr) return SLS_ERROR;
    return reconnect_by_mode(cur_tm_ms);  // policy hook
}
```

Subclasses implement `reconnect_by_mode` with the actual mode/timer logic. Pusher's
`reconnect_all` (the per-URL map walk) stays in pusher unchanged; puller's interval
guard stays in puller.

**Verify**:
- `wc -l src/core/SLSPullerManager.cpp` drops by ~80-100 lines; same for pusher.
- The asymmetry table from "Current state" is still reflected in the subclasses (each
  asymmetric concern has exactly one home).
- Tests from Step 1 still pass on the refactored code.
- Manual smoke: configure a puller to a known good source, confirm stream flows.

**STOP**: any test from Step 1 regresses → STOP and revert; the policy hook is
mismatched. Most likely cause: `requires_publisher_present` is backwards somewhere.

---

## Step 5: Unify log/rate-limit keys

**Risk: LOW.** **Confidence: HIGH.** Operator-visible — change one batch, document it.

Today puller uses `"puller_reconnect_"`; pusher uses `"pusher_reconnect"` (+ suffixes).
Unify the rate-limit key naming via a helper on the base:

```cpp
std::string CSLSRelayManager::rate_limit_key(const char *suffix) const {
    return std::string(role_short_name()) + "_" + suffix + "_" + m_stream_name;
}
// role_short_name() is overridden by subclass: "puller" or "pusher".
```

Replace the existing rate-limit key construction at all sites. Keep the log message
prefix (`[relay] Puller ...`/`[relay] Pusher ...`) byte-for-byte so operators still grep
the same words; only the rate-limit *key* changes.

**Verify**: `grep -rn 'rate_key.*=.*"' src/core/SLSPullerManager.cpp src/core/SLSPusherManager.cpp`
shows the constructions all go through the helper.

---

## Step 6: Final cleanup

**Risk: LOW.** **Confidence: HIGH.**

- Move `m_rwclock` (used only by pusher's reconnect-map mutation) from a per-subclass
  member into the pusher only — confirm it is unused in the puller. (Today it lives in
  the pusher; verify with `grep`.)
- Drop dead protected helpers, dead `static rate_key_base` strings, etc.
- Update `SLSRelayManager.hpp` doc comments to describe the policy hooks
  (`requires_publisher_present`, `dispatch_by_mode`, `reconnect_by_mode`,
  `format_upstream_url`).

**Verify**: `wc -l src/core/SLSRelayManager.cpp src/core/SLSPullerManager.cpp src/core/SLSPusherManager.cpp`
total is down by 200-300 lines.

---

## Test plan

- `tests/test_relay_manager.cpp` (Step 1) — dispatch by mode, reconnect timing,
  per-URL bookkeeping, URL template substitution, publisher-presence checks.
- Manual integration smoke: configure a puller pointing at another sls instance; play
  through it; tear down and reconnect. Then a pusher pointing at a downstream sls.
- `ctest --test-dir build --output-on-failure` and TSan/ASan variants all green.

## Done criteria

ALL must hold:

- [ ] `tests/test_relay_manager.cpp` lands BEFORE the Step 2-6 refactors
- [ ] `CSLSPullerManager.cpp` < 180 lines; `CSLSPusherManager.cpp` < 220 lines
- [ ] `make_stream_key`, `format_upstream_url`, `check_relay_param`, the start/reconnect
      scaffolding live in the base; `dispatch_by_mode` + `reconnect_by_mode` +
      `requires_publisher_present` are the only policy hooks the subclasses override
- [ ] Operator-visible log strings (`[relay] Puller ...`/`[relay] Pusher ...`) are
      preserved byte-for-byte
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] TSan clean on a smoke run with one puller + one pusher
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` row for 011 updated

## STOP conditions

- A Step 1 characterization test contradicts the documented "expected" behavior of one
  of the subclasses — STOP and surface as a bug. The test is the source of truth before
  the refactor; do not move ahead until the bug is recorded as a follow-up.
- Step 4's scaffolding loses the per-URL reconnect map behavior on the pusher — STOP and
  re-do; that map is the difference that makes pusher idempotent under flaky
  downstreams.
- A drift-check mismatch on any of the four relay files — STOP and re-read.

## Maintenance notes

- The `requires_publisher_present` hook is the contract that lets a future relay type
  (e.g. a sidecar transcoder) compose without forking the start/reconnect scaffolding.
- The rate-limit key unification in Step 5 makes operator dashboards consistent
  between puller and pusher — document the new key shape in `docs/` (plan 006 owns
  docs, log a follow-up if not already covered).
- Plan 008's `EntryHandle` will eventually replace `m_map_data->put(key, ...)` calls in
  the relay role objects (`CSLSPuller`/`CSLSPusher`); coordinate so that change lands
  in 008's scope, not here.
- Reviewer: scrutinize Step 4 (the publisher-presence direction is easy to flip by
  accident) and confirm Step 1's tests are honest about whether they hit the live
  network.

## Open questions

1. Is the pusher's `m_map_reconnect_relay` lock (`m_rwclock`) actually contended?
   Pusher's `connect_all` takes a write lock on every failing upstream; a flapping
   downstream produces lock churn but no real contention because all callers are on
   the listener thread. Verify with TSan; if uncontended, a `std::mutex` is enough.
2. The puller's `connect_loop` skips the rest of the loop on `index == m_cur_loop_index`
   even if that index is the only configured upstream. Today this leaves the puller in
   a state where `start()` returns SLS_ERROR but `m_cur_loop_index` has advanced — does
   `reconnect()` retry the same upstream on the next tick? Verify with a Step 1 test;
   if it never retries, that is a latent bug (record as follow-up; do NOT fix here).
3. Should we add a `disconnect_all()` / `stop()` to the base so listener cleanup can
   tear down all active relays in one call? Today the listener relies on each
   relay-role's own teardown. Out of scope for this plan but worth noting.
