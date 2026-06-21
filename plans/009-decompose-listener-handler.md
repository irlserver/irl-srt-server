# Plan 009: Decompose `CSLSListener::handler()`

> **Executor instructions**: This is the follow-up execution plan produced by Spike B of
> plan 007. It MUST start with characterization tests; the function it decomposes is the
> security boundary (SID parse, IP ACL, publisher takeover, player-key cache, deferred
> accept), and any refactor that lands without a regression net is reckless. Run every
> verification command before moving on. STOP per the STOP conditions. When done,
> update the row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat a7c358e..HEAD -- src/core/SLSListenerHandler.cpp src/core/SLSListener.hpp src/core/SLSListener.cpp src/core/sls_sid.* src/core/common.cpp`
> For any in-scope file that changed, re-read the live excerpts in "Current state"
> before editing; structural mismatch is a STOP condition.

## Status

- **Priority**: P3
- **Effort**: L (characterization harness M, refactor itself M)
- **Risk**: HIGH (security boundary; one mistake silently re-introduces an ACL bypass,
  a SID-parse error, or a publisher-takeover race)
- **Depends on**: 001 (hard); 003 Step 5 (request_kick) already landed and is relied on
  by the takeover path here; the IPv4-only ACL helper from 003 Step 6 is the seed of the
  first extracted helper.
- **Category**: tech-debt / safety
- **Planned at**: commit `a7c358e`, 2026-06-21

## Why this matters

`CSLSListener::handler()` is the 650-line god function that runs on every new accepted
SRT socket: it parses the streamid (twice — once with `libsrt_parse_sid`, then re-tokenises
via `strdup`/`strtok` for the player-key path), validates IP ACLs (twice — once for
publishers, once for players in `finish_player_accept`), handles publisher takeover,
talks to the player-key webhook cache, manages deferred accept for async webhook
validation, sizes the ring buffer, and finally hands the role to a worker. Reading it
end-to-end requires holding every one of those concerns in your head at once; changing
any one of them risks breaking another. Worse, the duplication between the publisher
ACL block and the player ACL block has already produced one drift (the IPv6 fallback
behavior was different until plan 003 Step 6 extracted `sls_check_ip_acl`).

The fix is **not** "split it because it's long". The fix is to lift the *pure* helpers
out first (where a test can pin their behavior independent of a live SRT socket), then
move the side-effecting steps into named functions with explicit dependencies, in a
sequence small enough that each commit is reviewable. Without characterization tests we
have no way to verify any of this is behavior-preserving, so step zero is the test
harness.

## Current state

`src/core/SLSListenerHandler.cpp:95-744` — the publisher accept path (`handler()`),
including:

- Lines 18-92: extracted IPv4 ACL helper `sls_check_ip_acl` (already factored out; the
  only existing helper).
- Lines 95-145: accept + create `CSLSSrt` + log new connection + bail on `getpeeraddr`
  failure.
- Lines 146-163: handoff-backlog ceiling check (`MAX_HANDOFF_BACKLOG`).
- Lines 165-224: latency negotiation (read `SRTO_RCVLATENCY` or `SRTO_PEERLATENCY`
  depending on role; reject if above `latency_max`; warn if below `latency_min`).
- Lines 226-284: SID read + parse + safe-name check + DEBUG logging.
- Lines 286-362: app/uplive lookup + publisher-listener-vs-player-listener gate +
  rate-limited connection-accepted logs.
- Lines 364-585: player-key handling — `strdup`+`strtok` re-parse of the SID, cache
  lookup, validation dispatch (synchronous OK / async PENDING / DENY), updated SID
  reparse + safe-name recheck.
- Lines 587-591: branch to `finish_player_accept` when the accept is a player.
- Lines 593-744: publisher accept tail — config lookup, ACL, publisher takeover
  (`request_kick`), `CSLSPublisher` construction, ring-buffer sizing, role wiring,
  `m_list_role->push(pub)`, then pusher-manager bootstrap.

`src/core/SLSListenerHandler.cpp:759-992` — `finish_player_accept` (the second 230-line
function). Duplicates the IP-ACL block (lines 868-889), runs the per-stream player cap,
constructs the `CSLSPlayer`, wires it up, pushes to the role list.

`src/core/SLSListenerHandler.cpp:994-1061` — `on_worker_tick`, `cleanupExpiredStreamOverrides`,
`drive_pending_player_connections` (deferred accept completion). Already cleanly split.

The duplication map (sites that must stay in sync today):

| Concern | Publisher block | Player block |
|---|---|---|
| `libsrt_getpeeraddr_raw` + `sls_check_ip_acl` | `:604-627` | `:868-889` |
| Publisher lookup | `:629` (`get_publisher` for takeover) | `:799,839,891` (multiple times) |
| `stat_info_t` build | `:668-678` | `:974-984` |
| `m_list_role->push` | `:721` | `:988` |

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure` | exit 0 |
| ASan | `cmake -S . -B build-asan -DSLS_SANITIZE=ON -DSLS_BUILD_TESTS=ON && cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure` | exit 0 |
| Integration smoke (manual) | bring up `srt-live-server` + ffmpeg publisher + ffmpeg player + curl `/disconnect` | all three exit cleanly |

## Scope

**In scope**: `src/core/SLSListenerHandler.cpp`, `src/core/SLSListener.hpp`,
`src/core/SLSListener.cpp` (only if a helper needs a member-data move), `src/core/sls_sid.*`
(extension only — already exists, see plan 001), and `tests/test_listener_*.cpp`
(new files).

**Out of scope**: anything in the data path (`SLSMapData`, `CSLSRecycleArray`,
`CSLSPublisher::handler`); the player-key webhook code (extracted helpers may CALL it but
not move it); the cross-worker fan-out (plan 012). Do not touch `finish_player_accept`'s
position relative to `handler()`'s decision to dispatch to it — just refactor what's
inside both.

## Git workflow

- Branch: `advisor/009-decompose-listener-handler`
- One commit per step; the test commits land first (they have to compile and pass
  against the un-refactored code).
- Conventional commits, lowercase, scoped: `test(listener): ...`,
  `refactor(listener): ...`. Do NOT push or open a PR unless instructed.

---

## Step 1: Test seam — make the accept path testable without a live SRT socket

**Risk: MED (touches the listener header; tests added).** **Confidence: MED.**

`handler()` calls into `CSLSSrt::libsrt_accept`, `libsrt_getpeeraddr_raw`,
`libsrt_getsockopt(SRTO_STREAMID/SRTO_RCVLATENCY/SRTO_PEERLATENCY)`, and
`libsrt_socket_nonblock`. None of these can run from a unit test today: they require an
actual SRT handshake.

The cheapest test seam is **an interface abstraction over the SRT calls the handler
needs**, with a real `CSLSSrt`-backed implementation in production and a fake one in
tests:

```cpp
// src/core/sls_accept_io.hpp
class IAcceptIO {
public:
    virtual ~IAcceptIO() = default;
    virtual int  get_streamid(char *buf, int buflen) = 0;
    virtual int  get_latency(int opt, int &out_ms) = 0;
    virtual int  get_peer(char *name, int &port,
                          unsigned long &ipv4, struct in6_addr &ipv6,
                          bool &is_ipv6) = 0;
    virtual int  get_peer_version(int &v) = 0;
    virtual void close() = 0;
    virtual int  set_nonblock(int v) = 0;
};
```

Pass an `IAcceptIO*` (or wrap the existing `CSLSSrt*` inline) into the extracted helpers.
This adds **one virtual call per accept** — once per connection, not per packet — which is
free.

Add `tests/test_listener_helpers.cpp` with a `FakeAcceptIO` that lets a doctest case
drive the handler helpers with canned streamids, peer addrs, latencies. The tests in
this step do NOT exercise the full `handler()` yet — only the helpers extracted in
Steps 2 and 3. They are written first so the helpers land with a test signature already.

**Acceptance test list (each becomes a doctest CASE)**:

Pure helpers (Step 2 unblocks these):
- SID parse: well-formed `h/sls_app/r` extracts host/app/stream; missing `h` returns
  invalid; whitespace-padded fields are trimmed; `;` and `:` are rejected by
  `sls_is_safe_name`.
- IP ACL (already extracted): IPv4 specific deny + IPv4 wildcard accept + IPv4 no-match
  default + IPv6 peer with wildcard accepts + IPv6 peer with only specific entries
  triggers the warning + returns NO_MATCH (regression net for plan 003 Step 6).
- Stream-key formation: `host/app/stream` round-trips through `snprintf("%s/%s", ...)`
  with bound checks.
- Listener-role-mismatch gate: publisher app on a player listener returns "refuse";
  player app on a publisher listener returns "refuse"; legacy listener accepts both.

Side-effecting helpers (Steps 3-4 unblock these):
- Publisher takeover: `request_kick` is called on the incumbent; the new accept is
  refused (client_count == 1 but no role pushed). Verified by mocking the
  `MapPublisher::get_publisher` to return a fake role whose `request_kick` ticks a
  counter.
- Player-key cached + stream-offline path: returns "refused, offline" without invoking
  the webhook (regression net for the rate-limited offline branch).
- Deferred accept enqueue: an uncached key with `validate_player_key == SLS_PENDING`
  pushes onto `m_pending_player_connections` instead of accepting.

**Verify**:
- `cmake --build build -j` → exit 0; the new `IAcceptIO` interface compiles without
  changes to `handler()`.
- `ctest --test-dir build --output-on-failure` → tests added by this step pass
  (compiled against the un-refactored handler — they only test helpers that exist
  *post-extraction*, so this step's tests are scaffolding that will compile but be
  disabled with `DOCTEST_CASE_DISABLED` until Step 2 lands the helpers).
- No production code path uses the fake.

**STOP**: extracting `IAcceptIO` requires moving member functions of `CSLSSrt` around in
ways that break the libsrt error-code semantics → STOP and use a header-only thin
wrapper around the free `srt_*` calls instead. Do not weaken `CSLSSrt`'s contract.

---

## Step 2: Extract the pure helpers

**Risk: LOW.** **Confidence: HIGH.**

These are side-effect-free, take inputs by reference / const-ref, and produce a value
(or fill an out-param). They can be moved with zero behavior change and are the testing
sweet spot:

1. `sls_parse_and_validate_sid(const char *sid, ParsedSid &out, std::string &err)` —
   wraps `libsrt_parse_sid` + `sls_is_safe_name` + the `h`/`sls_app`/`r` extraction.
   Replace BOTH SID-parse sites in `handler()` (the initial parse at `:248-271` and the
   post-player-key reparse at `:544-577`) with one call.
2. Replace the `strdup`/`strtok` re-parse at `:372-404` with a call to the same
   helper plus `sls_trim` (already a `common.cpp` function). Eliminates the duplicate
   parse and the `strdup` leak risk on the error path.
3. `sls_negotiate_latency(IAcceptIO &io, const sls_conf_server_t *conf, bool is_publisher,
   int &final_latency, std::string &err)` — wraps the latency read + min/max checks at
   `:165-224`. Pure aside from the IO call.
4. Keep the existing `sls_check_ip_acl` as-is (already extracted by plan 003 Step 6).

Enable the disabled tests from Step 1 that target these helpers.

**Verify**:
- `git diff src/core/SLSListenerHandler.cpp` shows the two SID parse blocks and the
  `strdup`/`strtok` block collapsed into single calls.
- `cmake --build build -j && ctest --test-dir build --output-on-failure` → all green.
- Behavior diff: zero (the helpers do the same work as the inline code; this is the
  promise to verify).

**STOP**: extracted helper changes a single observable behavior of the handler under
the new tests → STOP and audit; the most likely culprit is a code-path drift between
the original two SID parses that the helper accidentally smoothed over. The original
asymmetry might be a bug *or* a deliberate trim — either way, surface it.

---

## Step 3: Extract the side-effecting accept phases

**Risk: MED.** **Confidence: MED.** This is the structural move.

Replace the body of `handler()` with a phased sequence of named functions on
`CSLSListener`. Keep the original method as a thin orchestrator that returns
`client_count`. The seams (where to cut) mirror the existing implicit phases:

```cpp
int CSLSListener::handler() {
    AcceptCtx ctx;
    if (accept_socket(ctx) != SLS_OK) return ctx.client_count;
    if (admit_or_refuse(ctx) != SLS_OK) return ctx.client_count;  // backlog ceiling
    if (negotiate_latency_phase(ctx) != SLS_OK) return ctx.client_count;
    if (parse_and_validate_streamid(ctx) != SLS_OK) return ctx.client_count;
    if (gate_role_on_listener(ctx) != SLS_OK) return ctx.client_count;
    if (resolve_player_key_if_needed(ctx) != SLS_OK) return ctx.client_count;
    if (ctx.is_player_uplive)
        return finish_player_accept_v2(ctx);
    return finish_publisher_accept(ctx);
}
```

Where `AcceptCtx` is a small POD-ish bag containing the locals that survive across
phases: `CSLSSrt *srt`, the parsed SID fields, peer addresses, `session_id`, `cur_time`,
`final_latency`, `app_uplive`, `key_app`, `player_key`, `player_key_validation_required`,
`client_count`. The bag is **stack-allocated** in `handler()` and passed by reference;
no allocation/dispose churn.

`finish_publisher_accept` absorbs lines `:593-744`; `finish_player_accept_v2` absorbs
the existing `finish_player_accept` (now also using the helpers from Step 2 — the
duplicate ACL check at `:868-889` becomes one call to `sls_check_ip_acl`).

Order the commits so each function lands independently:

1. Introduce `AcceptCtx` (header only — no code moves yet).
2. Extract `accept_socket` (the `libsrt_accept` + `getpeeraddr` block).
3. Extract `admit_or_refuse` (backlog ceiling).
4. Extract `negotiate_latency_phase`.
5. Extract `parse_and_validate_streamid`.
6. Extract `gate_role_on_listener`.
7. Extract `resolve_player_key_if_needed` (this is the biggest one — keep it tight to
   the player-key path, do NOT pull deferred-accept enqueue logic into a sibling
   helper, that lives inside this phase).
8. Extract `finish_publisher_accept` (replaces the tail of `handler()`).
9. Rename `finish_player_accept` -> `finish_player_accept_v2` only if the signature
   changed; otherwise leave the name and remove the parameter list duplication.

**Verify after each commit**:
- `cmake --build build -j` → exit 0
- `ctest --test-dir build --output-on-failure` → all green
- A manual integration smoke: bring up one server, publish from ffmpeg, play from
  ffmpeg, hit `/disconnect`. No new warnings/errors in logs.

**Do not** refactor across commits; each step must compile and pass tests on its own.

**STOP**: any of the above commits regresses a doctest or the integration smoke → STOP
and revert that commit; the regression is the signal that a phase boundary is wrong.

---

## Step 4: Drop the duplicates and tighten the contracts

**Risk: LOW.** **Confidence: HIGH.**

With phases extracted, the remaining duplication is mechanical:

- The two `stat_info_t` builds (`:668-678` and `:974-984`) collapse into one
  `build_stat_info(CSLSRole *role, const AcceptCtx &ctx)` free function.
- `finish_player_accept_v2` reads the player-key cache twice (once at `:780-797` for the
  per-stream override seed, once at `:917-932` for the effective max-players). Both reads
  hit the same cache under the same mutex — consolidate into one read that fills both
  uses.
- `m_pending_player_connections` size check at `:502-508`: confirm post-refactor it is
  still inside `resolve_player_key_if_needed` and not moved into the worker tick.
- Make every function that the tests need `static` (file-local) where it doesn't need
  member access; this is a "make the seam tight" pass.

**Verify**:
- `grep -c "stat_info_t stat_info_obj" src/core/SLSListenerHandler.cpp` → 1 (or 0 if it
  is replaced by a constructor on `stat_info_t`).
- All Step 1 acceptance tests still pass.

---

## Step 5: Long tail — code-shape cleanups

**Risk: LOW.** **Confidence: HIGH.** Defer if time-boxed.

- `strdup` + `strtok` re-parse is already gone (Step 2). Confirm there is no
  `free(sid_copy)` left dangling.
- `URL_MAX_LEN` char buffers everywhere — replace with `std::string` on the
  helper signatures. Stack buffers are fine inside leaf functions.
- The `host_name`/`app_name`/`stream_name` char arrays inside `handler()` shrink to
  fields on `AcceptCtx`.
- Comments inside the original god function were the only documentation of intent;
  preserve every comment at the boundary it documents (e.g. the publisher takeover
  block's comment stays with `finish_publisher_accept`).

**Verify**: code review of `git diff origin/main..HEAD -- src/core/SLSListenerHandler.cpp`
shows no comment block was lost; all helper docstrings exist on the declaration.

---

## Test plan

- `tests/test_listener_helpers.cpp` (Step 1) — covers SID parse, IP ACL, latency
  negotiation, role gate, player-key cache decision tree, deferred-accept enqueue.
- TSan + ASan builds clean (the takeover path under TSan is the long pole — verify
  manually with two publishers fighting for the same stream key + a `/disconnect`).
- Integration smoke after each Step 3 commit (ffmpeg publish + play + `/disconnect`).
- `ctest --test-dir build --output-on-failure` and TSan/ASan variants all green.

## Done criteria

ALL must hold:

- [ ] `tests/test_listener_helpers.cpp` lands BEFORE Step 2 (commit order enforced)
- [ ] `CSLSListener::handler()` body is < 60 lines and each call site is a single function
- [ ] `finish_player_accept` uses the same `sls_check_ip_acl`/`sls_parse_and_validate_sid`
      helpers as the publisher path — no duplicated security logic
- [ ] No regression of the existing characterization tests (plan 001) or the ones added
      by this plan
- [ ] TSan and ASan builds clean on a smoke run including publisher takeover + `/disconnect`
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` row for 009 updated

## STOP conditions

- Plan 001 is not green on `main` — STOP; this plan refactors a security boundary and
  needs the verification baseline.
- A Step 3 commit regresses a doctest case from Step 1 — STOP, revert, and re-scope the
  phase boundary (the test is the contract, not the refactor).
- The `IAcceptIO` seam from Step 1 forces a change to `CSLSSrt`'s public API that other
  callers do not expect — STOP and use a thin free-function wrapper instead.
- A drift-check mismatch on `SLSListenerHandler.cpp` — STOP and re-read the file
  before continuing.

## Maintenance notes

- The extracted helpers (`sls_parse_and_validate_sid`, `sls_check_ip_acl`,
  `sls_negotiate_latency`) are the new pieces to keep unit-tested. Whenever a new SID
  field, ACL rule, or latency knob lands, the test cases for these helpers are the
  first thing to update.
- Plan 012 (worker affinity) changes how a role is dispatched after
  `m_list_role->push(role)`; that lives outside `CSLSListener::handler()` and should not
  collide with this plan's seams.
- Plan 008's lifetime change touches `set_map_data`/`m_map_data` on roles — verify the
  refactor here does not break the publisher's `set_map_data(key_stream_name, m_map_data)`
  call ordering at `:717` and the player's at `:967`.
- Reviewer: scrutinize the order of the Step 3 commits and confirm each one passes the
  doctest + integration smoke independently.

## Open questions

1. Should `AcceptCtx` carry the `srt` pointer or should each phase function take it
   explicitly? The bag is simpler to thread; the explicit signature is more honest about
   ownership. Lean toward bag-with-explicit-comment on ownership transfer.
2. The deferred-accept timeout (`m_player_key_auth_timeout + 2000`) is hard-coded inside
   `resolve_player_key_if_needed`. Surface it as a `sls_conf_server_t` field, or leave it
   as a follow-up?
3. Does `gate_role_on_listener` belong before or after `parse_and_validate_streamid`?
   Today the order is: parse SID -> look up uplive -> gate. The semantic dependency is
   "you need the parsed app_name to know if it is a player app". Keep the current order;
   document the dependency on the helper.
