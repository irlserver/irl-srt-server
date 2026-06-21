# Plan 010: Split `common.cpp` and `CSLSManager::start()`

> **Executor instructions**: Follow this plan step by step. The two halves (common.cpp
> split + SLSManager::start refactor) are sequenced inside one plan because they share a
> compile-time dependency (`common.hpp` is in almost every TU). Run every verification
> before moving on. STOP per the STOP conditions. When done, update the row for this
> plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat a7c358e..HEAD -- src/core/common.cpp src/core/common.hpp src/core/conf.cpp src/core/conf.hpp src/core/SLSManager.cpp src/core/SLSManager.hpp src/core/CMakeLists.txt`
> For any in-scope file that changed, re-read the live excerpts before editing;
> structural mismatch is a STOP condition.

## Status

- **Priority**: P3
- **Effort**: L (mechanical but wide — touches every TU that includes `common.hpp`)
- **Risk**: MED (compile fan-out is the danger; runtime behavior should not change)
- **Depends on**: 001 (hard — the new modules each get a doctest file); 005 already
  removed the `av_*`/`sls_format` dead code so the split is smaller; coordinate with
  008 Step 4 so both plans do not refactor `SLSManager::start()` at the same time.
- **Category**: tech-debt
- **Planned at**: commit `a7c358e`, 2026-06-21

## Why this matters

`src/core/common.cpp` is 1167 lines holding nine unrelated concerns: wall-clock + format,
string upper/lower/hash/trim/split, DNS resolution, filesystem (mkdir), PID-file
read/write, signal-based reload, privilege drop, and a 500-line MPEG-TS parser
(`sls_parse_spspps` + `sls_parse_ts_info` + the SPS/PPS clamp from plan 002). The
file is `#include`d transitively into nearly every TU because `common.hpp` is the
project's de-facto utility umbrella. Three consequences:

1. The TS parser — the most security-sensitive code in the file — cannot be unit-tested
   in isolation without dragging in PID files, privilege drops, and DNS. Plan 002's
   SPS/PPS overflow clamp went in with no test for exactly this reason.
2. The three `trim()` implementations (`common.cpp:530`, `conf.cpp:382`, `conf.cpp:720`)
   exist because pulling more from `common.cpp` was scarier than reimplementing the
   helper. They have already drifted (the conf.cpp variants differ in whitespace-set
   handling); the next drift is a config bug.
3. `CSLSManager::start()` (664-line method, the boot path) opens its own can: four raw
   `new[]` arrays (`m_map_data`, `m_map_publisher`, `m_map_puller`, `m_map_pusher`),
   listener-factory lambdas, log-config side effects, and worker spawning all in one
   place. The arrays leak on the error paths inside `start()` because the cleanup
   relies on `CSLSManager`'s destructor seeing them — but `start()` returns
   `SLS_ERROR` from a dozen sites before all four are constructed.

The split is mostly mechanical. The TS-parser extraction is the high-value piece (it
unblocks direct unit tests of the SPS/PPS parser plan 002 had to clamp blind).
`SLSManager::start()` is its own beast and is decomposed in Steps 5-6.

## Current state

`src/core/common.cpp` top-level functions (verified by `grep`):

| Line | Symbol | Concern |
|---|---|---|
| 58 | `sls_gettime_ms` | time |
| 63 | `sls_gettime` | time |
| 80 | `sls_gettime_default_string` | time/format |
| 90 | `sls_gettime_fmt` | time/format |
| 104 | `sls_strupper` | string |
| 112 | `sls_strlower` | string |
| 121 | `sls_hash_key` | string/hash |
| 135 | `sls_gethostbyname` | dns |
| 177 | `sls_mkdir_p` | filesystem (already on `std::filesystem`, plan 005) |
| 204 | `sls_remove_marks` | string |
| 225 | `sls_is_safe_name` | string/security |
| 252 | `sls_read_pid` | pid |
| 282 | `sls_is_pid_location_changed` | pid |
| 295 | `sls_reload_pid` | pid |
| 314 | `sls_load_pid_filename` | pid |
| 336 | `sls_write_pid` | pid |
| 380 | `sls_remove_pid` | pid |
| 413 | `sls_send_cmd` | signal/reload |
| 447 | `sls_drop_privileges` | privileges |
| 530 | `sls_trim` | string |
| 540 | `sls_split_string` | string |
| 560 | `sls_find_string` | string |
| 614 | `sls_parse_spspps` (static) | ts-parser |
| 732 | `sls_pes2es` (static) | ts-parser |
| 879 | `sls_parse_pat` (static) | ts-parser |
| 914 | `sls_parse_pmt_for_audio` | ts-parser |
| 998 | `sls_parse_ts_info` | ts-parser |
| 1104 | `sls_init_audio_track` | ts-parser |
| 1133 | `sls_init_ts_info` | ts-parser |

`src/core/SLSManager.cpp:67-346` — `CSLSManager::start()`:

- `:73-134` — config validation + log config (rate limiting, format, categories).
- `:135-148` — four raw `new[]` arrays sized by `m_server_count` (one per server).
- `:149-152` — `m_list_role = new CSLSRoleList`; one shared `AuthRejectCache`.
- `:160-304` — per-server listener creation (lambdas: `port_taken`, `make_listener`,
  `create_for_spec`), expansion of publisher/srtla/player port specs into listeners,
  legacy listener, fallback listener.
- `:305-343` — worker pool (`m_worker_threads` epoll workers, or a single in-thread
  group when worker_threads==0). Each worker is `init_epoll`'d, then `start()`ed.

`src/core/conf.cpp:382` and `:720` — second and third `trim` implementations.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Build | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON && cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |
| TSan | `cmake -S . -B build-tsan -DSLS_TSAN=ON -DSLS_BUILD_TESTS=ON && cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure` | exit 0 |
| Include hygiene | `grep -rn '#include "common.hpp"' src/` | the set of TUs that need rechecking |
| Header-only smoke | `grep -rn '#include "sls_time.hpp"' src/` after Step 2 | only the TUs that need it |

## Scope

**In scope**:
- New files: `src/core/sls_time.{hpp,cpp}`, `src/core/sls_string.{hpp,cpp}`,
  `src/core/sls_path.{hpp,cpp}`, `src/core/sls_pid.{hpp,cpp}`,
  `src/core/sls_privileges.{hpp,cpp}`, `src/core/ts_parser.{hpp,cpp}`
- Existing: `src/core/common.cpp`, `src/core/common.hpp`, `src/core/conf.cpp`,
  `src/core/conf.hpp`, `src/core/SLSManager.cpp`, `src/core/SLSManager.hpp`,
  `src/core/CMakeLists.txt`.
- `tests/test_ts_parser.cpp`, `tests/test_sls_string.cpp`, `tests/test_sls_path.cpp`.

**Out of scope**: any behavior change. The whole plan is code motion + signature
preservation. The only place a function signature should change is where the original
took a `char*` for what is morally a `std::string_view` and the call sites all pass a
literal/`std::string::c_str()` (e.g. `sls_trim`, `sls_split_string`). Even there, defer
the signature change to a follow-up unless it falls out for free.

## Git workflow

- Branch: `advisor/010-split-common-and-manager`
- One commit per module split, one commit per `SLSManager::start()` extraction.
- Conventional commits, lowercase, scoped: `refactor(common): extract sls_time module`,
  etc. Do NOT push or open a PR unless instructed.

---

## Step 1: TS parser extraction (highest value, do first)

**Risk: MED.** **Confidence: HIGH.** This is the only split where the extracted module
gains a unit test it could not have before.

Move out of `common.cpp` into `src/core/ts_parser.{hpp,cpp}`:
- `sls_parse_spspps` (static today; promote to file-private inside the new TU).
- `sls_pes2es` (same).
- `sls_parse_pat` (same).
- `sls_parse_pmt_for_audio` (public).
- `sls_parse_ts_info` (public).
- `sls_init_audio_track` (public).
- `sls_init_ts_info` (public).

The `ts_info` / `audio_track_info` struct definitions live in `common.hpp` today; move
them with the parser into `ts_parser.hpp` and `#include "ts_parser.hpp"` from
`common.hpp` for one release of source compatibility, then drop the back-include after
all sites switch. Keep that bridging include in for this plan; the cleanup is a final
sweep in Step 7.

Add `tests/test_ts_parser.cpp` with the unit tests plan 002 wished it had:
- Well-formed SPS/PPS payload parses; `sps_len`/`pps_len` set correctly.
- The exact overflow input plan 002 clamped (an SPS pretending to be > `sps_buf_size`)
  returns the clamped length, does not write past the buffer, ASan clean.
- PAT with one program -> PMT lookup returns the expected program PID.
- PMT with one audio track populates `audio_tracks[0]` with the expected PID.
- PMT with > `MAX_AUDIO_TRACKS` audio tracks stops at the cap and does not overrun.

**Verify**:
- `cmake --build build -j && ctest --test-dir build --output-on-failure` → all green
  (including the new `test_ts_parser` cases).
- `grep -n 'sls_parse_ts_info\|sls_parse_pmt_for_audio' src/core/common.cpp` → no
  matches.
- `nm build/libsls_core.a | grep sls_parse_ts_info` shows the symbol comes from
  `ts_parser.cpp.o`.

**STOP**: any caller breaks because a header was missed → STOP, add the missing
include, retry. Do NOT add `common.hpp` back as a kitchen-sink workaround.

---

## Step 2: String module (consolidates the three `trim` impls)

**Risk: LOW.** **Confidence: HIGH.**

Move into `src/core/sls_string.{hpp,cpp}`:
- `sls_strupper`, `sls_strlower`
- `sls_hash_key`
- `sls_remove_marks`
- `sls_is_safe_name` (security helper used by the listener handler — keep its signature
  byte-for-byte identical)
- `sls_trim`, `sls_split_string`, `sls_find_string`

Then:

- In `src/core/conf.cpp:382` and `:720`, delete the local `trim` implementations and
  replace call sites with `sls_trim`. **Compare the implementations first** —
  `common.cpp:530` uses `std::string::find_first_not_of(" \t\n\r")` (verify the live
  set). If the conf.cpp implementations strip a different whitespace set, surface that
  as a question (open question #1 below) and keep the union of the two sets in the
  consolidated helper, with a comment explaining why.
- `common.hpp` re-includes `sls_string.hpp` for source compatibility.

Add `tests/test_sls_string.cpp`:
- `sls_trim("  abc\t")` → `"abc"`; whitespace-only string trims to empty.
- `sls_is_safe_name` accepts alphanumerics + `_-` (read the live impl for the exact
  charset); rejects `/`, `..`, `;`, `:`, embedded NUL.
- `sls_split_string("a;b;c", ";", out)` → `["a","b","c"]`; `count` parameter caps.
- `sls_hash_key` matches the existing FNV/DJB hash on a known vector — do NOT change
  the algorithm, the hash is used as the puller `connect_hash` distribution key and a
  change would re-shuffle all upstream selections.

**Verify**:
- `grep -n 'static.*trim\|std::string trim' src/core/conf.cpp` → 0
- All call sites compile; tests pass.

---

## Step 3: Time, path, pid, privileges, dns modules

**Risk: LOW.** **Confidence: HIGH.** Pure code motion, no API change.

Split:

- `src/core/sls_time.{hpp,cpp}` — `sls_gettime`, `sls_gettime_ms`,
  `sls_gettime_default_string`, `sls_gettime_fmt`.
- `src/core/sls_path.{hpp,cpp}` — `sls_mkdir_p` (already `std::filesystem`-backed from
  plan 005).
- `src/core/sls_pid.{hpp,cpp}` — `sls_read_pid`, `sls_is_pid_location_changed`,
  `sls_reload_pid`, `sls_load_pid_filename`, `sls_write_pid`, `sls_remove_pid`,
  `sls_send_cmd` (signal-based reload — fits with pid).
- `src/core/sls_privileges.{hpp,cpp}` — `sls_drop_privileges`.
- `src/core/sls_dns.{hpp,cpp}` — `sls_gethostbyname`.

For each: declare in the `.hpp`, move definitions to the `.cpp`, register in
`src/core/CMakeLists.txt`, and let `common.hpp` keep re-including the new headers for
one release (no caller has to change yet).

Add `tests/test_sls_path.cpp` — `sls_mkdir_p` for a path with multiple missing parents
creates each and returns OK; on a path that already exists, returns OK; on a path
component that is a regular file, returns SLS_ERROR. (No new test for time/pid/
privileges/dns; those need real syscalls to be meaningful.)

**Verify**:
- `wc -l src/core/common.cpp` → drops to under ~50 lines (just the bridging includes
  if you keep them).
- All TUs compile; full ctest green.

---

## Step 4: Decide the fate of `common.hpp`

**Risk: LOW.** **Confidence: HIGH.**

Two options:

**Option A: keep `common.hpp` as the umbrella.** It transitively includes every new
sub-header. Call sites do not change. Lowest churn. Worst at controlling include
bloat.

**Option B: drop `common.hpp`'s back-includes.** Each TU now explicitly includes the
specific module it needs (`sls_string.hpp`, `sls_time.hpp`, ...). Best for compile time
and seeing the dependency graph. Highest churn (every TU touched).

**Recommendation**: Option A for this plan; mark Option B as a follow-up sweep
(`refactor(common): drop umbrella include`) after this plan lands and stabilises. The
deliverable here is the modules, not the cleanup.

`grep -rn '#include "common.hpp"' src/` lists every site touched if you decide to do
Option B; the actual count today is the canonical estimate.

---

## Step 5: `SLSManager::start()` — Step A: `std::vector` the four arrays

**Risk: MED.** **Confidence: HIGH.**

Replace the raw `new[]` block at `src/core/SLSManager.cpp:145-148`:

```cpp
m_map_data = new CSLSMapData[m_server_count];
m_map_publisher = new CSLSMapPublisher[m_server_count];
m_map_puller = new CSLSMapRelay[m_server_count];
m_map_pusher = new CSLSMapRelay[m_server_count];
```

with:

```cpp
m_map_data.resize(m_server_count);          // std::vector<CSLSMapData>
m_map_publisher.resize(m_server_count);
m_map_puller.resize(m_server_count);
m_map_pusher.resize(m_server_count);
```

Update `SLSManager.hpp` (member declarations) and the destructor (no manual `delete[]`).
The destructor currently deletes them via `delete[]`; that call goes away.

Every site that took `&m_map_data[i]` now takes `&m_map_data[i]` from the vector — same
expression, same pointer; the change is transparent. Same for the other three.

**Coordinate with plan 008 Step 4**: 008 also vectorises these. Whichever plan ships
first does the vectorisation; the second plan's Step skips this and just verifies the
move. Sequence in the README: do 010 first, then 008.

**Verify**:
- `cmake --build build -j` → exit 0.
- Full ctest green.
- `grep -n 'new CSLSMapData\[' src/core/SLSManager.cpp` → 0; same for the other three.
- A smoke run (one server, one publisher) starts and stops cleanly with no leak under
  ASan.

---

## Step 6: `SLSManager::start()` — Step B: extract `apply_log_config`, `init_workers`, `init_listeners`

**Risk: MED.** **Confidence: MED.** This is the structural move.

Replace the body of `start()` with three named member functions plus the small entry
point. The order is fixed by the dependencies in the original code.

```cpp
int CSLSManager::start() {
    if (init_log_config() != SLS_OK) return SLS_ERROR;
    if (init_data_maps()  != SLS_OK) return SLS_ERROR;   // Step 5's vectors
    if (init_listeners()  != SLS_OK) return SLS_ERROR;
    if (init_workers()    != SLS_OK) return SLS_ERROR;
    return SLS_OK;
}
```

- `init_log_config()` — lines `:80-133` (level, file, rate-limit, summary, JSON format,
  per-category levels). Pure side effects on the log globals.
- `init_data_maps()` — lines `:135-157` (vector resize from Step 5 + role list + auth
  reject cache).
- `init_listeners()` — lines `:160-304`. The internal lambdas (`port_taken`,
  `make_listener`, `create_for_spec`) become member helpers or `static` file-local
  helpers; whichever keeps the diff smaller. The legacy listener and fallback listener
  blocks are their own helpers (`maybe_init_legacy_listener`, `init_fallback_listener`)
  for testability later.
- `init_workers()` — lines `:307-343`.

**Verify**:
- `cmake --build build -j` → exit 0.
- Full ctest green.
- `wc -l src/core/SLSManager.cpp` → `start()` itself is < 30 lines.
- Smoke run starts a server and accepts one publisher + one player.

**STOP**: a listener-init failure leaves a partially-initialised manager (e.g. some
listeners started, then a later port is taken and we return SLS_ERROR with running
threads) — that bug exists today; surface it as a follow-up (`init_listeners` should
roll back what it created on failure). Do NOT fix it in this plan; just note it.

---

## Step 7: Final cleanup

**Risk: LOW.** **Confidence: HIGH.**

- Drop the bridging includes from `common.hpp` if Option B was chosen in Step 4
  (otherwise keep them).
- Delete `common.cpp` entirely if Step 1-3 left it empty (replace with a one-line
  `// see sls_time/sls_string/etc.` comment file or remove from CMake).
- Remove `common.hpp`'s declarations that were moved (leave only the umbrella includes
  if Option A).

**Verify**: `wc -l src/core/common.{cpp,hpp}` shows the file shrunk to under 100 lines
total (umbrella header only) or zero (Option B).

---

## Test plan

- `tests/test_ts_parser.cpp` (Step 1) — SPS/PPS clamp, PAT, PMT, audio-track parse.
- `tests/test_sls_string.cpp` (Step 2) — trim, safe-name, split, hash.
- `tests/test_sls_path.cpp` (Step 3) — `sls_mkdir_p` happy + error paths.
- Full ctest + TSan/ASan all green after each commit.
- Manual smoke: publisher + player + `/disconnect` start/stop cleanly.

## Done criteria

ALL must hold:

- [ ] `ts_parser` module exists with its own unit tests; `sls_parse_ts_info` no longer
      lives in `common.cpp`
- [ ] Exactly one `trim` implementation in the codebase (the one in `sls_string`)
- [ ] The four `new[]` arrays in `SLSManager::start()` are gone (replaced by
      `std::vector`)
- [ ] `CSLSManager::start()` body is < 30 lines (orchestrator only); each phase is its
      own member function
- [ ] `ctest --test-dir build --output-on-failure` passes (incl. new tests)
- [ ] ASan/TSan clean on a smoke run including config reload (`SIGHUP`)
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` row for 010 updated

## STOP conditions

- A `trim`/`safe-name`/`hash` consolidation changes the observable output on any input
  — STOP and document the divergence; the existing call sites may depend on the old
  behavior.
- An extracted module reintroduces a circular `#include` — STOP and reorganise; the
  whole point of the split is to reduce coupling.
- Plan 008 Step 4 already vectorised the data maps and a merge conflict is brewing —
  STOP and coordinate; this plan's Step 5 then becomes a no-op verification.
- A drift-check mismatch on `common.cpp` or `SLSManager.cpp` — STOP and re-read before
  proceeding.

## Maintenance notes

- The `ts_parser` module is the new home for any future TS-related work (audio gap
  filler internals, SCTE-35, etc.). Keep it focused on parsing; the audio-gap synth
  stays in `SLSAudioGapFiller`.
- `sls_string`'s charset for `sls_is_safe_name` is the security-relevant choice — any
  change must update the test suite first, then the implementation.
- Plan 008 Step 4 depends on the vectorisation in Step 5 above. Land 010 first.
- Plan 009's seams (`AcceptCtx`, helpers) live in `SLSListenerHandler.cpp`, not in
  `common`. The two plans should not collide; if they do, the conflict is mechanical.
- Reviewer: scrutinize Step 2's `trim` consolidation (verify the whitespace-set
  decision is documented) and Step 6's phase boundaries (each should compile + pass
  tests independently).

## Open questions

1. Do the three current `trim` implementations strip the same whitespace set? Diff
   them in Step 2 before consolidating. If they diverge, pick the wider set and
   surface the change in the commit message.
2. Should `sls_dns` consolidate with `sls_path` and `sls_time` into a single
   `sls_sys` module, or stay as separate `.hpp/.cpp` pairs? Lean toward separate —
   one concern per module is the point.
3. `CSLSManager::start()` returns `SLS_ERROR` from a dozen sites without rolling back
   partially-started listeners and workers. Fix in this plan or open as a follow-up?
   Recommend: follow-up (Step 6 STOP note documents it).
