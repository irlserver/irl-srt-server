# Plan 001: Establish a verification baseline (unit tests, sanitizers, CI)

> **Executor instructions**: Follow this plan step by step. Run every verification
> command and confirm the expected result before moving to the next step. If anything
> in the "STOP conditions" section occurs, stop and report — do not improvise. When
> done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 78d67c0..HEAD -- CMakeLists.txt src/core/CMakeLists.txt`
> If `CMakeLists.txt` or `src/core/CMakeLists.txt` changed since this plan was written,
> re-read them before proceeding; on a structural mismatch treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW (adds files + opt-in build targets; touches no production code path)
- **Depends on**: none
- **Category**: tests / dx
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

This is a ~17.8k-LOC, network-facing, multi-threaded C++ server with manual memory
management (`new[]`/`memcpy` ring buffers) and zero automated tests. `CMakeLists.txt`
calls `include(CTest); enable_testing()` but no `add_test()` exists anywhere, and there
is no CI. Every change ships unverified; the only regression signal is a streamer's feed
going dark in production. This plan creates the one-command "does it still work?" answer
that every other plan (especially 003 and 007) depends on, and adds a sanitizer build so
the memory/concurrency bug classes this codebase is prone to crash loudly in CI instead
of subtly in the field.

## Current state

- `CMakeLists.txt:1-2` — `cmake_minimum_required (VERSION 3.10 FATAL_ERROR)`, `project(srt-live-server VERSION 3.1.0)`.
- `CMakeLists.txt:6-12` — compiler flags are only `-Wall -Wno-invalid-offsetof` (no sanitizers).
- `CMakeLists.txt` (near line 21-22) — `include(CTest)` and `enable_testing()` are already present; no test target is registered.
- `src/core/CMakeLists.txt` — builds `add_library(sls_core STATIC ...)` from ~84 files and links `spdlog`, `nlohmann_json::nlohmann_json`, `httplib`, `BS_thread_pool`, `Threads::Threads`, `CxxUrl`. `target_include_directories(sls_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})`.
- `lib/` holds vendored submodules (spdlog, json, cpp-httplib, CxxUrl, thread-pool). There is no `lib/doctest`.
- Building `sls_core` requires the SRT library installed on the system (the static lib links `srt` transitively via the executables; see `src/CMakeLists.txt`).

The first units to test are the ones with the least environmental coupling (no live SRT
socket, no thread, no wall clock). Their real signatures (read them again before writing
tests — header excerpts below are the contract):

- `src/core/sls_sid.hpp:17,22` —
  `std::map<std::string,std::string> sls_parse_streamid(const char *sid);`
  `bool sls_validate_sid_format(const char *sid);`
- `src/core/auth_reject_cache.hpp:19-41` — class `AuthRejectCache` with
  `explicit AuthRejectCache(time_t ttl_seconds = 30)`, `void set_ttl(time_t)`,
  `void record_failure(const std::string&)`, `bool is_blocked(const std::string&) const`,
  `void cleanup()`.
- `src/core/SLSRecycleArray.hpp` — `CSLSRecycleArray` with `void setSize(int)`,
  `int put(char*, int)`, `int get(char*, int, SLSRecycleArrayID*, int aligned)`,
  `int count()`. (Read the header for the exact `SLSRecycleArrayID` shape and `get` semantics.)
- `src/core/SLSBitrateLimit.hpp` — `CSLSBitrateLimit` (read header for the public API).
- `src/core/SLSAudioGapFiller.hpp` — `SLSAudioGapFiller`; constants `MAX_PTS_GAP`, PTS wrap at `1<<33`, AAC/MP3/Opus sample-rate tables (read header for the API).

Convention: this repo uses 4-space indent, `CamelCase` classes with `C`/`SLS` prefixes,
`snake_case` methods, `m_`-prefixed members. Match it in test code where it touches repo types.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Submodules | `git submodule update --init` | exit 0; `lib/*` populated |
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` | exit 0, no errors |
| Build | `cmake --build build -j` | exit 0; `build/bin/sls_tests` exists |
| Run tests | `ctest --test-dir build --output-on-failure` | all tests pass |
| Sanitizer cfg | `cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_SANITIZE=ON` | exit 0 |
| Sanitizer run | `ctest --test-dir build-asan --output-on-failure` | all pass, no ASan/UBSan reports |

> If `cmake` configure fails because the **SRT library is not installed**, that is an
> environment problem, not a plan failure — see STOP conditions.

## Scope

**In scope** (create/modify only these):
- `lib/doctest/doctest.h` (vendor — single header)
- `tests/CMakeLists.txt` (create)
- `tests/test_main.cpp` (create — doctest entry point)
- `tests/test_sls_sid.cpp`, `tests/test_recycle_array.cpp`, `tests/test_auth_reject_cache.cpp`, `tests/test_bitrate_limit.cpp`, `tests/test_audio_gap_filler.cpp` (create)
- `CMakeLists.txt` (add `SLS_BUILD_TESTS` / `SLS_SANITIZE` options + `add_subdirectory(tests)`)
- `.github/workflows/ci.yml` (create)

**Out of scope** (do NOT touch):
- Any file under `src/` — this plan adds tests only; if a test reveals a bug, record it
  and STOP (the fix belongs to plan 002/003/004, which already cover the known ones).
- `lib/` submodules other than the new `lib/doctest`.

## Git workflow

- Branch: `advisor/001-verification-baseline`
- Commit per step; conventional-commits, lowercase, scoped — e.g.
  `test(core): add doctest harness and first unit tests`,
  `ci(build): add github actions build + ctest + sanitizer matrix`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Vendor doctest

Download the single-header doctest (a widely-used, zero-dependency C++ test framework)
to `lib/doctest/doctest.h`. Use a pinned release tag, not master. If the environment has
no network access, STOP and report (the operator may need to add it as a submodule).

**Verify**: `test -f lib/doctest/doctest.h && head -5 lib/doctest/doctest.h` → shows the
doctest license/version banner.

### Step 2: Add CMake options and test subdirectory

In `CMakeLists.txt`, after the compiler-flags block, add:

```cmake
option(SLS_BUILD_TESTS "Build unit tests" OFF)
option(SLS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(SLS_TSAN "Build with ThreadSanitizer (mutually exclusive with SLS_SANITIZE)" OFF)

if (SLS_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
endif()
if (SLS_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=thread)
endif()
```

At the end of `CMakeLists.txt` (after the existing `add_subdirectory(${PROJECT_SOURCE_DIR}/src)` is reached via the include chain), add:

```cmake
if (SLS_BUILD_TESTS)
    add_subdirectory(tests)
endif()
```

Create `tests/CMakeLists.txt`:

```cmake
add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE ${PROJECT_SOURCE_DIR}/lib/doctest)

add_executable(sls_tests
    test_main.cpp
    test_sls_sid.cpp
    test_recycle_array.cpp
    test_auth_reject_cache.cpp
    test_bitrate_limit.cpp
    test_audio_gap_filler.cpp
)
target_link_libraries(sls_tests PRIVATE sls_core doctest)
add_test(NAME unit COMMAND sls_tests)
```

Create `tests/test_main.cpp`:

```cpp
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
```

**Verify**: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` → exit 0.

### Step 3: Write the first unit tests

Write the five test files. Before writing each, **read the corresponding header** for the
exact API; the signatures above are the contract but read for `SLSRecycleArrayID`, the
bitrate-limit API, and the gap-filler API which are not fully quoted here. Cover at
minimum these cases (each `DOCTEST_TEST_CASE`):

- `test_sls_sid.cpp` — `sls_validate_sid_format`: a well-formed `#!::h=..,sls_app=..,r=..`;
  a well-formed bare `host/app/stream`; empty string; missing `/` parts; a streamid with
  `..` in a component (must be rejected — `sls_is_safe_name`); whitespace-padded values
  (must still validate, trimming is intended). Also `sls_parse_streamid` returns the
  expected keys for both forms.
- `test_recycle_array.cpp` — construct, `setSize(N)`; `put` then `get` round-trips bytes;
  a `put` that wraps the ring (write near the end, then a length that crosses the seam)
  returns the correct two-segment data to a reader; a reader that has fallen more than
  `N` bytes behind resyncs (overrun path) rather than returning corrupt bytes; zero-length
  and oversized (`len > m_nDataSize`) `put` are rejected with `SLS_ERROR`.
- `test_auth_reject_cache.cpp` — `record_failure` then `is_blocked` is true; an unknown
  key is not blocked; after `set_ttl(1)` and the TTL elapses (use a tiny ttl and a
  deterministic approach — the cache uses `time(nullptr)`, so test boundary behavior via
  the public API, or document the second-granularity limitation and assert what you can);
  empty streamid is never blocked.
- `test_bitrate_limit.cpp` — bytes accumulate within a window, the limiter reports the
  expected rate, and counters reset across the window boundary (read the header for the
  exact methods; assert the windowed accounting).
- `test_audio_gap_filler.cpp` — PTS wrap at `1<<33` is handled; a gap larger than
  `MAX_PTS_GAP` is clamped; frame size is selected correctly from the AAC/MP3/Opus
  sample-rate tables for a couple of known sample rates.

Keep tests pure: no SRT socket, no thread, no sleeping on real time beyond what the cache
TTL test minimally needs. If a unit turns out to require a live socket/thread to
construct, **skip that file, leave a `// TODO` test stub, and note it in your report** —
do not refactor production code to make it testable (that is plan 007's job).

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` →
all test cases pass.

### Step 4: Confirm the sanitizer build runs the tests clean

**Verify**:
```
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_SANITIZE=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```
→ all pass with no ASan/UBSan diagnostics. If ASan/UBSan reports a real defect in
`sls_core` exercised by a test, that is a genuine bug — record it precisely (it likely
belongs to plan 003) and STOP; do not fix production code here.

### Step 5: Add CI

Create `.github/workflows/ci.yml` that, on `push` and `pull_request`:
1. checks out with `submodules: recursive`;
2. installs build deps and the SRT library (on Ubuntu: `libsrt-openssl-dev` or build the
   `irlserver/srt` fork — match what the Dockerfile does; if the fork is required, build
   and `make install` it as a prior step, mirroring `Dockerfile:8-15`);
3. runs a matrix of three configs: plain Debug, `-DSLS_SANITIZE=ON`, `-DSLS_TSAN=ON`;
   each configures with `-DSLS_BUILD_TESTS=ON`, builds, and runs `ctest --output-on-failure`;
4. caches `lib/` keyed on the submodule SHAs.

**Verify**: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`
→ exit 0 (valid YAML). (CI can only be fully verified once pushed; that is the operator's call.)

## Test plan

The deliverable *is* the test suite. New tests live in `tests/` as listed in Step 3.
There is no existing test to model after — this plan establishes the pattern; keep it
doctest-idiomatic and self-contained.

Verification: `ctest --test-dir build --output-on-failure` → all pass; the same under
`build-asan`.

## Done criteria

ALL must hold:

- [ ] `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` exits 0
- [ ] `cmake --build build -j` exits 0 and produces `build/bin/sls_tests` (or `build/tests/sls_tests`)
- [ ] `ctest --test-dir build --output-on-failure` passes with ≥ 5 test files registered
- [ ] The ASan/UBSan build (`-DSLS_SANITIZE=ON`) builds and `ctest` passes clean
- [ ] `.github/workflows/ci.yml` is valid YAML with the three-config matrix
- [ ] `git status` shows no modifications under `src/` (only `tests/`, `lib/doctest/`, `CMakeLists.txt`, `.github/`)
- [ ] `plans/README.md` status row for 001 updated

## STOP conditions

Stop and report (do not improvise) if:
- The SRT library is not installed and cannot be installed in the environment (configure
  fails on a missing `srt` dependency) — report so the operator can provision it.
- No network access to fetch doctest and it is not already vendored.
- A test reveals a real defect in production code (record exact repro + `file:line`; it
  likely maps to plan 002/003/004).
- The existing `CMakeLists.txt` structure has drifted so far from the excerpts that the
  option/subdirectory additions don't fit cleanly.
- Linking `sls_tests` against `sls_core` pulls in `srt_*` symbols a test can't satisfy —
  report; the operator may need a small test-only seam (defer to plan 007, don't add it here).

## Maintenance notes

- Every new pure-logic module should get a `tests/test_*.cpp` and a line in
  `tests/CMakeLists.txt`.
- Plans 003 and 007 assume this harness exists; they add regression tests into it.
- A reviewer should confirm the CI sanitizer jobs actually run `ctest` (not just build)
  and that the matrix is not silently skipping on a missing SRT dep.
- TSan and ASan are mutually exclusive; keep them as separate build dirs/CI jobs.
