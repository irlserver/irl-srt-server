# Plan 005: Build, tooling & supply-chain hardening

> **Executor instructions**: Follow this plan step by step. Each step is independent with
> its own verification. If anything in "STOP conditions" occurs, stop and report. When
> done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 78d67c0..HEAD -- Dockerfile .gitmodules CMakeLists.txt src/core/common.cpp src/core/common.hpp`
> Compare excerpts against live code for any changed file; mismatch ⇒ STOP for that step.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: LOW (Steps 1–3, 5) / MED (Step 4, dead-code removal touches `sls_mkdir_p`)
- **Depends on**: none
- **Category**: dx / migration
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

The build is not reproducible (the SRT fork and OS base image float; submodules pin to
arbitrary master/develop commits), there is no style/lint enforcement, and `common.cpp`
carries dead code that is a footgun (`sls_format` silently returns `""`). This plan makes
builds deterministic, adds lightweight enforcement, and removes the dead weight.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Submodules | `git submodule update --init` | exit 0 |
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug` | exit 0 |
| Build | `cmake --build build -j` | exit 0 |
| Submodule pins | `git submodule status` | shows pinned SHAs |
| clang-format check | `clang-format --version` then `git ls-files '*.cpp' '*.hpp' \| xargs clang-format --dry-run` | runs (warnings ok at first) |

## Scope

**In scope**: `Dockerfile`, `.gitmodules`, the `lib/*` submodule pins (via checkout),
`CMakeLists.txt`, `src/core/common.cpp`, `src/core/common.hpp`, `.clang-format` (create),
`.clang-tidy` (create), `.editorconfig` (create, optional).

**Out of scope**: production logic; the CI workflow file (that's plan 001 — if 001 landed,
you may add a `clang-format --dry-run` step there, but don't create CI here).

## Git workflow

- Branch: `advisor/005-build-supply-chain`
- One commit per step, conventional-commits, lowercase, scoped — e.g.
  `build(docker): pin srt fork and alpine base to fixed refs`,
  `chore(deps): pin vendored submodules to release tags`.

---

## Step 1: Pin the SRT fork to a commit SHA in the Dockerfile

**Risk: LOW.** **Confidence: HIGH.**

Current state — `Dockerfile:8-15`:
```dockerfile
RUN git clone https://github.com/irlserver/srt.git
WORKDIR /tmp/srt
RUN git checkout belabox && ./configure && make -j$(nproc) && make install
```
`belabox` is a moving branch with no SHA — two builds a week apart can ship different SRT
cores with no record.

Fix: introduce a build arg pinned to a known-good commit and check it out explicitly:
```dockerfile
ARG SRT_COMMIT=<known-good-belabox-sha>
RUN git clone https://github.com/irlserver/srt.git
WORKDIR /tmp/srt
RUN git checkout ${SRT_COMMIT} && ./configure && make -j$(nproc) && make install
```
To choose the SHA: `git ls-remote https://github.com/irlserver/srt.git belabox` gives the
current tip; use that as the initial pin (record it in the Dockerfile and in your report).
Keep `belabox` referenced in a comment so the bump source is documented.

**Verify**: `grep -n "SRT_COMMIT" Dockerfile` → shows the ARG and the checkout; the SHA is
a full 40-char hex, not a branch name.

---

## Step 2: Pin the Alpine base image

**Risk: LOW–MED.** **Confidence: HIGH.**

Current state — `Dockerfile:2,17`: `FROM alpine:latest as build` and `FROM alpine:latest`,
plus `apk upgrade` on both stages — fully floating OS toolchain.

Fix: pin to a specific Alpine version (and ideally a digest). Replace both `FROM` lines
with `FROM alpine:3.20` (or the current stable at execution time — check
`https://hub.docker.com/_/alpine` tags; use a concrete `3.x`). Optionally append
`@sha256:<digest>`. Remove `apk upgrade` from the **final** stage (rely on the pinned base);
keep `apk add --no-cache <pkgs>` as-is. Leave the build stage's `apk upgrade` only if a
specific fix needs it; prefer removing it for reproducibility.

**Verify**: `grep -n "FROM alpine" Dockerfile` → both lines pin a concrete version (no
`:latest`); `grep -cn "apk upgrade" Dockerfile` → reduced.

---

## Step 3: Pin vendored submodules to release tags

**Risk: LOW.** **Confidence: HIGH.**

Current state — `git submodule status` shows floating pins:
```
79d83feb... lib/cpp-httplib   (post-v0.48.0 master commit)
e4bdf1be... lib/json          (a dependabot[bot] commit on develop)
f1d748e5... lib/spdlog        (.gitmodules claims branch = 1.9.2)
bd4533f1... lib/thread-pool   (already at a v5.x tag — OK)
e81b86e8... lib/CxxUrl        (upstream master)
```
`.gitmodules` declares `branch = 1.9.2` for spdlog (misleading) and no branch for the rest.

Fix: for each header-only submodule, check out a **release tag** and record it:
```
git submodule update --init
cd lib/cpp-httplib && git fetch --tags && git checkout v0.48.0 && cd ../..
cd lib/json        && git fetch --tags && git checkout v3.12.0 && cd ../..
cd lib/spdlog      && git fetch --tags && git checkout v1.17.0 && cd ../..
cd lib/CxxUrl      && git fetch --tags && git checkout <latest-release-tag> && cd ../..
git add lib/cpp-httplib lib/json lib/spdlog lib/CxxUrl
```
(thread-pool is already on a tag; leave it unless you want to bump it.) Use the tags listed
or, if a newer stable exists at execution time, the newest stable release tag — never a
branch tip. After checkout, **rebuild** to catch any API breakage from the version change
(json/spdlog moving is the main risk; cpp-httplib/CxxUrl too).

In `.gitmodules`, fix the misleading spdlog `branch = 1.9.2` line: either remove the
`branch =` line entirely (pins are the source of truth) or set it to the real tracking
branch. Add a short note to the README (coordinate with plan 006) that "pins are the source
of truth; bump with checkout + `git add lib/<x>`".

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` (if 001
landed) or at least `cmake --build build -j` → exit 0 after the version bumps;
`git submodule status` shows the chosen tags' SHAs; `grep -n "1.9.2" .gitmodules` → no
matches (or corrected).

> If bumping json/spdlog/cpp-httplib causes compile errors (API drift), STOP and report
> the exact errors — the operator may prefer a different tag. Do not patch production code
> to chase a tag here.

---

## Step 4: Remove dead code in `common.cpp` (`sls_format`, `av_*`)

**Risk: MED (only because `sls_mkdir_p` uses `av_*`).** **Confidence: HIGH.**

`sls_format` returns an empty string (its body is commented out) and has no external
callers; the `av_malloc`/`av_free`/`av_strdup`/`av_strncasecmp`/`av_str_replace`/`av_tolower`
helpers exist solely for `sls_mkdir_p`.

Current state — `src/core/common.cpp:59-75` (`sls_format` stub), `:198-303` (`av_*` block),
`:305-345` (`sls_mkdir_p` using `av_strdup`/`av_strncasecmp`/`av_free`). Confirmed: `grep`
for `sls_format`/`av_*` finds no callers outside `common.cpp`.

Fix, in order:
1. **Delete `sls_format`**: remove the definition (`:59-75`) and its prototype in
   `common.hpp`. First re-confirm no callers: `grep -rn "sls_format" src/` → only the
   definition/prototype. If any caller exists, STOP (it's silently broken; report it).
2. **Rewrite `sls_mkdir_p`** to use `std::filesystem` (already `#include`d in this file)
   instead of the `av_*` helpers:
   ```cpp
   int sls_mkdir_p(const char *path)
   {
       if (!path || !*path) return -1;
       std::error_code ec;
       std::filesystem::create_directories(path, ec);
       return ec ? -1 : 0;
   }
   ```
   Note: the original `mkdir(temp, 0755)` set mode 0755. `create_directories` uses the
   process umask (typically yields 0755 for new dirs under a default umask). If the exact
   0755 mode is load-bearing for HLS recording, follow with
   `std::filesystem::permissions(path, std::filesystem::perms::owner_all | perms::group_read | perms::group_exec | perms::others_read | perms::others_exec, ec);`
   Read the callers of `sls_mkdir_p` to judge whether mode matters; if unsure, include the
   explicit `permissions` call to preserve 0755.
3. **Delete the `av_*` block** (`:198-303`) now that `sls_mkdir_p` no longer uses it. Re-run
   `grep -rn "av_strdup\|av_malloc\|av_free\|av_strncasecmp\|av_str_replace\|av_tolower\|max_alloc_size" src/`
   → no matches outside the deleted block before removing.
4. Remove the now-dead commented-out blocks noted in the audit (`common.cpp:159,173-176,181-184`
   DNS/address dumps, `:265` orphaned comment) if they are pure noise — optional, low value.

**Verify**: `cmake --build build -j` → exit 0;
`grep -rn "sls_format\|av_strdup\|av_malloc" src/` → no matches.

---

## Step 5: Add clang-format, clang-tidy, and `-Wextra`

**Risk: LOW (configs are advisory at first).** **Confidence: HIGH.**

There is no `.clang-format`, `.clang-tidy`, or `.editorconfig`, and the build uses only
`-Wall -Wno-invalid-offsetof`.

Fix:
1. **`.clang-format`** — base on LLVM with 4-space indent (closest to existing style).
   Generate a starting point: `clang-format --style=LLVM --dump-config > .clang-format`,
   then set `IndentWidth: 4`, `UseTab: Never`, `ColumnLimit: 0` (or 120). Do NOT reformat
   the whole tree in this plan (that would bury future diffs) — just commit the config.
2. **`.clang-tidy`** — conservative, warn-only to start:
   ```yaml
   Checks: 'bugprone-*,performance-*,modernize-use-override,modernize-use-nullptr,-bugprone-easily-swappable-parameters'
   WarningsAsErrors: ''
   HeaderFilterRegex: 'src/core/.*'
   ```
3. **`-Wextra -Wshadow`** — in `CMakeLists.txt`, change the three compiler-flag branches
   (GNU/Clang/else) from `-Wall -Wno-invalid-offsetof` to
   `-Wall -Wextra -Wshadow -Wno-invalid-offsetof`. Do **not** add `-Werror` (the existing
   tree will emit many new warnings; failing the build is out of scope here). Leave the
   GNU-only `-fcompare-debug-second` as-is.

**Verify**: `test -f .clang-format && test -f .clang-tidy` → both exist;
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j` → still exits 0
(warnings allowed, errors not). Report the approximate new-warning count so the operator
can scope a follow-up cleanup.

---

## Test plan

No new unit tests (build/config/cleanup only). The gate is: the project still builds
(`cmake --build build -j` exit 0), tests still pass if 001 landed
(`ctest --test-dir build --output-on-failure`), and submodule version bumps don't break
compilation.

## Done criteria

ALL must hold:

- [ ] `Dockerfile` pins SRT to a 40-char SHA and Alpine to a concrete version (no `:latest`)
- [ ] `git submodule status` shows release-tag SHAs for cpp-httplib, json, spdlog, CxxUrl
- [ ] `.gitmodules` no longer carries a misleading `branch = 1.9.2`
- [ ] `cmake --build build -j` exits 0 after submodule bumps and dead-code removal
- [ ] `grep -rn "sls_format\|av_strdup\|av_malloc" src/` → no matches
- [ ] `.clang-format` and `.clang-tidy` exist; `-Wextra -Wshadow` added to all three flag branches
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` status row for 005 updated

## STOP conditions

- Step 3: a submodule tag bump breaks compilation — STOP, report the errors and the tag.
- Step 4: any external caller of `sls_format` exists, or `sls_mkdir_p`'s 0755 mode is
  clearly load-bearing and `std::filesystem::permissions` doesn't reproduce it — STOP and report.
- Step 1: cannot resolve the `belabox` tip SHA (no network) — STOP and report; the operator
  supplies the pin.

## Maintenance notes

- Document the submodule/SRT bump workflow (checkout tag/SHA + `git add`) — coordinate with
  plan 006's CONTRIBUTING/README note.
- A follow-up plan can flip clang-tidy / `-Wextra` to `-Werror` in CI once the warning
  backlog is cleared (per-file).
- Reviewer: confirm the SRT SHA actually builds the belabox patches the server relies on
  (SRTLA), and that the json/spdlog version bumps didn't change runtime behavior.
