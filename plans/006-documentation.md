# Plan 006: Documentation

> **Executor instructions**: Follow this plan step by step. If anything in "STOP
> conditions" occurs, stop and report. When done, update the status row in
> `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 78d67c0..HEAD -- README.md ChangeLog.md src/sls.conf CMakeLists.txt Dockerfile`
> If these changed materially, re-read them before editing.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: LOW (docs only)
- **Depends on**: none (but reflect any IPv6-ACL / submodule-pin outcomes from 003/005 if those landed)
- **Category**: docs
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

The README points contributors at the wrong SRT dependency (upstream Haivision instead of
the belabox-patched `irlserver/srt` fork the build actually needs), omits required system
deps, and sends operators to the *original* project's wiki for config — which documents
none of the IRL-specific directives that are the entire reason this fork exists. The
ChangeLog froze at upstream v1.5.1 while the project is at v3.1.0. And there is no
`CLAUDE.md` to orient agents/new contributors. None of this is urgent, but wrong docs cost
more than missing docs.

> Per the maintainer's documentation style: **do not use dashes (— or -) as punctuation**
> in the docs you write. Use periods, commas, or parentheses. (This applies to the prose
> in README/CONFIGURATION/CLAUDE.md, not to code, config keys, or CLI flags.)

## Current state

- `README.md:10` points to `https://github.com/Haivision/srt`; the build needs the fork
  (`Dockerfile:8`: `git clone https://github.com/irlserver/srt.git`, branch `belabox`).
- `README.md:15-20` "Compilation" omits OpenSSL + zlib (`CMakeLists.txt` does
  `find_package(OpenSSL REQUIRED)`; Dockerfile `apk add openssl-dev zlib-dev`).
- `README.md:42` links the config directives to the upstream `rstular/srt-live-server` wiki.
- IRL directives live only in `src/sls.conf` comments and the feature docs:
  `listen_publisher_srtla`, the `player_key_*` family, `max_input_bitrate_kbps` family,
  `audio_gap_fill`, `push_destination_*` family. (See `src/sls.conf` and
  `PLAYER_KEY_IMPLEMENTATION.md`, `BITRATE_LIMITING.md`, `AUDIO_GAP_FILLING.md`.)
- `ChangeLog.md` newest entry is upstream v1.5.1; `CMakeLists.txt:2` declares `VERSION 3.1.0`.
- No `CLAUDE.md` / `AGENTS.md` at repo root.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Find IRL directives | `grep -nE "^\s*(listen_|player_key|max_input_bitrate|audio_gap_fill|push_destination)" src/sls.conf` | lists the directives to document |
| Confirm version | `grep -n "VERSION" CMakeLists.txt` | `VERSION 3.1.0` |
| Version history | `git log --oneline --no-merges` | the fork's feature commits |

## Scope

**In scope**: `README.md`, `ChangeLog.md`, `CLAUDE.md` (create), `CONFIGURATION.md`
(create), optionally `CONTRIBUTING.md` (create, for the submodule-bump note).

**Out of scope**: any code; the existing feature docs (`*_IMPLEMENTATION.md` etc.) — link
to them, don't rewrite them.

## Git workflow

- Branch: `advisor/006-documentation`
- One commit per step, conventional-commits, lowercase, scoped — e.g.
  `docs: fix srt dependency and build prerequisites in readme`.

## Steps

### Step 1: Fix README Requirements / Compilation / Configuration

- Change the SRT requirement to the fork: point to `https://github.com/irlserver/srt`,
  branch `belabox`, and note it carries the SRTLA patches the server depends on (building
  against upstream Haivision SRT causes the glitching the README itself warns about).
- Add the system prerequisites the build needs: OpenSSL (`openssl-dev`/`libssl-dev`),
  zlib (`zlib-dev`/`zlib1g-dev`), a C++17 compiler, CMake, and the submodules
  (`git submodule update --init`).
- Replace the `rstular` wiki link with a pointer to the new in-repo `CONFIGURATION.md`
  (Step 2). Keep the upstream wiki link only as "for the base SLS directives".
- If plan 001 landed, add a short "Running the tests" subsection
  (`cmake -S . -B build -DSLS_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build`).

**Verify**: `grep -n "irlserver/srt" README.md` → present; `grep -n "Haivision" README.md`
→ only as a secondary reference, not the primary build dependency.

### Step 2: Create `CONFIGURATION.md` cataloging IRL directives

Document every IRL-specific config directive with: name, type, default, and a one-line
behavior summary. Source the list from `src/sls.conf` (use the grep command above) and the
feature docs. At minimum cover:
- `listen_player`, `listen_publisher`, `listen_publisher_srtla` (multi-port syntax: list,
  ranges, mix)
- the `player_key_*` family (auth URL, cache duration, timeout, format, etc.)
- `max_input_bitrate_kbps` and its siblings (bitrate limiting)
- `audio_gap_fill`
- `push_destination_*` family (webhook-driven push targets)
- `api_keys`, `http_port`, `cors_header`, `log_*` (including the per-category log levels)
- any `relay { }` block options (note their status — see plan 007 if the relay direction is resolved)

Cross-link `AUDIO_GAP_FILLING.md`, `BITRATE_LIMITING.md`, `PLAYER_KEY_IMPLEMENTATION.md`.
If plan 003 landed and changed IPv6 ACL behavior, document the resulting IP-ACL semantics
(IPv4 enforced; IPv6 behavior as implemented).

**Verify**: every directive from the grep appears in `CONFIGURATION.md`
(`for d in $(grep -oE "^\s*[a-z_]+" src/sls.conf | sort -u); do grep -q "$d" CONFIGURATION.md || echo "MISSING: $d"; done`
prints nothing for the IRL directives — some base/comment tokens may legitimately be absent;
use judgment).

### Step 3: Backfill `ChangeLog.md`

Add a "Fork history" section above the upstream history. Populate entries for the fork's
shipped work, grouped by the `CMakeLists.txt` `VERSION` bumps, working from
`git log --oneline --no-merges`. Capture at least the headline features: SRTLA/bonded
support, player-key auth + deferred accept, push URL validation, bitrate limiting, audio
gap filling, session tracking, summary logging, the HTTP stats/disconnect API, handshake-
time DoS rejection. You do not need a line per commit; group by feature and version.

**Verify**: `grep -n "3.1.0" ChangeLog.md` → present; the newest entry is no longer v1.5.1.

### Step 4: Create `CLAUDE.md`

A top-level orientation file for agents and new contributors:
1. Build invocation incl. submodules and required system packages (mirror README Step 1).
2. Layout map: `src/core/` builds the `sls_core` static lib; `src/srt-live-server.cpp` and
   `src/srt-live-client.cpp` are the two thin executables (`srt_server`, `srt_client`).
3. Where the live SRT socket boundary is and how to keep unit tests off it.
4. The test harness (from plan 001) and how to add a test.
5. A warning: this project has manual-memory ring buffers and shared cross-thread state;
   run the sanitizer build (`-DSLS_SANITIZE=ON` / `-DSLS_TSAN=ON`) before submitting a PR
   that touches `SLSRecycleArray`, `SLSRole`, `SLSSrt`, or the listener/manager threading.
6. Pointers to the feature docs and `CONFIGURATION.md`.
7. The commit conventions (conventional commits, lowercase, scoped to package/app name).

**Verify**: `test -f CLAUDE.md` → exists; it names the build command, the layout, and the
sanitizer guidance.

## Done criteria

ALL must hold:

- [ ] README points to `irlserver/srt` (belabox) as the primary SRT dep and lists OpenSSL/zlib
- [ ] `CONFIGURATION.md` exists and covers the IRL directives from `src/sls.conf`
- [ ] `ChangeLog.md` has a fork-history section reaching 3.1.0
- [ ] `CLAUDE.md` exists with build/layout/test/sanitizer guidance
- [ ] No dash characters used as punctuation in the new/edited prose
- [ ] `git status` shows only doc files modified
- [ ] `plans/README.md` status row for 006 updated

## STOP conditions

- A directive in `src/sls.conf` is ambiguous (you cannot tell what it does from the conf
  comment + code) — note it as "TODO: confirm" in `CONFIGURATION.md` rather than guessing,
  and list these in your report.

## Maintenance notes

- Keep `CONFIGURATION.md` in sync when config directives are added (consider a CI check or
  a CONTRIBUTING note).
- If plan 007 resolves the static-vs-dynamic relay question, update the relay section.
- If plan 005 changed the submodule-bump workflow, document it (CONTRIBUTING or README).
