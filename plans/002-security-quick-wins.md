# Plan 002: Security quick wins

> **Executor instructions**: Follow this plan step by step. Each step is an independent
> fix with its own verification. Run every verification command and confirm the expected
> result before moving on. If anything in "STOP conditions" occurs, stop and report —
> do not improvise. When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 78d67c0..HEAD -- src/core/common.cpp src/core/common.hpp src/core/SLSListenerAuth.cpp src/core/SLSListenerHandler.cpp src/srt-live-server.cpp src/core/auth_reject_cache.cpp src/core/auth_reject_cache.hpp src/core/SLSRole.cpp src/core/SLSPullerManager.cpp`
> For any in-scope file that changed, compare the "Current state" excerpt against the live
> code before editing it; on a mismatch, treat that step as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M (sum of several S fixes)
- **Risk**: LOW–MED per step (noted inline)
- **Depends on**: 001 (soft — tests make Step 1 and Step 7 much safer; not a hard block)
- **Category**: security / bug
- **Planned at**: commit `78d67c0`, 2026-06-21

## Why this matters

A public-facing SRT server parses untrusted publisher data and runs an outbound auth
webhook. This plan closes the high-confidence security/robustness gaps found in the audit:
a heap overflow reachable from publisher data, a denial-of-service via a misbehaving auth
backend, a timing oracle on the control API key, and several smaller hardening items.
Each is a small, localized change with a clear verification.

> **Threat-model note**: the maintainer treats the SRT `streamid` as a bearer capability
> and the server logs as operator-trusted. Do NOT add auth to per-publisher `/stats`,
> change CORS, or redact streamids/keys from logs — those are intentional and out of scope.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Submodules | `git submodule update --init` | exit 0 |
| Configure | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON` | exit 0 |
| Build | `cmake --build build -j` | exit 0 |
| Tests | `ctest --test-dir build --output-on-failure` | all pass |

(If plan 001 has not landed, build with `-DSLS_BUILD_TESTS=OFF` and rely on compile +
manual reasoning; prefer landing 001 first.)

## Scope

**In scope**: `src/core/common.cpp`, `src/core/common.hpp` (only if a clamp constant is
added), `src/core/SLSListenerAuth.cpp`, `src/core/SLSListenerHandler.cpp`,
`src/srt-live-server.cpp`, `src/core/auth_reject_cache.cpp`, `src/core/auth_reject_cache.hpp`,
`src/core/SLSRole.cpp`, `src/core/SLSPullerManager.cpp`, and new/edited `tests/*`.

**Out of scope**: the `/stats` auth model, CORS config, log redaction (all by design);
the ring buffer (plan 003); any refactor (plan 007).

## Git workflow

- Branch: `advisor/002-security-quick-wins`
- One commit per step, conventional-commits, lowercase, scoped — e.g.
  `fix(core): clamp sps/pps copy to ts_info buffer size`.
- Do NOT push or open a PR unless instructed.

---

## Step 1: Clamp SPS/PPS copy to the destination buffer (heap overflow)

**Risk: LOW.** **Confidence: HIGH.**

`ti->sps` and `ti->pps` are fixed 188-byte buffers, but the copied length is the distance
between H.264 start codes, bounded only by the PES payload size — a publisher can craft a
NAL larger than 188 bytes and overflow the heap.

Current state — `src/core/common.hpp:189-192`:
```cpp
    int sps_len;
    uint8_t sps[TS_PACK_LEN];   // TS_PACK_LEN == 188
    int pps_len;
    uint8_t pps[TS_PACK_LEN];
```
Current state — `src/core/common.cpp` (two copy sites, `:767-768` and `:808-814`):
```cpp
                if (H264_NAL_SPS == nal_type)
                {
                    ti->sps_len = p_end - p;
                    memcpy(ti->sps, p, ti->sps_len);
                }
                else if (H264_NAL_PPS == nal_type)
                {
                    ti->pps_len = p_end - p;
                    memcpy(ti->pps, p, ti->pps_len);
                }
```
(The same pair repeats in the "last nal" block around `:806-814`.)

Fix: at **both** SPS sites and **both** PPS sites, reject/clamp when the computed length
exceeds the destination. Prefer reject (treat as a malformed unit) so a truncated SPS is
never stored. Target shape:
```cpp
                if (H264_NAL_SPS == nal_type)
                {
                    int n = (int)(p_end - p);
                    if (n < 0 || n > (int)sizeof(ti->sps))
                    {
                        spdlog::warn("parse_spspps: SPS len {} exceeds buffer {}, dropping.",
                                     n, (int)sizeof(ti->sps));
                    }
                    else
                    {
                        ti->sps_len = n;
                        memcpy(ti->sps, p, n);
                    }
                }
```
Apply the analogous guard to PPS (`sizeof(ti->pps)`) and to the last-nal block. Use
`sizeof(ti->sps)`/`sizeof(ti->pps)` — do not hardcode 188.

**Test** (add to `tests/test_sls_sid.cpp` or a new `tests/test_ts_parse.cpp` — note
`sls_parse_spspps` is `static`; test through the nearest non-static entry point that
reaches it, e.g. `sls_parse_ts_info`/`sls_pes2es` in `common.hpp`; read the headers to
pick the reachable one): feed a synthetic ES/PES buffer containing an SPS NAL longer than
188 bytes and assert the parser does not write past `ti->sps` (the buffer stays within
bounds and `sps_len <= sizeof(ti->sps)`). If no non-static entry point reaches it, note
that and rely on the ASan build catching the overflow on a crafted input.

**Verify**: `cmake --build build -j` → exit 0; ASan build (`build-asan`) + the new test →
no heap-buffer-overflow report.

---

## Step 2: Negative-cache malformed player-key webhook responses (DoS)

**Risk: LOW.** **Confidence: HIGH.**

When the player-key webhook returns HTTP 200 with a body that fails JSON parse, lacks
`stream_id`, or carries an unusable `stream_id`, the handler returns **without** inserting
any cache entry. The pending player connection then stays parked until its deferred-accept
deadline, and every reconnect re-fires the webhook — exhausting the 1024 pending slots.

Current state — `src/core/SLSListenerAuth.cpp:302-357` (the three early returns at
`:336`, `:348`, `:356` skip `cache_negative()`):
```cpp
    auto cache_negative = [&]() { ... insert_player_key_cache_locked(key, e); };
    ...
        } else {
            spdlog::error("... JSON response missing 'stream_id' for key='{}'.", ...);
            return;                                  // <-- no cache_negative()
        }
    ...
    } catch (const nlohmann::json::exception& e) {
        spdlog::error("... failed to parse JSON for key='{}': {}.", ...);
        return;                                      // <-- no cache_negative()
    }
    ...
    if (stream_id.empty() || stream_id.length() >= URL_MAX_LEN) {
        spdlog::error("... invalid or empty stream_id '{}' for key='{}'.", ...);
        return;                                      // <-- no cache_negative()
    }
```

Fix: call `cache_negative();` immediately before each of those three `return;` statements,
matching the existing transport-failure / non-200 handling at `:316` and `:323`. This makes
a malformed response behave like an auth rejection (short negative TTL), so reconnects
short-circuit instead of re-dispatching.

**Test**: in `tests/` add a case if a seam exists; otherwise this is verified by reading
(the change is three one-line additions). Document in your report that no isolated unit
seam exists for `process_player_key_response` (it depends on listener state), so the test
is deferred to an integration harness.

**Verify**: `cmake --build build -j` → exit 0. Confirm by reading that all three early
returns are now preceded by `cache_negative();`.

---

## Step 3: Constant-time API-key comparison (timing oracle)

**Risk: LOW.** **Confidence: HIGH.**

The control/reset API key is compared with `==`, which short-circuits on the first
differing byte — a remotely observable timing oracle on the `/disconnect` key.

Current state — `src/srt-live-server.cpp:272-276` (in `/stats`) and `:344-348` (in `/disconnect`):
```cpp
            for (const auto& key : conf_srt->api_keys) {
                if (key == auth_header) {
                    return true;   // (and `authorized = true; break;` in /disconnect)
                }
            }
```

Fix: add a file-local constant-time comparison helper near the top of
`src/srt-live-server.cpp` and use it at both sites:
```cpp
static bool sls_ct_equal(const std::string &a, const std::string &b) {
    // Compare over a fixed length so timing does not reveal the prefix match
    // length. Still returns false on length mismatch, but does so after a full
    // pass to avoid an early-out oracle on equal-length candidates.
    size_t n = a.size() > b.size() ? a.size() : b.size();
    unsigned char diff = (unsigned char)(a.size() ^ b.size());
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < a.size() ? (unsigned char)a[i] : 0;
        unsigned char cb = i < b.size() ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}
```
Replace `key == auth_header` with `sls_ct_equal(key, auth_header)` at both sites.

**Verify**: `cmake --build build -j` → exit 0; `grep -n "key == auth_header" src/srt-live-server.cpp`
→ no matches.

---

## Step 4: Clamp the webhook `max_players` override

**Risk: LOW.** **Confidence: MED (defense-in-depth; the webhook is operator-trusted).**

The player-key webhook's `max_players_per_stream` is accepted as any integer and applied
verbatim, so a misconfigured backend could send a negative value (which means "unlimited"
per `sls.conf`) or an absurd ceiling.

Current state — `src/core/SLSListenerAuth.cpp:338-344`:
```cpp
        if (json_response.contains("max_players_per_stream")) {
            if (json_response["max_players_per_stream"].is_number_integer()) {
                json_max_players_override = json_response["max_players_per_stream"].get<int>();
                json_has_max_players_override = true;
            } else { ... }
        }
```
Applied at `src/core/SLSListenerHandler.cpp:882` (`effective_max_players = entry.max_players_per_stream_override;`).

Fix: after reading `json_max_players_override`, clamp it to a sane range. Allow `-1`
(unlimited, the documented sentinel) and any non-negative value, but reject values below
`-1` (treat as "no override"). If the app config exposes a ceiling, clamp the positive
value to it; otherwise leave positive values as-is but reject `< -1`:
```cpp
                json_max_players_override = json_response["max_players_per_stream"].get<int>();
                if (json_max_players_override < -1) {
                    spdlog::warn("[{}] player-key webhook max_players_per_stream={} invalid, ignoring override.",
                                 fmt::ptr(this), json_max_players_override);
                    json_has_max_players_override = false;
                } else {
                    json_has_max_players_override = true;
                }
```

**Verify**: `cmake --build build -j` → exit 0.

---

## Step 5: Check `strdup` result on the accept path

**Risk: LOW.** **Confidence: HIGH.**

`strdup` is called per accepted connection and its result is passed straight to `strtok`
with no null check; under memory pressure a NULL deref crashes the listener thread.

Current state — `src/core/SLSListenerHandler.cpp:309-310`:
```cpp
    char* sid_copy = strdup(sid);
    char* token = strtok(sid_copy, "/");
```

Fix: guard the allocation; on failure log and bail out of this accept cleanly (close the
SRT socket the way the surrounding error paths do — read the nearby `srt->libsrt_close(); delete srt; return ...;`
pattern in this function and mirror it). Minimal:
```cpp
    char* sid_copy = strdup(sid);
    if (!sid_copy) {
        spdlog::error("[{}] CSLSListener::handler, strdup(sid) failed (OOM).", fmt::ptr(this));
        // mirror the function's existing close-and-return cleanup here
    }
    char* token = strtok(sid_copy, "/");
```
Read the function to use the correct local names (`srt`, `client_count`, etc.) in the cleanup.

**Verify**: `cmake --build build -j` → exit 0.

---

## Step 6: Key the auth-reject cache on the canonical streamid

**Risk: LOW.** **Confidence: HIGH (bypass is real; severity is DoS-blunting effectiveness, not access).**

The negative auth cache is keyed on the raw wire streamid, so byte-level variations
(trailing whitespace, extra k/v fields, key reordering) that parse to the same logical
stream are distinct keys and bypass the rejection.

Current state — written on `src/core/SLSRole.cpp:766` `m_auth_reject_cache->record_failure(get_streamid());`
and read in the publisher listen callback (`src/core/sls_sid.cpp`, `sls_publisher_listen_callback`).
The cache itself (`src/core/auth_reject_cache.cpp:30,39`) does an exact map lookup on the
passed string.

Fix: canonicalize before insert and before lookup so both sides agree. Add a small helper
(e.g. in `sls_sid.cpp`/`.hpp` next to `sls_parse_streamid`) that returns a canonical key
`h + "/" + sls_app + "/" + r` from a streamid, and use it at:
- `SLSRole.cpp:766` — `record_failure(sls_canonical_sid_key(get_streamid()))`
- the `is_blocked(...)` call in `sls_publisher_listen_callback` (read `sls_sid.cpp` to find it)

If a streamid does not parse into all three components, fall back to the raw string (so
behavior is unchanged for unparseable input). Keep `AuthRejectCache` itself unchanged —
it is a generic string cache; only the keys passed to it change.

**Test**: add to `tests/test_auth_reject_cache.cpp` (or a new `tests/test_sls_sid.cpp`
case) — two streamids differing only in trailing whitespace / key order produce the same
canonical key.

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` → pass.

---

## Step 7: Tighten `sls_is_safe_name` against URL-significant characters (puller URL injection)

**Risk: MED.** **Confidence: MED (reachable only when the pull relay is enabled).**

When the pull relay is configured, the client-chosen `stream_name` is concatenated into an
outbound SRT URL. `sls_is_safe_name` blocks path separators and control chars but allows
`?`, `=`, `&`, `:`, `@`, `#`, letting a player splice SRT query parameters into the relay
leg's upstream URL.

Current state — `src/core/common.cpp:368-382`:
```cpp
bool sls_is_safe_name(const char *s)
{
    if (!s || !*s) return false;
    if (s[0] == '.' && (s[1] == 0 || (s[1] == '.' && s[2] == 0))) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
        if (*p == '/' || *p == '\\') return false;
        if (*p < 0x20 || *p == 0x7f) return false;
    }
    return true;
}
```
Concatenation site — `src/core/SLSPullerManager.cpp:78` (`snprintf(szURL, ..., "srt://%s/%s", szTmp, m_stream_name)`).

Fix (preferred — minimal blast radius): reject the URL-significant characters that have no
legitimate place in a stream name, by adding them to the per-character rejection in
`sls_is_safe_name`:
```cpp
        if (*p == '/' || *p == '\\') return false;
        if (*p == '?' || *p == '#' || *p == '&' || *p == '=' ||
            *p == '@' || *p == ':' || *p == '%' || *p == ' ') return false;
        if (*p < 0x20 || *p == 0x7f) return false;
```

**This is the highest-risk step in the plan**: `sls_is_safe_name` gates *all* streamid
components (publisher and player), so over-tightening could reject streamids that
legitimate clients already use. Before applying, `grep -rn "sls_is_safe_name" src/` and
confirm the characters you add are not part of any documented/used streamid. If any added
character is plausibly in legitimate use, STOP and report rather than risk locking out
existing streams. A safer alternative if uncertain: leave `sls_is_safe_name` as-is and
instead URL-encode `m_stream_name` at the two `SLSPullerManager` concatenation sites
(`:78` and the `set_relay_param` site) — but that requires confirming the upstream SRT URL
parser's decoding behavior.

**Test**: add to `tests/test_sls_sid.cpp` — a name containing `?` / `=` is rejected by
`sls_is_safe_name`; a normal alphanumeric/`._-` name is accepted.

**Verify**: `cmake --build build -j && ctest --test-dir build --output-on-failure` → pass;
existing streamid validation tests from plan 001 still pass.

---

## Step 8 (optional hardening): circuit-breaker for auth-backend outages

**Risk: MED.** **Confidence: HIGH that current behavior is fail-open; this behavior is a
DOCUMENTED tradeoff.**

On publisher-auth transport failure or 5xx, the code deliberately does **not** negative-
cache (so a backend hiccup doesn't lock out legitimate publishers) — see the comment at
`src/core/SLSRole.cpp:758-766`. The cost is unbounded accept+reject+webhook amplification
while the backend is unhealthy.

**Before implementing, confirm with the operator that fail-open is not desired.** If they
confirm the current fail-open is intentional (likely, given the documented comment), mark
this step REJECTED in your report and skip it. If they want a brake:

Fix sketch (only if requested): add a per-listener short-TTL accept rate cap that engages
after N consecutive transport-failure/5xx responses within a window, bounding retries to a
few per second until the backend recovers. Keep the per-key fail-open semantics; throttle
at the listener level. This is a larger change — if pursued, write it as its own plan.

**Verify**: n/a unless implemented.

---

## Test plan

- New tests in `tests/test_sls_sid.cpp` (canonical key, tightened safe-name, oversized SPS
  if a reachable entry point exists) and `tests/test_auth_reject_cache.cpp` (canonical key
  collision). Model after the harness from plan 001.
- `ctest --test-dir build --output-on-failure` → all pass including the new cases.

## Done criteria

ALL must hold:

- [ ] `cmake --build build -j` exits 0 (and the ASan build for Step 1 is clean)
- [ ] `grep -n "key == auth_header" src/srt-live-server.cpp` → no matches
- [ ] All four SPS/PPS copy sites in `common.cpp` are length-guarded (no raw `memcpy(ti->sps, p, ti->sps_len)` without a bound)
- [ ] All three malformed-response early returns in `SLSListenerAuth.cpp::process_player_key_response` call `cache_negative()` first
- [ ] `strdup(sid)` result is null-checked in `SLSListenerHandler.cpp`
- [ ] Auth-reject cache reads and writes use a canonical key
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] `git status` shows only in-scope files modified
- [ ] `plans/README.md` status row for 002 updated; Step 8 marked done/rejected with reason

## STOP conditions

- Step 1: no non-static entry point reaches `sls_parse_spspps` and the ASan build can't be
  used — apply the clamp anyway (it's correct) but report the missing test coverage.
- Step 7: any character you would add to `sls_is_safe_name` is plausibly in legitimate
  streamid use — STOP, do not risk locking out streams; report for an operator decision.
- Step 8: do not implement without explicit operator confirmation that fail-open should change.
- Any step's verification fails twice after a reasonable fix attempt.
- A fix appears to require touching an out-of-scope file.

## Maintenance notes

- Step 1's clamp uses `sizeof(ti->sps/pps)`; if those buffers are ever resized, the clamp
  follows automatically — keep it `sizeof`-based.
- Step 6's canonical key must stay in sync with how the webhook resolves the stream and how
  `sls_validate_sid_format` parses; if the streamid grammar changes, revisit both.
- Reviewer should scrutinize Step 7 hardest (it gates all streamids) and Step 3 (verify the
  helper has no early-out).
