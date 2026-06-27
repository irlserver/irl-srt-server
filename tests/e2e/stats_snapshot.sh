#!/usr/bin/env bash
# Golden-shape snapshot of the HTTP control plane (/stats, /healthz,
# /disconnect), driven against a real running srt_server with one live
# publisher + player. Todo 37: this LOCKS the JSON shape of the stats/control
# API — the "must not change the stats/control API shape" constraint — so a
# later change that adds, removes, or renames a key is caught here.
#
# It deliberately asserts ONLY the key/shape structure, never volatile values:
# every response is passed through tests/e2e/normalize-stats.jq, which redacts
# counters/rates/timestamps/ids to type placeholders and collapses the dynamic
# publisher-map key. See that filter for the per-field rationale.
#
# Modes:
#   (default)   VERIFY: re-fetch, re-normalize, diff against the committed
#               tests/fixtures/*-shape.json. Any structural drift fails.
#   --update    BLESS:  write/refresh the fixtures from the live responses.
#
# Binaries are taken from $SRT_SERVER / $SRT_CLIENT (or PATH, or ./build/bin).
# ffmpeg synthesises the TS payload (SLS relays TS opaquely); jq + curl drive
# and normalize. Any failure exits non-zero.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF="$SCRIPT_DIR/sls-stats.conf"
JQ_FILTER="$SCRIPT_DIR/normalize-stats.jq"
FIXTURE_DIR="$REPO_ROOT/tests/fixtures"

UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1

# Binary discovery: env override, then ./build/bin, then PATH.
find_bin() {
    _name="$1"; _env="$2"
    if [ -n "$_env" ]; then printf '%s\n' "$_env"; return 0; fi
    if [ -x "$REPO_ROOT/build/bin/$_name" ]; then printf '%s\n' "$REPO_ROOT/build/bin/$_name"; return 0; fi
    command -v "$_name" 2>/dev/null && return 0
    return 1
}

SRT_SERVER="$(find_bin srt_server "${SRT_SERVER:-}")" || { echo "FAIL: srt_server not found" >&2; exit 1; }
SRT_CLIENT="$(find_bin srt_client "${SRT_CLIENT:-}")" || { echo "FAIL: srt_client not found" >&2; exit 1; }
command -v ffmpeg >/dev/null 2>&1 || { echo "FAIL: ffmpeg not found" >&2; exit 1; }
command -v jq     >/dev/null 2>&1 || { echo "FAIL: jq not found" >&2; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "FAIL: curl not found" >&2; exit 1; }

API_KEY="stats-shape-test-key"
HTTP="http://127.0.0.1:8282"
PUB_PORT=5401
PLAY_PORT=5400
STREAM="live/snap"
PUB_SID="publish/$STREAM"
PLAY_SID="play/$STREAM"

WORKDIR="$(mktemp -d)"
IN_TS="$WORKDIR/in.ts"
OUT_TS="$WORKDIR/out.ts"
SERVER_LOG="$WORKDIR/server.log"
SERVER_PID=""; PUB_PID=""; PLAY_PID=""

cleanup() {
    [ -n "$PLAY_PID" ] && kill "$PLAY_PID" 2>/dev/null || true
    [ -n "$PUB_PID" ] && kill "$PUB_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

fail() { echo "STATS-SNAPSHOT FAIL: $1" >&2; exit 1; }

# Normalize a JSON body to its structural shape (sorted keys for a stable diff).
normalize() { jq -S -f "$JQ_FILTER"; }

# Compare a normalized body against a committed fixture, or write it in --update.
check_or_update() {
    _label="$1"; _fixture="$2"; _body="$3"
    _norm="$(printf '%s' "$_body" | normalize)" || fail "$_label: response is not valid JSON"
    if [ "$UPDATE" -eq 1 ]; then
        printf '%s\n' "$_norm" > "$_fixture"
        echo "UPDATED $_label -> ${_fixture#"$REPO_ROOT"/}"
    else
        [ -f "$_fixture" ] || fail "$_label: fixture missing: ${_fixture#"$REPO_ROOT"/} (run with --update to create)"
        if ! printf '%s\n' "$_norm" | diff -u "$_fixture" - ; then
            fail "$_label: API shape drifted from ${_fixture#"$REPO_ROOT"/} (a key was added/removed/renamed)"
        fi
        echo "OK $_label shape matches ${_fixture#"$REPO_ROOT"/}"
    fi
}

# --- synthesise a TS with BOTH video and an AAC audio track (so the snapshot
#     locks the audioGapFill.tracks[] element shape, not just an empty array) ---
ffmpeg -nostdin -loglevel error \
    -f lavfi -i "testsrc=duration=40:size=320x240:rate=25" \
    -f lavfi -i "sine=frequency=1000:duration=40" \
    -c:v mpeg2video -b:v 2M -c:a aac -ar 48000 -ac 2 \
    -f mpegts "$IN_TS"
[ -s "$IN_TS" ] || fail "ffmpeg produced an empty input TS"

# --- start the server ---
"$SRT_SERVER" -c "$CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# wait for the HTTP control plane to come up (/healthz needs no auth)
up=0
i=0
while [ "$i" -lt 50 ]; do
    if curl -fsS "$HTTP/healthz" >/dev/null 2>&1; then up=1; break; fi
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$SERVER_LOG" >&2; fail "srt_server exited during startup"; }
    i=$((i + 1)); sleep 0.2
done
[ "$up" -eq 1 ] || { cat "$SERVER_LOG" >&2; fail "HTTP control plane never came up on $HTTP"; }

# --- drive one publisher + one player ---
"$SRT_CLIENT" -r "srt://127.0.0.1:${PUB_PORT}?streamid=${PUB_SID}" -i "$IN_TS" >/dev/null 2>&1 &
PUB_PID=$!
sleep 2
"$SRT_CLIENT" -r "srt://127.0.0.1:${PLAY_PORT}?streamid=${PLAY_SID}" -o "$OUT_TS" >/dev/null 2>&1 &
PLAY_PID=$!

# --- poll /stats until the publisher is live AND an audio track was parsed ---
stats=""
ready=0
i=0
while [ "$i" -lt 60 ]; do
    stats="$(curl -fsS -H "Authorization: $API_KEY" "$HTTP/stats" 2>/dev/null || true)"
    if [ -n "$stats" ] && printf '%s' "$stats" | jq -e \
        '((.publishers // {}) | length) > 0 and (([.publishers[]?.audioGapFill.audioTrackCount] | add) // 0) > 0' \
        >/dev/null 2>&1; then
        ready=1; break
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$SERVER_LOG" >&2; fail "srt_server died while streaming"; }
    i=$((i + 1)); sleep 0.5
done
[ "$ready" -eq 1 ] || { echo "--- last /stats ---" >&2; printf '%s\n' "$stats" >&2; fail "no live publisher with an audio track within timeout"; }

# the live publisher-map key (e.g. publish/live/snap); used for the per-publisher path
PUB_KEY="$(printf '%s' "$stats" | jq -r '.publishers | keys[0]')"
[ -n "$PUB_KEY" ] || fail "could not read publisher key from /stats"

# --- capture + lock each control-plane response shape ---

# 1. GET /stats (all publishers) — the headline fixture, full per-publisher shape.
check_or_update "GET /stats" "$FIXTURE_DIR/stats-shape.json" "$stats"

# 2. GET /healthz — liveness probe shape.
healthz="$(curl -fsS "$HTTP/healthz")"
check_or_update "GET /healthz" "$FIXTURE_DIR/healthz-shape.json" "$healthz"

# 3. POST /disconnect with no 'stream' param — 400 error-body shape.
disc_missing="$(curl -s -X POST -H "Authorization: $API_KEY" "$HTTP/disconnect")"
check_or_update "POST /disconnect (missing stream)" "$FIXTURE_DIR/disconnect-shape.json" "$disc_missing"

# 4. GET /stats with no Authorization — 401 error-body shape.
stats_unauth="$(curl -s "$HTTP/stats")"
check_or_update "GET /stats (unauthorized)" "$FIXTURE_DIR/stats-unauthorized-shape.json" "$stats_unauth"

# 5. GET /stats?publisher=<id> — the per-publisher code path must yield the SAME
#    structural shape as the all-publishers path (both wrap one publisher object).
stats_one="$(curl -fsS -H "Authorization: $API_KEY" "$HTTP/stats" --data-urlencode "publisher=$PUB_KEY" -G)"
one_norm="$(printf '%s' "$stats_one" | normalize)" || fail "per-publisher /stats not valid JSON"
all_norm="$(printf '%s' "$stats" | normalize)"
if [ "$one_norm" != "$all_norm" ]; then
    printf '%s\n' "$one_norm" | diff -u <(printf '%s\n' "$all_norm") - || true
    fail "GET /stats?publisher= shape differs from GET /stats shape"
fi
echo "OK GET /stats?publisher= shape matches GET /stats"

if [ "$UPDATE" -eq 1 ]; then
    echo "STATS-SNAPSHOT: fixtures updated."
else
    echo "STATS-SNAPSHOT PASS: control-plane API shape matches all committed fixtures."
fi
