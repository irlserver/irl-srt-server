#!/usr/bin/env bash
# Publisher-reconnect replay regression test, driven against a real running
# srt_server with one player that SURVIVES a publisher restart.
#
# Guards the stale-ring-reader bug class: the fork keeps player roles alive
# across a publisher reconnect, but the per-stream ring is deleted and
# recreated with the publisher. A surviving reader whose anchor is not
# invalidated (generation check in CSLSRecycleArray::get) would drain the
# recycled buffer's previous-session bytes — the viewer sees a multi-second
# REPLAY of content it already watched.
#
# Scenario:
#   1. publisher session A streams a TS whose video DTS starts near 0
#   2. session A is killed; the player rides out the outage
#      (player_idle_streams_timeout > outage) while the server reaps the
#      publisher (peer_idle_timeout) and deletes the ring
#   3. publisher session B streams a TS offset to DTS ~100s (-output_ts_offset)
#      onto the SAME stream key, recreating the ring
#   4. the player's continuous recording is checked with ffprobe:
#        - video DTS must never run backward (tolerance for muxer jitter);
#          replayed session-A bytes after session B began would show as a
#          drop from >=100s back toward 0
#        - DTS must reach session B's offset, proving the surviving player
#          re-anchored on the recreated ring and received live data
#   5. the server log must contain the generation re-anchor line, proving the
#      intended mechanism (not a player reconnect) delivered session B
#
# Binaries are taken from $SRT_SERVER / $SRT_CLIENT (or PATH, or ./build/bin).
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF="$SCRIPT_DIR/sls-reconnect.conf"

find_bin() {
    _name="$1"; _env="$2"
    if [ -n "$_env" ]; then printf '%s\n' "$_env"; return 0; fi
    if [ -x "$REPO_ROOT/build/bin/$_name" ]; then printf '%s\n' "$REPO_ROOT/build/bin/$_name"; return 0; fi
    command -v "$_name" 2>/dev/null && return 0
    return 1
}

SRT_SERVER="$(find_bin srt_server "${SRT_SERVER:-}")" || { echo "FAIL: srt_server not found" >&2; exit 1; }
SRT_CLIENT="$(find_bin srt_client "${SRT_CLIENT:-}")" || { echo "FAIL: srt_client not found" >&2; exit 1; }
command -v ffmpeg  >/dev/null 2>&1 || { echo "FAIL: ffmpeg not found" >&2; exit 1; }
command -v ffprobe >/dev/null 2>&1 || { echo "FAIL: ffprobe not found" >&2; exit 1; }
command -v jq      >/dev/null 2>&1 || { echo "FAIL: jq not found" >&2; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "FAIL: curl not found" >&2; exit 1; }

API_KEY="reconnect-replay-test-key"
HTTP="http://127.0.0.1:8283"
PUB_PORT=5501
PLAY_PORT=5500
STREAM="live/reconn"
PUB_SID="publish/$STREAM"
PLAY_SID="play/$STREAM"
# Session B's DTS offset (seconds). Must be far above session A's duration so
# a backward DTS step is unambiguous.
B_OFFSET=100

WORKDIR="$(mktemp -d)"
IN_A="$WORKDIR/session_a.ts"
IN_B="$WORKDIR/session_b.ts"
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

fail() {
    echo "RECONNECT-REPLAY FAIL: $1" >&2
    [ -f "$SERVER_LOG" ] && { echo "--- server log tail ---" >&2; tail -40 "$SERVER_LOG" >&2; }
    exit 1
}

pub_count() {
    curl -fsS -H "Authorization: $API_KEY" "$HTTP/stats" 2>/dev/null \
        | jq -r '(.publishers // {}) | length' 2>/dev/null || echo ""
}

# Wait until pub_count equals $1, up to $2 seconds. Dies if the server dies.
wait_pub_count() {
    _want="$1"; _secs="$2"; _i=0
    while [ "$_i" -lt $((_secs * 2)) ]; do
        [ "$(pub_count)" = "$_want" ] && return 0
        kill -0 "$SERVER_PID" 2>/dev/null || fail "srt_server died while waiting for $_want publisher(s)"
        _i=$((_i + 1)); sleep 0.5
    done
    return 1
}

# --- synthesise the two sessions: same encoding, disjoint DTS ranges ---
ffmpeg -nostdin -loglevel error \
    -f lavfi -i "testsrc=duration=30:size=320x240:rate=25" \
    -f lavfi -i "sine=frequency=1000:duration=30" \
    -c:v mpeg2video -b:v 2M -c:a aac -ar 48000 -ac 2 \
    -f mpegts "$IN_A"
ffmpeg -nostdin -loglevel error \
    -f lavfi -i "testsrc=duration=30:size=320x240:rate=25" \
    -f lavfi -i "sine=frequency=2000:duration=30" \
    -c:v mpeg2video -b:v 2M -c:a aac -ar 48000 -ac 2 \
    -output_ts_offset "$B_OFFSET" \
    -f mpegts "$IN_B"
[ -s "$IN_A" ] && [ -s "$IN_B" ] || fail "ffmpeg produced an empty input TS"

# --- start the server ---
"$SRT_SERVER" -c "$CONF" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

up=0; i=0
while [ "$i" -lt 50 ]; do
    if curl -fsS "$HTTP/healthz" >/dev/null 2>&1; then up=1; break; fi
    kill -0 "$SERVER_PID" 2>/dev/null || fail "srt_server exited during startup"
    i=$((i + 1)); sleep 0.2
done
[ "$up" -eq 1 ] || fail "HTTP control plane never came up on $HTTP"

# --- session A + the long-lived player ---
"$SRT_CLIENT" -r "srt://127.0.0.1:${PUB_PORT}?streamid=${PUB_SID}" -i "$IN_A" >/dev/null 2>&1 &
PUB_PID=$!
disown "$PUB_PID" # keep bash job control from reporting the later kill -9
wait_pub_count 1 15 || fail "session A publisher never went live"
"$SRT_CLIENT" -r "srt://127.0.0.1:${PLAY_PORT}?streamid=${PLAY_SID}" -o "$OUT_TS" >/dev/null 2>&1 &
PLAY_PID=$!
disown "$PLAY_PID"

# Let the player collect several seconds of session A.
sleep 6
[ -s "$OUT_TS" ] || fail "player received nothing from session A"

# --- outage: kill session A, wait for the server to reap it (ring deleted) ---
kill -9 "$PUB_PID" 2>/dev/null || true
PUB_PID=""
wait_pub_count 0 20 || fail "session A publisher was never reaped after kill"

# The player must ride out the outage, not be idle-reaped.
kill -0 "$PLAY_PID" 2>/dev/null || fail "player died during the publisher outage"

# --- session B on the same key: fresh ring, surviving reader must re-anchor ---
"$SRT_CLIENT" -r "srt://127.0.0.1:${PUB_PORT}?streamid=${PUB_SID}" -i "$IN_B" >/dev/null 2>&1 &
PUB_PID=$!
disown "$PUB_PID"
wait_pub_count 1 15 || fail "session B publisher never went live"

# Let session B flow to the surviving player.
sleep 8
kill -0 "$PLAY_PID" 2>/dev/null || fail "player died after the publisher returned"

# Stop traffic before inspecting the recording.
kill "$PUB_PID" 2>/dev/null || true; PUB_PID=""
kill "$PLAY_PID" 2>/dev/null || true; PLAY_PID=""
sleep 1

# --- assertions ---

# 1. The intended mechanism fired: the surviving reader was re-anchored on the
#    recreated ring (generation check), not silently drained or reconnected.
grep -q "re-anchoring at live write head" "$SERVER_LOG" \
    || fail "server log has no generation re-anchor line; player did not survive onto the new ring"

# 2. Video DTS in the player's continuous recording must never run backward.
#    0.5s tolerance absorbs muxer jitter; a replay of session-A bytes after
#    session B began is a drop of ~100s and is unmistakable.
dts_check="$(ffprobe -loglevel error -select_streams v:0 \
        -show_entries packet=dts_time -of csv=p=0 "$OUT_TS" 2>/dev/null \
    | awk -F, '
        $1 == "" || $1 == "N/A" { next }
        { if (max != "" && $1 < max - 0.5) { printf "BACKWARD %.3f after %.3f\n", $1, max; exit 1 }
          if (max == "" || $1 > max) max = $1 }
        END { if (max == "") { print "EMPTY"; exit 1 }; printf "MAX %.3f\n", max }')" \
    || fail "replayed content detected in player recording: $dts_check"

# 3. Session B actually reached the surviving player: max DTS must be in B's
#    offset range. This is what proves re-anchor delivered live data (and,
#    together with check 2, that ONLY live data was delivered).
max_dts="$(printf '%s\n' "$dts_check" | awk '/^MAX/ { print $2 }')"
awk -v m="$max_dts" -v off="$B_OFFSET" 'BEGIN { exit !(m >= off) }' \
    || fail "player never received session B content (max video DTS ${max_dts}s < ${B_OFFSET}s)"

echo "RECONNECT-REPLAY PASS: player survived the publisher restart, re-anchored, and received only forward-moving content (max video DTS ${max_dts}s)."
