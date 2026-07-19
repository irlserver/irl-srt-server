#!/usr/bin/env bash
# Unattended /stats scraper for irl-srt-server jump/replay diagnosis.
#
# Polls the stats API on an interval and appends one CSV row per stream per
# tick, so you never have to watch live. When a streamer reports a jump at
# 19:11, open the CSV and read that stream's rows around 19:11.
#
# It also prints a stderr WARN line the moment any stream crosses a backlog or
# backpressure threshold, so `docker logs`/journal shows the interesting moments
# without you tailing anything.
#
# Survives publisher reconnects by design: the ring-side gauges reset when a
# streamer's encoder reconnects, but this scraper has already captured the
# pre-reset rows with timestamps, so the history is on disk regardless.
#
# Usage:
#   ./sls-diag-scrape.sh                 # defaults: localhost:8181, 5s, ./sls-diag.csv
#   STATS_URL=http://127.0.0.1:8181/stats INTERVAL=5 OUT=/var/log/sls-diag.csv ./sls-diag-scrape.sh
#
# Requires: curl, jq.

set -euo pipefail

STATS_URL="${STATS_URL:-http://127.0.0.1:8181/stats}"
INTERVAL="${INTERVAL:-5}"
OUT="${OUT:-./sls-diag.csv}"
# Alert thresholds. backlog in ms of playout; backpressure/overrun are deltas
# per tick (counter differences between two polls).
BACKLOG_MS_WARN="${BACKLOG_MS_WARN:-750}"
BACKPRESSURE_WARN="${BACKPRESSURE_WARN:-1}"
# Sender-side TLPKTDROP toward viewers per tick: each dropped packet is a
# small skip-forward some viewer saw. Non-zero with pktRcvDrop=0 means the
# jump happened viewer-side, not at ingest.
SNDDROP_WARN="${SNDDROP_WARN:-1}"

if ! command -v jq >/dev/null; then echo "need jq" >&2; exit 1; fi

# clear=1 so each poll returns per-interval peaks/deltas rather than lifetime
# totals. Do NOT run two clearing scrapers at once or they steal each other's
# deltas.
sep='?'; case "$STATS_URL" in *\?*) sep='&';; esac
POLL_URL="${STATS_URL}${sep}reset=1"

if [ ! -f "$OUT" ]; then
  echo "ts,stream,bitrateKbps,maxReaderBacklogMs,maxReaderBacklogBytes,sendBackpressure,ringOverruns,pktRcvDrop,viewerPktSndDrop,msRcvBuf,rtt,uptime" > "$OUT"
fi

echo "scraping $POLL_URL every ${INTERVAL}s -> $OUT (backlog warn >${BACKLOG_MS_WARN}ms)" >&2

while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  body="$(curl -fsS --max-time 4 "$POLL_URL" 2>/dev/null || true)"
  if [ -n "$body" ]; then
    # Flatten publishers{} into CSV rows. Field names match SLSManager.cpp.
    echo "$body" | jq -r --arg ts "$ts" '
      (.publishers // {}) | to_entries[] |
      [ $ts, .key,
        (.value.bitrate // 0),
        (.value.maxReaderBacklogMs // 0),
        (.value.maxReaderBacklogBytes // 0),
        (.value.sendBackpressure // 0),
        (.value.ringOverruns // 0),
        (.value.pktRcvDrop // 0),
        (.value.viewerPktSndDrop // 0),
        (.value.msRcvBuf // 0),
        (.value.rtt // 0),
        (.value.uptime // 0) ] | @csv' >> "$OUT" 2>/dev/null || true

    # Stderr alerts on threshold crossings (shows up in docker/journal logs).
    echo "$body" | jq -r --arg ts "$ts" --argjson bl "$BACKLOG_MS_WARN" --argjson bp "$BACKPRESSURE_WARN" --argjson sd "$SNDDROP_WARN" '
      (.publishers // {}) | to_entries[] |
      select((.value.maxReaderBacklogMs // 0) >= $bl or (.value.sendBackpressure // 0) >= $bp or (.value.viewerPktSndDrop // 0) >= $sd) |
      "[\($ts)] SLS-DIAG WARN stream=\(.key) backlogMs=\(.value.maxReaderBacklogMs // 0) backpressure=\(.value.sendBackpressure // 0) overruns=\(.value.ringOverruns // 0) pktRcvDrop=\(.value.pktRcvDrop // 0) viewerSndDrop=\(.value.viewerPktSndDrop // 0)"' >&2 2>/dev/null || true
  fi
  sleep "$INTERVAL"
done
