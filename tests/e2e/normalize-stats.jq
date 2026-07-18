# Reduce a /stats (or control) JSON response to its STRUCTURAL SHAPE only, so a
# committed golden snapshot locks the SET and NESTING of keys without pinning any
# volatile runtime value. This is the lock for the "must not change the
# stats/control API shape" constraint (todo 37): adding, removing, or renaming a
# key changes this output; changing a counter/rate/timestamp does NOT.
#
# Redactions, and WHY each redacted field is volatile (must not be asserted):
#   number  -> "<number>" : every counter/rate/gauge is run-dependent —
#       pktRcvLoss, pktRcvDrop, bytesRcvLoss, bytesRcvDrop, mbpsRecvRate, rtt,
#       msRcvBuf, mbpsBandwidth, bitrate, uptime, latency, ringOverruns,
#       sendBackpressure, and the reader-backlog gauges.
#   boolean -> "<bool>"   : config/timing-dependent, so only PRESENCE is part
#       of the contract.
#   string  -> "<string>" : status text and any string value is content, not
#       shape.
#   dynamic publisher map key (the live stream id, e.g. "publish/live/abc123")
#       -> collapsed to ONE representative entry under the fixed key
#       "<STREAM_ID>", so the snapshot never depends on the stream name and a
#       single live publisher is enough to lock the per-publisher object.
#   arrays  -> at most ONE normalized element, so the element shape is locked
#       without depending on the live element count.
# Object KEYS are preserved verbatim: they ARE the shape under test.

def shape:
  if type == "object" then
    (to_entries | map(.value |= shape) | from_entries)
  elif type == "array" then
    (if length == 0 then [] else [(.[0] | shape)] end)
  elif type == "number" then "<number>"
  elif type == "boolean" then "<bool>"
  elif type == "string" then "<string>"
  else .
  end;

# Collapse the dynamic publisher map to one placeholder-keyed entry BEFORE
# shape-normalizing, so the live stream id never leaks into the fixture. Leaves
# responses with no "publishers" object (e.g. /healthz, error bodies) untouched.
(if (.publishers? | type) == "object" and (.publishers | length) > 0
 then .publishers = {"<STREAM_ID>": (.publishers | to_entries | .[0].value)}
 else . end)
| shape
