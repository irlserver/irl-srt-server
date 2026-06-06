# Bitrate Limiting

Configurable maximum input bitrate limiting for SRT streams with automatic disconnection for sustained violations.

## Overview

The bitrate limiter uses a 5-second sliding window to calculate average bitrate. When the average exceeds the configured limit (adjusted by spike tolerance), a violation timer starts. If the violation is sustained for the configured timeout, the stream is disconnected.

## Key Features

- **Sliding Window Averaging**: 5-second sliding window for stable bitrate measurement
- **Configurable Spike Tolerance**: Controls how much over the limit is allowed before violations start (default: 1.2x)
- **Per-Stream Limiting**: Each publisher stream gets its own independent limiter
- **Configurable Timeout**: How long a violation must be sustained before disconnect (default: 30s)
- **Violation Tracking**: Monitors violation duration and logs detailed information

## Configuration

Add the following to your app section in `sls.conf`:

```
app {
    app_player live;
    app_publisher live;

    # Bitrate limiting for IRL streams
    max_input_bitrate_kbps 15000;              # 15 Mbps limit
    max_input_bitrate_violation_timeout 30;    # disconnect after 30s sustained violation
    max_input_bitrate_spike_tolerance 120;     # 1.2x tolerance (triggers at 18 Mbps)
}
```

### Configuration Options

- `max_input_bitrate_kbps`: Maximum average bitrate in kilobits per second
  - `0`: Unlimited (default)
  - `> 0`: Specific limit in kbps
  - Example: `15000` = 15 Mbps limit

- `max_input_bitrate_violation_timeout`: Seconds of sustained violation before disconnect
  - Range: `1-300` seconds
  - Default: `30` seconds

- `max_input_bitrate_spike_tolerance`: Spike tolerance as a percentage
  - `100`: No tolerance — configured limit is exact ceiling
  - `120`: 1.2x tolerance (default) — 15 Mbps limit triggers violations at 18 Mbps
  - `150`: 1.5x tolerance — 15 Mbps limit triggers violations at 22.5 Mbps
  - `200`: 2x tolerance — 15 Mbps limit triggers violations at 30 Mbps
  - Range: `100-500`

## How It Works

1. **Sliding Window**: Maintains a 5-second sliding window of received data
2. **Average Calculation**: Computes average bitrate over the window
3. **Spike Check**: Compares average against `limit * spike_tolerance`
4. **Violation Tracking**: If over the spike threshold, violation timer starts
5. **Reset on Recovery**: If bitrate drops below threshold, violation timer resets
6. **Disconnect**: After sustained violation exceeds timeout, stream is disconnected

## Example Scenarios

### IRL Streaming (recommended config)
- Config: `max_input_bitrate_kbps 15000`, spike_tolerance 120, timeout 30s
- Stream at 12 Mbps → OK
- VBR spike to 17 Mbps → OK (under 18 Mbps threshold)
- Sustained 20 Mbps for 30s → Disconnected
- Stream at 19 Mbps for 10s, drops to 14 Mbps → Violation resets, no disconnect

### Strict Limiting
- Config: `max_input_bitrate_kbps 20000`, spike_tolerance 100, timeout 10s
- Stream at 20 Mbps → OK (at limit, not over)
- Stream at 21 Mbps sustained for 10s → Disconnected (no tolerance)

### Generous Limiting
- Config: `max_input_bitrate_kbps 10000`, spike_tolerance 150, timeout 60s
- Effective threshold: 15 Mbps
- Stream must sustain above 15 Mbps for a full minute before disconnect

## Monitoring and Logging

### Log Messages

```
[INFO] CSLSRole::init_bitrate_limiter, initialized with max_bitrate=15000kbps, violation_timeout=30s, spike_tolerance=1.20
[WARN] CSLSBitrateLimit::check_data_bitrate, bitrate violation started. Current bitrate: 19000kbps, spike limit: 18000kbps, max: 15000kbps
[WARN] CSLSBitrateLimit::check_data_bitrate, sustained violation for 15000ms. Current bitrate: 20000kbps, limit: 18000kbps
[ERROR] CSLSBitrateLimit::check_data_bitrate, disconnecting stream due to sustained bitrate violation. Duration: 30000ms
[INFO] CSLSBitrateLimit::check_data_bitrate, bitrate violation ended after 8000ms. Current bitrate: 12000kbps
```

## Tuning Guide

| Use Case | Limit | Spike Tolerance | Timeout | Notes |
|----------|-------|----------------|---------|-------|
| IRL bonded cellular | 12000-15000 | 120 | 30 | Most IRL streams are 4-12 Mbps |
| Studio/home via SRTLA | 20000-25000 | 120 | 30 | Stable connections, higher quality |
| Strict server protection | any | 100 | 10 | No tolerance, fast disconnect |
| Lenient/shared server | any | 150 | 60 | Generous tolerance for variable content |

## Limitations

1. **Stream Disconnection**: Streams are disconnected entirely, not throttled
2. **Per-Stream Only**: Limits apply per publisher, not globally
3. **SRT-Specific**: Currently integrated only with SRT data flow
4. **No Encoder Feedback**: SRT Live mode does not signal the encoder to reduce bitrate; the encoder must have its own dynamic bitrate feature (e.g., OBS "Dynamic Bitrate") to react to disconnections
