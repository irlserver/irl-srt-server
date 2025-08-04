# Maximum Average Input Bitrate Limiting

This feature implements configurable maximum average input bitrate limiting for SRT streams with automatic stream disconnection for sustained violations.

## Overview

The bitrate limiting feature allows you to set a maximum average input bitrate per stream. When streams exceed the limit for a sustained period (10 seconds), they are automatically disconnected. This helps prevent streams from consuming excessive bandwidth while allowing temporary spikes for variable bitrate content.

## Key Features

- **Sliding Window Averaging**: Uses a 5-second sliding window to calculate average bitrate
- **Spike Tolerance**: Allows temporary spikes up to 2x the configured limit for short periods
- **Per-Stream Limiting**: Each publisher stream can have its own bitrate limit
- **Automatic Disconnection**: Disconnects streams after 10 seconds of sustained violations
- **Violation Tracking**: Monitors violation duration and logs detailed information
- **Statistics**: Tracks total bytes received, violation status, and current bitrate

## Configuration

Add the following configuration option to your app section in `sls.conf`:

```
app {
    app_player live;
    app_publisher live;
    
    # Maximum input bitrate per stream in kilobits per second (0 = unlimited)
    # Stream will be disconnected after 10 seconds of sustained violations
    max_input_bitrate_kbps 20000; # 20 Mbps limit
    
    # ... other app configurations
}
```

### Configuration Options

- `max_input_bitrate_kbps`: Maximum average bitrate in kilobits per second
  - `0`: Unlimited (default)
  - `> 0`: Specific limit in kbps
  - Example: `20000` = 20 Mbps limit

## How It Works

1. **Sliding Window**: Maintains a 5-second sliding window of received data
2. **Spike Detection**: Allows bursts up to 2x the configured limit for short periods
3. **Violation Tracking**: Monitors when streams exceed the spike limit continuously
4. **Automatic Disconnection**: Disconnects streams after 10 seconds of sustained violations

## Example Scenarios

### Scenario 1: Normal Operation
- Configured limit: 20000 kbps (20 Mbps)
- Stream sends steady 15000 kbps → Stream continues normally
- Brief spike to 35000 kbps → Spike allowed due to 2x tolerance (40 Mbps)
- Extended period at 35000 kbps → Stream disconnected after 10 seconds

### Scenario 2: Variable Bitrate Content
- Configured limit: 10000 kbps (10 Mbps)
- Scene with low motion: 5000 kbps → Stream continues normally
- Action scene spike: 18000 kbps → Allowed temporarily (under 20 Mbps spike limit)
- Sustained high action: 25000 kbps → Stream disconnected after 10 seconds

## Implementation Details

### Core Components

1. **CSLSBitrateLimit**: Main bitrate limiting class
   - Implements sliding window algorithm
   - Handles spike tolerance logic
   - Provides statistics and monitoring

2. **SLSRole Integration**: Base role class enhanced with:
   - Bitrate limiter initialization
   - Data filtering in `handler_read_data()`
   - Statistics collection

3. **SLSPublisher Enhancement**: Publisher class updated to:
   - Initialize bitrate limiter from configuration
   - Apply limits to incoming SRT data

### Configuration Flow

1. Configuration parsed from `sls.conf`
2. Publisher initializes with `max_input_bitrate_kbps` setting
3. Bitrate limiter created if limit > 0
4. Each data packet checked against limiter before processing

### Data Flow

```
SRT Data → handler_read_data() → check_data_bitrate() → OK/Violation/Disconnect
                                      ↓                        ↓
                              Update sliding window    → Stream Disconnect
                              Track violations              (invalid_srt())
                              Calculate current bitrate
                              Apply spike tolerance
```

## Monitoring and Logging

### Log Messages

The system logs the following events:

```
[INFO] CSLSBitrateLimit::init, initialized with max_bitrate=20000kbps, window=5000ms, spike_tolerance=2.00
[WARN] CSLSBitrateLimit::check_data_bitrate, bitrate violation started. Current bitrate: 35000kbps, spike limit: 40000kbps, max: 20000kbps
[WARN] CSLSBitrateLimit::check_data_bitrate, sustained violation for 8000ms. Current bitrate: 38000kbps, limit: 40000kbps
[ERROR] CSLSBitrateLimit::check_data_bitrate, disconnecting stream due to sustained bitrate violation. Duration: 10000ms, current bitrate: 37000kbps, limit: 40000kbps
[INFO] CSLSBitrateLimit::check_data_bitrate, bitrate violation ended after 3000ms. Current bitrate: 15000kbps
```

### Statistics Available

- Total bytes received
- Current bitrate (kbps)
- Whether limiting is currently active
- Whether stream is currently in violation
- Current violation duration (if applicable)

## Performance Considerations

- **Memory Usage**: ~40 bytes per data point in sliding window (minimal overhead)
- **CPU Impact**: Constant time operations for most checks
- **Cleanup**: Automatic cleanup of old data points every second

## Tuning Parameters

The implementation uses sensible defaults that work well for most scenarios:

- **Window Size**: 5 seconds (good balance of responsiveness vs. stability)
- **Spike Tolerance**: 2.0x (allows reasonable bursts)
- **Cleanup Interval**: 1 second (efficient without being wasteful)

These parameters are hardcoded but could be made configurable if needed.

## Limitations

1. **Stream Disconnection**: Streams are disconnected entirely, not throttled
2. **Fixed Thresholds**: 10-second violation period and 2x spike tolerance are hardcoded
3. **Per-Stream Only**: Limits apply per publisher, not globally
4. **SRT-Specific**: Currently integrated only with SRT data flow

## Future Enhancements

Potential improvements for future versions:

- Global bandwidth limits across all streams
- Configurable violation threshold and spike tolerance
- Throttling/rate limiting instead of disconnection
- Warning notifications before disconnection
- Integration with adaptive bitrate streaming
- Quality-based violation handling (consider stream importance)