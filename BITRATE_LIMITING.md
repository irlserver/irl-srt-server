# Maximum Average Input Bitrate Limiting

This feature implements configurable maximum average input bitrate limiting for SRT streams with spike tolerance.

## Overview

The bitrate limiting feature allows you to set a maximum average input bitrate per stream while still allowing temporary spikes above the limit. This helps prevent streams from consuming excessive bandwidth while maintaining flexibility for variable bitrate content.

## Key Features

- **Sliding Window Averaging**: Uses a 5-second sliding window to calculate average bitrate
- **Spike Tolerance**: Allows temporary spikes up to 2x the configured limit
- **Per-Stream Limiting**: Each publisher stream can have its own bitrate limit
- **Graceful Degradation**: Drops packets when limits are exceeded, logs violations
- **Statistics**: Tracks total bytes received, dropped, and current bitrate

## Configuration

Add the following configuration option to your app section in `sls.conf`:

```
app {
    app_player live;
    app_publisher live;
    
    # Maximum input bitrate per stream in kilobits per second (0 = unlimited)
    # Allows temporary spikes up to 2x the limit while maintaining average
    max_input_bitrate_kbps 5000; # 5 Mbps limit
    
    # ... other app configurations
}
```

### Configuration Options

- `max_input_bitrate_kbps`: Maximum average bitrate in kilobits per second
  - `0`: Unlimited (default)
  - `> 0`: Specific limit in kbps
  - Example: `5000` = 5 Mbps limit

## How It Works

1. **Sliding Window**: Maintains a 5-second sliding window of received data
2. **Spike Detection**: Allows bursts up to 2x the configured limit for short periods
3. **Average Enforcement**: Ensures the average bitrate over the window stays within limits
4. **Packet Dropping**: When limits are exceeded, new packets are dropped (not queued)

## Example Scenarios

### Scenario 1: Normal Operation
- Configured limit: 1000 kbps (1 Mbps)
- Stream sends steady 800 kbps → All packets allowed
- Brief spike to 1500 kbps → Spike allowed due to tolerance
- Extended period at 1500 kbps → Packets dropped to maintain 1000 kbps average

### Scenario 2: Variable Bitrate Content
- Configured limit: 2000 kbps (2 Mbps)
- Scene with low motion: 500 kbps → All packets allowed
- Action scene spike: 3000 kbps → Allowed temporarily
- Continuous action: 2500 kbps → Some packets dropped to maintain average

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
SRT Data → handler_read_data() → check_data_allowed() → Allow/Drop → Process/Discard
                                      ↓
                              Update sliding window
                              Calculate current bitrate
                              Apply spike tolerance
```

## Monitoring and Logging

### Log Messages

The system logs the following events:

```
[INFO] CSLSBitrateLimit::init, initialized with max_bitrate=5000kbps, window=5000ms, spike_tolerance=2.00
[WARN] CSLSBitrateLimit::check_data_allowed, dropping 1316 bytes. Projected bitrate: 5500kbps, spike limit: 10000kbps, window: 5000ms
```

### Statistics Available

- Total bytes received
- Total bytes dropped
- Current bitrate (kbps)
- Whether limiting is currently active

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

1. **Packet-Level Dropping**: Drops complete packets, not partial data
2. **No Buffering**: Excess data is dropped, not delayed
3. **Per-Stream Only**: Limits apply per publisher, not globally
4. **SRT-Specific**: Currently integrated only with SRT data flow

## Future Enhancements

Potential improvements for future versions:

- Global bandwidth limits across all streams
- Configurable window size and spike tolerance
- Quality-based dropping (drop lower priority data first)
- Rate limiting with queuing instead of dropping
- Integration with adaptive bitrate streaming