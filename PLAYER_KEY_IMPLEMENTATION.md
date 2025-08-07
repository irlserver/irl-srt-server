# Player Key Authentication Implementation

## Overview

This implementation introduces separate player keys for the SRT Live Server using the configured stream ID format (`domain_player/app_player/playerkey`), allowing you to control access to streams using player-specific keys that are validated through an API endpoint.

## Features

### 1. Configuration Option
- **New configuration**: `player_key_auth_url`
- **Purpose**: Specifies the API endpoint to validate player keys
- **Format**: HTTP URL that accepts GET requests with `player_key` parameter

### 2. Configured Stream ID Format
Player connections use the configured domain and app names from the SLS configuration:

```
srt://host:port?streamid=<domain_player>/<app_player>/playerkey
```

When player key authentication is enabled:
- `domain_player` = configured domain for players (e.g., "play")
- `app_player` = configured application name for players (e.g., "live")
- `playerkey` = the player key to validate

### 3. API Integration
When a player connects with format `<domain_player>/<app_player>/playerkey`, the server makes an HTTP GET request to:
```
<player_key_auth_url>?player_key=playerkey
```

Expected API response (JSON only):
- **JSON format**: `{"stream_id": "publish/live/actualstream"}`
- **HTTP 200**: Player key is valid, connect to the returned stream ID
- **Non-200 status**: Player key is invalid, reject connection

## Configuration Example

```conf
server {
    listen_player 4000;
    listen_publisher 4001;
    
    domain_player play;
    domain_publisher publish;
    
    # Enable player key authentication
    player_key_auth_url http://127.0.0.1:8000/sls/validate_player_key;
    player_key_auth_timeout 2000;         # HTTP timeout in milliseconds
    player_key_cache_duration 60000;      # Cache duration in milliseconds
    
    # Security features
    player_key_rate_limit_requests -1;    # No rate limiting by default (-1 = unlimited)
    player_key_rate_limit_window 60000;   # Rate limit window in milliseconds
    player_key_min_length 8;              # Minimum player key length
    player_key_max_length 64;             # Maximum player key length
    
    app {
        app_player live;
        app_publisher live;
        allow publish all;
        allow play all;
    }
}
```

## Usage Examples

### Publisher Connection (unchanged)
```bash
ffmpeg -f ... -c ... "srt://host:4001?streamid=publish/live/mystream"
```

### Player Connection with Player Key
```bash
ffplay "srt://host:4000?streamid=play/live/abc123"
```

In this example:
- The player provides stream ID `play/live/abc123` (using configured `domain_player=play` and `app_player=live`)
- Server extracts player key `abc123` from the stream ID
- Server calls: `http://127.0.0.1:8000/sls/validate_player_key?player_key=abc123`
- API returns: `{"stream_id": "publish/live/mystream"}`
- Player is connected to the actual stream `mystream`

## Implementation Details

### Files Modified

1. **src/core/SLSListener.hpp**
   - Added `player_key_auth_url` configuration parameter
   - Added `m_player_key_auth_url` member variable
   - Added `validate_player_key()` method declaration
   - Added member variables for storing configured domains and apps

2. **src/core/SLSListener.cpp**
   - Added `#include <nlohmann/json.hpp>` for JSON parsing
   - Implemented `validate_player_key()` method with HTTP client and JSON parsing
   - Added stream ID parsing using configured `domain_player` and `app_player` values
   - Store configuration values in member variables during initialization
   - Integrated player key validation into connection handling

3. **src/sls.conf**
   - Added configuration examples showing usage with configured values
   - Updated documentation for JSON-only API responses

### Key Implementation Features

1. **Uses Configuration**: Respects configured `domain_player` and `app_player` values
2. **Multiple Domains/Apps**: Supports multiple configured player domains and apps
3. **JSON Only**: API responses must be valid JSON with `stream_id` field
4. **Backward Compatibility**: Only applies to configured player formats when auth URL is configured
5. **Stream ID Replacement**: Validated stream ID replaces the original for processing
6. **Robust JSON Parsing**: Uses nlohmann/json library with proper error handling

## Performance Optimizations

### 1. Non-Blocking HTTP Requests
The implementation uses non-blocking HTTP requests with configurable timeouts to prevent blocking the listener thread:

- **Timeout Control**: Configurable `player_key_auth_timeout` (default: 2000ms)
- **Non-Blocking Loop**: Uses polling with microsecond sleeps to avoid busy waiting
- **Graceful Timeouts**: Proper cleanup on timeout with detailed error logging

### 2. Player Key Caching
To reduce API calls and improve responsiveness, the server caches successful validations:

- **Configurable Duration**: `player_key_cache_duration` (default: 60000ms)
- **Automatic Expiry**: Cache entries automatically expire after the configured duration
- **Cache Cleanup**: Expired entries are removed when accessed
- **Memory Efficient**: Uses STL map for fast lookups and automatic memory management
- **Negative Caching**: Failed validations are cached briefly to prevent repeated API abuse

### 3. Configuration Options
New configuration parameters for performance tuning:

```conf
player_key_auth_timeout 2000;         # HTTP timeout in milliseconds
player_key_cache_duration 60000;      # Cache duration in milliseconds
```

**Recommended Settings by Use Case:**

**Standard Server** (Default - no rate limiting):
```conf
player_key_rate_limit_requests -1;    # Unlimited (default)
player_key_min_length 8;
player_key_max_length 64;
```

**High-Security Server** (Enable strict rate limiting):
```conf
player_key_rate_limit_requests 5;     # Enable strict rate limiting
player_key_min_length 12;
player_key_max_length 32;
```

**Low-Latency Server** (Moderate rate limiting):
```conf
player_key_rate_limit_requests 15;    # Enable moderate rate limiting
player_key_min_length 6;
player_key_max_length 32;
```

## Security Features

### 1. Rate Limiting per IP Address
Prevents abuse by limiting validation requests per IP address:

- **Configurable Limits**: `player_key_rate_limit_requests` (default: -1, unlimited)
- **Sliding Window**: `player_key_rate_limit_window` (default: 60000ms)
- **Automatic Cleanup**: Expired rate limit entries are automatically removed
- **Per-IP Tracking**: Each client IP is tracked independently
- **Disabled by Default**: Set to -1 for unlimited requests (default behavior)

**Configuration:**
```conf
player_key_rate_limit_requests -1;    # -1 = unlimited (default), >0 = max requests per window
player_key_rate_limit_window 60000;   # Rate limit window in milliseconds
```

**To enable rate limiting:**
```conf
player_key_rate_limit_requests 10;    # Enable: max 10 requests per IP per window
player_key_rate_limit_window 60000;   # 60 second window
```

### 2. Player Key Format Validation
Input validation ensures player keys meet security requirements:

- **Length Constraints**: Configurable minimum and maximum length
- **Character Validation**: Regex-based format validation
- **Fast Rejection**: Invalid formats are rejected before API calls
- **Secure Defaults**: Alphanumeric, hyphens, and underscores only

**Configuration:**
```conf
player_key_min_length 8;              # Minimum player key length
player_key_max_length 64;             # Maximum player key length
# Valid pattern: ^[a-zA-Z0-9_-]{min,max}$
```

### 3. Negative Caching
Failed validations are cached to prevent repeated API abuse:

- **Shorter Duration**: Failed keys cached for 1/4 of normal cache time
- **Prevents Brute Force**: Reduces load on authentication API
- **Automatic Expiry**: Expired negative entries are cleaned up
- **Security Logging**: Failed attempts are logged for monitoring

### 4. Multi-Layer Security
The implementation provides defense in depth:

1. **Format Validation** - Fast client-side checks
2. **Rate Limiting** - Per-IP request throttling  
3. **Negative Caching** - Prevents repeated invalid attempts
4. **Timeout Protection** - Prevents hanging connections
5. **Comprehensive Logging** - Security event monitoring

**Security Event Logging:**
- Invalid format attempts
- Rate limit violations
- Failed authentication attempts
- Timeout events
- Cache hits/misses

## Stream ID Flow

1. **Player connects**: `srt://host:4000?streamid=play/live/playerkey123`
2. **Server detects**: Configured format with matching `domain_player` and `app_player`
3. **Extract key**: `playerkey123` from the third part
4. **API call**: `GET /validate_player_key?player_key=playerkey123`
5. **API response**: `{"stream_id": "publish/live/actualstream"}`
6. **Stream replacement**: Original `play/live/playerkey123` becomes `publish/live/actualstream`
7. **Normal processing**: Continue with standard SRT Live Server logic

## Configuration Flexibility

The implementation works with any configured domain and app names:

```conf
# Example 1: Standard configuration
domain_player play;
app_player live;
# Player connects: srt://host:port?streamid=play/live/playerkey

# Example 2: Custom configuration  
domain_player viewer;
app_player stream;
# Player connects: srt://host:port?streamid=viewer/stream/playerkey

# Example 3: Multiple domains
domain_player "play watch";
app_player live;
# Player can connect with either:
# srt://host:port?streamid=play/live/playerkey
# srt://host:port?streamid=watch/live/playerkey
```

## API Endpoint Implementation Example

Here's a simple Python Flask API endpoint example:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database of player keys -> stream mappings
PLAYER_KEYS = {
    "abc123": "publish/live/stream1",
    "def456": "publish/live/stream2", 
    "xyz789": "publish/live/stream3"
}

@app.route('/sls/validate_player_key')
def validate_player_key():
    player_key = request.args.get('player_key')
    
    if not player_key:
        return jsonify({"error": "Missing player_key parameter"}), 400
    
    if player_key in PLAYER_KEYS:
        stream_id = PLAYER_KEYS[player_key]
        return jsonify({"stream_id": stream_id})
    else:
        return jsonify({"error": "Invalid player key"}), 403

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
```

## Error Handling

The implementation includes comprehensive error handling:

1. **Invalid JSON**: If API response is not valid JSON, connection is rejected
2. **Missing stream_id**: If JSON doesn't contain `stream_id` field, connection is rejected
3. **Non-string stream_id**: If `stream_id` field is not a string, connection is rejected
4. **Invalid Player Key**: If API returns non-200 status, connection is rejected
5. **API Unavailable**: If HTTP request fails, connection is rejected
6. **Network Timeouts**: Built-in timeout handling via existing HTTP client
7. **HTTP Request Timeout**: Configurable timeout prevents blocking listener thread
8. **Cache Management**: Automatic cleanup of expired cache entries
9. **Invalid Key Format**: Player keys that don't match regex pattern are rejected
10. **Rate Limiting**: Excessive requests from same IP are rejected
11. **Length Validation**: Keys outside configured length range are rejected
12. **Negative Cache Hits**: Previously failed keys are rejected from cache

## Testing

To test the implementation:

1. Set up an API endpoint that responds to player key validation requests
2. Configure `player_key_auth_url` in your server configuration
3. Test publisher connections: `srt://host:port?streamid=publish/live/test` (should work unchanged)
4. Test player connections with valid keys: `srt://host:port?streamid=play/live/validkey` (should work)
5. Test player connections with invalid keys: `srt://host:port?streamid=play/live/invalidkey` (should be rejected)
6. Test normal player connections: `srt://host:port?streamid=play/live/normalstream` (should work if no auth URL configured)

## Benefits

1. **Simple Format**: Uses standard SRT stream ID format, no complex parameters
2. **Clean Integration**: Player key is naturally part of the stream identifier
3. **Dynamic Mapping**: Player keys can map to any actual stream via API
4. **Secure**: Invalid keys are rejected at connection time
5. **Flexible**: API can implement any authentication/authorization logic
6. **JSON Standard**: Uses industry-standard JSON for API responses