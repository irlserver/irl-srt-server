# Player Key Authentication Implementation

## Overview

This implementation introduces separate player keys for the SRT Live Server using the traditional stream ID format (`play/live/playerkey`), allowing you to control access to streams using player-specific keys that are validated through an API endpoint.

## Features

### 1. Configuration Option
- **New configuration**: `player_key_auth_url`
- **Purpose**: Specifies the API endpoint to validate player keys
- **Format**: HTTP URL that accepts GET requests with `player_key` parameter

### 2. Traditional Stream ID Format
Player connections use the standard SRT stream ID format where the stream name is the player key:

```
srt://host:port?streamid=play/live/playerkey
```

When player key authentication is enabled:
- `play` = domain (indicates player connection)
- `live` = application name
- `playerkey` = the player key to validate

### 3. API Integration
When a player connects with format `play/live/playerkey`, the server makes an HTTP GET request to:
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
    
    # Enable player key authentication
    player_key_auth_url http://127.0.0.1:8000/sls/validate_player_key;
    
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
- The player provides stream ID `play/live/abc123`
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

2. **src/core/SLSListener.cpp**
   - Added `#include <nlohmann/json.hpp>` for JSON parsing
   - Implemented `validate_player_key()` method with HTTP client and JSON parsing
   - Added traditional stream ID parsing (`play/live/playerkey`)
   - Integrated player key validation into connection handling

3. **src/sls.conf**
   - Added configuration examples with traditional format
   - Updated documentation for JSON-only API responses

### Key Implementation Features

1. **Traditional Format**: Uses standard SRT stream ID format `play/live/playerkey`
2. **JSON Only**: API responses must be valid JSON with `stream_id` field
3. **Backward Compatibility**: Only applies to `play/live/*` format when auth URL is configured
4. **Stream ID Replacement**: Validated stream ID replaces the original for processing
5. **Robust JSON Parsing**: Uses nlohmann/json library with proper error handling

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

## Stream ID Flow

1. **Player connects**: `srt://host:4000?streamid=play/live/playerkey123`
2. **Server detects**: Traditional format with `play` domain
3. **Extract key**: `playerkey123` from the third part
4. **API call**: `GET /validate_player_key?player_key=playerkey123`
5. **API response**: `{"stream_id": "publish/live/actualstream"}`
6. **Stream replacement**: Original `play/live/playerkey123` becomes `publish/live/actualstream`
7. **Normal processing**: Continue with standard SRT Live Server logic

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