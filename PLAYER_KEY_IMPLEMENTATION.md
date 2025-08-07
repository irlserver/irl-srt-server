# Player Key Authentication Implementation

## Overview

This implementation introduces separate player keys for the SRT Live Server, allowing you to control access to streams using player-specific keys that are validated through an API endpoint.

## Features

### 1. Configuration Option
- **New configuration**: `player_key_auth_url`
- **Purpose**: Specifies the API endpoint to validate player keys
- **Format**: HTTP URL that accepts GET requests with `player_key` parameter

### 2. Stream ID Format
Player connections can now include a `player_key` parameter in their stream ID:

```
srt://host:port?streamid=h=<domain>&sls_app=<app>&r=<stream>&player_key=<key>
```

### 3. API Integration
When a player connects with a `player_key`, the server makes an HTTP GET request to:
```
<player_key_auth_url>?player_key=<key>
```

Expected API responses:
- **JSON format**: `{"stream_id": "publish/live/streamname"}`
- **Plain text format**: `publish/live/streamname`
- **HTTP 200**: Player key is valid, use returned stream ID
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
ffmpeg -f ... -c ... "srt://host:4001?streamid=h=publish&sls_app=live&r=mystream"
```

### Player Connection with Player Key
```bash
ffplay "srt://host:4000?streamid=h=play&sls_app=live&r=dummy&player_key=abc123"
```

In this example:
- The player provides `player_key=abc123`
- Server calls: `http://127.0.0.1:8000/sls/validate_player_key?player_key=abc123`
- API might return: `publish/live/mystream`
- Player is connected to the actual stream `mystream` instead of `dummy`

## Implementation Details

### Files Modified

1. **src/core/SLSListener.hpp**
   - Added `player_key_auth_url` configuration parameter
   - Added `m_player_key_auth_url` member variable
   - Added `validate_player_key()` method declaration

2. **src/core/SLSListener.cpp**
   - Implemented `validate_player_key()` method with HTTP client logic
   - Added player key extraction from stream ID
   - Added validation enforcement for player connections
   - Integrated with existing connection handling logic

3. **src/sls.conf**
   - Added configuration examples and documentation
   - Provided usage examples for both server blocks

### Key Implementation Features

1. **Backward Compatibility**: Player key authentication is optional - if `player_key_auth_url` is not configured, the system works exactly as before.

2. **Security**: When player key authentication is enabled, player connections MUST provide a valid `player_key` or they will be rejected.

3. **Flexible API Response**: Supports both JSON and plain text responses from the validation API.

4. **Integration with Existing Webhooks**: Uses the same HTTP client infrastructure as the existing `on_event_url` feature.

5. **Comprehensive Logging**: Detailed logging for authentication attempts, successes, and failures.

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
        return "Missing player_key parameter", 400
    
    if player_key in PLAYER_KEYS:
        stream_id = PLAYER_KEYS[player_key]
        return jsonify({"stream_id": stream_id})
    else:
        return "Invalid player key", 403

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
```

## Error Handling

The implementation includes comprehensive error handling:

1. **Missing Player Key**: If authentication is enabled but no `player_key` is provided, connection is rejected
2. **Invalid Player Key**: If the API returns non-200 status, connection is rejected
3. **API Unavailable**: If the HTTP request fails, connection is rejected
4. **Malformed Response**: If the API response cannot be parsed, connection is rejected
5. **Network Timeouts**: Built-in timeout handling via existing HTTP client

## Security Considerations

1. **API Security**: Ensure your validation API endpoint is properly secured
2. **Player Key Security**: Player keys should be kept confidential
3. **Rate Limiting**: Consider implementing rate limiting on your API endpoint
4. **Logging**: Monitor authentication attempts for suspicious activity

## Testing

To test the implementation:

1. Set up an API endpoint that responds to player key validation requests
2. Configure `player_key_auth_url` in your server configuration
3. Test publisher connections (should work unchanged)
4. Test player connections with valid player keys (should work)
5. Test player connections with invalid player keys (should be rejected)
6. Test player connections without player keys when authentication is enabled (should be rejected)

## Benefits

1. **Enhanced Security**: Control who can access specific streams
2. **Dynamic Access Control**: Player permissions can be changed via API without server restart
3. **Audit Trail**: All authentication attempts are logged
4. **Scalable**: Works with existing SRT Live Server architecture
5. **Flexible**: Supports various API response formats and authentication schemes