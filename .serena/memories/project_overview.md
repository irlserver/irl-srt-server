# SRT Live Server (irl-srt-server)

## Purpose
An open source live streaming server for low latency based on Secure Reliable Transport (SRT). It supports MPEG-TS format streaming with typically less than 1 second latency over the internet.

## Tech Stack
- **Language**: C++17
- **Build System**: CMake
- **Key Libraries**:
  - SRT (Secure Reliable Transport) - for streaming protocol
  - spdlog - for logging
  - nlohmann/json - for JSON processing
  - httplib - for HTTP REST API server
- **Platforms**: Unix-based operating systems only

## Project Structure
- `src/core/` - Core SRT server components
  - `SLSManager` - Main manager coordinating all components
  - `SLSListener` - Listens for SRT connections
  - `SLSPublisher` - Handles publisher streams
  - `SLSPlayer` - Handles player connections
  - `SLSRole` - Base role class
  - HTTP-related: `HttpClient`, `HttpRoleList`
- `src/srt-live-server.cpp` - Main server executable entry point
- `src/srt-live-client.cpp` - Test client tool
- `lib/` - External dependencies (spdlog, nlohmann/json)

## Key Concepts
- Uses RTMP-style URL format: `domain/app/stream_name` 
- StreamID in SRT is the unique stream identifier
- Separate publisher and player domains/apps to distinguish roles
- HTTP REST API on port 8181 (configurable) for statistics

## Configuration
- Config file: `sls.conf` (searched in /etc/sls/, /usr/local/etc/sls/, /usr/etc/sls/, ./)
- Supports multiple server blocks with different latency profiles
- Can configure publisher/player ports separately
