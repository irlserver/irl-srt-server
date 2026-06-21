# Release Notes

## Fork history (`irlserver/srt-live-server`)

The entries below cover work done in the IRL fork on top of the upstream `rstular/srt-live-server` history (preserved further down). Versions follow the `project(... VERSION)` field in `CMakeLists.txt`. Within a version, entries are grouped by feature area rather than per commit.

### v3.1.0 (in progress)

**SRTLA / bonded cellular**

- `listen_publisher_srtla` directive (and a separate listen port) enables SRTLA patches automatically on the publisher socket. Direct SRT publishers stay on `listen_publisher` without the patches. Multiple ports per role via comma lists and inclusive ranges (`listen_player 4000,4010,5000-5005`).

**Player key authentication**

- Per stream player keys validated against an external HTTP endpoint with rate limiting, length and character validation, success and failure caching, configurable cache duration and timeouts.
- Per session `max_players_per_stream` override returned in the validation response.
- Non blocking player key validation: deferred accept lets the worker keep serving traffic while the HTTP lookup is in flight. Reject and retry path for transient validation failures.

**Push destinations from publish auth webhook**

- The publish auth webhook may return a `pushTargets` array. SLS spawns one dynamic `CSLSPusher` per accepted entry, bounded by the new app level knobs (`push_destination_max`, `push_destination_allow_internal`, `push_destination_allow_self`, `push_destination_allow_schemes`, `push_destination_max_url_len`).
- URL validation includes DNS resolution and self bind detection.

**Bitrate limiting**

- `max_input_bitrate_kbps` enforces a publisher ceiling with configurable spike tolerance (`max_input_bitrate_spike_tolerance`) and sustained violation timeout (`max_input_bitrate_violation_timeout`).
- Publishers that sustain violations past the timeout are disconnected.

**Audio gap filling**

- `audio_gap_fill` inserts silent AAC or Opus frames when audio PTS gaps are detected to prevent OBS audio breaking during packet loss. Stats endpoint reports audio gap counters. Iterated fixes for PES continuation handling and CC rewriting.

**HTTP stats and control API**

- New `/healthz` endpoint for Kubernetes probes.
- New disconnect stream endpoint with API key authorization.
- `api_keys` directive supports comma separated keys with constant time comparison.
- Atomic stats counters and a read locked `put()` so `/stats` no longer stalls the data path.
- Replaced the blocking HTTP client with an `AsyncHttpClient` (thread pool backed) for stats posting, player key validation, and `on_event_url` callbacks.

**Logging redesign**

- Per category log levels (`log_level_connection`, `log_level_listener`, `log_level_stream`, `log_level_data`, `log_level_relay`, `log_level_http`, `log_level_auth`, `log_level_system`).
- Rate limited repetitive events (`log_rate_limit_*`).
- Periodic operational summary (`log_summary_*`).
- Session id tagging on log lines for grep based correlation (`log_session_ids`).
- Optional JSON file sink (`log_format json`) for log aggregators.

**Security and hardening**

- Listener wide SRT encryption via `srt_passphrase` and `srt_pbkeylen`, validated at listener start.
- Handshake time rejection for streamid based DoS (`auth_reject_cache_ttl` negative cache on the canonical streamid).
- Streamid sanitization: reject unsafe characters in host, app, and stream components; trim whitespace; reject URL significant characters.
- Bounded and time gated auth, rate limit, and player key caches.
- Constant time API key comparison on control endpoints.
- Drop privileges after binding via `user` and `group` directives.
- Numeric config values validated through `strtol` / `strtod`.
- Async signal safe signal handlers; SIGTERM handling.
- `peer_idle_timeout` (`SRTO_PEERIDLETIMEO`) per accepted socket.

**Stability and performance**

- Publisher takeover on reconnect.
- Event driven worker (`eventfd`, no polling `msleep` on Linux), portable `epoll` wakeup via self pipe on non Linux.
- Event driven egress, drop the permanent `SRT_EPOLL_OUT` arm.
- Player latency clamped via `SRTO_PEERLATENCY`; bumped UDP buffers; explicit `SRTO_TLPKTDROP`.
- Disconnect viewers stuck in continuous backpressure; handle `EASYNCSND` backpressure without disconnecting healthy viewers.
- Race free `m_nDataCount`, write locked `setSize` on the publisher ring; size publisher ring per bitrate with reader overrun detection.
- Compile out per packet `SPDLOG_TRACE` / `SPDLOG_DEBUG` on the data path; drop per packet string allocations.
- Race and leak fixes on the accept path (close socket and free `addrinfo` on `libsrt_setup` errors; stop leaking `stat_info_t` per accepted role; null check `strdup(sid)`; kick publisher via atomic flag in `disconnect_stream`).
- Removed HLS recording.

**Portability**

- Build restored on macOS (portable `pthread_t` formatting, portable link libs, qualified `socket::bind`).

**Tooling**

- doctest based unit test harness wired into CTest; first tests covering `SLSRecycleArray`, `auth_reject_cache`, `sls_sid`, bitrate limit, and audio gap filler. AddressSanitizer / UndefinedBehaviorSanitizer and ThreadSanitizer build options. GitHub Actions matrix building Release plus the two sanitizer flavors and running `ctest`.
- `clang-format` and `clang-tidy` configs; `-Wextra -Wshadow` warnings enabled.
- Pinned vendored submodules (cpp-httplib `v0.48.0`, json `v3.12.0`, spdlog tracks the `irlserver/spdlog` fork). SRT belabox fork pinned by commit in the Dockerfile.

**IP-ACL**

- IPv6 peers no longer silently bypass IPv4 allow / deny rules. They are matched only against the wildcard entry and otherwise hit the documented default with a one shot warning per call. Specific IPv6 ACL entries are still not supported (see `CONFIGURATION.md`).

### v3.0.0

- Switched to git submodules for vendored libraries (`spdlog`, `cpp-httplib`, `nlohmann/json`, `thread-pool`, `CxxUrl`).

### v2.5.0

- Per stream player limit (`max_players_per_stream`) with per session override returned by the player key validation API.
- Initial player key validation against an external API endpoint.
- Initial bitrate limiting feature for SRT stream input with configurable violation timeout.
- Disconnect stream endpoint, gated by API key authorization.
- SIGTERM signal handling.
- Refactored `SLSListener` into modular components (`SLSListenerCore`, `SLSListenerAuth`, `SLSListenerConfig`, `SLSListenerHandler`).
- Separate publisher and player listen ports (`listen_publisher`, `listen_player`).
- Dynamic latency, additional listener and worker logging, configuration file search in standard paths.

### v2.4.1

- API key support for control endpoints.

### v2.4.0

- Enabled `SRTO_SRTLAPATCHES` for SRTLA / bonded cellular compatibility.

### v2.3.2

- Stats: always emit the publishers array when status is ok; initialize the SRT stats object before requesting stats.

### v2.3.1

- Increased `POLLING_TIME` to reduce CPU usage.

### v2.3.0

- Switched the SRT dependency to the `irlserver/srt` fork (belabox patches).
- Lowered SRT flight credit constant.

### v2.2.0 (security update)

- Initial IPv6 support on listener sockets.
- SRT socket option tweaks.
- Small JSON API fixes; lower `TS_UDP_LEN` log severity to trace.

## Upstream history (`rstular/srt-live-server`)

## v1.5.1

- Fixed JSON status callback - information is now being sent via HTTP to the endpoint specified in the configuration file.
- Use proper JSON encoding library.

## v1.5.0

- Added `allow` and `deny` directives, to enable simple access control (see [Directives](https://github.com/rstular/srt-live-server/wiki/Directives) for more info).
- Added `pidfile` directive (see [Directives](https://github.com/rstular/srt-live-server/wiki/Directives) for more info).
- Bug fixes.

## v1.4.9

- Compatibility with Raspberry Pi.

## v1.4.8

- Compatibility with `srt v1.4.1`, add the set latency method before setup method.

## v1.4.7

- update the PID file path from `/opt/soft/sls/` to `/tmp/sls` to avoid the root authority in some case.

## v1.4.6

- update the PID file path from `~/` to `/opt/soft/sls/`

## v1.4.5

- add HLS record feature.

## v1.4.4

- OBS streaming compatible, OBS support the srt protocol which is later than v25.0. (https://obsproject.com/forum/threads/obs-studio-25-0-release-candidate.116067/)

## v1.4.3

- change the TCP epoll mode to select mode for compatibility with MacOS.
- modify the HTTP check repeat bug for reopen.

## v1.4.2

- add remote_ip and remote_port to on_event_url which can be as the unique identification for player or publisher.

## v1.4.1

- add publisher feather to slc(srt-live-client) tool, which can push ts file with srt according dts.
- modify the HTTP bug when host is not available.

## v1.4

- add HTTP statistic info.
- add HTTP event notification, on_connect, on_close.
- add player feature to slc(srt-live-client) tool for pressure test.

## v1.3

- support reload.
- add idle_streams_timeout feature for relay.
- change license type from gpl to mit.

## v1.2.1

- support hostname:port/app in upstreams of pull and push.

## v1.2

- update the memory mode, in v1.1 which is publisher copy data to eacc player, in v1.2 each publisher put data to a array and all players read data from this array.
- update the relation of the publisher and player, the player is not a member of publisher. the only relation of them is array data.
- add push and pull features, support all and hash mode for push, support loop and hash for pull. in cluster mode, you can push a stream to a hash node, and pull this stream from the same hash node.
