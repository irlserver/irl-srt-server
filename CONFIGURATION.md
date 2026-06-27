# Configuration reference

This document catalogs the configuration directives that the IRL fork of `srt-live-server` adds on top of the upstream SLS project, plus the base directives whose behavior changed in this fork. The canonical example with inline comments is `src/sls.conf`.

For directives inherited unchanged from upstream SLS see the upstream wiki at `https://github.com/rstular/srt-live-server/wiki/Directives`. Feature deep dives live in [`AUDIO_GAP_FILLING.md`](AUDIO_GAP_FILLING.md), [`BITRATE_LIMITING.md`](BITRATE_LIMITING.md), and [`PLAYER_KEY_IMPLEMENTATION.md`](PLAYER_KEY_IMPLEMENTATION.md). This file links to those rather than restating them.

## Conventions

- Directives live in one of three scopes: `srt { }` (global), `srt { server { } }` (per server), or `srt { server { app { } } }` (per app).
- Boolean values accept `true` / `false` or `1` / `0`. Strings may be optionally wrapped in single or double quotes; the quotes are stripped at parse time.
- Time values are in the unit the directive name implies (`_ms` suffix for milliseconds, `_timeout` is usually seconds unless otherwise noted, see the per directive entry).
- `-1` is the conventional "unlimited" sentinel for counted limits.

## Global scope (`srt { ... }`)

### Server runtime

| Directive | Type | Default | Notes |
|---|---|---|---|
| `worker_threads` | int | `1` | Worker threads handling SRT connections. Bump for many concurrent streams (more than 5). |
| `worker_connections` | int | `300` | Max concurrent SRT connections per worker. |
| `pidfile` | path | `/tmp/sls/sls_server.pid` | PID file path; created on start, removed on stop. |
| `user` | string | (unset) | Drop privileges to this user after binding. Only applies when started as root, otherwise ignored with a warning. |
| `group` | string | user's primary group | Drop privileges to this group. Pairs with `user`. |

### HTTP stats and control API

| Directive | Type | Default | Notes |
|---|---|---|---|
| `http_port` | int | `8181` | Port for the HTTP stats / control API. Exposes `/stats`, `/healthz`, and the disconnect endpoints. |
| `cors_header` | string | `*` | Value sent in `Access-Control-Allow-Origin`. Restrict to a specific domain for production. |
| `api_keys` | string list | (unset) | Comma separated API keys. Clients pass one in `Authorization: <key>` to use the control endpoints without the `?publisher=` query. Compared in constant time. |
| `stat_post_url` | url | (unset) | If set, SLS POSTs the stats JSON to this URL on the interval below. |
| `stat_post_interval` | int (seconds) | `1` | Interval between auto posted stats payloads. |

### Logging

The fork ships a redesigned logging system designed to keep log volume sane on IRL setups where players and OBS reconnect frequently. The per category levels and the rate limiter together let an operator silence noisy subsystems without losing real errors.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `log_file` | path | `logs/srt_server.log` | Log file path. |
| `log_level` | enum | `info` | Global log level (`trace`, `debug`, `info`, `warn`, `error`). |
| `log_format` | enum | `text` | `text` or `json`. JSON is useful for log aggregators. |
| `log_rate_limit_enabled` | bool | `1` | Enable per event rate limiting. |
| `log_rate_limit_window` | int (seconds) | `60` | Time window for the rate limit threshold. |
| `log_rate_limit_threshold` | int | `5` | Log every Nth occurrence of a repeated event. |
| `log_summary_enabled` | bool | `1` | Emit periodic operational summary (active publishers / players, connect counts, errors). |
| `log_summary_interval` | int (seconds) | `60` | Summary cadence. |
| `log_session_ids` | bool | `1` | Tag log lines with a short connection id like `[connection:a3f2]` for grep based correlation. |
| `log_level_connection` | enum | inherits `log_level` | Publisher / player connect and disconnect events. |
| `log_level_listener` | enum | inherits `log_level` | Listener lifecycle, accepts. |
| `log_level_stream` | enum | inherits `log_level` | Stream lifecycle (publishers). |
| `log_level_data` | enum | inherits `log_level` | Data path / packet trace. Very verbose. |
| `log_level_relay` | enum | inherits `log_level` | Puller and pusher operations. |
| `log_level_http` | enum | inherits `log_level` | HTTP API and webhooks. |
| `log_level_auth` | enum | inherits `log_level` | Authentication, player keys. |
| `log_level_system` | enum | inherits `log_level` | Startup, shutdown, config reload. |

## Per server scope (`srt { server { ... } } }`)

### Listener ports

`listen_player`, `listen_publisher`, and `listen_publisher_srtla` each accept either a single port, a comma separated list, an inclusive range (`a-b`), or any mix. One SRT listener is created per port. SRTLA patches are enabled automatically on `listen_publisher_srtla` and disabled on `listen_publisher`.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `listen_player` | port list | (required) | Player facing port(s). |
| `listen_publisher` | port list | (required for direct SRT publishers) | Direct SRT publisher port(s) (OBS, FFmpeg without SRTLA). |
| `listen_publisher_srtla` | port list | (required for SRTLA publishers) | SRTLA / bonded cellular publisher port(s) (used together with `srtla_rec`). |

### Latency and connection tuning

| Directive | Type | Default | Notes |
|---|---|---|---|
| `latency_min` | int (ms) | (per role default) | Minimum SRT latency for both publisher and player listeners. Floor enforced and warned when configured below the SRT default. |
| `latency_max` | int (ms) | (per role default) | Maximum latency for accepted connections. |
| `backlog` | int | `100` | Listen backlog for simultaneous connection attempts. |
| `idle_streams_timeout` | int (seconds) | `30` | Close streams idle for this long. `-1` disables. |
| `peer_idle_timeout` | int (ms) | `0` (libsrt default) | `SRTO_PEERIDLETIMEO` applied to every accepted socket. Bounds how long a peer may go silent (no data, no keepalive) before the link is declared broken. The belabox SRT fork raises the libsrt default so bonded cellular gaps do not kill healthy publishers; set a tighter value (for example `4000`) only when publishers reach SLS over a stable hop (a local `srtla_rec` terminating the bond). Avoid on direct bonded SRTLA listeners. |
| `publisher_first_data_grace` | int (ms) | `0` (built in `3000`) | First data probation for an accepted publisher. A connection that completes the SRT handshake, registers as a publisher, then never delivers a media packet (almost always a player or preview pointed at the ingest port, a valid stream key still authenticates) is reaped by `(negotiated latency + this grace)` instead of squatting the key for the full `idle_streams_timeout`. The latency term is required because SRT's TSBPD holds the first packet for the whole receive latency window, so a legitimate high latency encoder (Moblin around `3000`, Belabox `2000` to `3000`) surfaces its first byte only after that window. The grace covers RTT, encoder warmup, and TSBPD jitter on top of it. `0` applies the built in `3000`. `-1` disables probation. Works with the publisher takeover guard, which refuses a new connection for a key whose incumbent is actively delivering rather than evicting the live broadcaster. |

### Listener wide SRT encryption

These run during the SRT crypto handshake on every accepted connection (publishers and players). This is orthogonal to `player_key_auth_url`, which runs after the handshake on streamid lookup.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `srt_passphrase` | string (10 to 79 bytes) | (unset, no encryption) | libsrt enforces this passphrase during the crypto handshake. Validated at listener start. |
| `srt_pbkeylen` | int (0, 16, 24, 32) | `0` (libsrt default, AES-128) | Key length in bytes. Validated at listener start. |

### Streamid routing

| Directive | Type | Default | Notes |
|---|---|---|---|
| `domain_player` | string | (required) | Domain segment used in the player streamid (`<domain_player>/<app>/<stream>`). |
| `domain_publisher` | string | (required) | Domain segment used in the publisher streamid. |
| `default_sid` | string | (unset) | Default streamid to use when the encoder omits one. |

The pair `domain_publisher` / `app_publisher` must not equal `domain_player` / `app_player` in the same server block.

### Webhooks

| Directive | Type | Default | Notes |
|---|---|---|---|
| `on_event_url` | url | (unset) | HTTP endpoint called on publisher and player connect / close. Callback shape: `?method=on_connect\|on_close&role_name=&srt_url=<stream_url>`. The publish auth response may include a `pushTargets` array that drives per publisher push destinations (see below). |
| `auth_reject_cache_ttl` | int (seconds) | `30` | Negative auth cache TTL. A publisher streamid whose `on_event_url` lookup returns non 200 is remembered for this many seconds; subsequent attempts with the same canonical streamid are rejected at the SRT handshake (no accept, no webhook). `0` falls back to the 30 second default. Mitigates streamid rotating DoS. |

### Player key authentication

When `player_key_auth_url` is set, player connections targeting the configured `domain_player` / `app_player` are validated against the API endpoint. The response maps the player key to the real stream id (and optionally to a per stream player limit). See [`PLAYER_KEY_IMPLEMENTATION.md`](PLAYER_KEY_IMPLEMENTATION.md) for the full protocol.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `player_key_auth_url` | url | (unset, disabled) | API endpoint for validating player keys. `GET <url>?player_key=<key>`. Expected JSON response: `{"stream_id": "publish/live/actualstream", "max_players_per_stream": 10}` (the limit is optional). |
| `player_key_auth_timeout` | int (ms) | `2000` | HTTP timeout for the validation call. |
| `player_key_cache_duration` | int (ms) | `60000` | Duration to cache successful validations (and briefly cache rejections to prevent API abuse). |
| `player_key_rate_limit_requests` | int | `-1` (unlimited) | Max validation requests per peer IP per window. |
| `player_key_rate_limit_window` | int (ms) | `60000` | Rate limit window. |
| `player_key_min_length` | int | `8` | Minimum accepted player key length. |
| `player_key_max_length` | int | `64` | Maximum accepted player key length. Valid characters are printable ASCII (hex `0x20` to `0x7E`). |

## Per app scope (`srt { server { app { ... } } }`)

### Routing

| Directive | Type | Default | Notes |
|---|---|---|---|
| `app_player` | string | (required) | App segment used in the player streamid. |
| `app_publisher` | string | (required) | App segment used in the publisher streamid. |

### IP access control (allow / deny)

`allow` and `deny` directives gate connections per role.

| Directive | Type | Notes |
|---|---|---|
| `allow publish <ip\|all>` | rule | Whitelist for publishers. |
| `deny publish <ip>` | rule | Blacklist for publishers. |
| `allow play <ip\|all>` | rule | Whitelist for players. |
| `deny play <ip>` | rule | Blacklist for players. |

**Known IPv6 limitation.** The ACL storage type (`sls_ip_access_t`) holds only an IPv4 address. As a result, specific IPv6 allow or deny rules are not enforced today. IPv6 peers match only the wildcard entry (`all`) and otherwise hit the documented default (currently "accept by default", matching the IPv4 no match path); a one shot warning per call is logged so operators know that explicit IPv6 ACL entries are being ignored. Tracking item: add IPv6 ACL matching to `conf.cpp` and `SLSListenerHandler.cpp`. Until then, an explicit `deny play <ipv6>` rule will not take effect.

### Per stream limits

| Directive | Type | Default | Notes |
|---|---|---|---|
| `max_players_per_stream` | int | `-1` (unlimited) | Cap on simultaneous players per stream. May be overridden per session by `max_players_per_stream` in a player key validation response. |

### Bitrate limiting

See [`BITRATE_LIMITING.md`](BITRATE_LIMITING.md) for the algorithm.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `max_input_bitrate_kbps` | int | (unset, disabled) | Sustained publisher bitrate ceiling in kbps. |
| `max_input_bitrate_violation_timeout` | int (seconds) | `30` | Disconnect after this many seconds of sustained violation. |
| `max_input_bitrate_spike_tolerance` | int (percent) | `120` | Spike multiplier in percent (`120` means trigger at 1.2x of `max_input_bitrate_kbps`). |

### Audio gap filling

See [`AUDIO_GAP_FILLING.md`](AUDIO_GAP_FILLING.md) for behavior, supported codecs, and the stats fields it exposes.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `audio_gap_fill` | bool | `false` | Inserts silent AAC / Opus frames when an audio PTS gap is detected, preventing OBS audio breaks during packet loss. |

### Push destinations

Push destinations let the publish auth webhook drive per publisher SRT pushers. When `push_destination_max > 0` and the publish auth response includes a JSON body `{ "pushTargets": [{ "url": "srt://..." }, ...] }`, SLS spawns one `CSLSPusher` caller per accepted entry. Each URL is validated again at use time. Aggregate egress per stream is bounded by `push_destination_max * max_input_bitrate_kbps`.

| Directive | Type | Default | Notes |
|---|---|---|---|
| `push_destination_max` | int | `0` (feature disabled) | Maximum number of push targets accepted per publisher. `0` disables the feature regardless of webhook output. |
| `push_destination_allow_internal` | bool | `false` | When `false`, RFC1918, loopback, and link local destinations are rejected. |
| `push_destination_allow_self` | bool | `false` | When `false`, the server's own bind addresses are rejected as destinations. |
| `push_destination_allow_schemes` | string list | `srt` | Allowed URL schemes for destinations. |
| `push_destination_max_url_len` | int (bytes) | `1024` | Maximum accepted destination URL length. |

### Relay (`relay { }` block)

The per app `relay { }` block configures static pull or push relays. The static relay code path remains in the codebase but is largely superseded for push by the dynamic `pushTargets` mechanism described above. The pull direction is still in active use.

| Block field | Type | Notes |
|---|---|---|
| `type` | enum | `pull` or `push`. |
| `mode` | enum | `pull`: `loop` or `hash`. `push`: `all` or `hash`. |
| `reconnect_interval` | int (seconds) | Reconnect delay on failure. |
| `idle_streams_timeout` | int (seconds) | Idle teardown timeout. `-1` disables. |
| `upstreams` | url list | Space separated list of upstream SRT URLs. Templates like `{stream_name}` are substituted. |

TODO: confirm whether the static `relay { type push; }` direction is still preferred over dynamic `pushTargets` for any operator workflow; cross reference the resolution from plan 007 once it lands.

## See also

- [`AUDIO_GAP_FILLING.md`](AUDIO_GAP_FILLING.md). Audio PTS gap detection, silent frame insertion, supported codecs, and stats fields.
- [`BITRATE_LIMITING.md`](BITRATE_LIMITING.md). Sustained vs spike tolerance, disconnect criteria.
- [`PLAYER_KEY_IMPLEMENTATION.md`](PLAYER_KEY_IMPLEMENTATION.md). Full player key auth protocol and response schema.
- [`CLAUDE.md`](CLAUDE.md). Orientation for contributors and agents (build layout, sanitizer guidance, commit conventions).
