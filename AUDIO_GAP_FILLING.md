# Audio Gap Filling

When SRT packets are lost during IRL streaming (e.g., cellular network dropouts), OBS Studio's media source can experience broken, glitchy, or robotic audio. This feature detects gaps in audio PTS (Presentation Timestamp) and inserts silent MPEG-TS packets to keep the audio decoder in sync, so listeners hear brief silence instead of audio artifacts.

## Background

This is inspired by [Moblin's approach](https://github.com/eerimoq/moblin) to the same problem. Moblin fixes audio breaking by detecting PTS gaps in decoded audio and inserting silent PCM buffers. Our implementation works at the MPEG-TS transport level (before decoding), inserting silent audio frames directly into the stream before it reaches OBS or other players.

## How It Works

### 1. PMT Parsing — Identify Audio Streams

When a publisher connects and starts streaming, the server parses the MPEG-TS Program Map Table (PMT) to find **all** audio elementary stream PIDs and their codec types. Up to 4 audio tracks are supported per stream.

| Stream Type | Codec | Gap Filling | Format Detection |
|-------------|-------|-------------|------------------|
| `0x0F` | AAC (ADTS) | Supported | ADTS header parsing |
| `0x11` | AAC (LATM/LOAS) | Supported | ADTS header parsing |
| `0x03` | MPEG-1 Audio (MP3) | Supported | MP3 frame header parsing |
| `0x04` | MPEG-2 Audio (MP3) | Supported | MP3 frame header parsing |
| `0x81` | AC-3 (Dolby Digital) | Detected, not filled | — |
| `0x06` + Opus descriptor | Opus | Detected, not filled | — |

### 2. Multi-Track Support

Each audio track is tracked independently with its own:
- **PID** — elementary stream PID from the PMT
- **PTS** — last seen presentation timestamp
- **Continuity counter** — for generating valid TS packets
- **Format info** — sample rate, channels, profile, detected from the actual stream

The `audio_track_info` struct holds per-track state, and the PMT parser collects all audio tracks (up to `MAX_AUDIO_TRACKS = 4`). Each track's PES stream_id (`0xC0`, `0xC1`, etc.) is recorded from the actual stream for correct gap packet generation.

### 3. Format Auto-Detection

On the first audio PES packet for each track, the server reads the codec-specific frame header from the elementary stream payload:

**AAC (ADTS):**
- Sample rate — from the ADTS sample rate index (7350 Hz through 96000 Hz)
- Channel configuration — mono, stereo, 5.1, 7.1, etc.
- AAC profile — AAC-LC, HE-AAC, etc.

**MP3 (MPEG Audio):**
- MPEG version — MPEG-1, MPEG-2, MPEG-2.5
- Sample rate — from the version-specific rate table (8000 Hz through 48000 Hz)
- Channel mode — stereo, joint stereo, dual channel, mono
- Bitrate index — for frame size calculation

### 4. PTS Gap Detection

For each incoming audio PES packet, the server compares its PTS with the track's last seen PTS. The expected frame duration is calculated dynamically per codec:

**AAC:** `1024 samples / sample_rate * 90000`
- 48000 Hz → 1920 PTS ticks (~21.3 ms)
- 44100 Hz → 2089 PTS ticks (~23.2 ms)

**MP3:** `1152 samples / sample_rate * 90000`
- 48000 Hz → 2160 PTS ticks (~24.0 ms)
- 44100 Hz → 2351 PTS ticks (~26.1 ms)

If the PTS delta exceeds one frame duration:
```
gap_frames = round(pts_delta / frame_duration) - 1
```

### 5. Silent Packet Generation

For each missing frame, the server generates a complete MPEG-TS packet containing:

- **TS header** — correct audio PID, payload unit start indicator, incrementing continuity counter
- **Adaptation field** — stuffing bytes to pad the packet to 188 bytes
- **PES header** — track's actual stream_id, interpolated PTS timestamp
- **Codec-specific silent frame:**
  - **AAC**: ADTS header (7 bytes) matching the stream's profile/rate/channels + minimal silent payload (~6 bytes)
  - **MP3**: Valid MPEG audio frame header (4 bytes) + zeroed side info + zeroed main data = silence

### 6. PTS Wraparound Handling

PTS is a 33-bit value that wraps at 2^33 (8,589,934,592 ticks, about 26.5 hours). The gap detector handles wraparound by checking for negative deltas and adjusting modulo 2^33.

Gaps larger than 2 seconds (180,000 PTS ticks) are ignored — these likely indicate a stream restart or encoder reconnection rather than packet loss.

### 7. Safety Limits

- Maximum gap fill: **100 frames** per gap (~2 seconds of silence)
- Maximum PTS gap considered: **2 seconds**
- Maximum audio tracks: **4** per stream
- Unsupported codecs (AC-3, Opus) are detected in PMT but not gap-filled

## Configuration

Add `audio_gap_fill` to your app block in `sls.conf`:

```nginx
srt {
    server {
        listen_publisher 4001;
        listen_player 4000;

        app {
            app_player live;
            app_publisher live;

            # Enable audio gap filling (default: false)
            audio_gap_fill true;

            # ... other settings ...
        }
    }
}
```

The setting is per-app and defaults to `false` (disabled).

## Data Flow

```
Publisher (SRT) → libsrt_read() → handler_read_data()
                                        ↓
                                  CSLSMapData::put()
                                        ↓
                                  check_ts_info()     ← parses PAT/PMT, finds audio PIDs
                                        ↓
                                  check_audio_gap()   ← detects PTS gaps per audio track
                                        ↓
                              SLSAudioGapFiller::     ← generates silent TS packets
                              generate_gap_packets()    (AAC or MP3, per track)
                                        ↓
                                  array_data->put()   ← inserts silent packets into buffer
                                        ↓
                                  Players read from buffer (gap-filled stream)
```

Gap filling happens at the publisher/buffer level, so it benefits all connected players simultaneously.

## Files

| File | Purpose |
|------|---------|
| `src/core/SLSAudioGapFiller.hpp` | Gap filler class, constants, sample rate tables (ADTS + MP3) |
| `src/core/SLSAudioGapFiller.cpp` | Silent frame generation (AAC + MP3), format detection, gap packet building |
| `src/core/common.hpp` | `audio_track_info` struct (per-track state), `ts_info` extended with track array |
| `src/core/common.cpp` | PMT parsing for multiple audio PIDs, `sls_init_audio_track()` |
| `src/core/SLSMapData.hpp/cpp` | Multi-track gap detection in `check_audio_gap()` |
| `src/core/SLSPublisher.hpp/cpp` | `audio_gap_fill` config option in `sls_conf_app_t` |

## Logging

The feature logs at different levels:

- **INFO** — When audio format is detected per track (codec, sample rate, channels)
- **INFO** — When silent packets are inserted (track PID, count, bytes)
- **INFO** — Number of audio tracks found in PMT
- **DEBUG** — Gap fill details (PTS delta, frame count, timestamps)
- **DEBUG** — PMT audio PID discovery per track

Example log output:
```
[info] sls_parse_pmt_for_audio: found 2 audio track(s)
[info] SLSAudioGapFiller: detected AAC format on PID=256 - profile=2, sample_rate=48000Hz, channels=2
[info] SLSAudioGapFiller: detected MP3 format on PID=257 - mpeg_ver=3, layer=1, sample_rate=44100Hz, channels=2
[info] CSLSMapData::check_audio_gap: PID=256 inserted 3 silent packets (564 bytes)
```

## Limitations

- **AC-3 and Opus not filled** — These codecs are detected in the PMT but silent frame generation is not implemented for them. AC-3 has a complex frame structure, and Opus uses variable frame sizes.
- **Not a codec fix** — This inserts silence at the transport level. If the audio decoder itself has state corruption from lost data, a brief glitch may still occur at the gap boundaries.
- **Assumes standard framing** — AAC detection looks for ADTS sync words; MP3 detection looks for MPEG audio frame sync. Non-standard framing won't be detected.
- **MP3 silent frames use 32kbps** — Silent MP3 frames are generated at the lowest standard bitrate (32kbps MPEG-1 Layer III) regardless of the stream's actual bitrate. This produces the smallest valid silent frame.

## Verification

1. Build: `cd build && cmake .. && make`
2. Set `audio_gap_fill true;` in your app block in `sls.conf`
3. Start the server and connect a publisher (e.g., Moblin, Larix, FFmpeg)
4. Connect an OBS media source to the server's player port
5. Simulate packet loss (network impairment, or drop SRT packets)
6. **Expected**: Audio should go silent during gaps instead of breaking/glitching
7. Check logs for `SLSAudioGapFiller` and `check_audio_gap` messages
