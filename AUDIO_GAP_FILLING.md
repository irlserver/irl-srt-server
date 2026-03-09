# Audio Gap Filling

When SRT packets are lost during IRL streaming (e.g., cellular network dropouts), OBS Studio's media source can experience broken, glitchy, or robotic audio. This feature detects gaps in audio PTS (Presentation Timestamp) and inserts silent AAC MPEG-TS packets to keep the audio decoder in sync, so listeners hear brief silence instead of audio artifacts.

## Background

This is inspired by [Moblin's approach](https://github.com/eerimoq/moblin) to the same problem. Moblin fixes audio breaking by detecting PTS gaps in decoded audio and inserting silent PCM buffers. Our implementation works at the MPEG-TS transport level (before decoding), inserting silent AAC frames directly into the stream before it reaches OBS or other players.

## How It Works

### 1. PMT Parsing — Identify the Audio Stream

When a publisher connects and starts streaming, the server parses the MPEG-TS Program Map Table (PMT) to find the audio elementary stream PID and codec type. Supported audio stream types:

| Stream Type | Codec | Gap Filling |
|-------------|-------|-------------|
| `0x0F` | AAC (ADTS) | Supported |
| `0x11` | AAC (LATM) | Supported |
| `0x03` | MPEG-1 Audio (MP3) | Detected but not filled |
| `0x04` | MPEG-2 Audio (MP3) | Detected but not filled |

### 2. ADTS Format Auto-Detection

On the first audio PES packet, the server reads the ADTS (Audio Data Transport Stream) header from the elementary stream payload to detect:

- **Sample rate** — from the ADTS sample rate index (supports 7350 Hz through 96000 Hz)
- **Channel configuration** — mono, stereo, 5.1, 7.1, etc.
- **AAC profile** — typically AAC-LC

This means the gap filler adapts to whatever audio format the encoder is sending. There is no hardcoded assumption about sample rate or channel count.

### 3. PTS Gap Detection

For each incoming audio PES packet, the server compares its PTS with the last seen audio PTS. The expected frame duration is calculated dynamically:

```
frame_duration_pts = 1024 (samples per AAC frame) / sample_rate * 90000 (PTS clock)
```

Examples:
- 48000 Hz → 1920 PTS ticks per frame (~21.3 ms)
- 44100 Hz → 2089 PTS ticks per frame (~23.2 ms)
- 32000 Hz → 2880 PTS ticks per frame (~32.0 ms)

If the PTS delta exceeds one frame duration, the number of missing frames is:

```
gap_frames = round(pts_delta / frame_duration) - 1
```

### 4. Silent Packet Generation

For each missing frame, the server generates a complete MPEG-TS packet containing:

- **TS header** — correct audio PID, payload unit start indicator, incrementing continuity counter
- **Adaptation field** — stuffing bytes to pad the packet to 188 bytes
- **PES header** — audio stream ID (`0xC0`), interpolated PTS timestamp
- **ADTS header** — matching the stream's actual profile, sample rate, and channel configuration
- **Silent AAC payload** — minimal AAC-LC frame with zero spectral data (~6 bytes)

Each silent frame is small enough (~13 bytes ADTS) to fit in a single 188-byte TS packet.

### 5. PTS Wraparound Handling

PTS is a 33-bit value that wraps at 2^33 (8,589,934,592 ticks, about 26.5 hours). The gap detector handles wraparound by checking for negative deltas and adjusting modulo 2^33.

Gaps larger than 2 seconds (180,000 PTS ticks) are ignored — these likely indicate a stream restart or encoder reconnection rather than packet loss.

### 6. Safety Limits

- Maximum gap fill: **100 frames** per gap (~2 seconds of silence)
- Maximum PTS gap considered: **2 seconds**
- Only AAC streams are filled (MP3 detection is present but filling is not implemented)

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
                                  check_ts_info()     ← parses PAT/PMT, finds audio PID
                                        ↓
                                  check_audio_gap()   ← detects PTS gaps in audio
                                        ↓
                              SLSAudioGapFiller::     ← generates silent AAC TS packets
                              generate_gap_packets()
                                        ↓
                                  array_data->put()   ← inserts silent packets into buffer
                                        ↓
                                  Players read from buffer (gap-filled stream)
```

Gap filling happens at the publisher/buffer level, so it benefits all connected players simultaneously.

## Files

| File | Purpose |
|------|---------|
| `src/core/SLSAudioGapFiller.hpp` | Gap filler class declaration, constants, ADTS sample rate table |
| `src/core/SLSAudioGapFiller.cpp` | Silent AAC frame generation, ADTS format detection, gap packet building |
| `src/core/common.hpp` | `ts_info` struct extended with audio tracking fields |
| `src/core/common.cpp` | PMT parsing for audio PID (`sls_parse_pmt_for_audio`), field initialization |
| `src/core/SLSMapData.hpp/cpp` | Gap detection logic in `check_audio_gap()`, `set_audio_gap_fill()` |
| `src/core/SLSPublisher.hpp/cpp` | `audio_gap_fill` config option in `sls_conf_app_t` |

## Logging

The feature logs at different levels:

- **INFO** — When audio format is detected (sample rate, channels, profile)
- **INFO** — When silent packets are inserted (count and bytes)
- **DEBUG** — Gap fill details (PTS delta, frame count, timestamps)
- **DEBUG** — PMT audio PID discovery

Example log output:
```
[info] SLSAudioGapFiller: detected audio format - profile=2, sample_rate=48000Hz, channels=2, sr_index=3
[info] CSLSMapData::check_audio_gap: inserted 3 silent packets (564 bytes)
```

## Limitations

- **AAC only** — Only AAC (ADTS/LATM) streams are gap-filled. MP3 audio PID is detected but silent frames are not generated for it.
- **Single audio stream** — Only the first audio PID found in the PMT is tracked. Streams with multiple audio tracks will only have the first one gap-filled.
- **Not a codec fix** — This inserts silence at the transport level. If the audio decoder itself has state corruption from lost data, a brief glitch may still occur at the gap boundaries.
- **Assumes ADTS framing** — The format detector looks for ADTS sync words. Non-ADTS AAC (raw AAC in MP4/fMP4) won't be detected.

## Verification

1. Build: `cd build && cmake .. && make`
2. Set `audio_gap_fill true;` in your app block in `sls.conf`
3. Start the server and connect a publisher (e.g., Moblin, Larix, FFmpeg)
4. Connect an OBS media source to the server's player port
5. Simulate packet loss (network impairment, or drop SRT packets)
6. **Expected**: Audio should go silent during gaps instead of breaking/glitching
7. Check logs for `SLSAudioGapFiller` and `check_audio_gap` messages
