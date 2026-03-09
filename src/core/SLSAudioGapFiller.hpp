/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2024 irl-srt-server contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <stdint.h>
#include <vector>
#include "common.hpp"

// Maximum gap to fill (about 2 seconds) - larger gaps are likely stream restarts
static const int MAX_GAP_FRAMES = 100;

// PTS is 33-bit, wraps at 2^33
static const int64_t PTS_WRAP = (int64_t)1 << 33;

// Maximum reasonable PTS delta (about 2 seconds)
static const int64_t MAX_PTS_GAP = 2 * 90000;

// AAC samples per frame (AAC-LC always uses 1024 samples per frame)
static const int AAC_SAMPLES_PER_FRAME = 1024;

// MPEG-2 Audio (MP3) samples per frame
static const int MP3_SAMPLES_PER_FRAME = 1152;

// ADTS sample rate table (ISO 14496-3)
static const int ADTS_SAMPLE_RATES[] = {
    96000, 88200, 64000, 48000, 44100, 32000,
    24000, 22050, 16000, 12000, 11025, 8000, 7350
};
static const int ADTS_SAMPLE_RATE_COUNT = 13;

class SLSAudioGapFiller
{
public:
    // Calculate PTS duration of one audio frame based on sample rate and codec
    static int64_t frame_pts_duration(int sample_rate, int stream_type);

    // Generate silent AAC MPEG-TS packets to fill a gap between lastPTS and currentPTS.
    // Uses the audio format from ts_info to build matching silent frames.
    // Returns the generated TS data (multiple of TS_PACK_LEN bytes).
    static std::vector<uint8_t> generate_gap_packets(
        const ts_info *ti,
        int64_t last_pts,
        int64_t current_pts,
        uint8_t &cc);

    // Try to detect audio format (sample rate, channels) from an ADTS header
    // in the ES payload. Returns true if format was detected.
    static bool detect_adts_format(const uint8_t *es_data, int es_len, ts_info *ti);

private:
    // Build a single silent AAC TS packet with the given PTS
    static void build_silent_aac_ts_packet(
        uint8_t *out_packet,
        const ts_info *ti,
        int64_t pts,
        uint8_t &cc);

    // Build the silent AAC ADTS frame for the given format
    static int build_silent_adts_frame(
        uint8_t *out_buf,
        int profile,
        int sample_rate_index,
        int channel_config);

    // Write PTS into a PES header buffer (5 bytes)
    static void write_pes_pts(uint8_t *buf, int64_t pts, int marker_bits);
};
