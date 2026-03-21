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

// Maximum gap to fill (about 5 seconds) - covers cellular handoffs on bonded SRTLA
static const int MAX_GAP_FRAMES = 250;

// PTS is 33-bit, wraps at 2^33
static const int64_t PTS_WRAP = (int64_t)1 << 33;

// Maximum reasonable PTS delta (about 5 seconds) - covers SRTLA reconnections
static const int64_t MAX_PTS_GAP = 5 * 90000;

// AAC samples per frame (AAC-LC always uses 1024 samples per frame)
static const int AAC_SAMPLES_PER_FRAME = 1024;

// MPEG-1/2 Audio Layer III (MP3) samples per frame
static const int MP3_SAMPLES_PER_FRAME = 1152;

// ADTS sample rate table (ISO 14496-3)
static const int ADTS_SAMPLE_RATES[] = {
    96000, 88200, 64000, 48000, 44100, 32000,
    24000, 22050, 16000, 12000, 11025, 8000, 7350
};
static const int ADTS_SAMPLE_RATE_COUNT = 13;

// MP3 sample rate table (MPEG-1)
static const int MP3_SAMPLE_RATES_MPEG1[] = {44100, 48000, 32000};
// MP3 sample rate table (MPEG-2)
static const int MP3_SAMPLE_RATES_MPEG2[] = {22050, 24000, 16000};
// MP3 sample rate table (MPEG-2.5)
static const int MP3_SAMPLE_RATES_MPEG25[] = {11025, 12000, 8000};

// MP3 bitrate table for MPEG-1 Layer III (kbps), index 0 = free, 15 = bad
static const int MP3_BITRATES_MPEG1_L3[] = {
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0
};

class SLSAudioGapFiller
{
public:
    // Calculate PTS duration of one audio frame based on sample rate and codec
    static int64_t frame_pts_duration(int sample_rate, int stream_type);

    // Generate silent MPEG-TS packets for a specific audio track to fill a PTS gap.
    // Supports AAC (ADTS) and MP3. Returns TS data (multiple of TS_PACK_LEN bytes).
    static std::vector<uint8_t> generate_gap_packets(
        const audio_track_info *track,
        int64_t last_pts,
        int64_t current_pts,
        uint8_t &cc);

    // Try to detect audio format from an ADTS header in the ES payload.
    static bool detect_adts_format(const uint8_t *es_data, int es_len, audio_track_info *at);

    // Try to detect audio format from an MP3 frame header in the ES payload.
    static bool detect_mp3_format(const uint8_t *es_data, int es_len, audio_track_info *at);

    // Try to auto-detect format based on stream type and ES data.
    static bool detect_format(const uint8_t *es_data, int es_len, audio_track_info *at);

    // Check if a stream type is a supported audio codec for gap filling
    static bool is_supported_audio(int stream_type);

private:
    // Build a single silent TS packet with the given PTS for the given track
    static void build_silent_ts_packet(
        uint8_t *out_packet,
        const audio_track_info *track,
        int64_t pts,
        uint8_t &cc);

    // Build a silent AAC ADTS frame for the given format. Returns frame length.
    static int build_silent_adts_frame(
        uint8_t *out_buf,
        int profile,
        int sample_rate_index,
        int channel_config);

    // Build a silent MP3 frame for the given format. Returns frame length.
    static int build_silent_mp3_frame(
        uint8_t *out_buf,
        const audio_track_info *track);

    // Write PTS into a PES header buffer (5 bytes)
    static void write_pes_pts(uint8_t *buf, int64_t pts, int marker_bits);
};
