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

#include <string.h>
#include <cmath>
#include "spdlog/spdlog.h"

#include "SLSAudioGapFiller.hpp"

// Minimal silent AAC payload - single channel element with all-zero spectral data
// This is codec-agnostic within AAC-LC; the ADTS header specifies the actual format
static const uint8_t SILENT_AAC_PAYLOAD[] = {
    0x21, 0x10, 0x05, 0x00, 0xA0, 0x19
};
static const int SILENT_AAC_PAYLOAD_LEN = sizeof(SILENT_AAC_PAYLOAD);

int64_t SLSAudioGapFiller::frame_pts_duration(int sample_rate, int stream_type)
{
    if (sample_rate <= 0)
        return 0;

    int samples_per_frame;
    if (stream_type == 0x03 || stream_type == 0x04)
        samples_per_frame = MP3_SAMPLES_PER_FRAME;
    else
        samples_per_frame = AAC_SAMPLES_PER_FRAME;

    // PTS ticks = samples_per_frame / sample_rate * 90000
    return (int64_t)samples_per_frame * 90000 / sample_rate;
}

bool SLSAudioGapFiller::detect_adts_format(const uint8_t *es_data, int es_len, ts_info *ti)
{
    if (es_len < 7)
        return false;

    // Look for ADTS syncword 0xFFF
    if (es_data[0] != 0xFF || (es_data[1] & 0xF0) != 0xF0)
        return false;

    // Parse ADTS header
    int profile = ((es_data[2] >> 6) & 0x03) + 1; // Object type = profile + 1 in ADTS
    int sample_rate_index = (es_data[2] >> 2) & 0x0F;
    int channel_config = ((es_data[2] & 0x01) << 2) | ((es_data[3] >> 6) & 0x03);

    if (sample_rate_index >= ADTS_SAMPLE_RATE_COUNT)
        return false;
    if (channel_config == 0 || channel_config > 7)
        return false;

    ti->audio_profile = profile;
    ti->audio_sample_rate_index = sample_rate_index;
    ti->audio_sample_rate = ADTS_SAMPLE_RATES[sample_rate_index];
    ti->audio_channel_config = channel_config;
    ti->audio_channels = (channel_config == 7) ? 8 : channel_config;
    ti->audio_format_detected = true;

    spdlog::info("SLSAudioGapFiller: detected audio format - profile={}, sample_rate={}Hz, channels={}, sr_index={}",
                 profile, ti->audio_sample_rate, ti->audio_channels, sample_rate_index);

    return true;
}

int SLSAudioGapFiller::build_silent_adts_frame(
    uint8_t *out_buf,
    int profile,
    int sample_rate_index,
    int channel_config)
{
    int frame_len = 7 + SILENT_AAC_PAYLOAD_LEN; // ADTS header + payload

    // ADTS header (7 bytes, no CRC)
    out_buf[0] = 0xFF;
    out_buf[1] = 0xF1; // MPEG-4, Layer 0, no CRC protection

    // profile (2 bits) | sample_rate_index (4 bits) | private (1 bit) | channel_config high (1 bit)
    out_buf[2] = ((profile - 1) << 6) | (sample_rate_index << 2) | (0 << 1) | ((channel_config >> 2) & 0x01);

    // channel_config low (2 bits) | original (1) | home (1) | copyright_id (1) | copyright_start (1) | frame_length high (2 bits)
    out_buf[3] = ((channel_config & 0x03) << 6) | ((frame_len >> 11) & 0x03);

    // frame_length mid (8 bits)
    out_buf[4] = (frame_len >> 3) & 0xFF;

    // frame_length low (3 bits) | buffer_fullness high (5 bits)
    out_buf[5] = ((frame_len & 0x07) << 5) | 0x1F; // buffer fullness = 0x7FF (VBR)

    // buffer_fullness low (6 bits) | number_of_raw_data_blocks (2 bits)
    out_buf[6] = 0xFC; // buffer fullness continued + 0 raw data blocks

    // Silent payload
    memcpy(out_buf + 7, SILENT_AAC_PAYLOAD, SILENT_AAC_PAYLOAD_LEN);

    return frame_len;
}

void SLSAudioGapFiller::write_pes_pts(uint8_t *buf, int64_t pts, int marker_bits)
{
    buf[0] = ((marker_bits & 0xF) << 4) | (((pts >> 30) & 0x07) << 1) | 1;
    buf[1] = (pts >> 22) & 0xFF;
    buf[2] = (((pts >> 15) & 0x7F) << 1) | 1;
    buf[3] = (pts >> 7) & 0xFF;
    buf[4] = (((pts) & 0x7F) << 1) | 1;
}

void SLSAudioGapFiller::build_silent_aac_ts_packet(
    uint8_t *out_packet,
    const ts_info *ti,
    int64_t pts,
    uint8_t &cc)
{
    memset(out_packet, 0xFF, TS_PACK_LEN);

    // Build the ADTS frame with the stream's actual format
    uint8_t adts_frame[64];
    int adts_len = build_silent_adts_frame(
        adts_frame,
        ti->audio_profile,
        ti->audio_sample_rate_index,
        ti->audio_channel_config);

    // PES header: 00 00 01 C0 <len_hi> <len_lo> 80 80 05 <pts 5 bytes>
    int pes_header_len = 14; // 3 (start code) + 1 (stream_id) + 2 (length) + 3 (flags+hdr_len) + 5 (PTS)
    int pes_payload_len = pes_header_len + adts_len;
    int ts_payload_capacity = TS_PACK_LEN - 4; // 184
    int stuffing_needed = ts_payload_capacity - pes_payload_len;

    int pos = 0;

    // TS header
    out_packet[pos++] = TS_SYNC_BYTE;
    out_packet[pos++] = 0x40 | ((ti->audio_pid >> 8) & 0x1F); // PUSI=1 + PID high
    out_packet[pos++] = ti->audio_pid & 0xFF;                  // PID low

    if (stuffing_needed > 0)
    {
        out_packet[pos++] = 0x30 | (cc & 0x0F); // adaptation + payload
        cc = (cc + 1) & 0x0F;

        out_packet[pos++] = stuffing_needed - 1; // adaptation field length
        if (stuffing_needed > 1)
        {
            out_packet[pos++] = 0x00; // flags
            // Rest is 0xFF (already from memset)
            pos += stuffing_needed - 2;
        }
    }
    else
    {
        out_packet[pos++] = 0x10 | (cc & 0x0F); // payload only
        cc = (cc + 1) & 0x0F;
    }

    // PES header
    out_packet[pos++] = 0x00; // start code
    out_packet[pos++] = 0x00;
    out_packet[pos++] = 0x01;
    out_packet[pos++] = 0xC0; // audio stream_id

    int pes_remaining = 3 + 5 + adts_len; // flags(2) + hdr_data_len(1) + pts(5) + payload
    out_packet[pos++] = (pes_remaining >> 8) & 0xFF;
    out_packet[pos++] = pes_remaining & 0xFF;

    out_packet[pos++] = 0x80; // marker bits
    out_packet[pos++] = 0x80; // PTS only
    out_packet[pos++] = 5;    // PES header data length

    write_pes_pts(out_packet + pos, pts, 0x2);
    pos += 5;

    // ADTS silent frame
    memcpy(out_packet + pos, adts_frame, adts_len);
}

std::vector<uint8_t> SLSAudioGapFiller::generate_gap_packets(
    const ts_info *ti,
    int64_t last_pts,
    int64_t current_pts,
    uint8_t &cc)
{
    std::vector<uint8_t> result;

    if (last_pts == INVALID_DTS_PTS || current_pts == INVALID_DTS_PTS)
        return result;

    if (!ti->audio_format_detected || ti->audio_sample_rate <= 0)
        return result;

    // Only support AAC gap filling (stream types 0x0F and 0x11)
    if (ti->audio_stream_type != 0x0F && ti->audio_stream_type != 0x11)
        return result;

    int64_t frame_duration = frame_pts_duration(ti->audio_sample_rate, ti->audio_stream_type);
    if (frame_duration <= 0)
        return result;

    // Calculate PTS delta with wraparound handling
    int64_t pts_delta = current_pts - last_pts;
    if (pts_delta < 0)
        pts_delta += PTS_WRAP;

    // Ignore very large gaps (likely stream restart)
    if (pts_delta > MAX_PTS_GAP || pts_delta <= frame_duration)
        return result;

    int num_gap_frames = (int)std::round((double)pts_delta / frame_duration) - 1;
    if (num_gap_frames <= 0)
        return result;
    if (num_gap_frames > MAX_GAP_FRAMES)
        num_gap_frames = MAX_GAP_FRAMES;

    spdlog::debug("SLSAudioGapFiller: filling {} silent frames ({}Hz), pts_delta={}, last_pts={}, current_pts={}",
                  num_gap_frames, ti->audio_sample_rate, pts_delta, last_pts, current_pts);

    result.resize(num_gap_frames * TS_PACK_LEN);

    for (int i = 0; i < num_gap_frames; i++)
    {
        int64_t fill_pts = (last_pts + (int64_t)(i + 1) * frame_duration) % PTS_WRAP;
        build_silent_aac_ts_packet(result.data() + i * TS_PACK_LEN, ti, fill_pts, cc);
    }

    return result;
}
