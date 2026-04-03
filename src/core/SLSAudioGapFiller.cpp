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
static const uint8_t SILENT_AAC_PAYLOAD[] = {
    0x21, 0x10, 0x05, 0x00, 0xA0, 0x19
};
static const int SILENT_AAC_PAYLOAD_LEN = sizeof(SILENT_AAC_PAYLOAD);

bool SLSAudioGapFiller::is_supported_audio(int stream_type)
{
    return stream_type == 0x0F || stream_type == 0x11 || // AAC
           stream_type == 0x03 || stream_type == 0x04 || // MP3
           stream_type == STREAM_TYPE_PRIVATE_DATA;       // Opus (via descriptor)
}

bool SLSAudioGapFiller::is_opus_audio(const audio_track_info *track)
{
    // Opus is signaled as stream_type 0x06 (private data) with a Registration
    // descriptor containing "Opus". We detect it by checking format_detected
    // combined with stream_type and the profile field set to a sentinel value.
    return track->stream_type == STREAM_TYPE_PRIVATE_DATA && track->format_detected;
}

int64_t SLSAudioGapFiller::frame_pts_duration(int sample_rate, int stream_type)
{
    if (sample_rate <= 0)
        return 0;

    int samples_per_frame;
    if (stream_type == 0x03 || stream_type == 0x04)
        samples_per_frame = MP3_SAMPLES_PER_FRAME;
    else if (stream_type == STREAM_TYPE_PRIVATE_DATA)
        samples_per_frame = OPUS_SAMPLES_PER_FRAME;
    else
        samples_per_frame = AAC_SAMPLES_PER_FRAME;

    return (int64_t)samples_per_frame * 90000 / sample_rate;
}

bool SLSAudioGapFiller::detect_adts_format(const uint8_t *es_data, int es_len, audio_track_info *at)
{
    if (es_len < 7)
        return false;

    // Look for ADTS syncword 0xFFF
    if (es_data[0] != 0xFF || (es_data[1] & 0xF0) != 0xF0)
        return false;

    int profile = ((es_data[2] >> 6) & 0x03) + 1;
    int sample_rate_index = (es_data[2] >> 2) & 0x0F;
    int channel_config = ((es_data[2] & 0x01) << 2) | ((es_data[3] >> 6) & 0x03);

    if (sample_rate_index >= ADTS_SAMPLE_RATE_COUNT)
        return false;
    if (channel_config == 0 || channel_config > 7)
        return false;

    at->profile = profile;
    at->sample_rate_index = sample_rate_index;
    at->sample_rate = ADTS_SAMPLE_RATES[sample_rate_index];
    at->channel_config = channel_config;
    at->channels = (channel_config == 7) ? 8 : channel_config;
    at->format_detected = true;

    spdlog::info("SLSAudioGapFiller: detected AAC format on PID={} - profile={}, sample_rate={}Hz, channels={}",
                 at->pid, profile, at->sample_rate, at->channels);
    return true;
}

bool SLSAudioGapFiller::detect_mp3_format(const uint8_t *es_data, int es_len, audio_track_info *at)
{
    if (es_len < 4)
        return false;

    // MP3 frame sync: 11 set bits (0xFFE0 mask)
    if (es_data[0] != 0xFF || (es_data[1] & 0xE0) != 0xE0)
        return false;

    // Parse MPEG audio header
    int mpeg_version = (es_data[1] >> 3) & 0x03; // 00=2.5, 01=reserved, 10=2, 11=1
    int layer = (es_data[1] >> 1) & 0x03;         // 01=Layer III, 10=Layer II, 11=Layer I
    int bitrate_index = (es_data[2] >> 4) & 0x0F;
    int sr_index = (es_data[2] >> 2) & 0x03;
    int channel_mode = (es_data[3] >> 6) & 0x03;  // 00=stereo, 01=joint, 10=dual, 11=mono

    if (mpeg_version == 1 || layer == 0 || sr_index == 3 || bitrate_index == 0 || bitrate_index == 15)
        return false; // reserved/invalid values

    int sample_rate = 0;
    if (mpeg_version == 3) // MPEG-1
        sample_rate = MP3_SAMPLE_RATES_MPEG1[sr_index];
    else if (mpeg_version == 2) // MPEG-2
        sample_rate = MP3_SAMPLE_RATES_MPEG2[sr_index];
    else if (mpeg_version == 0) // MPEG-2.5
        sample_rate = MP3_SAMPLE_RATES_MPEG25[sr_index];

    if (sample_rate == 0)
        return false;

    at->profile = mpeg_version; // store MPEG version
    at->sample_rate_index = sr_index;
    at->sample_rate = sample_rate;
    at->channel_config = channel_mode;
    at->channels = (channel_mode == 3) ? 1 : 2;
    at->bitrate_index = bitrate_index;
    at->format_detected = true;

    spdlog::info("SLSAudioGapFiller: detected MP3 format on PID={} - mpeg_ver={}, layer={}, sample_rate={}Hz, channels={}",
                 at->pid, mpeg_version, layer, at->sample_rate, at->channels);
    return true;
}

bool SLSAudioGapFiller::detect_opus_format(const uint8_t *es_data, int es_len, audio_track_info *at)
{
    // Opus in MPEG-TS uses a control header byte before each Opus packet.
    // The control header encodes frame size and channel count info.
    // For gap filling we just need to know it's Opus; the frame parameters
    // are fixed (48kHz, 20ms frames) as required by the Opus-in-MPEG-TS spec.
    if (es_len < 1)
        return false;

    // The first byte is the Opus control header. We accept any value as long
    // as the PMT already identified this PID as Opus via the registration descriptor.
    // Opus in MPEG-TS always uses 48kHz internally.
    at->sample_rate = OPUS_DEFAULT_SAMPLE_RATE;
    at->channels = 2; // stereo is most common; the actual channel count doesn't affect silence generation
    at->format_detected = true;

    spdlog::info("SLSAudioGapFiller: detected Opus format on PID={} - sample_rate={}Hz, channels={}",
                 at->pid, at->sample_rate, at->channels);
    return true;
}

bool SLSAudioGapFiller::detect_format(const uint8_t *es_data, int es_len, audio_track_info *at)
{
    if (at->stream_type == 0x0F || at->stream_type == 0x11)
        return detect_adts_format(es_data, es_len, at);
    else if (at->stream_type == 0x03 || at->stream_type == 0x04)
        return detect_mp3_format(es_data, es_len, at);
    else if (at->stream_type == STREAM_TYPE_PRIVATE_DATA)
        return detect_opus_format(es_data, es_len, at);
    return false;
}

int SLSAudioGapFiller::build_silent_adts_frame(
    uint8_t *out_buf,
    int profile,
    int sample_rate_index,
    int channel_config)
{
    int frame_len = 7 + SILENT_AAC_PAYLOAD_LEN;

    out_buf[0] = 0xFF;
    out_buf[1] = 0xF1; // MPEG-4, Layer 0, no CRC

    out_buf[2] = ((profile - 1) << 6) | (sample_rate_index << 2) | ((channel_config >> 2) & 0x01);
    out_buf[3] = ((channel_config & 0x03) << 6) | ((frame_len >> 11) & 0x03);
    out_buf[4] = (frame_len >> 3) & 0xFF;
    out_buf[5] = ((frame_len & 0x07) << 5) | 0x1F;
    out_buf[6] = 0xFC;

    memcpy(out_buf + 7, SILENT_AAC_PAYLOAD, SILENT_AAC_PAYLOAD_LEN);
    return frame_len;
}

int SLSAudioGapFiller::build_silent_mp3_frame(
    uint8_t *out_buf,
    const audio_track_info *track)
{
    // Build a valid MP3 frame header with zero audio data (silence)
    // MPEG-1 Layer III frame structure:
    //   Header (4 bytes) + side information (17 or 32 bytes) + main data (zero = silence)

    int mpeg_version = track->profile; // 3=MPEG-1, 2=MPEG-2, 0=MPEG-2.5
    int sr_index = track->sample_rate_index;
    int channel_mode = track->channel_config;
    bool is_mono = (channel_mode == 3);

    // Use a low bitrate for the silent frame (index 1 = 32kbps for MPEG-1 L3)
    int bitrate_index = 1;

    // Calculate frame size: frame_size = 144 * bitrate / sample_rate + padding
    int bitrate = MP3_BITRATES_MPEG1_L3[bitrate_index] * 1000;
    int frame_size = 144 * bitrate / track->sample_rate;
    // No padding for our silent frame

    if (frame_size < 4 || frame_size > 188)
        return 0;

    memset(out_buf, 0, frame_size);

    // Frame sync (11 bits = 1)
    out_buf[0] = 0xFF;

    // sync cont (3 bits) | mpeg_version (2 bits) | layer (2 bits=01 for L3) | protection (1 bit=1 no CRC)
    uint8_t byte1 = 0xE0; // sync bits continued
    byte1 |= (mpeg_version & 0x03) << 3;
    byte1 |= 0x02; // Layer III = 01, shifted left by 1
    byte1 |= 0x01; // no CRC
    out_buf[1] = byte1;

    // bitrate_index (4 bits) | sr_index (2 bits) | padding (1 bit=0) | private (1 bit=0)
    out_buf[2] = (bitrate_index << 4) | (sr_index << 2);

    // channel_mode (2 bits) | mode_ext (2 bits=0) | copyright (1=0) | original (1=1) | emphasis (2=0)
    out_buf[3] = (channel_mode << 6) | 0x04; // original=1

    // Side information follows (17 bytes mono, 32 bytes stereo for MPEG-1)
    // All zeros = silence (no main data, no scalefactors)
    // Already zeroed by memset

    return frame_size;
}

int SLSAudioGapFiller::build_silent_opus_frame(
    uint8_t *out_buf,
    const audio_track_info *track)
{
    // Opus silent frame: a single-byte Opus control header for MPEG-TS,
    // followed by a minimal Opus silence packet.
    //
    // The Opus-in-MPEG-TS spec (draft-spittka-payload-rtp-opus) uses a
    // control header byte before each Opus packet. For a 20ms frame:
    //   control_header = 0x7F (start_trim=0, end_trim=0, control=0, frame_count=1)
    //
    // The actual Opus silence is a single-byte TOC with code 0 (silence):
    //   TOC byte: config=0 (SILK-only 10ms NB), s=0, c=0
    //   But the simplest valid silence is just FC (hybrid 20ms, stereo, code 0)
    //   followed by no frame data (code 0 = 1 frame of 0 bytes = silence).
    //
    // Minimal approach: Opus control header (1 byte) + Opus TOC (1 byte)
    // The TOC byte 0xFC = config 31 (FB 20ms), stereo, code 0 (1 frame).
    // With code 0 and 0 bytes of frame data, the decoder outputs silence.

    // Opus MPEG-TS control header: single Opus packet in this access unit
    out_buf[0] = 0x7E; // control header: start_trim_flag=0, end_trim_flag=0, control_ext=0, payload follows

    // Opus TOC byte: silence
    // 0xF8 = config=31 (fullband, 20ms), mono, code=0 (1 frame, 0 bytes = silence)
    // 0xFC = config=31 (fullband, 20ms), stereo, code=0
    out_buf[1] = (track->channels > 1) ? 0xFC : 0xF8;

    return 2;
}

void SLSAudioGapFiller::write_pes_pts(uint8_t *buf, int64_t pts, int marker_bits)
{
    buf[0] = ((marker_bits & 0xF) << 4) | (((pts >> 30) & 0x07) << 1) | 1;
    buf[1] = (pts >> 22) & 0xFF;
    buf[2] = (((pts >> 15) & 0x7F) << 1) | 1;
    buf[3] = (pts >> 7) & 0xFF;
    buf[4] = (((pts) & 0x7F) << 1) | 1;
}

void SLSAudioGapFiller::build_silent_ts_packet(
    uint8_t *out_packet,
    const audio_track_info *track,
    int64_t pts,
    uint8_t &cc)
{
    memset(out_packet, 0xFF, TS_PACK_LEN);

    // Build the silent audio frame based on codec type
    uint8_t audio_frame[188];
    int audio_frame_len = 0;

    if (track->stream_type == 0x0F || track->stream_type == 0x11)
    {
        audio_frame_len = build_silent_adts_frame(
            audio_frame, track->profile, track->sample_rate_index, track->channel_config);
    }
    else if (track->stream_type == 0x03 || track->stream_type == 0x04)
    {
        audio_frame_len = build_silent_mp3_frame(audio_frame, track);
    }
    else if (track->stream_type == STREAM_TYPE_PRIVATE_DATA)
    {
        audio_frame_len = build_silent_opus_frame(audio_frame, track);
    }

    if (audio_frame_len <= 0)
        return;

    // PES header size: 3 (start code) + 1 (stream_id) + 2 (length) + 3 (flags+hdr_len) + 5 (PTS) = 14
    int pes_header_len = 14;
    int pes_payload_len = pes_header_len + audio_frame_len;
    int ts_payload_capacity = TS_PACK_LEN - 4; // 184
    int stuffing_needed = ts_payload_capacity - pes_payload_len;

    // If the audio frame is too large for a single TS packet, skip it
    if (stuffing_needed < 0)
        return;

    int pos = 0;

    // TS header
    out_packet[pos++] = TS_SYNC_BYTE;
    out_packet[pos++] = 0x40 | ((track->pid >> 8) & 0x1F);
    out_packet[pos++] = track->pid & 0xFF;

    if (stuffing_needed > 0)
    {
        out_packet[pos++] = 0x30 | (cc & 0x0F);
        cc = (cc + 1) & 0x0F;
        out_packet[pos++] = stuffing_needed - 1;
        if (stuffing_needed > 1)
        {
            out_packet[pos++] = 0x00;
            pos += stuffing_needed - 2;
        }
    }
    else
    {
        out_packet[pos++] = 0x10 | (cc & 0x0F);
        cc = (cc + 1) & 0x0F;
    }

    // PES header
    out_packet[pos++] = 0x00;
    out_packet[pos++] = 0x00;
    out_packet[pos++] = 0x01;
    out_packet[pos++] = track->stream_id;

    int pes_remaining = 3 + 5 + audio_frame_len;
    out_packet[pos++] = (pes_remaining >> 8) & 0xFF;
    out_packet[pos++] = pes_remaining & 0xFF;

    out_packet[pos++] = 0x80; // marker bits
    out_packet[pos++] = 0x80; // PTS only
    out_packet[pos++] = 5;    // PES header data length

    write_pes_pts(out_packet + pos, pts, 0x2);
    pos += 5;

    // Audio frame
    memcpy(out_packet + pos, audio_frame, audio_frame_len);
}

std::vector<uint8_t> SLSAudioGapFiller::generate_gap_packets(
    const audio_track_info *track,
    int64_t last_pts,
    int64_t current_pts,
    uint8_t &cc)
{
    std::vector<uint8_t> result;

    if (last_pts == INVALID_DTS_PTS || current_pts == INVALID_DTS_PTS)
        return result;

    if (!track->format_detected || track->sample_rate <= 0)
        return result;

    if (!is_supported_audio(track->stream_type))
        return result;

    int64_t frame_duration = frame_pts_duration(track->sample_rate, track->stream_type);
    if (frame_duration <= 0)
        return result;

    int64_t pts_delta = current_pts - last_pts;
    if (pts_delta < 0)
        pts_delta += PTS_WRAP;

    if (pts_delta > MAX_PTS_GAP || pts_delta <= frame_duration)
        return result;

    int num_gap_frames = (int)std::round((double)pts_delta / frame_duration) - 1;
    if (num_gap_frames <= 0)
        return result;
    if (num_gap_frames > MAX_GAP_FRAMES)
        num_gap_frames = MAX_GAP_FRAMES;

    spdlog::debug("SLSAudioGapFiller: PID={} filling {} silent frames ({}Hz, type={:#x}), pts_delta={}",
                  track->pid, num_gap_frames, track->sample_rate, track->stream_type, pts_delta);

    result.resize(num_gap_frames * TS_PACK_LEN);

    for (int i = 0; i < num_gap_frames; i++)
    {
        int64_t fill_pts = (last_pts + (int64_t)(i + 1) * frame_duration) % PTS_WRAP;
        build_silent_ts_packet(result.data() + i * TS_PACK_LEN, track, fill_pts, cc);
    }

    return result;
}
