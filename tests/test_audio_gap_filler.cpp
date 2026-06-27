#include "doctest.h"

#include <cstring>

#include "SLSAudioGapFiller.hpp"
#include "common.hpp"

// SLSAudioGapFiller is pure logic (no I/O, no threads). We pin: codec
// classification, frame-duration math against the ADTS / MP3 / Opus rate
// tables, and the bounds of generate_gap_packets (PTS wrap, MAX_PTS_GAP,
// MAX_GAP_FRAMES clamp).

namespace
{
// Stream type IDs used by MPEG-TS PMT for audio elementary streams.
constexpr int STREAM_TYPE_AAC_ADTS = 0x0F;
constexpr int STREAM_TYPE_AAC_LATM = 0x11;
constexpr int STREAM_TYPE_MP3_V1 = 0x03;
constexpr int STREAM_TYPE_MP3_V2 = 0x04;
constexpr int STREAM_TYPE_OPUS = STREAM_TYPE_PRIVATE_DATA; // 0x06

// audio_track_info holds std::atomic members so it is neither copyable nor
// movable. Configure in place via an out parameter.
void init_track(audio_track_info &t, int stream_type, int sample_rate)
{
    sls_init_audio_track(&t);
    t.pid = 256;
    t.stream_type = stream_type;
    t.sample_rate = sample_rate;
    t.channels = 2;
    t.channel_config = 2;
    t.format_detected = true;
}
} // namespace

TEST_CASE("SLSAudioGapFiller::is_supported_audio classifies AAC/MP3/Opus and rejects others")
{
    CHECK(SLSAudioGapFiller::is_supported_audio(STREAM_TYPE_AAC_ADTS));
    CHECK(SLSAudioGapFiller::is_supported_audio(STREAM_TYPE_AAC_LATM));
    CHECK(SLSAudioGapFiller::is_supported_audio(STREAM_TYPE_MP3_V1));
    CHECK(SLSAudioGapFiller::is_supported_audio(STREAM_TYPE_MP3_V2));
    CHECK(SLSAudioGapFiller::is_supported_audio(STREAM_TYPE_OPUS));
    CHECK_FALSE(SLSAudioGapFiller::is_supported_audio(0x1B)); // H.264 video
    CHECK_FALSE(SLSAudioGapFiller::is_supported_audio(0x00));
}

TEST_CASE("SLSAudioGapFiller::frame_pts_duration: AAC at 48 kHz -> 1920 PTS ticks")
{
    // 1024 samples / 48000 Hz * 90000 ticks/s = 1920.
    CHECK(SLSAudioGapFiller::frame_pts_duration(48000, STREAM_TYPE_AAC_ADTS) == 1920);
    // AAC at 44.1 kHz -> 1024 * 90000 / 44100 = 2089 (integer truncation).
    CHECK(SLSAudioGapFiller::frame_pts_duration(44100, STREAM_TYPE_AAC_ADTS) == 2089);
}

TEST_CASE("SLSAudioGapFiller::frame_pts_duration: MP3 at 44.1 kHz -> 2351 PTS ticks")
{
    // 1152 samples / 44100 Hz * 90000 = 2351.
    CHECK(SLSAudioGapFiller::frame_pts_duration(44100, STREAM_TYPE_MP3_V1) == 2351);
    CHECK(SLSAudioGapFiller::frame_pts_duration(48000, STREAM_TYPE_MP3_V2) == 2160);
}

TEST_CASE("SLSAudioGapFiller::frame_pts_duration: Opus at 48 kHz -> 1800 PTS ticks")
{
    // 960 samples / 48000 Hz * 90000 = 1800.
    CHECK(SLSAudioGapFiller::frame_pts_duration(OPUS_DEFAULT_SAMPLE_RATE, STREAM_TYPE_OPUS) == 1800);
}

TEST_CASE("SLSAudioGapFiller::frame_pts_duration: rejects nonsensical sample rate")
{
    CHECK(SLSAudioGapFiller::frame_pts_duration(0, STREAM_TYPE_AAC_ADTS) == 0);
    CHECK(SLSAudioGapFiller::frame_pts_duration(-1, STREAM_TYPE_AAC_ADTS) == 0);
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: returns empty for invalid PTS")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    uint8_t cc = 0;
    auto r1 = SLSAudioGapFiller::generate_gap_packets(&t, INVALID_DTS_PTS, 90000, cc);
    CHECK(r1.empty());
    auto r2 = SLSAudioGapFiller::generate_gap_packets(&t, 1000, INVALID_DTS_PTS, cc);
    CHECK(r2.empty());
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: returns empty when format not detected")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    t.format_detected = false;
    uint8_t cc = 0;
    auto r = SLSAudioGapFiller::generate_gap_packets(&t, 0, 90000, cc);
    CHECK(r.empty());
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: gap larger than MAX_PTS_GAP is rejected")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    uint8_t cc = 0;
    // current - last > MAX_PTS_GAP (5 * 90000 = 450000). Use a clean +1s
    // over the limit so PTS wrap arithmetic isn't a factor.
    auto r = SLSAudioGapFiller::generate_gap_packets(&t, 0, MAX_PTS_GAP + 90000, cc);
    CHECK(r.empty());
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: gap of one frame is not filled")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    uint8_t cc = 0;
    // pts_delta == frame_duration -> nothing to fill (gap of zero frames).
    auto r = SLSAudioGapFiller::generate_gap_packets(&t, 0, 1920, cc);
    CHECK(r.empty());
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: PTS wrap at 2^33 is handled")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    uint8_t cc = 0;
    // Last PTS just below wrap, current PTS just after wrap. Naive subtraction
    // would be negative; the filler must treat this as a small positive delta.
    int64_t last = PTS_WRAP - 1920; // one frame from the wrap
    int64_t current = 1920;         // one frame past the wrap == 2 frames gap
    auto r = SLSAudioGapFiller::generate_gap_packets(&t, last, current, cc);
    // pts_delta after wrap fix == 3840 ticks, one frame is 1920 -> insert 1 frame.
    CHECK(r.size() == (size_t)TS_PACK_LEN);
}

TEST_CASE("SLSAudioGapFiller::generate_gap_packets: emits one TS packet per filled frame, capped at MAX_GAP_FRAMES")
{
    audio_track_info t;
    init_track(t, STREAM_TYPE_AAC_ADTS, 48000);
    uint8_t cc = 0;
    // A 4-frame gap (delta = 5 * frame_duration -> 4 fill frames).
    auto r4 = SLSAudioGapFiller::generate_gap_packets(&t, 0, 5 * 1920, cc);
    CHECK(r4.size() == (size_t)(4 * TS_PACK_LEN));

    // A gap just under MAX_PTS_GAP — at a high sample rate the frame
    // duration is small enough that the gap would otherwise produce more
    // than MAX_GAP_FRAMES, so the clamp must kick in.
    audio_track_info t2;
    init_track(t2, STREAM_TYPE_AAC_ADTS, 96000);
    uint8_t cc2 = 0;
    auto rbig = SLSAudioGapFiller::generate_gap_packets(&t2, 0, MAX_PTS_GAP - 1, cc2);
    CHECK(rbig.size() == (size_t)(MAX_GAP_FRAMES * TS_PACK_LEN));
}

TEST_CASE("SLSAudioGapFiller::detect_adts_format: parses a valid ADTS header")
{
    // ADTS: syncword FFF + MPEG-4, no CRC, profile=AAC-LC (00 -> +1 = 1),
    // sample_rate_index=4 (44100), channel_config=2 (stereo).
    // Byte 2 = profile<<6 | sr_idx<<2 | priv<<1 | ch_high
    //        = 0<<6 | 4<<2 | 0<<1 | 0 = 0x10
    // Byte 3 = ch_low<<6 | ... = (2 & 0x03)<<6 = 0x80
    uint8_t adts[7] = {0xFF, 0xF1, 0x10, 0x80, 0x00, 0x00, 0xFC};
    audio_track_info t{};
    sls_init_audio_track(&t);
    CHECK(SLSAudioGapFiller::detect_adts_format(adts, sizeof(adts), &t));
    CHECK(t.format_detected);
    CHECK(t.sample_rate == 44100);
    CHECK(t.channels == 2);
    CHECK(t.profile == 1); // AAC-LC
}

TEST_CASE("SLSAudioGapFiller::detect_adts_format: rejects garbage")
{
    audio_track_info t{};
    sls_init_audio_track(&t);
    uint8_t junk[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK_FALSE(SLSAudioGapFiller::detect_adts_format(junk, sizeof(junk), &t));
    CHECK_FALSE(t.format_detected);
}
