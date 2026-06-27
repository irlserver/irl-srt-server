#include "doctest.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "SLSMapData.hpp"
#include "common.hpp"

// T6: the MPEG-TS parser is now length-driven. Each test feeds a crafted packet
// whose declared fields point past the real buffer. The buffers are exact-sized
// heap allocations, so any regression to an unbounded read trips AddressSanitizer
// and aborts the case — a clean pass under -DSLS_SANITIZE=ON is the assertion.

namespace
{
std::vector<uint8_t> make_packet(uint8_t b1, uint8_t b2, uint8_t b3)
{
    std::vector<uint8_t> pkt(TS_PACK_LEN, 0x00);
    pkt[0] = TS_SYNC_BYTE;
    pkt[1] = b1;
    pkt[2] = b2;
    pkt[3] = b3;
    return pkt;
}

std::vector<uint8_t> make_pat(int pmt_pid)
{
    std::vector<uint8_t> pkt = make_packet(0x40, 0x00, 0x10); // PUSI, PID 0, payload
    pkt[4] = 0x00;                                            // pointer_field
    pkt[5] = 0x00;                                            // table_id (PAT)
    pkt[6] = 0xB0;                                            // section_syntax + section_length hi nibble = 0
    pkt[7] = 0x0D;                                            // section_length = 13
    pkt[8] = 0x00;
    pkt[9] = 0x01;  // transport_stream_id
    pkt[10] = 0xC1; // version / current_next_indicator
    pkt[11] = 0x00; // section_number
    pkt[12] = 0x00; // last_section_number
    pkt[13] = 0x00;
    pkt[14] = 0x01; // program_number = 1 (non-zero -> sets pmt_pid)
    pkt[15] = 0xE0 | ((pmt_pid >> 8) & 0x1F);
    pkt[16] = pmt_pid & 0xFF;
    return pkt;
}

std::vector<uint8_t> make_pmt(int pmt_pid, int audio_pid)
{
    std::vector<uint8_t> pkt = make_packet(0x40 | ((pmt_pid >> 8) & 0x1F), pmt_pid & 0xFF, 0x10);
    pkt[4] = 0x00; // pointer_field
    pkt[5] = 0x02; // table_id (PMT)
    pkt[6] = 0xB0; // section_length hi nibble = 0
    pkt[7] = 0x12; // section_length = 18
    pkt[8] = 0x00;
    pkt[9] = 0x01;  // program_number
    pkt[10] = 0xC1; // version / current_next_indicator
    pkt[11] = 0x00;
    pkt[12] = 0x00;
    pkt[13] = 0xE0;
    pkt[14] = 0x00; // PCR_PID
    pkt[15] = 0xF0;
    pkt[16] = 0x00; // program_info_length = 0
    pkt[17] = 0x0F; // stream_type = AAC (audio)
    pkt[18] = 0xE0 | ((audio_pid >> 8) & 0x1F);
    pkt[19] = audio_pid & 0xFF;
    pkt[20] = 0xF0;
    pkt[21] = 0x00; // es_info_length = 0
    return pkt;
}

// Audio TS packet whose adaptation field pushes the PES payload to offset 178,
// so the 5-byte PTS read at pkt[187..191] would overrun the 188-byte packet
// unless the MEM-1 bound (pos + 13 < pkt_len) clamps it.
std::vector<uint8_t> make_audio_overrun(int audio_pid)
{
    std::vector<uint8_t> pkt =
        make_packet(0x40 | ((audio_pid >> 8) & 0x1F), audio_pid & 0xFF, 0x30); // adaptation+payload
    pkt[4] = 173; // adaptation_field_length -> pos = 4 + 1 + 173 = 178
    const int pos = 178;
    pkt[pos + 0] = 0x00;
    pkt[pos + 1] = 0x00;
    pkt[pos + 2] = 0x01; // PES start code
    pkt[pos + 3] = 0xC0; // audio stream_id
    pkt[pos + 4] = 0x00;
    pkt[pos + 5] = 0x00; // PES packet length
    pkt[pos + 6] = 0x80; // PES header flags 1
    pkt[pos + 7] = 0x80; // PES header flags 2 -> PTS present
    pkt[pos + 8] = 0x05; // PES_header_data_length
    pkt[pos + 9] = 0x21; // first PTS byte (pkt[187]); pkt[188..191] are OOB
    return pkt;
}
} // namespace

TEST_CASE("sls_parse_ts_info: crafted PAT section_length=0xFFF stays in bounds")
{
    std::vector<uint8_t> pkt = make_packet(0x40, 0x00, 0x10);
    pkt[4] = 0x00; // pointer_field
    pkt[5] = 0x00; // table_id
    pkt[6] = 0x0F; // section_length hi nibble = 0xF
    pkt[7] = 0xFF; // section_length lo -> 0xFFF (4095)

    ts_info ti;
    sls_init_ts_info(&ti);
    CHECK(sls_parse_ts_info(pkt.data(), TS_PACK_LEN, &ti) == SLS_OK);
}

TEST_CASE("sls_parse_ts_info: PAT with adaptation_field_length=182 stays in bounds")
{
    std::vector<uint8_t> pkt = make_packet(0x40, 0x00, 0x30); // adaptation+payload
    pkt[4] = 182; // pos = 4 + 183 = 187, then +1 pointer -> 188, PAT len = 0

    ts_info ti;
    sls_init_ts_info(&ti);
    CHECK(sls_parse_ts_info(pkt.data(), TS_PACK_LEN, &ti) == SLS_ERROR);
}

TEST_CASE("sls_parse_ts_info: truncated PES PTS stays in bounds")
{
    const int es_pid = 0x100;
    std::vector<uint8_t> pkt = make_packet(0x40 | ((es_pid >> 8) & 0x1F), es_pid & 0xFF, 0x30);
    pkt[4] = 170; // pos = 4 + 171 = 175, only 13 payload bytes remain
    const int pos = 175;
    pkt[pos + 0] = 0x00;
    pkt[pos + 1] = 0x00;
    pkt[pos + 2] = 0x01; // PES start code
    pkt[pos + 3] = 0xE0; // video stream_id
    pkt[pos + 4] = 0x00;
    pkt[pos + 5] = 0x00;
    pkt[pos + 6] = 0x80;
    pkt[pos + 7] = 0x80; // PTS present, but the 5 PTS bytes run past the packet
    pkt[pos + 8] = 0x05;

    ts_info ti;
    sls_init_ts_info(&ti);
    CHECK(sls_parse_ts_info(pkt.data(), TS_PACK_LEN, &ti) == SLS_ERROR);
}

TEST_CASE("sls_parse_ts_info: short buffers (< one packet) are rejected, not parsed")
{
    std::vector<uint8_t> pkt = make_pat(0x100);
    ts_info ti;
    sls_init_ts_info(&ti);
    for (int len : {0, 1, 4, 100, 187})
    {
        CHECK(sls_parse_ts_info(pkt.data(), len, &ti) == SLS_ERROR);
    }
}

TEST_CASE("CSLSMapData::put tolerates arbitrary read lengths without OOB")
{
    CSLSMapData m;
    m.set_caps(0, 0);
    char key[] = "app/lens";
    REQUIRE(m.add(key) == SLS_OK);

    // Over-allocate so put()'s internal array copy of `len` bytes is always safe;
    // check_ts_info must only ever touch the complete 188-byte packets within len.
    std::vector<char> buf(TS_UDP_LEN + TS_PACK_LEN, 0);
    for (int len : {1, 4, 187, 188, 189, 1315, 1316})
    {
        m.put(key, buf.data(), len);
    }
    CHECK(true);
}

TEST_CASE("CSLSMapData::put parses a well-formed PAT+PMT (length-driven, no regression)")
{
    CSLSMapData m;
    m.set_caps(0, 0);
    char key[] = "app/legit";
    REQUIRE(m.add(key) == SLS_OK);

    std::vector<uint8_t> pat = make_pat(0x100);
    std::vector<uint8_t> pmt = make_pmt(0x100, 0x101);
    std::vector<char> buf(2 * TS_PACK_LEN, 0);
    memcpy(buf.data(), pat.data(), TS_PACK_LEN);
    memcpy(buf.data() + TS_PACK_LEN, pmt.data(), TS_PACK_LEN);

    REQUIRE(m.put(key, buf.data(), (int)buf.size()) >= 0);

    CSLSMapData::AudioGapStreamStats stats;
    REQUIRE(m.get_audio_gap_stats(key, stats));
    CHECK(stats.pmt_parsed);
    CHECK(stats.audio_track_count == 1);
    REQUIRE(stats.tracks.size() == 1);
    CHECK(stats.tracks[0].pid == 0x101);
}

TEST_CASE("CSLSMapData::check_audio_gap bounds the PES/PTS read (MEM-1)")
{
    CSLSMapData m;
    m.set_caps(0, 0);
    char key[] = "app/mem1";
    REQUIRE(m.add(key) == SLS_OK);
    m.set_audio_gap_fill(key, true);

    std::vector<uint8_t> pat = make_pat(0x100);
    std::vector<uint8_t> pmt = make_pmt(0x100, 0x101);
    std::vector<uint8_t> aud = make_audio_overrun(0x101);

    // Exact 7-packet buffer: a regression reads aud's PTS at buf[1316..1319],
    // one past the end, which AddressSanitizer flags.
    std::vector<char> buf(7 * TS_PACK_LEN, 0);
    memcpy(buf.data() + 0 * TS_PACK_LEN, pat.data(), TS_PACK_LEN);
    memcpy(buf.data() + 1 * TS_PACK_LEN, pmt.data(), TS_PACK_LEN);
    memcpy(buf.data() + 6 * TS_PACK_LEN, aud.data(), TS_PACK_LEN);

    REQUIRE(m.put(key, buf.data(), (int)buf.size()) >= 0);

    CSLSMapData::AudioGapStreamStats stats;
    REQUIRE(m.get_audio_gap_stats(key, stats));
    CHECK(stats.pmt_parsed);
    CHECK(stats.audio_track_count == 1);
}
