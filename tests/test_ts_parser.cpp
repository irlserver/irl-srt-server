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

    // A real PAT+PMT must parse without any out-of-bounds read (the assertion
    // under -DSLS_SANITIZE=ON) and without put() reporting failure.
    REQUIRE(m.put(key, buf.data(), (int)buf.size()) >= 0);
}

// --- ingest continuity tracking ---

namespace
{
std::vector<uint8_t> cc_packet(int pid, uint8_t cc, bool has_payload = true, bool declared_disc = false)
{
    std::vector<uint8_t> pkt(TS_PACK_LEN, 0xFF);
    pkt[0] = 0x47;
    pkt[1] = (uint8_t)((pid >> 8) & 0x1F);
    pkt[2] = (uint8_t)(pid & 0xFF);
    int afc = declared_disc ? 0x3 : (has_payload ? 0x1 : 0x2);
    pkt[3] = (uint8_t)(((afc & 0x3) << 4) | (cc & 0x0F));
    if (afc & 0x2)
    {
        pkt[4] = 1;
        pkt[5] = declared_disc ? 0x80 : 0x00;
    }
    return pkt;
}

std::vector<uint8_t> concat(const std::vector<std::vector<uint8_t>> &packets)
{
    std::vector<uint8_t> out;
    for (const auto &p : packets)
        out.insert(out.end(), p.begin(), p.end());
    return out;
}
} // namespace

TEST_CASE("sls_ts_check_continuity: sequential counters and duplicates are clean")
{
    ts_cc_state st;
    sls_init_ts_cc_state(&st);

    auto chunk = concat({cc_packet(0x101, 0), cc_packet(0x101, 1), cc_packet(0x101, 2),
                         cc_packet(0x101, 2), // spec-legal duplicate
                         cc_packet(0x101, 3), cc_packet(0x102, 5), cc_packet(0x102, 6)});
    CHECK(sls_ts_check_continuity(chunk.data(), (int)chunk.size(), &st) == 0);

    // Wrap 15 -> 0 is sequential.
    ts_cc_state st2;
    sls_init_ts_cc_state(&st2);
    auto wrap = concat({cc_packet(0x101, 15), cc_packet(0x101, 0)});
    CHECK(sls_ts_check_continuity(wrap.data(), (int)wrap.size(), &st2) == 0);
}

TEST_CASE("sls_ts_check_continuity: breaks are detected and tolerated cases are not")
{
    ts_cc_state st;
    sls_init_ts_cc_state(&st);

    auto ok = concat({cc_packet(0x101, 0), cc_packet(0x101, 1)});
    CHECK(sls_ts_check_continuity(ok.data(), (int)ok.size(), &st) == 0);

    // 1 -> 5 is a break (packets 2..4 lost at ingest).
    auto hole = cc_packet(0x101, 5);
    CHECK(sls_ts_check_continuity(hole.data(), (int)hole.size(), &st) == 1);

    // The tracker resynced to 5, so 6 is clean again.
    auto next = cc_packet(0x101, 6);
    CHECK(sls_ts_check_continuity(next.data(), (int)next.size(), &st) == 0);

    // A muxer-declared discontinuity is not a break.
    auto declared = cc_packet(0x101, 12, true, true);
    CHECK(sls_ts_check_continuity(declared.data(), (int)declared.size(), &st) == 0);

    // Null packets and payload-less packets are ignored.
    auto noise = concat({cc_packet(0x1FFF, 9), cc_packet(0x101, 13, false)});
    CHECK(sls_ts_check_continuity(noise.data(), (int)noise.size(), &st) == 0);
}
