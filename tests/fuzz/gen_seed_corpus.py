#!/usr/bin/env python3
"""Regenerate the libFuzzer seed corpora for the three boundary parsers.

The seeds are committed under tests/fuzz/corpus/{ts,streamid,conf}/ so a short
`./fuzz_* -max_total_time=30 corpus/<x>/` run starts from real, valid inputs
(coverage-guided fuzzing converges far faster from a representative corpus than
from an empty one). This script is the reproducible source of those bytes.

The TS packets mirror the make_pat / make_pmt / make_audio_overrun builders in
tests/test_ts_parser.cpp byte-for-byte; the streamid and conf seeds mirror the
fixtures in tests/test_sls_sid.cpp and src/tests/test_conf_validation.cpp. Run
from anywhere: it writes relative to this file.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")

TS_PACK_LEN = 188
TS_SYNC_BYTE = 0x47


# ---- MPEG-TS packet builders (mirror tests/test_ts_parser.cpp) --------------
def make_packet(b1, b2, b3):
    pkt = bytearray(TS_PACK_LEN)
    pkt[0] = TS_SYNC_BYTE
    pkt[1] = b1
    pkt[2] = b2
    pkt[3] = b3
    return pkt


def make_pat(pmt_pid):
    pkt = make_packet(0x40, 0x00, 0x10)  # PUSI, PID 0, payload
    pkt[4] = 0x00
    pkt[5] = 0x00
    pkt[6] = 0xB0
    pkt[7] = 0x0D
    pkt[8] = 0x00
    pkt[9] = 0x01
    pkt[10] = 0xC1
    pkt[11] = 0x00
    pkt[12] = 0x00
    pkt[13] = 0x00
    pkt[14] = 0x01
    pkt[15] = 0xE0 | ((pmt_pid >> 8) & 0x1F)
    pkt[16] = pmt_pid & 0xFF
    return pkt


def make_pmt(pmt_pid, audio_pid):
    pkt = make_packet(0x40 | ((pmt_pid >> 8) & 0x1F), pmt_pid & 0xFF, 0x10)
    pkt[4] = 0x00
    pkt[5] = 0x02
    pkt[6] = 0xB0
    pkt[7] = 0x12
    pkt[8] = 0x00
    pkt[9] = 0x01
    pkt[10] = 0xC1
    pkt[11] = 0x00
    pkt[12] = 0x00
    pkt[13] = 0xE0
    pkt[14] = 0x00
    pkt[15] = 0xF0
    pkt[16] = 0x00
    pkt[17] = 0x0F  # stream_type = AAC (audio)
    pkt[18] = 0xE0 | ((audio_pid >> 8) & 0x1F)
    pkt[19] = audio_pid & 0xFF
    pkt[20] = 0xF0
    pkt[21] = 0x00
    return pkt


def make_audio_overrun(audio_pid):
    pkt = make_packet(0x40 | ((audio_pid >> 8) & 0x1F), audio_pid & 0xFF, 0x30)
    pkt[4] = 173  # adaptation_field_length -> pos = 178
    pos = 178
    pkt[pos + 0] = 0x00
    pkt[pos + 1] = 0x00
    pkt[pos + 2] = 0x01  # PES start code
    pkt[pos + 3] = 0xC0  # audio stream_id
    pkt[pos + 4] = 0x00
    pkt[pos + 5] = 0x00
    pkt[pos + 6] = 0x80
    pkt[pos + 7] = 0x80  # PTS present
    pkt[pos + 8] = 0x05
    pkt[pos + 9] = 0x21
    return pkt


def make_video_pes(es_pid):
    # A clean PES start packet (payload-only) that routes through sls_pes2es.
    pkt = make_packet(0x40 | ((es_pid >> 8) & 0x1F), es_pid & 0xFF, 0x10)
    pos = 4
    pkt[pos + 0] = 0x00
    pkt[pos + 1] = 0x00
    pkt[pos + 2] = 0x01  # PES start code
    pkt[pos + 3] = 0xE0  # video stream_id
    pkt[pos + 4] = 0x00
    pkt[pos + 5] = 0x00
    pkt[pos + 6] = 0x80
    pkt[pos + 7] = 0x80  # PTS present
    pkt[pos + 8] = 0x05
    pkt[pos + 9] = 0x21
    pkt[pos + 10] = 0x00
    pkt[pos + 11] = 0x01
    pkt[pos + 12] = 0x00
    pkt[pos + 13] = 0x01
    return pkt


def write(rel, data):
    path = os.path.join(CORPUS, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, (bytes, bytearray)) else data.encode())
    return path


def gen_ts():
    pat = make_pat(0x100)
    pmt = make_pmt(0x100, 0x101)
    write("ts/pat.bin", bytes(pat))
    write("ts/pmt.bin", bytes(pmt))
    write("ts/pat_pmt.bin", bytes(pat) + bytes(pmt))
    write("ts/video_pes.bin", bytes(make_video_pes(0x100)))
    # PAT + PMT + 4 null packets + the MEM-1 audio-overrun packet (the 7-packet
    # buffer shape from the check_audio_gap test).
    null_pkt = make_packet(0x1F, 0xFF, 0x00)
    multi = bytes(pat) + bytes(pmt)
    multi += bytes(null_pkt) * 4
    multi += bytes(make_audio_overrun(0x101))
    write("ts/pat_pmt_audio.bin", multi)


def gen_streamid():
    seeds = {
        "valid_std": "#!::h=example.com,sls_app=live,r=feed1",
        "valid_bare": "example.com/live/feed1",
        "valid_dotnames": "example.com/live/Feed.01",
        "whitespace": "#!::h= example.com , sls_app= live , r= feed1 ",
        "reordered": "#!::sls_app=live,r=feed1,h=example.com",
        "traversal_std": "#!::h=..,sls_app=live,r=feed1",
        "traversal_bare": "../../etc/passwd",
        "url_inject": "example.com/live/feed1?evil=1",
        "amp_inject": "example.com/live/feed&1",
        "missing_key": "#!::h=example.com,sls_app=live",
        "not_a_streamid": "not-a-streamid",
        "control_byte": b"#!::h=example.com,sls_app=li\x01ve,r=feed1",
        "tab_byte": b"#!::h=example.com,sls_app=li\tve,r=feed1",
        "empty": b"",
    }
    for name, val in seeds.items():
        write("streamid/" + name, val)


def gen_conf():
    seeds = {
        "single": "4000",
        "list": "4000,4010,5000-5005",
        "range": "5000-5010",
        "single_range": "5005-5005",
        "dedupe": "5000-5002,5001",
        "whitespace": " 4000 , 4001 ",
        "reversed_range": "5005-5000",
        "trailing_comma": "4000,4001,",
        "port_zero": "0",
        "port_overflow": "65536",
        "non_numeric": "abc",
        "dash_only": "40-",
        "leading_dash": "-40",
        "bool_true": "true",
        "bool_false": "false",
        "int_val": "12345",
        "double_val": "3.14",
        "quoted": '"hello world"',
        "upstreams": "a:1 b:2 c:3",
        "empty": "",
    }
    for name, val in seeds.items():
        write("conf/" + name, val)


def main():
    gen_ts()
    gen_streamid()
    gen_conf()
    total = sum(len(files) for _, _, files in os.walk(CORPUS))
    print("wrote %d seed files under %s" % (total, CORPUS))


if __name__ == "__main__":
    main()
