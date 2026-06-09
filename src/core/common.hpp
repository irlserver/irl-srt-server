
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Edward.Wu
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

#include <atomic>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <unistd.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "constants.hpp"

using namespace std;

/**********************************************
 * function return type
 */
/* error handling */
#if EDOM > 0
#define SLSERROR(e) (-(e))   ///< Returns a negative error code from a POSIX error code, to return from library functions.
#define SLSUNERROR(e) (-(e)) ///< Returns a POSIX error code from a library function error return value.
#else
/* Some platforms have E* and errno already negated. */
#define SLSERROR(e) (e)
#define SLSUNERROR(e) (e)
#endif

#define MKTAG(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((unsigned)(d) << 24))
#define SLSERRTAG(a, b, c, d) (-(int)MKTAG(a, b, c, d))

#define SLS_OK SLSERRTAG(0x0, 0x0, 0x0, 0x0)                       ///< OK
#define SLS_ERROR SLSERRTAG(0x0, 0x0, 0x0, 0x1)                    ///<
#define SLS_PENDING SLSERRTAG(0x0, 0x0, 0x0, 0x2)                  ///< async result not ready yet (e.g. player-key webhook in flight)
#define SLSERROR_BSF_NOT_FOUND SLSERRTAG(0xF8, 'B', 'S', 'F')      ///< Bitstream filter not found
#define SLSERROR_BUG SLSERRTAG('B', 'U', 'G', '!')                 ///< Internal bug, also see SLSERROR_BUG2
#define SLSERROR_BUFFER_TOO_SMALL SLSERRTAG('B', 'U', 'F', 'S')    ///< Buffer too small
#define SLSERROR_EOF SLSERRTAG('E', 'O', 'F', ' ')                 ///< End of file
#define SLSERROR_EXIT SLSERRTAG('E', 'X', 'I', 'T')                ///< Immediate exit was requested; the called function should not be restarted
#define SLSERROR_EXTERNAL SLSERRTAG('E', 'X', 'T', ' ')            ///< Generic error in an external library
#define SLSERROR_INVALIDDATA SLSERRTAG('I', 'N', 'D', 'A')         ///< Invalid data found when processing input
#define SLSERROR_OPTION_NOT_FOUND SLSERRTAG(0xF8, 'O', 'P', 'T')   ///< Option not found
#define SLSERROR_PROTOCOL_NOT_FOUND SLSERRTAG(0xF8, 'P', 'R', 'O') ///< Protocol not found
#define SLSERROR_STREAM_NOT_FOUND SLSERRTAG(0xF8, 'S', 'T', 'R')   ///< Stream of the StreamID not found
#define SLSERROR_UNKNOWN SLSERRTAG('U', 'N', 'K', 'N')             ///< Unknown error, typically from an external library

#define SLSERROR_INVALID_SOCK SLSERRTAG('I', 'N', 'V', 'S') ///< Unknown error, typically from an external library
/**
 * end
 **********************************************/

//#define SAFE_CREATE(p, class_name) { if (!p) new class_name(); }
#define SAFE_DELETE(p) \
    {                  \
        if (p)         \
        {              \
            delete p;  \
            p = NULL;  \
        }              \
    }
#define msleep(ms) usleep(ms * 1000)

#define TS_PACK_LEN 188
#define TS_UDP_LEN 1316 // 7*188
#define SHORT_STR_MAX_LEN 256
#define STR_MAX_LEN 2048
#define HOST_MAX_LEN 256
#define URL_MAX_LEN STR_MAX_LEN
#define STR_DATE_TIME_LEN 32
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#define IP_MAX_LEN INET6_ADDRSTRLEN

int64_t sls_gettime_ms(void); // rturn millisecond
int64_t sls_gettime(void);    // rturn microsecond
void sls_gettime_fmt(char *dst, size_t dst_len, int64_t cur_time_sec, const char *fmt);
void sls_gettime_default_string(char *cur_time_buf, size_t cur_time_buf_len);
char *sls_strupper(char *str);
char *sls_strlower(char *str);
void sls_remove_marks(char *s);
bool sls_is_safe_name(const char *s);

uint32_t sls_hash_key(const char *data, size_t len);
int sls_gethostbyname(const char *hostname, char *ip);
int sls_mkdir_p(const char *path);

static char pid_file_name[STR_MAX_LEN] = DEFAULT_PIDFILE;
int sls_load_pid_filename();
int sls_reload_pid();
int sls_read_pid();
int sls_write_pid(int pid);
int sls_remove_pid();
int sls_send_cmd(const char *cmd);
int sls_drop_privileges(const char *user, const char *group);

std::string sls_trim(const std::string &str);
void sls_split_string(std::string str, std::string separator, std::vector<std::string> &result, int count = -1);
std::string sls_find_string(std::vector<std::string> &src, std::string &dst, bool caseSensitive = true);

struct stat_info_t
{
    int port;
    std::string role;
    std::string pub_domain_app;
    std::string stream_name;
    std::string url;
    std::string remote_ip;
    int remote_port;
    std::string start_time;
    int kbitrate;
};

/*
 * parse ts packet
 */

#define TS_SYNC_BYTE 0x47
#define TS_PACK_LEN 188
#define INVALID_PID -1
#define PAT_PID 0
#define INVALID_DTS_PTS -1
#define MAX_PES_PAYLOAD 200 * 1024

// Maximum number of audio tracks we can track per stream
#define MAX_AUDIO_TRACKS 4

// Per-audio-track state for gap filling
struct audio_track_info
{
    int pid;                    // Audio elementary stream PID (from PMT)
    int stream_type;            // Stream type (0x0F=AAC, 0x03=MP3, 0x06=private/Opus, etc.)
    uint8_t stream_id;          // PES stream_id for this track (0xC0, 0xC1, etc.)
    int64_t last_pts;           // Last seen audio PTS (90kHz clock)
    uint8_t cc;                 // Continuity counter from the actual stream
    uint8_t expected_cc;        // Expected CC for rewriting (sequential, no gaps)
    bool cc_initialized;        // Whether expected_cc has been initialized from stream
    bool in_gap;                // True after gap detection until a clean PES start arrives
    int sample_rate;            // Detected sample rate (e.g. 44100, 48000)
    int channels;               // Detected channel count (1=mono, 2=stereo, etc.)
    int sample_rate_index;      // ADTS sample rate index (0-12), or MP3 sr index
    int channel_config;         // ADTS channel configuration (1-7)
    int profile;                // AAC profile (1=AAC-LC, etc.), or MP3 layer
    int bitrate_index;          // MP3 bitrate index (for frame size calculation)
    bool format_detected;       // Whether we've captured the audio format from headers
    // Counter fields are atomic so the HTTP /stats path can read them
    // without taking CSLSMapData::m_rwclock for any non-trivial duration.
    // That removes the stats-vs-data-path lock contention that manifested
    // as periodic msRcvBuf spikes on viewers.
    std::atomic<uint64_t> gap_count{0};         // Number of detected PTS gaps on this track
    std::atomic<uint64_t> silent_frames_inserted{0};  // Number of silent frames generated for this track
    std::atomic<uint64_t> silent_packets_inserted{0}; // Number of TS packets inserted for this track
    std::atomic<uint64_t> silent_bytes_inserted{0};   // Number of TS bytes inserted for this track
    int64_t last_gap_pts_delta; // Most recent detected PTS delta that triggered filling
    int last_gap_frames;        // Number of frames inserted for the most recent detected gap
    std::atomic<uint64_t> partial_pes_dropped{0}; // Number of partial PES continuation packets dropped
};

struct ts_info
{
    int es_pid;
    int64_t dts;
    int64_t pts;
    bool need_spspps;
    int sps_len;
    uint8_t sps[TS_PACK_LEN];
    int pps_len;
    uint8_t pps[TS_PACK_LEN];
    uint8_t ts_data[TS_UDP_LEN];
    uint8_t pat[TS_PACK_LEN];
    int pat_len;
    int pmt_pid;
    uint8_t pmt[TS_PACK_LEN];
    int pmt_len;

    // Audio gap filling fields
    bool audio_gap_fill_enabled; // Whether gap filling is enabled for this stream
    bool pmt_parsed;            // Whether PMT has been parsed for audio PIDs
    int audio_track_count;      // Number of audio tracks found in PMT
    // Atomic counters — see audio_track_info above for rationale.
    std::atomic<uint64_t> gap_count{0};         // Total number of detected audio gaps across all tracks
    std::atomic<uint64_t> silent_frames_inserted{0};  // Total number of silent frames inserted
    std::atomic<uint64_t> silent_packets_inserted{0}; // Total number of TS packets inserted
    std::atomic<uint64_t> silent_bytes_inserted{0};   // Total number of TS bytes inserted
    audio_track_info audio_tracks[MAX_AUDIO_TRACKS]; // Per-track state
};
void sls_init_ts_info(ts_info *ti);
void sls_init_audio_track(audio_track_info *at);
int sls_parse_ts_info(const uint8_t *packet, ts_info *ti);
int sls_parse_pmt_for_audio(const uint8_t *pmt_data, int len, ts_info *ti);
