// libFuzzer target for the MPEG-TS parser (T6 length-driven hardening, c350a7c).
//
// The parser was made length-driven so a crafted packet whose declared fields
// point past the buffer is rejected instead of read out of bounds. This harness
// locks that: it feeds the raw, exact-sized libFuzzer buffer straight into
// sls_parse_ts_info (which drives the PAT / PMT / PES path) and into the
// standalone sls_parse_pmt_for_audio entry. Because libFuzzer poisons the bytes
// immediately after `data[size-1]`, any regression to an unbounded read trips
// AddressSanitizer and the fuzzer records a crash. It adds NO parser logic.
#include <climits>
#include <cstddef>
#include <cstdint>

#include "common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // sls_parse_ts_info / sls_parse_pmt_for_audio take an int length; a corpus
    // file larger than INT_MAX would wrap negative. Skip it — the parser would
    // reject a negative length anyway — so the narrowing cast is well-defined.
    if (size > static_cast<size_t>(INT_MAX))
        return 0;
    const int len = static_cast<int>(size);

    // Full single-packet path: sync-byte, PUSI, PID routing, adaptation-field
    // skip, then PAT (sls_parse_pat) or PES (sls_pes2es) by PID.
    ts_info ti;
    sls_init_ts_info(&ti);
    sls_parse_ts_info(data, len, &ti);

    // Reach the PMT audio-descriptor walk directly, independent of TS framing,
    // so the fuzzer can drive sls_parse_pmt_for_audio's section/ES-loop bounds
    // without first having to satisfy the outer TS header checks.
    ts_info ti_pmt;
    sls_init_ts_info(&ti_pmt);
    sls_parse_pmt_for_audio(data, len, &ti_pmt);

    return 0;
}
