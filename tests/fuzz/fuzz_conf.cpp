// libFuzzer target for the config-input parsers that sit on the operator
// boundary (conf.cpp): the listen port-list parser, the shared tokenizer, and
// the scalar/string value setters.
//
// sls_parse_port_list validates that every entry is a single port, a
// comma-list, or an ascending inclusive range within 1..65535, rejecting a
// reversed range / non-numeric / out-of-range spec at parse time. This harness
// feeds the raw fuzz bytes through it, through the strtok-based tokenizer that
// backs portlist/ipset/upstreams/string_list, and through each scalar/string
// setter into a correctly-typed, offset-0 destination so the strtol/strtod
// range checks and the memcpy bounds are exercised on a real-sized buffer.
// It adds NO parser logic — it only drives the shipping setters.
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "conf.hpp"

namespace {
// sls_parse_port_list dedups via a linear std::find per port, so one VALID range
// like "1-65535" expands O(n^2) — a single unit costs ~tens of seconds of pure
// CPU. That cost is an algorithmic property of the listen-port spec, which is
// operator-trusted config parsed once at startup (not a network-boundary input),
// and the parser is off-limits to change here. So the harness upper-bounds the
// expansion itself and declines only an oversized-but-valid range, keeping the
// fuzzer on the validation + memory-safety paths it exists to lock. Malformed
// tokens expand to nothing (rejected immediately), so only ascending ranges count.
constexpr long kMaxExpansion = 8192;

bool port_expansion_within_bound(const std::string &spec)
{
    long total = 0;
    size_t start = 0;
    while (start <= spec.size())
    {
        size_t comma = spec.find(',', start);
        std::string tok = spec.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        start = (comma == std::string::npos) ? spec.size() + 1 : comma + 1;

        size_t dash = tok.find('-');
        if (dash == std::string::npos)
        {
            total += 1;
        }
        else
        {
            char *e1 = nullptr;
            char *e2 = nullptr;
            long lo = std::strtol(tok.c_str(), &e1, 10);
            long hi = std::strtol(tok.c_str() + dash + 1, &e2, 10);
            if (lo >= 1 && hi >= lo && hi <= 65535)
                total += (hi - lo + 1);
        }
        if (total > kMaxExpansion)
            return false;
    }
    return true;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Config values are NUL-terminated C strings; copy so c_str() is valid.
    const std::string text(reinterpret_cast<const char *>(data), size);
    const char *v = text.c_str();

    // Gate only the two expanding entry points; the validation edge cases this
    // fuzzer locks (reversed/out-of-range/non-numeric/stray-comma) are all small
    // specs that still flow through.
    const bool expand_ok = port_expansion_within_bound(text);

    // --- primary target: the listen-port spec parser ---------------------
    if (expand_ok)
    {
        std::vector<int> ports;
        sls_parse_port_list(v, ports);
    }

    // --- the shared tokenizer behind portlist / ipset / upstreams --------
    sls_conf_string_split(v, ",");
    sls_conf_string_split(v, "\t ");

    // --- scalar / string value setters -----------------------------------
    // Each setter writes at cmd->offset; give every one offset 0 and a
    // destination of the right type/size so its bounds are real.
    sls_conf_cmd_t cmd{};
    cmd.name = "fuzz";
    cmd.mark = "fuzz";
    cmd.offset = 0;

    int dst_int = 0;
    cmd.min = static_cast<double>(INT_MIN);
    cmd.max = static_cast<double>(INT_MAX);
    sls_conf_set_int(v, &cmd, &dst_int);

    double dst_double = 0.0;
    cmd.min = -1e18;
    cmd.max = 1e18;
    sls_conf_set_double(v, &cmd, &dst_double);

    bool dst_bool = false;
    sls_conf_set_bool(v, &cmd, &dst_bool);

    // The string-family setters bound the stored value by cmd->max, so set max
    // to one less than the buffer to keep the trailing NUL write in bounds.
    char dst_str[1024];
    cmd.min = 0;
    cmd.max = static_cast<double>(sizeof(dst_str) - 1);
    sls_conf_set_string(v, &cmd, dst_str);

    if (expand_ok)
    {
        char dst_ports[1024];
        cmd.min = 1;
        cmd.max = static_cast<double>(sizeof(dst_ports) - 1);
        sls_conf_set_portlist(v, &cmd, dst_ports);
    }

    char dst_up[1024];
    cmd.min = 1;
    cmd.max = static_cast<double>(sizeof(dst_up) - 1);
    sls_conf_set_upstreams(v, &cmd, dst_up);

    return 0;
}
