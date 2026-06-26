// libFuzzer target for the SRT streamid parser and its handshake-time
// safety/validation path (sls_sid.cpp).
//
// The streamid is attacker-controlled: it arrives in the SRT handshake before
// any accept. sls_validate_sid_format must reject path separators, control
// bytes, bare "."/".." and url-significant characters, and sls_canonical_sid_key
// must collapse byte-variants of one logical streamid to a single cache key so a
// misbehaving peer cannot bypass the negative-auth cache. This harness drives
// all of those on the raw fuzz bytes. It adds NO validation logic — it only
// calls the shipping functions, so the rejection semantics stay exactly as is.
#include <cstddef>
#include <cstdint>
#include <string>

#include "sls_sid.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // On the wire a streamid is always a NUL-terminated C string, so mirror that
    // exactly: copy into a std::string (which adds the terminator) and hand the
    // parser its c_str(). An embedded NUL truncates here just as it would in the
    // real libsrt path, so the harness faithfully reproduces production input.
    const std::string sid(reinterpret_cast<const char *>(data), size);

    // Parse -> map of components (the "#!::k=v,..." and bare "h/app/r" forms).
    sls_parse_streamid(sid.c_str());

    // The security gate the publisher/player listen callbacks run pre-accept.
    sls_validate_sid_format(sid.c_str());

    // Canonicalization used to build the negative-auth cache key.
    sls_canonical_sid_key(sid);

    return 0;
}
