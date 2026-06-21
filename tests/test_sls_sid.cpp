#include "doctest.h"

#include "sls_sid.hpp"

// These tests pin the contract that the SRT handshake callback and the
// post-accept handler rely on. A regression here means a malformed or unsafe
// streamid could either be accepted by the listener (security) or a valid one
// could be rejected mid-handshake (correctness for legitimate publishers).

TEST_CASE("sls_validate_sid_format: well-formed standard #!:: form is accepted")
{
    // Standard SRT extension form used by the irl streamer/relay path.
    CHECK(sls_validate_sid_format("#!::h=example.com,sls_app=live,r=feed1"));
}

TEST_CASE("sls_validate_sid_format: well-formed bare host/app/stream is accepted")
{
    CHECK(sls_validate_sid_format("example.com/live/feed1"));
}

TEST_CASE("sls_validate_sid_format: empty / null streamid is rejected")
{
    CHECK_FALSE(sls_validate_sid_format(nullptr));
    CHECK_FALSE(sls_validate_sid_format(""));
}

TEST_CASE("sls_validate_sid_format: missing required keys is rejected")
{
    // Missing r= component.
    CHECK_FALSE(sls_validate_sid_format("#!::h=example.com,sls_app=live"));
    // Bare form with fewer than three slash-separated parts.
    CHECK_FALSE(sls_validate_sid_format("example.com/live"));
    CHECK_FALSE(sls_validate_sid_format("example.com"));
}

TEST_CASE("sls_validate_sid_format: path traversal in any component is rejected")
{
    // sls_is_safe_name explicitly rejects "." and ".." as a whole component
    // and any '/' or '\\' embedded inside a component. The #!:: form does
    // not allow '/' inside a value (the parser splits on ',' first), so we
    // pin '..' in each slot.
    CHECK_FALSE(sls_validate_sid_format("#!::h=..,sls_app=live,r=feed1"));
    CHECK_FALSE(sls_validate_sid_format("#!::h=example.com,sls_app=..,r=feed1"));
    CHECK_FALSE(sls_validate_sid_format("#!::h=example.com,sls_app=live,r=.."));
}

TEST_CASE("sls_validate_sid_format: control characters in a component are rejected")
{
    // sls_is_safe_name rejects bytes < 0x20 and 0x7f. A bare tab in a value
    // would survive the split (',' / '=' parser) but must not pass validation.
    CHECK_FALSE(sls_validate_sid_format("#!::h=example.com,sls_app=li\x01ve,r=feed1"));
}

TEST_CASE("sls_validate_sid_format: surrounding whitespace is trimmed before validation")
{
    // The parser trims values so a stray paste artifact does not change the
    // resulting on_event_url. A space-padded but otherwise valid streamid
    // must still validate.
    CHECK(sls_validate_sid_format("#!::h= example.com , sls_app= live , r= feed1 "));
}

TEST_CASE("sls_parse_streamid: standard form yields h / sls_app / r")
{
    auto m = sls_parse_streamid("#!::h=example.com,sls_app=live,r=feed1");
    CHECK(m["h"] == "example.com");
    CHECK(m["sls_app"] == "live");
    CHECK(m["r"] == "feed1");
}

TEST_CASE("sls_parse_streamid: bare host/app/stream yields the same key set")
{
    auto m = sls_parse_streamid("example.com/live/feed1");
    CHECK(m["h"] == "example.com");
    CHECK(m["sls_app"] == "live");
    CHECK(m["r"] == "feed1");
}

TEST_CASE("sls_parse_streamid: null / empty input returns an empty map")
{
    CHECK(sls_parse_streamid(nullptr).empty());
    CHECK(sls_parse_streamid("").empty());
}

TEST_CASE("sls_canonical_sid_key: byte variants of the same streamid collide")
{
    // Trailing whitespace, k/v reordering, and the bare vs. standard form
    // are all the same logical (h, sls_app, r) tuple. Negative-cache key
    // collisions would let a misbehaving client bypass the reject cache,
    // so all of these must reduce to the same canonical key.
    const std::string canon = sls_canonical_sid_key("#!::h=example.com,sls_app=live,r=feed1");
    CHECK(canon == sls_canonical_sid_key("#!::h=example.com , sls_app=live , r=feed1"));
    CHECK(canon == sls_canonical_sid_key("#!::sls_app=live,r=feed1,h=example.com"));
    CHECK(canon == sls_canonical_sid_key("example.com/live/feed1"));
    CHECK(canon == "example.com/live/feed1");
}

TEST_CASE("sls_canonical_sid_key: unparseable input falls back to the raw streamid")
{
    // Unchanged behavior for inputs that don't carry h/sls_app/r — the
    // caller still gets *some* key (the raw streamid), just no collapsing.
    const std::string weird = "not-a-streamid";
    CHECK(sls_canonical_sid_key(weird) == weird);
    CHECK(sls_canonical_sid_key("").empty());
}
