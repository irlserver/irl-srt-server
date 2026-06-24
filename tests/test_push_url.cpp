#include "doctest.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

#include "SLSPushUrlValidator.hpp"

// T8 (CWE-134): a webhook-supplied push URL must never be interpreted as a
// fmt format string. These tests pin both halves of the fix: the substitution
// copies a format spec verbatim instead of expanding it, and the validator
// rejects any brace that is not the single legitimate {stream_name} token.

namespace
{
sls_conf_app_t default_app_conf()
{
    sls_conf_app_t app{};
    return app;
}
} // namespace

TEST_CASE("sls_substitute_stream_name: replaces the {stream_name} token")
{
    CHECK(sls_substitute_stream_name("srt://h:9000?streamid={stream_name}", "feed1") ==
          "srt://h:9000?streamid=feed1");
}

TEST_CASE("sls_substitute_stream_name: replaces every occurrence")
{
    CHECK(sls_substitute_stream_name("{stream_name}/{stream_name}", "x") == "x/x");
}

TEST_CASE("sls_substitute_stream_name: a brace-free template is unchanged")
{
    CHECK(sls_substitute_stream_name("srt://h:9000?streamid=live/feed", "ignored") ==
          "srt://h:9000?streamid=live/feed");
}

TEST_CASE("sls_substitute_stream_name: a format spec is copied verbatim, never expanded")
{
    // The crux of the fix: {stream_name:>1500000000} is not the substitution
    // target, so it survives as literal text instead of allocating ~1.5 GB.
    CHECK(sls_substitute_stream_name("p={stream_name:>1500000000}", "x") ==
          "p={stream_name:>1500000000}");
}

TEST_CASE("validate_push_url: a malicious fmt format spec is rejected")
{
    sls_conf_app_t app = default_app_conf();
    CHECK(validate_push_url(
              "srt://127.0.0.1:9000?streamid=live/feed&p={stream_name:>1500000000}",
              app, {}) == PushUrlReject::BadPlaceholder);
}

TEST_CASE("validate_push_url: an unknown {foo} placeholder is rejected")
{
    sls_conf_app_t app = default_app_conf();
    CHECK(validate_push_url("srt://127.0.0.1:9000?streamid=live/{foo}", app, {}) ==
          PushUrlReject::BadPlaceholder);
}

TEST_CASE("validate_push_url: a stray closing brace is rejected")
{
    sls_conf_app_t app = default_app_conf();
    CHECK(validate_push_url("srt://127.0.0.1:9000?streamid=live/feed}", app, {}) ==
          PushUrlReject::BadPlaceholder);
}

TEST_CASE("validate_push_url: the legitimate {stream_name} token is accepted")
{
    sls_conf_app_t app = default_app_conf();
    app.push_destination_allow_internal = true; // 127.0.0.1 is loopback
    // The one allowed token passes the brace filter and the URL validates once
    // the token is resolved for parsing (127.0.0.1 is numeric, so no network).
    CHECK(validate_push_url("srt://127.0.0.1:9000?streamid={stream_name}", app, {}) ==
          PushUrlReject::Ok);
}

// T12 (CWE-367/CWE-918): the validator hands back the exact address it vetted so
// the relay dials that IP instead of re-resolving the host (DNS-rebinding TOCTOU).
TEST_CASE("validate_push_url: an accepted URL fills the vetted address")
{
    sls_conf_app_t app = default_app_conf();
    app.push_destination_allow_internal = true;
    sockaddr_storage vetted{};
    CHECK(validate_push_url("srt://127.0.0.1:9000?streamid=live/feed", app, {}, &vetted) ==
          PushUrlReject::Ok);
    REQUIRE(vetted.ss_family == AF_INET);
    const sockaddr_in *v4 = reinterpret_cast<const sockaddr_in *>(&vetted);
    in_addr expected{};
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &expected) == 1);
    CHECK(v4->sin_addr.s_addr == expected.s_addr);
    CHECK(ntohs(v4->sin_port) == 9000);
}

TEST_CASE("validate_push_url: a rejected URL leaves the vetted address untouched")
{
    sls_conf_app_t app = default_app_conf(); // allow_internal stays false
    sockaddr_storage vetted{};
    std::memset(&vetted, 0, sizeof(vetted));
    CHECK(validate_push_url("srt://127.0.0.1:9000?streamid=live/feed", app, {}, &vetted) ==
          PushUrlReject::DenyInternal);
    CHECK(vetted.ss_family == 0);
}
