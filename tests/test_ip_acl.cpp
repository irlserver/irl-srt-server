#include "doctest.h"

#include "conf.hpp"

#include <arpa/inet.h>
#include <cstddef>
#include <cstring>

// These tests pin the IP-ACL config parser contract. The security-relevant
// regression they guard: before family-aware ACLs, an IPv6 literal such as
// `deny publish 2001:db8::1` was rejected at parse time, so the rule silently
// did not exist and the IPv6 peer was admitted. The parser must now accept
// IPv6 literals as family-V6 entries while leaving IPv4 parsing byte-for-byte
// unchanged.

namespace
{
struct acl_holder
{
    sls_ip_acl_t acl;
};

sls_conf_cmd_t make_cmd(const char *name)
{
    sls_conf_cmd_t cmd;
    cmd.name = name;
    cmd.mark = "";
    cmd.offset = static_cast<int>(offsetof(acl_holder, acl));
    cmd.set = sls_conf_set_ipset;
    cmd.min = 0;
    cmd.max = 256;
    return cmd;
}
} // namespace

TEST_CASE("ip-acl parser: IPv4 literal parses to a V4 entry (host byte order, unchanged)")
{
    acl_holder h{};
    sls_conf_cmd_t cmd = make_cmd("deny");

    CHECK(sls_conf_set_ipset("publish 192.168.1.10", &cmd, &h) == SLS_CONF_OK);
    REQUIRE(h.acl.publish.size() == 1);
    CHECK(h.acl.publish[0].family == sls_ip_family::V4);
    CHECK(h.acl.publish[0].action == sls_access_action::DENY);

    struct in_addr expect;
    REQUIRE(inet_pton(AF_INET, "192.168.1.10", &expect) == 1);
    CHECK(h.acl.publish[0].ip_address == ntohl(expect.s_addr));
}

TEST_CASE("ip-acl parser: the 'all' keyword parses to a WILDCARD entry")
{
    acl_holder h{};
    sls_conf_cmd_t cmd = make_cmd("allow");

    CHECK(sls_conf_set_ipset("play all", &cmd, &h) == SLS_CONF_OK);
    REQUIRE(h.acl.play.size() == 1);
    CHECK(h.acl.play[0].family == sls_ip_family::WILDCARD);
    CHECK(h.acl.play[0].action == sls_access_action::ACCEPT);
}

TEST_CASE("ip-acl parser: IPv6 literal now parses to a V6 entry (regression guard)")
{
    acl_holder h{};
    sls_conf_cmd_t cmd = make_cmd("deny");

    CHECK(sls_conf_set_ipset("publish 2001:db8::1", &cmd, &h) == SLS_CONF_OK);
    REQUIRE(h.acl.publish.size() == 1);
    CHECK(h.acl.publish[0].family == sls_ip_family::V6);
    CHECK(h.acl.publish[0].action == sls_access_action::DENY);

    struct in6_addr expect;
    REQUIRE(inet_pton(AF_INET6, "2001:db8::1", &expect) == 1);
    CHECK(memcmp(&h.acl.publish[0].ip_address6, &expect, sizeof(expect)) == 0);
}

TEST_CASE("ip-acl parser: compressed IPv6 loopback parses to a V6 entry")
{
    acl_holder h{};
    sls_conf_cmd_t cmd = make_cmd("allow");

    CHECK(sls_conf_set_ipset("play ::1", &cmd, &h) == SLS_CONF_OK);
    REQUIRE(h.acl.play.size() == 1);
    CHECK(h.acl.play[0].family == sls_ip_family::V6);
}

TEST_CASE("ip-acl parser: a non-address token is still rejected")
{
    acl_holder h{};
    sls_conf_cmd_t cmd = make_cmd("deny");

    // A parse error returns a non-NULL diagnostic string (SLS_CONF_OK is NULL).
    // Compare by value, not pointer: the error literal lives in another
    // translation unit, so the addresses differ.
    const char *result = sls_conf_set_ipset("publish not-an-ip", &cmd, &h);
    REQUIRE(result != SLS_CONF_OK);
    CHECK(strcmp(result, SLS_CONF_WRONG_TYPE) == 0);
    CHECK(h.acl.publish.empty());
}
