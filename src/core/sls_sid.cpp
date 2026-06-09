#include "sls_sid.hpp"

#include <cstring>
#include <vector>

#include "auth_reject_cache.hpp"
#include "common.hpp"

using std::string;

std::map<std::string, std::string> sls_parse_streamid(const char *sid)
{
    static const char stdhdr[] = "#!::";
    std::map<std::string, std::string> ret;
    if (!sid)
        return ret;

    if (strlen(sid) > 4 && memcmp(sid, stdhdr, 4) == 0)
    {
        std::vector<string> items;
        sls_split_string(sid + 4, ",", items);
        for (auto &i : items)
        {
            std::vector<string> kv;
            sls_split_string(i, "=", kv);
            if (kv.size() == 2)
                ret[sls_trim(kv.at(0))] = sls_trim(kv.at(1));
        }
    }
    else
    {
        std::vector<string> items;
        sls_split_string(sid, "/", items);
        if (items.size() >= 3)
        {
            ret["h"] = sls_trim(items.at(0));
            ret["sls_app"] = sls_trim(items.at(1));
            ret["r"] = sls_trim(items.at(2));
        }
    }
    return ret;
}

bool sls_validate_sid_format(const char *sid)
{
    if (!sid || sid[0] == '\0')
        return false;

    std::map<std::string, std::string> kv = sls_parse_streamid(sid);
    auto h = kv.find("h");
    auto a = kv.find("sls_app");
    auto r = kv.find("r");
    if (h == kv.end() || a == kv.end() || r == kv.end())
        return false;

    return sls_is_safe_name(h->second.c_str()) &&
           sls_is_safe_name(a->second.c_str()) &&
           sls_is_safe_name(r->second.c_str());
}

int sls_publisher_listen_callback(void *opaque, SRTSOCKET ns, int hsversion,
                                  const struct sockaddr *peeraddr,
                                  const char *streamid)
{
    (void)hsversion;
    (void)peeraddr;

    if (!sls_validate_sid_format(streamid))
    {
        // Any reject reason serializes on the wire as 1000 + reason, which the
        // upstream relay's is_srt_handshake_reject also counts as defense in
        // depth. ROGUE ("incorrect data in handshake") fits a malformed sid.
        srt_setrejectreason(ns, SRT_REJ_ROGUE);
        return -1;
    }

    AuthRejectCache *cache = static_cast<AuthRejectCache *>(opaque);
    if (cache != nullptr && cache->is_blocked(streamid))
    {
        srt_setrejectreason(ns, SRT_REJ_RESOURCE);
        return -1;
    }

    return 0; // accept; the post-accept webhook still authorizes the key
}

int sls_player_listen_callback(void *opaque, SRTSOCKET ns, int hsversion,
                               const struct sockaddr *peeraddr,
                               const char *streamid)
{
    (void)opaque;
    (void)hsversion;
    (void)peeraddr;

    if (!sls_validate_sid_format(streamid))
    {
        srt_setrejectreason(ns, SRT_REJ_ROGUE);
        return -1;
    }

    return 0; // accept; the post-accept handler resolves and authorizes
}
