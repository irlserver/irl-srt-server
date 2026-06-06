
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

#include <vector>

#include "SLSRole.hpp"
#include "SLSRoleList.hpp"
#include "SLSMapPublisher.hpp"

/**
 * sls_conf_app_t
 */
SLS_CONF_DYNAMIC_DECLARE_BEGIN(app)
char app_player[STR_MAX_LEN];
char app_publisher[STR_MAX_LEN];
int publisher_exit_delay;
int max_input_bitrate_kbps;
int max_input_bitrate_violation_timeout;
int max_input_bitrate_spike_tolerance;
int max_players_per_stream;
sls_ip_acl_t ip_actions;
bool audio_gap_fill;
int push_destination_max;
// Allow flags: default false (memset 0) means deny, which is the safe default.
// Operators must explicitly opt in to push to private/self addresses.
bool push_destination_allow_internal;
bool push_destination_allow_self;
char push_destination_allow_schemes[STR_MAX_LEN];
int push_destination_max_url_len;
SLS_CONF_DYNAMIC_DECLARE_END

/**
 * app cmd declare
 */
SLS_CONF_CMD_DYNAMIC_DECLARE_BEGIN(app)
SLS_SET_CONF(app, string, app_player, "live", 1, STR_MAX_LEN - 1),
    SLS_SET_CONF(app, string, app_publisher, "uplive", 1, STR_MAX_LEN - 1),
    SLS_SET_CONF(app, int, publisher_exit_delay, "delay exit time, unit second.", 1, 300),
    SLS_SET_CONF(app, int, max_input_bitrate_kbps, "Maximum input bitrate in kbps (0=unlimited)", 0, 1000000),
    SLS_SET_CONF(app, int, max_input_bitrate_violation_timeout, "Timeout in seconds before disconnecting violating streams", 1, 300),
    SLS_SET_CONF(app, int, max_input_bitrate_spike_tolerance, "Spike tolerance as percentage above limit before violation starts (e.g. 120 = 1.2x)", 100, 500),
    SLS_SET_CONF(app, int, max_players_per_stream, "maximum number of players per stream", -1, 10000),
    SLS_SET_CONF2(app, ipset, ip_actions, allow, "allow address(es) to play/publish a stream", 1, 256),
    SLS_SET_CONF2(app, ipset, ip_actions, deny, "deny address(es) from playing/publishing a stream", 1, 256),
    SLS_SET_CONF(app, bool, audio_gap_fill, "fill audio gaps with silence to prevent OBS audio breaking", 0, 0),
    SLS_SET_CONF(app, int, push_destination_max, "max push destinations per stream from webhook (0=disabled)", 0, 16),
    SLS_SET_CONF(app, bool, push_destination_allow_internal, "allow push destinations resolving to loopback/RFC1918/link-local/ULA (default: deny)", 0, 0),
    SLS_SET_CONF(app, bool, push_destination_allow_self, "allow push destinations resolving to this server's bind addresses (default: deny)", 0, 0),
    SLS_SET_CONF(app, string, push_destination_allow_schemes, "whitespace-separated allowed URI schemes for push destinations (default: srt)", 0, STR_MAX_LEN - 1),
    SLS_SET_CONF(app, int, push_destination_max_url_len, "maximum length of a push destination URL (0=default 1024)", 0, 4096),
    SLS_CONF_CMD_DYNAMIC_DECLARE_END

    /**
 * CSLSPublisher
 */
    class CSLSPusherManager;

class CSLSPublisher : public CSLSRole
{
public:
    CSLSPublisher();
    virtual ~CSLSPublisher();

    void set_map_publisher(CSLSMapPublisher *publisher);

    // Listener handler wires these so the publisher can spin up its own
    // CSLSPusherManager once the publish auth webhook returns push URLs.
    void set_role_list(CSLSRoleList *list) { m_role_list = list; }
    void set_listen_port(int port) { m_listen_port = port; }

    virtual int init();
    virtual int uninit();

    virtual int handler();
    virtual void on_map_data_set() override;
    virtual bool is_audio_gap_fill_enabled() const override;

private:
    // Spawns a CSLSPusherManager carrying the URLs in m_push_urls. Called
    // once per publisher lifetime, lazily after the webhook response.
    void try_spawn_dynamic_pusher();

    CSLSMapPublisher *m_map_publisher;
    CSLSRoleList *m_role_list = nullptr;
    int m_listen_port = 0;
    CSLSPusherManager *m_dynamic_pusher_manager = nullptr;
    struct SLS_RELAY_INFO *m_dynamic_pusher_sri = nullptr;
};
