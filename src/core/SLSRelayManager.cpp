
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

#include <errno.h>
#include <string.h>
#include "spdlog/spdlog.h"

#include "common.hpp"
#include "SLSRelayManager.hpp"
#include "SLSLog.hpp"
#include "util.hpp"

/**
 * CSLSRelayManager class implementation
 */
CSLSRelayManager::CSLSRelayManager()
{
	m_reconnect_begin_tm = 0;
	m_map_publisher = NULL;
	m_map_data = NULL;
	m_role_list = NULL;
	m_sri = NULL;
	m_listen_port = 0;

	memset(m_app_uplive, 0, sizeof(m_app_uplive));
	memset(m_stream_name, 0, sizeof(m_stream_name));
}

CSLSRelayManager::~CSLSRelayManager()
{
}

void CSLSRelayManager::set_map_publisher(CSLSMapPublisher *map_publisher)
{
	m_map_publisher = map_publisher;
}

void CSLSRelayManager::set_map_data(CSLSMapData *map_data)
{
	m_map_data = map_data;
}

void CSLSRelayManager::set_role_list(CSLSRoleList *role_list)
{
	m_role_list = role_list;
}

void CSLSRelayManager::set_relay_conf(SLS_RELAY_INFO *sri)
{
	m_sri = sri;
}

void CSLSRelayManager::set_relay_info(const char *app_uplive, const char *stream_name)
{
	strlcpy(m_app_uplive, app_uplive, sizeof(m_app_uplive));
	strlcpy(m_stream_name, stream_name, sizeof(m_stream_name));
}

void CSLSRelayManager::set_listen_port(int port)
{
	m_listen_port = port;
}

int CSLSRelayManager::connect(const char *url, const sockaddr_storage *vetted_addr)
{
	int ret = SLS_ERROR;
	if (url == NULL || strlen(url) == 0)
	{
		spdlog::error("[{}] CSLSManager::connect, failed, url={}.", fmt::ptr(this), url ? url : "null");
		return ret;
	}

    std::shared_ptr<CSLSRelay> cur_relay(create_relay()); //new relay;
    cur_relay->init();
    // Pass the pre-vetted destination so open() dials it directly instead of
    // re-resolving (DNS-rebinding SSRF). Null for pullers/static relays.
    if (vetted_addr != nullptr)
    {
        cur_relay->set_vetted_addr(*vetted_addr);
    }
    ret = cur_relay->open(url);
    if (SLS_OK == ret)
    {
		cur_relay->set_idle_streams_timeout(m_sri->m_idle_streams_timeout);

		//set stat info
		char tmp[URL_MAX_LEN] = {0};
		char stat_base[URL_MAX_LEN] = {0};
		char cur_time[STR_DATE_TIME_LEN] = {0};
		sls_gettime_default_string(cur_time, sizeof(cur_time));
		char relay_peer_name[IP_MAX_LEN] = {0};
		int relay_peer_port = 0;
		cur_relay->get_peer_info(relay_peer_name, relay_peer_port);
		cur_relay->get_stat_base(stat_base);

		//stat info
		stat_info_t stat_info_obj;
		stat_info_obj.port = m_listen_port;
		stat_info_obj.role = cur_relay->get_role_name();
		stat_info_obj.pub_domain_app = m_app_uplive;
		stat_info_obj.stream_name = m_stream_name;
		stat_info_obj.url = url;
		stat_info_obj.remote_ip = relay_peer_name;
		stat_info_obj.remote_port = relay_peer_port;
		stat_info_obj.start_time = cur_time;

		cur_relay->set_stat_info_base(stat_info_obj);

		ret = set_relay_param(cur_relay);
		if (SLS_OK != ret)
		{
			cur_relay->uninit();
		}
		return ret;
	}
	else
	{
		cur_relay->uninit();
	}
	return ret;
}

int CSLSRelayManager::connect_hash()
{
	int ret;
	char szURL[URL_MAX_LEN] = {0};
	//make hash to hostnames by stream_name
	std::string url = get_hash_url();
	if (url.empty())
	{
		spdlog::error("[{}] CSLSRelayManager::connect_hash, failed, no upstreams configured, m_stream_name={}.",
					  fmt::ptr(this), m_stream_name);
		return SLS_ERROR;
	}
	const char *szTmp = url.c_str();

	// Percent-encode the client-supplied stream name so its '?'/'=' cannot break
	// out of the upstream streamid and inject relay socket options into our
	// outbound leg. CxxUrl decodes it on parse, so the upstream still receives
	// the literal streamid (including any legacy query token).
	std::string encoded_stream = url_encode(m_stream_name);
	ret = snprintf(szURL, sizeof(szURL), "srt://%s/%s", szTmp, encoded_stream.c_str());
	if (ret < 0 || (unsigned)ret >= sizeof(szURL))
	{
		spdlog::error("[{}] CSLSManager::connect_hash, failed, url={}.", fmt::ptr(this), url.c_str());
		return SLS_ERROR;
	}

	if (SLS_OK != (ret = connect(szURL)))
	{
		spdlog::error("[{}] CSLSRelayManager::connect_hash, failed, connect szURL={}, m_stream_name={}.",
					  fmt::ptr(this), szURL, m_stream_name);
	}
	else
	{
		spdlog::info("[{}] CSLSRelayManager::connect_hash, ok, connect szURL={}, m_stream_name={}.",
					 fmt::ptr(this), szURL, m_stream_name);
	}
	return ret;
}

std::string CSLSRelayManager::get_hash_url()
{
	// Empty m_upstreams would make `key % size()` a modulo-by-zero (UB/crash)
	// and m_upstreams[index] an out-of-bounds read. Refuse instead.
	if (NULL == m_sri || m_sri->m_upstreams.empty())
	{
		return "";
	}
	uint32_t key = sls_hash_key(m_stream_name, strlen(m_stream_name));
	uint32_t index = key % m_sri->m_upstreams.size();
	return m_sri->m_upstreams[index];
}
