
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
#include "SLSPullerManager.hpp"
#include "SLSLog.hpp"
#include "SLSPuller.hpp"
#include "SLSLogCategory.hpp"
#include "SLSLogRateLimiter.hpp"
#include "SLSSummaryLogger.hpp"

/**
 * CSLSPullerManager class implementation
 */

CSLSPullerManager::CSLSPullerManager()
{
	m_cur_loop_index = -1;
}

CSLSPullerManager::~CSLSPullerManager()
{
}

// start to connect from next of cur index per time.
int CSLSPullerManager::connect_loop()
{
	int ret = SLS_ERROR;

	if (m_sri == NULL || m_sri->m_upstreams.size() == 0)
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller connect_loop failed, no upstreams configured | app={} stream={}",
						 m_app_uplive, m_stream_name);
		}
		return SLS_ERROR;
	}

	if (-1 == m_cur_loop_index)
	{
		m_cur_loop_index = m_sri->m_upstreams.size() - 1;
	}
	int index = m_cur_loop_index;
	index++;

	char szURL[URL_MAX_LEN] = {};
	while (true)
	{
		if (index >= (int)m_sri->m_upstreams.size())
			index = 0;

		const char *szTmp = m_sri->m_upstreams[index].c_str();
		ret = snprintf(szURL, sizeof(szURL), "srt://%s/%s", szTmp, m_stream_name);
		if (ret < 0 || (unsigned)ret >= sizeof(szURL))
		{
			spdlog::error("[relay] Puller connect_loop failed, URL too long | ret={}", ret);
			return SLS_ERROR;
		}

		ret = connect(szURL);
		if (SLS_OK == ret)
		{
			break;
		}
		if (index == m_cur_loop_index)
		{
			if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller connect_loop failed, no available pullers | app={} stream={}",
						 m_app_uplive, m_stream_name);
			}
			break;
		}
		spdlog::info("[{}] CSLSPullerManager::connect_loop, failed, index={:d}, m_app_uplive={}, m_stream_name={}, szURL=‘{}’.",
					 fmt::ptr(this), m_app_uplive, m_stream_name, szURL);
		index++;
	}
	m_cur_loop_index = index;
	return ret;
}

int CSLSPullerManager::start()
{
	int ret;

	if (NULL == m_sri)
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller start failed, no upstreams configured | app={} stream={}",
						 m_app_uplive, m_stream_name);
			}
		return SLS_ERROR;
	}

	// check publisher
	char key_stream_name[1024] = {0};
	ret = snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", m_app_uplive, m_stream_name);
	if (ret < 0 || (unsigned)ret >= sizeof(key_stream_name))
	{
		spdlog::error("[relay] Puller operation failed, URL too long | ret={}", ret);
		return SLS_ERROR;
	}
	if (NULL != m_map_publisher)
	{
		CSLSRole *publisher = m_map_publisher->get_publisher(key_stream_name);
		if (NULL != publisher)
		{
			spdlog::error("[relay] Puller start failed, publisher already exists | stream={} publisher={}",
					  key_stream_name, fmt::ptr(publisher));
			return SLS_ERROR;
		}
	}

	if (SLS_PM_LOOP == m_sri->m_mode)
	{
		ret = connect_loop();
	}
	else if (SLS_PM_HASH == m_sri->m_mode)
	{
		ret = connect_hash();
	}
	else
	{
		spdlog::error("[relay] Puller start failed, invalid mode | mode={} app={} stream={}",
				  m_sri->m_mode, m_app_uplive, m_stream_name);
		ret = SLS_ERROR;
	}
	return ret;
}

CSLSRelay *CSLSPullerManager::create_relay()
{
	CSLSRelay *relay = new CSLSPuller;
	return relay;
}

int CSLSPullerManager::check_relay_param()
{
	if (NULL == m_role_list)
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller check_relay_param failed, m_role_list is null | stream={}",
						 m_stream_name);
			}
		return SLS_ERROR;
	}
	if (NULL == m_map_publisher)
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller check_relay_param failed, m_map_publisher is null | stream={}",
						 m_stream_name);
			}
		return SLS_ERROR;
	}
	if (NULL == m_map_data)
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller check_relay_param failed, m_map_data is null | stream={}",
						 m_stream_name);
			}
		return SLS_ERROR;
	}
	return SLS_OK;
}

int CSLSPullerManager::set_relay_param(CSLSRelay *relay)
{
	int ret;
	char key_stream_name[URL_MAX_LEN] = {0};

	ret = snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", m_app_uplive, m_stream_name);
	if (ret < 0 || (unsigned)ret >= sizeof(key_stream_name))
	{
		spdlog::error("[relay] Puller operation failed, URL too long | ret={}", ret);
		return SLS_ERROR;
	}

	if (SLS_OK != check_relay_param())
	{
		spdlog::warn("[{}] CSLSRelayManager::set_relay_param, check_relay_param failed, stream={}.",
					 fmt::ptr(this), key_stream_name);
		return SLS_ERROR;
	}

	if (SLS_OK != m_map_publisher->set_push_2_publisher(key_stream_name, relay))
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller set_relay_param failed, m_map_publisher->set_push_2_publisher failed | stream={}",
						 key_stream_name);
			}
		return SLS_ERROR;
	}

	if (SLS_OK != m_map_data->add(key_stream_name))
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller set_relay_param failed, m_map_data->add failed | stream={} relay={}",
						 key_stream_name, fmt::ptr(relay));
			}
		m_map_publisher->remove(relay);
		return SLS_ERROR;
	}

	relay->set_map_data(key_stream_name, m_map_data);
	relay->set_map_publisher(m_map_publisher);
	relay->set_relay_manager(this);
	m_role_list->push(relay);

	return SLS_OK;
}

int CSLSPullerManager::add_reconnect_stream(char *relay_url)
{
	m_reconnect_begin_tm = sls_gettime_ms();
	return m_reconnect_begin_tm;
}

int CSLSPullerManager::reconnect(int64_t cur_tm_ms)
{
	int ret = SLS_ERROR;
	char key_stream_name[URL_MAX_LEN] = {0};

	if (cur_tm_ms - m_reconnect_begin_tm < (m_sri->m_reconnect_interval * 1000))
	{
		return ret;
	}
	m_reconnect_begin_tm = cur_tm_ms;

	if (SLS_OK != check_relay_param())
	{
		if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::debug)) {
			spdlog::debug("[relay] Puller reconnect check_relay_param failed | stream={}",
						 m_stream_name);
			}
		return SLS_ERROR;
	}

	ret = snprintf(key_stream_name, sizeof(key_stream_name), "%s/%s", m_app_uplive, m_stream_name);
	if (ret < 0 || (unsigned)ret >= sizeof(key_stream_name))
	{
		spdlog::error("[relay] Puller operation failed, URL too long | ret={}", ret);
		return SLS_ERROR;
	}

	if (SLS_OK != start())
	{
		CSLSLogRateLimiter::EventStats stats;
		std::string rate_key = std::string("puller_reconnect_") + key_stream_name;
		if (sls_get_rate_limiter().should_log(rate_key, stats)) {
			spdlog::info("[relay] Puller reconnect start failed | stream={} ({}x in {}s)",
						 key_stream_name, stats.count, sls_get_log_config().rate_limit_window_sec);
			}
		return SLS_ERROR;
	}
	if (sls_should_log_category(SLSLogCategory::RELAY, spdlog::level::info)) {
			spdlog::info("[relay] Puller reconnect success | stream={}",
						 key_stream_name);
			}
	return SLS_OK;
}
