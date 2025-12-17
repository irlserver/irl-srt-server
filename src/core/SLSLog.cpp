
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

#include <mutex>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <strings.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/ansicolor_sink.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "SLSLog.hpp"
#include "SLSJsonSink.hpp"
#include "SLSLock.hpp"

std::mutex LOGGER_MUTEX;

// Global logging infrastructure
static sls_log_config_t g_log_config;
static CSLSLogRateLimiter g_rate_limiter;
static CSLSSummaryLogger g_summary_logger;
static std::string g_log_file_path;

int initialize_logger()
{
    std::vector<spdlog::sink_ptr> sinks;

    auto console_sink = std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>();
    sinks.push_back(console_sink);

    auto combined_logger = std::make_shared<spdlog::logger>(APP_NAME, begin(sinks), end(sinks));
    combined_logger->set_level(DEFAULT_LOG_LEVEL);

    spdlog::set_default_logger(combined_logger);

    // Initialize log configuration with defaults
    g_log_config.rate_limit_enabled = true;
    g_log_config.rate_limit_window_sec = 60;
    g_log_config.rate_limit_threshold = 5;
    g_log_config.summary_enabled = true;
    g_log_config.summary_interval_sec = 60;
    g_log_config.session_ids_enabled = true;
    g_log_config.json_format = false;
    
    // Initialize all category levels as "not set"
    for (int i = 0; i < static_cast<int>(SLSLogCategory::COUNT); i++)
    {
        g_log_config.category_level_set[i] = false;
        g_log_config.category_levels[i] = spdlog::level::info;
    }

    return 0;
}

int sls_set_log_level(char *log_level)
{
    log_level = sls_strlower(log_level); //to upper
    std::string log_level_str(log_level);
    spdlog::level::level_enum new_level = spdlog::level::from_str(log_level_str);
    spdlog::get(APP_NAME)->set_level(new_level);
    spdlog::warn("Setting logging level to {}", spdlog::level::to_string_view(new_level));
    return SLS_OK;
}

int sls_set_log_file(char *log_file)
{
    if (log_file && strlen(log_file) > 0)
    {
        g_log_file_path = log_file;
        
        spdlog::sink_ptr file_sink;
        
        // Use JSON sink if JSON format is enabled
        if (g_log_config.json_format)
        {
            file_sink = std::make_shared<json_file_sink_mt>(log_file);
        }
        else
        {
            file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file);
        }
        
        LOGGER_MUTEX.lock();
        spdlog::get(APP_NAME)->sinks().push_back(file_sink);
        LOGGER_MUTEX.unlock();
        return SLS_OK;
    }
    return SLS_ERROR;
}

int sls_set_category_log_level(SLSLogCategory category, const char *log_level)
{
    std::string log_level_str(log_level);
    spdlog::level::level_enum new_level = spdlog::level::from_str(log_level_str);
    
    int cat_idx = static_cast<int>(category);
    g_log_config.category_levels[cat_idx] = new_level;
    g_log_config.category_level_set[cat_idx] = true;
    
    return SLS_OK;
}

sls_log_config_t& sls_get_log_config()
{
    return g_log_config;
}

CSLSLogRateLimiter& sls_get_rate_limiter()
{
    return g_rate_limiter;
}

CSLSSummaryLogger& sls_get_summary_logger()
{
    return g_summary_logger;
}

bool sls_should_log_category(SLSLogCategory category, spdlog::level::level_enum level)
{
    int cat_idx = static_cast<int>(category);
    
    // Check category-specific level if set
    if (g_log_config.category_level_set[cat_idx])
    {
        return level >= g_log_config.category_levels[cat_idx];
    }
    
    // Fall back to global level
    return level >= spdlog::get(APP_NAME)->level();
}
