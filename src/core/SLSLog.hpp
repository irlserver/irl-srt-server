
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

#include <cstdarg>
#include <stdio.h>
#include "spdlog/spdlog.h"

#include "common.hpp"
#include "SLSLock.hpp"
#include "SLSLogCategory.hpp"
#include "SLSLogRateLimiter.hpp"
#include "SLSSessionTracker.hpp"
#include "SLSSummaryLogger.hpp"

static const char APP_NAME[] = "srt-live";

/**
 * Logging configuration structure
 */
struct sls_log_config_t
{
    bool rate_limit_enabled;
    int rate_limit_window_sec;
    int rate_limit_threshold;
    bool summary_enabled;
    int summary_interval_sec;
    bool session_ids_enabled;
    bool json_format;
    
    // Per-category log levels (nullptr means use global level)
    spdlog::level::level_enum category_levels[static_cast<int>(SLSLogCategory::COUNT)];
    bool category_level_set[static_cast<int>(SLSLogCategory::COUNT)];
};

/**
 * Initialize logger with default settings
 */
int initialize_logger();

/**
 * Set global log level
 */
int sls_set_log_level(char *log_level);

/**
 * Set log file
 */
int sls_set_log_file(char *log_file);

/**
 * Set category-specific log level
 */
int sls_set_category_log_level(SLSLogCategory category, const char *log_level);

/**
 * Get current log configuration
 */
sls_log_config_t& sls_get_log_config();

/**
 * Get global rate limiter
 */
CSLSLogRateLimiter& sls_get_rate_limiter();

/**
 * Get global summary logger
 */
CSLSSummaryLogger& sls_get_summary_logger();

/**
 * Check if category should be logged at given level
 */
bool sls_should_log_category(SLSLogCategory category, spdlog::level::level_enum level);
