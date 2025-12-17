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

#include "spdlog/sinks/base_sink.h"
#include "spdlog/details/null_mutex.h"
#include <nlohmann/json.hpp>
#include <mutex>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

using json = nlohmann::json;

/**
 * JSON file sink for spdlog using nlohmann/json
 * 
 * Formats log messages as JSON objects with structured fields:
 * - timestamp: ISO 8601 format
 * - level: log level string
 * - logger: logger name
 * - message: log message
 * - category: extracted from [category:session] or [category] tags
 * - session: extracted from [category:session] tags
 */
template<typename Mutex>
class json_file_sink : public spdlog::sinks::base_sink<Mutex>
{
public:
    explicit json_file_sink(const std::string& filename)
        : file_(filename, std::ios::app)
    {
        if (!file_.is_open())
        {
            throw spdlog::spdlog_ex("Failed to open file " + filename);
        }
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        json log_entry;
        
        // Timestamp in ISO 8601 format
        auto time_t = std::chrono::system_clock::to_time_t(msg.time);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.time.time_since_epoch()) % 1000;
        
        std::tm tm;
        gmtime_r(&time_t, &tm);
        
        std::ostringstream timestamp;
        timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
                 << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
        
        log_entry["timestamp"] = timestamp.str();
        
        // Log level
        auto level_sv = spdlog::level::to_string_view(msg.level);
        log_entry["level"] = std::string(level_sv.data(), level_sv.size());
        
        // Logger name
        log_entry["logger"] = std::string(msg.logger_name.begin(), msg.logger_name.end());
        
        // Message
        std::string message(msg.payload.begin(), msg.payload.end());
        log_entry["message"] = message;
        
        // Parse category and session from message if present
        // Format: [category:session] or [category]
        if (message.length() > 2 && message[0] == '[')
        {
            size_t close_bracket = message.find(']');
            if (close_bracket != std::string::npos)
            {
                std::string tag = message.substr(1, close_bracket - 1);
                size_t colon = tag.find(':');
                if (colon != std::string::npos)
                {
                    log_entry["category"] = tag.substr(0, colon);
                    log_entry["session"] = tag.substr(colon + 1);
                }
                else
                {
                    log_entry["category"] = tag;
                }
            }
        }
        
        // Write JSON to file
        file_ << log_entry.dump() << std::endl;
    }

    void flush_() override
    {
        file_.flush();
    }

private:
    std::ofstream file_;
};

using json_file_sink_mt = json_file_sink<std::mutex>;
using json_file_sink_st = json_file_sink<spdlog::details::null_mutex>;
