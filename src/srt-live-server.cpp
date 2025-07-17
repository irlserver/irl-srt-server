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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <httplib.h>
#include "spdlog/spdlog.h"

using namespace std;
using namespace httplib;

#include <nlohmann/json.hpp>
#include "SLSLog.hpp"
#include "SLSManager.hpp"
#include "HttpClient.hpp"

using json = nlohmann::json;

/*
 * ctrl + c controller
 */
static bool b_exit = 0;
static void ctrl_c_handler(int s)
{
    spdlog::warn("caught signal {:d}, exit.", s);
    sls_remove_pid();
    b_exit = true;
}

static bool b_reload = 0;
static void reload_handler(int s)
{
    spdlog::warn("caught signal {:d}, reload.", s);
    b_reload = true;
}

Server svr;

/**
 * usage information
 */
#define BANNER_WIDTH 40
#define VERSION_STRING "v" SLS_VERSION
static void usage()
{
    spdlog::info("{:-<{}}", "", BANNER_WIDTH);
    spdlog::info("{: ^{}}", "irl-srt-server", BANNER_WIDTH);
    spdlog::info("{: ^{}}", VERSION_STRING, BANNER_WIDTH);
    spdlog::info("{: ^{}}", "Based on srt-live-server", BANNER_WIDTH);
    spdlog::info("{: ^{}}", "Modified by IRLServer (https://github.com/irlserver/irl-srt-server)", BANNER_WIDTH);
    spdlog::info("{:-<{}}", "", BANNER_WIDTH);
}

// add new parameter here
static sls_conf_cmd_t conf_cmd_opt[] = {
    SLS_SET_OPT(string, c, conf_file_name, "conf file name", 1, 1023),
    SLS_SET_OPT(string, s, c_cmd, "cmd: reload", 1, 1023),
    SLS_SET_OPT(string, l, log_level, "log level: fatal/error/warning/info/debug/trace", 1, 1023),
    //  SLS_SET_OPT(int, x, xxx,          "", 1, 100),//example
};

void httpWorker(int bindPort)
{
    svr.listen("::", bindPort);
}

int main(int argc, char *argv[])
{
    struct sigaction sigIntHandler;
    struct sigaction sigHupHandler;
    sls_opt_t sls_opt;

    initialize_logger();

    CSLSManager *sls_manager = NULL;

    vector<CSLSManager *> reload_manager_list;
    CHttpClient *http_stat_client = new CHttpClient;

    int ret = SLS_OK;
    int httpPort = 8181;
    char cors_header[URL_MAX_LEN] = "*";
    int l = sizeof(sockaddr_in);
    int64_t tm_begin_ms = 0;

    char stat_method[] = "POST";
    sls_conf_srt_t *conf_srt = NULL;

    usage();

    // parse cmd line
    memset(&sls_opt, 0, sizeof(sls_opt));
    if (argc > 1)
    {
        // parset argv
        int cmd_size = sizeof(conf_cmd_opt) / sizeof(sls_conf_cmd_t);
        ret = sls_parse_argv(argc, argv, &sls_opt, conf_cmd_opt, cmd_size);
        if (ret != SLS_OK)
        {
            return SLS_ERROR;
        }
    }

    // reload
    if (strcmp(sls_opt.c_cmd, "") != 0)
    {
        return sls_send_cmd(sls_opt.c_cmd);
    }

    // log level
    if (strlen(sls_opt.log_level) > 0)
    {
        sls_set_log_level(sls_opt.log_level);
    }

    // Test erro info...
    // CSLSSrt::libsrt_print_error_info();

    // ctrl + c to exit
    sigIntHandler.sa_handler = ctrl_c_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, 0);

    // hup to reload
    sigHupHandler.sa_handler = reload_handler;
    sigemptyset(&sigHupHandler.sa_mask);
    sigHupHandler.sa_flags = 0;
    sigaction(SIGHUP, &sigHupHandler, 0);

    // init srt
    CSLSSrt::libsrt_init();

    // parse conf file
    if (strlen(sls_opt.conf_file_name) == 0)
    {
        ret = snprintf(sls_opt.conf_file_name, sizeof(sls_opt.conf_file_name), "./sls.conf");
        if (ret < 0 || (unsigned)ret >= sizeof(sls_opt.conf_file_name))
        {
            spdlog::critical("INTERNAL BUG! Conf file name is too long.");
            goto EXIT_PROC;
        }
    }
    ret = sls_conf_open(sls_opt.conf_file_name);
    if (ret != SLS_OK)
    {
        spdlog::critical("Could not read configuration file, exiting.");
        goto EXIT_PROC;
    }

    sls_load_pid_filename();
    if (0 != sls_write_pid(getpid()))
    {
        spdlog::critical("Could not write PID file, exiting.");
        goto EXIT_PROC;
    }

    // sls manager
    spdlog::info("SRT Live Server is running...");

    sls_manager = new CSLSManager;
    if (SLS_OK != sls_manager->start())
    {
        spdlog::critical("sls_manager->start failed, exiting.");
        goto EXIT_PROC;
    }

    conf_srt = (sls_conf_srt_t *)sls_conf_get_root_conf();
    ret = strnlen(conf_srt->stat_post_url, URL_MAX_LEN);
    if (ret >= URL_MAX_LEN)
    {
        spdlog::critical("stat_post_url is too long, exiting.");
        goto EXIT_PROC;
    }
    else if (ret > 0)
    {
        http_stat_client->set_stage_callback(CSLSManager::stat_client_callback, sls_manager);
        http_stat_client->open(conf_srt->stat_post_url, stat_method, conf_srt->stat_post_interval);
    }

    if (strlen(conf_srt->cors_header) > 0) {
        strcpy(cors_header, conf_srt->cors_header);
    }

    svr.Get("/stats", [&](const Request& req, Response& res) {
        json ret;
        sls_conf_srt_t *conf_srt = (sls_conf_srt_t *)sls_conf_get_root_conf(); // Get config

        if (!sls_manager || !conf_srt) { // Check config ptr too
            ret["status"]  = "error";
            ret["message"] = "Internal server error: manager or config not available";
            res.status = 500;
            res.set_header("Access-Control-Allow-Origin", cors_header);
            res.set_content(ret.dump(), "application/json");
            return;
        }

        int clear = req.has_param("reset") ? 1 : 0;

        // If publisher param exists, use old logic
        if (req.has_param("publisher")) {
            ret = sls_manager->generate_json_for_publisher(req.get_param_value("publisher"), clear);
            if (ret["status"] == "error") {
                res.status = 404; // Not Found
            }
        } else {
            // Publisher param missing: List all publishers if API key is configured
            bool authorized = false;
            if (conf_srt->api_keys.empty()) {
                // No API keys configured, disallow access
                authorized = false;
            } else {
                // API keys configured, check Authorization header
                if (req.has_header("Authorization")) {
                    std::string auth_header = req.get_header_value("Authorization");
                    for (const auto& key : conf_srt->api_keys) {
                        if (key == auth_header) {
                            authorized = true;
                            break;
                        }
                    }
                }
            }

            if (authorized) {
                ret = sls_manager->generate_json_for_all_publishers(clear);
                // Status should already be 'ok' from generate_json_for_all_publishers
                // No need to set 404 here, as we are listing all (even if empty)
            } else {
                ret["status"] = "error";
                ret["message"] = "Unauthorized: API key required or invalid.";
                res.status = 401; // Unauthorized
            }
        }

        res.set_header("Access-Control-Allow-Origin", cors_header);
        res.set_content(ret.dump(), "application/json");
    });
    
    if (conf_srt->http_port) {
        httpPort = conf_srt->http_port;
    }
    std::thread(httpWorker, std::ref(httpPort)).detach();

    while (!b_exit)
    {
        int64_t cur_tm_ms = sls_gettime_ms();
        ret = 0;
        if (sls_manager->is_single_thread())
        {
            ret = sls_manager->single_thread_handler();
        }
        if (NULL != http_stat_client)
        {
            if (!http_stat_client->is_valid())
            {
                if (SLS_OK == http_stat_client->check_repeat(cur_tm_ms))
                {
                    http_stat_client->reopen();
                }
            }
            ret = http_stat_client->handler();
            if (SLS_OK == http_stat_client->check_finished() ||
                SLS_OK == http_stat_client->check_timeout(cur_tm_ms))
            {
                // http_stat_client->get_response_info();
                http_stat_client->close();
            }
        }

        msleep(10);

        /*for test reload...
        int64_t tm_cur = sls_gettime();
        int64_t d = tm_cur - tm;
        if ( d >= 10000000) {
            b_reload = !b_reload;
            tm = tm_cur;
            printf("\n\n\n\n");
        }
        //*/

        // Check reloaded manager
        std::vector<CSLSManager *>::iterator it;
        for (it = reload_manager_list.begin(); it != reload_manager_list.end(); it++)
        {
            CSLSManager *manager = *it;
            if (nullptr != manager && SLS_OK == manager->check_invalid())
            {
                spdlog::info("Checking reloaded manager, deleting manager={:p} ...", fmt::ptr(manager));
                manager->stop();
                reload_manager_list.erase(it);
                delete manager;
            }
        }

        if (b_reload)
        {
            // Reload
            b_reload = false;
            spdlog::info("Reloading SRT Live Server...");
            ret = sls_manager->reload();
            if (ret != SLS_OK)
            {
                spdlog::error("Reload failed [sls_manager->reload failed]");
                continue;
            }
            reload_manager_list.push_back(sls_manager);
            sls_manager = NULL;
            spdlog::info("Pushing old sls_manager to list.");

            sls_conf_close();
            ret = sls_conf_open(sls_opt.conf_file_name);
            if (ret != SLS_OK)
            {
                spdlog::critical("Reload failed (could not read config file)");
                break;
            }
            spdlog::info("Successfuly reloaded config file.");

            spdlog::info("Reloading PID file location (if needed)");
            if (sls_reload_pid() != SLS_OK)
            {
                spdlog::critical("Reload recreate PID file");
                break;
            }

            sls_manager = new CSLSManager;
            if (SLS_OK != sls_manager->start())
            {
                spdlog::critical("Reload failed [sls_manager->start]");
                break;
            }
            if (strlen(conf_srt->stat_post_url) > 0)
            {
                http_stat_client->set_stage_callback(CSLSManager::stat_client_callback, sls_manager);
                http_stat_client->open(conf_srt->stat_post_url, stat_method, conf_srt->stat_post_interval);
            }

            spdlog::info("Reloaded successfully.");
        }
    }

EXIT_PROC:
    spdlog::info("Stopping SRT Live Server...");

    // stop srt
    if (NULL != sls_manager)
    {
        sls_manager->stop();
        delete sls_manager;
        sls_manager = NULL;
        spdlog::info("Released sls_manager");
    }

    // release all reload manager
    spdlog::info("Releasing reload_manager_list, count={:d}.", reload_manager_list.size());
    std::vector<CSLSManager *>::iterator it;
    for (it = reload_manager_list.begin(); it != reload_manager_list.end(); it++)
    {
        CSLSManager *manager = *it;
        if (NULL == manager)
        {
            continue;
        }
        manager->stop();
        delete manager;
    }
    spdlog::info("Released reload_manager_list");
    reload_manager_list.clear();

    spdlog::info("Releasing http_stat_client");
    // release http_stat_client
    if (NULL != http_stat_client)
    {
        http_stat_client->close();
        delete http_stat_client;
        http_stat_client = NULL;
    }

    // uninit srt
    spdlog::info("Destroy SRT objects");
    CSLSSrt::libsrt_uninit();

    spdlog::info("Closing configuration file");
    sls_conf_close();

    spdlog::info("Removing PID file");
    sls_remove_pid();

    spdlog::info("Execution finished, goodbye.");

    return 0;
}
