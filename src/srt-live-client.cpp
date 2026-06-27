
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
#include <signal.h>
#include <unistd.h>
#include "spdlog/spdlog.h"

using namespace std;

#include "SLSLog.hpp"
#include "SLSClient.hpp"
#include "util.hpp"

/*
 * ctrl + c controller
 */
static volatile sig_atomic_t b_exit = 0;
static void ctrl_c_handler(int s)
{
    printf("\ncaught signal %d, exit.\n", s);
    b_exit = 1;
}

/**
 * usage information
 */
#define BANNER_WIDTH 40
#define VERSION_STRING "v" SLS_VERSION
static void usage()
{
    spdlog::info("{:-<{}}", "", BANNER_WIDTH);
    spdlog::info("{: ^{}}", "srt-live-client", BANNER_WIDTH);
    spdlog::info("{: ^{}}", VERSION_STRING, BANNER_WIDTH);
    spdlog::info("{:-<{}}", "", BANNER_WIDTH);
    spdlog::info("-r srt_url [-o out_file_name] [-c worker_count]");
    spdlog::info("-r srt_url -i ts_file_name");
}

struct sls_opt_client_t
{
    char input_ts_file[1024];
    char srt_url[1024];
    char out_file_name[1024];
    char ts_file_name[1024];
    int worker_count;
    bool loop;
    //  int xxx;                  //-x example
};

int main(int argc, char *argv[])
{
    struct sigaction sigIntHandler;
    sls_opt_client_t sls_opt;

    usage();

    // parse cmd line
    if (argc < 3)
    {
        spdlog::critical("Not enough parameters provided, exiting.");
        return SLS_OK;
    }

    // parset argv
    memset(&sls_opt, 0, sizeof(sls_opt));
    int i = 1;
    // Consume the argument that follows a flag. A trailing flag with no value
    // (e.g. `srt_client -r`) would otherwise deref argv[argc], which the C
    // standard fixes at NULL -> a crash in sls_remove_marks/strlcpy.
    auto take_value = [&](const char *flag) -> const char *
    {
        if (i + 1 >= argc)
        {
            spdlog::critical("Missing value for parameter '{}', exiting!", flag);
            return nullptr;
        }
        ++i;
        sls_remove_marks(argv[i]);
        return argv[i++];
    };
    while (i < argc)
    {
        sls_remove_marks(argv[i]);
        if (strcmp("-r", argv[i]) == 0)
        {
            const char *v = take_value("-r");
            if (!v)
                return SLS_OK;
            strlcpy(sls_opt.srt_url, v, sizeof(sls_opt.srt_url));
        }
        else if (strcmp("-i", argv[i]) == 0)
        {
            const char *v = take_value("-i");
            if (!v)
                return SLS_OK;
            strlcpy(sls_opt.ts_file_name, v, sizeof(sls_opt.ts_file_name));
        }
        else if (strcmp("-o", argv[i]) == 0)
        {
            const char *v = take_value("-o");
            if (!v)
                return SLS_OK;
            strlcpy(sls_opt.out_file_name, v, sizeof(sls_opt.out_file_name));
        }
        else if (strcmp("-c", argv[i]) == 0)
        {
            const char *v = take_value("-c");
            if (!v)
                return SLS_OK;
            sls_opt.worker_count = atoi(v);
        }
        else if (strcmp("-l", argv[i]) == 0)
        {
            const char *v = take_value("-l");
            if (!v)
                return SLS_OK;
            sls_opt.loop = atoi(v);
        }
        else
        {
            spdlog::critical("Wrong parameter '{}', exiting!", argv[i]);
            return SLS_OK;
        }
    }
    CSLSClient sls_client;
    if (strlen(sls_opt.ts_file_name) > 0)
    {
        if (SLS_OK != sls_client.push(sls_opt.srt_url, sls_opt.ts_file_name, sls_opt.loop))
        {
            spdlog::error("sls_client.push failed, exiting.");
            return SLS_ERROR;
        }
    }
    else
    {
        if (SLS_OK != sls_client.play(sls_opt.srt_url, sls_opt.out_file_name))
        {
            spdlog::error("sls_client.play failed, exiting.");
            return SLS_ERROR;
        }
        for (i = 1; i < sls_opt.worker_count; i++)
        {
            pid_t fpid;
            fpid = fork();
            if (fpid < 0)
            {
                spdlog::error("Error when forking! [ERRNO={:d}]", fpid);
            }
            else if (fpid == 0)
            {
                spdlog::info("Child process spawned [PID={:d}]", getpid());
                break;
            }
            else
            {
                spdlog::info("Parent process resumed [PID={:d}]", getpid());
            }
        }
    }

    // ctrl + c to exit
    sigIntHandler.sa_handler = ctrl_c_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, 0);

    spdlog::info("SRT Live Client is running...");
    while (!b_exit)
    {
        int ret = sls_client.handler();
        if (ret > 0)
        {
            continue;
        }
        else if (0 == ret)
        {
            msleep(1);
        }
        else
        {
            break;
        }
    }

    spdlog::info("Stopping SLS_client");
    sls_client.close();

    spdlog::info("Execution finished, goodbye.");
    return SLS_OK;
}
