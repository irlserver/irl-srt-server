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

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "conf.hpp"
#include "SLSLock.hpp"
#include "SLSRole.hpp"

class CSLSMapPublisher
{
public:
    CSLSMapPublisher();
    virtual ~CSLSMapPublisher();

    int set_conf(std::string key, sls_conf_base_t *ca);
    int set_live_2_uplive(std::string strLive, std::string strUplive);
    int set_push_2_publisher(std::string app_streamname, std::shared_ptr<CSLSRole> role);
    int remove(CSLSRole *role);
    void clear();

    std::string get_uplive(std::string key_app);
    sls_conf_base_t *get_ca(std::string key_app);

    // Returns a shared_ptr COPY taken under the read lock, so the caller owns a
    // reference for the whole time it uses the publisher. This is the core of
    // the cross-thread UAF fix: the worker thread can erase the map entry (and
    // drop its own reference) while the HTTP stats / control thread still holds
    // this copy — the role object stays alive until the caller is done.
    std::shared_ptr<CSLSRole> get_publisher(std::string strAppStreamName);
    std::vector<std::string> get_publisher_names();
    std::map<std::string, std::shared_ptr<CSLSRole>> get_publishers();

private:
    std::map<std::string, std::string> m_map_live_2_uplive;       // 'hostname/live':'hostname/uplive'
    std::map<std::string, sls_conf_base_t *> m_map_uplive_2_conf; // 'hostname/uplive':sls_app_conf_t
    std::map<std::string, std::shared_ptr<CSLSRole>> m_map_push_2_publisher; // 'hostname/uplive/steam_name':publisher'

    CSLSRWLock m_rwclock;
};
