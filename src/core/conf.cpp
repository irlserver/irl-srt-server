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

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "spdlog/spdlog.h"

#include "conf.hpp"
#include "common.hpp"
#include "SLSLog.hpp"
#include "util.hpp"

sls_conf_base_t sls_first_conf = {"", NULL, NULL};
sls_runtime_conf_t *sls_runtime_conf_t::first = NULL;

/*
 * runtime conf
 */
sls_runtime_conf_t::sls_runtime_conf_t(const char *c, create_conf_func f, sls_conf_cmd_t *cmd, int len)
{
    conf_name = c;
    create_fn = f;
    conf_cmd = cmd;
    conf_cmd_size = len;
    next = NULL;

    this->next = first;
    first = this;
}

sls_conf_cmd_t *sls_conf_find(const char *n, sls_conf_cmd_t *cmd, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (strcmp(n, cmd->name) == 0)
        {
            return cmd;
        }
        cmd++;
    }
    return NULL;
}

const char *sls_conf_set_int(const char *v, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    int *np;
    char *end;
    long lv;

    np = (int *)(p + cmd->offset);

    if (v == NULL || *v == '\0')
        return SLS_CONF_WRONG_TYPE;

    errno = 0;
    lv = strtol(v, &end, 10);
    if (end == v || *end != '\0' || errno == ERANGE || lv < INT_MIN || lv > INT_MAX)
        return SLS_CONF_WRONG_TYPE;
    if (lv < cmd->min || lv > cmd->max)
        return SLS_CONF_OUT_RANGE;
    *np = (int)lv;
    return SLS_CONF_OK;
}

const char *sls_conf_set_ipset(const char *conf_line, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    sls_ip_acl_t *ip_acl;
    vector<sls_ip_access_t> *ip_access_list;

    int len = strlen(conf_line);
    if (len < cmd->min || len > cmd->max)
        return SLS_CONF_OUT_RANGE;

    // Split configuration line at tabs and spaces
    vector<string> conf_line_split = sls_conf_string_split(conf_line, "\t ");
    // Check whether we have both arguments (play|publish, address|all)
    if (conf_line_split.size() != 2)
    {
        spdlog::error("Expected two arguments (play|publish, address|all), got '{}'", conf_line);
        return SLS_CONF_WRONG_TYPE;
    }

    // Get ACL object from the memory offset
    ip_acl = (sls_ip_acl_t *)(p + cmd->offset);
    // Store action, IP address
    sls_ip_access_t ip_access_obj;

    // Check if we got valid ACL target
    if (strcmp(conf_line_split[0].c_str(), "play") == 0)
    {
        ip_access_list = &(ip_acl->play);
    }
    else if (strcmp(conf_line_split[0].c_str(), "publish") == 0)
    {
        ip_access_list = &(ip_acl->publish);
    }
    else
    {
        spdlog::error("Unknown ACL target '{}'", conf_line_split[0].c_str());
        return SLS_CONF_WRONG_TYPE;
    }

    // Check if provided IP is a well-known IP address/term
    if (strcmp(conf_line_split[1].c_str(), "all") == 0)
    {
        ip_access_obj.ip_address = 0;
    }
    else
    {
        // Otherwise, parse the address
        struct in_addr parsed_addr_struct;
        // TODO: IPv6 support (https://linux.die.net/man/3/inet_pton)
        if (inet_pton(AF_INET, conf_line_split[1].c_str(), &parsed_addr_struct) != 1)
        {
            spdlog::warn("Invalid IPv4 address provided [ip='{}' list='{}']", conf_line_split[1], cmd->name);
            return SLS_CONF_WRONG_TYPE;
        }
        // Use ntohl, in case this is used for anything else in the future
        ip_access_obj.ip_address = ntohl(parsed_addr_struct.s_addr);
    }

    // Get correct action
    if (strcmp(cmd->name, "allow") == 0)
    {
        ip_access_obj.action = sls_access_action::ACCEPT;
    }
    else if (strcmp(cmd->name, "deny") == 0)
    {
        ip_access_obj.action = sls_access_action::DENY;
    }
    else
    {
        // If we reach this, something is wrong with the code
        // (incorrect modification of config directives)
        spdlog::error("Invalid command name '{}'", cmd->name);
        return SLS_CONF_WRONG_TYPE;
    }

    // Add IP object to the list
    ip_access_list->push_back(ip_access_obj);
    spdlog::debug("Added IP address to the list [ip='{}' list='{}' action='{}']",
                  conf_line_split[1], conf_line_split[0], cmd->name);
    return SLS_CONF_OK;
}

const char *sls_conf_set_string(const char *v, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    char *np;
    int len = strlen(v);

    // Strip a single pair of surrounding quotes (single or double) so users
    // can naturally write quoted string values. Without this the quotes are
    // stored as part of the string and downstream comparisons (notably
    // SRTO_PASSPHRASE against an unquoted client passphrase) silently fail.
    if (len >= 2 && (v[0] == '"' || v[0] == '\'') && v[len - 1] == v[0])
    {
        v += 1;
        len -= 2;
    }

    if (len < cmd->min || len > cmd->max)
        return SLS_CONF_OUT_RANGE;

    np = (char *)(p + cmd->offset);
    memcpy(np, v, len);
    np[len] = 0;
    return SLS_CONF_OK;
}

const char *sls_conf_set_double(const char *v, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    double *np;
    char *end;
    double v1;

    np = (double *)(p + cmd->offset);

    if (v == NULL || *v == '\0')
        return SLS_CONF_WRONG_TYPE;

    errno = 0;
    v1 = strtod(v, &end);
    if (end == v || *end != '\0' || errno == ERANGE)
        return SLS_CONF_WRONG_TYPE;
    if (v1 < cmd->min || v1 > cmd->max)
        return SLS_CONF_OUT_RANGE;
    *np = v1;
    return SLS_CONF_OK;
}

const char *sls_conf_set_bool(const char *v, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    bool *np;

    np = (bool *)(p + cmd->offset);

    if (0 == strcmp(v, "true"))
    {
        *np = true;
        return SLS_CONF_OK;
    }
    else if (0 == strcmp(v, "false"))
    {
        *np = false;
        return SLS_CONF_OK;
    }
    else
    {
        return SLS_CONF_WRONG_TYPE;
    }
}

int sls_conf_get_conf_count(sls_conf_base_t *c)
{
    int count = 0;
    while (c)
    {
        c = c->sibling;
        count++;
    }
    return count;
}

/**
 * @brief Split provided char array at any of the provided delimiters.
 * 
 * @param str String to split into tokens.
 * @param delim Delimiters to consider when splitting.
 * @return vector<char *> Vector of strings - individual tokens.
 */
vector<string> sls_conf_string_split(const char *str, const char *delim)
{
    vector<string> res;
    if (strcmp(str, "") == 0)
        return res;

    char *strs = new char[strlen(str) + 1];
    strcpy(strs, str);

    char *d = new char[strlen(delim) + 1];
    strcpy(d, delim);

    char *p = strtok(strs, d);
    while (p)
    {
        string s = p;
        res.push_back(s);
        p = strtok(NULL, d);
    }

    delete[] strs;
    delete[] d;
    return res;
}

/**
 * @brief Trim spaces at the beginning and the end of the string
 * 
 * @param s String to trim.
 * @return string& Trimmed string.
 */
string &trim(string &s)
{
    if (s.empty())
    {
        return s;
    }
    s.erase(0, s.find_first_not_of(" "));
    s.erase(s.find_last_not_of(" ") + 1);
    return s;
}

string &replace_all(string &str, const string &old_value, const string &new_value)
{
    while (true)
    {
        string::size_type pos(0);
        if ((pos = str.find(old_value)) != string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}

sls_conf_base_t *sls_conf_create_block_by_name(string n, sls_runtime_conf_t *&p_runtime)
{
    sls_conf_base_t *p = NULL;
    p_runtime = sls_runtime_conf_t::first;
    while (p_runtime)
    {
        if (strcmp(n.c_str(), p_runtime->conf_name) == 0)
        {
            p = p_runtime->create_fn();
            //sls_add_conf_to_runtime(p, p_runtime);
            break;
        }
        p_runtime = p_runtime->next;
    }
    return p;
}

int sls_conf_parse_block(ifstream &ifs, int &line, sls_conf_base_t *b, bool &child, sls_runtime_conf_t *p_runtime, int brackets_layers)
{
    int ret = SLS_ERROR;
    sls_conf_base_t *block = NULL;
    string str_line, str_line_last;
    string n, v, line_end_flag;
    int index;

    while (getline(ifs, str_line))
    {
        line++;
        spdlog::trace("line:{:d}='{}'", line, str_line);
        //remove #
        index = str_line.find('#');
        if (index != -1)
        {
            str_line = str_line.substr(0, index);
        }
        //trim and replace '\t'
        str_line = replace_all(str_line, "\t", "");
        str_line = trim(str_line);
        if (str_line.length() == 0)
        {
            spdlog::trace("line:{:d}='{}', is comment.", line, str_line);
            continue;
        }

        //check if the last char is ';', '{', '}'
        line_end_flag = str_line.substr(str_line.length() - 1);

        if (line_end_flag == ";")
        {
            if (!b)
            {
                spdlog::error("line:{:d}='{}', not found block.", line, str_line);
                ret = SLS_ERROR;
                break;
            }

            // fix1: don't parse the value if main configuration block is not initialized
            if (brackets_layers == 0 || !p_runtime)
            {
                spdlog::error("line:{:d}='{}', values outside of the SRT configuration block", line, str_line);
                ret = SLS_ERROR;
                break;
            }

            //key value
            str_line = str_line.substr(0, str_line.length() - 1);

            str_line = replace_all(str_line, "\t", "");
            str_line = trim(str_line);

            //split by space
            int index = str_line.find(' ');
            if (index == -1)
            {
                spdlog::error("line:{:d}='{}', no space separator.", line, str_line);
                ret = SLS_ERROR;
                break;
            }
            n = str_line.substr(0, index);
            v = str_line.substr(index + 1, str_line.length() - (index + 1));
            v = trim(v);

            sls_conf_cmd_t *it = sls_conf_find(n.c_str(), p_runtime->conf_cmd, p_runtime->conf_cmd_size);
            if (!it)
            {
                spdlog::error("line:{:d}='{}', wrong name='{}'.", line, str_line, n);
                ret = SLS_ERROR;
                break;
            }
            const char *r = it->set(v.c_str(), it, b);
            if (r != SLS_CONF_OK)
            {
                spdlog::error("line:{:d}, set failed, {}, name='{}', value='{}'.", line, r, n, v);
                ret = SLS_ERROR;
                break;
            }
            spdlog::trace("line:{:d}, set name='{}', value='{}'.", line, n, v);
        }
        else if (line_end_flag == "{")
        {
            str_line = str_line.substr(0, str_line.length() - 1);
            str_line = replace_all(str_line, "\t", "");
            str_line = trim(str_line);

            n = str_line;
            if (n.length() == 0)
            {
                if (str_line_last.length() == 0)
                {
                    spdlog::error("line:{:d}, no name found.", line);
                    ret = SLS_ERROR;
                    break;
                }
                n = str_line_last;
                str_line_last = "";
            }
            // new block
            block = sls_conf_create_block_by_name(n, p_runtime);
            if (!block)
            {
                spdlog::error("line:{:d}, name='{}' not found.", line, n);
                ret = SLS_ERROR;
                break;
            }
            if (child)
                b->child = block;
            else
                b->sibling = block;
            b = block;
            child = true;
            brackets_layers++;
            ret = sls_conf_parse_block(ifs, line, b, child, p_runtime, brackets_layers);
            if (ret != SLS_OK)
            {
                spdlog::error("line:{:d}, parse block='{}' failed.", line, block->name);
                ret = SLS_ERROR;
                break;
            }
        }
        else if (line_end_flag == "}")
        {
            if (str_line != line_end_flag)
            {
                spdlog::error("line:{:d}='{}', end indicator '}}' with more info.", line, str_line);
                ret = SLS_ERROR;
                break;
            }
            brackets_layers--;
            ret = SLS_OK;
            child = false;
            break;
        }
        else
        {
            spdlog::error("line:{:d}='{}', invalid end flag, except ';', '{{', '}}',", line, str_line);
            ret = SLS_ERROR;
            break;
        }
        str_line_last = str_line;
    }
    return ret;
}

int sls_conf_open(const char *conf_file)
{
    ifstream ifs(conf_file);
    int ret = 0;
    int line = 0;
    bool child = true;
    int brackets_layers = 0;

    sls_runtime_conf_t *p_runtime = NULL;

    spdlog::info("sls_conf_open, parsing conf file='{}'.", conf_file);
    if (!ifs.is_open())
    {
        spdlog::critical("open conf file='{}' failed, please check if the file exist.", conf_file);
        return SLS_ERROR;
    }

    ret = sls_conf_parse_block(ifs, line, &sls_first_conf, child, p_runtime, brackets_layers);
    if (ret != SLS_OK)
    {
        if (0 == brackets_layers)
        {
            spdlog::critical("parse conf file='{}' failed.", conf_file);
        }
        else
        {
            spdlog::critical("parse conf file='{}' failed, please check count of '{{' and '}}'.", conf_file);
        }
    }
    return ret;
}

void sls_conf_release(sls_conf_base_t *c)
{
    if (c == nullptr)
    {
        spdlog::warn("sls_conf_release, config not loaded");
        return;
    }

    sls_conf_base_t *c_b;
    if (c->child != NULL)
    {
        c_b = c->child;
        sls_conf_release(c_b);
        c->child = NULL;
    }
    if (c->sibling != NULL)
    {
        c_b = c->sibling;
        sls_conf_release(c_b);
        c->sibling = NULL;
    }
    if (c->child == NULL && c->sibling == NULL)
    {
        spdlog::debug("sls_conf_release, delete '{}'.", c->name);
        delete c;
        return;
    }
}

void sls_conf_close()
{
    sls_conf_base_t *c = sls_first_conf.child;
    sls_conf_release(c);
}

sls_conf_base_t *sls_conf_get_root_conf()
{
    return sls_first_conf.child;
}

int sls_parse_argv(int argc, char *argv[], sls_opt_t *sls_opt, sls_conf_cmd_t *conf_cmd_opt, int cmd_size)
{
    char opt_name[256] = {0};
    char opt_value[256] = {0};
    char temp[256] = {0};

    int ret = SLS_OK;
    int i = 1; //skip
    int len = cmd_size;

    //special for '-h'
    if (argc == 2)
    {
        strlcpy(temp, argv[1], sizeof(temp));
        sls_remove_marks(temp);
        if (strcmp(temp, "-h") == 0)
        {
            spdlog::info("option help info:");
            for (i = 0; i < len; i++)
            {
                spdlog::info("-{}, {}, range: {:.0f}-{:.0f}.",
                             conf_cmd_opt[i].name,
                             conf_cmd_opt[i].mark,
                             conf_cmd_opt[i].min,
                             conf_cmd_opt[i].max);
            }
        }
        else
        {
            spdlog::critical("wrong parameter, '{}'.", argv[1]);
        }
        return SLS_ERROR;
    }
    while (i < argc)
    {
        strlcpy(temp, argv[i], sizeof(temp));
        len = strlen(temp);
        if (len == 0)
        {
            spdlog::critical("wrong parameter, is ''.");
            ret = SLS_ERROR;
            return ret;
        }
        sls_remove_marks(temp);
        if (temp[0] != '-')
        {
            spdlog::critical("wrong parameter '{}', the first character must be '-'.", opt_name);
            ret = SLS_ERROR;
            return ret;
        }
        strlcpy(opt_name, temp + 1, sizeof(opt_name));

        sls_conf_cmd_t *it = sls_conf_find(opt_name, conf_cmd_opt, cmd_size);
        if (!it)
        {
            spdlog::critical("wrong parameter '{}'.", argv[i]);
            ret = SLS_ERROR;
            return ret;
        }
        i++;
        if (i >= argc)
        {
            spdlog::critical("missing value for parameter '-{}'.", opt_name);
            return SLS_ERROR;
        }
        strlcpy(opt_value, argv[i++], sizeof(opt_value));
        sls_remove_marks(opt_value);
        const char *r = it->set(opt_value, it, sls_opt);
        if (r != SLS_CONF_OK)
        {
            spdlog::critical("parameter set failed, {}, name='{}', value='{}'.", r, opt_name, opt_value);
            ret = SLS_ERROR;
            return ret;
        }
    }
    return ret;
}

// Helper function to trim leading/trailing whitespace
std::string trim_whitespace(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t");
    if (string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(" \t");
    return str.substr(first, (last - first + 1));
}

const char *sls_conf_set_string_list(const char *v, sls_conf_cmd_t *cmd, void *conf)
{
    char *p = (char *)conf;
    std::vector<std::string> *list_ptr = (std::vector<std::string> *)(p + cmd->offset);

    // Clear existing list if any
    list_ptr->clear();

    std::vector<std::string> tokens = sls_conf_string_split(v, ",");
    for (const auto& token : tokens)
    {
        std::string trimmed_token = trim_whitespace(token);
        if (!trimmed_token.empty()) {
            list_ptr->push_back(trimmed_token);
        }
    }

     if (list_ptr->size() < cmd->min || list_ptr->size() > cmd->max) {
         return SLS_CONF_OUT_RANGE;
     }

    return SLS_CONF_OK;
}
