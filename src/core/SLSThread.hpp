
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

#include <pthread.h>
#include <atomic>

/**
 * CSLSThread , the base thread class
 */
class CSLSThread
{
public:
    CSLSThread();
    ~CSLSThread();

    int start();
    int stop();

    bool is_exit();

    virtual int work();

protected:
    // Worker-loop exit flag. Written by stop() (release) on the controlling
    // thread and by CSLSGroup::handler() (release) on the worker itself;
    // read by is_exit() (acquire) from the manager thread and by the worker
    // loop predicate (acquire). Atomic because the write and the read happen
    // on different threads — a plain bool here is a data race (TSan-flagged)
    // with no happens-before edge guaranteeing the worker ever observes the
    // stop request. release/acquire publishes the request without a lock.
    std::atomic<bool> m_exit{false};
    pthread_t m_th_id;

    virtual void clear();

private:
    static void *thread_func(void *);
};
