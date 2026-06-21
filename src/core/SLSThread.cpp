
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

#include "SLSThread.hpp"
#include "SLSLog.hpp"

/**
 * CSLSThread class implementation
 */

CSLSThread::CSLSThread()
{
	m_exit = 0;
	m_th_id = 0;
}
CSLSThread::~CSLSThread()
{
	stop();
}

int CSLSThread::start()
{
	int ret = 0;
	int err;
	pthread_t th_id;

	err = pthread_create(&th_id, NULL, thread_func, (void *)this);
	if (err != 0)
	{
		spdlog::error("[{}] CSLSThread::start, can't create thread, error: {}", fmt::ptr(this), strerror(err));
		return -1;
	}
	m_th_id = th_id;
	spdlog::info("[{}] CSLSThread::start, pthread_create ok, m_th_id={:d}.", fmt::ptr(this), sls_tid(m_th_id));

	return ret;
}
int CSLSThread::stop()
{
	int ret = 0;
	if (0 == m_th_id)
	{
		return ret;
	}
	spdlog::info("[{}] CSLSThread::stop, m_th_id={:d}.", fmt::ptr(this), sls_tid(m_th_id));

	m_exit = 1;
	pthread_join(m_th_id, NULL);
	m_th_id = 0;
	clear();

	return ret;
}

void CSLSThread::clear()
{
}

bool CSLSThread::is_exit()
{
	return m_exit == 1;
}

void *CSLSThread::thread_func(void *arg)
{
	CSLSThread *pThis = (CSLSThread *)arg;
	if (!pThis)
	{
		spdlog::error("CSLSThread::thread_func, thread arg is null.");
	}

	pThis->work();
	return NULL;
}

int CSLSThread::work()
{
	int ret = 0;

	return ret;
}
