#pragma once

#include "spdlog/spdlog.h"

#define DEFAULT_PIDFILE "/tmp/sls/sls_server.pid"

// Default first-data probation grace (ms) applied to an accepted publisher when
// the conf directive publisher_first_data_grace is left unset. This is added on
// top of the publisher's negotiated SRT receive latency to form the reap
// deadline: a publisher that completes the handshake but delivers no media
// within (latency + grace) is reaped (almost always a player/preview pointed at
// the ingest port, not a broadcaster).
//
// The latency term is essential: SRT's TSBPD holds the first packet for the
// full receive-latency window (m_iTsbPdDelay_ms = RCVLATENCY) before delivering
// it to the application, so a legitimate high-latency encoder (e.g. Moblin at
// 3000ms, Belabox at 2000-3000ms) surfaces its first byte only after that
// window. The grace alone covers RTT, encoder warmup, and TSBPD scheduling
// jitter on top of that.
static const int SLS_DEFAULT_PUBLISHER_FIRST_DATA_GRACE_MS = 3000;

#ifdef NDEBUG
static const spdlog::level::level_enum DEFAULT_LOG_LEVEL = spdlog::level::info;
#else
static const spdlog::level::level_enum DEFAULT_LOG_LEVEL = spdlog::level::debug;
#endif
