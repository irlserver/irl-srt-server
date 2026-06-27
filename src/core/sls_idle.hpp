#pragma once

#include <cstdint>

// Idle / first-data reaping decision for a receiving role (publisher / puller),
// factored out of CSLSRole so it can be unit-tested without a live SRT socket.
//
// Two timeouts govern when a receiving role is torn down:
//
//   * first-data probation: a freshly accepted publisher that has never
//     delivered a single media packet is almost always a player or preview
//     pointed at the ingest port (it completes the SRT handshake, registers as
//     a publisher, then sends nothing). Reaping it on a bounded deadline stops
//     it squatting the stream key for the full idle timeout. Probation applies
//     only while no media has been received; the first packet ends it. The
//     caller sets first_data_timeout_ms to the absolute deadline, which must
//     account for SRT's TSBPD: the receiver holds the first packet for the full
//     negotiated receive-latency window before delivering it, so the deadline
//     is computed as (negotiated latency + grace), not a flat constant, or a
//     legitimate high-latency encoder would be reaped while still buffering.
//
//   * idle timeout: the ordinary "no new data for N seconds" reaper that
//     governs a publisher which delivered media and then went quiet.
//
// Parameters:
//   now_ms                 current wall clock (sls_gettime_ms units).
//   last_recv_data_ms      ms of the most recent media read, or 0 if this role
//                          has never received any data.
//   last_activity_ms       the role's last-activity marker (m_invalid_begin_tm):
//                          the connect time until the first read advances it.
//   first_data_timeout_ms  probation window in ms; <= 0 disables probation
//                          (the default for players, which never receive).
//   idle_timeout_s         ordinary idle timeout in seconds; -1 = unlimited.
inline bool sls_should_reap_role(int64_t now_ms, int64_t last_recv_data_ms, int64_t last_activity_ms,
                                 int first_data_timeout_ms, int idle_timeout_s)
{
    if (first_data_timeout_ms > 0 && last_recv_data_ms == 0)
    {
        return (now_ms - last_activity_ms) >= first_data_timeout_ms;
    }

    if (idle_timeout_s == -1)
    {
        return false;
    }

    return (now_ms - last_activity_ms) >= (int64_t)idle_timeout_s * 1000;
}
