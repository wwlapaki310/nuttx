/****************************************************************************
 * drivers/net/wireguard/wg_tai64n.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <syslog.h>

#include <nuttx/clock.h>
#include <nuttx/mutex.h>

#include "wg_crypto.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_TAI64_UNIX_EPOCH 0x400000000000000aull

/* Without an RTC, clock_initialize() seeds CLOCK_REALTIME from
 * CONFIG_START_YEAR, so a realtime that is still below the year after it was
 * almost certainly never set -- a device is not plausibly up for a year with
 * no time source. A responder remembers the greatest timestamp it accepted
 * for this key, so such a device stops reconnecting after a reboot until its
 * clock passes that value, and the wait is as long as the previous session.
 * Say so once instead of leaving a silent connectivity failure.
 *
 * This is a heuristic for the common "never set" case. It cannot tell a
 * plausible-but-wrong date from a correct one, and does not try to.
 */

#define WG_SECS_PER_YEAR    31556952ull
#define WG_CLOCK_UNSET_BELOW \
  (((uint64_t)CONFIG_START_YEAR + 1 - 1970) * WG_SECS_PER_YEAR)

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Shared across interfaces and key/peer reconfiguration. The lock protects
 * only timestamp allocation; no socket operations or device locks are taken
 * while holding it. This high-water mark does NOT survive reboot.
 */

static mutex_t g_timestamp_lock = NXMUTEX_INITIALIZER;
static uint64_t g_timestamp_seconds;
static uint32_t g_timestamp_nanos;
static bool g_clock_unset_warned;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_tai64n
 *
 * Description:
 *   Encode realtime as TAI64N, rounded down to tick resolution. If the clock
 *   repeats or goes backwards during this boot, advance the last issued
 *   value by one tick instead. Consume values even when a later handshake
 *   construction or send fails. The platform must supply a realtime clock
 *   that advances across boots: a configured start date is not sufficient.
 *
 * Returned Value:
 *   True on success; false without changing out on clock/lock failure,
 *   invalid time, or timestamp exhaustion. Never fall back to uptime.
 *
 ****************************************************************************/

bool wg_tai64n(FAR uint8_t out[WG_TAI64N_LEN])
{
  struct timespec ts;
  uint64_t seconds;
  uint32_t nanos;
  bool result = false;
  bool warn = false;
  int i;

  if (nxmutex_lock(&g_timestamp_lock) < 0)
    {
      return false;
    }

  if (nxclock_gettime(CLOCK_REALTIME, &ts) < 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0 || ts.tv_nsec >= NSEC_PER_SEC ||
      (uint64_t)ts.tv_sec > UINT64_MAX - WG_TAI64_UNIX_EPOCH)
    {
      goto out;
    }

  /* Still issue the timestamp: a peer that has never seen this key accepts
   * it, so refusing here would break first-time pairing on a board with no
   * clock. Only the reconnect-after-reboot case is affected, so warn.
   */

  if (!g_clock_unset_warned &&
      (uint64_t)ts.tv_sec < WG_CLOCK_UNSET_BELOW)
    {
      g_clock_unset_warned = true;
      warn = true;
    }

  seconds = (uint64_t)ts.tv_sec + WG_TAI64_UNIX_EPOCH;
  nanos = (uint32_t)ts.tv_nsec - ((uint32_t)ts.tv_nsec % NSEC_PER_TICK);

  if (seconds < g_timestamp_seconds ||
      (seconds == g_timestamp_seconds && nanos <= g_timestamp_nanos))
    {
      seconds = g_timestamp_seconds;
      nanos = g_timestamp_nanos + NSEC_PER_TICK;
      if (nanos >= NSEC_PER_SEC)
        {
          if (seconds == UINT64_MAX)
            {
              goto out;
            }

          seconds++;
          nanos = 0;
        }
    }

  g_timestamp_seconds = seconds;
  g_timestamp_nanos = nanos;
  for (i = 0; i < 8; i++)
    {
      out[i] = (uint8_t)(seconds >> (8 * (7 - i)));
    }

  for (i = 0; i < 4; i++)
    {
      out[8 + i] = (uint8_t)(nanos >> (8 * (3 - i)));
    }

  result = true;
out:
  nxmutex_unlock(&g_timestamp_lock);

  if (warn)
    {
      syslog(LOG_WARNING,
             "wireguard: the realtime clock looks unset; handshakes will be "
             "refused by a peer that already saw a later timestamp for this "
             "key, until the clock passes it. Set the time (RTC or SNTP) "
             "before bringing wg0 up.\n");
    }

#ifdef CONFIG_NET_WIREGUARD_DEBUG_TAI64N
  if (result)
    {
      syslog(LOG_INFO, "wg test: tai64n %08lx%08lx%08lx\n",
             (unsigned long)(seconds >> 32),
             (unsigned long)(seconds & UINT32_MAX), (unsigned long)nanos);
    }
#endif

  return result;
}
