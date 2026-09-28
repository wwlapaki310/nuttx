/****************************************************************************
 * include/nuttx/net/wireguard.h
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

#ifndef __INCLUDE_NUTTX_NET_WIREGUARD_H
#define __INCLUDE_NUTTX_NET_WIREGUARD_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

/* This header is the user-visible ABI of the WireGuard network device:
 * the structures passed with SIOCSWGIF / SIOCGWGIF / SIOCSWGPEER /
 * SIOCDWGPEER / SIOCGWGPEER (see include/nuttx/net/ioctl.h). It is
 * included by the wg command in user space as well as by the driver, so
 * it must contain only standard types and fixed-size, pointer-free
 * structures. In PROTECTED and KERNEL builds the driver reads and writes
 * the caller's copy of these structures directly; a pointer inside them
 * could not be validated.
 */

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_KEY_LEN            32   /* Curve25519 keys and pre-shared keys */
#define WG_MAX_AIPS           8    /* allowed-ips entries per request */

/* wg_ifreq_s.flags: which optional fields are present (set) or valid (get)
 */

#define WG_IF_HAS_PRIVATE_KEY (1 << 0)  /* Set only: private_key is set */
#define WG_IF_HAS_LISTEN_PORT (1 << 1)  /* listen_port is set/valid */
#define WG_IF_HAS_ADDR        (1 << 2)  /* addr/netmask are set/valid */
#define WG_IF_HAS_PUBLIC_KEY  (1 << 3)  /* Get only: public_key is valid */
#define WG_IF_UP              (1 << 4)  /* Set: bring up. Get: is up */
#define WG_IF_DOWN            (1 << 5)  /* Set: take down */

/* wg_peerreq_s.flags */

#define WG_PEER_HAS_PSK       (1 << 0)  /* preshared_key is set/valid */
#define WG_PEER_HAS_ENDPOINT  (1 << 1)  /* endpoint is set/valid */
#define WG_PEER_HAS_KEEPALIVE (1 << 2)  /* keepalive is set/valid */
#define WG_PEER_HAS_AIPS      (1 << 3)  /* aips[0..naips) are set/valid */
#define WG_PEER_REPLACE_AIPS  (1 << 4)  /* Set: replace, do not append */
#define WG_PEER_HANDSHAKED    (1 << 5)  /* Get: last_handshake is valid */

/* wg_peerreq_s.last_handshake when no handshake has completed */

#define WG_HANDSHAKE_NEVER    0xffffffffu

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* One allowed-ips entry: a destination prefix routed to (and accepted
 * from) the peer. IPv4 only for now.
 */

struct wg_aip_s
{
  struct in_addr addr;
  uint8_t cidr;                 /* Prefix length, 0..32 */
  uint8_t pad[3];
};

/* SIOCSWGIF / SIOCGWGIF: interface-level configuration. The private key
 * is write-only: it is accepted by SIOCSWGIF and is never copied back by
 * SIOCGWGIF, so that key material does not leave the kernel once set.
 */

struct wg_ifreq_s
{
  char ifname[IFNAMSIZ];        /* In: which interface, e.g. "wg0" */
  uint32_t flags;               /* WG_IF_* */
  uint8_t private_key[WG_KEY_LEN];
  uint8_t public_key[WG_KEY_LEN];
  uint16_t listen_port;         /* UDP port, host byte order */
  uint16_t npeers;              /* Get: peers currently configured */
  struct in_addr addr;          /* Tunnel-side address of wg0 */
  struct in_addr netmask;
};

/* SIOCSWGPEER / SIOCDWGPEER / SIOCGWGPEER: one peer. Set and delete
 * address the peer by public key; get enumerates by index (0..npeers-1)
 * and fills in the rest. Statistics are get-only.
 */

struct wg_peerreq_s
{
  char ifname[IFNAMSIZ];        /* In: which interface */
  uint32_t flags;               /* WG_PEER_* */
  uint16_t index;               /* Get: which peer */
  uint16_t keepalive;           /* Persistent keepalive, seconds; 0 = off */
  uint8_t public_key[WG_KEY_LEN];
  uint8_t preshared_key[WG_KEY_LEN];
  struct sockaddr_in endpoint;  /* Peer's current (get) / initial (set) */
  uint8_t naips;
  uint8_t pad[3];
  struct wg_aip_s aips[WG_MAX_AIPS];

  /* Get only */

  uint32_t last_handshake;      /* Milliseconds ago, WG_HANDSHAKE_NEVER */
  uint64_t rx_bytes;
  uint64_t tx_bytes;
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

#if defined(__KERNEL__) || defined(CONFIG_BUILD_FLAT)
/****************************************************************************
 * Name: wireguard_initialize
 *
 * Description:
 *   Register the WireGuard network devices (wg0 .. wgN-1, with N =
 *   CONFIG_NET_WIREGUARD_NINTERFACES). Called once during OS start-up
 *   from drivers_initialize(). The interfaces come up with no key and no
 *   peers; they are configured through the ioctls above, normally by the
 *   wg command.
 *
 * Returned Value:
 *   OK on success; a negated errno value on failure.
 *
 ****************************************************************************/

int wireguard_initialize(void);
#endif

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_NUTTX_NET_WIREGUARD_H */
