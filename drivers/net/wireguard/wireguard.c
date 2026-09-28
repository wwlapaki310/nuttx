/****************************************************************************
 * drivers/net/wireguard/wireguard.c
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

/* WireGuard as a NuttX network device.
 *
 * wgN is a NET_LL_TUN device on the netdev_lowerhalf framework. IP packets
 * the stack routes to it are encrypted and sent as UDP datagrams to the
 * peer whose allowed-ips cover the destination; datagrams received on the
 * UDP socket are decrypted and handed back to the stack as packets that
 * arrived on wgN. The UDP socket is held as a struct socket and driven
 * with the psock_* interfaces, the same way drivers/net/rpmsgdrv.c holds
 * its socket. A kernel thread waits on the socket and also runs the
 * protocol timers (handshake retry, keepalive, rekey).
 *
 * Protocol and peer state is protected by this device's d_lock, also used
 * by the upper half. Outbound datagrams are copied to a bounded queue;
 * only the receive thread calls psock_sendto, without d_lock held and
 * without references to live protocol state. The decrypted receive queue
 * uses a spinlock like rpmsgdrv.c.
 *
 * The protocol itself lives in wg_noise.c; this file only knows about
 * sockets, packets, timers and configuration.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <debug.h>
#ifdef CONFIG_NET_WIREGUARD_DEBUG_TX_STALL
#include <syslog.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <nuttx/kthread.h>
#include <nuttx/kmalloc.h>
#include <nuttx/signal.h>
#include <nuttx/semaphore.h>
#include <nuttx/spinlock.h>
#include <nuttx/clock.h>
#include <nuttx/queue.h>
#include <nuttx/net/net.h>
#include <nuttx/net/netdev.h>
#include <nuttx/net/netdev_lowerhalf.h>
#include <nuttx/net/ioctl.h>
#include <nuttx/net/ip.h>
#include <nuttx/net/wireguard.h>

#include "wg_crypto.h"
#include "wg_noise.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* The receive queue is a netpkt_queue_t, i.e. a struct iob_queue_s, which
 * only exists when IOB chain heads are allocated. mm/iob/Kconfig defaults
 * IOB_NCHAINS to IOB_NBUFFERS for NET_WIREGUARD, but a configuration can
 * still pin it to zero; say so here instead of failing later on an
 * incomplete type.
 */

#if CONFIG_IOB_NCHAINS < 1
#  error "CONFIG_NET_WIREGUARD requires CONFIG_IOB_NCHAINS > 0"
#endif

#define WG_NINTERFACES      CONFIG_NET_WIREGUARD_NINTERFACES
#define WG_PKTSIZE          CONFIG_NET_WIREGUARD_PKTSIZE

/* Transport data: 16-byte header, payload padded to 16, then the tag */

#define WG_DATA_HDRLEN      sizeof(struct wg_msg_data_s)
#define WG_CRYPT_BUFSIZE    (WG_DATA_HDRLEN + ((WG_PKTSIZE + 15) & ~15) + \
                             WG_AUTHTAG_LEN)

/* How often the receive thread wakes to run the timers when nothing
 * arrives. The protocol's shortest interval is REKEY_TIMEOUT (5 s), so
 * this only needs to be a comfortable fraction of that.
 */

#define WG_TIMER_MSECS      400
#define WG_STOP_WAIT_MSECS  (4 * WG_TIMER_MSECS)
#define WG_STOP_RETRIES     3       /* Total stop wait = RETRIES * WAIT */

/* Serialised outer source address for cookies: 4-byte IPv4 + 2-byte port */

#define WG_SOURCE_LEN       (sizeof(in_addr_t) + sizeof(uint16_t))

/* Receive packets the driver may hold before the upper half drains them */

#define WG_RX_QUOTA         4
#define WG_TX_QUOTA         4
#define WG_RX_BUDGET        16

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct wg_outbound_s
{
  sq_entry_t entry;
  struct sockaddr_in to;
  size_t len;
  uint8_t data[];
};

struct wg_netdev_s
{
  struct netdev_lowerhalf_s lower;  /* Must be first */
  struct wg_device_s wg;            /* Protocol state (keys, peers) */

  struct socket psock;              /* The "wire": a UDP socket */
  uint16_t listen_port;
  bool bifup;                       /* Interface is up */
  bool running;                     /* RX thread should keep going */
  bool reaping;                     /* One ifdown owns the exit wait */
  pid_t rxpid;
  sem_t rxdone;                     /* Posted when the RX thread exits */
  sem_t wake;                       /* UDP readiness or queued output */
  sq_queue_t txqueue;               /* Immutable outer UDP datagrams */
  unsigned int ntx;                 /* Queued plus in-flight datagrams */
#ifdef CONFIG_NET_WIREGUARD_DEBUG_STOP_STALL
  bool stop_stalled;                /* Test delay once per interface */
#endif
#ifdef CONFIG_NET_WIREGUARD_DEBUG_TX_STALL
  bool tx_stalled;                  /* Test delay with a datagram owned */
#endif

  netpkt_queue_t rxqueue;           /* Decrypted packets for receive() */
  spinlock_t rxlock;

  uint32_t init_window_start;       /* Initiation-rate bucket (5.4.7) */
  uint32_t init_count;

  /* Scratch buffers. Serialised by the device lock like everything else
   * that touches the protocol state.
   */

  uint8_t plainbuf[WG_PKTSIZE];
  uint8_t cryptbuf[WG_CRYPT_BUFSIZE];    /* TX encryption scratch */
  uint8_t rxbuf[WG_CRYPT_BUFSIZE];       /* RX datagram, owned by rx thread */
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int  wg_ifup(FAR struct netdev_lowerhalf_s *dev);
static int  wg_ifdown(FAR struct netdev_lowerhalf_s *dev);
static int  wg_transmit(FAR struct netdev_lowerhalf_s *dev,
                        FAR netpkt_t *pkt);
static FAR netpkt_t *wg_receive(FAR struct netdev_lowerhalf_s *dev);
static int  wg_ioctl(FAR struct netdev_lowerhalf_s *dev, int cmd,
                     unsigned long arg);

static int  wg_send_data(FAR struct wg_netdev_s *priv,
                         FAR struct wg_peer_s *peer,
                         FAR const uint8_t *plaintext, size_t len);
static void wg_send_initiation(FAR struct wg_netdev_s *priv,
                               FAR struct wg_peer_s *peer);
static void wg_run_timers(FAR struct wg_netdev_s *priv);
static int  wg_rx_thread(int argc, FAR char *argv[]);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct netdev_ops_s g_wg_ops =
{
  .ifup     = wg_ifup,
  .ifdown   = wg_ifdown,
  .transmit = wg_transmit,
  .receive  = wg_receive,
  .ioctl    = wg_ioctl,
};

static struct wg_netdev_s g_wg[WG_NINTERFACES];

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_tx_enqueue
 *
 * Description:
 *   Queue an immutable datagram and endpoint while holding d_lock. A
 *   successful return means queued, not delivered by the UDP backend.
 *
 ****************************************************************************/

static ssize_t wg_tx_enqueue(FAR struct wg_netdev_s *priv,
                            FAR const void *buf, size_t len,
                            in_addr_t ip, uint16_t port)
{
  FAR struct wg_outbound_s *out;

  DEBUGASSERT(nxrmutex_is_hold(&priv->lower.netdev.d_lock));

  /* Include the worker's in-flight datagram in the quota. No caller waits
   * for queue space: transport loss is recovered by the inner protocol,
   * and handshake/keepalive timers retry control traffic.
   */

  if (!priv->running || priv->ntx >= WG_TX_QUOTA)
    {
      return -EAGAIN;
    }

  out = kmm_malloc(sizeof(*out) + len);
  if (out == NULL)
    {
      return -ENOMEM;
    }

  memset(&out->to, 0, sizeof(out->to));
  out->to.sin_family = AF_INET;
  out->to.sin_addr.s_addr = ip;
  out->to.sin_port = htons(port);
  out->len = len;
  memcpy(out->data, buf, len);
  sq_addlast(&out->entry, &priv->txqueue);
  priv->ntx++;
  nxsem_post(&priv->wake);
  return len;
}

/* The socket worker owns removed entries until send returns. Never carry
 * a peer/keypair pointer or a protocol scratch buffer across this call.
 */

static void wg_flush_tx(FAR struct wg_netdev_s *priv)
{
  FAR struct net_driver_s *dev = &priv->lower.netdev;
  FAR struct wg_outbound_s *out;
  ssize_t ret;
  int budget;

  for (budget = 0; budget < WG_TX_QUOTA; budget++)
    {
      netdev_lock(dev);
      out = priv->running ?
        (FAR struct wg_outbound_s *)sq_remfirst(&priv->txqueue) : NULL;
      netdev_unlock(dev);
      if (out == NULL)
        {
          break;
        }

      DEBUGASSERT(!nxrmutex_is_hold(&dev->d_lock));
#ifdef CONFIG_NET_WIREGUARD_DEBUG_TX_STALL
      if (!priv->tx_stalled && out->data[0] == WG_MSG_TRANSPORT_DATA &&
          out->len > WG_DATA_HDRLEN + WG_AUTHTAG_LEN)
        {
          uint8_t before[WG_HASH_LEN];
          uint8_t after[WG_HASH_LEN];
          unsigned int pending;

          priv->tx_stalled = true;
          wg_hash(before, out->data, out->len);
          syslog(LOG_WARNING, "wg test: output stall entered\n");
          nxsig_usleep((WG_STOP_RETRIES + 7) * WG_STOP_WAIT_MSECS * 1000);
          wg_hash(after, out->data, out->len);
          DEBUGASSERT(wg_equal(before, after, WG_HASH_LEN));
          netdev_lock(dev);
          pending = priv->ntx;
          netdev_unlock(dev);
          syslog(LOG_WARNING, "wg test: output owned %u\n", pending);
          syslog(LOG_WARNING, "wg test: output stall left\n");
        }
#endif

      ret = psock_sendto(&priv->psock, out->data, out->len, MSG_DONTWAIT,
                         (FAR struct sockaddr *)&out->to, sizeof(out->to));
      kmm_free(out);

      netdev_lock(dev);
      if (ret < 0)
        {
          NETDEV_TXERRORS(dev);
        }

      priv->ntx--;
      netdev_unlock(dev);
    }
}

static bool wg_running(FAR struct wg_netdev_s *priv)
{
  bool running;

  netdev_lock(&priv->lower.netdev);
  running = priv->running;
  netdev_unlock(&priv->lower.netdev);
  return running;
}

/****************************************************************************
 * Name: wg_source_bytes
 *
 * Description:
 *   Serialise an outer source address for the cookie MAC. Only used on
 *   both sides of this driver's own cookie exchange, so the layout is a
 *   private convention.
 *
 ****************************************************************************/

static void wg_source_bytes(FAR uint8_t *out, in_addr_t ip, uint16_t port)
{
  uint16_t nport = htons(port);

  memcpy(out, &ip, sizeof(ip));
  memcpy(out + sizeof(ip), &nport, sizeof(nport));
}

/****************************************************************************
 * Name: wg_peer_for_dest
 *
 * Description:
 *   Cryptokey routing: the peer whose allowed-ips contain the destination,
 *   longest prefix first.
 *
 ****************************************************************************/

static FAR struct wg_peer_s *wg_peer_for_dest(FAR struct wg_netdev_s *priv,
                                              in_addr_t dest)
{
  FAR struct wg_peer_s *best = NULL;
  uint32_t best_mask = 0;
  int x;
  int y;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &priv->wg.peers[x];

      if (!peer->valid)
        {
          continue;
        }

      for (y = 0; y < WG_MAX_AIPS_PER_PEER; y++)
        {
          FAR struct wg_allowed_s *aip = &peer->allowed[y];
          uint32_t mask;

          if (!aip->valid || (dest & aip->mask) != (aip->ip & aip->mask))
            {
              continue;
            }

          mask = ntohl(aip->mask);
          if (best == NULL || mask > best_mask)
            {
              best = peer;
              best_mask = mask;
            }
        }
    }

  return best;
}

/****************************************************************************
 * Name: wg_source_allowed
 *
 * Description:
 *   The other half of cryptokey routing: a decrypted packet is only
 *   accepted if its inner source address is in the peer's allowed-ips.
 *
 ****************************************************************************/

static bool wg_source_allowed(FAR struct wg_peer_s *peer, in_addr_t src)
{
  int y;

  for (y = 0; y < WG_MAX_AIPS_PER_PEER; y++)
    {
      FAR struct wg_allowed_s *aip = &peer->allowed[y];

      if (aip->valid && (src & aip->mask) == (aip->ip & aip->mask))
        {
          return true;
        }
    }

  return false;
}

/****************************************************************************
 * Name: wg_under_load
 *
 * Description:
 *   Count one handshake initiation and report whether more than
 *   CONFIG_NET_WIREGUARD_LOAD_THRESHOLD arrived in the current second
 *   (5.4.7). Anyone who knows the public key can produce a valid mac1, so
 *   without this an initiation flood costs the receiver two X25519
 *   operations per packet.
 *
 ****************************************************************************/

static bool wg_under_load(FAR struct wg_netdev_s *priv)
{
  uint32_t now = wg_now();

  if (now - priv->init_window_start >= 1000)
    {
      priv->init_window_start = now;
      priv->init_count = 0;
    }

  priv->init_count++;
  return priv->init_count > CONFIG_NET_WIREGUARD_LOAD_THRESHOLD;
}

/****************************************************************************
 * Name: wg_send_data
 *
 * Description:
 *   Encrypt a packet (or nothing, for a keepalive) under the peer's
 *   current session and send it. Marks the peer for a new handshake when
 *   the session is near its message or time limit (6.2).
 *
 ****************************************************************************/

static int wg_send_data(FAR struct wg_netdev_s *priv,
                         FAR struct wg_peer_s *peer,
                         FAR const uint8_t *plaintext, size_t len)
{
  FAR struct wg_keypair_s *kp = &peer->curr_keypair;
  FAR struct wg_msg_data_s *hdr;
  size_t padded;
  size_t total;
  uint32_t now;
  int ret;

  /* As responder we may not use the new session until the initiator has
   * sent on it; fall back to the previous one meanwhile.
   */

  if (kp->valid && !kp->initiator && kp->last_rx == 0)
    {
      kp = &peer->prev_keypair;
    }

  if (!kp->valid || (!kp->initiator && kp->last_rx == 0))
    {
      return -ENOKEY;
    }

  if (wg_expired(kp->keypair_millis, WG_REJECT_AFTER_TIME) ||
      kp->sending_counter >= WG_REJECT_AFTER_MESSAGES)
    {
      wg_keypair_destroy(kp);
      return -ENOKEY;
    }

  padded = (len + 15) & ~(size_t)15;
  total = WG_DATA_HDRLEN + padded + WG_AUTHTAG_LEN;
  if (total > sizeof(priv->cryptbuf))
    {
      nerr("ERROR: packet too large (%zu bytes)\n", len);
      return -EMSGSIZE;
    }

  memset(priv->cryptbuf, 0, total);
  hdr = (FAR struct wg_msg_data_s *)priv->cryptbuf;
  hdr->type = WG_MSG_TRANSPORT_DATA;
  hdr->receiver = kp->remote_index;
  wg_write_le64(hdr->counter, kp->sending_counter);

  if (len > 0)
    {
      memcpy(priv->cryptbuf + WG_DATA_HDRLEN, plaintext, len);
    }

  wg_encrypt_packet(priv->cryptbuf + WG_DATA_HDRLEN,
                    priv->cryptbuf + WG_DATA_HDRLEN, padded, kp);

  ret = wg_tx_enqueue(priv, priv->cryptbuf, total, peer->ip, peer->port);
  if (ret >= 0)
    {
      now = wg_now();
      peer->last_tx = now;
      kp->last_tx = now;
      peer->tx_bytes += total - WG_DATA_HDRLEN;
    }

  if (kp->sending_counter >= WG_REKEY_AFTER_MESSAGES ||
      (kp->initiator && wg_expired(kp->keypair_millis,
                                   WG_REKEY_AFTER_TIME)))
    {
      peer->send_handshake = true;
    }

  return ret < 0 ? ret : OK;
}

/****************************************************************************
 * Name: wg_send_initiation
 *
 * Description:
 *   Build and send a handshake initiation (5.4.2). The mac1 is kept so a
 *   cookie reply can be decrypted.
 *
 ****************************************************************************/

static void wg_send_initiation(FAR struct wg_netdev_s *priv,
                               FAR struct wg_peer_s *peer)
{
  struct wg_msg_init_s msg;

  if (peer->ip == 0 || peer->port == 0)
    {
      return;
    }

  if (!wg_create_init(&priv->wg, peer, &msg))
    {
      return;
    }

  wg_tx_enqueue(priv, &msg, sizeof(msg), peer->ip, peer->port);

  peer->send_handshake = false;
  peer->last_initiation_tx = wg_now();
  memcpy(peer->handshake_mac1, msg.mac1, WG_MAC_LEN);
  peer->handshake_mac1_valid = true;
  wg_zero(&msg, sizeof(msg));
}

/****************************************************************************
 * Name: wg_send_response
 ****************************************************************************/

static void wg_send_response(FAR struct wg_netdev_s *priv,
                             FAR struct wg_peer_s *peer)
{
  struct wg_msg_response_s msg;

  if (!wg_create_response(&priv->wg, peer, &msg))
    {
      return;
    }

  wg_start_session(peer, false);
  wg_tx_enqueue(priv, &msg, sizeof(msg), peer->ip, peer->port);
  wg_zero(&msg, sizeof(msg));
}

/****************************************************************************
 * Name: wg_send_cookie
 *
 * Description:
 *   Answer an initiation that arrived under load without a valid mac2
 *   with a cookie reply (5.4.7).
 *
 ****************************************************************************/

static void wg_send_cookie(FAR struct wg_netdev_s *priv,
                           FAR const uint8_t *mac1, uint32_t sender,
                           in_addr_t ip, uint16_t port)
{
  struct wg_msg_cookie_s msg;
  uint8_t source[WG_SOURCE_LEN];

  wg_source_bytes(source, ip, port);
  if (wg_create_cookie(&priv->wg, &msg, mac1, sender, source,
                       sizeof(source)))
    {
      wg_tx_enqueue(priv, &msg, sizeof(msg), ip, port);
    }
}

/****************************************************************************
 * Name: wg_deliver
 *
 * Description:
 *   Queue a decrypted IP packet for the upper half. Called with the
 *   device lock held, from the receive thread. Notify the upper half only
 *   after leaving protocol processing and releasing the device lock.
 *
 ****************************************************************************/

static void wg_deliver(FAR struct wg_netdev_s *priv,
                       FAR const uint8_t *data, size_t len)
{
  FAR struct netdev_lowerhalf_s *dev = &priv->lower;
  FAR netpkt_t *pkt;
  irqstate_t flags;

  pkt = netpkt_alloc(dev, NETPKT_RX);
  if (pkt == NULL)
    {
      NETDEV_RXDROPPED(&dev->netdev);
      return;
    }

  if (netpkt_copyin(dev, pkt, data, len, 0) < 0)
    {
      netpkt_free(dev, pkt, NETPKT_RX);
      NETDEV_RXDROPPED(&dev->netdev);
      return;
    }

  flags = spin_lock_irqsave(&priv->rxlock);
  if (netpkt_tryadd_queue(pkt, &priv->rxqueue) < 0)
    {
      spin_unlock_irqrestore(&priv->rxlock, flags);
      netpkt_free(dev, pkt, NETPKT_RX);
      NETDEV_RXDROPPED(&dev->netdev);
      return;
    }

  spin_unlock_irqrestore(&priv->rxlock, flags);
}

/****************************************************************************
 * Name: wg_process_data
 *
 * Description:
 *   A transport data message for one of our sessions (5.4.6). Order of
 *   operations matters: authenticate, check the replay window, and only
 *   then update the endpoint and session state. Updating the endpoint
 *   first would let a captured packet resent from another address steer
 *   the peer's traffic there.
 *
 ****************************************************************************/

static void wg_process_data(FAR struct wg_netdev_s *priv,
                            FAR struct wg_peer_s *peer,
                            FAR struct wg_msg_data_s *hdr, size_t datalen,
                            in_addr_t ip, uint16_t port)
{
  FAR struct wg_keypair_s *kp;
  FAR const uint8_t *src;
  uint64_t counter;
  uint32_t now;

  kp = wg_keypair_by_index(peer, hdr->receiver);
  if (kp == NULL)
    {
      return;
    }

  if (!kp->receiving_valid ||
      wg_expired(kp->keypair_millis, WG_REJECT_AFTER_TIME) ||
      kp->replay_counter >= WG_REJECT_AFTER_MESSAGES)
    {
      wg_keypair_destroy(kp);
      return;
    }

  if (datalen < WG_AUTHTAG_LEN ||
      datalen - WG_AUTHTAG_LEN > sizeof(priv->plainbuf))
    {
      return;
    }

  counter = wg_read_le64(hdr->counter);
  src = (FAR const uint8_t *)hdr + WG_DATA_HDRLEN;

  if (!wg_decrypt_packet(priv->plainbuf, src, datalen, counter, kp))
    {
      return;
    }

  if (!wg_check_replay(kp, counter))
    {
      return;
    }

  peer->ip = ip;
  peer->port = port;

  now = wg_now();
  kp->last_rx = now;
  peer->last_rx = now;
  peer->rx_bytes += datalen;

  wg_keypair_update(peer, kp);

  if (kp->initiator &&
      wg_expired(kp->keypair_millis, WG_REJECT_AFTER_TIME -
                 peer->keepalive_interval - WG_REKEY_TIMEOUT))
    {
      peer->send_handshake = true;
    }

  netdev_lower_carrier_on(&priv->lower);

  /* Keepalives carry no payload; anything else is an IP packet whose
   * inner source must be allowed for this peer.
   */

  if (datalen > WG_AUTHTAG_LEN)
    {
      FAR struct ipv4_hdr_s *iphdr = (FAR struct ipv4_hdr_s *)priv->plainbuf;
      size_t pktlen = datalen - WG_AUTHTAG_LEN;
      uint16_t totlen;

      if (((iphdr->vhl >> 4) & 0x0f) != 4)
        {
          return;
        }

      totlen = ((uint16_t)iphdr->len[0] << 8) | iphdr->len[1];
      if (totlen > pktlen || totlen < IPv4_HDRLEN)
        {
          return;
        }

      if (!wg_source_allowed(peer, net_ip4addr_conv32(iphdr->srcipaddr)))
        {
          return;
        }

      wg_deliver(priv, priv->plainbuf, totlen);
    }
}

/****************************************************************************
 * Name: wg_process_datagram
 *
 * Description:
 *   Dispatch one received UDP datagram. Called with the network lock
 *   held. On an initiation the checks go mac1 -> (under load) mac2 ->
 *   the Diffie-Hellman work, per 5.4.7.
 *
 ****************************************************************************/

static void wg_process_datagram(FAR struct wg_netdev_s *priv,
                                FAR uint8_t *data, size_t len,
                                in_addr_t ip, uint16_t port)
{
  FAR struct wg_peer_s *peer;

  switch (wg_message_type(data, len))
    {
      case WG_MSG_HANDSHAKE_INIT:
        {
          FAR struct wg_msg_init_s *msg = (FAR struct wg_msg_init_s *)data;

          if (!wg_check_mac1(&priv->wg, data, sizeof(*msg) - 2 * WG_MAC_LEN,
                             msg->mac1))
            {
              break;
            }

          if (wg_under_load(priv))
            {
              uint8_t source[WG_SOURCE_LEN];

              wg_source_bytes(source, ip, port);
              if (!wg_check_mac2(&priv->wg, data, sizeof(*msg) - WG_MAC_LEN,
                                 source, sizeof(source), msg->mac2))
                {
                  wg_send_cookie(priv, msg->mac1, msg->sender, ip, port);
                  break;
                }
            }

          peer = wg_process_init(&priv->wg, msg);
          if (peer != NULL)
            {
              peer->ip = ip;
              peer->port = port;
              wg_send_response(priv, peer);
            }
        }
        break;

      case WG_MSG_HANDSHAKE_RESPONSE:
        {
          FAR struct wg_msg_response_s *msg =
            (FAR struct wg_msg_response_s *)data;

          if (!wg_check_mac1(&priv->wg, data, sizeof(*msg) - 2 * WG_MAC_LEN,
                             msg->mac1))
            {
              break;
            }

          peer = wg_peer_by_handshake(&priv->wg, msg->receiver);
          if (peer != NULL && wg_process_response(&priv->wg, peer, msg))
            {
              peer->ip = ip;
              peer->port = port;
              wg_start_session(peer, true);

              /* Confirm the session with a keepalive */

              wg_send_data(priv, peer, NULL, 0);
              netdev_lower_carrier_on(&priv->lower);
            }
        }
        break;

      case WG_MSG_COOKIE_REPLY:
        {
          FAR struct wg_msg_cookie_s *msg =
            (FAR struct wg_msg_cookie_s *)data;

          /* The peer is under load and wants mac2 on our next initiation.
           * Retry at once rather than waiting for the REKEY_TIMEOUT retry.
           */

          peer = wg_peer_by_handshake(&priv->wg, msg->receiver);
          if (peer != NULL && wg_process_cookie(&priv->wg, peer, msg))
            {
              wg_send_initiation(priv, peer);
            }
        }
        break;

      case WG_MSG_TRANSPORT_DATA:
        {
          FAR struct wg_msg_data_s *msg = (FAR struct wg_msg_data_s *)data;

          peer = wg_peer_by_receiver(&priv->wg, msg->receiver);
          if (peer != NULL)
            {
              wg_process_data(priv, peer, msg, len - WG_DATA_HDRLEN, ip,
                              port);
            }
        }
        break;

      default:
        break;
    }
}

/****************************************************************************
 * Name: wg_run_timers
 *
 * Description:
 *   Per-peer maintenance (6.1/6.2): expire old sessions, send keepalives,
 *   start or retry handshakes. Caller holds the device lock.
 *
 ****************************************************************************/

static void wg_run_timers(FAR struct wg_netdev_s *priv)
{
  bool link_up = false;
  int x;

  DEBUGASSERT(nxrmutex_is_hold(&priv->lower.netdev.d_lock));

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &priv->wg.peers[x];
      bool can_initiate;
      bool should_initiate;

      if (!peer->valid)
        {
          continue;
        }

      /* Nothing heard for three reject periods: forget everything,
       * including the learned endpoint.
       */

      if (peer->curr_keypair.valid &&
          wg_expired(peer->curr_keypair.keypair_millis,
                     WG_REJECT_AFTER_TIME * 3))
        {
          wg_keypair_destroy(&peer->next_keypair);
          wg_keypair_destroy(&peer->curr_keypair);
          wg_keypair_destroy(&peer->prev_keypair);
          peer->ip = peer->connect_ip;
          peer->port = peer->connect_port;
        }

      if (peer->curr_keypair.valid &&
          (wg_expired(peer->curr_keypair.keypair_millis,
                      WG_REJECT_AFTER_TIME) ||
           peer->curr_keypair.sending_counter >= WG_REJECT_AFTER_MESSAGES))
        {
          wg_keypair_destroy(&peer->curr_keypair);
        }

      if (peer->keepalive_interval > 0 &&
          (peer->curr_keypair.valid || peer->prev_keypair.valid) &&
          wg_expired(peer->last_tx, peer->keepalive_interval))
        {
          wg_send_data(priv, peer, NULL, 0);
        }

      can_initiate = peer->last_initiation_tx == 0 ||
                     wg_expired(peer->last_initiation_tx, WG_REKEY_TIMEOUT);

      should_initiate = can_initiate &&
        (peer->send_handshake ||
         (peer->curr_keypair.valid && !peer->curr_keypair.initiator &&
          wg_expired(peer->curr_keypair.keypair_millis,
                     WG_REJECT_AFTER_TIME - peer->keepalive_interval)) ||
         (!peer->curr_keypair.valid && peer->active));

      if (should_initiate)
        {
          wg_send_initiation(priv, peer);
        }

      if (peer->curr_keypair.valid || peer->prev_keypair.valid)
        {
          link_up = true;
        }
    }

  if (!link_up)
    {
      netdev_lower_carrier_off(&priv->lower);
    }
}

/****************************************************************************
 * Name: wg_poll_cb, wg_rx_thread
 *
 * Description:
 *   The receive thread waits on the UDP socket for at most WG_TIMER_MSECS,
 *   drains whatever arrived, and runs the timers. It owns the socket
 *   while running; ifdown waits for it to exit before closing it.
 *
 ****************************************************************************/

static void wg_poll_cb(FAR struct pollfd *fds)
{
  nxsem_post((FAR sem_t *)fds->arg);
}

static int wg_rx_thread(int argc, FAR char *argv[])
{
  FAR struct wg_netdev_s *priv;
  struct pollfd fds;
  int budget;
  int ifidx;

  ifidx = atoi(argv[1]);
  priv = &g_wg[ifidx];

  while (wg_running(priv))
    {
      struct sockaddr_in from;
      socklen_t fromlen;
      ssize_t n;

      memset(&fds, 0, sizeof(fds));
      fds.events = POLLIN;
      fds.arg    = &priv->wake;
      fds.cb     = wg_poll_cb;

      if (psock_poll(&priv->psock, &fds, true) >= 0)
        {
          nxsem_tickwait(&priv->wake, MSEC2TICK(WG_TIMER_MSECS));
          psock_poll(&priv->psock, &fds, false);
        }

      while (nxsem_trywait(&priv->wake) >= 0);

      /* Re-check running inside the drain loop: a sustained inbound flood
       * would otherwise keep this loop busy past ifdown's stop timeout,
       * and ifdown must be able to close the socket knowing the thread has
       * left it.
       */

      for (budget = 0;
           budget < WG_RX_BUDGET && wg_running(priv); budget++)
        {
          fromlen = sizeof(from);
          n = psock_recvfrom(&priv->psock, priv->rxbuf, WG_CRYPT_BUFSIZE,
                             MSG_DONTWAIT, (FAR struct sockaddr *)&from,
                             &fromlen);
          if (n <= 0)
            {
              break;
            }

          netdev_lock(&priv->lower.netdev);
          if (priv->running)
            {
              wg_process_datagram(priv, priv->rxbuf, (size_t)n,
                                  from.sin_addr.s_addr,
                                  ntohs(from.sin_port));
            }

          netdev_unlock(&priv->lower.netdev);
          netdev_lower_rxready(&priv->lower);
          wg_flush_tx(priv);
        }

      netdev_lock(&priv->lower.netdev);
      if (priv->running)
        {
          wg_run_timers(priv);
        }

      netdev_unlock(&priv->lower.netdev);
      wg_flush_tx(priv);
    }

#ifdef CONFIG_NET_WIREGUARD_DEBUG_STOP_STALL
  if (!priv->stop_stalled)
    {
      priv->stop_stalled = true;
      nxsig_usleep((WG_STOP_RETRIES + 1) * WG_STOP_WAIT_MSECS * 1000);
    }
#endif

  nxsem_post(&priv->rxdone);
  return 0;
}

/****************************************************************************
 * Name: wg_rx_teardown
 *
 * Description:
 *   Stop the RX thread and release the socket and semaphore, but only once
 *   the thread has confirmed it has left them (it posts rxdone as its last
 *   act). Idempotent: with rxpid == 0 there is nothing to do. If the bounded
 *   wait times out the thread is still live, so nothing is torn down and
 *   -ETIMEDOUT is returned; the interface stays in a stopping state (IFF_UP
 *   stays set) and a repeated ifdown calls this again to reap it. The wait
 *   releases d_lock so the socket worker can finish. reaping excludes a
 *   second waiter while that lock is released.
 *
 ****************************************************************************/

static int wg_rx_teardown(FAR struct wg_netdev_s *priv)
{
  int x;

  if (priv->rxpid == 0)
    {
      return OK;
    }

  if (priv->reaping)
    {
      return -EBUSY;
    }

  priv->reaping = true;
  priv->running = false;
  nxsem_post(&priv->wake);
  for (x = 0; x < WG_STOP_RETRIES; x++)
    {
      if (net_sem_timedwait2(&priv->rxdone, false, WG_STOP_WAIT_MSECS,
                             &priv->lower.netdev.d_lock, NULL) >= 0)
        {
          break;
        }
    }

  priv->reaping = false;
  if (x >= WG_STOP_RETRIES)
    {
      return -ETIMEDOUT;
    }

  priv->rxpid = 0;
  nxsem_destroy(&priv->rxdone);
  nxsem_destroy(&priv->wake);
  psock_close(&priv->psock);
  return OK;
}

/****************************************************************************
 * Name: wg_down_finish
 *
 * Description:
 *   Finish taking the interface down once the RX thread has stopped: wipe
 *   every peer's session and handshake state, restore the configured
 *   endpoints, and free anything left in the receive queue. Shared by
 *   wg_ifdown and its retry path so that a down whose stop
 *   timed out is still completed properly when the thread is finally reaped.
 *
 ****************************************************************************/

static void wg_down_finish(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  FAR struct wg_outbound_s *out;
  FAR netpkt_t *pkt;
  irqstate_t flags;
  int x;

  while ((out = (FAR struct wg_outbound_s *)
          sq_remfirst(&priv->txqueue)) != NULL)
    {
      kmm_free(out);
    }

  priv->ntx = 0;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &priv->wg.peers[x];

      if (peer->valid)
        {
          wg_peer_clear_sessions(peer);
          peer->ip = peer->connect_ip;
          peer->port = peer->connect_port;
        }
    }

  flags = spin_lock_irqsave(&priv->rxlock);
  while ((pkt = netpkt_remove_queue(&priv->rxqueue)) != NULL)
    {
      spin_unlock_irqrestore(&priv->rxlock, flags);
      netpkt_free(dev, pkt, NETPKT_RX);
      flags = spin_lock_irqsave(&priv->rxlock);
    }

  spin_unlock_irqrestore(&priv->rxlock, flags);
}

/****************************************************************************
 * Name: wg_ifup
 *
 * Description:
 *   Open the UDP socket and start the receive thread. Refused until a
 *   private key has been set.
 *
 ****************************************************************************/

static int wg_ifup(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  struct sockaddr_in addr;
  FAR char *argv[2];
  char arg[8];
  int ret;
  int x;

  DEBUGASSERT(nxrmutex_is_hold(&dev->netdev.d_lock));

  if (priv->bifup)
    {
      return OK;
    }

  /* netdev_ifup only reaches here with IFF_UP clear, which a previous
   * ifdown sets only after it fully stopped (rxpid == 0). A leftover thread
   * (a stop that timed out) keeps IFF_UP set, so recovery runs through a
   * repeated ifdown, not here. This guard is therefore defensive only.
   */

  if (priv->rxpid > 0)
    {
      nerr("ERROR: %s is still stopping\n", dev->netdev.d_ifname);
      return -EBUSY;
    }

  if (!priv->wg.valid)
    {
      nerr("ERROR: %s has no private key\n", dev->netdev.d_ifname);
      return -EINVAL;
    }

  ret = psock_socket(AF_INET, SOCK_DGRAM, 0, &priv->psock);
  if (ret < 0)
    {
      nerr("ERROR: psock_socket() failed: %d\n", ret);
      return ret;
    }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(priv->listen_port);

  ret = psock_bind(&priv->psock, (FAR struct sockaddr *)&addr,
                   sizeof(addr));
  if (ret < 0)
    {
      nerr("ERROR: psock_bind() failed: %d\n", ret);
      psock_close(&priv->psock);
      return ret;
    }

  /* Start from the configured endpoints and kick off handshakes to the
   * peers that have one.
   */

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &priv->wg.peers[x];

      if (peer->valid && peer->connect_ip != 0 && peer->connect_port != 0)
        {
          peer->active = true;
          peer->ip = peer->connect_ip;
          peer->port = peer->connect_port;
          peer->send_handshake = true;
        }
    }

  priv->running = true;
  nxsem_init(&priv->rxdone, 0, 0);
  nxsem_init(&priv->wake, 0, 0);

  snprintf(arg, sizeof(arg), "%d", (int)(priv - g_wg));
  argv[0] = arg;
  argv[1] = NULL;

  ret = kthread_create("wg_rx", CONFIG_NET_WIREGUARD_RXPRIORITY,
                       CONFIG_NET_WIREGUARD_RXSTACKSIZE, wg_rx_thread, argv);
  if (ret < 0)
    {
      nerr("ERROR: kthread_create failed: %d\n", ret);
      priv->running = false;
      nxsem_destroy(&priv->rxdone);
      nxsem_destroy(&priv->wake);
      psock_close(&priv->psock);
      return ret;
    }

  priv->rxpid = ret;
  priv->bifup = true;
  return OK;
}

/****************************************************************************
 * Name: wg_ifdown
 *
 * Description:
 *   Stop the receive thread, close the socket, and end every session:
 *   keys and handshake state are wiped and the endpoints fall back to
 *   the configured ones.
 *
 ****************************************************************************/

static int wg_ifdown(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  int ret;

  DEBUGASSERT(nxrmutex_is_hold(&dev->netdev.d_lock));

  /* Enter also while already down-but-stopping (bifup clear, rxpid set) so
   * a stop that previously timed out is reaped and finished here.
   */

  if (!priv->bifup && priv->rxpid == 0)
    {
      return OK;
    }

  priv->bifup = false;
  netdev_lower_carrier_off(dev);

  /* Stop the RX thread and wait for it to actually leave the socket and the
   * semaphore before either is destroyed. The thread checks running in both
   * its outer and inner loops and posts rxdone as its last act, so it
   * normally wakes within a poll period. A backend send can take longer.
   * On timeout nothing is torn
   * down (no close from under a live thread): d_ifdown returns an error so
   * the netdev layer leaves IFF_UP set, and a repeated ifdown (the only
   * caller reached while IFF_UP is still set) reaps the thread once it has
   * finally exited and completes the teardown.
   */

  ret = wg_rx_teardown(priv);
  if (ret < 0)
    {
      nerr("ERROR: %s RX thread did not stop; left stopping\n",
           dev->netdev.d_ifname);
      return ret;
    }

  wg_down_finish(dev);
  return OK;
}

/****************************************************************************
 * Name: wg_transmit
 *
 * Description:
 *   An IP packet from the stack. Route it to a peer by destination,
 *   encrypt and send. Without a session the packet is dropped and a
 *   handshake is requested; the stack will retransmit.
 *
 ****************************************************************************/

static int wg_transmit(FAR struct netdev_lowerhalf_s *dev,
                       FAR netpkt_t *pkt)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  FAR struct ipv4_hdr_s *iphdr;
  FAR struct wg_peer_s *peer;
  unsigned int len = netpkt_getdatalen(dev, pkt);
  int ret;

  DEBUGASSERT(nxrmutex_is_hold(&dev->netdev.d_lock));

  if (!priv->bifup || len < IPv4_HDRLEN || len > sizeof(priv->plainbuf))
    {
      goto drop;
    }

  netpkt_copyout(dev, priv->plainbuf, pkt, len, 0);
  iphdr = (FAR struct ipv4_hdr_s *)priv->plainbuf;

  if (((iphdr->vhl >> 4) & 0x0f) != 4)
    {
      goto drop;
    }

  peer = wg_peer_for_dest(priv, net_ip4addr_conv32(iphdr->destipaddr));
  if (peer == NULL)
    {
      goto drop;
    }

  ret = wg_send_data(priv, peer, priv->plainbuf, len);
  if (ret < 0)
    {
      if (ret != -ENOKEY)
        {
          goto drop;  /* Backpressure does not invalidate the session */
        }

      /* No usable session: ask for one now instead of on the next timer
       * tick, unless one was requested within REKEY_TIMEOUT.
       */

      peer->active = true;
      if (peer->last_initiation_tx == 0 ||
          wg_expired(peer->last_initiation_tx, WG_REKEY_TIMEOUT))
        {
          wg_send_initiation(priv, peer);
        }
      else
        {
          peer->send_handshake = true;
        }

      goto drop;
    }

  netpkt_free(dev, pkt, NETPKT_TX);
  netdev_lower_txdone(dev);
  return OK;

drop:
  NETDEV_ERRORS(&dev->netdev);
  netpkt_free(dev, pkt, NETPKT_TX);
  netdev_lower_txdone(dev);
  return OK;
}

/****************************************************************************
 * Name: wg_receive
 *
 * Description:
 *   Hand the upper half the next decrypted packet, if any.
 *
 ****************************************************************************/

static FAR netpkt_t *wg_receive(FAR struct netdev_lowerhalf_s *dev)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  FAR netpkt_t *pkt;
  irqstate_t flags;

  flags = spin_lock_irqsave(&priv->rxlock);
  pkt = netpkt_remove_queue(&priv->rxqueue);
  spin_unlock_irqrestore(&priv->rxlock, flags);

  return pkt;
}

/****************************************************************************
 * Name: wg_aip_overlaps
 *
 * Description:
 *   True if a prefix is already claimed by another peer's allowed-ips
 *   (cryptokey routing requires each destination to map to one peer).
 *
 ****************************************************************************/

static bool wg_aip_overlaps(FAR struct wg_netdev_s *priv,
                            FAR const struct wg_peer_s *self,
                            in_addr_t ip, in_addr_t mask)
{
  int x;
  int y;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &priv->wg.peers[x];

      if (!peer->valid || peer == self)
        {
          continue;
        }

      for (y = 0; y < WG_MAX_AIPS_PER_PEER; y++)
        {
          FAR struct wg_allowed_s *aip = &peer->allowed[y];
          in_addr_t common;

          if (!aip->valid)
            {
              continue;
            }

          common = mask & aip->mask;
          if ((ip & common) == (aip->ip & common))
            {
              return true;
            }
        }
    }

  return false;
}

/****************************************************************************
 * Name: wg_set_peer
 *
 * Description:
 *   SIOCSWGPEER: add a peer or update an existing one, addressed by
 *   public key. Everything is validated into a copy first so that a
 *   rejected request leaves the peer untouched.
 *
 ****************************************************************************/

static int wg_set_peer(FAR struct wg_netdev_s *priv,
                       FAR const struct wg_peerreq_s *req)
{
  FAR struct wg_peer_s *peer;
  struct wg_allowed_s allowed[WG_MAX_AIPS_PER_PEER];
  bool created = false;
  int naips = 0;
  int i;

  if (!priv->wg.valid)
    {
      return -ENOKEY;
    }

  if (wg_is_zero(req->public_key, WG_KEY_LEN) ||
      wg_equal(req->public_key, priv->wg.public_key, WG_KEY_LEN))
    {
      return -EINVAL;
    }

  if (req->flags & WG_PEER_HAS_ENDPOINT)
    {
      if (req->endpoint.sin_family != AF_INET ||
          req->endpoint.sin_port == 0 ||
          req->endpoint.sin_addr.s_addr == INADDR_ANY ||
          IN_MULTICAST(ntohl(req->endpoint.sin_addr.s_addr)))
        {
          return -EINVAL;
        }
    }

  peer = wg_peer_by_pubkey(&priv->wg, req->public_key);

  /* Allowed-ips: normalise, then check they do not collide with another
   * peer's. When appending, the existing entries count towards the limit.
   */

  memset(allowed, 0, sizeof(allowed));
  if (req->flags & WG_PEER_HAS_AIPS)
    {
      if (req->naips > WG_MAX_AIPS)
        {
          return -EINVAL;
        }

      if (peer != NULL && !(req->flags & WG_PEER_REPLACE_AIPS))
        {
          for (i = 0; i < WG_MAX_AIPS_PER_PEER; i++)
            {
              if (peer->allowed[i].valid)
                {
                  allowed[naips++] = peer->allowed[i];
                }
            }
        }

      for (i = 0; i < req->naips; i++)
        {
          in_addr_t mask;

          if (req->aips[i].cidr > 32 || naips >= WG_MAX_AIPS_PER_PEER)
            {
              return naips >= WG_MAX_AIPS_PER_PEER ? -ENOSPC : -EINVAL;
            }

          mask = req->aips[i].cidr == 0 ? 0 :
                 htonl(0xffffffffu << (32 - req->aips[i].cidr));

          if (wg_aip_overlaps(priv, peer, req->aips[i].addr.s_addr, mask))
            {
              return -EEXIST;
            }

          allowed[naips].valid = true;
          allowed[naips].ip = req->aips[i].addr.s_addr & mask;
          allowed[naips].mask = mask;
          naips++;
        }
    }

  if (peer == NULL)
    {
      peer = wg_peer_alloc(&priv->wg);
      if (peer == NULL)
        {
          return -ENOSPC;
        }

      if (!wg_peer_init(&priv->wg, peer, req->public_key,
                        (req->flags & WG_PEER_HAS_PSK) ?
                        req->preshared_key : NULL))
        {
          return -EINVAL;   /* Low-order public key */
        }

      created = true;
    }
  else if (req->flags & WG_PEER_HAS_PSK)
    {
      memcpy(peer->preshared_key, req->preshared_key, WG_SESSION_KEY_LEN);
    }

  if (req->flags & WG_PEER_HAS_ENDPOINT)
    {
      peer->connect_ip = req->endpoint.sin_addr.s_addr;
      peer->connect_port = ntohs(req->endpoint.sin_port);
      if (created || !peer->curr_keypair.valid)
        {
          peer->ip = peer->connect_ip;
          peer->port = peer->connect_port;
        }

      if (priv->bifup)
        {
          peer->active = true;
          peer->send_handshake = true;
        }
    }

  if (req->flags & WG_PEER_HAS_KEEPALIVE)
    {
      peer->keepalive_interval = req->keepalive;
    }

  if (req->flags & WG_PEER_HAS_AIPS)
    {
      memcpy(peer->allowed, allowed, sizeof(allowed));
    }

  return OK;
}

/****************************************************************************
 * Name: wg_get_peer
 *
 * Description:
 *   SIOCGWGPEER: the index-th configured peer.
 *
 ****************************************************************************/

static int wg_get_peer(FAR struct wg_netdev_s *priv,
                       FAR struct wg_peerreq_s *req)
{
  FAR struct wg_peer_s *peer = NULL;
  int seen = 0;
  int x;
  int i;

  for (x = 0; x < WG_MAX_PEERS && peer == NULL; x++)
    {
      if (priv->wg.peers[x].valid && seen++ == req->index)
        {
          peer = &priv->wg.peers[x];
        }
    }

  if (peer == NULL)
    {
      return -ENOENT;
    }

  req->flags = 0;
  memcpy(req->public_key, peer->public_key, WG_KEY_LEN);
  memset(req->preshared_key, 0, WG_KEY_LEN);
  if (!wg_is_zero(peer->preshared_key, WG_KEY_LEN))
    {
      req->flags |= WG_PEER_HAS_PSK;   /* Present, but not disclosed */
    }

  memset(&req->endpoint, 0, sizeof(req->endpoint));
  if (peer->ip != 0)
    {
      req->flags |= WG_PEER_HAS_ENDPOINT;
      req->endpoint.sin_family = AF_INET;
      req->endpoint.sin_addr.s_addr = peer->ip;
      req->endpoint.sin_port = htons(peer->port);
    }

  req->flags |= WG_PEER_HAS_KEEPALIVE;
  req->keepalive = peer->keepalive_interval;

  req->naips = 0;
  for (i = 0; i < WG_MAX_AIPS_PER_PEER; i++)
    {
      FAR struct wg_allowed_s *aip = &peer->allowed[i];
      uint32_t hmask;
      uint8_t cidr = 0;

      if (!aip->valid)
        {
          continue;
        }

      for (hmask = ntohl(aip->mask); hmask & 0x80000000u; hmask <<= 1)
        {
          cidr++;
        }

      req->aips[req->naips].addr.s_addr = aip->ip;
      req->aips[req->naips].cidr = cidr;
      req->naips++;
    }

  if (req->naips > 0)
    {
      req->flags |= WG_PEER_HAS_AIPS;
    }

  req->last_handshake = WG_HANDSHAKE_NEVER;
  if (peer->curr_keypair.valid)
    {
      req->flags |= WG_PEER_HANDSHAKED;
      req->last_handshake = wg_now() - peer->curr_keypair.keypair_millis;
    }

  req->rx_bytes = peer->rx_bytes;
  req->tx_bytes = peer->tx_bytes;
  return OK;
}

/****************************************************************************
 * Name: wg_set_if
 *
 * Description:
 *   SIOCSWGIF. The private key and listen port can only change while the
 *   interface is down: sessions are bound to them.
 *
 ****************************************************************************/

static int wg_set_if(FAR struct wg_netdev_s *priv,
                     FAR const struct wg_ifreq_s *req)
{
  int ret = OK;

  if ((req->flags & WG_IF_UP) && !priv->bifup && priv->rxpid != 0)
    {
      return -EBUSY;  /* netdev_ifup would otherwise skip the callback */
    }

  if ((req->flags & (WG_IF_HAS_PRIVATE_KEY | WG_IF_HAS_LISTEN_PORT)) &&
      (priv->bifup || priv->rxpid != 0))
    {
      return -EBUSY;
    }

  if (req->flags & WG_IF_HAS_PRIVATE_KEY)
    {
      size_t savedsize = sizeof(struct wg_peer_s) * WG_MAX_PEERS;
      FAR struct wg_peer_s *saved;
      int x;

      if (wg_is_zero(req->private_key, WG_KEY_LEN))
        {
          return -EINVAL;
        }

      /* Peers precompute DH with the static key, so re-initialise them
       * from their configuration afterwards. wg_peer_s is large (it holds
       * keypairs and anti-replay windows), so this snapshot goes on the
       * heap rather than the stack, which is small in kernel builds.
       */

      saved = kmm_malloc(savedsize);
      if (saved == NULL)
        {
          return -ENOMEM;
        }

      memcpy(saved, priv->wg.peers, savedsize);
      wg_zero(&priv->wg, sizeof(priv->wg));

      if (!wg_device_init(&priv->wg, req->private_key))
        {
          wg_zero(saved, savedsize);
          kmm_free(saved);
          return -EINVAL;
        }

      for (x = 0; x < WG_MAX_PEERS; x++)
        {
          FAR struct wg_peer_s *peer = &priv->wg.peers[x];

          if (!saved[x].valid)
            {
              continue;
            }

          if (wg_peer_init(&priv->wg, peer, saved[x].public_key,
                           wg_is_zero(saved[x].preshared_key, WG_KEY_LEN) ?
                           NULL : saved[x].preshared_key))
            {
              peer->connect_ip = saved[x].connect_ip;
              peer->connect_port = saved[x].connect_port;
              peer->ip = saved[x].connect_ip;
              peer->port = saved[x].connect_port;
              peer->keepalive_interval = saved[x].keepalive_interval;
              memcpy(peer->allowed, saved[x].allowed, sizeof(peer->allowed));
            }
        }

      wg_zero(saved, savedsize);
      kmm_free(saved);
    }

  if (req->flags & WG_IF_HAS_LISTEN_PORT)
    {
      priv->listen_port = req->listen_port;
    }

  if (req->flags & WG_IF_HAS_ADDR)
    {
      priv->lower.netdev.d_ipaddr = req->addr.s_addr;
      priv->lower.netdev.d_netmask = req->netmask.s_addr;
    }

  if (req->flags & WG_IF_UP)
    {
      ret = netdev_ifup(&priv->lower.netdev);
    }
  else if (req->flags & WG_IF_DOWN)
    {
      ret = netdev_ifdown(&priv->lower.netdev);
    }

  return ret;
}

/****************************************************************************
 * Name: wg_get_if
 *
 * Description:
 *   SIOCGWGIF. The private key is never copied out.
 *
 ****************************************************************************/

static void wg_get_if(FAR struct wg_netdev_s *priv,
                      FAR struct wg_ifreq_s *req)
{
  int x;

  req->flags = WG_IF_HAS_LISTEN_PORT | WG_IF_HAS_ADDR;
  memset(req->private_key, 0, WG_KEY_LEN);
  memset(req->public_key, 0, WG_KEY_LEN);

  if (priv->wg.valid)
    {
      req->flags |= WG_IF_HAS_PUBLIC_KEY;
      memcpy(req->public_key, priv->wg.public_key, WG_KEY_LEN);
    }

  if (priv->bifup)
    {
      req->flags |= WG_IF_UP;
    }

  req->listen_port = priv->listen_port;
  req->addr.s_addr = priv->lower.netdev.d_ipaddr;
  req->netmask.s_addr = priv->lower.netdev.d_netmask;

  req->npeers = 0;
  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      if (priv->wg.peers[x].valid)
        {
          req->npeers++;
        }
    }
}

/****************************************************************************
 * Name: wg_ioctl
 *
 * Description:
 *   The five WireGuard control commands (include/nuttx/net/wireguard.h).
 *   The request structures are flat and fixed-size and are read from and
 *   written to the caller's copy directly.
 *
 ****************************************************************************/

static int wg_ioctl(FAR struct netdev_lowerhalf_s *dev, int cmd,
                    unsigned long arg)
{
  FAR struct wg_netdev_s *priv = (FAR struct wg_netdev_s *)dev;
  int ret;

  netdev_lock(&dev->netdev);

  switch (cmd)
    {
      case SIOCSWGIF:
        ret = wg_set_if(priv, (FAR const struct wg_ifreq_s *)(uintptr_t)arg);
        break;

      case SIOCGWGIF:
        wg_get_if(priv, (FAR struct wg_ifreq_s *)(uintptr_t)arg);
        ret = OK;
        break;

      case SIOCSWGPEER:
        ret = wg_set_peer(priv,
                          (FAR const struct wg_peerreq_s *)(uintptr_t)arg);
        break;

      case SIOCDWGPEER:
        {
          FAR const struct wg_peerreq_s *req =
            (FAR const struct wg_peerreq_s *)(uintptr_t)arg;
          FAR struct wg_peer_s *peer;

          if (priv->bifup || priv->rxpid != 0)
            {
              ret = -EBUSY;   /* Sessions may be in flight */
              break;
            }

          peer = wg_peer_by_pubkey(&priv->wg, req->public_key);
          if (peer == NULL)
            {
              ret = -ENOENT;
              break;
            }

          wg_peer_destroy(peer);
          ret = OK;
        }
        break;

      case SIOCGWGPEER:
        ret = wg_get_peer(priv, (FAR struct wg_peerreq_s *)(uintptr_t)arg);
        break;

      default:
        ret = -ENOTTY;
        break;
    }

  netdev_unlock(&dev->netdev);
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wireguard_initialize
 *
 * Description:
 *   Register wg0 .. wgN-1. Nothing is opened or started here; the socket
 *   and receive thread are created by ifup, once a key has been set.
 *
 ****************************************************************************/

int wireguard_initialize(void)
{
  int ret = OK;
  int i;

  wg_noise_init();

  for (i = 0; i < WG_NINTERFACES; i++)
    {
      FAR struct wg_netdev_s *priv = &g_wg[i];
      FAR struct netdev_lowerhalf_s *dev = &priv->lower;

      memset(priv, 0, sizeof(*priv));
      spin_lock_init(&priv->rxlock);
      priv->listen_port = 51820 + i;

      dev->ops = &g_wg_ops;
      /* RX already has a thread. Direct notification also avoids waiting
       * for an upper-half work item holding/waiting for d_lock on ifdown.
       */

      dev->rxtype = NETDEV_RX_DIRECT;
      dev->quota[NETPKT_RX] = WG_RX_QUOTA;
      dev->quota[NETPKT_TX] = 1;
      dev->netdev.d_pktsize = WG_PKTSIZE;
      strlcpy(dev->netdev.d_ifname, "wg%d", IFNAMSIZ);

      ret = netdev_lower_register(dev, NET_LL_TUN);
      if (ret < 0)
        {
          nerr("ERROR: netdev_lower_register failed: %d\n", ret);
          break;
        }
    }

  return ret;
}
