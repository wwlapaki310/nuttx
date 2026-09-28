/****************************************************************************
 * drivers/net/wireguard/wg_noise.h
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: 2021 Daniel Hope (www.floorsense.nz)
 * SPDX-FileContributor: Daniel Hope <daniel.hope@smartalock.com>
 * SPDX-FileContributor: Satoru Akita
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived from wireguard.h in smartalock/wireguard-lwip. The protocol
 * state machine is unchanged; the structures are re-expressed in NuttX
 * style, lwIP types are replaced by in_addr_t, and the anti-replay window
 * is wider than the original.
 *
 ****************************************************************************/

#ifndef __DRIVERS_NET_WIREGUARD_WG_NOISE_H
#define __DRIVERS_NET_WIREGUARD_WG_NOISE_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "wg_crypto.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_MAX_PEERS          CONFIG_NET_WIREGUARD_MAX_PEERS
#define WG_MAX_AIPS_PER_PEER  CONFIG_NET_WIREGUARD_MAX_AIPS
#define WG_REPLAY_WORDS       (CONFIG_NET_WIREGUARD_REPLAY_WINDOW / 64)

/* Timers and limits (whitepaper 6.1), seconds unless noted */

#define WG_COOKIE_SECRET_MAX_AGE  (2 * 60)
#define WG_REKEY_AFTER_MESSAGES   (1ull << 60)
#define WG_REJECT_AFTER_MESSAGES  (0xffffffffffffffffull - (1ull << 13))
#define WG_REKEY_AFTER_TIME       120
#define WG_REJECT_AFTER_TIME      180
#define WG_REKEY_TIMEOUT          5
#define WG_KEEPALIVE_TIMEOUT      10

/* Message types (5.4) */

#define WG_MSG_INVALID            0
#define WG_MSG_HANDSHAKE_INIT     1
#define WG_MSG_HANDSHAKE_RESPONSE 2
#define WG_MSG_COOKIE_REPLY       3
#define WG_MSG_TRANSPORT_DATA     4

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* Wire formats. The 32-bit index fields are opaque values chosen by each
 * side and echoed back, so no byte-order conversion is applied to them;
 * the data counter is little-endian and is handled as bytes.
 */

begin_packed_struct struct wg_msg_init_s
{
  uint8_t type;
  uint8_t reserved[3];
  uint32_t sender;
  uint8_t ephemeral[WG_KEY_LEN];
  uint8_t enc_static[WG_KEY_LEN + WG_AUTHTAG_LEN];
  uint8_t enc_timestamp[WG_TAI64N_LEN + WG_AUTHTAG_LEN];
  uint8_t mac1[WG_MAC_LEN];
  uint8_t mac2[WG_MAC_LEN];
} end_packed_struct;

begin_packed_struct struct wg_msg_response_s
{
  uint8_t type;
  uint8_t reserved[3];
  uint32_t sender;
  uint32_t receiver;
  uint8_t ephemeral[WG_KEY_LEN];
  uint8_t enc_empty[WG_AUTHTAG_LEN];
  uint8_t mac1[WG_MAC_LEN];
  uint8_t mac2[WG_MAC_LEN];
} end_packed_struct;

begin_packed_struct struct wg_msg_cookie_s
{
  uint8_t type;
  uint8_t reserved[3];
  uint32_t receiver;
  uint8_t nonce[WG_COOKIE_NONCE_LEN];
  uint8_t enc_cookie[WG_COOKIE_LEN + WG_AUTHTAG_LEN];
} end_packed_struct;

begin_packed_struct struct wg_msg_data_s
{
  uint8_t type;
  uint8_t reserved[3];
  uint32_t receiver;
  uint8_t counter[8];

  /* Followed by the encrypted packet and its tag */
} end_packed_struct;

/* One transport session (5.4.5) */

struct wg_keypair_s
{
  bool valid;
  bool initiator;               /* We sent the initiation for this session */
  bool sending_valid;
  bool receiving_valid;
  uint32_t keypair_millis;      /* wg_now() when established */
  uint32_t local_index;
  uint32_t remote_index;
  uint32_t last_tx;
  uint32_t last_rx;
  uint64_t sending_counter;
  uint64_t replay_counter;      /* Highest counter received, plus one */
  uint64_t replay_bitmap[WG_REPLAY_WORDS];
  uint8_t sending_key[WG_SESSION_KEY_LEN];
  uint8_t receiving_key[WG_SESSION_KEY_LEN];
};

/* An in-progress handshake */

struct wg_handshake_s
{
  bool valid;
  bool initiator;
  uint32_t local_index;
  uint32_t remote_index;
  uint8_t ephemeral_private[WG_KEY_LEN];
  uint8_t remote_ephemeral[WG_KEY_LEN];
  uint8_t hash[WG_HASH_LEN];
  uint8_t chaining_key[WG_HASH_LEN];
};

/* A cryptokey-routing entry: destinations routed to, and sources accepted
 * from, the peer.
 */

struct wg_allowed_s
{
  bool valid;
  in_addr_t ip;                 /* Network byte order */
  in_addr_t mask;               /* Network byte order */
};

struct wg_peer_s
{
  bool valid;                   /* Slot in use */
  bool active;                  /* Try to keep a session up */
  bool send_handshake;          /* An initiation is due */
  bool handshake_mac1_valid;    /* handshake_mac1 is the last one we sent */
  uint16_t keepalive_interval;  /* Seconds; 0 disables */

  /* Endpoint: the configured one, and the last one a valid packet came
   * from (which is where we send).
   */

  in_addr_t connect_ip;
  uint16_t connect_port;
  in_addr_t ip;
  uint16_t port;

  struct wg_allowed_s allowed[WG_MAX_AIPS_PER_PEER];

  uint8_t public_key[WG_KEY_LEN];
  uint8_t preshared_key[WG_SESSION_KEY_LEN];
  uint8_t public_key_dh[WG_KEY_LEN];    /* DH(our static, their static) */

  struct wg_keypair_s curr_keypair;
  struct wg_keypair_s prev_keypair;
  struct wg_keypair_s next_keypair;

  uint8_t greatest_timestamp[WG_TAI64N_LEN];  /* Replay guard (5.1) */
  struct wg_handshake_s handshake;

  uint32_t cookie_millis;       /* When cookie was received; 0 = none */
  uint8_t cookie[WG_COOKIE_LEN];
  uint8_t handshake_mac1[WG_MAC_LEN];

  uint8_t label_cookie_key[WG_SESSION_KEY_LEN];  /* Hash(Label-Cookie||S) */
  uint8_t label_mac1_key[WG_SESSION_KEY_LEN];    /* Hash(Label-Mac1||S) */

  uint32_t last_initiation_rx;
  uint32_t last_initiation_tx;
  uint32_t last_tx;
  uint32_t last_rx;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
};

struct wg_device_s
{
  bool valid;                   /* A private key has been set */
  uint8_t public_key[WG_KEY_LEN];
  uint8_t private_key[WG_KEY_LEN];
  uint8_t cookie_secret[WG_HASH_LEN];
  uint32_t cookie_secret_millis;
  uint8_t label_cookie_key[WG_SESSION_KEY_LEN];
  uint8_t label_mac1_key[WG_SESSION_KEY_LEN];
  struct wg_peer_s peers[WG_MAX_PEERS];
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* Device and peers */

void wg_noise_init(void);
bool wg_device_init(FAR struct wg_device_s *dev,
                    FAR const uint8_t *private_key);
bool wg_peer_init(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer,
                  FAR const uint8_t *public_key,
                  FAR const uint8_t *preshared_key);
void wg_peer_destroy(FAR struct wg_peer_s *peer);
void wg_peer_clear_sessions(FAR struct wg_peer_s *peer);
FAR struct wg_peer_s *wg_peer_alloc(FAR struct wg_device_s *dev);
int wg_peer_index(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer);
FAR struct wg_peer_s *wg_peer_by_pubkey(FAR struct wg_device_s *dev,
                                        FAR const uint8_t *public_key);
FAR struct wg_peer_s *wg_peer_by_receiver(FAR struct wg_device_s *dev,
                                          uint32_t receiver);
FAR struct wg_peer_s *wg_peer_by_handshake(FAR struct wg_device_s *dev,
                                           uint32_t receiver);

/* Sessions */

void wg_start_session(FAR struct wg_peer_s *peer, bool initiator);
void wg_keypair_update(FAR struct wg_peer_s *peer,
                       FAR struct wg_keypair_s *received);
void wg_keypair_destroy(FAR struct wg_keypair_s *keypair);
FAR struct wg_keypair_s *wg_keypair_by_index(FAR struct wg_peer_s *peer,
                                             uint32_t idx);
bool wg_check_replay(FAR struct wg_keypair_s *keypair, uint64_t counter);
bool wg_expired(uint32_t created_millis, uint32_t valid_seconds);

/* Messages */

uint8_t wg_message_type(FAR const uint8_t *data, size_t len);
bool wg_check_mac1(FAR struct wg_device_s *dev, FAR const uint8_t *data,
                   size_t len, FAR const uint8_t *mac1);
bool wg_check_mac2(FAR struct wg_device_s *dev, FAR const uint8_t *data,
                   size_t len, FAR const uint8_t *source, size_t sourcelen,
                   FAR const uint8_t *mac2);
FAR struct wg_peer_s *wg_process_init(FAR struct wg_device_s *dev,
                                      FAR struct wg_msg_init_s *msg);
bool wg_process_response(FAR struct wg_device_s *dev,
                         FAR struct wg_peer_s *peer,
                         FAR struct wg_msg_response_s *msg);
bool wg_process_cookie(FAR struct wg_device_s *dev,
                       FAR struct wg_peer_s *peer,
                       FAR struct wg_msg_cookie_s *msg);
bool wg_create_init(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer,
                    FAR struct wg_msg_init_s *msg);
bool wg_create_response(FAR struct wg_device_s *dev,
                        FAR struct wg_peer_s *peer,
                        FAR struct wg_msg_response_s *msg);
bool wg_create_cookie(FAR struct wg_device_s *dev,
                      FAR struct wg_msg_cookie_s *msg,
                      FAR const uint8_t *mac1, uint32_t index,
                      FAR const uint8_t *source, size_t sourcelen);

/* Transport data */

void wg_encrypt_packet(FAR uint8_t *dst, FAR const uint8_t *src,
                       size_t srclen, FAR struct wg_keypair_s *keypair);
bool wg_decrypt_packet(FAR uint8_t *dst, FAR const uint8_t *src,
                       size_t srclen, uint64_t counter,
                       FAR struct wg_keypair_s *keypair);

#endif /* __DRIVERS_NET_WIREGUARD_WG_NOISE_H */
