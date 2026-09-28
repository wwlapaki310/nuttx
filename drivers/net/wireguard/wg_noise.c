/****************************************************************************
 * drivers/net/wireguard/wg_noise.c
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
 * Derived from wireguard.c in smartalock/wireguard-lwip: the Noise_IKpsk2
 * handshake, session key schedule, cookie mechanism and transport data
 * encryption of the WireGuard protocol (https://www.wireguard.com/papers/
 * wireguard.pdf, section numbers below refer to it). Compared with the
 * original: NuttX coding style, NuttX crypto/ primitives through
 * wg_crypto.h, a wider anti-replay window, and a repaired per-peer
 * initiation rate limit. Nothing here touches the network; that is the
 * job of wireguard.c.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "wg_crypto.h"
#include "wg_noise.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Valid initiations accepted from one peer per second (5.4.7) */

#define WG_MAX_INITIATIONS_PER_SECOND 2

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* 5.4 constants. The lengths are those of the strings without NUL. */

static const uint8_t g_construction[37] =
  "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t g_identifier[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const uint8_t g_label_mac1[8] = "mac1----";
static const uint8_t g_label_cookie[8] = "cookie--";

/* Hash(Construction) and Hash(Hash(Construction) || Identifier),
 * computed once by wg_noise_init().
 */

static uint8_t g_construction_hash[WG_HASH_LEN];
static uint8_t g_identifier_hash[WG_HASH_LEN];

static const uint8_t g_zero_key[WG_KEY_LEN];

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_mac_key
 *
 * Description:
 *   Hash(Label || public key): the key for mac1 (Label-Mac1) and for the
 *   cookie reply AEAD (Label-Cookie), precomputed per key.
 *
 ****************************************************************************/

static void wg_mac_key(FAR uint8_t *key, FAR const uint8_t *public_key,
                       FAR const uint8_t *label, size_t labellen)
{
  uint8_t buf[8 + WG_KEY_LEN];

  memcpy(buf, label, labellen);
  memcpy(buf + labellen, public_key, WG_KEY_LEN);
  wg_hash(key, buf, labellen + WG_KEY_LEN);
}

/****************************************************************************
 * Name: wg_new_cookie_secret, wg_peer_cookie
 *
 * Description:
 *   5.4.7: the cookie for a source is Mac(Rm, source address || port),
 *   with the secret Rm rotated every two minutes.
 *
 ****************************************************************************/

static void wg_new_cookie_secret(FAR struct wg_device_s *dev)
{
  wg_random(dev->cookie_secret, sizeof(dev->cookie_secret));
  dev->cookie_secret_millis = wg_now();
}

static void wg_peer_cookie(FAR struct wg_device_s *dev, FAR uint8_t *cookie,
                           FAR const uint8_t *source, size_t sourcelen)
{
  if (wg_expired(dev->cookie_secret_millis, WG_COOKIE_SECRET_MAX_AGE))
    {
      wg_new_cookie_secret(dev);
    }

  wg_mac(cookie, source, sourcelen, dev->cookie_secret, WG_HASH_LEN);
}

/****************************************************************************
 * Name: wg_unique_index
 *
 * Description:
 *   A random 32-bit session/handshake index not currently in use by any
 *   peer of this device (0 and 0xffffffff are reserved).
 *
 ****************************************************************************/

static uint32_t wg_unique_index(FAR struct wg_device_s *dev)
{
  uint8_t buf[4];
  uint32_t result;
  bool existing;
  int x;

  do
    {
      do
        {
          wg_random(buf, sizeof(buf));
          result = wg_read_le32(buf);
        }
      while (result == 0 || result == 0xffffffff);

      existing = false;
      for (x = 0; x < WG_MAX_PEERS && !existing; x++)
        {
          FAR struct wg_peer_s *peer = &dev->peers[x];

          existing = result == peer->curr_keypair.local_index ||
                     result == peer->prev_keypair.local_index ||
                     result == peer->next_keypair.local_index ||
                     result == peer->handshake.local_index;
        }
    }
  while (existing);

  return result;
}

/****************************************************************************
 * Name: wg_generate_private_key, wg_generate_public_key
 ****************************************************************************/

static bool wg_generate_private_key(FAR uint8_t *key)
{
  if (!wg_random(key, WG_KEY_LEN))
    {
      return false;
    }

  wg_x25519_clamp(key);
  return true;
}

static bool wg_generate_public_key(FAR uint8_t *public_key,
                                   FAR const uint8_t *private_key)
{
  if (wg_equal(private_key, g_zero_key, WG_KEY_LEN))
    {
      return false;
    }

  return wg_x25519_public(public_key, private_key);
}

/****************************************************************************
 * Name: wg_add_keypair
 *
 * Description:
 *   Install a freshly derived session (5.4.5): as initiator it becomes
 *   current at once, as responder it is "next" until the initiator's
 *   first data packet confirms it (wg_keypair_update()).
 *
 ****************************************************************************/

static void wg_add_keypair(FAR struct wg_peer_s *peer,
                           FAR const struct wg_keypair_s *keypair)
{
  if (keypair->initiator)
    {
      if (peer->next_keypair.valid)
        {
          peer->prev_keypair = peer->next_keypair;
          wg_keypair_destroy(&peer->next_keypair);
        }
      else
        {
          peer->prev_keypair = peer->curr_keypair;
        }

      peer->curr_keypair = *keypair;
    }
  else
    {
      peer->next_keypair = *keypair;
      wg_keypair_destroy(&peer->prev_keypair);
    }
}

/****************************************************************************
 * Name: wg_sign_message
 *
 * Description:
 *   Append mac1 and, when we hold a fresh cookie from this peer, mac2 to
 *   an initiation or response (5.4.4). len is the full message length;
 *   mac1 and mac2 are the last two 16-byte fields.
 *
 ****************************************************************************/

static void wg_sign_message(FAR struct wg_peer_s *peer, FAR uint8_t *msg,
                            size_t len)
{
  FAR uint8_t *mac1 = msg + len - 2 * WG_MAC_LEN;
  FAR uint8_t *mac2 = msg + len - WG_MAC_LEN;

  wg_mac(mac1, msg, len - 2 * WG_MAC_LEN, peer->label_mac1_key,
         WG_SESSION_KEY_LEN);

  if (peer->cookie_millis == 0 ||
      wg_expired(peer->cookie_millis, WG_COOKIE_SECRET_MAX_AGE))
    {
      wg_zero(mac2, WG_MAC_LEN);
    }
  else
    {
      wg_mac(mac2, msg, len - WG_MAC_LEN, peer->cookie, WG_COOKIE_LEN);
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_noise_init
 *
 * Description:
 *   Precompute the two hashes every handshake starts from. Call once.
 *
 ****************************************************************************/

void wg_noise_init(void)
{
  uint8_t buf[WG_HASH_LEN + sizeof(g_identifier)];

  wg_hash(g_construction_hash, g_construction, sizeof(g_construction));

  memcpy(buf, g_construction_hash, WG_HASH_LEN);
  memcpy(buf + WG_HASH_LEN, g_identifier, sizeof(g_identifier));
  wg_hash(g_identifier_hash, buf, sizeof(buf));
}

/****************************************************************************
 * Name: wg_device_init
 *
 * Description:
 *   Set the device's static key pair from a private key. Peers must be
 *   (re)initialised afterwards, since their precomputed DH depends on it.
 *
 ****************************************************************************/

bool wg_device_init(FAR struct wg_device_s *dev,
                    FAR const uint8_t *private_key)
{
  memcpy(dev->private_key, private_key, WG_KEY_LEN);
  wg_x25519_clamp(dev->private_key);

  dev->valid = wg_generate_public_key(dev->public_key, dev->private_key);
  if (!dev->valid)
    {
      wg_zero(dev->private_key, WG_KEY_LEN);
      return false;
    }

  wg_new_cookie_secret(dev);
  wg_mac_key(dev->label_mac1_key, dev->public_key, g_label_mac1,
             sizeof(g_label_mac1));
  wg_mac_key(dev->label_cookie_key, dev->public_key, g_label_cookie,
             sizeof(g_label_cookie));
  return true;
}

/****************************************************************************
 * Name: wg_peer_init
 *
 * Description:
 *   Initialise a peer slot with its static public key and optional
 *   pre-shared key, and precompute DH(our static, their static). Fails
 *   for a low-order public key, whose DH result would be zero.
 *
 ****************************************************************************/

bool wg_peer_init(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer,
                  FAR const uint8_t *public_key,
                  FAR const uint8_t *preshared_key)
{
  wg_zero(peer, sizeof(*peer));

  if (!dev->valid)
    {
      return false;
    }

  memcpy(peer->public_key, public_key, WG_KEY_LEN);
  if (preshared_key != NULL)
    {
      memcpy(peer->preshared_key, preshared_key, WG_SESSION_KEY_LEN);
    }

  if (!wg_x25519(peer->public_key_dh, dev->private_key, peer->public_key))
    {
      wg_zero(peer, sizeof(*peer));
      return false;
    }

  wg_mac_key(peer->label_mac1_key, peer->public_key, g_label_mac1,
             sizeof(g_label_mac1));
  wg_mac_key(peer->label_cookie_key, peer->public_key, g_label_cookie,
             sizeof(g_label_cookie));
  peer->valid = true;
  return true;
}

/****************************************************************************
 * Name: wg_peer_destroy, wg_peer_clear_sessions
 ****************************************************************************/

void wg_peer_destroy(FAR struct wg_peer_s *peer)
{
  wg_zero(peer, sizeof(*peer));
}

void wg_peer_clear_sessions(FAR struct wg_peer_s *peer)
{
  wg_keypair_destroy(&peer->curr_keypair);
  wg_keypair_destroy(&peer->prev_keypair);
  wg_keypair_destroy(&peer->next_keypair);
  wg_zero(&peer->handshake, sizeof(peer->handshake));
  peer->handshake_mac1_valid = false;
  peer->send_handshake = false;
  peer->active = false;
}

/****************************************************************************
 * Name: wg_peer_alloc, wg_peer_index, wg_peer_by_*
 ****************************************************************************/

FAR struct wg_peer_s *wg_peer_alloc(FAR struct wg_device_s *dev)
{
  int x;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      if (!dev->peers[x].valid)
        {
          return &dev->peers[x];
        }
    }

  return NULL;
}

int wg_peer_index(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer)
{
  int x;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      if (peer == &dev->peers[x])
        {
          return x;
        }
    }

  return -1;
}

FAR struct wg_peer_s *wg_peer_by_pubkey(FAR struct wg_device_s *dev,
                                        FAR const uint8_t *public_key)
{
  int x;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &dev->peers[x];

      if (peer->valid && memcmp(peer->public_key, public_key,
                                WG_KEY_LEN) == 0)
        {
          return peer;
        }
    }

  return NULL;
}

FAR struct wg_peer_s *wg_peer_by_receiver(FAR struct wg_device_s *dev,
                                          uint32_t receiver)
{
  int x;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &dev->peers[x];

      if (peer->valid &&
          ((peer->curr_keypair.valid &&
            peer->curr_keypair.local_index == receiver) ||
           (peer->next_keypair.valid &&
            peer->next_keypair.local_index == receiver) ||
           (peer->prev_keypair.valid &&
            peer->prev_keypair.local_index == receiver)))
        {
          return peer;
        }
    }

  return NULL;
}

FAR struct wg_peer_s *wg_peer_by_handshake(FAR struct wg_device_s *dev,
                                           uint32_t receiver)
{
  int x;

  for (x = 0; x < WG_MAX_PEERS; x++)
    {
      FAR struct wg_peer_s *peer = &dev->peers[x];

      if (peer->valid && peer->handshake.valid &&
          peer->handshake.initiator &&
          peer->handshake.local_index == receiver)
        {
          return peer;
        }
    }

  return NULL;
}

/****************************************************************************
 * Name: wg_start_session
 *
 * Description:
 *   5.4.5 Transport Data Key Derivation: turn a completed handshake into
 *   a key pair and wipe the handshake state.
 *
 ****************************************************************************/

void wg_start_session(FAR struct wg_peer_s *peer, bool initiator)
{
  FAR struct wg_handshake_s *hs = &peer->handshake;
  struct wg_keypair_s kp;

  wg_zero(&kp, sizeof(kp));
  kp.initiator = initiator;
  kp.local_index = hs->local_index;
  kp.remote_index = hs->remote_index;
  kp.keypair_millis = wg_now();
  kp.sending_valid = true;
  kp.receiving_valid = true;

  /* (Tsend_i = Trecv_r, Trecv_i = Tsend_r) := Kdf2(C, empty) */

  if (initiator)
    {
      wg_kdf2(kp.sending_key, kp.receiving_key, hs->chaining_key, NULL, 0);
    }
  else
    {
      wg_kdf2(kp.receiving_key, kp.sending_key, hs->chaining_key, NULL, 0);
    }

  kp.valid = true;

  wg_zero(hs, sizeof(*hs));
  wg_add_keypair(peer, &kp);
  wg_zero(&kp, sizeof(kp));
}

/****************************************************************************
 * Name: wg_keypair_update, wg_keypair_destroy, wg_keypair_by_index
 ****************************************************************************/

void wg_keypair_update(FAR struct wg_peer_s *peer,
                       FAR struct wg_keypair_s *received)
{
  if (received == &peer->next_keypair)
    {
      peer->prev_keypair = peer->curr_keypair;
      peer->curr_keypair = peer->next_keypair;
      wg_keypair_destroy(&peer->next_keypair);
    }
}

void wg_keypair_destroy(FAR struct wg_keypair_s *keypair)
{
  wg_zero(keypair, sizeof(*keypair));
}

FAR struct wg_keypair_s *wg_keypair_by_index(FAR struct wg_peer_s *peer,
                                             uint32_t idx)
{
  if (peer->curr_keypair.valid && peer->curr_keypair.local_index == idx)
    {
      return &peer->curr_keypair;
    }
  else if (peer->next_keypair.valid &&
           peer->next_keypair.local_index == idx)
    {
      return &peer->next_keypair;
    }
  else if (peer->prev_keypair.valid &&
           peer->prev_keypair.local_index == idx)
    {
      return &peer->prev_keypair;
    }

  return NULL;
}

/****************************************************************************
 * Name: wg_check_replay
 *
 * Description:
 *   RFC 2401 appendix C sliding window over the received counters of a
 *   key pair, WG_REPLAY_WORDS * 64 packets wide. Returns true if the
 *   counter is new (and records it), false if it was seen already or is
 *   too old. Call only after the packet has been authenticated.
 *
 ****************************************************************************/

bool wg_check_replay(FAR struct wg_keypair_s *keypair, uint64_t counter)
{
  const uint64_t window = (uint64_t)WG_REPLAY_WORDS * 64;
  uint64_t seq = counter + 1;   /* Counters start at 0; window at 1 */
  uint64_t diff;

  if (seq == 0)
    {
      return false;
    }

  if (seq > keypair->replay_counter)
    {
      diff = seq - keypair->replay_counter;
      if (diff < window)
        {
          size_t words = (size_t)(diff / 64);
          unsigned bits = (unsigned)(diff % 64);
          int i;

          for (i = WG_REPLAY_WORDS - 1; i >= 0; i--)
            {
              uint64_t v = 0;

              if ((size_t)i >= words)
                {
                  v = keypair->replay_bitmap[i - words] << bits;
                  if (bits != 0 && (size_t)i > words)
                    {
                      v |= keypair->replay_bitmap[i - words - 1] >>
                           (64 - bits);
                    }
                }

              keypair->replay_bitmap[i] = v;
            }

          keypair->replay_bitmap[0] |= 1;
        }
      else
        {
          memset(keypair->replay_bitmap, 0, sizeof(keypair->replay_bitmap));
          keypair->replay_bitmap[0] = 1;
        }

      keypair->replay_counter = seq;
      return true;
    }

  diff = keypair->replay_counter - seq;
  if (diff < window)
    {
      uint64_t bit = (uint64_t)1 << (diff % 64);
      size_t word = (size_t)(diff / 64);

      if ((keypair->replay_bitmap[word] & bit) == 0)
        {
          keypair->replay_bitmap[word] |= bit;
          return true;
        }
    }

  return false;
}

/****************************************************************************
 * Name: wg_expired
 ****************************************************************************/

bool wg_expired(uint32_t created_millis, uint32_t valid_seconds)
{
  uint32_t diff = wg_now() - created_millis;

  return diff >= valid_seconds * 1000;
}

/****************************************************************************
 * Name: wg_message_type
 *
 * Description:
 *   Classify a received datagram by its type byte and length. Anything
 *   that is not exactly one of the four message shapes is invalid.
 *
 ****************************************************************************/

uint8_t wg_message_type(FAR const uint8_t *data, size_t len)
{
  if (len < 4 || data[1] != 0 || data[2] != 0 || data[3] != 0)
    {
      return WG_MSG_INVALID;
    }

  switch (data[0])
    {
      case WG_MSG_HANDSHAKE_INIT:
        return len == sizeof(struct wg_msg_init_s) ?
               WG_MSG_HANDSHAKE_INIT : WG_MSG_INVALID;

      case WG_MSG_HANDSHAKE_RESPONSE:
        return len == sizeof(struct wg_msg_response_s) ?
               WG_MSG_HANDSHAKE_RESPONSE : WG_MSG_INVALID;

      case WG_MSG_COOKIE_REPLY:
        return len == sizeof(struct wg_msg_cookie_s) ?
               WG_MSG_COOKIE_REPLY : WG_MSG_INVALID;

      case WG_MSG_TRANSPORT_DATA:
        return len >= sizeof(struct wg_msg_data_s) + WG_AUTHTAG_LEN ?
               WG_MSG_TRANSPORT_DATA : WG_MSG_INVALID;

      default:
        return WG_MSG_INVALID;
    }
}

/****************************************************************************
 * Name: wg_check_mac1, wg_check_mac2
 ****************************************************************************/

bool wg_check_mac1(FAR struct wg_device_s *dev, FAR const uint8_t *data,
                   size_t len, FAR const uint8_t *mac1)
{
  uint8_t calculated[WG_MAC_LEN];

  wg_mac(calculated, data, len, dev->label_mac1_key, WG_SESSION_KEY_LEN);
  return wg_equal(calculated, mac1, WG_MAC_LEN);
}

bool wg_check_mac2(FAR struct wg_device_s *dev, FAR const uint8_t *data,
                   size_t len, FAR const uint8_t *source, size_t sourcelen,
                   FAR const uint8_t *mac2)
{
  uint8_t cookie[WG_COOKIE_LEN];
  uint8_t calculated[WG_MAC_LEN];

  wg_peer_cookie(dev, cookie, source, sourcelen);
  wg_mac(calculated, data, len, cookie, WG_COOKIE_LEN);
  return wg_equal(calculated, mac2, WG_MAC_LEN);
}

/****************************************************************************
 * Name: wg_process_init
 *
 * Description:
 *   5.4.2, responder side. Decrypt the initiator's static key and
 *   timestamp; on success the peer's handshake state is primed for
 *   wg_create_response() and the peer is returned. mac1 (and mac2 under
 *   load) must have been checked by the caller.
 *
 ****************************************************************************/

FAR struct wg_peer_s *wg_process_init(FAR struct wg_device_s *dev,
                                      FAR struct wg_msg_init_s *msg)
{
  FAR struct wg_peer_s *result = NULL;
  FAR struct wg_peer_s *peer;
  uint8_t key[WG_SESSION_KEY_LEN];
  uint8_t chaining_key[WG_HASH_LEN];
  uint8_t hash[WG_HASH_LEN];
  uint8_t s[WG_KEY_LEN];
  uint8_t t[WG_TAI64N_LEN];
  uint8_t dh[WG_KEY_LEN];
  uint32_t now;

  /* Ci := Hash(Construction); Hi := Hash(Ci || Identifier) */

  memcpy(chaining_key, g_construction_hash, WG_HASH_LEN);
  memcpy(hash, g_identifier_hash, WG_HASH_LEN);

  /* Hi := Hash(Hi || Spub_r) */

  wg_mix_hash(hash, dev->public_key, WG_KEY_LEN);

  /* Ci := Kdf1(Ci, Epub_i); Hi := Hash(Hi || msg.ephemeral) */

  wg_kdf1(chaining_key, chaining_key, msg->ephemeral, WG_KEY_LEN);
  wg_mix_hash(hash, msg->ephemeral, WG_KEY_LEN);

  /* (Ci, k) := Kdf2(Ci, DH(Spriv_r, Epub_i)) */

  if (!wg_x25519(dh, dev->private_key, msg->ephemeral))
    {
      goto out;
    }

  wg_kdf2(chaining_key, key, chaining_key, dh, WG_KEY_LEN);

  /* msg.static := AEAD(k, 0, Spub_i, Hi) */

  if (!wg_aead_decrypt(s, msg->enc_static, sizeof(msg->enc_static), hash,
                       WG_HASH_LEN, 0, key))
    {
      goto out;
    }

  wg_mix_hash(hash, msg->enc_static, sizeof(msg->enc_static));

  peer = wg_peer_by_pubkey(dev, s);
  if (peer == NULL)
    {
      goto out;
    }

  /* (Ci, k) := Kdf2(Ci, DH(Spriv_r, Spub_i)) - precomputed per peer */

  wg_kdf2(chaining_key, key, chaining_key, peer->public_key_dh, WG_KEY_LEN);

  /* msg.timestamp := AEAD(k, 0, Timestamp(), Hi) */

  if (!wg_aead_decrypt(t, msg->enc_timestamp, sizeof(msg->enc_timestamp),
                       hash, WG_HASH_LEN, 0, key))
    {
      goto out;
    }

  wg_mix_hash(hash, msg->enc_timestamp, sizeof(msg->enc_timestamp));

  /* 5.1: the timestamp must exceed the greatest one seen from this peer,
   * and no more than WG_MAX_INITIATIONS_PER_SECOND valid initiations are
   * accepted per second from it. TAI64N is big-endian, so memcmp orders
   * it correctly.
   */

  now = wg_now();
  if (memcmp(t, peer->greatest_timestamp, WG_TAI64N_LEN) <= 0)
    {
      goto out;
    }

  if (peer->last_initiation_rx != 0 &&
      now - peer->last_initiation_rx <
        1000 / WG_MAX_INITIATIONS_PER_SECOND)
    {
      goto out;
    }

  peer->last_initiation_rx = now;
  memcpy(peer->greatest_timestamp, t, WG_TAI64N_LEN);

  memcpy(peer->handshake.remote_ephemeral, msg->ephemeral, WG_KEY_LEN);
  memcpy(peer->handshake.hash, hash, WG_HASH_LEN);
  memcpy(peer->handshake.chaining_key, chaining_key, WG_HASH_LEN);
  peer->handshake.remote_index = msg->sender;
  peer->handshake.valid = true;
  peer->handshake.initiator = false;
  result = peer;

out:
  wg_zero(key, sizeof(key));
  wg_zero(hash, sizeof(hash));
  wg_zero(chaining_key, sizeof(chaining_key));
  wg_zero(dh, sizeof(dh));
  wg_zero(s, sizeof(s));
  return result;
}

/****************************************************************************
 * Name: wg_process_response
 *
 * Description:
 *   5.4.3, initiator side. Finish the handshake we started with
 *   wg_create_init(). On success the caller calls wg_start_session().
 *
 ****************************************************************************/

bool wg_process_response(FAR struct wg_device_s *dev,
                         FAR struct wg_peer_s *peer,
                         FAR struct wg_msg_response_s *msg)
{
  FAR struct wg_handshake_s *hs = &peer->handshake;
  uint8_t key[WG_SESSION_KEY_LEN];
  uint8_t hash[WG_HASH_LEN];
  uint8_t chaining_key[WG_HASH_LEN];
  uint8_t dh[WG_KEY_LEN];
  uint8_t tau[WG_HASH_LEN];
  bool result = false;

  if (!hs->valid || !hs->initiator)
    {
      return false;
    }

  memcpy(hash, hs->hash, WG_HASH_LEN);
  memcpy(chaining_key, hs->chaining_key, WG_HASH_LEN);

  /* Cr := Kdf1(Cr, Epub_r); Hr := Hash(Hr || msg.ephemeral) */

  wg_kdf1(chaining_key, chaining_key, msg->ephemeral, WG_KEY_LEN);
  wg_mix_hash(hash, msg->ephemeral, WG_KEY_LEN);

  /* Cr := Kdf1(Cr, DH(Epriv_i, Epub_r)) */

  if (!wg_x25519(dh, hs->ephemeral_private, msg->ephemeral))
    {
      goto out;
    }

  wg_kdf1(chaining_key, chaining_key, dh, WG_KEY_LEN);

  /* Cr := Kdf1(Cr, DH(Spriv_i, Epub_r)) */

  if (!wg_x25519(dh, dev->private_key, msg->ephemeral))
    {
      goto out;
    }

  wg_kdf1(chaining_key, chaining_key, dh, WG_KEY_LEN);

  /* (Cr, tau, k) := Kdf3(Cr, Q); Hr := Hash(Hr || tau) */

  wg_kdf3(chaining_key, tau, key, chaining_key, peer->preshared_key,
          WG_SESSION_KEY_LEN);
  wg_mix_hash(hash, tau, WG_HASH_LEN);

  /* msg.empty := AEAD(k, 0, empty, Hr) */

  if (!wg_aead_decrypt(NULL, msg->enc_empty, sizeof(msg->enc_empty), hash,
                       WG_HASH_LEN, 0, key))
    {
      goto out;
    }

  memcpy(hs->remote_ephemeral, msg->ephemeral, WG_KEY_LEN);
  memcpy(hs->hash, hash, WG_HASH_LEN);
  memcpy(hs->chaining_key, chaining_key, WG_HASH_LEN);
  hs->remote_index = msg->sender;
  result = true;

out:
  wg_zero(key, sizeof(key));
  wg_zero(hash, sizeof(hash));
  wg_zero(chaining_key, sizeof(chaining_key));
  wg_zero(dh, sizeof(dh));
  wg_zero(tau, sizeof(tau));
  return result;
}

/****************************************************************************
 * Name: wg_process_cookie
 *
 * Description:
 *   5.4.7, initiator side: the peer is under load and sent a cookie for
 *   us to put in mac2 of the next initiation. The cookie is encrypted
 *   under the mac1 of our last initiation, which we kept for this.
 *
 ****************************************************************************/

bool wg_process_cookie(FAR struct wg_device_s *dev,
                       FAR struct wg_peer_s *peer,
                       FAR struct wg_msg_cookie_s *msg)
{
  uint8_t cookie[WG_COOKIE_LEN];

  if (!peer->handshake_mac1_valid)
    {
      return false;
    }

  if (!wg_xaead_decrypt(cookie, msg->enc_cookie, sizeof(msg->enc_cookie),
                        peer->handshake_mac1, WG_MAC_LEN, msg->nonce,
                        peer->label_cookie_key))
    {
      return false;
    }

  memcpy(peer->cookie, cookie, WG_COOKIE_LEN);
  peer->cookie_millis = wg_now();
  peer->handshake_mac1_valid = false;
  wg_zero(cookie, sizeof(cookie));
  return true;
}

/****************************************************************************
 * Name: wg_create_init
 *
 * Description:
 *   5.4.2, initiator side. Build a handshake initiation for the peer and
 *   prime the handshake state for wg_process_response(). The caller
 *   records msg->mac1 as peer->handshake_mac1 when it sends the message.
 *
 ****************************************************************************/

bool wg_create_init(FAR struct wg_device_s *dev, FAR struct wg_peer_s *peer,
                    FAR struct wg_msg_init_s *msg)
{
  FAR struct wg_handshake_s *hs = &peer->handshake;
  uint8_t timestamp[WG_TAI64N_LEN];
  uint8_t key[WG_SESSION_KEY_LEN];
  uint8_t dh[WG_KEY_LEN];
  bool result = false;

  memset(msg, 0, sizeof(*msg));

  if (!wg_tai64n(timestamp))
    {
      goto out;
    }

  /* Ci := Hash(Construction); Hi := Hash(Ci || Identifier);
   * Hi := Hash(Hi || Spub_r)
   */

  memcpy(hs->chaining_key, g_construction_hash, WG_HASH_LEN);
  memcpy(hs->hash, g_identifier_hash, WG_HASH_LEN);
  wg_mix_hash(hs->hash, peer->public_key, WG_KEY_LEN);

  /* (Epriv_i, Epub_i) := DH-Generate() */

  if (!wg_generate_private_key(hs->ephemeral_private) ||
      !wg_generate_public_key(msg->ephemeral, hs->ephemeral_private))
    {
      goto out;
    }

  /* Ci := Kdf1(Ci, Epub_i); Hi := Hash(Hi || msg.ephemeral) */

  wg_kdf1(hs->chaining_key, hs->chaining_key, msg->ephemeral, WG_KEY_LEN);
  wg_mix_hash(hs->hash, msg->ephemeral, WG_KEY_LEN);

  /* (Ci, k) := Kdf2(Ci, DH(Epriv_i, Spub_r)) */

  if (!wg_x25519(dh, hs->ephemeral_private, peer->public_key))
    {
      goto out;
    }

  wg_kdf2(hs->chaining_key, key, hs->chaining_key, dh, WG_KEY_LEN);

  /* msg.static := AEAD(k, 0, Spub_i, Hi); Hi := Hash(Hi || msg.static) */

  wg_aead_encrypt(msg->enc_static, dev->public_key, WG_KEY_LEN, hs->hash,
                  WG_HASH_LEN, 0, key);
  wg_mix_hash(hs->hash, msg->enc_static, sizeof(msg->enc_static));

  /* (Ci, k) := Kdf2(Ci, DH(Spriv_i, Spub_r)) */

  wg_kdf2(hs->chaining_key, key, hs->chaining_key, peer->public_key_dh,
          WG_KEY_LEN);

  /* msg.timestamp := AEAD(k, 0, Timestamp(), Hi);
   * Hi := Hash(Hi || msg.timestamp)
   */

  wg_aead_encrypt(msg->enc_timestamp, timestamp, WG_TAI64N_LEN, hs->hash,
                  WG_HASH_LEN, 0, key);
  wg_mix_hash(hs->hash, msg->enc_timestamp, sizeof(msg->enc_timestamp));

  msg->type = WG_MSG_HANDSHAKE_INIT;
  msg->sender = wg_unique_index(dev);
  hs->valid = true;
  hs->initiator = true;
  hs->local_index = msg->sender;

  wg_sign_message(peer, (FAR uint8_t *)msg, sizeof(*msg));
  result = true;

out:
  wg_zero(key, sizeof(key));
  wg_zero(dh, sizeof(dh));
  wg_zero(timestamp, sizeof(timestamp));
  return result;
}

/****************************************************************************
 * Name: wg_create_response
 *
 * Description:
 *   5.4.3, responder side, after wg_process_init(). The caller calls
 *   wg_start_session(peer, false) once the message is built.
 *
 ****************************************************************************/

bool wg_create_response(FAR struct wg_device_s *dev,
                        FAR struct wg_peer_s *peer,
                        FAR struct wg_msg_response_s *msg)
{
  FAR struct wg_handshake_s *hs = &peer->handshake;
  uint8_t key[WG_SESSION_KEY_LEN];
  uint8_t dh[WG_KEY_LEN];
  uint8_t tau[WG_HASH_LEN];
  bool result = false;

  memset(msg, 0, sizeof(*msg));

  if (!hs->valid || hs->initiator)
    {
      return false;
    }

  /* (Epriv_r, Epub_r) := DH-Generate() */

  if (!wg_generate_private_key(hs->ephemeral_private) ||
      !wg_generate_public_key(msg->ephemeral, hs->ephemeral_private))
    {
      goto out;
    }

  /* Cr := Kdf1(Cr, Epub_r); Hr := Hash(Hr || msg.ephemeral) */

  wg_kdf1(hs->chaining_key, hs->chaining_key, msg->ephemeral, WG_KEY_LEN);
  wg_mix_hash(hs->hash, msg->ephemeral, WG_KEY_LEN);

  /* Cr := Kdf1(Cr, DH(Epriv_r, Epub_i)) */

  if (!wg_x25519(dh, hs->ephemeral_private, hs->remote_ephemeral))
    {
      goto out;
    }

  wg_kdf1(hs->chaining_key, hs->chaining_key, dh, WG_KEY_LEN);

  /* Cr := Kdf1(Cr, DH(Epriv_r, Spub_i)) */

  if (!wg_x25519(dh, hs->ephemeral_private, peer->public_key))
    {
      goto out;
    }

  wg_kdf1(hs->chaining_key, hs->chaining_key, dh, WG_KEY_LEN);

  /* (Cr, tau, k) := Kdf3(Cr, Q); Hr := Hash(Hr || tau) */

  wg_kdf3(hs->chaining_key, tau, key, hs->chaining_key,
          peer->preshared_key, WG_SESSION_KEY_LEN);
  wg_mix_hash(hs->hash, tau, WG_HASH_LEN);

  /* msg.empty := AEAD(k, 0, empty, Hr); Hr := Hash(Hr || msg.empty) */

  wg_aead_encrypt(msg->enc_empty, NULL, 0, hs->hash, WG_HASH_LEN, 0, key);
  wg_mix_hash(hs->hash, msg->enc_empty, sizeof(msg->enc_empty));

  msg->type = WG_MSG_HANDSHAKE_RESPONSE;
  msg->receiver = hs->remote_index;
  msg->sender = wg_unique_index(dev);
  hs->local_index = msg->sender;

  wg_sign_message(peer, (FAR uint8_t *)msg, sizeof(*msg));
  result = true;

out:
  wg_zero(key, sizeof(key));
  wg_zero(dh, sizeof(dh));
  wg_zero(tau, sizeof(tau));
  return result;
}

/****************************************************************************
 * Name: wg_create_cookie
 *
 * Description:
 *   5.4.7, responder side: answer an initiation that arrived under load
 *   without a valid mac2. The cookie is bound to the sender's address and
 *   port and encrypted under the initiation's mac1.
 *
 ****************************************************************************/

bool wg_create_cookie(FAR struct wg_device_s *dev,
                      FAR struct wg_msg_cookie_s *msg,
                      FAR const uint8_t *mac1, uint32_t index,
                      FAR const uint8_t *source, size_t sourcelen)
{
  uint8_t cookie[WG_COOKIE_LEN];

  wg_zero(msg, sizeof(*msg));
  msg->type = WG_MSG_COOKIE_REPLY;
  msg->receiver = index;

  if (!wg_random(msg->nonce, sizeof(msg->nonce)))
    {
      return false;
    }

  wg_peer_cookie(dev, cookie, source, sourcelen);
  wg_xaead_encrypt(msg->enc_cookie, cookie, WG_COOKIE_LEN, mac1,
                   WG_MAC_LEN, msg->nonce, dev->label_cookie_key);
  wg_zero(cookie, sizeof(cookie));
  return true;
}

/****************************************************************************
 * Name: wg_encrypt_packet, wg_decrypt_packet
 *
 * Description:
 *   5.4.6 transport data: AEAD with the sending counter as nonce and no
 *   associated data. dst needs srclen + WG_AUTHTAG_LEN bytes.
 *
 ****************************************************************************/

void wg_encrypt_packet(FAR uint8_t *dst, FAR const uint8_t *src,
                       size_t srclen, FAR struct wg_keypair_s *keypair)
{
  wg_aead_encrypt(dst, src, srclen, NULL, 0, keypair->sending_counter,
                  keypair->sending_key);
  keypair->sending_counter++;
}

bool wg_decrypt_packet(FAR uint8_t *dst, FAR const uint8_t *src,
                       size_t srclen, uint64_t counter,
                       FAR struct wg_keypair_s *keypair)
{
  return wg_aead_decrypt(dst, src, srclen, NULL, 0, counter,
                         keypair->receiving_key);
}
