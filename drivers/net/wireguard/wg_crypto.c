/****************************************************************************
 * drivers/net/wireguard/wg_crypto.c
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
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include <nuttx/clock.h>
#include <nuttx/random.h>
#include <nuttx/fs/fs.h>
#include <nuttx/crypto/blake2s.h>
#include <crypto/chachapoly.h>
#include <crypto/curve25519.h>

#include "wg_crypto.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_BLAKE2S_BLOCK    64

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: wg_x25519, wg_x25519_public, wg_x25519_clamp
 *
 * Description:
 *   Curve25519 scalar multiplication on top of crypto/curve25519.c, whose
 *   functions follow the Linux convention of returning non-zero on
 *   success and zero when the result is the all-zero point. That is the
 *   opposite of the reference implementation this port derives from, so
 *   the boolean is normalised here and callers never see the raw value.
 *
 ****************************************************************************/

bool wg_x25519(FAR uint8_t out[WG_KEY_LEN],
               FAR const uint8_t scalar[WG_KEY_LEN],
               FAR const uint8_t point[WG_KEY_LEN])
{
  return curve25519(out, scalar, point) != 0;
}

bool wg_x25519_public(FAR uint8_t pub[WG_KEY_LEN],
                      FAR const uint8_t priv[WG_KEY_LEN])
{
  return curve25519_generate_public(pub, priv) != 0;
}

void wg_x25519_clamp(FAR uint8_t priv[WG_KEY_LEN])
{
  curve25519_clamp_secret(priv);
}

/****************************************************************************
 * Name: wg_hash, wg_mix_hash, wg_mac
 ****************************************************************************/

void wg_hash(FAR uint8_t out[WG_HASH_LEN], FAR const void *in,
             size_t inlen)
{
  blake2s(out, WG_HASH_LEN, in, inlen, NULL, 0);
}

void wg_mix_hash(FAR uint8_t hash[WG_HASH_LEN], FAR const void *in,
                 size_t inlen)
{
  blake2s_state s;

  blake2s_init(&s, WG_HASH_LEN);
  blake2s_update(&s, hash, WG_HASH_LEN);
  blake2s_update(&s, in, inlen);
  blake2s_final(&s, hash, WG_HASH_LEN);
  wg_zero(&s, sizeof(s));
}

void wg_mac(FAR uint8_t out[WG_MAC_LEN], FAR const void *in, size_t inlen,
            FAR const uint8_t *key, size_t keylen)
{
  blake2s(out, WG_MAC_LEN, in, inlen, key, keylen);
}

/****************************************************************************
 * Name: wg_hmac
 *
 * Description:
 *   HMAC-BLAKE2s per RFC 2104 with the 64-byte BLAKE2s block size. The
 *   handshake uses this as the extract/expand function of HKDF.
 *
 ****************************************************************************/

void wg_hmac(FAR uint8_t out[WG_HASH_LEN], FAR const uint8_t *key,
             size_t keylen, FAR const void *in, size_t inlen)
{
  uint8_t k_ipad[WG_BLAKE2S_BLOCK];
  uint8_t k_opad[WG_BLAKE2S_BLOCK];
  uint8_t tk[WG_HASH_LEN];
  blake2s_state s;
  int i;

  if (keylen > WG_BLAKE2S_BLOCK)
    {
      wg_hash(tk, key, keylen);
      key = tk;
      keylen = WG_HASH_LEN;
    }

  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, keylen);
  memcpy(k_opad, key, keylen);

  for (i = 0; i < WG_BLAKE2S_BLOCK; i++)
    {
      k_ipad[i] ^= 0x36;
      k_opad[i] ^= 0x5c;
    }

  blake2s_init(&s, WG_HASH_LEN);
  blake2s_update(&s, k_ipad, sizeof(k_ipad));
  blake2s_update(&s, in, inlen);
  blake2s_final(&s, out, WG_HASH_LEN);

  blake2s_init(&s, WG_HASH_LEN);
  blake2s_update(&s, k_opad, sizeof(k_opad));
  blake2s_update(&s, out, WG_HASH_LEN);
  blake2s_final(&s, out, WG_HASH_LEN);

  wg_zero(&s, sizeof(s));
  wg_zero(k_ipad, sizeof(k_ipad));
  wg_zero(k_opad, sizeof(k_opad));
  wg_zero(tk, sizeof(tk));
}

/****************************************************************************
 * Name: wg_kdf1, wg_kdf2, wg_kdf3
 *
 * Description:
 *   HKDF (whitepaper 5.4.1): tau0 = HMAC(key, input); tau1 = HMAC(tau0,
 *   0x1); tau2 = HMAC(tau0, tau1 || 0x2); tau3 = HMAC(tau0, tau2 || 0x3).
 *
 ****************************************************************************/

void wg_kdf1(FAR uint8_t t1[WG_HASH_LEN], FAR const uint8_t *chaining_key,
             FAR const void *data, size_t datalen)
{
  uint8_t tau0[WG_HASH_LEN];
  uint8_t output[WG_HASH_LEN + 1];

  wg_hmac(tau0, chaining_key, WG_HASH_LEN, data, datalen);
  output[0] = 1;
  wg_hmac(output, tau0, WG_HASH_LEN, output, 1);
  memcpy(t1, output, WG_HASH_LEN);

  wg_zero(tau0, sizeof(tau0));
  wg_zero(output, sizeof(output));
}

void wg_kdf2(FAR uint8_t t1[WG_HASH_LEN], FAR uint8_t t2[WG_HASH_LEN],
             FAR const uint8_t *chaining_key, FAR const void *data,
             size_t datalen)
{
  uint8_t tau0[WG_HASH_LEN];
  uint8_t output[WG_HASH_LEN + 1];

  wg_hmac(tau0, chaining_key, WG_HASH_LEN, data, datalen);
  output[0] = 1;
  wg_hmac(output, tau0, WG_HASH_LEN, output, 1);
  memcpy(t1, output, WG_HASH_LEN);

  output[WG_HASH_LEN] = 2;
  wg_hmac(output, tau0, WG_HASH_LEN, output, WG_HASH_LEN + 1);
  memcpy(t2, output, WG_HASH_LEN);

  wg_zero(tau0, sizeof(tau0));
  wg_zero(output, sizeof(output));
}

void wg_kdf3(FAR uint8_t t1[WG_HASH_LEN], FAR uint8_t t2[WG_HASH_LEN],
             FAR uint8_t t3[WG_HASH_LEN], FAR const uint8_t *chaining_key,
             FAR const void *data, size_t datalen)
{
  uint8_t tau0[WG_HASH_LEN];
  uint8_t output[WG_HASH_LEN + 1];

  wg_hmac(tau0, chaining_key, WG_HASH_LEN, data, datalen);
  output[0] = 1;
  wg_hmac(output, tau0, WG_HASH_LEN, output, 1);
  memcpy(t1, output, WG_HASH_LEN);

  output[WG_HASH_LEN] = 2;
  wg_hmac(output, tau0, WG_HASH_LEN, output, WG_HASH_LEN + 1);
  memcpy(t2, output, WG_HASH_LEN);

  output[WG_HASH_LEN] = 3;
  wg_hmac(output, tau0, WG_HASH_LEN, output, WG_HASH_LEN + 1);
  memcpy(t3, output, WG_HASH_LEN);

  wg_zero(tau0, sizeof(tau0));
  wg_zero(output, sizeof(output));
}

/****************************************************************************
 * Name: wg_aead_encrypt, wg_aead_decrypt, wg_xaead_encrypt, wg_xaead_decrypt
 *
 * Description:
 *   crypto/chachapoly.c implements exactly the AEAD constructions
 *   WireGuard uses (RFC 8439 with a 64-bit counter nonce, and the
 *   XChaCha20 variant with a 192-bit nonce). Its decrypt functions return
 *   non-zero on success after a constant-time tag comparison.
 *
 ****************************************************************************/

void wg_aead_encrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                     size_t srclen, FAR const uint8_t *ad, size_t adlen,
                     uint64_t nonce, FAR const uint8_t *key)
{
  chacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key);
}

bool wg_aead_decrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                     size_t srclen, FAR const uint8_t *ad, size_t adlen,
                     uint64_t nonce, FAR const uint8_t *key)
{
  return chacha20poly1305_decrypt(dst, src, srclen, ad, adlen, nonce,
                                  key) != 0;
}

void wg_xaead_encrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                      size_t srclen, FAR const uint8_t *ad, size_t adlen,
                      FAR const uint8_t nonce[WG_COOKIE_NONCE_LEN],
                      FAR const uint8_t *key)
{
  xchacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key);
}

bool wg_xaead_decrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                      size_t srclen, FAR const uint8_t *ad, size_t adlen,
                      FAR const uint8_t nonce[WG_COOKIE_NONCE_LEN],
                      FAR const uint8_t *key)
{
  return xchacha20poly1305_decrypt(dst, src, srclen, ad, adlen, nonce,
                                   key) != 0;
}

/****************************************************************************
 * Name: wg_random
 *
 * Description:
 *   Fill a buffer from the kernel's random source: the entropy pool when
 *   CONFIG_CRYPTO_RANDOM_POOL is selected, otherwise the hardware RNG
 *   behind /dev/urandom (CONFIG_DEV_URANDOM_ARCH). Kconfig does not allow
 *   NET_WIREGUARD with the constant-seeded software PRNGs, so there is no
 *   deterministic fallback here on purpose.
 *
 * Returned Value:
 *   true if the whole buffer was filled, false if the source is not
 *   available. On false the buffer contents are undefined and the caller
 *   must not use them as key material.
 *
 ****************************************************************************/

bool wg_random(FAR void *buf, size_t len)
{
#ifdef CONFIG_CRYPTO_RANDOM_POOL
  up_rngbuf(buf, len);
  return true;
#else
  struct file f;
  FAR uint8_t *p = buf;
  size_t total = 0;
  int ret;

  ret = file_open(&f, "/dev/urandom", O_RDONLY);
  if (ret < 0)
    {
      return false;
    }

  while (total < len)
    {
      ssize_t n = file_read(&f, p + total, len - total);

      if (n <= 0)
        {
          break;
        }

      total += (size_t)n;
    }

  file_close(&f);
  return total == len;
#endif
}

/****************************************************************************
 * Name: wg_now
 *
 * Description:
 *   Milliseconds from the scheduler tick counter, wrapping at 2^32. The
 *   protocol only ever compares differences, so the wrap is harmless, but
 *   several places use zero as "never", so a real reading is never zero.
 *   This deliberately does not go through CLOCK_REALTIME or the RTC: the
 *   timers must keep running on boards whose RTC is not yet (or never)
 *   available.
 *
 ****************************************************************************/

uint32_t wg_now(void)
{
  uint32_t ms = (uint32_t)TICK2MSEC(clock_systime_ticks());

  return ms == 0 ? 1 : ms;
}

/****************************************************************************
 * Name: wg_equal, wg_zero, wg_is_zero
 ****************************************************************************/

bool wg_equal(FAR const void *a, FAR const void *b, size_t len)
{
  return timingsafe_bcmp(a, b, len) == 0;
}

void wg_zero(FAR void *p, size_t len)
{
  explicit_bzero(p, len);
}

bool wg_is_zero(FAR const void *p, size_t len)
{
  FAR const uint8_t *b = p;
  uint8_t acc = 0;
  size_t i;

  for (i = 0; i < len; i++)
    {
      acc |= b[i];
    }

  return acc == 0;
}

/****************************************************************************
 * Name: wg_read_le64, wg_write_le64, wg_read_le32, wg_write_le32
 ****************************************************************************/

uint64_t wg_read_le64(FAR const uint8_t *p)
{
  uint64_t v = 0;
  int i;

  for (i = 7; i >= 0; i--)
    {
      v = (v << 8) | p[i];
    }

  return v;
}

void wg_write_le64(FAR uint8_t *p, uint64_t v)
{
  int i;

  for (i = 0; i < 8; i++)
    {
      p[i] = (uint8_t)(v >> (8 * i));
    }
}

uint32_t wg_read_le32(FAR const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

void wg_write_le32(FAR uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
