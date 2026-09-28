/****************************************************************************
 * drivers/net/wireguard/wg_crypto.h
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

#ifndef __DRIVERS_NET_WIREGUARD_WG_CRYPTO_H
#define __DRIVERS_NET_WIREGUARD_WG_CRYPTO_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The cryptographic and platform primitives the WireGuard protocol core
 * needs, on top of NuttX's crypto/ and clock/random services. Everything
 * the core knows about the outside world goes through this header, so
 * this is also where a test build substitutes deterministic time and
 * randomness to check the handshake against known-answer vectors.
 */

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define WG_KEY_LEN            32  /* Curve25519 keys, pre-shared keys */
#define WG_HASH_LEN           32  /* BLAKE2s-256 */
#define WG_SESSION_KEY_LEN    32  /* ChaCha20-Poly1305 key */
#define WG_AUTHTAG_LEN        16  /* Poly1305 tag */
#define WG_MAC_LEN            16  /* mac1 / mac2 (BLAKE2s-128) */
#define WG_COOKIE_LEN         16
#define WG_COOKIE_NONCE_LEN   24  /* XChaCha20-Poly1305 nonce */
#define WG_TAI64N_LEN         12

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/* Curve25519. Both return true on success and false when the result is
 * the all-zero point (a low-order or invalid input), in which case the
 * output must not be used.
 */

bool wg_x25519(FAR uint8_t out[WG_KEY_LEN],
               FAR const uint8_t scalar[WG_KEY_LEN],
               FAR const uint8_t point[WG_KEY_LEN]);
bool wg_x25519_public(FAR uint8_t pub[WG_KEY_LEN],
                      FAR const uint8_t priv[WG_KEY_LEN]);
void wg_x25519_clamp(FAR uint8_t priv[WG_KEY_LEN]);

/* BLAKE2s: plain hash, keyed MAC (16-byte output), HMAC and the three
 * HKDF forms the handshake uses (whitepaper 5.4.1).
 */

void wg_hash(FAR uint8_t out[WG_HASH_LEN], FAR const void *in,
             size_t inlen);
void wg_mix_hash(FAR uint8_t hash[WG_HASH_LEN], FAR const void *in,
                 size_t inlen);
void wg_mac(FAR uint8_t out[WG_MAC_LEN], FAR const void *in, size_t inlen,
            FAR const uint8_t *key, size_t keylen);
void wg_hmac(FAR uint8_t out[WG_HASH_LEN], FAR const uint8_t *key,
             size_t keylen, FAR const void *in, size_t inlen);
void wg_kdf1(FAR uint8_t t1[WG_HASH_LEN], FAR const uint8_t *chaining_key,
             FAR const void *data, size_t datalen);
void wg_kdf2(FAR uint8_t t1[WG_HASH_LEN], FAR uint8_t t2[WG_HASH_LEN],
             FAR const uint8_t *chaining_key, FAR const void *data,
             size_t datalen);
void wg_kdf3(FAR uint8_t t1[WG_HASH_LEN], FAR uint8_t t2[WG_HASH_LEN],
             FAR uint8_t t3[WG_HASH_LEN], FAR const uint8_t *chaining_key,
             FAR const void *data, size_t datalen);

/* AEAD: ChaCha20-Poly1305 with a 64-bit counter nonce (transport data and
 * handshake fields) and XChaCha20-Poly1305 with a 24-byte random nonce
 * (cookie replies). dst holds len + WG_AUTHTAG_LEN bytes after encryption;
 * decrypt takes srclen including the tag and returns false on failure.
 */

void wg_aead_encrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                     size_t srclen, FAR const uint8_t *ad, size_t adlen,
                     uint64_t nonce, FAR const uint8_t *key);
bool wg_aead_decrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                     size_t srclen, FAR const uint8_t *ad, size_t adlen,
                     uint64_t nonce, FAR const uint8_t *key);
void wg_xaead_encrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                      size_t srclen, FAR const uint8_t *ad, size_t adlen,
                      FAR const uint8_t nonce[WG_COOKIE_NONCE_LEN],
                      FAR const uint8_t *key);
bool wg_xaead_decrypt(FAR uint8_t *dst, FAR const uint8_t *src,
                      size_t srclen, FAR const uint8_t *ad, size_t adlen,
                      FAR const uint8_t nonce[WG_COOKIE_NONCE_LEN],
                      FAR const uint8_t *key);

/* Platform: random bytes (false if no usable source), a millisecond
 * monotonic clock that never reads zero, and a realtime TAI64N timestamp.
 * wg_tai64n returns false without modifying out if no timestamp can be
 * issued. It guards against rollback only within this boot; the platform
 * must restore a sufficiently advanced realtime clock after reboot.
 */

bool wg_random(FAR void *buf, size_t len);
uint32_t wg_now(void);
bool wg_tai64n(FAR uint8_t out[WG_TAI64N_LEN]);

/* Constant-time helpers */

bool wg_equal(FAR const void *a, FAR const void *b, size_t len);
void wg_zero(FAR void *p, size_t len);
bool wg_is_zero(FAR const void *p, size_t len);

/* Little-endian 64-bit counter <-> bytes, as used on the wire */

uint64_t wg_read_le64(FAR const uint8_t *p);
void wg_write_le64(FAR uint8_t *p, uint64_t v);
uint32_t wg_read_le32(FAR const uint8_t *p);
void wg_write_le32(FAR uint8_t *p, uint32_t v);

#endif /* __DRIVERS_NET_WIREGUARD_WG_CRYPTO_H */
