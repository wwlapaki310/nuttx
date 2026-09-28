/****************************************************************************
 * crypto/testmngr.c
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

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <nuttx/debug.h>

#include <sys/param.h>

#include <nuttx/fs/fs.h>
#include <nuttx/kmalloc.h>
#include <nuttx/crypto/crypto.h>
#include <crypto/chachapoly.h>

#ifdef CONFIG_CRYPTO_ALGTEST

#include "testmngr.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#if defined(CONFIG_CRYPTO_AES)

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static int do_test_aes(FAR struct cipher_testvec *test,
                       int mode,
                       int encrypt)
{
  FAR void *out = kmm_zalloc(test->rlen);

  int res = aes_cypher(out, test->input, test->ilen, test->iv, test->key,
                       test->klen, mode, encrypt);

  if (res == OK)
    {
      res = memcmp(out, test->result, test->rlen);
    }

  kmm_free(out);
  return res;
}

#define AES_CYPHER_TEST_ENCRYPT(mode, mode_str, count, template) \
  for (i = 0; i < count; i++) { \
    if (do_test_aes(template + i, mode, CYPHER_ENCRYPT)) { \
      crypterr("ERROR: Failed " mode_str " encrypt test #%i\n", i); \
      return -1; \
    } \
  }

#define AES_CYPHER_TEST_DECRYPT(mode, mode_str, count, template) \
  for (i = 0; i < count; i++) { \
    if (do_test_aes(template + i, mode, CYPHER_DECRYPT)) { \
      crypterr("ERROR: Failed " mode_str " decrypt test #%i\n", i); \
      return -1; \
    } \
  }

#define AES_CYPHER_TEST(mode, mode_str, enc_count, dec_count, \
                       enc_template, dec_template) \
  AES_CYPHER_TEST_ENCRYPT(mode, mode_str, enc_count, enc_template)\
  AES_CYPHER_TEST_DECRYPT(mode, mode_str, dec_count, dec_template)

static int test_aes(void)
{
  int i;

  AES_CYPHER_TEST(AES_MODE_ECB, "ECB", nitems(aes_enc_tv_template),
                  nitems(aes_dec_tv_template), aes_enc_tv_template,
                  aes_dec_tv_template)
  AES_CYPHER_TEST(AES_MODE_CBC, "CBC", nitems(aes_cbc_enc_tv_template),
                  nitems(aes_cbc_dec_tv_template),
                  aes_cbc_enc_tv_template, aes_cbc_dec_tv_template)
  AES_CYPHER_TEST(AES_MODE_CTR, "CTR", nitems(aes_ctr_enc_tv_template),
                  nitems(aes_ctr_dec_tv_template),
                  aes_ctr_enc_tv_template, aes_ctr_dec_tv_template)

  return OK;
}
#endif

/* crypto/chachapoly.c is always compiled, so its AEADs are testable. */

static int test_chacha20poly1305(void)
{
  int i;

  for (i = 0; i < nitems(chacha20poly1305_tv_template); i++)
    {
      FAR struct aead_testvec *tv = &chacha20poly1305_tv_template[i];
      FAR uint8_t *out = kmm_zalloc(tv->rlen);
      FAR uint8_t *dec = kmm_zalloc(tv->ilen);
      int ret = OK;

      if (out == NULL || dec == NULL)
        {
          kmm_free(out);
          kmm_free(dec);
          return -1;
        }

      chacha20poly1305_encrypt(out, (FAR const uint8_t *)tv->input, tv->ilen,
                               (FAR const uint8_t *)tv->ad, tv->adlen,
                               tv->counter, (FAR const uint8_t *)tv->key);
      if (memcmp(out, tv->result, tv->rlen) != 0)
        {
          crypterr("ERROR: Failed chacha20poly1305 encrypt #%i\n", i);
          ret = -1;
        }
      else if (chacha20poly1305_decrypt(
                 dec, (FAR const uint8_t *)tv->result, tv->rlen,
                 (FAR const uint8_t *)tv->ad, tv->adlen, tv->counter,
                 (FAR const uint8_t *)tv->key) != 1 ||
               memcmp(dec, tv->input, tv->ilen) != 0)
        {
          crypterr("ERROR: Failed chacha20poly1305 decrypt #%i\n", i);
          ret = -1;
        }
      else
        {
          /* A tampered tag must be rejected. */

          out[tv->rlen - 1] ^= 0x01;
          if (chacha20poly1305_decrypt(dec, out, tv->rlen,
                                       (FAR const uint8_t *)tv->ad,
                                       tv->adlen,
                                       tv->counter,
                                       (FAR const uint8_t *)tv->key) == 1)
            {
              crypterr("ERROR: chacha20poly1305 forged tag accepted #%i\n",
                       i);
              ret = -1;
            }
        }

      kmm_free(out);
      kmm_free(dec);
      if (ret != OK)
        {
          return ret;
        }
    }

  return OK;
}

static int test_xchacha20poly1305(void)
{
  int i;

  for (i = 0; i < nitems(xchacha20poly1305_tv_template); i++)
    {
      FAR struct xaead_testvec *tv = &xchacha20poly1305_tv_template[i];
      FAR uint8_t *out = kmm_zalloc(tv->rlen);
      FAR uint8_t *dec = kmm_zalloc(tv->ilen);
      int ret = OK;

      if (out == NULL || dec == NULL)
        {
          kmm_free(out);
          kmm_free(dec);
          return -1;
        }

      xchacha20poly1305_encrypt(out, (FAR const uint8_t *)tv->input,
                                tv->ilen,
                                (FAR const uint8_t *)tv->ad, tv->adlen,
                                (FAR const uint8_t *)tv->nonce,
                                (FAR const uint8_t *)tv->key);
      if (memcmp(out, tv->result, tv->rlen) != 0)
        {
          crypterr("ERROR: Failed xchacha20poly1305 encrypt #%i\n", i);
          ret = -1;
        }
      else if (xchacha20poly1305_decrypt(
                 dec, (FAR const uint8_t *)tv->result, tv->rlen,
                 (FAR const uint8_t *)tv->ad, tv->adlen,
                 (FAR const uint8_t *)tv->nonce,
                 (FAR const uint8_t *)tv->key) != 1 ||
               memcmp(dec, tv->input, tv->ilen) != 0)
        {
          crypterr("ERROR: Failed xchacha20poly1305 decrypt #%i\n", i);
          ret = -1;
        }
      else
        {
          /* A tampered tag must be rejected. */

          out[tv->rlen - 1] ^= 0x01;
          if (xchacha20poly1305_decrypt(dec, out, tv->rlen,
                                        (FAR const uint8_t *)tv->ad,
                                        tv->adlen,
                                        (FAR const uint8_t *)tv->nonce,
                                        (FAR const uint8_t *)tv->key) == 1)
            {
              crypterr("ERROR: xchacha20poly1305 forged tag accepted #%i\n",
                       i);
              ret = -1;
            }
        }

      kmm_free(out);
      kmm_free(dec);
      if (ret != OK)
        {
          return ret;
        }
    }

  return OK;
}

int crypto_test(void)
{
#if defined(CONFIG_CRYPTO_AES)
  if (test_aes())
    {
      return -1;
    }
#endif

  if (test_chacha20poly1305())
    {
      return -1;
    }

  if (test_xchacha20poly1305())
    {
      return -1;
    }

  return OK;
}

#else /* CONFIG_CRYPTO_ALGTEST */

int crypto_test(void)
{
  return OK;
}

#endif /* CONFIG_CRYPTO_ALGTEST */
