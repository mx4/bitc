#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/evp.h>

#include "hash.h"
#include "ripemd160.h"
#include "util.h"


/*
 *-------------------------------------------------------------------------
 *
 * uint256_from_str --
 *
 *-------------------------------------------------------------------------
 */

bool
uint256_from_str(const char *str,
                 uint256    *hash)
{
   int i;

   if (strlen(str) != 2 * DIGEST_SHA256_LEN) {
      return 0;
   }

   for (i = 0; i < DIGEST_SHA256_LEN; i++) {
      char str0[3] = { 0 };
      uint32 v = 0;
      int res;

      memcpy(str0, str + 2 * i, 2);
      res = sscanf(str0, "%02x", &v);
      if (res != 1) {
         return 0;
      }
      hash->data[DIGEST_SHA256_LEN - i - 1] = v;
   }
   return 1;
}


/*
 *---------------------------------------------------
 *
 * uint256_reverse --
 *
 *---------------------------------------------------
 */

static void
uint256_reverse(uint256 *hash)
{
   int i;

   for (i = 0; i < ARRAYSIZE(hash->data) / 2; i++) {
      uint8 v = hash->data[DIGEST_SHA256_LEN - i - 1];
      hash->data[DIGEST_SHA256_LEN - i - 1] = hash->data[i];
      hash->data[i] = v;
   }
}


/*
 *---------------------------------------------------
 *
 * uint160_reverse --
 *
 *---------------------------------------------------
 */

static void
uint160_reverse(uint160 *hash)
{
   int i;

   for (i = 0; i < ARRAYSIZE(hash->data) / 2; i++) {
      uint8 v = hash->data[DIGEST_RIPEMD160_LEN - i - 1];
      hash->data[DIGEST_RIPEMD160_LEN - i - 1] = hash->data[i];
      hash->data[i] = v;
   }
}



/*
 *---------------------------------------------------
 *
 * uint160_snprintf_reverse --
 *
 *---------------------------------------------------
 */

void
uint160_snprintf_reverse(char *str,
                         size_t len,
                         const uint160 *hash)
{
   uint160 h;

   memcpy(&h, hash, sizeof h);
   uint160_reverse(&h);

   str_snprintf_bytes(str, len, NULL, h.data, ARRAYSIZE(h.data));
}



/*
 *---------------------------------------------------
 *
 * uint256_snprintf_reverse --
 *
 *---------------------------------------------------
 */

void
uint256_snprintf_reverse(char *str,
                         size_t len,
                         const uint256 *hash)
{
   uint256 h;

   ASSERT(len >= 2 * sizeof(uint256) + 1);

   memcpy(&h, hash, sizeof h);
   uint256_reverse(&h);

   str_snprintf_bytes(str, len, NULL, h.data, ARRAYSIZE(h.data));
}


/*
 *---------------------------------------------------
 *
 * sha256_calc --
 *
 *---------------------------------------------------
 */

void
sha256_calc(const void *buf,
            size_t      bufLen,
            uint256    *digest)
{
   uint32 digestLen = sizeof *digest;
   EVP_MD_CTX *ctx;

   ctx = EVP_MD_CTX_new();

   EVP_DigestInit(ctx, EVP_sha256());
   EVP_DigestUpdate(ctx, buf, bufLen);
   EVP_DigestFinal(ctx, digest->data, &digestLen);

   EVP_MD_CTX_free(ctx);
}


/*
 *---------------------------------------------------
 *
 * hash160_calc --
 *
 *---------------------------------------------------
 */

void
hash160_calc(const void *buf,
             size_t      bufLen,
             uint160    *digest)
{
   uint256 h;

   sha256_calc(buf, bufLen, &h);
   ripemd160(&h.data[0], sizeof h, digest->data);
}


/*
 *---------------------------------------------------
 *
 * hash256_calc --
 *
 *---------------------------------------------------
 */

void
hash256_calc(const void *buf,
             size_t len,
             uint256 *hash)
{
   uint256 hash0;

   sha256_calc(buf, len, &hash0);
   sha256_calc(&hash0, sizeof hash0, hash);
}


/*
 *---------------------------------------------------
 *
 * hash4_calc --
 *
 *---------------------------------------------------
 */

void
hash4_calc(const void *buf,
           size_t len,
           uint8 hash[4])
{
   uint256 hash0;

   hash256_calc(buf, len, &hash0);
   memcpy(hash, &hash0.data, 4);
}

