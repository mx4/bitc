#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/bn.h>
#include <openssl/err.h>

#include "basic_defs.h"
#include "util.h"
#include "base58.h"
#include "hash.h"

#define LGPFX "B58:"

static const char *base58Chars =
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


/*
 *------------------------------------------------------------------------
 *
 * base58_getvch --
 *
 *------------------------------------------------------------------------
 */

static void
base58_getvch(const BIGNUM *v,
              uint8 **buf,
              size_t *len)
{
   uint32 size;
   uint8 *s;

   size = BN_bn2mpi(v, NULL);
   if (size <= 4) {
      *buf = NULL;
      *len = 0;
      return;
   }

   s = safe_malloc(size);
   BN_bn2mpi(v, s);

   *len = size - 4;
   *buf = safe_malloc(*len);
   str_copyreverse(*buf, s + 4, *len);
   free(s);
}


/*
 *------------------------------------------------------------------------
 *
 * base58_decode --
 *
 *------------------------------------------------------------------------
 */

static void
base58_decode(const char *str,
              uint8     **dst,
              size_t     *dstLen)
{
   const char *buf;
   BN_CTX *ctx;
   BIGNUM *bn58;
   BIGNUM *bnc;
   BIGNUM *bn;

   ctx = BN_CTX_new();

   bn58 = BN_new();
   bnc  = BN_new();
   bn   = BN_new();

   BN_set_word(bn58, 58);
   BN_set_word(bn, 0);
   *dst = NULL;
   *dstLen = 0;

   while (isspace(*str)) {
      str++;
   }

   for (buf = str; *buf; buf++) {
      const char *p = strchr(base58Chars, *buf);
      if (p == NULL) {
         while (isspace(*buf)) {
            buf++;
         }
         if (*buf != '\0') {
            NOT_TESTED();
            goto err;
         }
         break;
      }
      BN_set_word(bnc, p - base58Chars);
      if (!BN_mul(bn, bn, bn58, ctx)) {
         NOT_TESTED();
         goto err;
      }
      if (!BN_add(bn, bn, bnc)) {
         NOT_TESTED();
         goto err;
      }
   }

   uint8 *tmp;
   size_t len;
   base58_getvch(bn, &tmp, &len);

   if (len >= 2 && tmp[len - 1] == 0 &&
       ((uint8)tmp[len - 2] >= 0x80)) {
      len--;
   }

   uint32 numLeadingZeros = 0;
   for (buf = str; *buf == base58Chars[0]; buf++) {
      numLeadingZeros++;
   }

   *dstLen = len + numLeadingZeros;
   *dst = safe_calloc(1, *dstLen);

   str_copyreverse(*dst + numLeadingZeros, tmp, len);
   free(tmp);

err:
   BN_free(bn58);
   BN_free(bnc);
   BN_free(bn);
   BN_CTX_free(ctx);
}


/*
 *------------------------------------------------------------------------
 *
 * base58_decode_check --
 *
 *------------------------------------------------------------------------
 */

static bool
base58_decode_check(uint8      *addrtype,
                    const char *buf,
                    uint8     **dataOut,
                    size_t     *lenOut)
{
   uint8 *data;
   size_t len;
   uint8 h[4];

   *dataOut = NULL;
   *lenOut = 0;
   base58_decode(buf, &data, &len);

   if (len < 4) {
      goto error;
   }

   hash4_calc(data, len - 4, h);

   if (memcmp(h, data + len - 4, 4) != 0) {
      log_warn(LGPFX" hash mismatch.\n");
      goto error;
   }
   memset(data + len - 4, 0, 4);
   len -= 4;

   if (addrtype) {
      *addrtype = data[0];
      memmove(data, data + 1, len + 1);
      len--;
   }
   *dataOut = data;
   *lenOut = len;
   return 1;

error:
   free(data);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * base58_setvch --
 *
 *------------------------------------------------------------------------
 */

static void
base58_setvch(BIGNUM *bn,
              const void *buf0,
              size_t len0)
{
   uint32 len = len0 + 4;
   uint8 buffer[len];
   BIGNUM *res;

   ASSERT(BN_is_zero(bn));

   buffer[0] = (len0 >> 24) & 0xff;
   buffer[1] = (len0 >> 16) & 0xff;
   buffer[2] = (len0 >>  8) & 0xff;
   buffer[3] = (len0 >>  0) & 0xff;

   str_copyreverse(buffer + 4, buf0, len0);

   res = BN_mpi2bn(buffer, len, bn);
   if (res == NULL) {
      unsigned long int err = ERR_get_error();
      log_warn(LGPFX" BN_mpi2bn failed: %s (%lu)\n", ERR_error_string(err, NULL), err);
   }
   ASSERT(res);
}


/*
 *------------------------------------------------------------------------
 *
 * base58_encode --
 *
 *------------------------------------------------------------------------
 */

static char *
base58_encode(const void *buf,
              size_t len)
{
   const uint8 *buf0 = (uint8 *)buf;
   char *str = safe_malloc(len * 138 / 100 + 1);
   char *rev = safe_malloc(len + 1);
   char *s = NULL;
   size_t strLen = 0;
   BN_CTX *ctx;
   BIGNUM *bn58;
   BIGNUM *bn0;
   BIGNUM *bn;
   BIGNUM *div0;
   BIGNUM *rem;
   int i;

   ctx = BN_CTX_new();

   div0 = BN_new();
   rem  = BN_new();
   bn58 = BN_new();
   bn0  = BN_new();
   bn   = BN_new();

   BN_set_word(bn58, 58);
   BN_set_word(bn0, 0);

   str_copyreverse(rev, buf0, len);
   rev[len] = 0;
   base58_setvch(bn, rev, len + 1);
   s = NULL;
   ASSERT(!BN_is_zero(bn));

   while (BN_cmp(bn, bn0) > 0) {
      if (!BN_div(div0, rem, bn, bn58, ctx)) {
         goto err;
      }
      BN_copy(bn, div0);

      str[strLen] = base58Chars[BN_get_word(rem)];
      strLen++;
   }
   ASSERT(strLen != 0);

   for (i = 0; i < len; i++) {
      if (buf0[i] != 0) {
         break;
      }
      str[strLen] = base58Chars[0];
      strLen++;
   }

   s = safe_calloc(1, strLen + 1);

   str_copyreverse(s, str, strLen);

err:
   free(str);
   free(rev);
   BN_free(bn58);
   BN_free(bn0);
   BN_free(bn);
   BN_free(div0);
   BN_free(rem);
   BN_CTX_free(ctx);

   return s;
}


/*
 *------------------------------------------------------------------------
 *
 * base58_encode_check --
 *
 *------------------------------------------------------------------------
 */

static char *
base58_encode_check(uint8 addrtype,
                    bool have_addrtype,
                    const void *buf,
                    size_t len)
{
   char *s;
   char *res;
   uint8 h[4];
   int i = 0;

   s = safe_calloc(1, len + 1 + 4);

   if (have_addrtype) {
      s[i] = addrtype;
      i++;
   }

   memcpy(s + i, buf, len);
   i += len;

   hash4_calc(s, i, h);
   memcpy(s + i, h, 4);
   i += 4;

   res = base58_encode(s, i);
   free(s);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * b58_pubkey_from_uint160 --
 *
 *------------------------------------------------------------------------
 */

char *
b58_pubkey_from_uint160(const uint160 *digest)
{
   return base58_encode_check(PUBKEY_ADDRESS, 1, digest, sizeof *digest);
}


/*
 *------------------------------------------------------------------------
 *
 * b58_pubkey_is_valid --
 *
 *------------------------------------------------------------------------
 */

bool
b58_pubkey_is_valid(const char *addr)
{
   uint8 *buf = NULL;
   uint8 type;
   size_t len;

   if (addr == NULL) {
      return 0;
   }

   base58_decode_check(&type, addr, &buf, &len);
   free(buf);

   return len == sizeof(uint160) &&
      (type == PUBKEY_ADDRESS || type == SCRIPT_ADDRESS);
}


/*
 *------------------------------------------------------------------------
 *
 * b58_bytes_to_privkey --
 *
 *------------------------------------------------------------------------
 */

char *
b58_bytes_to_privkey(const uint8 *key,
                     size_t len)
{
   return base58_encode_check(PRIVKEY_ADDRESS, 1, key, len);
}


/*
 *------------------------------------------------------------------------
 *
 * b58_bytes_to_pubkey --
 *
 *------------------------------------------------------------------------
 */

char *
b58_bytes_to_pubkey(const uint8 *key,
                    size_t len)
{
   return base58_encode_check(PUBKEY_ADDRESS, 1, key, len);
}


/*
 *------------------------------------------------------------------------
 *
 * b58_privkey_to_bytes --
 *
 *------------------------------------------------------------------------
 */

bool
b58_privkey_to_bytes(const char *addr,
                     uint8     **key,
                     size_t     *len)
{
   uint8 *buf = NULL;
   uint8 type;

   base58_decode_check(&type, addr, &buf, len);

   log_info(LGPFX" -- type=%d, len=%zu\n", type, *len);

   if (type == PRIVKEY_ADDRESS && (*len == 32 || (*len == 33 && buf[32] == 1))) {
      *key = buf;
      return 1;
   }
   free(buf);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * b58_pubkey_to_uint160 --
 *
 *      Decodes a bitcoin address and retrieve the encode pubkey hash.
 *
 *------------------------------------------------------------------------
 */

void
b58_pubkey_to_uint160(const char *addr,
                      uint160 *digest)
{
   uint8 *buf = NULL;
   size_t len = 0;
   uint8 type;

   base58_decode_check(&type, addr, &buf, &len);
   ASSERT(type == PUBKEY_ADDRESS);
   if (len == sizeof *digest) {
      memcpy(digest, buf, sizeof *digest);
   }
   free(buf);
}

