#pragma once

#include <string.h>
#include "basic_defs.h"


#define DIGEST_SHA256_LEN       32
#define DIGEST_RIPEMD160_LEN    20


typedef struct {
   uint8   data[DIGEST_SHA256_LEN];
} uint256;


typedef struct {
   uint8   data[DIGEST_RIPEMD160_LEN];
} uint160;


/*
 *---------------------------------------------------------------------
 *
 * uint160_zero_out --
 *
 *---------------------------------------------------------------------
 */

static inline void
uint160_zero_out(uint160 *h)
{
   memset(h, 0, sizeof *h);
}


/*
 *---------------------------------------------------------------------
 *
 * uint256_zero_out --
 *
 *---------------------------------------------------------------------
 */

static inline void
uint256_zero_out(uint256 *h)
{
   memset(h, 0, sizeof *h);
}


/*
 *---------------------------------------------------------------------
 *
 * uint256_issame --
 *
 *---------------------------------------------------------------------
 */

static inline bool
uint256_issame(const uint256 *a,
               const uint256 *b)
{
   return memcmp(a->data, b->data, sizeof *a) == 0;
}


/*
 *---------------------------------------------------------------------
 *
 * uint256_iszero --
 *
 *---------------------------------------------------------------------
 */

static inline bool
uint256_iszero(const uint256 *h)
{
   uint256 zero;

   if (h == NULL) {
      return 1;
   }
   uint256_zero_out(&zero);

   return uint256_issame(&zero, h);
}


/*
 *---------------------------------------------------------------------
 *
 * uint160_issame --
 *
 *---------------------------------------------------------------------
 */

static inline bool
uint160_issame(const uint160 *a,
               const uint160 *b)
{
   return memcmp(a->data, b->data, sizeof *a) == 0;
}


/*
 *---------------------------------------------------------------------
 *
 * uint160_iszero --
 *
 *---------------------------------------------------------------------
 */

static inline bool
uint160_iszero(const uint160 *h)
{
   uint160 zero;

   if (h == NULL) {
      return 1;
   }
   uint160_zero_out(&zero);

   return uint160_issame(&zero, h);
}


void uint256_snprintf_reverse(char *s, size_t len, const uint256 *h);
void uint160_snprintf_reverse(char *s, size_t len, const uint160 *h);
bool uint256_from_str(const char *str, uint256 *hash);

static inline const char *
uint256_to_str(const uint256 *h)
{
   static _Thread_local char buf[4][80];
   static _Thread_local int idx;
   char *b = buf[idx++ & 3];
   uint256_snprintf_reverse(b, 80, h);
   return b;
}

void hash256_calc(const void *buf, size_t len, uint256 *hash);
void hash160_calc(const void *buf, size_t bufLen, uint160 *digest);
void hash4_calc(const void *buf, size_t len, uint8 hash[4]);

void sha256_calc(const void *buf, size_t bufLen, uint256 *digest);

