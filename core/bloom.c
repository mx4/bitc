#include <math.h>
#include <stdlib.h>

#include "bitc-defs.h"
#include "bloom.h"
#include "MurmurHash3.h"
#include "util.h"

#define LGPFX "BLOOM:"

#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455L
#define LN2        0.6931471805599453094172321214581765680755001343602552L

static const uint8 bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

struct bloom_filter {
   uint8       *filter;
   uint32       filterSize;
   uint32       numHashFuncs;
   uint32       tweak;
};


/*
 *-------------------------------------------------------------------------
 *
 * bloom_create --
 *
 *-------------------------------------------------------------------------
 */

struct bloom_filter *
bloom_create(int n,
             double fp)
{
   struct bloom_filter *f;

   f = safe_malloc(sizeof *f);
   f->filterSize = MIN((uint32)(-1 / LN2SQUARED * n * log(fp)),
                       MAX_BLOOM_FILTER_SIZE * 8) / 8;
   f->filter = safe_calloc(1, f->filterSize);
   ASSERT(f->filterSize <= MAX_BLOOM_FILTER_SIZE);
   f->numHashFuncs = MIN((uint32)(f->filterSize * 8 / n * LN2), MAX_HASH_FUNCS);
   ASSERT(f->numHashFuncs <= MAX_HASH_FUNCS);
   f->tweak = 5; /* XXX */

   log_info(LGPFX" filterSize=%u numHashFuncs=%u tweak=%u\n",
       f->filterSize, f->numHashFuncs, f->tweak);

   return f;
}


/*
 *-------------------------------------------------------------------------
 *
 * bloom_hash --
 *
 *-------------------------------------------------------------------------
 */

static uint32
bloom_hash(const struct bloom_filter *f,
           uint32                     funIdx,
           const uint8               *data,
           size_t                     len)
{
   uint32 h;

   h = MurmurHash3(data, len, funIdx * 0xFBA4C795 + f->tweak);

   return h % (f->filterSize * 8);
}


/*
 *-------------------------------------------------------------------------
 *
 * bloom_add --
 *
 *-------------------------------------------------------------------------
 */

void
bloom_add(struct bloom_filter *f,
          const void          *data,
          size_t               len)
{
   int i;

   for (i = 0; i < f->numHashFuncs; i++) {
      uint32 idx = bloom_hash(f, i, data, len);

      ASSERT((idx >> 3) < f->filterSize);

      f->filter[idx >> 3] |= bit_mask[7 & idx];
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * bloom_free --
 *
 *-------------------------------------------------------------------------
 */

void
bloom_free(struct bloom_filter *f)
{
   if (f == NULL) {
      return;
   }
   free(f->filter);
   free(f);
}


/*
 *-------------------------------------------------------------------------
 *
 * bloom_getinfo --
 *
 *-------------------------------------------------------------------------
 */

void
bloom_getinfo(const struct bloom_filter *f,
              uint8                    **filter,
              uint32                    *filterSize,
              uint32                    *numHashFuncs,
              uint32                    *tweak)
{
   ASSERT(f);

   *filter       = f->filter;
   *filterSize   = f->filterSize;
   *numHashFuncs = f->numHashFuncs;
   *tweak        = f->tweak;
}
