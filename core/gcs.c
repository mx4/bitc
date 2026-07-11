#include <string.h>
#include <stdlib.h>

#include "basic_defs.h"
#include "util.h"
#include "gcs.h"

#define LGPFX "GCS:"

/*
 *------------------------------------------------------------------------
 *
 * SipHash-2-4
 *
 * Reference implementation per the SipHash paper (Aumasson, Bernstein 2012).
 * The test vector for key = 0x000102030405060708090a0b0c0d0e0f and
 * data  = 0x000102...1f (32 bytes) should produce 0xa129ca6149be45e5.
 *
 *------------------------------------------------------------------------
 */

#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND(state) \
   do { \
      state.v0 += state.v1; state.v1 = ROTL(state.v1, 13); state.v1 ^= state.v0; \
      state.v0 = ROTL(state.v0, 32); \
      state.v2 += state.v3; state.v3 = ROTL(state.v3, 16); state.v3 ^= state.v2; \
      state.v0 += state.v3; state.v3 = ROTL(state.v3, 21); state.v3 ^= state.v0; \
      state.v2 += state.v1; state.v1 = ROTL(state.v1, 17); state.v1 ^= state.v2; \
      state.v2 = ROTL(state.v2, 32); \
   } while (0)

struct siphash_state {
   uint64 v0, v1, v2, v3;
};

uint64
siphash_2_4(const uint8 key[16],
            const uint8 *data,
            size_t len)
{
   struct siphash_state s;
   uint64 k0, k1;
   uint64 b;
   size_t total_len = len;

   k0 = ((uint64)key[0])       | ((uint64)key[1] << 8)  |
        ((uint64)key[2] << 16) | ((uint64)key[3] << 24) |
        ((uint64)key[4] << 32) | ((uint64)key[5] << 40) |
        ((uint64)key[6] << 48) | ((uint64)key[7] << 56);
   k1 = ((uint64)key[8])        | ((uint64)key[9] << 8)  |
        ((uint64)key[10] << 16) | ((uint64)key[11] << 24) |
        ((uint64)key[12] << 32) | ((uint64)key[13] << 40) |
        ((uint64)key[14] << 48) | ((uint64)key[15] << 56);

   s.v0 = 0x736f6d6570736575ULL ^ k0;
   s.v1 = 0x646f72616e646f6dULL ^ k1;
   s.v2 = 0x6c7967656e657261ULL ^ k0;
   s.v3 = 0x7465646279746573ULL ^ k1;

   while (len >= 8) {
      uint64 m = ((uint64)data[0])       | ((uint64)data[1] << 8)  |
                 ((uint64)data[2] << 16) | ((uint64)data[3] << 24) |
                 ((uint64)data[4] << 32) | ((uint64)data[5] << 40) |
                 ((uint64)data[6] << 48) | ((uint64)data[7] << 56);
      s.v3 ^= m;
      SIPROUND(s);
      SIPROUND(s);
      s.v0 ^= m;
      data += 8;
      len -= 8;
   }

   /*
    * The final block's top byte holds the total message length mod 256,
    * NOT the trailing remainder. (len has been decremented by the loop.)
    */
   b = (uint64)(total_len & 0xff) << 56;
   switch (len) {
   case 7: b |= (uint64)data[6] << 48; /* fallthrough */
   case 6: b |= (uint64)data[5] << 40; /* fallthrough */
   case 5: b |= (uint64)data[4] << 32; /* fallthrough */
   case 4: b |= (uint64)data[3] << 24; /* fallthrough */
   case 3: b |= (uint64)data[2] << 16; /* fallthrough */
   case 2: b |= (uint64)data[1] << 8;  /* fallthrough */
   case 1: b |= (uint64)data[0];       break;
   case 0: break;
   }

   s.v3 ^= b;
   SIPROUND(s);
   SIPROUND(s);
   s.v0 ^= b;

   s.v2 ^= 0xff;
   SIPROUND(s);
   SIPROUND(s);
   SIPROUND(s);
   SIPROUND(s);

   return s.v0 ^ s.v1 ^ s.v2 ^ s.v3;
}

#undef ROTL
#undef SIPROUND


/*
 *------------------------------------------------------------------------
 *
 * gcs_self_test --
 *
 *------------------------------------------------------------------------
 */
bool
gcs_self_test(void)
{
   static const uint8 key[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   };
   static const uint8 data[15] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
   };
   /* Canonical SipHash-2-4 vector for the 15-byte message 00..0e. */
   uint64 expected = 0xa129ca6149be45e5ULL;
   uint64 got;

   got = siphash_2_4(key, data, sizeof data);
   if (got != expected) {
      log_warn(LGPFX" SipHash self-test FAILED: got 0x%llx, expected 0x%llx\n",
              (unsigned long long)got, (unsigned long long)expected);
      return 0;
   }
   log_info(LGPFX" SipHash self-test passed.\n");
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * Bit reader for Golomb-Rice decoding (MSB-first, per BIP158).
 *
 *------------------------------------------------------------------------
 */
struct bit_reader {
   const uint8 *data;
   size_t       len;
   size_t       byte_pos;
   int          bit_pos;  /* 7 = MSB of current byte, down to 0 */
   bool         exhausted;
};

static void
bit_reader_init(struct bit_reader *br, const uint8 *data, size_t len)
{
   br->data      = data;
   br->len       = len;
   br->byte_pos  = 0;
   br->bit_pos   = 7;
   br->exhausted = (len == 0);
}

/* Read one bit. Returns 0 or 1, or -1 if exhausted. */
static int
bit_reader_read_bit(struct bit_reader *br)
{
   int bit;

   if (br->exhausted) {
      return -1;
   }
   bit = (br->data[br->byte_pos] >> br->bit_pos) & 1;
   br->bit_pos--;
   if (br->bit_pos < 0) {
      br->bit_pos = 7;
      br->byte_pos++;
      if (br->byte_pos >= br->len) {
         br->exhausted = 1;
      }
   }
   return bit;
}

/* Read `n` bits as an unsigned integer (MSB first). Returns -1 on exhaustion. */
static int64
bit_reader_read_bits(struct bit_reader *br, int n)
{
   int64 val = 0;
   int i;

   for (i = 0; i < n; i++) {
      int bit = bit_reader_read_bit(br);
      if (bit < 0) {
         return -1;
      }
      val = (val << 1) | bit;
   }
   return val;
}

/*
 * Read a Golomb-Rice encoded value with parameter P.
 * Per BIP158: quotient is unary (q 1-bits followed by a 0-bit),
 * remainder is P bits big-endian.
 * Returns the decoded value, or -1 on exhaustion.
 */
static int64
bit_reader_read_gr(struct bit_reader *br, int P)
{
   int64 quotient = 0;
   int64 remainder;
   int bit;

   /* Read quotient: count 1-bits until a 0-bit (BIP158 unary). */
   for (;;) {
      bit = bit_reader_read_bit(br);
      if (bit < 0) {
         return -1;
      }
      if (bit == 0) {
         break;
      }
      quotient++;
      if (quotient > 100000000) {
         /* Sanity: a quotient this large means a malformed filter. */
         return -1;
      }
   }

   remainder = bit_reader_read_bits(br, P);
   if (remainder < 0) {
      return -1;
   }

   return quotient * ((int64)1 << P) + remainder;
}


/*
 *------------------------------------------------------------------------
 *
 * CompactSize (varint) reader for raw byte buffers.
 *
 *------------------------------------------------------------------------
 */
static int
read_compactsize(const uint8 *data, size_t len, size_t *pos, uint64 *out)
{
   uint8 c;

   if (*pos >= len) {
      return 1;
   }
   c = data[*pos];
   (*pos)++;

   if (c < 253) {
      *out = c;
   } else if (c == 253) {
      uint16 v;
      if (*pos + 2 > len) return 1;
      v = ((uint16)data[*pos]) | ((uint16)data[*pos + 1] << 8);
      *pos += 2;
      *out = v;
   } else if (c == 254) {
      uint32 v;
      if (*pos + 4 > len) return 1;
      v = ((uint32)data[*pos])       | ((uint32)data[*pos + 1] << 8) |
          ((uint32)data[*pos + 2] << 16) | ((uint32)data[*pos + 3] << 24);
      *pos += 4;
      *out = v;
   } else {
      uint64 v;
      int i;
      if (*pos + 8 > len) return 1;
      v = 0;
      for (i = 0; i < 8; i++) {
         v |= (uint64)data[*pos + i] << (i * 8);
      }
      *pos += 8;
      *out = v;
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * gcs_filter_match_any --
 *
 *      BIP158 GCS membership test. Intersects the sorted stream of filter
 *      values with the sorted set of query hashes.
 *
 *------------------------------------------------------------------------
 */
bool
gcs_filter_match_any(const uint8 *filterData, size_t filterLen,
                     const uint256 *blockHash,
                     const uint8 * const *items, const size_t *itemLens,
                     size_t n)
{
   uint8 key[16];
   uint64 N;
   uint64 F;
   size_t pos = 0;
   struct bit_reader br;
   int64 filter_val = 0;   /* running decoded value from the filter */
   size_t q_idx = 0;       /* index into the sorted query array */
   int64 *query_hashes;    /* sorted array of query hashes */
   size_t i;

   if (filterData == NULL || filterLen == 0 || blockHash == NULL ||
       items == NULL || itemLens == NULL || n == 0) {
      return 0;
   }

   /* SipHash key = first 16 bytes of the block hash (BIP158). */
   memcpy(key, blockHash->data, 16);

   /* Read N (number of items in the filter) as a CompactSize varint. */
   if (read_compactsize(filterData, filterLen, &pos, &N)) {
      log_warn(LGPFX" truncated filter: cannot read N.\n");
      return 0;
   }
   if (N > 10000000) {
      log_warn(LGPFX" filter N=%llu is unreasonably large; rejecting.\n",
              (unsigned long long)N);
      return 0;
   }

   F = N * GCS_M;

   /* An empty filter (N=0) contains no items. */
   if (N == 0) {
      return 0;
   }

   /* Compute query hashes and sort them. */
   query_hashes = safe_malloc(n * sizeof *query_hashes);
   for (i = 0; i < n; i++) {
      uint64 h = siphash_2_4(key, items[i], itemLens[i]);
      /* Map to range [0, F) using 64x64->128 multiplication. */
      __uint128_t wide = (__uint128_t)h * (__uint128_t)F;
      query_hashes[i] = (int64)(uint64)(wide >> 64);
   }

   /* Simple insertion sort (n is small — typically a handful of wallet keys). */
   for (i = 1; i < n; i++) {
      int64 v = query_hashes[i];
      size_t j = i;
      while (j > 0 && query_hashes[j - 1] > v) {
         query_hashes[j] = query_hashes[j - 1];
         j--;
      }
      query_hashes[j] = v;
   }

   /* Initialize the bit reader over the remaining filter bytes. */
   bit_reader_init(&br, filterData + pos, filterLen - pos);

   /* Intersect the two sorted streams. */
   while (q_idx < n) {
      int64 target = query_hashes[q_idx];

      if (filter_val < 0) {
         /* Bit reader exhausted. */
         break;
      }

      if (filter_val == target) {
         free(query_hashes);
         return 1;
      }

      if (filter_val < target) {
         /* Advance the filter stream. */
         int64 delta = bit_reader_read_gr(&br, GCS_P);
         if (delta < 0) {
            break;
         }
         filter_val += delta;
      } else {
         /* filter_val > target: advance the query stream. */
         q_idx++;
      }
   }

   free(query_hashes);
   return 0;
}
