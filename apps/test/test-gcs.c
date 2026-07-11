/*
 * GCS / SipHash self-test.
 *
 * Build:
 *   make test-gcs
 *
 * Run:
 *   ./test-gcs
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "basic_defs.h"
#include "hash.h"
#include "gcs.h"

/*
 * We verify:
 * 1. SipHash-2-4 against the canonical test vector.
 * 2. GCS membership: build a small synthetic filter by hand and verify
 *    that a known-present item matches and a known-absent item does not.
 *
 * For (2), since we don't have a GCS *encoder* in this project (we only
 * need to decode/match filters served by peers), we use a hand-crafted
 * minimal filter. The simplest test is the SipHash vector + a structural
 * test of gcs_filter_match_any on a trivially small filter.
 */

int
main(void)
{
   bool ok;

   printf("=== GCS self-test ===\n");

   ok = gcs_self_test();
   if (!ok) {
      printf("FAIL: SipHash self-test\n");
      return 1;
   }
   printf("PASS: SipHash-2-4 test vector\n");

   /*
    * Test gcs_filter_match_any on a minimal synthetic filter.
    *
    * A BIP158 filter is: varint(N) + Golomb-Rice encoded deltas.
    * For N=1, one item with hash H, the filter encodes:
    *   varint(1) + GR(H)  where GR(v) = quotient * 2^P + remainder
    *
    * We can't easily build this without an encoder, so instead we test
    * the error-handling paths: empty filter, truncated filter, NULL inputs.
    */
   {
      uint256 blockHash;
      const uint8 *items[] = { (const uint8 *)"test" };
      size_t itemLens[] = { 4 };
      bool match;

      memset(blockHash.data, 0x42, 32);

      /* Empty filter: should return false, not crash. */
      match = gcs_filter_match_any(NULL, 0, &blockHash, items, itemLens, 1);
      if (match) {
         printf("FAIL: empty filter should not match\n");
         return 1;
      }
      printf("PASS: empty filter handled safely\n");

      /* Filter with just N=0 (varint 0x00): no items, should not match. */
      {
         uint8 filter[] = { 0x00 };
         match = gcs_filter_match_any(filter, sizeof filter, &blockHash,
                                      items, itemLens, 1);
         if (match) {
            printf("FAIL: N=0 filter should not match\n");
            return 1;
         }
         printf("PASS: N=0 filter does not match\n");
      }

      /* Truncated filter (varint says N=1 but no data follows). */
      {
         uint8 filter[] = { 0x01 }; /* N=1, but no bitstream */
         match = gcs_filter_match_any(filter, sizeof filter, &blockHash,
                                      items, itemLens, 1);
         if (match) {
            printf("FAIL: truncated filter should not match\n");
            return 1;
         }
         printf("PASS: truncated filter handled safely\n");
      }

      /* No query items: should return false. */
      match = gcs_filter_match_any((const uint8 *)"\x00", 1, &blockHash,
                                   NULL, NULL, 0);
      if (match) {
         printf("FAIL: no query items should not match\n");
         return 1;
      }
      printf("PASS: no query items handled safely\n");
   }

   /*
    * Official BIP158 test vector: testnet block 926485.
    * The basic filter and the scriptPubKeys in the block are published, so a
    * correct decoder MUST match every script that is in the block, and MUST
    * NOT match a script that is absent.
    *
    *   block hash (display/BE):
    *     000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313
    *   basic filter:
    *     09027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800
    */
   {
      /*
       * The SipHash key is the first 16 bytes of the block hash in
       * little-endian (internal) representation, i.e. the display hash
       * reversed. We store the full 32-byte LE hash in uint256.data, which
       * is exactly what bitc's deserialize_uint256 produces from the wire.
       */
      static const uint8 filter[] = {
         0x09, 0x02, 0x7a, 0xce, 0xa6, 0x1b, 0x6c, 0xc3,
         0xfb, 0x33, 0xf5, 0xd5, 0x2f, 0x7d, 0x08, 0x8a,
         0x6b, 0x2f, 0x75, 0xd2, 0x34, 0xe8, 0x9c, 0xa8,
         0x00,
      };
      uint256 blockHash;
      /* display hash bytes, big-endian as printed */
      static const uint8 display[32] = {
         0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x5d,
         0x60,0x77,0xa4,0x11,0xa8,0xf5,0xcc,0x95,
         0xca,0xf7,0x75,0xcc,0xf1,0x1c,0x54,0xe2,
         0x7d,0xf7,0x5c,0xe5,0x8d,0x18,0x73,0x13,
      };
      int i;
      /* Present in the block (from the test vector's script list). */
      static const uint8 present1[] = { /* P2SH a914...87 */
         0xa9,0x14,0xfe,0xb8,0xa2,0x96,0x35,0xc5,0x6d,
         0x9c,0xd9,0x13,0x12,0x2f,0x90,0x67,0x87,0x56,
         0xbf,0x23,0x88,0x76,0x87,
      };
      static const uint8 present2[] = { /* P2PKH 76a914...88ac */
         0x76,0xa9,0x14,0xc0,0x1a,0x7c,0xa1,0x6b,0x47,
         0xbe,0x50,0xcb,0xdb,0xc6,0x07,0x24,0xf7,0x01,
         0xd5,0x2d,0x75,0x15,0x66,0x88,0xac,
      };
      /* Not in the block: an all-zero hash160 P2PKH. */
      static const uint8 absent[] = {
         0x76,0xa9,0x14,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x88,0xac,
      };
      const uint8 *one[1];
      size_t onelen[1];
      bool m;

      /* reverse display -> LE internal */
      for (i = 0; i < 32; i++) {
         blockHash.data[i] = display[31 - i];
      }

      one[0] = present1; onelen[0] = sizeof present1;
      m = gcs_filter_match_any(filter, sizeof filter, &blockHash,
                               one, onelen, 1);
      if (!m) {
         printf("FAIL: BIP158 vector present1 should match\n");
         return 1;
      }
      printf("PASS: BIP158 vector present1 (P2SH) matches\n");

      one[0] = present2; onelen[0] = sizeof present2;
      m = gcs_filter_match_any(filter, sizeof filter, &blockHash,
                               one, onelen, 1);
      if (!m) {
         printf("FAIL: BIP158 vector present2 should match\n");
         return 1;
      }
      printf("PASS: BIP158 vector present2 (P2PKH) matches\n");

      one[0] = absent; onelen[0] = sizeof absent;
      m = gcs_filter_match_any(filter, sizeof filter, &blockHash,
                               one, onelen, 1);
      if (m) {
         printf("FAIL: BIP158 vector absent should NOT match\n");
         return 1;
      }
      printf("PASS: BIP158 vector absent does not match\n");
   }

   printf("=== All GCS tests passed ===\n");
   return 0;
}
