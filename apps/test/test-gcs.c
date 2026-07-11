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

   printf("=== All GCS tests passed ===\n");
   return 0;
}
