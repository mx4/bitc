#pragma once

#include "basic_defs.h"
#include "hash.h"  /* uint256 */

/*
 * BIP158 Golomb-Coded Set (GCS) filter matching and SipHash-2-4.
 *
 * This module is self-contained: it has no dependencies on peer, wallet, or
 * block-store code. It is testable in isolation against the BIP158 test
 * vectors.
 */

/* SipHash-2-4 with a 16-byte key. */
uint64 siphash_2_4(const uint8 key[16], const uint8 *data, size_t len);

/* BIP158 basic filter parameters. */
#define GCS_P 19
#define GCS_M 784931

/*
 * Returns true if any of the `n` items (each a scriptPubKey byte-string) is in
 * the GCS-encoded filter. blockHash is the little-endian 32-byte block hash;
 * the SipHash key is the first 16 bytes of it (per BIP158).
 *
 * filterData: raw GCS-encoded filter bytes (as received in a 'cfilter' message)
 * filterLen:  length of filterData in bytes
 * items:      array of pointers to scriptPubKey byte-strings
 * itemLens:   array of lengths for each item
 * n:          number of items
 *
 * Returns false on malformed/truncated filters (never asserts on network data).
 */
bool gcs_filter_match_any(const uint8 *filterData, size_t filterLen,
                          const uint256 *blockHash,
                          const uint8 * const *items, const size_t *itemLens,
                          size_t n);

/* Self-test: verifies SipHash against the known test vector. Returns true on
 * success. */
bool gcs_self_test(void);
