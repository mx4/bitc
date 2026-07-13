#pragma once

#include "basic_defs.h"
#include "hash.h"  /* uint256 */

/*
 * BIP157 compact-filter header chain store.
 *
 * Persists one filter header per block height to a versioned file. Each filter
 * header commits to the previous one:
 *   filterHeader = hash256( filterHash || prevFilterHeader )
 *
 * This gives the SPV client a trust-minimized anchor: by cross-checking
 * filter headers across multiple peers (via getcfcheckpt), the client can
 * detect a lying peer that serves fake filters.
 *
 * The store need not start at height 0: an empty store's first append
 * establishes its base height (see cfheaderstore_get_base_height), so a
 * wallet with a recent birth can anchor its cfheader chain on a getcfcheckpt
 * checkpoint near its birth height instead of syncing from genesis.
 */

struct cfheaderstore;

/* Compute filterHeader = hash256( filterHash || prevFilterHeader ). */
void cfheader_calc(const uint256 *filterHash, const uint256 *prevFilterHeader,
                   uint256 *out);

int  cfheaderstore_init(const char *filename, struct cfheaderstore **cfs);
void cfheaderstore_exit(struct cfheaderstore *cfs);

/* Returns the height of the highest stored filter header, or -1 if empty. */
int  cfheaderstore_get_tip_height(const struct cfheaderstore *cfs);

/* Returns the height of the lowest stored filter header, or -1 if empty. */
int  cfheaderstore_get_base_height(const struct cfheaderstore *cfs);

/* Append a filter header at the given height. Height must be tip+1, or (for
 * the very first append to an empty store) any height -- that height becomes
 * the store's base. Returns 0 on success, nonzero on error. Flushes to disk
 * on append. */
int  cfheaderstore_append(struct cfheaderstore *cfs, int height,
                          const uint256 *filterHeader,
                          const uint256 *filterHash);

/* Look up the filter header at a given height. Returns 0 on success. */
int  cfheaderstore_get_header(const struct cfheaderstore *cfs, int height,
                              uint256 *filterHeader);

/* Look up the filter hash at a given height. Returns 0 on success. */
int  cfheaderstore_get_hash(const struct cfheaderstore *cfs, int height,
                            uint256 *filterHash);
