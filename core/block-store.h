#pragma once

#include <time.h>

#include "hash.h"
#include "btc-message.h"

struct blockstore;
struct config;

int  blockstore_init(struct config *, struct blockstore **bs);
void blockstore_exit(struct blockstore *bs);
void blockstore_zap(struct config *config);
void blockstore_get_genesis(const struct blockstore *bs, uint256 *hash);
void blockstore_get_best_hash(const struct blockstore *bs, uint256 *hash);
void blockstore_get_next_hashes(struct blockstore *bs, const uint256 *start,
                                uint256 **hash, int *n);
bool blockstore_add_header(struct blockstore *bs, const btc_block_header *hdr,
                           const uint256 *hash, bool *orphan);
void blockstore_write_headers(struct blockstore *bs);
bool blockstore_has_header(const struct blockstore *bs, const uint256 *hash);
bool blockstore_is_orphan(const struct blockstore *bs, const uint256 *hash);
bool blockstore_is_block_known(const struct blockstore *bs, const uint256 *hash);
int  blockstore_get_height(const struct blockstore *bs);
int  blockstore_get_block_height(struct blockstore *bs, const uint256 *hash);
void blockstore_get_hash_from_birth(const struct blockstore *bs, uint64 b, uint256 *h);
bool blockstore_is_next(struct blockstore *bs, const uint256 *p, const uint256 *n);
time_t blockstore_get_timestamp(const struct blockstore *bs);
time_t blockstore_get_block_timestamp(const struct blockstore *bs,
                                      const uint256 *h);
void blockstore_get_highest(struct blockstore *bs,
                            const uint256 *hash0,
                            const uint256 *hash1,
                            uint256 *hash);
void blockstore_get_locator_hashes(const struct blockstore *bs,
                                   uint256 **hash, int *num);
bool
blockstore_get_block_at_height(struct blockstore *bs, int height, uint256 *hash,
                               btc_block_header *header);

