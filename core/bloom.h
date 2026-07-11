#pragma once

#include "basic_defs.h"

struct bloom_filter;

struct bloom_filter * bloom_create(int n, double falsePositive);
void bloom_free(struct bloom_filter *f);
void bloom_add(struct bloom_filter *f, const void *data, size_t len);
void bloom_getinfo(const struct bloom_filter *f, uint8 **filter,
                   uint32 *filterSize, uint32 *numHashFuncs, uint32 *tweak);

