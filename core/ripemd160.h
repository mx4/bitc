#pragma once

#include "basic_defs.h"

/*
 * RIPEMD-160, needed for hash160 = RIPEMD160(SHA256(x)). OpenSSL deprecated
 * its RIPEMD160() in 3.0 (moved to the legacy provider), so we ship a small
 * self-contained implementation rather than depend on that provider.
 */
void ripemd160(const void *data, size_t len, uint8 digest[20]);
