#pragma once

#include <stdatomic.h>

#include "basic_defs.h"

typedef struct {
   _Atomic uint32 value;
} atomic_uint32;

typedef struct {
   _Atomic uint64 value;
} atomic_uint64;

static inline uint32
atomic_read(const atomic_uint32 *var)
{
   return atomic_load(&var->value);
}

static inline void
atomic_write(atomic_uint32 *var, uint32 val)
{
   atomic_store(&var->value, val);
}

static inline void
atomic_sub(atomic_uint32 *var, uint32 val)
{
   atomic_fetch_sub(&var->value, val);
}

static inline void
atomic_add(atomic_uint32 *var, uint32 val)
{
   atomic_fetch_add(&var->value, val);
}

static inline void
atomic_dec(atomic_uint32 *var)
{
   atomic_fetch_sub(&var->value, 1);
}

static inline bool
atomic_dec_and_test(atomic_uint32 *var)
{
   return atomic_fetch_sub(&var->value, 1) == 1;
}

static inline void
atomic_inc(atomic_uint32 *var)
{
   atomic_fetch_add(&var->value, 1);
}

static inline uint32
atomic_cmpxchg(atomic_uint32 *var, uint32 old, uint32 new)
{
   atomic_compare_exchange_strong(&var->value, &old, new);
   return old;
}

static inline void
atomic64_inc(atomic_uint64 *var)
{
   atomic_fetch_add(&var->value, 1);
}

static inline void
atomic64_dec(atomic_uint64 *var)
{
   atomic_fetch_sub(&var->value, 1);
}

static inline void
atomic64_write(atomic_uint64 *var, uint64 val)
{
   atomic_store(&var->value, val);
}

static inline uint64
atomic64_read(const atomic_uint64 *var)
{
   return atomic_load(&var->value);
}

static inline void
atomic64_sub(atomic_uint64 *var, uint64 val)
{
   atomic_fetch_sub(&var->value, val);
}

static inline void
atomic64_add(atomic_uint64 *var, uint64 val)
{
   atomic_fetch_add(&var->value, val);
}

static inline uint64
atomic64_cmpxchg(atomic_uint64 *var, uint64 old, uint64 new)
{
   atomic_compare_exchange_strong(&var->value, &old, new);
   return old;
}